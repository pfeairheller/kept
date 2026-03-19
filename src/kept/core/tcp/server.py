import asyncio
from asyncio import Queue
from typing import Dict

from keri.core import parsing
from keri import help

from kept.essr.server import Rack

logger = help.ogler.getLogger()


class KERITCPHandler:
    """Handler that processes TCP connections and passes streams to KERI parser."""

    def __init__(self, app: Rack):
        """Initialize handler with KERI Kevery instance.

        Parameters:
            app (Rack): Rack app with configured handlers for incoming ESSR encoded esn messages
        """
        self.app = app

    async def handle_connection(self, reader, writer):
        """Handle incoming TCP connection by processing stream with KERI parser.

        Parameters:
            reader (StreamReader): Asyncio stream reader for incoming data
            writer (StreamWriter): Asyncio stream writer for outgoing data
        """
        client_addr = writer.get_extra_info("peername")
        logger.info(f"New connection from {client_addr}")

        try:
            # Create parser with connection stream
            rxbs = bytearray()
            wrapper = ExchangerWrapper(self.app.exc, self.app, writer)
            parser = parsing.Parser(ims=rxbs, exc=wrapper, framed=True)
            parsator = parser.onceParsator()
            # Prime the generator (advance to first yield)
            try:
                next(parsator)
            except StopIteration:
                pass  # Parser completed immediately (shouldn't happen)

            while True:
                # Read data from connection
                data = await reader.read(4096)
                if not data:
                    logger.info(f"Connection from {client_addr} closed")
                    break

                # Extend receive buffer and parse
                rxbs.extend(data)

                # Process all available messages
                try:
                    next(parsator)
                except StopIteration:
                    pass
                    # Continue processing despite parse errors

        except asyncio.CancelledError:
            logger.error(f"Connection handler for {client_addr} cancelled")

        except Exception as e:
            logger.error(f"Error handling connection from {client_addr}: {e}")

        finally:
            writer.close()
            await writer.wait_closed()
            logger.info(f"Connection to {client_addr} closed")


class KERITCPServer:
    """Asyncio TCP server for KERI protocol messages."""

    def __init__(self, app, host="localhost", port=8080, cycle_time=0.25):
        """Initialize TCP server.

        Parameters:
            app (Rack): Rack app with configured handlers for incoming ESSR encoded esn messages
            host (str): Host address to bind to
            port (int): Port number to bind to
            cycle_time (float): Time in seconds between service() calls (default: 0.1)
        """
        self.app = app
        self.host = host
        self.port = port
        self.cycle_time = cycle_time
        self.server = None
        self.handler = KERITCPHandler(self.app)
        self.startup_task = None
        self.service_task = None
        self.running = False

        self.startup_event = asyncio.Event()
        self.shutdown_event = asyncio.Event()
        self.startup_failed = False
        self.shutdown_failed = False
        self.receive_queue: Queue[Dict] = asyncio.Queue()

    async def _service_loop(self):
        """Background task that calls service() on regular intervals."""
        while self.running:
            try:
                self.app.service()
                await asyncio.sleep(self.cycle_time)
            except asyncio.CancelledError:
                logger.info("Service loop cancelled")
                break
            except Exception as e:
                logger.error(f"Error in service loop: {e}")
                await asyncio.sleep(self.cycle_time)

    async def start(self):
        """Start the TCP server."""
        self.running = True

        scope = dict()
        scope["type"] = "lifespan"
        scope["app"] = self.app

        startup_event = {"type": "lifespan.startup"}
        await self.receive_queue.put(startup_event)
        self.startup_task = asyncio.create_task(
            self.app.lifespan(scope=scope, receive=self.receive, send=self.send)
        )
        self.service_task = asyncio.create_task(self._service_loop())

        self.server = await asyncio.start_server(
            self.handler.handle_connection, self.host, self.port
        )

        addr = self.server.sockets[0].getsockname()
        logger.info(f"KERI TCP server serving on {addr}")

        async with self.server:
            await self.server.serve_forever()

    async def stop(self):
        """Stop the TCP server."""
        self.running = False

        if self.service_task:
            self.service_task.cancel()
            try:
                await self.service_task
            except asyncio.CancelledError:
                pass

        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("KERI TCP server stopped")

    async def send(self, message: Dict) -> None:
        assert message["type"] in (
            "lifespan.startup.complete",
            "lifespan.startup.failed",
            "lifespan.shutdown.complete",
            "lifespan.shutdown.failed",
        )

        if message["type"] == "lifespan.startup.complete":
            self.startup_event.set()

        elif message["type"] == "lifespan.startup.failed":
            self.startup_event.set()
            self.startup_failed = True
            if message.get("message"):
                logger.error(message["message"])

        elif message["type"] == "lifespan.shutdown.complete":
            self.shutdown_event.set()

        elif message["type"] == "lifespan.shutdown.failed":
            self.shutdown_event.set()
            self.shutdown_failed = True
            if message.get("message"):
                logger.error(message["message"])

    async def receive(self) -> Dict:
        return await self.receive_queue.get()


class ExchangerWrapper:
    def __init__(self, exc, app, writer):
        self._exc = exc
        self.app = app
        self.writer = writer

    def __getattr__(self, name):
        """Delegate attribute access to the wrapped object"""
        return getattr(self._exc, name)

    def processEvent(self, serder, tsgs=None, cigars=None, **kwargs):
        self.app.assign_writer(serder.said, writer=self.writer)
        self._exc.processEvent(serder, tsgs, cigars, **kwargs)

        while self._exc.cues:
            cue = self._exc.cues.popleft()
            if cue["kin"] == "notFound":
                asyncio.create_task(self.app.not_found(serder.said))


async def run_server(app: Rack, host="localhost", port=8080):
    """Convenience function to run KERI TCP server.

    Parameters:
        app (Rack): Rack app with configured handlers for incoming ESSR encoded esn messages
        host (str): Host address to bind to
        port (int): Port number to bind to
    """
    server = KERITCPServer(app, host, port)
    await server.start()
