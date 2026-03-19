# -*- encoding: utf-8 -*-
"""
HEKI
kept.core.tcp.client package

"""

import asyncio
import socket

from keri.help import ogler
from typing import Optional

logger = ogler.getLogger()


class AsyncTCPClient:
    """AsyncIO TCP client for connecting to a server and sending/receiving data."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected = False

    async def connect(self) -> bool:
        """Connect to the TCP server."""
        try:
            self.reader, self.writer = await asyncio.open_connection(
                self.host, self.port
            )
            self.connected = True

            return True
        except Exception as e:
            logger.error(f"Failed to connect to {self.host}:{self.port}: {e}")
            return False

    async def disconnect(self):
        """Disconnect from the TCP server."""
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
        self.connected = False
        self.reader = None
        self.writer = None

    async def send(self, data: bytes) -> bool:
        """Send data to the server."""
        if not self.connected or not self.writer:
            logger.error("Not connected to server")
            return False

        try:
            self.writer.write(data)
            await self.writer.drain()
            logger.debug(f"Sent {len(data)} bytes")
            return True
        except Exception as e:
            logger.error(f"Failed to send data: {e}")
            return False

    async def receive(self, buffer_size: int = 4096) -> Optional[bytes]:
        """Receive data from the server."""
        if not self.connected or not self.reader:
            logger.error("Not connected to server")
            return None

        try:
            data = await self.reader.read(buffer_size)
            if data:
                logger.debug(f"Received {len(data)} bytes")
            return data
        except Exception as e:
            logger.error(f"Failed to receive data: {e}")
            return None

    async def receive_all(self, expected_size: int = None) -> Optional[bytes]:
        """Receive all available data from the server."""
        if not self.connected or not self.reader:
            logger.error("Not connected to server")
            return None

        try:
            if expected_size:
                data = await self.reader.readexactly(expected_size)
            else:
                data = await self.reader.read(-1)

            if data:
                logger.debug(f"Received all data: {len(data)} bytes")
            return data
        except Exception as e:
            logger.error(f"Failed to receive all data: {e}")
            return None

    async def send_and_receive(
        self, data: bytes, response_size: int = 4096
    ) -> Optional[bytes]:
        """Send data and wait for a response."""
        if await self.send(data):
            return await self.receive(response_size)
        return None

    def is_connected(self) -> bool:
        """Check if the client is connected."""
        return (
            self.connected and self.writer is not None and not self.writer.is_closing()
        )

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()


class TCPClient:
    """Synchronous TCP client for connecting to a server and sending/receiving data."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.connected = False

    def connect(self) -> bool:
        """Connect to the TCP server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            return True
        except Exception as e:
            logger.error(f"Failed to connect to {self.host}:{self.port}: {e}")
            return False

    def disconnect(self):
        """Disconnect from the TCP server."""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
        self.connected = False
        self.socket = None

    def send(self, data: bytes) -> bool:
        """Send data to the server."""
        if not self.connected or not self.socket:
            logger.error("Not connected to server")
            return False

        try:
            self.socket.sendall(data)
            logger.debug(f"Sent {len(data)} bytes")
            return True
        except Exception as e:
            logger.error(f"Failed to send data: {e}")
            return False

    def receive(self, buffer_size: int = 4096) -> Optional[bytes]:
        """Receive data from the server."""
        if not self.connected or not self.socket:
            logger.error("Not connected to server")
            return None

        try:
            data = self.socket.recv(buffer_size)
            if data:
                logger.debug(f"Received {len(data)} bytes")
            return data
        except Exception as e:
            logger.error(f"Failed to receive data: {e}")
            return None

    def receive_all(self, expected_size: int = None) -> Optional[bytes]:
        """Receive all available data from the server."""
        if not self.connected or not self.socket:
            logger.error("Not connected to server")
            return None

        try:
            if expected_size:
                # Receive exactly expected_size bytes
                data = b""
                remaining = expected_size
                while remaining > 0:
                    chunk = self.socket.recv(min(remaining, 4096))
                    if not chunk:
                        raise ConnectionError(
                            "Connection closed before receiving all data"
                        )
                    data += chunk
                    remaining -= len(chunk)
            else:
                # Receive until connection closes
                data = b""
                while True:
                    chunk = self.socket.recv(4096)
                    if not chunk:
                        break
                    data += chunk

            if data:
                logger.debug(f"Received all data: {len(data)} bytes")
            return data
        except Exception as e:
            logger.error(f"Failed to receive all data: {e}")
            return None

    def send_and_receive(
        self, data: bytes, response_size: int = 4096
    ) -> Optional[bytes]:
        """Send data and wait for a response."""
        if self.send(data):
            return self.receive(response_size)
        return None

    def is_connected(self) -> bool:
        """Check if the client is connected."""
        return self.connected and self.socket is not None

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
