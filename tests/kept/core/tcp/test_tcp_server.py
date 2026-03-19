import asyncio
import pytest
from unittest.mock import Mock, AsyncMock, patch
from asyncio import Queue

from kept.core.tcp.server import (
    KERITCPHandler,
    KERITCPServer,
    ExchangerWrapper,
    run_server,
)
from kept.essr.server import Rack


class TestKERITCPHandler:

    @pytest.fixture
    def mock_app(self):
        app = Mock(spec=Rack)
        app.exc = Mock()
        return app

    @pytest.fixture
    def handler(self, mock_app):
        return KERITCPHandler(mock_app)

    def test_init(self, mock_app):
        handler = KERITCPHandler(mock_app)
        assert handler.app == mock_app

    @pytest.mark.asyncio
    async def test_handle_connection_successful_processing(self, handler, mock_app):
        reader = AsyncMock()
        writer = Mock()
        writer.get_extra_info.return_value = ("127.0.0.1", 12345)
        writer.close = Mock()
        writer.wait_closed = AsyncMock()

        test_data = b"test_keri_data"
        reader.read.side_effect = [test_data, b""]

        mock_wrapper = Mock()
        mock_parser = Mock()
        mock_parsator = Mock()
        # Generator should raise StopIteration after processing
        mock_parsator.__next__ = Mock(side_effect=[None, StopIteration, StopIteration])
        mock_parser.onceParsator.return_value = mock_parsator

        with (
            patch("kept.core.tcp.server.ExchangerWrapper", return_value=mock_wrapper),
            patch("keri.core.parsing.Parser", return_value=mock_parser),
        ):

            await handler.handle_connection(reader, writer)

            assert reader.read.call_count == 2
            writer.close.assert_called_once()
            writer.wait_closed.assert_called_once()
            mock_parser.onceParsator.assert_called_once()
            # Should be called 3 times: once to prime, twice in the loop
            assert mock_parsator.__next__.call_count == 2

    @pytest.mark.asyncio
    async def test_handle_connection_parse_error(self, handler, mock_app):
        reader = AsyncMock()
        writer = Mock()
        writer.get_extra_info.return_value = ("127.0.0.1", 12345)
        writer.close = Mock()
        writer.wait_closed = AsyncMock()

        test_data = b"invalid_data"
        reader.read.side_effect = [test_data, b""]

        mock_wrapper = Mock()
        mock_parser = Mock()
        mock_parser.parseOne.side_effect = ValueError("Parse error")

        with (
            patch("kept.core.tcp.server.ExchangerWrapper", return_value=mock_wrapper),
            patch("keri.core.parsing.Parser", return_value=mock_parser),
        ):

            await handler.handle_connection(reader, writer)

            writer.close.assert_called_once()
            writer.wait_closed.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_connection_cancelled_error(self, handler, mock_app):
        reader = AsyncMock()
        writer = Mock()
        writer.get_extra_info.return_value = ("127.0.0.1", 12345)
        writer.close = Mock()
        writer.wait_closed = AsyncMock()

        reader.read.side_effect = asyncio.CancelledError()

        await handler.handle_connection(reader, writer)

        writer.close.assert_called_once()
        writer.wait_closed.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_connection_general_exception(self, handler, mock_app):
        reader = AsyncMock()
        writer = Mock()
        writer.get_extra_info.return_value = ("127.0.0.1", 12345)
        writer.close = Mock()
        writer.wait_closed = AsyncMock()

        reader.read.side_effect = Exception("Connection error")

        await handler.handle_connection(reader, writer)

        writer.close.assert_called_once()
        writer.wait_closed.assert_called_once()


class TestKERITCPServer:

    @pytest.fixture
    def mock_app(self):
        app = Mock(spec=Rack)
        app.service = Mock()
        app.lifespan = AsyncMock()
        return app

    @pytest.fixture
    def server(self, mock_app):
        return KERITCPServer(mock_app, host="localhost", port=8080, cycle_time=0.1)

    def test_init(self, mock_app):
        server = KERITCPServer(mock_app, host="test_host", port=9999, cycle_time=0.2)
        assert server.app == mock_app
        assert server.host == "test_host"
        assert server.port == 9999
        assert server.cycle_time == 0.2
        assert server.server is None
        assert isinstance(server.handler, KERITCPHandler)
        assert server.startup_task is None
        assert server.service_task is None
        assert server.running is False
        assert isinstance(server.startup_event, asyncio.Event)
        assert isinstance(server.shutdown_event, asyncio.Event)
        assert server.startup_failed is False
        assert server.shutdown_failed is False
        assert isinstance(server.receive_queue, Queue)

    def test_init_defaults(self, mock_app):
        server = KERITCPServer(mock_app)
        assert server.host == "localhost"
        assert server.port == 8080
        assert server.cycle_time == 0.25

    @pytest.mark.asyncio
    async def test_service_loop_normal_operation(self, server, mock_app):
        server.running = True
        server.cycle_time = 0.01

        call_count = 0

        def side_effect():
            nonlocal call_count
            call_count += 1
            if call_count >= 3:
                server.running = False

        mock_app.service.side_effect = side_effect

        await server._service_loop()

        assert call_count == 3
        assert mock_app.service.call_count == 3

    @pytest.mark.asyncio
    async def test_service_loop_cancelled(self, server, mock_app):
        server.running = True
        mock_app.service.side_effect = asyncio.CancelledError()

        await server._service_loop()

        mock_app.service.assert_called_once()

    @pytest.mark.asyncio
    async def test_service_loop_exception(self, server, mock_app):
        server.running = True
        server.cycle_time = 0.01

        call_count = 0

        def side_effect():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Service error")
            elif call_count >= 2:
                server.running = False

        mock_app.service.side_effect = side_effect

        await server._service_loop()

        assert call_count == 2

    @pytest.mark.asyncio
    async def test_start(self, server, mock_app):
        mock_asyncio_server = AsyncMock()
        mock_socket = Mock()
        mock_socket.getsockname.return_value = ("localhost", 8080)
        mock_asyncio_server.sockets = [mock_socket]
        mock_asyncio_server.serve_forever = AsyncMock()
        mock_asyncio_server.__aenter__.return_value = mock_asyncio_server
        mock_asyncio_server.__aexit__.return_value = None

        with patch(
            "asyncio.start_server", new=AsyncMock(return_value=mock_asyncio_server)
        ):

            task = asyncio.create_task(server.start())
            await asyncio.sleep(0.01)
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            assert server.running is True

    @pytest.mark.asyncio
    async def test_stop(self, server):
        server.running = True

        mock_service_task = Mock()
        mock_service_task.cancel = Mock()

        await server.stop()

        assert server.running is False

    @pytest.mark.asyncio
    async def test_stop_no_tasks(self, server):
        server.running = True
        server.service_task = None
        server.server = None

        await server.stop()

        assert server.running is False

    @pytest.mark.asyncio
    async def test_send_startup_complete(self, server):
        message = {"type": "lifespan.startup.complete"}

        await server.send(message)

        assert server.startup_event.is_set()
        assert server.startup_failed is False

    @pytest.mark.asyncio
    async def test_send_startup_failed(self, server):
        message = {"type": "lifespan.startup.failed", "message": "Startup failed"}

        await server.send(message)

        assert server.startup_event.is_set()
        assert server.startup_failed is True

    @pytest.mark.asyncio
    async def test_send_startup_failed_no_message(self, server):
        message = {"type": "lifespan.startup.failed"}

        await server.send(message)

        assert server.startup_event.is_set()
        assert server.startup_failed is True

    @pytest.mark.asyncio
    async def test_send_shutdown_complete(self, server):
        message = {"type": "lifespan.shutdown.complete"}

        await server.send(message)

        assert server.shutdown_event.is_set()
        assert server.shutdown_failed is False

    @pytest.mark.asyncio
    async def test_send_shutdown_failed(self, server):
        message = {"type": "lifespan.shutdown.failed", "message": "Shutdown failed"}

        await server.send(message)

        assert server.shutdown_event.is_set()
        assert server.shutdown_failed is True

    @pytest.mark.asyncio
    async def test_send_shutdown_failed_no_message(self, server):
        message = {"type": "lifespan.shutdown.failed"}

        await server.send(message)

        assert server.shutdown_event.is_set()
        assert server.shutdown_failed is True

    @pytest.mark.asyncio
    async def test_send_invalid_message_type(self, server):
        message = {"type": "invalid.type"}

        with pytest.raises(AssertionError):
            await server.send(message)

    @pytest.mark.asyncio
    async def test_receive(self, server):
        test_message = {"type": "test", "data": "test_data"}
        await server.receive_queue.put(test_message)

        result = await server.receive()

        assert result == test_message


class TestExchangerWrapper:

    @pytest.fixture
    def mock_exc(self):
        exc = Mock()
        exc.processEvent = Mock()
        exc.cues = Mock()
        exc.cues.popleft = Mock()
        exc.some_attribute = "test_value"
        return exc

    @pytest.fixture
    def mock_app(self):
        app = Mock()
        app.assign_writer = Mock()
        app.not_found = AsyncMock()
        return app

    @pytest.fixture
    def mock_writer(self):
        return Mock()

    @pytest.fixture
    def wrapper(self, mock_exc, mock_app, mock_writer):
        return ExchangerWrapper(mock_exc, mock_app, mock_writer)

    def test_init(self, mock_exc, mock_app, mock_writer):
        wrapper = ExchangerWrapper(mock_exc, mock_app, mock_writer)
        assert wrapper._exc == mock_exc
        assert wrapper.app == mock_app
        assert wrapper.writer == mock_writer

    def test_getattr(self, wrapper, mock_exc):
        result = wrapper.some_attribute
        assert result == "test_value"

        del mock_exc.some_attribute
        with pytest.raises(AttributeError):
            wrapper.some_attribute

    @pytest.mark.asyncio
    async def test_processEvent_no_cues(self, wrapper, mock_exc, mock_app, mock_writer):
        mock_serder = Mock()
        mock_serder.said = "test_said"
        mock_exc.cues = []

        wrapper.processEvent(mock_serder)

        mock_app.assign_writer.assert_called_once_with("test_said", writer=mock_writer)
        mock_exc.processEvent.assert_called_once_with(mock_serder, None, None)

    @pytest.mark.asyncio
    async def test_processEvent_with_optional_args(
        self, wrapper, mock_exc, mock_app, mock_writer
    ):
        mock_serder = Mock()
        mock_serder.said = "test_said"
        mock_exc.cues = []

        wrapper.processEvent(
            mock_serder, tsgs="test_tsgs", cigars="test_cigars", extra_arg="test"
        )

        mock_app.assign_writer.assert_called_once_with("test_said", writer=mock_writer)
        mock_exc.processEvent.assert_called_once_with(
            mock_serder, "test_tsgs", "test_cigars", extra_arg="test"
        )

    @pytest.mark.asyncio
    async def test_processEvent_with_not_found_cue(
        self, wrapper, mock_exc, mock_app, mock_writer
    ):
        mock_serder = Mock()
        mock_serder.said = "test_said"

        from collections import deque

        mock_cues = deque([{"kin": "notFound"}])
        mock_exc.cues = mock_cues

        with patch("asyncio.create_task") as mock_create_task:
            wrapper.processEvent(mock_serder)

            mock_app.assign_writer.assert_called_once_with(
                "test_said", writer=mock_writer
            )
            mock_exc.processEvent.assert_called_once_with(mock_serder, None, None)
            mock_create_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_processEvent_with_other_cue(
        self, wrapper, mock_exc, mock_app, mock_writer
    ):
        mock_serder = Mock()
        mock_serder.said = "test_said"

        from collections import deque

        mock_cues = deque([{"kin": "other"}])
        mock_exc.cues = mock_cues

        with patch("asyncio.create_task") as mock_create_task:
            wrapper.processEvent(mock_serder)

            mock_app.assign_writer.assert_called_once_with(
                "test_said", writer=mock_writer
            )
            mock_exc.processEvent.assert_called_once_with(mock_serder, None, None)
            mock_create_task.assert_not_called()

    @pytest.mark.asyncio
    async def test_processEvent_multiple_cues(
        self, wrapper, mock_exc, mock_app, mock_writer
    ):
        mock_serder = Mock()
        mock_serder.said = "test_said"

        from collections import deque

        mock_cues = deque([{"kin": "notFound"}, {"kin": "other"}, {"kin": "notFound"}])
        mock_exc.cues = mock_cues

        with patch("asyncio.create_task") as mock_create_task:
            wrapper.processEvent(mock_serder)

            mock_app.assign_writer.assert_called_once_with(
                "test_said", writer=mock_writer
            )
            mock_exc.processEvent.assert_called_once_with(mock_serder, None, None)
            assert mock_create_task.call_count == 2


class TestRunServer:

    @pytest.mark.asyncio
    async def test_run_server(self):
        mock_app = Mock(spec=Rack)

        with patch("kept.core.tcp.server.KERITCPServer") as mock_server_class:
            mock_server_instance = AsyncMock()
            mock_server_class.return_value = mock_server_instance

            await run_server(mock_app, "test_host", 9999)

            mock_server_class.assert_called_once_with(mock_app, "test_host", 9999)
            mock_server_instance.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_server_defaults(self):
        mock_app = Mock(spec=Rack)

        with patch("kept.core.tcp.server.KERITCPServer") as mock_server_class:
            mock_server_instance = AsyncMock()
            mock_server_class.return_value = mock_server_instance

            await run_server(mock_app)

            mock_server_class.assert_called_once_with(mock_app, "localhost", 8080)
            mock_server_instance.start.assert_called_once()
