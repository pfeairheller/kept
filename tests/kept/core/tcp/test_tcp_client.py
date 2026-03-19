import asyncio
import pytest
from unittest.mock import Mock, AsyncMock, patch

from kept.core.tcp.client import AsyncTCPClient


class TestAsyncTCPClient:

    @pytest.fixture
    def client(self):
        return AsyncTCPClient("localhost", 8080)

    def test_init(self):
        client = AsyncTCPClient("test_host", 9999)
        assert client.host == "test_host"
        assert client.port == 9999
        assert client.reader is None
        assert client.writer is None
        assert client.connected is False

    @pytest.mark.asyncio
    async def test_connect_success(self, client):
        mock_reader = AsyncMock()
        mock_writer = Mock()

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            result = await client.connect()

            assert result is True
            assert client.connected is True
            assert client.reader == mock_reader
            assert client.writer == mock_writer

    @pytest.mark.asyncio
    async def test_connect_failure(self, client):
        with patch(
            "asyncio.open_connection",
            side_effect=ConnectionRefusedError("Connection refused"),
        ):
            result = await client.connect()

            assert result is False
            assert client.connected is False
            assert client.reader is None
            assert client.writer is None

    @pytest.mark.asyncio
    async def test_connect_general_exception(self, client):
        with patch("asyncio.open_connection", side_effect=Exception("General error")):
            result = await client.connect()

            assert result is False
            assert client.connected is False

    @pytest.mark.asyncio
    async def test_disconnect(self, client):
        mock_writer = Mock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()

        client.writer = mock_writer
        client.connected = True
        client.reader = AsyncMock()

        await client.disconnect()

        mock_writer.close.assert_called_once()
        mock_writer.wait_closed.assert_called_once()
        assert client.connected is False
        assert client.reader is None
        assert client.writer is None

    @pytest.mark.asyncio
    async def test_disconnect_no_writer(self, client):
        client.connected = True
        client.reader = AsyncMock()
        client.writer = None

        await client.disconnect()

        assert client.connected is False
        assert client.reader is None
        assert client.writer is None

    @pytest.mark.asyncio
    async def test_send_success(self, client):
        mock_writer = Mock()
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()

        client.connected = True
        client.writer = mock_writer

        test_data = b"test data"
        result = await client.send(test_data)

        assert result is True
        mock_writer.write.assert_called_once_with(test_data)
        mock_writer.drain.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_not_connected(self, client):
        client.connected = False

        result = await client.send(b"test data")

        assert result is False

    @pytest.mark.asyncio
    async def test_send_no_writer(self, client):
        client.connected = True
        client.writer = None

        result = await client.send(b"test data")

        assert result is False

    @pytest.mark.asyncio
    async def test_send_exception(self, client):
        mock_writer = Mock()
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock(
            side_effect=ConnectionResetError("Connection reset")
        )

        client.connected = True
        client.writer = mock_writer

        result = await client.send(b"test data")

        assert result is False

    @pytest.mark.asyncio
    async def test_receive_success(self, client):
        mock_reader = AsyncMock()
        test_data = b"received data"
        mock_reader.read.return_value = test_data

        client.connected = True
        client.reader = mock_reader

        result = await client.receive()

        assert result == test_data
        mock_reader.read.assert_called_once_with(4096)

    @pytest.mark.asyncio
    async def test_receive_custom_buffer_size(self, client):
        mock_reader = AsyncMock()
        test_data = b"received data"
        mock_reader.read.return_value = test_data

        client.connected = True
        client.reader = mock_reader

        result = await client.receive(8192)

        assert result == test_data
        mock_reader.read.assert_called_once_with(8192)

    @pytest.mark.asyncio
    async def test_receive_empty_data(self, client):
        mock_reader = AsyncMock()
        mock_reader.read.return_value = b""

        client.connected = True
        client.reader = mock_reader

        result = await client.receive()

        assert result == b""

    @pytest.mark.asyncio
    async def test_receive_not_connected(self, client):
        client.connected = False

        result = await client.receive()

        assert result is None

    @pytest.mark.asyncio
    async def test_receive_no_reader(self, client):
        client.connected = True
        client.reader = None

        result = await client.receive()

        assert result is None

    @pytest.mark.asyncio
    async def test_receive_exception(self, client):
        mock_reader = AsyncMock()
        mock_reader.read.side_effect = ConnectionResetError("Connection reset")

        client.connected = True
        client.reader = mock_reader

        result = await client.receive()

        assert result is None

    @pytest.mark.asyncio
    async def test_receive_all_with_expected_size(self, client):
        mock_reader = AsyncMock()
        test_data = b"exact data"
        mock_reader.readexactly.return_value = test_data

        client.connected = True
        client.reader = mock_reader

        result = await client.receive_all(10)

        assert result == test_data
        mock_reader.readexactly.assert_called_once_with(10)

    @pytest.mark.asyncio
    async def test_receive_all_without_expected_size(self, client):
        mock_reader = AsyncMock()
        test_data = b"all available data"
        mock_reader.read.return_value = test_data

        client.connected = True
        client.reader = mock_reader

        result = await client.receive_all()

        assert result == test_data
        mock_reader.read.assert_called_once_with(-1)

    @pytest.mark.asyncio
    async def test_receive_all_empty_data(self, client):
        mock_reader = AsyncMock()
        mock_reader.read.return_value = b""

        client.connected = True
        client.reader = mock_reader

        result = await client.receive_all()

        assert result == b""

    @pytest.mark.asyncio
    async def test_receive_all_not_connected(self, client):
        client.connected = False

        result = await client.receive_all()

        assert result is None

    @pytest.mark.asyncio
    async def test_receive_all_no_reader(self, client):
        client.connected = True
        client.reader = None

        result = await client.receive_all()

        assert result is None

    @pytest.mark.asyncio
    async def test_receive_all_exception(self, client):
        mock_reader = AsyncMock()
        mock_reader.read.side_effect = ConnectionResetError("Connection reset")

        client.connected = True
        client.reader = mock_reader

        result = await client.receive_all()

        assert result is None

    @pytest.mark.asyncio
    async def test_receive_all_readexactly_exception(self, client):
        mock_reader = AsyncMock()
        mock_reader.readexactly.side_effect = asyncio.IncompleteReadError(
            b"partial", 10
        )

        client.connected = True
        client.reader = mock_reader

        result = await client.receive_all(10)

        assert result is None

    @pytest.mark.asyncio
    async def test_send_and_receive_success(self, client):
        mock_writer = Mock()
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()

        mock_reader = AsyncMock()
        test_response = b"response data"
        mock_reader.read.return_value = test_response

        client.connected = True
        client.writer = mock_writer
        client.reader = mock_reader

        test_data = b"request data"
        result = await client.send_and_receive(test_data)

        assert result == test_response
        mock_writer.write.assert_called_once_with(test_data)
        mock_reader.read.assert_called_once_with(4096)

    @pytest.mark.asyncio
    async def test_send_and_receive_custom_response_size(self, client):
        mock_writer = Mock()
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()

        mock_reader = AsyncMock()
        test_response = b"response data"
        mock_reader.read.return_value = test_response

        client.connected = True
        client.writer = mock_writer
        client.reader = mock_reader

        test_data = b"request data"
        result = await client.send_and_receive(test_data, 8192)

        assert result == test_response
        mock_reader.read.assert_called_once_with(8192)

    @pytest.mark.asyncio
    async def test_send_and_receive_send_fails(self, client):
        mock_writer = Mock()
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock(
            side_effect=ConnectionResetError("Connection reset")
        )

        client.connected = True
        client.writer = mock_writer

        result = await client.send_and_receive(b"test data")

        assert result is None

    def test_is_connected_true(self, client):
        mock_writer = Mock()
        mock_writer.is_closing.return_value = False

        client.connected = True
        client.writer = mock_writer

        assert client.is_connected() is True

    def test_is_connected_false_not_connected(self, client):
        client.connected = False

        assert client.is_connected() is False

    def test_is_connected_false_no_writer(self, client):
        client.connected = True
        client.writer = None

        assert client.is_connected() is False

    def test_is_connected_false_writer_closing(self, client):
        mock_writer = Mock()
        mock_writer.is_closing.return_value = True

        client.connected = True
        client.writer = mock_writer

        assert client.is_connected() is False

    @pytest.mark.asyncio
    async def test_async_context_manager_success(self):
        mock_reader = AsyncMock()
        mock_writer = Mock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            async with AsyncTCPClient("localhost", 8080) as client:
                assert client.connected is True
                assert client.reader == mock_reader
                assert client.writer == mock_writer

            mock_writer.close.assert_called_once()
            mock_writer.wait_closed.assert_called_once()
            assert client.connected is False

    @pytest.mark.asyncio
    async def test_async_context_manager_connection_failure(self):
        with patch(
            "asyncio.open_connection",
            side_effect=ConnectionRefusedError("Connection refused"),
        ):
            async with AsyncTCPClient("localhost", 8080) as client:
                assert client.connected is False
                assert client.reader is None
                assert client.writer is None

    @pytest.mark.asyncio
    async def test_async_context_manager_exception_in_context(self):
        mock_reader = AsyncMock()
        mock_writer = Mock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            try:
                async with AsyncTCPClient("localhost", 8080) as client:
                    assert client.connected is True
                    raise ValueError("Test exception")
            except ValueError:
                pass

            mock_writer.close.assert_called_once()
            mock_writer.wait_closed.assert_called_once()
            assert client.connected is False

    @pytest.mark.asyncio
    async def test_integration_full_workflow(self):
        mock_reader = AsyncMock()
        mock_writer = Mock()
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.is_closing.return_value = False

        test_response = b"server response"
        mock_reader.read.return_value = test_response

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            client = AsyncTCPClient("localhost", 8080)

            # Test connection
            connected = await client.connect()
            assert connected is True
            assert client.is_connected() is True

            # Test sending data
            sent = await client.send(b"hello server")
            assert sent is True

            # Test receiving data
            received = await client.receive()
            assert received == test_response

            # Test send and receive
            response = await client.send_and_receive(b"request", 1024)
            assert response == test_response

            # Test disconnection
            await client.disconnect()
            assert client.connected is False
            assert not client.is_connected()
