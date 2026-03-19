import asyncio
from unittest.mock import Mock, AsyncMock, patch

import pytest
from httpx import URL

from kept.core.authentication import CryptSigner
from kept.essr.client.client import AsyncClient
from kept.essr.client.responses import Response


class TestAsyncClient:

    @pytest.fixture
    def mock_crypt_signer(self):
        """Mock CryptSigner object"""
        signer = Mock(spec=CryptSigner)
        signer.hby = Mock()
        signer.encode = Mock(return_value=b"encoded_request")
        signer.encryption_target = "adb123"
        return signer

    @pytest.fixture
    def client(self):
        """Create AsyncClient instance with default parameters"""
        return AsyncClient(
            params={"param1": "value1"},
            return_route="/test",
            headers={"header1": "value1"},
            timeout=5,
            base_url="https://example.com",
        )

    def test_init_with_all_params(self):
        """Test AsyncClient initialization with all parameters"""
        params = {"test": "param"}
        headers = {"test": "header"}
        client = AsyncClient(
            params=params,
            return_route="/custom",
            headers=headers,
            timeout=15,
            base_url="https://test.com/api",
        )

        assert client.params == params
        assert client.return_route == "/custom"
        assert client.headers == headers
        assert client.timeout == 15
        assert client.base_url.raw_path == URL("https://test.com/api/").raw_path
        assert client._client is None

    def test_init_with_defaults(self):
        """Test AsyncClient initialization with default values"""
        client = AsyncClient()

        assert client.params is None
        assert client.return_route == "/"
        assert client.headers is None
        assert client.timeout == 10
        assert client.base_url.raw_path == URL("/").raw_path
        assert client._client is None

    def test_init_empty_return_route(self):
        """Test AsyncClient initialization with empty return_route"""
        client = AsyncClient(return_route="")
        assert client.return_route == "/"

    def test_base_url_property(self, client):
        """Test base_url property returns correct URL"""
        assert client.base_url.raw_path == URL("https://example.com/").raw_path

    def test_enforce_trailing_slash(self):
        """Test _enforce_trailing_slash static method"""
        url_without_slash = URL("https://example.com")
        url_with_slash = AsyncClient._enforce_trailing_slash(url_without_slash)
        assert url_with_slash.raw_path == URL("https://example.com/").raw_path

        url_already_with_slash = URL("https://example.com/")
        result = AsyncClient._enforce_trailing_slash(url_already_with_slash)
        assert result == URL("https://example.com/")

    def test_merge_url_absolute(self, client):
        """Test _merge_url with absolute URL"""
        absolute_url = "https://other.com/path"
        result = client._merge_url(absolute_url)
        assert result == URL("https://other.com/path")

    def test_merge_url_relative(self, client):
        """Test _merge_url with relative URL"""
        relative_url = "/api/endpoint"
        result = client._merge_url(relative_url)
        assert result == URL("https://example.com/api/endpoint")

    def test_merge_url_relative_no_leading_slash(self, client):
        """Test _merge_url with relative URL without leading slash"""
        relative_url = "api/endpoint"
        result = client._merge_url(relative_url)
        assert result == URL("https://example.com/api/endpoint")

    def test_merge_headers_with_none(self):
        """Test _merge_headers when client headers are None"""
        client = AsyncClient(headers=None)
        headers = {"new": "header"}
        result = client._merge_headers(headers)
        assert result == {"new": "header"}

    def test_merge_headers_with_existing(self, client):
        """Test _merge_headers with existing headers"""
        headers = {"new": "header", "header1": "overridden"}
        result = client._merge_headers(headers)
        assert result == {"header1": "overridden", "new": "header"}

    def test_merge_headers_with_none_input(self, client):
        """Test _merge_headers with None input"""
        result = client._merge_headers(None)
        assert result == {"header1": "value1"}

    def test_merge_queryparams_with_both(self, client):
        """Test _merge_queryparams with both client and method params"""
        params = {"new": "param", "param1": "overridden"}
        result = client._merge_queryparams(params)
        assert result == {"param1": "overridden", "new": "param"}

    def test_merge_queryparams_with_none_client(self):
        """Test _merge_queryparams when client params are None"""
        client = AsyncClient(params=None)
        params = {"test": "param"}
        result = client._merge_queryparams(params)
        assert result == {"test": "param"}

    def test_merge_queryparams_with_none_input(self, client):
        """Test _merge_queryparams with None input"""
        result = client._merge_queryparams(None)
        assert result == {"param1": "value1"}

    def test_merge_queryparams_both_none(self):
        """Test _merge_queryparams when both are None"""
        client = AsyncClient(params=None)
        result = client._merge_queryparams(None)
        assert result is None

    @patch("kept.essr.client.client.requests")
    def test_build_request_success(self, mock_requests, client, mock_crypt_signer):
        """Test _build_request method success"""
        url = URL("https://example.com/api/test")
        target = "test_target"

        mock_requests.http.return_value = {"request": "data"}

        result = client._build_request(
            crypt_signer=mock_crypt_signer,
            url=url,
            target=target,
            return_route="/custom",
            json='{"test": "json"}',
            data="test_data",
            params={"extra": "param"},
            headers={"extra": "header"},
        )

        assert result == b"encoded_request"

        mock_requests.http.assert_called_once_with(
            hostname="example.com",
            port=None,
            path="/api/test",
            params={"param1": "value1", "extra": "param"},
            return_route="/custom",
            json='{"test": "json"}',
            files=None,
            data="test_data",
            headers={"header1": "value1", "extra": "header"},
        )

        mock_crypt_signer.encode.assert_called_once_with(
            "/api/test", {"request": "data"}, target
        )

    @patch("kept.essr.client.client.requests")
    def test_build_request_exception(self, mock_requests, client, mock_crypt_signer):
        """Test _build_request method with exception"""
        url = URL("https://example.com/api/test")

        mock_requests.http.side_effect = Exception("Test error")

        with patch("kept.essr.client.client.logger") as mock_logger:
            result = client._build_request(
                crypt_signer=mock_crypt_signer,
                url=url,
                target="target",
                return_route="/test",
            )

        assert result is None
        mock_logger.error.assert_called_once_with("Error building request: Test error")

    @pytest.mark.asyncio
    @patch("kept.essr.client.client.AsyncTCPClient")
    async def test_request_success(
        self, mock_tcp_client_class, client, mock_crypt_signer
    ):
        """Test request method successful execution"""
        # Setup mocks
        mock_tcp_client = AsyncMock()
        mock_tcp_client.connect.return_value = True
        mock_tcp_client.send.return_value = True
        mock_tcp_client.disconnect = AsyncMock()
        mock_tcp_client_class.return_value = mock_tcp_client

        Response("sender", {"body": "payload", "headers": [(b"test", b"header")]})

        with patch.object(client, "_build_request", return_value=b"request_data"):
            with patch.object(
                client,
                "_read_and_parse",
                return_value=(
                    "sender",
                    {"body": "payload", "headers": [(b"test", b"header")]},
                ),
            ):
                with patch("kept.essr.client.client.logger") as mock_logger:
                    result = await client.request(
                        crypt_signer=mock_crypt_signer,
                        url="/api/test",
                        target="test_target",
                        headers=[("custom", "header")],
                        json='{"test": "json"}',
                        data="test_data",
                    )

        assert isinstance(result, Response)
        assert result.sender == "sender"
        assert result._payload == {"body": "payload", "headers": [(b"test", b"header")]}

        mock_tcp_client_class.assert_called_once_with("example.com", None)
        mock_tcp_client.connect.assert_called_once()
        mock_tcp_client.send.assert_called_once_with(b"request_data")
        mock_tcp_client.disconnect.assert_called_once()

        mock_logger.info.assert_any_call("Response received and processed.")

    @pytest.mark.asyncio
    @patch("kept.essr.client.client.AsyncTCPClient")
    async def test_request_connect_failure(
        self, mock_tcp_client_class, client, mock_crypt_signer
    ):
        """Test request method when connection fails"""
        mock_tcp_client = AsyncMock()
        mock_tcp_client.connect.return_value = False
        mock_tcp_client.disconnect = AsyncMock()
        mock_tcp_client_class.return_value = mock_tcp_client

        with patch.object(client, "_build_request", return_value=b"request_data"):
            with patch("kept.essr.client.client.logger") as mock_logger:
                with pytest.raises(
                    ConnectionError, match="Failed to connect to example.com:None"
                ):
                    await client.request(
                        crypt_signer=mock_crypt_signer, url="/api/test"
                    )

        mock_tcp_client.connect.assert_called_once()
        mock_tcp_client.disconnect.assert_called_once()
        mock_logger.error.assert_called_with("Failed to connect to example.com:None")

    @pytest.mark.asyncio
    @patch("kept.essr.client.client.AsyncTCPClient")
    async def test_request_send_failure(
        self, mock_tcp_client_class, client, mock_crypt_signer
    ):
        """Test request method when send fails"""
        mock_tcp_client = AsyncMock()
        mock_tcp_client.connect.return_value = True
        mock_tcp_client.send.return_value = False
        mock_tcp_client.disconnect = AsyncMock()
        mock_tcp_client_class.return_value = mock_tcp_client

        with patch.object(client, "_build_request", return_value=b"request_data"):
            with patch("kept.essr.client.client.logger") as mock_logger:
                with pytest.raises(
                    ConnectionError, match="Failed to send request to example.com:None"
                ):
                    await client.request(
                        crypt_signer=mock_crypt_signer, url="/api/test"
                    )

        mock_tcp_client.connect.assert_called_once()
        mock_tcp_client.send.assert_called_once_with(b"request_data")
        mock_tcp_client.disconnect.assert_called_once()
        mock_logger.error.assert_called_with(
            "Failed to send request to example.com:None"
        )

    @pytest.mark.asyncio
    @patch("kept.essr.client.client.AsyncTCPClient")
    async def test_request_timeout(
        self, mock_tcp_client_class, client, mock_crypt_signer
    ):
        """Test request method with timeout"""
        mock_tcp_client = AsyncMock()
        mock_tcp_client.connect.return_value = True
        mock_tcp_client.send.return_value = True
        mock_tcp_client.disconnect = AsyncMock()
        mock_tcp_client_class.return_value = mock_tcp_client

        async def slow_read_and_parse(*args):
            await asyncio.sleep(10)  # Longer than timeout
            return ("sender", {"test": "payload"})

        with patch.object(client, "_build_request", return_value=b"request_data"):
            with patch.object(
                client, "_read_and_parse", side_effect=slow_read_and_parse
            ):
                with patch("kept.essr.client.client.logger") as mock_logger:
                    with pytest.raises(
                        TimeoutError,
                        match="Timeout after 5 seconds waiting for response",
                    ):
                        await client.request(
                            crypt_signer=mock_crypt_signer, url="/api/test"
                        )

        mock_tcp_client.disconnect.assert_called_once()
        mock_logger.error.assert_called_with(
            "Timeout after 5 seconds waiting for response"
        )

    @pytest.mark.asyncio
    @patch("kept.essr.client.client.handlers")
    @patch("kept.essr.client.client.exchanging")
    @patch("kept.essr.client.client.parsing")
    async def test_read_and_parse_success(
        self, mock_parsing, mock_exchanging, mock_handlers, client, mock_crypt_signer
    ):
        """Test _read_and_parse method successful execution"""
        # Setup mocks
        mock_handler = Mock()
        mock_handler.sender = None  # Initially None
        mock_handler.payload = {"test": "payload"}
        mock_handlers.ESSRHandler.return_value = mock_handler

        mock_exchanger = Mock()
        mock_exchanging.Exchanger.return_value = mock_exchanger

        # Create mock parsator generator that sets handler.sender after first call
        def parsator_generator():
            # First next() call processes data and sets sender
            mock_handler.sender = "test_sender"
            yield
            # Second call raises StopIteration to break the loop

        mock_parsator = parsator_generator()

        mock_parser = Mock()
        mock_parser.onceParsator.return_value = mock_parsator
        mock_parsing.Parser.return_value = mock_parser

        mock_tcp_client = AsyncMock()
        # is_connected returns True twice, then False
        # handler.sender is None initially, then "test_sender" after first iteration
        mock_tcp_client.is_connected.side_effect = [
            True,
            True,
            False,
        ]
        mock_tcp_client.receive.side_effect = [
            b"data" * 1024,
            b"data2",
        ]  # First full buffer, then partial
        client._client = mock_tcp_client

        result = await client._read_and_parse(mock_crypt_signer.hby, mock_crypt_signer)

        assert result == ("test_sender", {"test": "payload"})

        # Verify exchanger creation
        mock_exchanging.Exchanger.assert_called_once_with(
            hby=mock_crypt_signer.hby, handlers=[mock_handler]
        )

        # Verify parser creation and onceParsator call
        mock_parsing.Parser.assert_called_once_with(framed=True, exc=mock_exchanger)
        mock_parser.onceParsator.assert_called_once()

        # Verify TCP client interactions
        assert mock_tcp_client.receive.call_count == 1
        mock_tcp_client.receive.assert_called_with(4096)

    @pytest.mark.asyncio
    async def test_read_and_parse_exception(self, client, mock_crypt_signer):
        """Test _read_and_parse method with exception during receive"""
        mock_tcp_client = AsyncMock()
        mock_tcp_client.is_connected.return_value = True
        mock_tcp_client.receive.side_effect = Exception("Receive error")
        client._client = mock_tcp_client

        response_received = AsyncMock()
        response_received.is_set = Mock(return_value=False)

        with patch("asyncio.Event", return_value=response_received):
            with patch("kept.essr.client.client.logger") as mock_logger:
                result = await client._read_and_parse(
                    mock_crypt_signer.hby, mock_crypt_signer
                )

        assert result is None
        mock_logger.error.assert_called_with(
            "Error reading/parsing data: Receive error"
        )

    @pytest.mark.asyncio
    async def test_close_with_client(self, client):
        """Test close method when client exists"""
        mock_tcp_client = AsyncMock()
        client._client = mock_tcp_client

        await client.close()

        mock_tcp_client.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_without_client(self, client):
        """Test close method when client is None"""
        client._client = None

        # Should not raise an error
        await client.close()

    @pytest.mark.asyncio
    async def test_async_context_manager(self, client):
        """Test AsyncClient as async context manager"""
        mock_tcp_client = AsyncMock()

        async with client as c:
            assert c is client
            c._client = mock_tcp_client

        # close() should be called on exit
        mock_tcp_client.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_context_manager_with_exception(self, client):
        """Test AsyncClient context manager with exception"""
        mock_tcp_client = AsyncMock()

        try:
            async with client as c:
                c._client = mock_tcp_client
                raise ValueError("Test exception")
        except ValueError:
            pass

        # close() should still be called on exception
        mock_tcp_client.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_context_manager_no_client(self, client):
        """Test AsyncClient context manager when no client is set"""
        try:
            async with client as c:
                assert c is client
                # Don't set _client
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Should not raise an error even if _client is None


class TestAsyncClientIntegration:
    """Integration-style tests that test multiple methods together"""

    @pytest.mark.asyncio
    @patch("kept.essr.client.client.AsyncTCPClient")
    @patch("kept.essr.client.client.requests")
    async def test_full_request_flow(self, mock_requests, mock_tcp_client_class):
        """Test complete request flow from start to finish"""
        # Setup
        client = AsyncClient(
            base_url="https://api.example.com",
            headers=[(b"Authorization", b"Bearer token")],
            timeout=10,
        )

        mock_crypt_signer = Mock(spec=CryptSigner)
        mock_crypt_signer.hby = Mock()
        mock_crypt_signer.encode.return_value = b"encoded_request_data"

        # Mock TCP client
        mock_tcp_client = AsyncMock()
        mock_tcp_client.connect.return_value = True
        mock_tcp_client.send.return_value = True
        mock_tcp_client.disconnect = AsyncMock()
        mock_tcp_client_class.return_value = mock_tcp_client

        # Mock requests module
        mock_requests.http.return_value = {"http": "request"}

        # Mock response parsing
        expected_response = (
            "test_sender",
            {"status": 200, "body": b"response", "headers": [(b"test", b"header")]},
        )

        with patch.object(client, "_read_and_parse", return_value=expected_response):
            result = await client.request(
                crypt_signer=mock_crypt_signer,
                url="/api/endpoint",
                target="encryption_target",
                json='{"data": "test"}',
                headers=[(b"Custom", b"header")],
            )

        # Verify the full flow
        assert isinstance(result, Response)
        assert result.sender == "test_sender"

        # Verify URL merging worked correctly
        mock_tcp_client_class.assert_called_once_with("api.example.com", None)

        # Verify request building
        mock_requests.http.assert_called_once()
        call_args = mock_requests.http.call_args
        assert call_args[1]["hostname"] == "api.example.com"
        assert call_args[1]["path"] == "/api/endpoint"
        assert call_args[1]["json"] == '{"data": "test"}'
        assert call_args[1]["headers"]["authorization"] == "Bearer token"
        assert call_args[1]["headers"]["custom"] == "header"

        # Verify encoding
        mock_crypt_signer.encode.assert_called_once_with(
            "/api/endpoint", {"http": "request"}, "encryption_target"
        )

        # Verify TCP operations
        mock_tcp_client.connect.assert_called_once()
        mock_tcp_client.send.assert_called_once_with(b"encoded_request_data")
        mock_tcp_client.disconnect.assert_called_once()
