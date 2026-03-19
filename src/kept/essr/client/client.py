# -*- encoding: utf-8 -*-
"""
HEKI
kept.essr.client package

"""

import asyncio
import logging
from httpx import Headers, QueryParams, URL

from keri.core import parsing
from keri.peer import exchanging

from . import requests, Response
from . import handlers
from ...core.authentication import CryptSigner

from ...core.tcp.client import AsyncTCPClient, TCPClient

logger = logging.getLogger(__name__)


class AsyncClient:
    """AsyncIO client for connecting to an ESSR server and sending/receiving data."""

    def __init__(
        self,
        *,
        params: dict | None = None,
        return_route: str = "/",
        headers: list | None = None,
        timeout: int = 10,
        base_url: URL | str = "",
    ):
        self.params = params
        self.return_route = return_route if return_route else "/"
        self.files = None  # TODO: support files from the commandline, maybe?
        self.headers = headers
        self.timeout = timeout
        self._base_url = self._enforce_trailing_slash(URL(base_url))

        # Create event and client
        self._client = None

    @property
    def base_url(self) -> URL:
        """
        Base URL to use when sending requests with relative URLs.
        """
        return self._base_url

    async def request(
        self,
        crypt_signer: CryptSigner,
        url: URL | str,
        target: str = None,
        headers: list = None,
        json: dict = None,
        data: bytes = None,
        files=None,
    ):

        url = self._merge_url(url)

        request = self._build_request(
            crypt_signer=crypt_signer,
            url=url,
            target=target,
            return_route=self.return_route,
            json=json,
            data=data,
            params=self.params,
            headers=headers,
        )

        self._client = AsyncTCPClient(url.host, url.port)

        try:
            # Connect to the server
            if await self._client.connect():
                # Send the request
                if await self._client.send(request):
                    logger.debug(f"Request sent successfully to {url.host}:{url.port}")

                    # Wait for response or timeout
                    try:
                        sender, payload = await asyncio.wait_for(
                            self._read_and_parse(crypt_signer.hby, crypt_signer),
                            timeout=self.timeout,
                        )
                        logger.info("Response received and processed.")

                        return Response(sender, payload)

                    except asyncio.TimeoutError:
                        logger.error(
                            f"Timeout after {self.timeout} seconds waiting for response"
                        )
                        raise TimeoutError(
                            f"Timeout after {self.timeout} seconds waiting for response"
                        )
                else:
                    logger.error(f"Failed to send request to {url.host}:{url.port}")
                    raise ConnectionError(
                        f"Failed to send request to {url.host}:{url.port}"
                    )

            else:
                logger.error(f"Failed to connect to {url.host}:{url.port}")
                raise ConnectionError(f"Failed to connect to {url.host}:{url.port}")
        finally:
            # Ensure client is disconnected
            await self._client.disconnect()

    async def close(self):
        if self._client:
            await self._client.disconnect()

    def _build_request(
        self,
        crypt_signer: CryptSigner,
        url: URL | str,
        target: str,
        return_route: str,
        json: dict = None,
        data: bytes = None,
        params: dict = None,
        headers: dict = None,
    ):

        try:
            # Make the request
            base_request = requests.http(
                hostname=url.host,
                port=url.port,
                path=url.path,
                params=self._merge_queryparams(params),
                return_route=return_route if return_route else self.return_route,
                json=json,
                files=None,  # TODO: support files from the commandline, maybe?
                data=data,
                headers=self._merge_headers(headers),
            )

            request = crypt_signer.encode(url.path, base_request, target)
            return request
        except Exception as e:
            logger.error(f"Error building request: {e}")
            return None

    async def _read_and_parse(self, hby, crypt_signer):
        """Background task to read all data from client and parse it"""
        response_received = asyncio.Event()

        handler = handlers.ESSRHandler(
            crypt_signer, self.return_route, response_received
        )
        exc = exchanging.Exchanger(hby=hby, handlers=[handler])
        parser = parsing.Parser(framed=True, exc=exc)
        ims = bytearray()

        parsator = parser.onceParsator(ims=ims, exc=exc)

        while (
            self._client.is_connected()
            and not response_received.is_set()
            and not handler.sender
        ):
            try:
                buf = await self._client.receive(4096)
                if not buf:
                    break

                ims.extend(buf)
                try:
                    next(parsator)
                except StopIteration:
                    break

            except Exception as e:
                logger.error(f"Error reading/parsing data: {e}")
                return None

        if not handler.sender:
            raise ConnectionError("Failed to read response.")

        return (
            handler.sender,
            handler.payload,
        )

    def _merge_queryparams(self, params):
        if params or self.params:
            merged_queryparams = QueryParams(self.params)
            merged_queryparams = merged_queryparams.merge(params)
            return dict(merged_queryparams)

        else:
            return None

    def _merge_headers(self, headers):
        merged_headers = Headers(self.headers)
        merged_headers.update(headers)

        return dict(merged_headers)

    def _merge_url(self, url: URL | str) -> URL:
        """
        Merge a URL argument together with any 'base_url' on the client,
        to create the URL used for the outgoing request.
        """
        merge_url = URL(url)
        if merge_url.is_relative_url:
            # To merge URLs we always append t`o the base URL. To get this
            # behaviour correct we always ensure the base URL ends in a '/'
            # separator, and strip any leading '/' from the merge URL.
            #
            # So, eg...
            #
            # >>> client = Client(base_url="https://www.example.com/subpath")
            # >>> client.base_url
            # URL('https://www.example.com/subpath/')
            # >>> client.build_request("GET", "/path").url
            # URL('https://www.example.com/subpath/path')
            merge_raw_path = self.base_url.raw_path + merge_url.raw_path.lstrip(b"/")
            return self.base_url.copy_with(raw_path=merge_raw_path)
        return merge_url

    @staticmethod
    def _enforce_trailing_slash(url: URL) -> URL:
        if url.raw_path.endswith(b"/"):
            return url
        return url.copy_with(raw_path=url.raw_path + b"/")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self.close()


class ESSRClient:
    """Synchronous client for connecting to an ESSR server and sending/receiving data."""

    def __init__(
        self,
        *,
        params: dict | None = None,
        return_route: str = "/",
        headers: list | None = None,
        timeout: int = 10,
        base_url: URL | str = "",
    ):
        self.params = params
        self.return_route = return_route if return_route else "/"
        self.files = None  # TODO: support files from the commandline, maybe?
        self.headers = headers
        self.timeout = timeout
        self._base_url = self._enforce_trailing_slash(URL(base_url))

        # Create event and client
        self._client = None

    @property
    def base_url(self) -> URL:
        """
        Base URL to use when sending requests with relative URLs.
        """
        return self._base_url

    def request(
        self,
        crypt_signer: CryptSigner,
        url: URL | str,
        target: str = None,
        headers: list = None,
        json: str = None,
        data: str = None,
        files=None,
    ):

        url = self._merge_url(url)

        request = self._build_request(
            crypt_signer=crypt_signer,
            url=url,
            target=target,
            return_route=self.return_route,
            json=json,
            data=data,
            params=self.params,
            headers=headers,
        )

        self._client = TCPClient(url.host, url.port)

        try:
            # Connect to the server
            if self._client.connect():
                # Send the request
                if self._client.send(request):
                    logger.debug(f"Request sent successfully to {url.host}:{url.port}")

                    # Wait for response with timeout
                    try:
                        sender, payload = self._read_and_parse(
                            crypt_signer.hby, crypt_signer
                        )
                        logger.info("Response received and processed.")

                        return Response(sender, payload)

                    except TimeoutError:
                        logger.error(
                            f"Timeout after {self.timeout} seconds waiting for response"
                        )
                        raise TimeoutError(
                            f"Timeout after {self.timeout} seconds waiting for response"
                        )
                else:
                    logger.error(f"Failed to send request to {url.host}:{url.port}")
                    raise ConnectionError(
                        f"Failed to send request to {url.host}:{url.port}"
                    )

            else:
                logger.error(f"Failed to connect to {url.host}:{url.port}")
                raise ConnectionError(f"Failed to connect to {url.host}:{url.port}")
        finally:
            # Ensure client is disconnected
            self._client.disconnect()

    def close(self):
        if self._client:
            self._client.disconnect()

    def _build_request(
        self,
        crypt_signer: CryptSigner,
        url: URL | str,
        target: str,
        return_route: str,
        json: str = None,
        data: str = None,
        params: dict = None,
        headers: dict = None,
    ):

        try:
            # Make the request
            base_request = requests.http(
                hostname=url.host,
                port=url.port,
                path=url.path,
                params=self._merge_queryparams(params),
                return_route=return_route if return_route else self.return_route,
                json=json,
                files=None,  # TODO: support files from the commandline, maybe?
                data=data,
                headers=self._merge_headers(headers),
            )

            request = crypt_signer.encode(url.path, base_request, target)
            return request
        except Exception as e:
            logger.error(f"Error building request: {e}")
            return None

    def _read_and_parse(self, hby, crypt_signer):
        """Read all data from client and parse it"""
        import socket as sock_module

        # Set socket timeout
        if self._client.socket:
            self._client.socket.settimeout(self.timeout)

        handler = handlers.ESSRHandler(crypt_signer, self.return_route, None)
        exc = exchanging.Exchanger(hby=hby, handlers=[handler])
        parser = parsing.Parser(framed=True, exc=exc)

        ims = bytearray()
        while self._client.is_connected():
            try:
                buf = self._client.receive(4096)
                if not buf:
                    break
                ims.extend(buf)
                if len(buf) != 4096:
                    break

            except sock_module.timeout:
                raise TimeoutError(
                    f"Timeout after {self.timeout} seconds waiting for response"
                )
            except Exception as e:
                logger.error(f"Error reading/parsing data: {e}")
                return None, None

        # Parse the received data using KERI Parser
        parser.parseOne(ims=ims)

        return (
            handler.sender,
            handler.payload,
        )

    def _merge_queryparams(self, params):
        if params or self.params:
            merged_queryparams = QueryParams(self.params)
            merged_queryparams = merged_queryparams.merge(params)
            return dict(merged_queryparams)

        else:
            return None

    def _merge_headers(self, headers):
        merged_headers = Headers(self.headers)
        merged_headers.update(headers)

        return dict(merged_headers)

    def _merge_url(self, url: URL | str) -> URL:
        """
        Merge a URL argument together with any 'base_url' on the client,
        to create the URL used for the outgoing request.
        """
        merge_url = URL(url)
        if merge_url.is_relative_url:
            # To merge URLs we always append t`o the base URL. To get this
            # behaviour correct we always ensure the base URL ends in a '/'
            # separator, and strip any leading '/' from the merge URL.
            #
            # So, eg...
            #
            # >>> client = Client(base_url="https://www.example.com/subpath")
            # >>> client.base_url
            # URL('https://www.example.com/subpath/')
            # >>> client.build_request("GET", "/path").url
            # URL('https://www.example.com/subpath/path')
            merge_raw_path = self.base_url.raw_path + merge_url.raw_path.lstrip(b"/")
            return self.base_url.copy_with(raw_path=merge_raw_path)
        return merge_url

    @staticmethod
    def _enforce_trailing_slash(url: URL) -> URL:
        if url.raw_path.endswith(b"/"):
            return url
        return url.copy_with(raw_path=url.raw_path + b"/")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            self.close()
