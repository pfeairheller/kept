from __future__ import annotations


import json
from typing import Mapping, Any, Iterator, NoReturn, AsyncGenerator, Dict, cast

from .datastructures import URL, State
from .responses import Headers
from .types import Scope, Receive, Message, Send


class ESSRConnection(Mapping[str, Any]):
    """
    A base class for incoming HTTP connections, that is used to provide
    any functionality that is common to both `Request` and `WebSocket`.
    """

    def __init__(self, scope: Scope, receive: Receive | None = None) -> None:
        assert scope["type"] in ("essr", "essr-sse")
        self.scope = scope

    def __getitem__(self, key: str) -> Any:
        return self.scope[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.scope)

    def __len__(self) -> int:
        return len(self.scope)

    # Don't use the `abc.Mapping.__eq__` implementation.
    # Connection instances should never be considered equal
    # unless `self is other`.
    __eq__ = object.__eq__
    __hash__ = object.__hash__

    @property
    def app(self) -> Any:
        return self.scope["app"]

    @property
    def url(self) -> URL:
        if not hasattr(self, "_url"):  # pragma: no branch
            self._url = URL(scope=self.scope)
        return self._url

    @property
    def base_url(self) -> URL:
        if not hasattr(self, "_base_url"):
            base_url_scope = dict(self.scope)
            # This is used by request.url_for, it might be used inside a Mount which
            # would have its own child scope with its own root_path, but the base URL
            # for url_for should still be the top level app root path.
            app_root_path = base_url_scope.get(
                "app_root_path", base_url_scope.get("root_path", "")
            )
            path = app_root_path
            if not path.endswith("/"):
                path += "/"
            base_url_scope["path"] = path
            base_url_scope["query_string"] = b""
            base_url_scope["root_path"] = app_root_path
            self._base_url = URL(scope=base_url_scope)
        return self._base_url

    @property
    def headers(self) -> Headers:
        if not hasattr(self, "_headers"):
            self._headers = Headers(headers=self.scope["headers"])
        return self._headers

    @property
    def query_params(self) -> Dict:
        if not hasattr(self, "_query_params"):  # pragma: no branch
            self._query_params = self.scope.get("query_params", {})
        return self._query_params

    @property
    def path_params(self) -> dict[str, Any]:
        return self.scope.get("path_params", {})

    @property
    def session(self) -> dict[str, Any]:
        assert (
            "session" in self.scope
        ), "SessionMiddleware must be installed to access request.session"
        return self.scope["session"]  # type: ignore[no-any-return]

    @property
    def auth(self) -> Any:
        assert (
            "auth" in self.scope
        ), "AuthenticationMiddleware must be installed to access request.auth"
        return self.scope["auth"]

    @property
    def user(self) -> Any:
        assert (
            "user" in self.scope
        ), "AuthenticationMiddleware must be installed to access request.user"
        return self.scope["user"]

    @property
    def state(self) -> State:
        if not hasattr(self, "_state"):
            # Ensure 'state' has an empty dict if it's not already populated.
            self.scope.setdefault("state", {})
            # Create a state instance with a reference to the dict in which it should
            # store info
            self._state = State(self.scope["state"])
        return self._state


async def empty_receive() -> NoReturn:
    raise RuntimeError("Receive channel has not been made available")


async def empty_send(message: Message) -> NoReturn:
    raise RuntimeError("Send channel has not been made available")


class Request(ESSRConnection):
    _form: Dict | None

    def __init__(
        self, scope: Scope, receive: Receive = empty_receive, send: Send = empty_send
    ):
        super().__init__(scope)
        assert scope["type"] == "essr"
        self._receive = receive
        self._send = send
        self._stream_consumed = False
        self._is_disconnected = False
        self._form = None

    @property
    def method(self) -> str:
        return cast(str, self.scope["method"])

    @property
    def receive(self) -> Receive:
        return self._receive

    async def stream(self) -> AsyncGenerator[bytes, None]:
        if hasattr(self, "_body"):
            yield self._body
            yield b""
            return
        if self._stream_consumed:
            raise RuntimeError("Stream consumed")
        while not self._stream_consumed:
            message = await self._receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                if not message.get("more_body", False):
                    self._stream_consumed = True
                if body:
                    yield body
            elif message["type"] == "http.disconnect":  # pragma: no branch
                self._is_disconnected = True
                raise ValueError()
        yield b""

    async def body(self) -> bytes:
        if not hasattr(self, "_body"):
            chunks: list[bytes] = []
            async for chunk in self.stream():
                chunks.append(chunk)
            self._body = b"".join(chunks)
        return self._body

    async def json(self) -> Any:
        if not hasattr(self, "_json"):  # pragma: no branch
            body = await self.body()
            self._json = json.loads(body)
        return self._json

    async def close(self) -> None:
        if self._form is not None:  # pragma: no branch
            await self._form.close()
