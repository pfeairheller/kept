# -*- encoding: utf-8 -*-
"""
rack.essr.applications module

Rack applications support for creating ESSR protected apps with exn message routing.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import inspect
import traceback
import types
from contextlib import asynccontextmanager, AbstractAsyncContextManager
from typing import Sequence, TypeVar, Callable, Generator, Any

import cbor2 as cbor
from keri import help, kering, core
from keri.core import coring
from keri.peer import exchanging

from kept.essr.server.types import Scope, Receive, Send, Message, Lifespan

logger = help.ogler.getLogger()


class BaseRoute:
    @property
    def resource(self) -> str:
        raise NotImplementedError()  # pragma: no cover

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        raise NotImplementedError()  # pragma: no cover


class Mount(BaseRoute):
    def __init__(self, path: str, app):
        self.path = path
        self.app = app

    @property
    def resource(self):
        return self.path

    async def handle(self, scope, receive, send) -> None:
        await self.app(scope, receive, send)


class ESSRHandler:
    def __init__(self, router, encryption_target, route: BaseRoute):
        self.router = router
        self.hby = router.hby
        self.encryption_target = encryption_target
        self.route = route

    @property
    def resource(self):
        return self.route.resource

    def handle(self, serder, attachments=None, essr=None):
        """

        This handler decrypts the the encrypted payload, verifies that the sender is in the encrypted payload
        and verifies that the recipient AID was signed as part of the package

        Parameters:
            serder (Serder): Serder of the IPEX protocol exn message
            attachments (list): list of tuples of root pathers and CESR SAD path attachments to the exn event
            essr (bytes):  essr attached bytes

        """
        # Get the encrypted payload
        if essr:
            data = essr
        else:
            enc = serder.ked["a"]["d"]
            data = coring.Texter(qb64=enc).raw

        rp = serder.ked["rp"]

        try:
            hab = self.router.hab(rp)
        except kering.ConfigurationError:
            logger.info(f"dessr: invalid encryption target from msg for rp={rp}")
            return

        # Ensure the signed receiver is us
        if hab is None or not (
            hab.pre == self.encryption_target
            or hab.kever.delpre == self.encryption_target
        ):
            logger.error(
                f"essr msg: invalid /essr/req message, rp={rp} not one of us={self.encryption_target}"
            )
            return

        # Decrypt it with our dest hab
        decrypted = hab.decrypt(data)
        req = cbor.loads(decrypted)

        # Ensure that the encrypted sender is the one that also signed it
        sender = req["i"]
        payload = req["a"]
        raw = req["body"]

        async def receive():
            encoded = bytearray(raw.encode("utf-8"))

            body = bytearray()
            if encoded:
                counter = core.Counter(qb64b=encoded, strip=True)
                for idx in range(counter.count):
                    body.extend(core.Matter(qb64b=encoded, strip=True).raw)

            return {
                "type": "http.request",
                "body": body,
                "more_body": False,
            }

        if sender != serder.ked["i"]:
            logger.error(
                f"dessr: invalid essr req message, encrypted sender={sender} not equal to message signer="
                f"{serder.ked['i']}"
            )
            return

        # Ensure that we know about this sender
        if sender not in self.hby.kevers:
            logger.error(f"essr-handler: unknown src aid={sender}")
            return

        scope = dict(
            type="essr",
            serder=serder,
            attachments=attachments,
            payload=payload,
            headers=payload.get("headers", {}),
            app=self.router,
            query_string=payload.get("query_string", ""),
            query_params=payload.get("params", {}),
        )
        asyncio.create_task(self.route.handle(scope, receive, self.send))

    async def send(self, msg: Message):
        typ = msg["type"]

        match typ:
            case "essr.response.send":
                said = msg["said"]
                ims = self.router.encode(msg)
                await self.router.send(said, ims)

            case "websocket.disconnect":
                await self.router.exc.disconnect(msg)


_T = TypeVar("_T")


class _AsyncLiftContextManager(AbstractAsyncContextManager[_T]):
    def __init__(self, cm: contextlib.AbstractContextManager[_T]):
        self._cm = cm

    async def __aenter__(self) -> _T:
        return self._cm.__enter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        tracebck: types.TracebackType | None,
    ) -> bool | None:
        return self._cm.__exit__(exc_type, exc_value, tracebck)


def _wrap_gen_lifespan_context(
    lifespan_context: Callable[[Any], Generator[Any, Any, Any]],
) -> Callable[[Any], AbstractAsyncContextManager[Any]]:
    cmgr = contextlib.contextmanager(lifespan_context)

    @functools.wraps(cmgr)
    def wrapper(app: Any) -> _AsyncLiftContextManager[Any]:
        return _AsyncLiftContextManager(cmgr(app))

    return wrapper


class _DefaultLifespan:
    def __init__(self, router: Rack):
        self._router = router

    async def __aenter__(self) -> None:
        await self._router.startup()

    async def __aexit__(self, *exc_info: object) -> None:
        await self._router.shutdown()

    def __call__(self: _T, app: object) -> _T:
        return self


class Rack:

    def __init__(
        self,
        hby,
        crypt_signer=None,
        debug=False,
        routes: Sequence[BaseRoute] | None = None,
        lifespan: Lifespan[Any] | None = None,
    ):
        self.hby = hby
        self.crypt_signer = crypt_signer
        self.debug = debug
        self.routes = routes or []
        self.writers = {}

        if lifespan is None:
            self.lifespan_context: Lifespan[Any] = _DefaultLifespan(self)

        elif inspect.isasyncgenfunction(lifespan):
            logger.warn(
                "async generator function lifespans are deprecated, "
                "use an @contextlib.asynccontextmanager function instead",
                DeprecationWarning,
            )
            self.lifespan_context = asynccontextmanager(
                lifespan,
            )
        elif inspect.isgeneratorfunction(lifespan):
            logger.warn(
                "generator function lifespans are deprecated, use an @contextlib.asynccontextmanager function instead",
                DeprecationWarning,
            )
            self.lifespan_context = _wrap_gen_lifespan_context(
                lifespan,
            )
        else:
            self.lifespan_context = lifespan

        handlers = []
        for route in self.routes:
            handlers.append(
                ESSRHandler(router=self, encryption_target=None, route=route)
            )

        self.exc = exchanging.Exchanger(hby=self.hby, handlers=handlers)

    async def lifespan(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        Handle ASGI lifespan messages, which allows us to manage application
        startup and shutdown events.
        """
        started = False
        app: Any = scope.get("app")
        await receive()
        try:
            async with self.lifespan_context(app) as maybe_state:
                if maybe_state is not None:
                    if "state" not in scope:
                        raise RuntimeError(
                            'The server does not support "state" in the lifespan scope.'
                        )
                    scope["state"].update(maybe_state)
                await send({"type": "lifespan.startup.complete"})
                started = True
                await receive()
        except BaseException:
            exc_text = traceback.format_exc()
            if started:
                await send({"type": "lifespan.shutdown.failed", "message": exc_text})
            else:
                await send({"type": "lifespan.startup.failed", "message": exc_text})
            raise
        else:
            await send({"type": "lifespan.shutdown.complete"})

    def service(self):
        self.exc.processEscrow()

    def assign_writer(self, said, writer):
        self.writers[said] = writer

    def remove_writer(self, said):
        self.writers.pop(said, None)

    async def startup(self):
        pass

    async def shutdown(self):
        pass

    async def not_found(self, said):
        serder = self.hby.db.exns.get(keys=(said,))
        essr = b"".join(
            [texter.raw for (_, texter) in self.hby.db.essrs.getItemIter(keys=(said,))]
        )
        rp = serder.ked["rp"]
        orig = serder.ked["r"]

        try:
            hab = self.crypt_signer.hab(rp)
        except kering.ConfigurationError:
            logger.info(f"dessr: invalid encryption target from msg for rp={rp}")
            return

        decrypted = hab.decrypt(essr)
        req = cbor.loads(decrypted)
        sender = req["i"]
        payload = req["a"]
        route = payload.get("return_route")

        ims = self.encode(
            dict(
                status=404,
                route=route,
                body=f"{orig} Not Found",
                said=said,
                sender=sender,
            )
        )
        await self.send(said, ims)

    def encode(self, msg):
        status = msg.get("status", 200)
        target = msg.get("sender", None)
        route = msg.get("route", "/")
        said = msg.get("said", None)
        headers = msg.get("headers", {})
        body = msg.get("body", b"")

        if route is None:
            raise ValueError("Route is required")

        # create the payload to be encrypted... must include sender
        payload = dict(status=status, headers=headers, body=body)

        return self.crypt_signer.encode(route, dict(a=payload), target, said)

    def hab(self, aid):
        return self.crypt_signer.hab(aid)

    async def send(self, said, ims):
        writer = self.writers[said]
        try:
            writer.write(ims)
            await writer.drain()
            logger.debug(f"Sent {len(ims)} bytes")
            return True
        except Exception as e:
            logger.error(f"Failed to send data: {e}")
            return False
