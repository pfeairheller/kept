from contextlib import AbstractAsyncContextManager
from typing import Callable, MutableMapping, Any, Awaitable, Mapping, Union, TypeVar

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]

Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

AppType = TypeVar("AppType")

StatelessLifespan = Callable[[AppType], AbstractAsyncContextManager[None]]
StatefulLifespan = Callable[[AppType], AbstractAsyncContextManager[Mapping[str, Any]]]
Lifespan = Union[StatelessLifespan[AppType], StatefulLifespan[AppType]]
