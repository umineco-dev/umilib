"""Services and routers. Mirrors ``umilib::service``.

A service is a function from the bytes of a request to the bytes of its
answer. A :class:`Router` gives each request to the service of the first
route whose :class:`Pattern` matches it, or to its fallback. Errors are
:class:`ServiceStatusError`; an exception a service raises is raised again
by :meth:`Router.call`.
"""

from __future__ import annotations

import ctypes
import itertools
from typing import Callable

from umilib.ffi import Buffer, Bytes, FFIError, Handle, Library


class ServiceStatusError(FFIError):
    """An error of a service; ``name`` is ``MisplacedWildcard``, ``UnfinishedEscape``, ``Unrouted`` or ``Failed``."""


Library.register_error("service", ServiceStatusError)


class Pattern(Handle):
    """A pattern of bytes. Its text is ``*`` for any input, ``bytes*`` for a prefix, ``*bytes`` for
    a suffix and ``bytes`` for the exact bytes; ``\\*`` and ``\\\\`` stand for ``*`` and ``\\``."""

    FREE = "umilib_service_pattern_free"

    @staticmethod
    def parse(text: bytes | str) -> Pattern:
        """The pattern of ``text`` (case not ignored); raises ``MisplacedWildcard`` or ``UnfinishedEscape``."""
        data = text.encode() if isinstance(text, str) else bytes(text)
        return Pattern(Handle.create("umilib_service_pattern_parse", *Bytes.readable(data)))

    def format(self) -> bytes:
        """The text of the pattern."""
        return self.library.output("umilib_service_pattern_format", self.handle)

    def ignoring_ascii_case(self, ignore: bool = True) -> Pattern:
        """A copy that ignores the case of ASCII letters if ``ignore`` is true."""
        return Pattern(Handle.create("umilib_service_pattern_ignoring_ascii_case", self.handle, ignore))

    @property
    def ignores_ascii_case(self) -> bool:
        return self.library.value("umilib_service_pattern_ignores_ascii_case", ctypes.c_bool, self.handle)

    def matches_bytes(self, data: bytes | bytearray | memoryview) -> bool:
        """Whether ``data`` matches."""
        return self.library.value("umilib_service_pattern_matches_bytes", ctypes.c_bool, self.handle, *Bytes.readable(data))


class Router(Handle):
    """A router of patterns of the request's bytes to services (functions from bytes to bytes)."""

    FREE = "umilib_service_router_free"

    def __init__(self) -> None:
        super().__init__(Handle.create("umilib_service_router_new"))
        #: The callbacks of the services alive, kept until their drop callback, and the exceptions raised.
        self.callbacks: dict[int, tuple] = {}
        self.raised: list[BaseException] = []
        #: The keys of the services' contexts (``next`` is atomic).
        self.keys = itertools.count(1)

    def entry(self, service: Callable[[bytes], bytes]) -> tuple[tuple, int]:
        """The C callbacks of ``service`` and the key of its context."""
        callbacks, raised, library = self.callbacks, self.raised, self.library

        def call(context: int, request: int, length: int, response: int) -> bool:
            try:
                answer = bytes(memoryview(service(ctypes.string_at(request, length) if length else b"")))
                data, size = Bytes.readable(answer)
                library.call("umilib_service_response_write", response, data, size)
                return True
            except BaseException as error:  # noqa: BLE001 - re-raised by Router.call
                raised.append(error)
                return False

        def drop(context: int) -> None:
            callbacks.pop(context, None)

        key = next(self.keys)
        entry = (library.type("umilib_service_ServiceCall")(call), library.type("umilib_service_ServiceDrop")(drop))
        callbacks[key] = entry
        return entry, key

    def push(self, pattern: Pattern, service: Callable[[bytes], bytes]) -> None:
        """Adds a route of ``pattern`` to ``service`` after the routes."""
        entry, key = self.entry(service)
        try:
            self.library.call("umilib_service_router_push", self.handle, pattern, entry[0], entry[1], key)
        except BaseException:
            # Not added: the router never calls its drop callback.
            self.callbacks.pop(key, None)
            raise

    def route(self, pattern: Pattern, service: Callable[[bytes], bytes]) -> Router:
        """Adds a route of ``pattern`` to ``service`` after the routes; returns the router."""
        self.push(pattern, service)
        return self

    def set_fallback(self, service: Callable[[bytes], bytes] | None) -> None:
        """Sets the service of the requests no route matches (``None`` removes it)."""
        if service is None:
            call, drop = self.library.type("umilib_service_ServiceCall")(), self.library.type("umilib_service_ServiceDrop")()
            self.library.call("umilib_service_router_set_fallback", self.handle, call, drop, None)
            return
        entry, key = self.entry(service)
        try:
            self.library.call("umilib_service_router_set_fallback", self.handle, entry[0], entry[1], key)
        except BaseException:
            self.callbacks.pop(key, None)
            raise

    def __len__(self) -> int:
        """The routes."""
        return self.library.value("umilib_service_router_len", ctypes.c_size_t, self.handle)

    def call(self, request: bytes | bytearray | memoryview) -> bytes:
        """The answer of the service of ``request``; raises ``Unrouted`` if no route matches, the
        exception of the service if it raised one, and ``Failed`` otherwise."""
        out = Buffer()
        # The services run in the call, on this thread; their exceptions are taken under the lock,
        # so that a call of another thread does not take them.
        with self.locked():
            try:
                self.library.call("umilib_service_router_call", self.handle, *Bytes.readable(request), ctypes.byref(out))
            except ServiceStatusError:
                if self.raised:
                    error = self.raised[0]
                    self.raised.clear()
                    raise error from None
                raise
        return self.library.take(out)


__all__ = ["Pattern", "Router", "ServiceStatusError"]
