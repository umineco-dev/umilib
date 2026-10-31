"""The Internet Control Message Protocol: what both versions share — the multi-part extensions of
error messages (RFC 4884), the rate limit of the errors a node originates (RFC 4443 §2.4 (f)) and the
error type. Mirrors ``umilib::protocol::icmp``.

Errors are :class:`ICMPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
from collections.abc import Iterator
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Nanoseconds


class ICMPError(FFIError):
    """An error of an ICMP message: ``Length``, ``Checksum``, ``Version``, ``Invalid`` or ``Limit``."""


Library.register_error("protocol.icmp", ICMPError)


class ICMPHeader:
    """Conversions of the first eight bytes of a message but the checksum to and from their C structure."""

    @staticmethod
    def to_structure(kind: int, code: int, rest: bytes) -> Any:
        if len(rest) != 4:
            raise ValueError("the rest of the header has 4 bytes")
        structure = Library.default().type("umilib_protocol_icmp_ICMPHeader")()
        Fields.assign(structure, "kind", int(kind))
        Fields.assign(structure, "code", code)
        ctypes.memmove(structure.rest, bytes(rest), 4)
        return structure

    @staticmethod
    def from_structure(structure: Any) -> tuple[int, int, bytes]:
        return structure.kind, structure.code, bytes(structure.rest)


@dataclasses.dataclass(frozen=True)
class ICMPExtensionObject:
    """One object of an extension structure (RFC 4884 §8): its class (``class_``, as ``class`` is a
    Python keyword), its sub-type and its payload."""

    HEADER_LENGTH: ClassVar[int] = 4
    UNIT: ClassVar[int] = 4
    INTERFACE_INFORMATION: ClassVar[int] = 2
    MPLS_LABEL_STACK: ClassVar[int] = 1

    class_: int
    kind: int
    payload: bytes

    def encode(self) -> bytes:
        """The bytes of the object; raises ``Length`` unless it is a multiple of 4 bytes."""
        return Library.default().output("umilib_protocol_icmp_icmp_extension_object_encode", self.class_, self.kind, *Bytes.readable(self.payload))


@dataclasses.dataclass(frozen=True)
class ICMPExtensions:
    """The extension structure of an error message (RFC 4884 §7): the checksum as received and the
    objects, as bytes."""

    VERSION: ClassVar[int] = 2
    HEADER_LENGTH: ClassVar[int] = 4
    MINIMUM_ORIGINAL_LENGTH: ClassVar[int] = 128
    WORDS: ClassVar[tuple[int, int]] = (4, 8)

    checksum: int
    objects: bytes

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> ICMPExtensions:
        """The structure that ``data`` is; raises ``Version``, ``Checksum`` or ``Length``."""
        data = bytes(data)
        checksum = Library.default().value("umilib_protocol_icmp_icmp_extensions_decode", ctypes.c_uint16, data, len(data))
        return cls(checksum, data[ICMPExtensions.HEADER_LENGTH :])

    def __iter__(self) -> Iterator[ICMPExtensionObject]:
        library = Library.default()
        # A zero checksum is none to check: the objects were checked when decoded.
        unchecked = bytes([ICMPExtensions.VERSION << 4, 0, 0, 0]) + self.objects
        index = 0
        while True:
            found, class_, kind, payload = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_uint8(), Buffer()
            library.call("umilib_protocol_icmp_icmp_extensions_get", unchecked, len(unchecked), index, ctypes.byref(found), ctypes.byref(class_), ctypes.byref(kind), ctypes.byref(payload))
            value = library.take(payload)
            if not found.value:
                return
            yield ICMPExtensionObject(class_.value, kind.value, value)
            index += 1

    def iter(self) -> Iterator[ICMPExtensionObject]:
        return iter(self)

    def check(self) -> None:
        """Raises ``Length`` unless the objects are one or more of whole 32-bit words (RFC 4884 §7, §8)."""
        Library.default().call("umilib_protocol_icmp_icmp_extensions_check", *Bytes.readable(self.objects))

    @staticmethod
    def check_word(word: int) -> None:
        """Raises ``Invalid`` unless ``word`` is 4 or 8 (RFC 4884 §4)."""
        Library.default().call("umilib_protocol_icmp_icmp_extensions_check_word", word)

    def encode(self) -> bytes:
        """The bytes of the structure, with the checksum of its objects."""
        return Library.default().output("umilib_protocol_icmp_icmp_extensions_encode", *Bytes.readable(self.objects))

    def encode_body(self, original: bytes, word: int) -> tuple[int, bytes]:
        """The body of an extended error message (RFC 4884 §4) and its length attribute: ``original``
        padded to a multiple of ``word`` bytes and to 128, then the structure."""
        attribute, buffer = ctypes.c_uint8(), Buffer()
        library = Library.default()
        library.call("umilib_protocol_icmp_icmp_extensions_encode_body", *Bytes.readable(self.objects), *Bytes.readable(original), word, ctypes.byref(attribute), ctypes.byref(buffer))
        return attribute.value, library.take(buffer)

    @staticmethod
    def split_body(body: bytes, attribute: int, word: int) -> tuple[bytes, ICMPExtensions | None]:
        """The original datagram of an error message whose length attribute is ``attribute`` words of
        ``word`` bytes, and its extension structure, if any."""
        body = bytes(body)
        original, found = ctypes.c_size_t(), ctypes.c_bool()
        Library.default().call("umilib_protocol_icmp_icmp_extensions_split_body", body, len(body), attribute, word, ctypes.byref(original), ctypes.byref(found))
        length = original.value
        return body[:length], (ICMPExtensions.decode(body[length:]) if found.value else None)


@dataclasses.dataclass(frozen=True)
class ICMPRateLimitConfig:
    """A bucket of ``burst`` tokens, one added every ``interval``; the defaults are the example of
    RFC 4443 §2.4 (f): bursts of 10, 10 a second."""

    burst: int = 10
    interval: datetime.timedelta = datetime.timedelta(milliseconds=100)


class ICMPRateLimiter(Handle):
    """The token bucket that limits the error messages a node originates."""

    FREE = "umilib_protocol_icmp_icmp_rate_limiter_free"

    def __init__(self, config: ICMPRateLimitConfig, now: int) -> None:
        super().__init__(Handle.create("umilib_protocol_icmp_icmp_rate_limiter_new", config.burst, Nanoseconds.from_timedelta(config.interval), now))
        self.config = config

    def allow(self, now: int) -> bool:
        """Whether a message may be sent at ``now``; takes its token if so."""
        return self.library.value("umilib_protocol_icmp_icmp_rate_limiter_allow", ctypes.c_bool, self.handle, now)


__all__ = ["ICMPError", "ICMPExtensionObject", "ICMPExtensions", "ICMPHeader", "ICMPRateLimitConfig", "ICMPRateLimiter"]
