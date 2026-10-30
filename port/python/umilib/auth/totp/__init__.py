"""One-time passwords: HOTP (RFC 4226) and TOTP (RFC 6238). Mirrors ``umilib::auth::totp``.

``HOTP[SHA1](key, digits)`` is ``HOTP::<SHA1>::new(key, digits)`` and
``TOTP[SHA256](key, config)`` is ``TOTP::<SHA256>::new(key, config)``: the
hash function is a cryptographic hash class of :mod:`umilib.hash`. A verifier keeps the
counter of the last password it accepted and accepts no password of that
counter or an earlier one again: ``verify`` returns the counter that matched.
Errors are :class:`OTPStatusError`.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any, ClassVar

from umilib.crypto import Specialization
from umilib.ffi import Bytes, FFIError, Handle, Library, Text
from umilib.hash import CryptographicDigest


class OTPStatusError(FFIError):
    """An error of a one-time password; ``name`` is ``KeyTooShort``, ``Digits``, ``Period``, ``Time`` or ``Hash``."""


Library.register_error("auth.totp", OTPStatusError)


@dataclass(frozen=True)
class TOTPConfig:
    """The digits of a password, the time step in seconds and its origin (seconds of the Unix epoch)."""

    digits: int = 6
    period: int = 30
    origin: int = 0


class OTPCode:
    """The constants of passwords."""

    MAXIMUM_DIGITS = 10


class HOTP(Handle):
    """HOTP (RFC 4226) over the hash function ``HOTP[H]``, of a key of at least 16 bytes and
    passwords of 6 to 10 digits."""

    FREE = "umilib_auth_totp_hotp_free"
    HASH: ClassVar[type[CryptographicDigest] | None] = None

    def __class_getitem__(cls, hash: type[CryptographicDigest]) -> Any:
        """The class of HOTP over ``hash``."""
        return Specialization.of(cls, (HOTP.check_hash(hash, "HOTP"),), {"HASH": hash, "__doc__": f"HOTP over {hash.__name__}."})

    @staticmethod
    def check_hash(hash: Any, name: str) -> type[CryptographicDigest]:
        """``hash`` if it is a cryptographic hash function class; raises TypeError otherwise."""
        if not (isinstance(hash, type) and issubclass(hash, CryptographicDigest) and hash.C_TYPE):
            raise TypeError(f"{name} needs a cryptographic hash function class, such as {name}[SHA1]")
        return hash

    def __init__(self, key: bytes | bytearray | memoryview, digits: int = 6) -> None:
        hash = Specialization.require(self.HASH, "HOTP")
        name, name_length = Text.encode(hash.C_TYPE)
        super().__init__(Handle.create("umilib_auth_totp_hotp_new", name, name_length, *Bytes.readable(key), digits))

    def generate(self, counter: int) -> str:
        """The password of ``counter``."""
        out, written = ctypes.create_string_buffer(OTPCode.MAXIMUM_DIGITS), ctypes.c_size_t()
        self.library.call("umilib_auth_totp_hotp_generate", self.handle, counter, out, OTPCode.MAXIMUM_DIGITS, ctypes.byref(written))
        return out.raw[: written.value].decode("ascii")

    def verify(self, code: str | bytes, counter: int, look_ahead: int = 0) -> int | None:
        """The counter from ``counter`` to ``counter + look_ahead`` whose password is ``code``, or ``None``."""
        data = code.encode("ascii") if isinstance(code, str) else bytes(code)
        found, matched = ctypes.c_bool(), ctypes.c_uint64()
        self.library.call(
            "umilib_auth_totp_hotp_verify", self.handle, *Bytes.readable(data), counter, look_ahead, ctypes.byref(found), ctypes.byref(matched)
        )
        return matched.value if found.value else None


class TOTP(Handle):
    """TOTP (RFC 6238) over the hash function ``TOTP[H]``: HOTP of the time step of a time
    (seconds of the Unix epoch)."""

    FREE = "umilib_auth_totp_totp_free"
    HASH: ClassVar[type[CryptographicDigest] | None] = None

    def __class_getitem__(cls, hash: type[CryptographicDigest]) -> Any:
        """The class of TOTP over ``hash``."""
        return Specialization.of(cls, (HOTP.check_hash(hash, "TOTP"),), {"HASH": hash, "__doc__": f"TOTP over {hash.__name__}."})

    def __init__(self, key: bytes | bytearray | memoryview, config: TOTPConfig = TOTPConfig()) -> None:
        hash = Specialization.require(self.HASH, "TOTP")
        name, name_length = Text.encode(hash.C_TYPE)
        structure = Library.default().type("umilib_auth_totp_TOTPConfig")(config.digits, config.period, config.origin)
        super().__init__(Handle.create("umilib_auth_totp_totp_new", name, name_length, *Bytes.readable(key), structure))
        self.config = config

    def counter(self, time: int) -> int:
        """The time step of ``time``; raises ``Time`` before the origin."""
        return self.library.value("umilib_auth_totp_totp_counter", ctypes.c_uint64, self.handle, time)

    def generate(self, time: int) -> str:
        """The password at ``time``; raises ``Time`` before the origin."""
        out, written = ctypes.create_string_buffer(OTPCode.MAXIMUM_DIGITS), ctypes.c_size_t()
        self.library.call("umilib_auth_totp_totp_generate", self.handle, time, out, OTPCode.MAXIMUM_DIGITS, ctypes.byref(written))
        return out.raw[: written.value].decode("ascii")

    def verify(self, code: str | bytes, time: int, behind: int = 1, ahead: int = 1) -> int | None:
        """The time step from ``behind`` steps before that of ``time`` to ``ahead`` steps after it whose
        password is ``code``, or ``None``; raises ``Time`` before the origin."""
        data = code.encode("ascii") if isinstance(code, str) else bytes(code)
        found, matched = ctypes.c_bool(), ctypes.c_uint64()
        self.library.call(
            "umilib_auth_totp_totp_verify", self.handle, *Bytes.readable(data), time, behind, ahead, ctypes.byref(found), ctypes.byref(matched)
        )
        return matched.value if found.value else None


__all__ = ["HOTP", "OTPCode", "OTPStatusError", "TOTP", "TOTPConfig"]
