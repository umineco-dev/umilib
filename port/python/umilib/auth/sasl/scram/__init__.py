"""SCRAM (RFC 5802) over SHA-1 and SHA-256 (RFC 7677), with channel binding for the ``-PLUS`` variants.
Mirrors ``umilib::auth::sasl::scram``.

``SCRAMClient[SHA256](username, password, nonce)`` is ``SCRAMClient::<SHA256>::new(...)``; the server reads the
client-first-message, the application looks up :attr:`SCRAMServer.username` and passes its credentials::

    client.client_first()                        -> client-first-message
    server.receive_client_first(message)
    server.server_first(credentials, nonce)      -> server-first-message
    client.receive_server_first(message)         -> client-final-message
    server.receive_client_final(message)         -> server-final-message
    client.receive_server_final(message)
"""

from __future__ import annotations

import ctypes
import enum
from typing import Any, ClassVar

from umilib.auth.sasl import GS2ChannelBinding, SASLMechanism
from umilib.crypto import Primitive, Specialization
from umilib.ffi import Buffer, Bytes, FFIError, Handle, Library, Text
from umilib.hash import CryptographicDigest

P = "umilib_auth_sasl_scram_scram"


class SCRAMError(FFIError):
    """A failed SCRAM exchange: a server error of RFC 5802 section 7 (``InvalidEncoding``, ``InvalidProof``,
    ``ChannelBindingsDontMatch``, ``UnknownUser``, ...) or ``Format``, ``Extension``, ``Nonce``, ``Iterations``,
    ``ServerSignature``, ``Salt``, ``Random``, ``State``."""


Library.register_error("auth.sasl.scram", SCRAMError)


class SCRAMServerError(enum.IntEnum):
    """The server errors of RFC 5802 section 7, in the order of the Rust ``ALL``."""

    InvalidEncoding = 0
    ExtensionsNotSupported = 1
    InvalidProof = 2
    ChannelBindingsDontMatch = 3
    ServerDoesSupportChannelBinding = 4
    ChannelBindingNotSupported = 5
    UnsupportedChannelBindingType = 6
    UnknownUser = 7
    InvalidUsernameEncoding = 8
    NoResources = 9
    OtherError = 10

    def registered_name(self) -> str:
        """The value of ``e=``, as ``invalid-proof``."""
        return Library.default().output(f"{P}_server_error_name", int(self)).decode()


class SCRAMNonce:
    """The nonces of SCRAM: random, printable."""

    @staticmethod
    def random(random: Any) -> str:
        """A nonce of 24 random bytes from the generator ``random``, in base64."""
        return Library.default().output(f"{P}_nonce_random", *random.source()).decode()


class SCRAMHashClass:
    """The hash functions SCRAM is registered with."""

    NAMES: ClassVar[tuple[str, ...]] = ("umilib_hash_sha_v1_SHA1", "umilib_hash_sha_v2_SHA256")

    @staticmethod
    def require(hash: Any, user: str) -> type[CryptographicDigest]:
        if not (isinstance(hash, type) and issubclass(hash, CryptographicDigest) and hash.C_TYPE in SCRAMHashClass.NAMES):
            raise TypeError(f"{user} needs SHA1 or SHA256, as {user}[SHA256]")
        return hash


class SCRAMCredentials(Primitive):
    """What a server keeps for a user: the salt, the iteration count, StoredKey and ServerKey."""

    PREFIX = f"{P}_credentials"
    HASH: ClassVar[type[CryptographicDigest] | None] = None

    def __class_getitem__(cls, hash: Any) -> Any:
        return Specialization.of(cls, (SCRAMHashClass.require(hash, cls.__name__),), {"HASH": hash})

    def __init__(self, password: str, salt: bytes | bytearray | memoryview, iterations: int) -> None:
        name, length = Text.encode(Specialization.require(self.HASH, "SCRAMCredentials").C_TYPE)
        super().__init__(Handle.create(f"{P}_credentials_new", name, length, *Text.encode(password), *Bytes.readable(salt), iterations))

    @classmethod
    def from_parts(cls, salt: bytes, iterations: int, stored_key: bytes, server_key: bytes) -> Any:
        """The credentials of their stored parts; ``Format`` for keys of another size than the hash output."""
        name, length = Text.encode(Specialization.require(cls.HASH, "SCRAMCredentials").C_TYPE)
        pointer = Handle.create(f"{P}_credentials_from_parts", name, length, *Bytes.readable(salt), iterations, *Bytes.readable(stored_key), *Bytes.readable(server_key))
        return cls.from_pointer(pointer)

    def parts(self) -> tuple[bytes, int, bytes, bytearray]:
        """The salt, the iteration count, StoredKey and ServerKey."""
        salt, stored, server = Buffer(), Buffer(), Buffer()
        iterations = ctypes.c_uint32()
        self.library.call(f"{P}_credentials_parts", self.handle, ctypes.byref(salt), ctypes.byref(iterations), ctypes.byref(stored), ctypes.byref(server))
        return self.library.take(salt), iterations.value, self.library.take(stored), self.library.take_secret(server)


class SCRAMClient(Primitive):
    """The client of SCRAM over ``SCRAMClient[H]``, without I/O."""

    PREFIX = f"{P}_client"
    HASH: ClassVar[type[CryptographicDigest] | None] = None

    def __class_getitem__(cls, hash: Any) -> Any:
        return Specialization.of(cls, (SCRAMHashClass.require(hash, cls.__name__),), {"HASH": hash})

    def __init__(self, username: str, password: str, nonce: str) -> None:
        """The client of ``username`` and ``password`` with the client nonce ``nonce`` (see
        :meth:`SCRAMNonce.random`), without channel binding."""
        name, length = Text.encode(Specialization.require(self.HASH, "SCRAMClient").C_TYPE)
        super().__init__(Handle.create(f"{P}_client_new", name, length, *Text.encode(username), *Text.encode(password), *Text.encode(nonce)))

    @classmethod
    def from_salted_password(cls, username: str, salt: bytes, iterations: int, salted_password: bytes | bytearray, nonce: str) -> Any:
        """The client of a SaltedPassword kept from an earlier exchange with ``salt`` and ``iterations``."""
        name, length = Text.encode(Specialization.require(cls.HASH, "SCRAMClient").C_TYPE)
        pointer = Handle.create(
            f"{P}_client_from_salted_password", name, length, *Text.encode(username), *Bytes.readable(salt), iterations, *Bytes.readable(salted_password), *Text.encode(nonce)
        )
        return cls.from_pointer(pointer)

    def set_authzid(self, authzid: str | None) -> None:
        self.library.call(f"{P}_client_set_authzid", self.handle, *Text.encode(authzid))

    def set_channel_binding(self, binding: GS2ChannelBinding, name: str | None = None, data: bytes = b"") -> None:
        """The flag ``binding`` (with the type ``name`` and its ``data`` for ``Required``)."""
        self.library.call(f"{P}_client_set_channel_binding", self.handle, int(binding), *Text.encode(name), *Bytes.readable(data))

    def set_iterations(self, minimum: int, maximum: int) -> None:
        """The iteration counts the client accepts (4096 to 1 000 000 by default)."""
        self.library.call(f"{P}_client_set_iterations", self.handle, minimum, maximum)

    def mechanism(self) -> SASLMechanism:
        return SASLMechanism(self.library.value(f"{P}_client_mechanism", ctypes.c_uint8, self.handle))

    def client_first(self) -> bytes:
        return self.library.output(f"{P}_client_client_first", self.handle)

    def receive_server_first(self, message: bytes | bytearray | memoryview) -> bytes:
        """The client-final-message for the server-first-message ``message``."""
        return self.library.output(f"{P}_client_receive_server_first", self.handle, *Bytes.readable(message))

    def receive_server_final(self, message: bytes | bytearray | memoryview) -> None:
        """Returns if the server proved it knows the key; raises :class:`SCRAMError` otherwise."""
        self.library.call(f"{P}_client_receive_server_final", self.handle, *Bytes.readable(message))

    def salted_secret(self) -> tuple[bytes, int, bytearray] | None:
        """The salt, the iteration count and the SaltedPassword to keep, once the exchange succeeded."""
        has, salt, salted = ctypes.c_bool(), Buffer(), Buffer()
        iterations = ctypes.c_uint32()
        self.library.call(f"{P}_client_salted_secret", self.handle, ctypes.byref(has), ctypes.byref(salt), ctypes.byref(iterations), ctypes.byref(salted))
        salt_bytes, salted_bytes = self.library.take(salt), self.library.take_secret(salted)
        return (salt_bytes, iterations.value, salted_bytes) if has.value else None


class SCRAMServer(Primitive):
    """The server of SCRAM over ``SCRAMServer[H]``, without I/O; ``plus`` for the ``-PLUS`` mechanism."""

    PREFIX = f"{P}_server"
    HASH: ClassVar[type[CryptographicDigest] | None] = None

    def __class_getitem__(cls, hash: Any) -> Any:
        return Specialization.of(cls, (SCRAMHashClass.require(hash, cls.__name__),), {"HASH": hash})

    def __init__(self, plus: bool = False) -> None:
        name, length = Text.encode(Specialization.require(self.HASH, "SCRAMServer").C_TYPE)
        super().__init__(Handle.create(f"{P}_server_new", name, length, plus))

    def add_channel_binding(self, name: str, data: bytes | bytearray | memoryview) -> None:
        """A channel binding type the server supports, with its data for this channel."""
        self.library.call(f"{P}_server_add_channel_binding", self.handle, *Text.encode(name), *Bytes.readable(data))

    def receive_client_first(self, message: bytes | bytearray | memoryview) -> None:
        self.library.call(f"{P}_server_receive_client_first", self.handle, *Bytes.readable(message))

    @property
    def username(self) -> str | None:
        """The username to look up (prepared with SASLprep), once the client-first-message is read."""
        data = self.library.optional(f"{P}_server_username", Buffer, self.handle)
        return None if data is None else data.decode()

    @property
    def authzid(self) -> str | None:
        data = self.library.optional(f"{P}_server_authzid", Buffer, self.handle)
        return None if data is None else data.decode()

    def server_first(self, credentials: SCRAMCredentials, nonce: str) -> bytes:
        """The server-first-message for ``credentials`` with the server's part of the nonce ``nonce``."""
        return self.library.output(f"{P}_server_server_first", self.handle, credentials, *Text.encode(nonce))

    def receive_client_final(self, message: bytes | bytearray | memoryview) -> bytes:
        """The server-final-message, if the client proved it knows the password."""
        return self.library.output(f"{P}_server_receive_client_final", self.handle, *Bytes.readable(message))

    def reject(self, error: SCRAMServerError) -> bytes:
        """Ends the exchange with ``error``: the server-final-message that reports it."""
        return self.library.output(f"{P}_server_reject", self.handle, int(error))


__all__ = ["SCRAMClient", "SCRAMCredentials", "SCRAMError", "SCRAMNonce", "SCRAMServer", "SCRAMServerError"]
