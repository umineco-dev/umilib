"""SRP-6a (RFC 5054). Mirrors ``umilib::crypto::srp``.

``SRP[G, H]`` computes the verifier of a user in a group of this module with
a hash function (SHA-1 for RFC 5054); ``SRPClient[G, H]`` and
``SRPServer[G, H]`` hold the secret exponents a and b and compute the
premaster secret of section 2.6. Integers are big-endian bytes.
"""

from __future__ import annotations

from typing import Any, ClassVar

from umilib.crypto import Names, Specialization
from umilib.crypto.random import Random
from umilib.ffi import Bytes, Handle, Library, Marker, Text
from umilib.hash import CryptographicDigest
from umilib.secret import Secret


class SRPGroup(Marker, abstract=True):
    """A group of SRP: a safe prime N and a generator g, named by its C type name."""


class SRP1024(SRPGroup):
    """The 1024-bit group of RFC 5054 appendix A.1."""


class SRP1536(SRPGroup):
    """The 1536-bit group of RFC 5054 appendix A.2."""


class SRP2048(SRPGroup):
    """The 2048-bit group of RFC 5054 appendix A.3."""


class SRP3072(SRPGroup):
    """The 3072-bit group of RFC 5054 appendix A.4."""


class SRP4096(SRPGroup):
    """The 4096-bit group of RFC 5054 appendix A.5."""


class SRP6144(SRPGroup):
    """The 6144-bit group of RFC 5054 appendix A.6."""


class SRP8192(SRPGroup):
    """The 8192-bit group of RFC 5054 appendix A.7."""


class SRPSuite:
    """The group and the hash function of ``SRP[G, H]``, ``SRPClient[G, H]`` and ``SRPServer[G, H]``."""

    @staticmethod
    def specialize(cls: type, parameters: Any) -> Any:
        group, hash = Specialization.pair(parameters, cls.__name__)
        group = Names.require(group, SRPGroup, cls.__name__)
        hash = Names.require(hash, CryptographicDigest, cls.__name__)
        return Specialization.of(cls, (group, hash), {})

    @staticmethod
    def names(cls: type) -> list[Any]:
        group, hash = Specialization.require(getattr(cls, "PARAMETERS", None), cls.__name__)
        return [*Text.encode(group.C_TYPE), *Text.encode(hash.C_TYPE)]


class SRP:
    """The computations of SRP in the group and with the hash function of ``SRP[G, H]``."""

    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    def __class_getitem__(cls, parameters: Any) -> Any:
        return SRPSuite.specialize(cls, parameters)

    @classmethod
    def verifier(
        cls,
        salt: bytes | bytearray | memoryview,
        identity: bytes | bytearray | memoryview,
        password: bytes | bytearray | memoryview,
    ) -> bytes:
        """v = g^x % N of the user ``identity`` with ``password`` and ``salt`` (section 2.4), without
        leading zeros; the server keeps it instead of the password."""
        arguments: list[Any] = []
        for value in (salt, identity, password):
            arguments.extend(Bytes.readable(value))
        return Library.default().output("umilib_crypto_srp_srp_verifier", *SRPSuite.names(cls), *arguments)


class SRPClient(Handle):
    """The client of SRP in the group and with the hash function of ``SRPClient[G, H]``: the secret
    exponent a and A = g^a % N (section 2.5.4); zeroized when released."""

    FREE = "umilib_crypto_srp_srp_client_free"
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    def __class_getitem__(cls, parameters: Any) -> Any:
        return SRPSuite.specialize(cls, parameters)

    def __init__(self, secret: bytes | bytearray) -> None:
        """The client of the secret exponent a of ``secret``; raises ``InvalidKey`` for a = 0 or more
        bytes than N. A ``bytearray`` is zeroized afterwards."""
        source = Secret(secret if isinstance(secret, bytearray) else bytearray(secret))
        with source:
            with source.locked():
                data, length = source.location()
                pointer = Handle.create("umilib_crypto_srp_srp_client_new", *SRPSuite.names(type(self)), data, length)
        super().__init__(pointer)

    @classmethod
    def new(cls, secret: bytes | bytearray) -> Any:
        return cls(secret)

    @classmethod
    def generate(cls, random: Random) -> Any:
        """A client with a random exponent of 256 bits at least."""
        client = cls.__new__(cls)
        handle, name, length = random.source()
        Handle.__init__(client, Handle.create("umilib_crypto_srp_srp_client_generate", *SRPSuite.names(cls), handle, name, length))
        return client

    def public_value(self) -> bytes:
        """A, as the client sends it (without leading zeros)."""
        return self.library.output("umilib_crypto_srp_srp_client_public_value", self.handle)

    def premaster_secret(
        self,
        identity: bytes | bytearray | memoryview,
        password: bytes | bytearray | memoryview,
        salt: bytes | bytearray | memoryview,
        server_public: bytes | bytearray | memoryview,
    ) -> bytearray:
        """The premaster secret of section 2.6, a secret to zeroize, for the user ``identity`` with
        ``password`` and the salt and B of the server; raises ``InvalidKey`` for B % N = 0 or u = 0."""
        arguments: list[Any] = []
        for value in (identity, password, salt, server_public):
            arguments.extend(Bytes.readable(value))
        return self.library.output_secret("umilib_crypto_srp_srp_client_premaster_secret", self.handle, *arguments)

    def __repr__(self) -> str:
        return "SRPClient(..)"


class SRPServer(Handle):
    """The server of SRP in the group and with the hash function of ``SRPServer[G, H]``: the verifier,
    the secret exponent b and B = k v + g^b % N; zeroized when released."""

    FREE = "umilib_crypto_srp_srp_server_free"
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    def __class_getitem__(cls, parameters: Any) -> Any:
        return SRPSuite.specialize(cls, parameters)

    def __init__(self, verifier: bytes | bytearray | memoryview, secret: bytes | bytearray) -> None:
        """The server of ``verifier`` (as :meth:`SRP.verifier` gives it) and the secret exponent b of
        ``secret``; raises ``InvalidKey`` for b = 0, v % N = 0 or values longer than N."""
        verifier_data, verifier_length = Bytes.readable(verifier)
        source = Secret(secret if isinstance(secret, bytearray) else bytearray(secret))
        with source:
            with source.locked():
                data, length = source.location()
                pointer = Handle.create("umilib_crypto_srp_srp_server_new", *SRPSuite.names(type(self)), verifier_data, verifier_length, data, length)
        super().__init__(pointer)

    @classmethod
    def new(cls, verifier: bytes | bytearray | memoryview, secret: bytes | bytearray) -> Any:
        return cls(verifier, secret)

    @classmethod
    def generate(cls, verifier: bytes | bytearray | memoryview, random: Random) -> Any:
        """A server of ``verifier`` with a random exponent of 256 bits at least."""
        server = cls.__new__(cls)
        verifier_data, verifier_length = Bytes.readable(verifier)
        handle, name, length = random.source()
        Handle.__init__(
            server, Handle.create("umilib_crypto_srp_srp_server_generate", *SRPSuite.names(cls), verifier_data, verifier_length, handle, name, length)
        )
        return server

    def public_value(self) -> bytes:
        """B, as the server sends it (without leading zeros)."""
        return self.library.output("umilib_crypto_srp_srp_server_public_value", self.handle)

    def premaster_secret(self, client_public: bytes | bytearray | memoryview) -> bytearray:
        """The premaster secret of section 2.6 for the client's A, a secret to zeroize; raises
        ``InvalidKey`` for A % N = 0 or u = 0."""
        data, length = Bytes.readable(client_public)
        return self.library.output_secret("umilib_crypto_srp_srp_server_premaster_secret", self.handle, data, length)

    def __repr__(self) -> str:
        return "SRPServer(..)"


__all__ = ["SRP", "SRP1024", "SRP1536", "SRP2048", "SRP3072", "SRP4096", "SRP6144", "SRP8192", "SRPClient", "SRPGroup", "SRPServer", "SRPSuite"]
