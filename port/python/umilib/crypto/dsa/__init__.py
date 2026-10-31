"""DSA (FIPS 186-4) with deterministic nonces (RFC 6979). Mirrors ``umilib::crypto::dsa``.

:class:`DSAParameters`, :class:`DSASigningKey` and :class:`DSAVerifyingKey`
hold their values in umilib; integers are big-endian bytes. ``DSA[SHA256]``
signs with a hash function; a :class:`DSASignature` is r || s, each of the
bytes of q, converted to and from DER.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import Names, Specialization
from umilib.crypto.random import Random
from umilib.ffi import Bytes, Handle, Library, Text
from umilib.hash import CryptographicDigest


class DSAParameters(Handle):
    """The domain parameters (p, q, g) of FIPS 186-4 section 4.3."""

    FREE = "umilib_crypto_dsa_dsa_parameters_free"

    def __init__(self, p: bytes | bytearray | memoryview, q: bytes | bytearray | memoryview, g: bytes | bytearray | memoryview) -> None:
        """The parameters of the sizes (L, N) of FIPS 186-4 section 4.2; raises ``InvalidParameter``
        for other sizes or inconsistent values."""
        arguments: list[Any] = []
        for value in (p, q, g):
            arguments.extend(Bytes.readable(value))
        super().__init__(Handle.create("umilib_crypto_dsa_dsa_parameters_new", *arguments))

    @classmethod
    def new(cls, p: bytes | bytearray | memoryview, q: bytes | bytearray | memoryview, g: bytes | bytearray | memoryview) -> DSAParameters:
        return cls(p, q, g)

    def p(self) -> bytes:
        return self.library.output("umilib_crypto_dsa_dsa_parameters_p", self.handle)

    def q(self) -> bytes:
        return self.library.output("umilib_crypto_dsa_dsa_parameters_q", self.handle)

    def g(self) -> bytes:
        """g, of the bytes of p."""
        return self.library.output("umilib_crypto_dsa_dsa_parameters_g", self.handle)

    def q_bytes(self) -> int:
        """The bytes of q, those of each half of a signature."""
        return self.library.value("umilib_crypto_dsa_dsa_parameters_q_bytes", ctypes.c_size_t, self.handle)

    def __repr__(self) -> str:
        return "DSAParameters(..)"


class DSAVerifyingKey(Handle):
    """A verifying key y of DSA under its parameters."""

    FREE = "umilib_crypto_dsa_dsa_verifying_key_free"

    def __init__(self, parameters: DSAParameters, y: bytes | bytearray | memoryview) -> None:
        """The key ``y`` under a copy of ``parameters``; raises ``InvalidKey`` unless 2 <= y <= p - 2
        and y^q = 1 mod p."""
        data, length = Bytes.readable(y)
        super().__init__(Handle.create("umilib_crypto_dsa_dsa_verifying_key_new", parameters.handle, data, length))
        self.parameters_value = parameters

    @classmethod
    def new(cls, parameters: DSAParameters, y: bytes | bytearray | memoryview) -> DSAVerifyingKey:
        return cls(parameters, y)

    def parameters(self) -> DSAParameters:
        return self.parameters_value

    def y(self) -> bytes:
        """y big-endian, of the bytes of p."""
        return self.library.output("umilib_crypto_dsa_dsa_verifying_key_y", self.handle)

    def __repr__(self) -> str:
        return f"DSAVerifyingKey({self.y().hex()})"


class DSASigningKey(Handle):
    """A signing key x of DSA with its parameters and verifying key; zeroized when released."""

    FREE = "umilib_crypto_dsa_dsa_signing_key_free"

    def __init__(self, parameters: DSAParameters, x: bytes | bytearray | memoryview) -> None:
        """The key ``x`` (1 <= x < q) under a copy of ``parameters``."""
        data, length = Bytes.readable(x)
        super().__init__(Handle.create("umilib_crypto_dsa_dsa_signing_key_new", parameters.handle, data, length))
        self.parameters_value = parameters

    @classmethod
    def new(cls, parameters: DSAParameters, x: bytes | bytearray | memoryview) -> DSASigningKey:
        return cls(parameters, x)

    @classmethod
    def generate(cls, parameters: DSAParameters, random: Random) -> DSASigningKey:
        """A key drawn from ``random`` (FIPS 186-4 appendix B.1.2)."""
        key = cls.__new__(cls)
        handle, name, length = random.source()
        Handle.__init__(key, Handle.create("umilib_crypto_dsa_dsa_signing_key_generate", parameters.handle, handle, name, length))
        key.parameters_value = parameters
        return key

    def parameters(self) -> DSAParameters:
        return self.parameters_value

    def x(self) -> bytearray:
        """x, of the bytes of q, a secret to zeroize."""
        return self.library.output_secret("umilib_crypto_dsa_dsa_signing_key_x", self.handle)

    def verifying_key(self) -> DSAVerifyingKey:
        key = DSAVerifyingKey.__new__(DSAVerifyingKey)
        Handle.__init__(key, Handle.create("umilib_crypto_dsa_dsa_signing_key_verifying_key", self.handle))
        key.parameters_value = self.parameters_value
        return key

    def __repr__(self) -> str:
        return "DSASigningKey(..)"


class DSASignature:
    """A signature (r, s) of DSA under its parameters, held as r || s."""

    def __init__(self, parameters: DSAParameters, data: bytes) -> None:
        self.parameters = parameters
        self.data = data

    @classmethod
    def from_bytes(cls, parameters: DSAParameters, data: bytes | bytearray | memoryview) -> DSASignature:
        """The signature of r || s; raises ``InvalidSignature`` unless 1 <= r, s < q."""
        signature = cls(parameters, bytes(data))
        signature.to_der()
        return signature

    def to_bytes(self) -> bytes:
        return self.data

    @classmethod
    def from_der(cls, parameters: DSAParameters, der: bytes | bytearray | memoryview) -> DSASignature:
        """The signature of the DER ``Dss-Sig-Value`` (RFC 3279 section 2.2.2)."""
        data, length = Bytes.readable(der)
        return cls(parameters, Library.default().output("umilib_crypto_dsa_dsa_signature_from_der", parameters.handle, data, length))

    def to_der(self) -> bytes:
        data, length = Bytes.readable(self.data)
        return Library.default().output("umilib_crypto_dsa_dsa_signature_to_der", self.parameters.handle, data, length)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DSASignature):
            return NotImplemented
        return self.data == other.data

    def __hash__(self) -> int:
        return hash(self.data)

    def __repr__(self) -> str:
        return f"DSASignature({self.data.hex()})"


class DSA:
    """The signatures of DSA with the hash function of ``DSA[H]`` and the nonces of RFC 6979."""

    HASH: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    def __class_getitem__(cls, hash: Any) -> Any:
        hash = Names.require(hash, CryptographicDigest, "DSA")
        return Specialization.of(cls, (hash,), {"HASH": hash})

    @classmethod
    def hash_name(cls) -> tuple[Any, int]:
        return Text.encode(Specialization.require(cls.HASH, "DSA").C_TYPE)

    @classmethod
    def sign(cls, key: DSASigningKey, message: bytes | bytearray | memoryview) -> DSASignature:
        size = 2 * key.parameters().q_bytes()
        out = (ctypes.c_uint8 * size)()
        data, length = Bytes.readable(message)
        Library.default().call("umilib_crypto_dsa_dsa_sign", key.handle, *cls.hash_name(), data, length, out, size)
        return DSASignature(key.parameters(), bytes(out))

    @classmethod
    def verify(cls, key: DSAVerifyingKey, message: bytes | bytearray | memoryview, signature: DSASignature) -> None:
        """Returns if ``signature`` is a signature of ``message``; raises ``InvalidSignature`` otherwise."""
        data, length = Bytes.readable(message)
        signature_data, signature_length = Bytes.readable(signature.data)
        Library.default().call("umilib_crypto_dsa_dsa_verify", key.handle, *cls.hash_name(), data, length, signature_data, signature_length)


__all__ = ["DSA", "DSAParameters", "DSASignature", "DSASigningKey", "DSAVerifyingKey"]
