"""ECCSI, elliptic curve-based certificateless signatures for identity-based encryption (RFC 6507).
Mirrors ``umilib::crypto::eccsi``.

A KMS (:class:`ECCSIKMS`) holds the secret KSAK and publishes KPAK; it
issues to each identity the secret SSK and the public PVT
(:class:`ECCSIUserKey`), with which ``ECCSI[C, H]`` signs. The C ABI takes
the pairs of section 4.1, such as P-256 with SHA-256: secrets are big-endian
integers of the bytes of the order, points the uncompressed form of RFC 6509
section 3.2. Secrets stay in a :class:`~umilib.secret.Secret`.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import Names, Specialization
from umilib.crypto.random import Random
from umilib.ffi import Bytes, Handle, Library, Text
from umilib.hash import CryptographicDigest
from umilib.math.ec import WeierstrassCurve
from umilib.secret import Secret


class ECCSINames:
    """The arguments that name a curve and a hash function."""

    @staticmethod
    def of(*parameters: Any) -> list[Any]:
        arguments: list[Any] = []
        for parameter in parameters:
            arguments.extend(Text.encode(parameter.C_TYPE))
        return arguments

    @staticmethod
    def kms_sizes(curve: Any) -> tuple[int, int]:
        """The bytes of a secret and of a point on ``curve``."""
        out = (ctypes.c_size_t * 2)()
        Library.default().call("umilib_crypto_eccsi_eccsi_kms_sizes", *ECCSINames.of(curve), out)
        return out[0], out[1]

    @staticmethod
    def sizes(curve: Any, hash: Any) -> tuple[int, int, int]:
        """The bytes of a secret, a point and a signature; raises ``InvalidParameter`` for a pair other
        than those of section 4.1."""
        out = (ctypes.c_size_t * 3)()
        Library.default().call("umilib_crypto_eccsi_eccsi_sizes", *ECCSINames.of(curve, hash), out)
        return out[0], out[1], out[2]


class ECCSIKMS:
    """The KMS of a community on the curve of ``ECCSIKMS[C]``: the KSAK and its KPAK (section 4.2)."""

    CURVE: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    def __class_getitem__(cls, curve: Any) -> Any:
        curve = Names.require(curve, WeierstrassCurve, "ECCSIKMS")
        return Specialization.of(cls, (curve,), {"CURVE": curve})

    def __init__(self, secret: bytes | bytearray) -> None:
        """The KMS of the KSAK ``secret`` (big-endian); raises ``InvalidKey`` for zero or a value not
        below the order. A ``bytearray`` is zeroized once the KMS holds its copy."""
        curve = Specialization.require(self.CURVE, "ECCSIKMS")
        self.secret_value = Secret(secret if isinstance(secret, bytearray) else bytearray(secret))
        out = (ctypes.c_uint8 * ECCSINames.kms_sizes(curve)[1])()
        try:
            with self.secret_value.locked():
                data, length = self.secret_value.location()
                Library.default().call("umilib_crypto_eccsi_eccsi_kms_public_key", *ECCSINames.of(curve), data, length, out, len(out))
        except BaseException:
            self.secret_value.close()
            raise
        self.public = bytes(out)

    @classmethod
    def new(cls, secret: bytes | bytearray) -> Any:
        return cls(secret)

    @classmethod
    def generate(cls, random: Random) -> Any:
        """A KMS with a random KSAK."""
        curve = Specialization.require(cls.CURVE, "ECCSIKMS")
        kms = cls.__new__(cls)
        size, point_size = ECCSINames.kms_sizes(curve)
        kms.secret_value = Secret(bytearray(size))
        public = (ctypes.c_uint8 * point_size)()
        handle, name, length = random.source()
        with Handle.locked_all(kms.secret_value, random):
            data, data_length = kms.secret_value.location_mut()
            Library.default().call(
                "umilib_crypto_eccsi_eccsi_kms_generate", *ECCSINames.of(curve), handle, name, length, data, data_length, public, len(public)
            )
        kms.public = bytes(public)
        return kms

    def public_key(self) -> bytes:
        """KPAK, the root of trust of the community."""
        return self.public

    def secret(self) -> Secret:
        """KSAK, the secret of the service."""
        return self.secret_value

    def issue(self, hash: Any, identity: bytes | bytearray | memoryview, random: Random) -> ECCSIUserKey:
        """The (SSK, PVT) pair of ``identity`` (section 5.1.1) for ``ECCSI[C, hash]``, with v drawn from ``random``."""
        handle, name, length = random.source()
        return self.issue_with("kms_issue", hash, identity, (handle, name, length), (random,))

    def issue_with_ephemeral(self, hash: Any, identity: bytes | bytearray | memoryview, ephemeral: bytes | bytearray) -> ECCSIUserKey:
        """The pair with v given (section 5.1.1 steps 2 to 6); v must be secret, random and used once.
        Raises ``InvalidParameter`` when another v is needed."""
        v = Secret(ephemeral if isinstance(ephemeral, bytearray) else bytearray(ephemeral))
        with v:
            return self.issue_with("kms_issue_with_ephemeral", hash, identity, v, (v,))

    def issue_with(self, function: str, hash: Any, identity: Any, tail: tuple[Any, ...] | Secret, handles: tuple[Handle, ...]) -> ECCSIUserKey:
        """Calls ``function`` with the trailing arguments ``tail`` (the generator, or the ephemeral
        secret, read while every handle is locked)."""
        curve = self.CURVE
        hash = Names.require(hash, CryptographicDigest, "ECCSIKMS.issue")
        size, point_size, _ = ECCSINames.sizes(curve, hash)
        secret = Secret(bytearray(size))
        token = (ctypes.c_uint8 * point_size)()
        identity_data, identity_length = Bytes.readable(identity)
        with Handle.locked_all(self.secret_value, secret, *handles):
            kms_data, kms_length = self.secret_value.location()
            secret_data, secret_length = secret.location_mut()
            arguments = tail.location() if isinstance(tail, Secret) else tail
            Library.default().call(
                f"umilib_crypto_eccsi_eccsi_{function}",
                *ECCSINames.of(curve, hash),
                kms_data,
                kms_length,
                identity_data,
                identity_length,
                *arguments,
                secret_data,
                secret_length,
                token,
                len(token),
            )
        return ECCSIUserKey[curve, hash].from_parts(self.public, bytes(identity), secret, bytes(token))

    def __repr__(self) -> str:
        return f"ECCSIKMS({self.public.hex()}, ..)"


class ECCSIUserKey:
    """The key of an identity for ``ECCSI[C, H]``: its SSK and PVT under the KPAK of its KMS."""

    CURVE: ClassVar[Any] = None
    HASH: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    def __class_getitem__(cls, parameters: Any) -> Any:
        curve, hash = Specialization.pair(parameters, "ECCSIUserKey")
        curve = Names.require(curve, WeierstrassCurve, "ECCSIUserKey")
        hash = Names.require(hash, CryptographicDigest, "ECCSIUserKey")
        return Specialization.of(cls, (curve, hash), {"CURVE": curve, "HASH": hash})

    def __init__(
        self,
        authority: bytes | bytearray | memoryview,
        identity: bytes | bytearray | memoryview,
        secret: bytes | bytearray,
        token: bytes | bytearray | memoryview,
    ) -> None:
        """The key of ``identity`` from the (SSK, PVT) pair ``secret`` and ``token`` of the KMS of KPAK
        ``authority``, validated (section 5.1.2); raises ``InvalidKey`` otherwise."""
        Specialization.require(self.PARAMETERS, "ECCSIUserKey")
        self.set(bytes(authority), bytes(identity), Secret(secret if isinstance(secret, bytearray) else bytearray(secret)), bytes(token))
        try:
            with self.secret_value.locked():
                data, length = self.secret_value.location()
                Library.default().call(
                    "umilib_crypto_eccsi_eccsi_user_key_check", *self.names(), *self.public_arguments(), data, length, *Bytes.readable(self.token_value)
                )
        except BaseException:
            self.secret_value.close()
            raise

    @classmethod
    def from_parts(cls, authority: bytes, identity: bytes, secret: Secret, token: bytes) -> Any:
        """The key of the parts a KMS issued, which it has validated."""
        key = cls.__new__(cls)
        key.set(authority, identity, secret, token)
        return key

    def set(self, authority: bytes, identity: bytes, secret: Secret, token: bytes) -> None:
        self.authority_value = authority
        self.identity_value = identity
        self.secret_value = secret
        self.token_value = token

    def names(self) -> list[Any]:
        return ECCSINames.of(self.CURVE, self.HASH)

    def public_arguments(self) -> list[Any]:
        return [*Bytes.readable(self.authority_value), *Bytes.readable(self.identity_value)]

    def identity(self) -> bytes:
        return self.identity_value

    def secret(self) -> Secret:
        """SSK."""
        return self.secret_value

    def token(self) -> bytes:
        """PVT."""
        return self.token_value

    def authority(self) -> bytes:
        """KPAK of the KMS."""
        return self.authority_value

    def __repr__(self) -> str:
        return f"ECCSIUserKey({self.identity_value!r}, ..)"


class ECCSI:
    """The signatures of ECCSI on the curve and with the hash function of ``ECCSI[C, H]``: r || s ||
    PVT, of ``SIGNATURE_SIZE`` bytes."""

    CURVE: ClassVar[Any] = None
    HASH: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None
    SIGNATURE_SIZE: ClassVar[int] = 0

    def __class_getitem__(cls, parameters: Any) -> Any:
        curve, hash = Specialization.pair(parameters, "ECCSI")
        curve = Names.require(curve, WeierstrassCurve, "ECCSI")
        hash = Names.require(hash, CryptographicDigest, "ECCSI")
        size = ECCSINames.sizes(curve, hash)[2]
        return Specialization.of(cls, (curve, hash), {"CURVE": curve, "HASH": hash, "SIGNATURE_SIZE": size})

    @classmethod
    def check(cls, key: ECCSIUserKey) -> None:
        Specialization.require(cls.PARAMETERS, "ECCSI")
        if (key.CURVE, key.HASH) != (cls.CURVE, cls.HASH):
            raise TypeError("the key is of another curve or hash function")

    @classmethod
    def sign(cls, key: ECCSIUserKey, message: bytes | bytearray | memoryview, random: Random) -> bytes:
        """The signature of ``message`` (section 5.2.1), with j derived from the key, the message and
        random bytes of ``random``."""
        cls.check(key)
        handle, name, length = random.source()
        return cls.sign_with("sign", key, message, (handle, name, length), (random,))

    @classmethod
    def sign_with_ephemeral(cls, key: ECCSIUserKey, message: bytes | bytearray | memoryview, ephemeral: bytes | bytearray) -> bytes:
        """Steps 2 to 7 of section 5.2.1 with j given; j must be secret, random and used once. Raises
        ``InvalidParameter`` when another j is needed."""
        cls.check(key)
        j = Secret(ephemeral if isinstance(ephemeral, bytearray) else bytearray(ephemeral))
        with j:
            return cls.sign_with("sign_with_ephemeral", key, message, j, (j,))

    @classmethod
    def sign_with(cls, function: str, key: ECCSIUserKey, message: Any, tail: tuple[Any, ...] | Secret, handles: tuple[Handle, ...]) -> bytes:
        """Calls ``function`` with the trailing arguments ``tail`` (the generator, or the ephemeral
        secret, read while every handle is locked)."""
        out = (ctypes.c_uint8 * cls.SIGNATURE_SIZE)()
        message_data, message_length = Bytes.readable(message)
        with Handle.locked_all(key.secret_value, *handles):
            data, length = key.secret_value.location()
            arguments = tail.location() if isinstance(tail, Secret) else tail
            Library.default().call(
                f"umilib_crypto_eccsi_eccsi_{function}",
                *key.names(),
                *key.public_arguments(),
                data,
                length,
                *Bytes.readable(key.token_value),
                message_data,
                message_length,
                *arguments,
                out,
                len(out),
            )
        return bytes(out)

    @classmethod
    def verify(
        cls,
        authority: bytes | bytearray | memoryview,
        identity: bytes | bytearray | memoryview,
        message: bytes | bytearray | memoryview,
        signature: bytes | bytearray | memoryview,
    ) -> None:
        """Returns if ``signature`` is a signature of ``message`` by ``identity`` in the community of
        KPAK ``authority`` (section 5.2.2); raises ``InvalidSignature`` otherwise."""
        Specialization.require(cls.PARAMETERS, "ECCSI")
        arguments: list[Any] = []
        for value in (authority, identity, message, signature):
            arguments.extend(Bytes.readable(value))
        Library.default().call("umilib_crypto_eccsi_eccsi_verify", *ECCSINames.of(cls.CURVE, cls.HASH), *arguments)


__all__ = ["ECCSI", "ECCSIKMS", "ECCSINames", "ECCSIUserKey"]
