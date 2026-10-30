"""Identity-based signatures on pairing-friendly curves. Mirrors ``umilib::crypto::ibs``.

A private key generator holds the master key (:class:`IBSMasterKey`): the
secret s and the public P_pub = s P in G_2.
It extracts the key of each identity (:class:`IBSUserKey`), with which the
user signs; anyone verifies from the identity and P_pub alone. The schemes
are :mod:`umilib.crypto.ibs.hess`, :mod:`umilib.crypto.ibs.chacheon` and
:mod:`umilib.crypto.ibs.sm9`, of the interface :class:`IdentityBasedSignature`;
each encodes the master public key in its own way.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import Names, Specialization
from umilib.crypto.random import Random
from umilib.ffi import Bytes, Handle, Library
from umilib.hash import CryptographicDigest
from umilib.math.pairing import PairingCurve
from umilib.secret import Secret

P = "umilib_crypto_ibs_ibs"


class IBSMasterKey(Handle):
    """The master key of a private key generator, which keeps its scheme; zeroized when released."""

    FREE = f"{P}_master_key_free"

    def __init__(self, scheme: type, pointer: int) -> None:
        super().__init__(pointer)
        self.scheme = scheme

    def public_key(self) -> bytes:
        """P_pub, the master public key."""
        return self.library.output(f"{P}_master_key_public_key", self.handle)

    def secret(self) -> bytearray:
        """s, big-endian of the bytes of r, a secret to zeroize."""
        return self.library.output_secret(f"{P}_master_key_secret", self.handle)

    def __repr__(self) -> str:
        return f"IBSMasterKey({self.scheme.__name__}, ..)"


class IBSUserKey(Handle):
    """The key s H1(ID) of a user, which keeps its scheme; zeroized when released."""

    FREE = f"{P}_user_key_free"

    def __init__(self, scheme: type, pointer: int) -> None:
        super().__init__(pointer)
        self.scheme = scheme

    def identity(self) -> bytes:
        return self.library.output(f"{P}_user_key_identity", self.handle)

    def __repr__(self) -> str:
        return f"IBSUserKey({self.scheme.__name__}, {self.identity()!r}, ..)"


class IdentityBasedSignature:
    """An identity-based signature scheme, as the Rust trait ``IdentityBasedSignature``: ``Hess[C, H]``
    on a pairing-friendly curve of :mod:`umilib.math.pairing` with a hash function."""

    PREFIX: ClassVar[str] = ""
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    def __class_getitem__(cls, parameters: Any) -> Any:
        curve, hash = Specialization.pair(parameters, cls.__name__)
        curve = PairingCurve.require(curve, cls.__name__)
        hash = Names.require(hash, CryptographicDigest, cls.__name__)
        return Specialization.of(cls, (curve, hash), {"__doc__": f"{cls.__name__} on {curve.__name__} with {hash.__name__}."})

    @classmethod
    def names(cls) -> list[Any]:
        from umilib.ffi import Text

        curve, hash = Specialization.require(cls.PARAMETERS, cls.__name__)
        return [*Text.encode(curve.C_TYPE), *Text.encode(hash.C_TYPE)]

    @classmethod
    def sizes(cls) -> tuple[int, int, int]:
        """The bytes of a master secret, a master public key and a signature."""
        out = (ctypes.c_size_t * 3)()
        Library.default().call(f"{cls.PREFIX}_sizes", *cls.names(), out)
        return out[0], out[1], out[2]

    @classmethod
    def setup(cls, random: Random) -> IBSMasterKey:
        """The master key of a new private key generator (Setup), drawn from ``random``."""
        handle, name, length = random.source()
        return IBSMasterKey(cls, Handle.create(f"{cls.PREFIX}_setup", *cls.names(), handle, name, length))

    @classmethod
    def master_key_new(cls, secret: bytes | bytearray) -> IBSMasterKey:
        """The master key of the secret s (big-endian, 1 <= s < r); raises ``InvalidKey`` otherwise. A
        ``bytearray`` is zeroized afterwards."""
        source = Secret(secret if isinstance(secret, bytearray) else bytearray(secret))
        with source:
            with source.locked():
                data, length = source.location()
                pointer = Handle.create(f"{cls.PREFIX}_master_key_new", *cls.names(), data, length)
        return IBSMasterKey(cls, pointer)

    @classmethod
    def extract(cls, master: IBSMasterKey, identity: bytes | bytearray | memoryview) -> IBSUserKey:
        """The private key of ``identity`` (Extract)."""
        if master.scheme is not cls:
            raise TypeError(f"the master key is one of {master.scheme.__name__}")
        data, length = Bytes.readable(identity)
        return IBSUserKey(cls, Handle.create(f"{P}_master_key_extract", master.handle, data, length))

    @classmethod
    def sign(cls, key: IBSUserKey, message: bytes | bytearray | memoryview, random: Random) -> bytes:
        """The encoded signature of ``message`` by the owner of ``key``, with random values of ``random``."""
        if key.scheme is not cls:
            raise TypeError(f"the key is one of {key.scheme.__name__}")
        data, length = Bytes.readable(message)
        handle, name, name_length = random.source()
        return Library.default().output(f"{P}_user_key_sign", key.handle, data, length, handle, name, name_length)

    @classmethod
    def verify(
        cls,
        master: bytes | bytearray | memoryview,
        identity: bytes | bytearray | memoryview,
        message: bytes | bytearray | memoryview,
        signature: bytes | bytearray | memoryview,
    ) -> None:
        """Returns if ``signature`` is a signature of ``message`` by ``identity`` under the master public
        key ``master``; raises ``InvalidSignature`` otherwise, and ``InvalidKey`` for a master key that is
        not a point of G_2."""
        arguments: list[Any] = []
        for value in (master, identity, message, signature):
            arguments.extend(Bytes.readable(value))
        Library.default().call(f"{cls.PREFIX}_verify", *cls.names(), *arguments)


__all__ = ["IBSMasterKey", "IBSUserKey", "IdentityBasedSignature"]
