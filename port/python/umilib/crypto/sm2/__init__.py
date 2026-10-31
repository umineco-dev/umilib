"""SM2 (GB/T 32918): signatures, key exchange and encryption. Mirrors ``umilib::crypto::sm2``.

The C ABI exports the parameters GB/T 32918 recommends, the curve of SM2
with SM3: ``SM2DSA[SM2, SM3]`` signs as :class:`SignatureScheme`, with the
default identity of GB/T 35276 or another (:meth:`SM2DSA.sign_with_identity`);
its keys serve :class:`SM2PKE` and :class:`SM2KEP` too: the private key is
big-endian, the public key the uncompressed point.
"""

from __future__ import annotations

import ctypes
import enum
from typing import Any, ClassVar

from umilib.crypto import EncodedKey, Names, SignatureScheme, SigningKey, Specialization, VerifyingKey
from umilib.crypto.random import Random
from umilib.ffi import Bytes, Handle, Library, Preset
from umilib.hash import CryptographicDigest
from umilib.math.ec import WeierstrassCurve
from umilib.secret import ConstantTimeEq


class SM2DSA(SignatureScheme):
    """The signatures of SM2 (GB/T 32918.2) on the curve and with the hash function of ``SM2DSA[C, H]``."""

    PREFIX = "umilib_crypto_sm2_sm2dsa"
    #: The identity of GB/T 35276 for signers without another.
    DEFAULT_IDENTITY: ClassVar[bytes] = b"1234567812345678"

    def __class_getitem__(cls, parameters: Any) -> Any:
        curve, hash = Specialization.pair(parameters, "SM2DSA")
        curve = Names.require(curve, WeierstrassCurve, "SM2DSA")
        hash = Names.require(hash, CryptographicDigest, "SM2DSA")
        return cls.specialize((curve, hash), cls.SIZES, {"__doc__": f"SM2 on {curve.__name__} with {hash.__name__}."})

    @classmethod
    def sign_with_identity(
        cls, key: SigningKey, identity: bytes | bytearray | memoryview, message: bytes | bytearray | memoryview
    ) -> bytes:
        """The signature of ``message`` by the signer ``identity``."""
        key.check(cls)
        out = (ctypes.c_uint8 * cls.SIGNATURE_SIZE)()
        identity_data, identity_length = Bytes.readable(identity)
        message_data, message_length = Bytes.readable(message)
        with EncodedKey.encodings(key) as [(data, length)]:
            cls.call("sign_with_identity", data, length, identity_data, identity_length, message_data, message_length, out, len(out))
        return bytes(out)

    @classmethod
    def verify_with_identity(
        cls,
        key: VerifyingKey,
        identity: bytes | bytearray | memoryview,
        message: bytes | bytearray | memoryview,
        signature: bytes | bytearray | memoryview,
    ) -> None:
        key.check(cls)
        identity_data, identity_length = Bytes.readable(identity)
        message_data, message_length = Bytes.readable(message)
        signature_data, signature_length = Bytes.readable(signature)
        with EncodedKey.encodings(key) as [(data, length)]:
            cls.call(
                "verify_with_identity",
                data,
                length,
                identity_data,
                identity_length,
                message_data,
                message_length,
                signature_data,
                signature_length,
            )


class SM2Signature:
    """A signature (r, s) of ``SM2DSA[C, H]``, held as r || s, converted to and from DER (GM/T
    0009-2012 section 7.3); the C ABI has the DER conversions with ``codec-asn1-der``."""

    SCHEME: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    def __class_getitem__(cls, parameters: Any) -> Any:
        curve, hash = Specialization.pair(parameters, "SM2Signature")
        return Specialization.of(cls, (curve, hash), {"SCHEME": SM2DSA[curve, hash]})

    def __init__(self, data: bytes) -> None:
        self.data = data

    @classmethod
    def from_bytes(cls, data: bytes | bytearray | memoryview) -> Any:
        """The signature of r || s; raises ``InvalidSignature`` unless 1 <= r, s < n."""
        signature = cls(bytes(data))
        signature.to_der()
        return signature

    def to_bytes(self) -> bytes:
        return self.data

    @classmethod
    def from_der(cls, der: bytes | bytearray | memoryview) -> Any:
        scheme = Specialization.require(cls.SCHEME, "SM2Signature")
        data, length = Bytes.readable(der)
        return cls(Library.default().output("umilib_crypto_sm2_sm2dsa_signature_from_der", *scheme.names(), data, length))

    def to_der(self) -> bytes:
        data, length = Bytes.readable(self.data)
        return Library.default().output("umilib_crypto_sm2_sm2dsa_signature_to_der", *self.SCHEME.names(), data, length)

    def __eq__(self, other: object) -> bool:
        if type(other) is not type(self):
            return NotImplemented
        return self.data == other.data  # type: ignore[attr-defined]

    def __hash__(self) -> int:
        return hash((type(self), self.data))

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.data.hex()})"


class SM2CiphertextOrder(enum.IntEnum):
    """The order of the parts of a ciphertext of :class:`SM2PKE`."""

    #: C1 || C3 || C2, of GB/T 32918.4-2016.
    C1C3C2 = 0
    #: C1 || C2 || C3, of the 2010 edition.
    C1C2C3 = 1


class SM2PKE:
    """The public-key encryption of SM2 (GB/T 32918.4) on the curve and with the hash function of
    ``SM2PKE[C, H]``, with the keys of ``SM2DSA[C, H]``."""

    SCHEME: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None
    #: The bytes a ciphertext adds to its message: C1 (65) and C3 (32).
    OVERHEAD: ClassVar[Any] = Preset(lambda: Library.default().function("umilib_crypto_sm2_sm2pke_overhead")())

    def __class_getitem__(cls, parameters: Any) -> Any:
        curve, hash = Specialization.pair(parameters, "SM2PKE")
        return Specialization.of(cls, (curve, hash), {"SCHEME": SM2DSA[curve, hash]})

    @classmethod
    def encrypt(
        cls, key: VerifyingKey, message: bytes | bytearray | memoryview, order: SM2CiphertextOrder, random: Random
    ) -> bytes:
        """The ciphertext of ``message`` for ``key`` in ``order``, with k drawn from ``random``."""
        scheme = Specialization.require(cls.SCHEME, "SM2PKE")
        key.check(scheme)
        out = (ctypes.c_uint8 * (len(message) + cls.OVERHEAD))()
        message_data, message_length = Bytes.readable(message)
        handle, name, length = random.source()
        with EncodedKey.encodings(key) as [(data, key_length)]:
            Library.default().call(
                "umilib_crypto_sm2_sm2pke_encrypt",
                *scheme.names(),
                data,
                key_length,
                message_data,
                message_length,
                int(order),
                handle,
                name,
                length,
                out,
                len(out),
            )
        return bytes(out)

    @classmethod
    def decrypt(
        cls, key: SigningKey, ciphertext: bytes | bytearray | memoryview, order: SM2CiphertextOrder, out: bytearray
    ) -> None:
        """Writes the message of ``ciphertext`` into ``out`` of its length (that of the ciphertext less
        ``OVERHEAD``); raises ``DecryptionFailed`` if C3 does not match."""
        scheme = Specialization.require(cls.SCHEME, "SM2PKE")
        key.check(scheme)
        ciphertext_data, ciphertext_length = Bytes.readable(ciphertext)
        with EncodedKey.encodings(key) as [(data, length)]:
            Library.default().call(
                "umilib_crypto_sm2_sm2pke_decrypt",
                *scheme.names(),
                data,
                length,
                ciphertext_data,
                ciphertext_length,
                int(order),
                Bytes.mutable(out),
                len(out),
            )


class SM2Role(enum.IntEnum):
    """The side of a party in :class:`SM2KEP`."""

    INITIATOR = 0
    RESPONDER = 1


class SM2KeyConfirmation:
    """The optional confirmations of the key exchange: S_B, which the responder sends, and S_A, which
    the initiator sends (GB/T 32918.3 steps B8 and A10)."""

    def __init__(self, responder: bytes, initiator: bytes) -> None:
        self.responder_value = responder
        self.initiator_value = initiator

    def responder(self) -> bytes:
        """S_B (0x02)."""
        return self.responder_value

    def initiator(self) -> bytes:
        """S_A (0x03)."""
        return self.initiator_value

    def __repr__(self) -> str:
        return "SM2KeyConfirmation(..)"


class SM2KEP(Handle):
    """One side of the key exchange of SM2 (GB/T 32918.3) on the curve of SM2 with SM3."""

    FREE = "umilib_crypto_sm2_sm2kep_free"

    def __init__(
        self,
        role: SM2Role,
        key: SigningKey,
        identity: bytes | bytearray | memoryview,
        ephemeral: SigningKey,
    ) -> None:
        """The side ``role`` of the key ``key`` and the signer ``identity``, with the ephemeral private
        key r of ``ephemeral``, which must be fresh and secret (see :meth:`generate`)."""
        scheme = SM2KEP.scheme()
        key.check(scheme)
        ephemeral.check(scheme)
        identity_data, identity_length = Bytes.readable(identity)
        with EncodedKey.encodings(key, ephemeral) as [(data, length), (ephemeral_data, ephemeral_length)]:
            pointer = Handle.create(
                "umilib_crypto_sm2_sm2kep_new", int(role), data, length, identity_data, identity_length, ephemeral_data, ephemeral_length
            )
        super().__init__(pointer)
        self.role = role

    @classmethod
    def generate(cls, role: SM2Role, key: SigningKey, identity: bytes | bytearray | memoryview, random: Random) -> SM2KEP:
        """The side ``role`` with an ephemeral key drawn from ``random``."""
        key.check(SM2KEP.scheme())
        side = cls.__new__(cls)
        identity_data, identity_length = Bytes.readable(identity)
        handle, name, name_length = random.source()
        with EncodedKey.encodings(key, handles=(random,)) as [(data, length)]:
            pointer = Handle.create(
                "umilib_crypto_sm2_sm2kep_generate", int(role), data, length, identity_data, identity_length, handle, name, name_length
            )
        Handle.__init__(side, pointer)
        side.role = role
        return side

    @staticmethod
    def scheme() -> Any:
        """``SM2DSA[SM2, SM3]``, the scheme of the keys of the exchange."""
        from umilib.crypto.curve.sm2 import SM2
        from umilib.hash.sm3 import SM3

        return SM2DSA[SM2, SM3]

    def ephemeral_public_key(self) -> bytes:
        """R, to send to the other party: the uncompressed point."""
        out = (ctypes.c_uint8 * 65)()
        self.library.call("umilib_crypto_sm2_sm2kep_ephemeral_public_key", self.handle, out, len(out))
        return bytes(out)

    def agree(
        self,
        peer: VerifyingKey,
        peer_identity: bytes | bytearray | memoryview,
        peer_ephemeral: bytes | bytearray | memoryview,
        out: bytearray,
    ) -> SM2KeyConfirmation:
        """Writes the shared key with the other party into ``out`` (of the length of the key to derive)
        and returns the confirmations; raises ``InvalidKey`` if the shared point is the identity."""
        peer.check(SM2KEP.scheme())
        responder, initiator = (ctypes.c_uint8 * 32)(), (ctypes.c_uint8 * 32)()
        identity_data, identity_length = Bytes.readable(peer_identity)
        ephemeral_data, ephemeral_length = Bytes.readable(peer_ephemeral)
        peer_data, peer_length = Bytes.readable(peer.to_bytes())
        self.library.call(
            "umilib_crypto_sm2_sm2kep_agree",
            self.handle,
            peer_data,
            peer_length,
            identity_data,
            identity_length,
            ephemeral_data,
            ephemeral_length,
            Bytes.mutable(out),
            len(out),
            responder,
            32,
            initiator,
            32,
        )
        return SM2KeyConfirmation(bytes(responder), bytes(initiator))

    def confirm(self, confirmation: SM2KeyConfirmation, received: bytes | bytearray | memoryview) -> bool:
        """Whether ``received`` is the confirmation the other party must send: S_B for the initiator,
        S_A for the responder; compared in constant time."""
        expected = confirmation.responder() if self.role == SM2Role.INITIATOR else confirmation.initiator()
        return ConstantTimeEq.ct_eq(expected, received).into_bool()

    def __repr__(self) -> str:
        return f"SM2KEP({self.role.name}, ..)"


__all__ = ["SM2CiphertextOrder", "SM2DSA", "SM2KEP", "SM2KeyConfirmation", "SM2PKE", "SM2Role", "SM2Signature"]
