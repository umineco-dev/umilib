"""SM9 key exchange, key encapsulation and public key encryption (GM/T 0044.3-2016 and 0044.4-2016).
Mirrors ``umilib::crypto::sm9``.

Every type is generic over a pairing-friendly curve of :mod:`umilib.math.pairing` and a hash
function; GM/T 0044.5 specifies ``SM9BN256`` with ``SM3``. The KGC holds the encryption master key
(:class:`SM9EncryptMasterKey`: ke and Ppub-e = [ke]P1) and extracts the key of each identity with
the identifier hid of its key generating function (:class:`SM9EncryptUserKey`: de in G_2); the
annexes of GM/T 0044.5 use hid 0x03. Scalars are big-endian of the bytes of the order, points of
G_1 x || y and points of G_2 04 || x || y, each coordinate of GF(p^2) its u-coefficient first.
The digital signature algorithm (part 2) is :mod:`umilib.crypto.ibs.sm9`.
"""

from __future__ import annotations

import ctypes
import enum
from typing import Any, ClassVar

from umilib.crypto import BlockCipherClass, Names, Specialization
from umilib.crypto.random import Random
from umilib.ffi import Bytes, Handle, Library, Marker, Text
from umilib.hash import CryptographicDigest
from umilib.math.pairing import PairingCurve
from umilib.secret import ConstantTimeEq, Secret

P = "umilib_crypto_sm9"


class SM9Scheme:
    """The curve and the hash function of a type ``T[C, H]`` of this module, named by their C type
    names in the calls of the C ABI."""

    CURVE: ClassVar[Any] = None
    HASH: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    @staticmethod
    def parameters(parameters: Any, user: str) -> tuple[Any, Any]:
        """The checked curve and hash function of ``user[C, H]``."""
        curve, hash = Specialization.pair(parameters, user)
        return PairingCurve.require(curve, user), Names.require(hash, CryptographicDigest, user)

    @classmethod
    def names(cls) -> list[Any]:
        Specialization.require(cls.PARAMETERS, cls.__name__)
        return [*Text.encode(cls.CURVE.C_TYPE), *Text.encode(cls.HASH.C_TYPE)]

    @classmethod
    def hash_name(cls) -> list[Any]:
        Specialization.require(cls.PARAMETERS, cls.__name__)
        return [*Text.encode(cls.HASH.C_TYPE)]

    @classmethod
    def sizes(cls) -> tuple[int, int, int, int]:
        """The bytes of a scalar (ke, r), a point of G_1 (Ppub-e, R, C), a point of G_2 (de) and an
        output of the hash function (C3, S_A, S_B)."""
        out = (ctypes.c_size_t * 4)()
        Library.default().call(f"{P}_sizes", *cls.names(), out)
        return out[0], out[1], out[2], out[3]

    @classmethod
    def check_key(cls, key: SM9EncryptUserKey) -> None:
        if not isinstance(key, SM9EncryptUserKey) or key.CURVE is not cls.CURVE:
            raise TypeError(f"{cls.__name__} needs a key of SM9EncryptUserKey[{cls.CURVE.__name__}]")


class SM9Ephemeral:
    """The random r given to the ``_with_ephemeral`` functions: big-endian, 1 <= r < N, secret, random
    and used once. A ``bytearray`` is zeroized afterwards."""

    @staticmethod
    def secret(ephemeral: bytes | bytearray) -> Secret:
        return Secret(ephemeral if isinstance(ephemeral, bytearray) else bytearray(ephemeral))


class SM9Role(enum.IntEnum):
    """The part a user plays in :class:`SM9KEP`."""

    INITIATOR = 0
    RESPONDER = 1


class SM9EncryptMasterKey(Handle):
    """The encryption master key of a KGC on the curve of ``SM9EncryptMasterKey[C]``: ke and Ppub-e;
    zeroized when released."""

    FREE = f"{P}_sm9_encrypt_master_key_free"
    CURVE: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    def __class_getitem__(cls, curve: Any) -> Any:
        curve = PairingCurve.require(curve, "SM9EncryptMasterKey")
        return Specialization.of(cls, (curve,), {"CURVE": curve})

    def __init__(self, secret: bytes | bytearray) -> None:
        """The master key of ke ``secret`` (big-endian, 1 <= ke < N); raises ``InvalidKey`` otherwise.
        A ``bytearray`` is zeroized afterwards."""
        curve = Specialization.require(self.CURVE, "SM9EncryptMasterKey")
        source = SM9Ephemeral.secret(secret)
        with source:
            with source.locked():
                data, length = source.location()
                pointer = Handle.create(f"{P}_sm9_encrypt_master_key_new", *Text.encode(curve.C_TYPE), data, length)
        super().__init__(pointer)

    @classmethod
    def generate(cls, random: Random) -> Any:
        """A master key with ke drawn from ``random``."""
        curve = Specialization.require(cls.CURVE, "SM9EncryptMasterKey")
        key = cls.__new__(cls)
        handle, name, length = random.source()
        pointer = Handle.create(f"{P}_sm9_encrypt_master_key_generate", *Text.encode(curve.C_TYPE), handle, name, length)
        Handle.__init__(key, pointer)
        return key

    def secret(self) -> bytearray:
        """ke, a secret to zeroize."""
        return self.library.output_secret(f"{P}_sm9_encrypt_master_key_secret", self.handle)

    def public_key(self) -> bytes:
        """Ppub-e, x || y."""
        return self.library.output(f"{P}_sm9_encrypt_master_key_public_key", self.handle)

    def extract(self, hash: Any, identity: bytes | bytearray | memoryview, hid: int) -> SM9EncryptUserKey:
        """The key of ``identity`` with the identifier ``hid``, with H1 of the hash function ``hash``
        (``extract::<H>`` in Rust); raises ``InvalidParameter`` if t1 = 0, when the master key must be
        generated again."""
        hash = Names.require(hash, CryptographicDigest, "SM9EncryptMasterKey.extract")
        data, length = Bytes.readable(identity)
        pointer = Handle.create(
            f"{P}_sm9_encrypt_master_key_extract", self.handle, *Text.encode(hash.C_TYPE), data, length, hid
        )
        return SM9EncryptUserKey[self.CURVE].from_pointer(pointer)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.public_key().hex()}, ..)"


class SM9EncryptUserKey(Handle):
    """The encryption key of a user on the curve of ``SM9EncryptUserKey[C]``: its identity, hid, de
    and Ppub-e; zeroized when released."""

    FREE = f"{P}_sm9_encrypt_user_key_free"
    CURVE: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    def __class_getitem__(cls, curve: Any) -> Any:
        curve = PairingCurve.require(curve, "SM9EncryptUserKey")
        return Specialization.of(cls, (curve,), {"CURVE": curve})

    def __init__(
        self,
        identity: bytes | bytearray | memoryview,
        hid: int,
        key: bytes | bytearray | memoryview,
        master: bytes | bytearray | memoryview,
    ) -> None:
        """The key de ``key`` (04 || x || y) of ``identity`` and ``hid`` under Ppub-e ``master``
        (x || y); raises ``InvalidKey`` unless both are points of their groups other than the identity.
        A wrong key decrypts nothing."""
        curve = Specialization.require(self.CURVE, "SM9EncryptUserKey")
        arguments: list[Any] = [*Text.encode(curve.C_TYPE), *Bytes.readable(identity), hid]
        arguments.extend(Bytes.readable(key))
        arguments.extend(Bytes.readable(master))
        super().__init__(Handle.create(f"{P}_sm9_encrypt_user_key_new", *arguments))

    @classmethod
    def from_pointer(cls, pointer: int) -> Any:
        key = cls.__new__(cls)
        Handle.__init__(key, pointer)
        return key

    def identity(self) -> bytes:
        return self.library.output(f"{P}_sm9_encrypt_user_key_identity", self.handle)

    def hid(self) -> int:
        """The identifier of the key generating function."""
        return self.library.value(f"{P}_sm9_encrypt_user_key_hid", ctypes.c_uint8, self.handle)

    def key(self) -> bytearray:
        """de, 04 || x || y, a secret to zeroize."""
        return self.library.output_secret(f"{P}_sm9_encrypt_user_key_key", self.handle)

    def master(self) -> bytes:
        """Ppub-e, x || y."""
        return self.library.output(f"{P}_sm9_encrypt_user_key_master", self.handle)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.identity()!r}, {self.hid():#04x}, ..)"


class SM9KeyConfirmation:
    """The optional confirmations of GM/T 0044.3-2016 section 6.1: S_B, which the responder sends,
    and S_A, which the initiator sends."""

    def __init__(self, responder: bytes, initiator: bytes) -> None:
        self.responder_value = responder
        self.initiator_value = initiator

    def responder(self) -> bytes:
        """Hv(0x82 || g1 || Hv(g2 || g3 || IDA || IDB || RA || RB))."""
        return self.responder_value

    def initiator(self) -> bytes:
        """Hv(0x83 || g1 || Hv(g2 || g3 || IDA || IDB || RA || RB))."""
        return self.initiator_value

    def __repr__(self) -> str:
        return "SM9KeyConfirmation(..)"


class SM9KEP(Handle, SM9Scheme):
    """One side of the key exchange of GM/T 0044.3-2016 on the curve and with the hash function of
    ``SM9KEP[C, H]``; zeroized when released."""

    FREE = f"{P}_sm9kep_free"

    def __class_getitem__(cls, parameters: Any) -> Any:
        curve, hash = SM9Scheme.parameters(parameters, "SM9KEP")
        return Specialization.of(cls, (curve, hash), {"CURVE": curve, "HASH": hash})

    def __init__(
        self,
        role: SM9Role,
        key: SM9EncryptUserKey,
        peer_identity: bytes | bytearray | memoryview,
        ephemeral: bytes | bytearray,
    ) -> None:
        """The side of ``role`` for the user of ``key`` with the user ``peer_identity`` and r
        ``ephemeral`` (see :class:`SM9Ephemeral`); raises ``InvalidKey`` for r = 0."""
        self.check_key(key)
        identity_data, identity_length = Bytes.readable(peer_identity)
        source = SM9Ephemeral.secret(ephemeral)
        with source:
            with source.locked():
                data, length = source.location()
                pointer = Handle.create(
                    f"{P}_sm9kep_new", key.handle, *self.hash_name(), int(role), identity_data, identity_length, data, length
                )
        super().__init__(pointer)
        self.side_role = SM9Role(role)

    @classmethod
    def generate(
        cls, role: SM9Role, key: SM9EncryptUserKey, peer_identity: bytes | bytearray | memoryview, random: Random
    ) -> Any:
        """The side of ``role`` with r drawn from ``random``."""
        cls.check_key(key)
        side = cls.__new__(cls)
        identity_data, identity_length = Bytes.readable(peer_identity)
        handle, name, length = random.source()
        pointer = Handle.create(
            f"{P}_sm9kep_generate", key.handle, *cls.hash_name(), int(role), identity_data, identity_length, handle, name, length
        )
        Handle.__init__(side, pointer)
        side.side_role = SM9Role(role)
        return side

    def role(self) -> SM9Role:
        return self.side_role

    def ephemeral_public_key(self) -> bytes:
        """R, x || y, which this side sends to the other."""
        return self.library.output(f"{P}_sm9kep_ephemeral_public_key", self.handle)

    def agree(self, peer_ephemeral: bytes | bytearray | memoryview, out: bytearray) -> SM9KeyConfirmation:
        """Writes SK of the other side's R into ``out`` (of the length of the key to derive) and returns
        the confirmations; raises ``InvalidKey`` unless R is a point of G_1 other than the identity."""
        size = self.sizes()[3]
        responder, initiator = (ctypes.c_uint8 * size)(), (ctypes.c_uint8 * size)()
        data, length = Bytes.readable(peer_ephemeral)
        self.library.call(
            f"{P}_sm9kep_agree", self.handle, data, length, Bytes.mutable(out), len(out), responder, size, initiator, size
        )
        return SM9KeyConfirmation(bytes(responder), bytes(initiator))

    def confirm(self, confirmation: SM9KeyConfirmation, received: bytes | bytearray | memoryview) -> bool:
        """Whether ``received`` is the confirmation the other user must send: S_B for the initiator,
        S_A for the responder; compared in constant time."""
        expected = confirmation.responder() if self.side_role == SM9Role.INITIATOR else confirmation.initiator()
        return ConstantTimeEq.ct_eq(expected, received).into_bool()

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.side_role.name}, ..)"


class SM9KEM(SM9Scheme):
    """The key encapsulation mechanism of GM/T 0044.4-2016 clause 6 on the curve and with the hash
    function of ``SM9KEM[C, H]``: C = [r]Q of the recipient's Q and K = KDF(C || w || ID, klen)."""

    def __class_getitem__(cls, parameters: Any) -> Any:
        curve, hash = SM9Scheme.parameters(parameters, "SM9KEM")
        return Specialization.of(cls, (curve, hash), {"CURVE": curve, "HASH": hash})

    @classmethod
    def encapsulate(
        cls,
        master: bytes | bytearray | memoryview,
        identity: bytes | bytearray | memoryview,
        hid: int,
        out: bytearray,
        random: Random,
    ) -> bytes:
        """Writes K for ``identity`` and ``hid`` under Ppub-e ``master`` (x || y) into ``out`` (klen / 8
        bytes, not empty) and returns C (x || y), with r drawn from ``random``."""
        encapsulated = (ctypes.c_uint8 * cls.sizes()[1])()
        arguments: list[Any] = [*cls.names(), *Bytes.readable(master), *Bytes.readable(identity), hid]
        handle, name, length = random.source()
        Library.default().call(
            f"{P}_sm9kem_encapsulate", *arguments, handle, name, length, Bytes.mutable(out), len(out), encapsulated, len(encapsulated)
        )
        return bytes(encapsulated)

    @classmethod
    def encapsulate_with_ephemeral(
        cls,
        master: bytes | bytearray | memoryview,
        identity: bytes | bytearray | memoryview,
        hid: int,
        ephemeral: bytes | bytearray,
        out: bytearray,
    ) -> bytes:
        """:meth:`encapsulate` with r ``ephemeral`` (see :class:`SM9Ephemeral`); raises
        ``InvalidParameter`` if K is zero, when another r is needed."""
        encapsulated = (ctypes.c_uint8 * cls.sizes()[1])()
        arguments: list[Any] = [*cls.names(), *Bytes.readable(master), *Bytes.readable(identity), hid]
        source = SM9Ephemeral.secret(ephemeral)
        with source:
            with source.locked():
                data, length = source.location()
                Library.default().call(
                    f"{P}_sm9kem_encapsulate_with_ephemeral",
                    *arguments,
                    data,
                    length,
                    Bytes.mutable(out),
                    len(out),
                    encapsulated,
                    len(encapsulated),
                )
        return bytes(encapsulated)

    @classmethod
    def decapsulate(cls, key: SM9EncryptUserKey, encapsulated: bytes | bytearray | memoryview, out: bytearray) -> None:
        """Writes K of C ``encapsulated`` (x || y) for ``key`` into ``out`` (klen / 8 bytes, not empty);
        raises ``InvalidKey`` unless C is a point of G_1 other than the identity, and
        ``DecryptionFailed`` if K is zero."""
        cls.check_key(key)
        data, length = Bytes.readable(encapsulated)
        Library.default().call(f"{P}_sm9kem_decapsulate", key.handle, *cls.hash_name(), data, length, Bytes.mutable(out), len(out))


class SM9Cipher(Marker, abstract=True):
    """The encryption of the message by K1 in :class:`SM9PKE` (GM/T 0044.4-2016 step A6)."""


class SM9StreamCipher(SM9Cipher):
    """The stream cipher of the KDF (step A6 a): K1 of the length of the message and C2 = M xor K1."""


class SM9BlockCipher(SM9Cipher, abstract=True):
    """The block cipher of ``SM9BlockCipher[B]`` with the KDF (step A6 b), in CBC mode with a zero
    initial vector, as GM/T 0044.5-2016 annex D uses SM4: K1 is a key of B of its largest size, k bytes,
    and the message is padded with k - (mlen mod k) bytes of that value. The C ABI names it by the C
    type name of B."""

    CIPHER: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    def __class_getitem__(cls, cipher: Any) -> Any:
        cipher = BlockCipherClass.require(cipher, "SM9BlockCipher")
        specialized = Specialization.of(cls, (cipher,), {"CIPHER": cipher})
        specialized.C_TYPE = cipher.C_TYPE
        return specialized


class SM9PKE(SM9Scheme):
    """The public key encryption algorithm of GM/T 0044.4-2016 clause 7 on the curve, with the hash
    function and the cipher of ``SM9PKE[C, H]`` (with :class:`SM9StreamCipher`) or ``SM9PKE[C, H,
    E]``: the ciphertext C1 || C3 || C2 with C1 = [r]Q (x || y) and C3 = MAC(K2, C2)."""

    CIPHER: ClassVar[Any] = None

    def __class_getitem__(cls, parameters: Any) -> Any:
        if isinstance(parameters, tuple) and len(parameters) == 3:
            curve, hash = SM9Scheme.parameters(parameters[:2], "SM9PKE")
            cipher = SM9Cipher.require(parameters[2], "SM9PKE")
        else:
            curve, hash = SM9Scheme.parameters(parameters, "SM9PKE")
            cipher = SM9StreamCipher
        return Specialization.of(cls, (curve, hash, cipher), {"CURVE": curve, "HASH": hash, "CIPHER": cipher})

    @classmethod
    def overhead(cls) -> int:
        """The bytes a ciphertext adds to C2: C1 and C3."""
        sizes = cls.sizes()
        return sizes[1] + sizes[3]

    @classmethod
    def encrypt(
        cls,
        master: bytes | bytearray | memoryview,
        identity: bytes | bytearray | memoryview,
        hid: int,
        message: bytes | bytearray | memoryview,
        random: Random,
    ) -> bytes:
        """The ciphertext of ``message`` for ``identity`` and ``hid`` under Ppub-e ``master`` (x || y),
        with r drawn from ``random``."""
        arguments: list[Any] = [*cls.names(), *Text.encode(cls.CIPHER.C_TYPE), *Bytes.readable(master)]
        arguments.extend([*Bytes.readable(identity), hid, *Bytes.readable(message)])
        handle, name, length = random.source()
        return Library.default().output(f"{P}_sm9pke_encrypt", *arguments, handle, name, length)

    @classmethod
    def encrypt_with_ephemeral(
        cls,
        master: bytes | bytearray | memoryview,
        identity: bytes | bytearray | memoryview,
        hid: int,
        message: bytes | bytearray | memoryview,
        ephemeral: bytes | bytearray,
    ) -> bytes:
        """:meth:`encrypt` with r ``ephemeral`` (see :class:`SM9Ephemeral`); raises
        ``InvalidParameter`` if K1 is zero, when another r is needed."""
        arguments: list[Any] = [*cls.names(), *Text.encode(cls.CIPHER.C_TYPE), *Bytes.readable(master)]
        arguments.extend([*Bytes.readable(identity), hid, *Bytes.readable(message)])
        source = SM9Ephemeral.secret(ephemeral)
        with source:
            with source.locked():
                data, length = source.location()
                return Library.default().output(f"{P}_sm9pke_encrypt_with_ephemeral", *arguments, data, length)

    @classmethod
    def decrypt(cls, key: SM9EncryptUserKey, ciphertext: bytes | bytearray | memoryview) -> bytearray:
        """The message of ``ciphertext`` for ``key``, a secret to zeroize; raises ``DecryptionFailed``
        for every invalid ciphertext."""
        cls.check_key(key)
        data, length = Bytes.readable(ciphertext)
        return Library.default().output_secret(
            f"{P}_sm9pke_decrypt", key.handle, *cls.hash_name(), *Text.encode(cls.CIPHER.C_TYPE), data, length
        )


__all__ = [
    "SM9BlockCipher",
    "SM9Cipher",
    "SM9EncryptMasterKey",
    "SM9EncryptUserKey",
    "SM9Ephemeral",
    "SM9KEM",
    "SM9KEP",
    "SM9KeyConfirmation",
    "SM9PKE",
    "SM9Role",
    "SM9Scheme",
    "SM9StreamCipher",
]
