"""Hybrid Public Key Encryption (HPKE, RFC 9180). Mirrors ``umilib::crypto::hpke``.

``HPKE[K, F, A]`` combines a KEM ``K`` (``DHKEM[X25519, SHA256]``, a key
agreement of :mod:`umilib.crypto.ecdh` with the hash function of its KEM), a
KDF ``F`` (HKDF with ``SHA256``, ``SHA384`` or ``SHA512``) and an AEAD ``A``
(``GCM[AES128]``, ``GCM[AES256]``, ``ChaCha20Poly1305`` or
:class:`HPKEExportOnly`), which the C ABI receives as the identifiers of
section 7. Keys are :class:`~umilib.crypto.PrivateKey` and
:class:`~umilib.crypto.PublicKey` of the KEM. A pre-shared key is the pair
(psk, psk_id) or ``None``; the sender's key selects the auth modes.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import CryptoError, EncodedKey, PrivateKey, PublicKey, Specialization
from umilib.crypto.random import Random
from umilib.ffi import Bytes, Handle, Library, Marker


class HPKEExportOnly(Marker):
    """The export-only AEAD of section 7.3 (aead_id 0xFFFF): contexts export secrets and refuse to
    seal or open."""


class HPKEIdentifiers:
    """The identifiers of section 7 of the classes that name the parts of a suite."""

    @staticmethod
    def kem(group: Any, hash: Any) -> int:
        """kem_id of the DHKEM of the key agreement ``group`` with ``hash``, the pairs of section 7.1."""
        from umilib.crypto.curve.p256 import P256
        from umilib.crypto.curve.p384 import P384
        from umilib.crypto.curve.p521 import P521
        from umilib.crypto.ecdh import ECDH, X448, X25519
        from umilib.hash.sha.v2 import SHA256, SHA384, SHA512

        pairs = {
            (ECDH[P256], SHA256): 0x0010,
            (ECDH[P384], SHA384): 0x0011,
            (ECDH[P521], SHA512): 0x0012,
            (X25519, SHA256): 0x0020,
            (X448, SHA512): 0x0021,
        }
        if (group, hash) not in pairs:
            raise TypeError("DHKEM takes a key agreement and the hash function of its KEM, as DHKEM[X25519, SHA256]")
        return pairs[(group, hash)]

    @staticmethod
    def kdf(hash: Any) -> int:
        """kdf_id of HKDF with ``hash`` (section 7.2)."""
        from umilib.hash.sha.v2 import SHA256, SHA384, SHA512

        identifiers = {SHA256: 0x0001, SHA384: 0x0002, SHA512: 0x0003}
        if hash not in identifiers:
            raise TypeError("HPKE takes the KDF SHA256, SHA384 or SHA512")
        return identifiers[hash]

    @staticmethod
    def aead(aead: Any) -> int:
        """aead_id of ``aead`` (section 7.3)."""
        from umilib.crypto.aes import AES128, AES256
        from umilib.crypto.chacha20poly1305 import ChaCha20Poly1305
        from umilib.crypto.mode.gcm import GCM

        identifiers = {GCM[AES128]: 0x0001, GCM[AES256]: 0x0002, ChaCha20Poly1305: 0x0003, HPKEExportOnly: 0xFFFF}
        if aead not in identifiers:
            raise TypeError("HPKE takes the AEAD GCM[AES128], GCM[AES256], ChaCha20Poly1305 or HPKEExportOnly")
        return identifiers[aead]


class DHKEM:
    """The DHKEM of section 4.1 over the key agreement and with the hash function of ``DHKEM[G, H]``."""

    ID: ClassVar[int] = 0
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None
    ENCAPSULATED_SIZE: ClassVar[int]
    PUBLIC_KEY_SIZE: ClassVar[int]
    PRIVATE_KEY_SIZE: ClassVar[int]

    def __class_getitem__(cls, parameters: Any) -> Any:
        group, hash = Specialization.pair(parameters, "DHKEM")
        identifier = HPKEIdentifiers.kem(group, hash)
        sizes = (ctypes.c_size_t * 3)()
        Library.default().call("umilib_crypto_hpke_hpke_sizes", identifier, sizes)
        attributes = {
            "ID": identifier,
            "ENCAPSULATED_SIZE": sizes[0],
            "PUBLIC_KEY_SIZE": sizes[1],
            "PRIVATE_KEY_SIZE": sizes[2],
            "__doc__": f"DHKEM({group.__name__}, HKDF-{hash.__name__}).",
        }
        return Specialization.of(cls, (group, hash), attributes)

    @classmethod
    def key_pair(cls, function: str, *arguments: Any, handles: tuple[Handle, ...] = ()) -> tuple[PrivateKey, PublicKey]:
        Specialization.require(cls.PARAMETERS, "DHKEM")
        private = PrivateKey.allocate(cls, cls.PRIVATE_KEY_SIZE)
        public = (ctypes.c_uint8 * cls.PUBLIC_KEY_SIZE)()
        with private.writable(handles) as (data, length):
            Library.default().call(f"umilib_crypto_hpke_hpke_{function}", cls.ID, *arguments, data, length, public, len(public))
        return private, PublicKey(cls, bytes(public))

    @classmethod
    def derive_key_pair(cls, ikm: bytes | bytearray | memoryview) -> tuple[PrivateKey, PublicKey]:
        """DeriveKeyPair(ikm) of section 7.1.3."""
        data, length = Bytes.readable(ikm)
        return cls.key_pair("derive_key_pair", data, length)

    @classmethod
    def generate_key_pair(cls, random: Random) -> tuple[PrivateKey, PublicKey]:
        """GenerateKeyPair(): a pair of keys drawn from ``random``."""
        handle, name, length = random.source()
        return cls.key_pair("generate_key_pair", handle, name, length, handles=(random,))

    @classmethod
    def public_key(cls, key: PrivateKey) -> PublicKey:
        key.check(cls)
        out = (ctypes.c_uint8 * cls.PUBLIC_KEY_SIZE)()
        with EncodedKey.encodings(key) as [(data, length)]:
            Library.default().call("umilib_crypto_hpke_hpke_public_key", cls.ID, data, length, out, len(out))
        return PublicKey(cls, bytes(out))

    @classmethod
    def deserialize_public_key(cls, data: bytes | bytearray | memoryview) -> PublicKey:
        """DeserializePublicKey (section 7.1.1) with the validation of section 7.1.4; raises ``InvalidKey``."""
        Specialization.require(cls.PARAMETERS, "DHKEM")
        encoded, length = Bytes.readable(data)
        Library.default().call("umilib_crypto_hpke_hpke_check_public_key", cls.ID, encoded, length)
        return PublicKey(cls, data)

    @classmethod
    def serialize_public_key(cls, key: PublicKey) -> bytes:
        key.check(cls)
        return key.to_bytes()

    @classmethod
    def deserialize_private_key(cls, data: bytes | bytearray | memoryview) -> PrivateKey:
        """DeserializePrivateKey (section 7.1.2); raises ``InvalidKey`` for an invalid key."""
        Specialization.require(cls.PARAMETERS, "DHKEM")
        key = PrivateKey(cls, data)
        key.validate(lambda encoded, length: Library.default().call("umilib_crypto_hpke_hpke_check_private_key", cls.ID, encoded, length))
        return key

    @classmethod
    def serialize_private_key(cls, key: PrivateKey, out: bytearray) -> None:
        key.check(cls)
        key.write(out)


class HPKESenderContext(Handle):
    """The context of a sender (section 5.2): it seals and exports, with its own sequence numbers."""

    FREE = "umilib_crypto_hpke_hpke_sender_context_free"

    def seal(self, associated: bytes | bytearray | memoryview, plaintext: bytes | bytearray | memoryview) -> bytes:
        """ContextS.Seal(aad, pt): the ciphertext with its tag; raises ``InvalidParameter`` for the
        export-only AEAD and ``LimitExceeded`` after the last sequence number."""
        associated_data, associated_length = Bytes.readable(associated)
        data, length = Bytes.readable(plaintext)
        return self.library.output("umilib_crypto_hpke_hpke_sender_context_seal", self.handle, associated_data, associated_length, data, length)

    def export(self, context: bytes | bytearray | memoryview, out: bytearray) -> None:
        """Context.Export(exporter_context, L) of section 5.3 into ``out`` of L bytes."""
        data, length = Bytes.readable(context)
        self.library.call("umilib_crypto_hpke_hpke_sender_context_export", self.handle, data, length, Bytes.mutable(out), len(out))

    def sequence(self) -> int:
        """The sequence number of the next message."""
        return self.library.value("umilib_crypto_hpke_hpke_sender_context_sequence", ctypes.c_uint64, self.handle)

    def __repr__(self) -> str:
        return "HPKESenderContext(..)"


class HPKEReceiverContext(Handle):
    """The context of a receiver (section 5.2): it opens and exports, with its own sequence numbers."""

    FREE = "umilib_crypto_hpke_hpke_receiver_context_free"

    def open(self, associated: bytes | bytearray | memoryview, ciphertext: bytes | bytearray | memoryview) -> bytearray:
        """ContextR.Open(aad, ct): the plaintext, a secret to zeroize; raises ``AuthenticationFailed``
        unless the ciphertext authenticates at the next sequence number, which then does not advance."""
        associated_data, associated_length = Bytes.readable(associated)
        data, length = Bytes.readable(ciphertext)
        return self.library.output_secret(
            "umilib_crypto_hpke_hpke_receiver_context_open", self.handle, associated_data, associated_length, data, length
        )

    def export(self, context: bytes | bytearray | memoryview, out: bytearray) -> None:
        """Context.Export(exporter_context, L) of section 5.3 into ``out`` of L bytes."""
        data, length = Bytes.readable(context)
        self.library.call("umilib_crypto_hpke_hpke_receiver_context_export", self.handle, data, length, Bytes.mutable(out), len(out))

    def sequence(self) -> int:
        """The sequence number of the next message."""
        return self.library.value("umilib_crypto_hpke_hpke_receiver_context_sequence", ctypes.c_uint64, self.handle)

    def __repr__(self) -> str:
        return "HPKEReceiverContext(..)"


class HPKE:
    """HPKE with the KEM, the KDF and the AEAD of ``HPKE[K, F, A]``."""

    KEM: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None
    IDENTIFIERS: ClassVar[tuple[int, int, int]] = (0, 0, 0)

    def __class_getitem__(cls, parameters: Any) -> Any:
        if not (isinstance(parameters, tuple) and len(parameters) == 3):
            raise TypeError("HPKE takes three parameters, as HPKE[DHKEM[X25519, SHA256], SHA256, ChaCha20Poly1305]")
        kem, kdf, aead = parameters
        if not (isinstance(kem, type) and issubclass(kem, DHKEM) and kem.PARAMETERS is not None):
            raise TypeError("HPKE takes a KEM, as DHKEM[X25519, SHA256]")
        identifiers = (kem.ID, HPKEIdentifiers.kdf(kdf), HPKEIdentifiers.aead(aead))
        return Specialization.of(cls, (kem, kdf, aead), {"KEM": kem, "IDENTIFIERS": identifiers})

    @classmethod
    def inputs(cls, info: Any, psk: tuple[Any, Any] | None) -> list[Any]:
        """The arguments of the C ABI for ``info`` and ``psk``. VerifyPSKInputs (section 5.1): a
        pre-shared key and its identifier are both non-empty, else ``InvalidParameter``; the C ABI
        reads two empty ones as no pre-shared key, so the empty pair is refused here."""
        if psk is not None and (len(psk[0]) == 0 or len(psk[1]) == 0):
            raise CryptoError("crypto", "InvalidParameter", "a pre-shared key and its identifier are both non-empty")
        arguments = list(Bytes.readable(info))
        psk_value, psk_id = psk if psk is not None else (b"", b"")
        arguments.extend(Bytes.readable(psk_value))
        arguments.extend(Bytes.readable(psk_id))
        return arguments

    @classmethod
    def setup_sender(
        cls,
        recipient: PublicKey,
        info: bytes | bytearray | memoryview,
        psk: tuple[bytes, bytes] | None,
        sender: PrivateKey | None,
        random: Random,
    ) -> tuple[bytes, HPKESenderContext]:
        """SetupBaseS, SetupPSKS, SetupAuthS or SetupAuthPSKS (section 5.1) for ``recipient``, with an
        ephemeral key drawn from ``random``: enc and the context. A pre-shared key and its identifier
        are both non-empty (``InvalidParameter`` otherwise)."""
        handle, name, length = random.source()
        return cls.setup("setup_sender", recipient, info, psk, sender, (handle, name, length), (random,))

    @classmethod
    def setup_sender_with_ephemeral(
        cls,
        recipient: PublicKey,
        info: bytes | bytearray | memoryview,
        psk: tuple[bytes, bytes] | None,
        sender: PrivateKey | None,
        ephemeral: PrivateKey,
    ) -> tuple[bytes, HPKESenderContext]:
        """:meth:`setup_sender` with the ephemeral key given (as DeriveKeyPair(ikmE) gives it in the
        test vectors of appendix A); the key must be fresh and secret."""
        ephemeral.check(Specialization.require(cls.KEM, "HPKE"))
        return cls.setup("setup_sender_with_ephemeral", recipient, info, psk, sender, None, (), ephemeral)

    @classmethod
    def setup(
        cls,
        function: str,
        recipient: PublicKey,
        info: Any,
        psk: tuple[Any, Any] | None,
        sender: PrivateKey | None,
        random: tuple[Any, Any, int] | None,
        handles: tuple[Handle, ...],
        ephemeral: PrivateKey | None = None,
    ) -> tuple[bytes, HPKESenderContext]:
        kem = Specialization.require(cls.KEM, "HPKE")
        recipient.check(kem)
        keys: list[EncodedKey] = [recipient]
        if sender is not None:
            sender.check(kem)
            keys.append(sender)
        if ephemeral is not None:
            keys.append(ephemeral)
        encapsulated = (ctypes.c_uint8 * kem.ENCAPSULATED_SIZE)()
        out = ctypes.c_void_p()
        with EncodedKey.encodings(*keys, handles=handles) as encodings:
            recipient_data, recipient_length = encodings[0]
            sender_data, sender_length = encodings[1] if sender is not None else (None, 0)
            tail = list(random) if random is not None else list(encodings[-1])
            Library.default().call(
                f"umilib_crypto_hpke_hpke_{function}",
                *cls.IDENTIFIERS,
                recipient_data,
                recipient_length,
                *cls.inputs(info, psk),
                sender_data,
                sender_length,
                *tail,
                encapsulated,
                len(encapsulated),
                ctypes.byref(out),
            )
        return bytes(encapsulated), HPKESenderContext(out.value)

    @classmethod
    def setup_receiver(
        cls,
        encapsulated: bytes | bytearray | memoryview,
        recipient: PrivateKey,
        info: bytes | bytearray | memoryview,
        psk: tuple[bytes, bytes] | None,
        sender: PublicKey | None,
    ) -> HPKEReceiverContext:
        """SetupBaseR, SetupPSKR, SetupAuthR or SetupAuthPSKR (section 5.1) for the enc
        ``encapsulated`` received by ``recipient``."""
        kem = Specialization.require(cls.KEM, "HPKE")
        recipient.check(kem)
        keys: list[EncodedKey] = [recipient]
        if sender is not None:
            sender.check(kem)
            keys.append(sender)
        encapsulated_data, encapsulated_length = Bytes.readable(encapsulated)
        out = ctypes.c_void_p()
        with EncodedKey.encodings(*keys) as encodings:
            recipient_data, recipient_length = encodings[0]
            sender_data, sender_length = encodings[1] if sender is not None else (None, 0)
            Library.default().call(
                "umilib_crypto_hpke_hpke_setup_receiver",
                *cls.IDENTIFIERS,
                encapsulated_data,
                encapsulated_length,
                recipient_data,
                recipient_length,
                *cls.inputs(info, psk),
                sender_data,
                sender_length,
                ctypes.byref(out),
            )
        return HPKEReceiverContext(out.value)

    @classmethod
    def seal(
        cls,
        recipient: PublicKey,
        info: bytes | bytearray | memoryview,
        associated: bytes | bytearray | memoryview,
        plaintext: bytes | bytearray | memoryview,
        psk: tuple[bytes, bytes] | None,
        sender: PrivateKey | None,
        random: Random,
    ) -> tuple[bytes, bytes]:
        """The single-shot encryption of section 6.1: enc and the ciphertext."""
        encapsulated, context = cls.setup_sender(recipient, info, psk, sender, random)
        with context:
            return encapsulated, context.seal(associated, plaintext)

    @classmethod
    def open(
        cls,
        encapsulated: bytes | bytearray | memoryview,
        recipient: PrivateKey,
        info: bytes | bytearray | memoryview,
        associated: bytes | bytearray | memoryview,
        ciphertext: bytes | bytearray | memoryview,
        psk: tuple[bytes, bytes] | None,
        sender: PublicKey | None,
    ) -> bytearray:
        """The single-shot decryption of section 6.1."""
        with cls.setup_receiver(encapsulated, recipient, info, psk, sender) as context:
            return context.open(associated, ciphertext)


__all__ = ["DHKEM", "HPKE", "HPKEExportOnly", "HPKEIdentifiers", "HPKEReceiverContext", "HPKESenderContext"]
