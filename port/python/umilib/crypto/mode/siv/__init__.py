"""SIV (RFC 5297): deterministic authenticated encryption, and an AEAD whose tag is the synthetic IV. Mirrors ``umilib::crypto::mode::siv``."""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import AEAD, BlockCipher, BlockCipherClass, CryptoError, Specialization
from umilib.ffi import Bytes, Handle, Text



class SIV(AEAD):
    """SIV over the 128-bit cipher ``SIV[C]``, with K1 (of S2V) and K2 (of CTR).

    As an AEAD, :meth:`encrypt` returns V followed by the ciphertext (section 6),
    and the nonce has at least one byte. The vector form takes up to 126
    components of associated data.
    """

    PREFIX = "umilib_crypto_mode_siv_siv"
    MAXIMUM_COMPONENTS: ClassVar[int] = 126
    SIV_SIZE: ClassVar[int] = 16
    CIPHER: ClassVar[type[BlockCipher] | None] = None

    def __class_getitem__(cls, cipher: type[BlockCipher]) -> Any:
        """The class of SIV over ``cipher``."""
        cipher = BlockCipherClass.require(cipher, "SIV", 16)
        return Specialization.of(cls, (cipher,), {"CIPHER": cipher})

    def __init__(self, mac_key: bytes | bytearray | memoryview, cipher_key: bytes | bytearray | memoryview) -> None:
        cipher = Specialization.require(self.CIPHER, "SIV")
        name, name_length = Text.encode(cipher.C_TYPE)
        mac, mac_length = Bytes.readable(mac_key)
        key, key_length = Bytes.readable(cipher_key)
        super().__init__(Handle.create(f"{self.PREFIX}_new", name, name_length, mac, mac_length, key, key_length))

    def encrypt(
        self,
        nonce: bytes | bytearray | memoryview,
        associated: bytes | bytearray | memoryview,
        plaintext: bytes | bytearray | memoryview,
    ) -> bytes:
        """V followed by the ciphertext of ``plaintext`` (section 6)."""
        buffer = bytearray(plaintext)
        v = self.encrypt_in_place(nonce, associated, buffer)
        return v + bytes(buffer)

    def decrypt(
        self,
        nonce: bytes | bytearray | memoryview,
        associated: bytes | bytearray | memoryview,
        ciphertext: bytes | bytearray | memoryview,
    ) -> bytes:
        """The plaintext of ``ciphertext``, which begins with V."""
        if len(ciphertext) < SIV.SIV_SIZE:
            raise CryptoError("crypto", "InputLength", "the input is shorter than V")
        buffer = bytearray(ciphertext[SIV.SIV_SIZE :])
        self.decrypt_in_place(nonce, associated, buffer, bytes(ciphertext[: SIV.SIV_SIZE]))
        return bytes(buffer)

    def encrypt_vector_in_place(self, associated: list[bytes], buffer: bytearray) -> bytes:
        """Encrypts ``buffer`` in place and returns V, which authenticates it and the components of ``associated``."""
        pointers, lengths, count, kept = Bytes.array(associated)
        v = (ctypes.c_uint8 * SIV.SIV_SIZE)()
        self.library.call(
            f"{self.PREFIX}_encrypt_vector_in_place", self.handle, pointers, lengths, count, Bytes.mutable(buffer), len(buffer), v, len(v)
        )
        del kept
        return bytes(v)

    def decrypt_vector_in_place(self, associated: list[bytes], buffer: bytearray, v: bytes | bytearray | memoryview) -> None:
        """Decrypts ``buffer`` in place if ``v`` authenticates it and the components of ``associated``."""
        pointers, lengths, count, kept = Bytes.array(associated)
        v_data, v_length = Bytes.readable(v)
        self.library.call(
            f"{self.PREFIX}_decrypt_vector_in_place", self.handle, pointers, lengths, count, Bytes.mutable(buffer), len(buffer), v_data, v_length
        )
        del kept


__all__ = ["SIV"]
