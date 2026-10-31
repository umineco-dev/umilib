"""RSA (RFC 8017): PKCS #1 v1.5 and PSS signatures and OAEP encryption. Mirrors ``umilib::crypto::rsa``.

:class:`RSAPublicKey` and :class:`RSAPrivateKey` hold the keys in umilib;
integers are big-endian bytes. The schemes are generic over the hash
function, as in Rust: ``RSAPKCS1v15[SHA256]``, ``RSAPSS[SHA256]`` (MGF1
with the same hash function) or ``RSAPSS[SHA256, SHA1]`` (MGF1 with SHA-1),
and ``RSAOAEP[SHA256]`` or ``RSAOAEP[SHA256, SHA1]``.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import Names, Specialization
from umilib.crypto.random import Random
from umilib.ffi import Bytes, Handle, Library, Text
from umilib.hash import CryptographicDigest


class RSAPublicKey(Handle):
    """An RSA public key (n, e) of RFC 8017 section 3.1."""

    FREE = "umilib_crypto_rsa_rsa_public_key_free"

    def __init__(self, n: bytes | bytearray | memoryview, e: bytes | bytearray | memoryview) -> None:
        """The key of the modulus ``n`` and the exponent ``e``; raises ``InvalidKey`` for an even
        modulus, an exponent out of 3..n - 1 or an even one."""
        n_data, n_length = Bytes.readable(n)
        e_data, e_length = Bytes.readable(e)
        super().__init__(Handle.create("umilib_crypto_rsa_rsa_public_key_new", n_data, n_length, e_data, e_length))

    @classmethod
    def from_pointer(cls, pointer: int) -> RSAPublicKey:
        key = cls.__new__(cls)
        Handle.__init__(key, pointer)
        return key

    @classmethod
    def new(cls, n: bytes | bytearray | memoryview, e: bytes | bytearray | memoryview) -> RSAPublicKey:
        return cls(n, e)

    def n(self) -> bytes:
        return self.library.output("umilib_crypto_rsa_rsa_public_key_n", self.handle)

    def e(self) -> bytes:
        return self.library.output("umilib_crypto_rsa_rsa_public_key_e", self.handle)

    def size(self) -> int:
        """k, the bytes of the modulus."""
        return self.library.value("umilib_crypto_rsa_rsa_public_key_size", ctypes.c_size_t, self.handle)

    @classmethod
    def from_pkcs1_der(cls, der: bytes | bytearray | memoryview) -> RSAPublicKey:
        """The key of the PKCS #1 ``RSAPublicKey`` in DER."""
        data, length = Bytes.readable(der)
        return cls.from_pointer(Handle.create("umilib_crypto_rsa_rsa_public_key_from_pkcs1_der", data, length))

    def to_pkcs1_der(self) -> bytes:
        return self.library.output("umilib_crypto_rsa_rsa_public_key_to_pkcs1_der", self.handle)

    def __repr__(self) -> str:
        return f"RSAPublicKey({8 * self.size()} bits)"


class RSAPrivateKey(Handle):
    """An RSA private key of RFC 8017 section 3.2, with its primes when they are known; zeroized when
    released."""

    FREE = "umilib_crypto_rsa_rsa_private_key_free"

    def __init__(self, public: RSAPublicKey, d: bytes | bytearray | memoryview) -> None:
        """The key of ``public`` and the private exponent ``d``, without its primes; raises
        ``InvalidKey`` unless d is below n."""
        arguments: list[Any] = []
        for value in (public.n(), public.e(), d):
            arguments.extend(Bytes.readable(value))
        super().__init__(Handle.create("umilib_crypto_rsa_rsa_private_key_new", *arguments))

    @classmethod
    def from_pointer(cls, pointer: int) -> RSAPrivateKey:
        key = cls.__new__(cls)
        Handle.__init__(key, pointer)
        return key

    @classmethod
    def new(cls, public: RSAPublicKey, d: bytes | bytearray | memoryview) -> RSAPrivateKey:
        return cls(public, d)

    @classmethod
    def from_primes(
        cls, p: bytes | bytearray | memoryview, q: bytes | bytearray | memoryview, e: bytes | bytearray | memoryview
    ) -> RSAPrivateKey:
        """The key of the primes ``p`` and ``q`` and the public exponent ``e``, with the CRT values."""
        arguments: list[Any] = []
        for value in (p, q, e):
            arguments.extend(Bytes.readable(value))
        return cls.from_pointer(Handle.create("umilib_crypto_rsa_rsa_private_key_from_primes", *arguments))

    @classmethod
    def generate(cls, bits: int, e: bytes | bytearray | memoryview, random: Random) -> RSAPrivateKey:
        """A key of a modulus of ``bits`` bits (at least 2048, even) with two primes drawn from ``random``."""
        e_data, e_length = Bytes.readable(e)
        handle, name, length = random.source()
        return cls.from_pointer(Handle.create("umilib_crypto_rsa_rsa_private_key_generate", bits, e_data, e_length, handle, name, length))

    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey.from_pointer(Handle.create("umilib_crypto_rsa_rsa_private_key_public_key", self.handle))

    def d(self) -> bytearray:
        """The private exponent d, big-endian, a secret to zeroize."""
        return self.library.output_secret("umilib_crypto_rsa_rsa_private_key_d", self.handle)

    @classmethod
    def from_pkcs1_der(cls, der: bytes | bytearray | memoryview) -> RSAPrivateKey:
        """The key of the PKCS #1 ``RSAPrivateKey`` (version 0) in DER."""
        data, length = Bytes.readable(der)
        return cls.from_pointer(Handle.create("umilib_crypto_rsa_rsa_private_key_from_pkcs1_der", data, length))

    def to_pkcs1_der(self) -> bytearray:
        """The PKCS #1 ``RSAPrivateKey`` in DER, a secret to zeroize; raises ``InvalidKey`` for a key
        without its primes."""
        return self.library.output_secret("umilib_crypto_rsa_rsa_private_key_to_pkcs1_der", self.handle)

    def __repr__(self) -> str:
        return "RSAPrivateKey(..)"


class RSAScheme:
    """A scheme of RSA generic over the hash function ``HASH`` and that of MGF1 ``MGF``."""

    HASH: ClassVar[Any] = None
    MGF: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    @classmethod
    def specialize_hashes(cls, parameters: Any, with_mgf: bool) -> Any:
        if with_mgf and isinstance(parameters, tuple):
            hash, mgf = Specialization.pair(parameters, cls.__name__)
        else:
            hash = mgf = parameters
        hash = Names.require(hash, CryptographicDigest, cls.__name__)
        mgf = Names.require(mgf, CryptographicDigest, cls.__name__)
        return Specialization.of(cls, (hash, mgf), {"HASH": hash, "MGF": mgf})

    @classmethod
    def names(cls, with_mgf: bool) -> list[Any]:
        Specialization.require(cls.PARAMETERS, cls.__name__)
        names = list(Text.encode(cls.HASH.C_TYPE))
        if with_mgf:
            names.extend(Text.encode(cls.MGF.C_TYPE))
        return names


class RSAPKCS1v15(RSAScheme):
    """The signatures RSASSA-PKCS1-v1_5 (section 8.2) with the hash function of ``RSAPKCS1v15[H]``."""

    def __class_getitem__(cls, hash: Any) -> Any:
        return cls.specialize_hashes(hash, False)

    @classmethod
    def sign(cls, key: RSAPrivateKey, message: bytes | bytearray | memoryview, random: Random) -> bytes:
        """The signature of ``message``; ``random`` blinds the private operation."""
        size = key.public_key().size()
        out = (ctypes.c_uint8 * size)()
        data, length = Bytes.readable(message)
        handle, name, name_length = random.source()
        Library.default().call("umilib_crypto_rsa_rsa_pkcs1v15_sign", key.handle, *cls.names(False), data, length, handle, name, name_length, out, size)
        return bytes(out)

    @classmethod
    def verify(cls, key: RSAPublicKey, message: bytes | bytearray | memoryview, signature: bytes | bytearray | memoryview) -> None:
        """Returns if ``signature`` is a signature of ``message``; raises ``InvalidSignature`` otherwise."""
        data, length = Bytes.readable(message)
        signature_data, signature_length = Bytes.readable(signature)
        Library.default().call("umilib_crypto_rsa_rsa_pkcs1v15_verify", key.handle, *cls.names(False), data, length, signature_data, signature_length)


class RSAPSS(RSAScheme):
    """The signatures RSASSA-PSS (section 8.1) with the hash functions of ``RSAPSS[H]`` or ``RSAPSS[H, G]``."""

    def __class_getitem__(cls, parameters: Any) -> Any:
        return cls.specialize_hashes(parameters, True)

    @classmethod
    def sign(cls, key: RSAPrivateKey, message: bytes | bytearray | memoryview, salt_length: int, random: Random) -> bytes:
        """The signature of ``message`` with a salt of ``salt_length`` random bytes."""
        size = key.public_key().size()
        out = (ctypes.c_uint8 * size)()
        data, length = Bytes.readable(message)
        handle, name, name_length = random.source()
        Library.default().call(
            "umilib_crypto_rsa_rsa_pss_sign", key.handle, *cls.names(True), salt_length, data, length, handle, name, name_length, out, size
        )
        return bytes(out)

    @classmethod
    def verify(
        cls,
        key: RSAPublicKey,
        message: bytes | bytearray | memoryview,
        signature: bytes | bytearray | memoryview,
        salt_length: int,
    ) -> None:
        """Returns if ``signature`` is a signature of ``message`` with a salt of ``salt_length`` bytes;
        raises ``InvalidSignature`` otherwise."""
        data, length = Bytes.readable(message)
        signature_data, signature_length = Bytes.readable(signature)
        Library.default().call(
            "umilib_crypto_rsa_rsa_pss_verify", key.handle, *cls.names(True), salt_length, data, length, signature_data, signature_length
        )


class RSAOAEP(RSAScheme):
    """The encryption RSAES-OAEP (section 7.1) with the hash functions of ``RSAOAEP[H]`` or ``RSAOAEP[H, G]``."""

    def __class_getitem__(cls, parameters: Any) -> Any:
        return cls.specialize_hashes(parameters, True)

    @classmethod
    def maximum_message(cls, key: RSAPublicKey) -> int | None:
        """The longest message for ``key``: k - 2 hLen - 2, or ``None`` if the key is too small."""
        maximum = key.size() - 2 * Specialization.require(cls.HASH, "RSAOAEP").OUTPUT_SIZE - 2
        return maximum if maximum >= 0 else None

    @classmethod
    def encrypt(
        cls, key: RSAPublicKey, message: bytes | bytearray | memoryview, label: bytes | bytearray | memoryview, random: Random
    ) -> bytes:
        """The ciphertext of ``message`` with ``label``; raises ``InputLength`` for a message longer than
        :meth:`maximum_message`."""
        size = key.size()
        out = (ctypes.c_uint8 * size)()
        label_data, label_length = Bytes.readable(label)
        data, length = Bytes.readable(message)
        handle, name, name_length = random.source()
        Library.default().call(
            "umilib_crypto_rsa_rsa_oaep_encrypt", key.handle, *cls.names(True), label_data, label_length, data, length, handle, name, name_length, out, size
        )
        return bytes(out)

    @classmethod
    def decrypt(
        cls, key: RSAPrivateKey, ciphertext: bytes | bytearray | memoryview, label: bytes | bytearray | memoryview, random: Random
    ) -> bytearray:
        """The message of ``ciphertext`` with ``label``, a secret to zeroize; raises ``DecryptionFailed``
        for any invalid ciphertext, without telling why (section 7.1.2)."""
        label_data, label_length = Bytes.readable(label)
        data, length = Bytes.readable(ciphertext)
        handle, name, name_length = random.source()
        return Library.default().output_secret(
            "umilib_crypto_rsa_rsa_oaep_decrypt", key.handle, *cls.names(True), label_data, label_length, data, length, handle, name, name_length
        )


__all__ = ["RSAOAEP", "RSAPKCS1v15", "RSAPSS", "RSAPrivateKey", "RSAPublicKey", "RSAScheme"]
