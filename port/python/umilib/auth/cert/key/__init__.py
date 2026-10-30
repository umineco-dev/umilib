"""Keys and algorithm identifiers of the X.509 public-key infrastructure. Mirrors ``umilib::auth::cert::key``.

Hash functions, curves, parameter sets and ciphers are :class:`enum.IntEnum`
members whose values are the numbers of the C ABI. A signing, key
generation or encryption call takes a generator of :mod:`umilib.crypto.random`.
Errors are :class:`KeyStatusError`.
"""

from __future__ import annotations

import ctypes
import enum
from dataclasses import dataclass
from typing import Any

from umilib.ffi import Buffer, Bytes, FFIError, Handle, Library, Text


class KeyStatusError(FFIError):
    """An error of a key: ``Encoding``, ``PEM``, ``PEMLabel``, ``UnknownAlgorithm``, ``Unsupported``,
    ``Parameters``, ``InvalidKey``, ``Limit``, ``Inconsistent``, ``Mismatch``, ``InvalidSignature`` or ``Decryption``."""


Library.register_error("auth.cert.key", KeyStatusError)


class HashAlgorithm(enum.IntEnum):
    SHA1 = 0
    SHA224 = 1
    SHA256 = 2
    SHA384 = 3
    SHA512 = 4
    SHA512_224 = 5
    SHA512_256 = 6
    SHA3_224 = 7
    SHA3_256 = 8
    SHA3_384 = 9
    SHA3_512 = 10
    SHAKE128 = 11
    SHAKE256 = 12


@dataclass(frozen=True)
class KeyLimits:
    """The largest keys accepted from an untrusted source: an RSA modulus and exponent, in bits (the defaults of OpenSSL)."""

    maximum_rsa_bits: int = 16384
    maximum_rsa_exponent_bits: int = 64


class NamedCurve(enum.IntEnum):
    P256 = 0
    P384 = 1
    P521 = 2
    Secp256k1 = 3
    BrainpoolP256r1 = 4
    BrainpoolP384r1 = 5
    BrainpoolP512r1 = 6


class MLDSAParameterSet(enum.IntEnum):
    MLDSA44 = 0
    MLDSA65 = 1
    MLDSA87 = 2


class SLHDSAParameterSet(enum.IntEnum):
    SHA2_128s = 0
    SHA2_128f = 1
    SHA2_192s = 2
    SHA2_192f = 3
    SHA2_256s = 4
    SHA2_256f = 5
    SHAKE_128s = 6
    SHAKE_128f = 7
    SHAKE_192s = 8
    SHAKE_192f = 9
    SHAKE_256s = 10
    SHAKE_256f = 11


class MLKEMParameterSet(enum.IntEnum):
    MLKEM512 = 0
    MLKEM768 = 1
    MLKEM1024 = 2


class PBES2Cipher(enum.IntEnum):
    AES128CBC = 0
    AES192CBC = 1
    AES256CBC = 2


@dataclass(frozen=True)
class PBES2Config:
    """The parameters of PBES2: written ones, and the most iterations accepted when decrypting."""

    prf: HashAlgorithm = HashAlgorithm.SHA256
    iterations: int = 600_000
    salt_length: int = 16
    cipher: PBES2Cipher = PBES2Cipher.AES256CBC
    maximum_iterations: int = 10_000_000

    def structure(self) -> Any:
        """The C structure of the parameters."""
        return Library.default().type("umilib_auth_cert_key_PBES2Config")(self.prf, self.cipher, self.iterations, self.salt_length, self.maximum_iterations)


class SignatureAlgorithm(Handle):
    """A signature algorithm and its parameters."""

    FREE = "umilib_auth_cert_key_signature_algorithm_free"

    @staticmethod
    def rsa_pkcs1v15(hash: HashAlgorithm) -> SignatureAlgorithm:
        return SignatureAlgorithm(Handle.create("umilib_auth_cert_key_signature_algorithm_rsa_pkcs1v15", hash))

    @staticmethod
    def rsa_pss(hash: HashAlgorithm, mask_hash: HashAlgorithm | None = None, salt_length: int | None = None) -> SignatureAlgorithm:
        """RSASSA-PSS; MGF1 with ``hash`` and a salt of its digest size by default (RFC 4055 §3.1)."""
        salt = Library.default().value("umilib_auth_cert_key_hash_algorithm_output_size", ctypes.c_size_t, hash) if salt_length is None else salt_length
        mask = hash if mask_hash is None else mask_hash
        return SignatureAlgorithm(Handle.create("umilib_auth_cert_key_signature_algorithm_rsa_pss", hash, mask, salt))

    @staticmethod
    def ecdsa(hash: HashAlgorithm) -> SignatureAlgorithm:
        return SignatureAlgorithm(Handle.create("umilib_auth_cert_key_signature_algorithm_ecdsa", hash))

    @staticmethod
    def ed25519() -> SignatureAlgorithm:
        return SignatureAlgorithm(Handle.create("umilib_auth_cert_key_signature_algorithm_ed25519"))

    @staticmethod
    def ed448() -> SignatureAlgorithm:
        return SignatureAlgorithm(Handle.create("umilib_auth_cert_key_signature_algorithm_ed448"))

    @staticmethod
    def mldsa(set: MLDSAParameterSet) -> SignatureAlgorithm:
        return SignatureAlgorithm(Handle.create("umilib_auth_cert_key_signature_algorithm_mldsa", set))

    @staticmethod
    def slhdsa(set: SLHDSAParameterSet, pre_hash: bool = False) -> SignatureAlgorithm:
        """Pure SLH-DSA, or HashSLH-DSA if ``pre_hash``."""
        return SignatureAlgorithm(Handle.create("umilib_auth_cert_key_signature_algorithm_slhdsa", set, pre_hash))

    @staticmethod
    def from_der(data: bytes | bytearray | memoryview) -> SignatureAlgorithm:
        """The algorithm of a DER ``AlgorithmIdentifier``."""
        return SignatureAlgorithm(Handle.create("umilib_auth_cert_key_signature_algorithm_from_der", *Bytes.readable(data)))

    def to_der(self) -> bytes:
        """The DER ``AlgorithmIdentifier`` of the algorithm."""
        return self.library.output("umilib_auth_cert_key_signature_algorithm_to_der", self.handle)


class KeyAlgorithm(Handle):
    """The algorithm of a key and its parameters."""

    FREE = "umilib_auth_cert_key_key_algorithm_free"

    @staticmethod
    def new(kind: int, parameter: int = 0) -> KeyAlgorithm:
        return KeyAlgorithm(Handle.create("umilib_auth_cert_key_key_algorithm_new", kind, parameter))

    @staticmethod
    def rsa() -> KeyAlgorithm:
        return KeyAlgorithm.new(0)

    @staticmethod
    def rsa_pss(signature: SignatureAlgorithm | None = None) -> KeyAlgorithm:
        """An RSA key for RSASSA-PSS only, restricted to the parameters of ``signature`` if given."""
        if signature is None:
            return KeyAlgorithm.new(1)
        return KeyAlgorithm(Handle.create("umilib_auth_cert_key_key_algorithm_rsa_pss", signature))

    @staticmethod
    def ec(curve: NamedCurve) -> KeyAlgorithm:
        return KeyAlgorithm.new(2, curve)

    @staticmethod
    def x25519() -> KeyAlgorithm:
        return KeyAlgorithm.new(3)

    @staticmethod
    def x448() -> KeyAlgorithm:
        return KeyAlgorithm.new(4)

    @staticmethod
    def ed25519() -> KeyAlgorithm:
        return KeyAlgorithm.new(5)

    @staticmethod
    def ed448() -> KeyAlgorithm:
        return KeyAlgorithm.new(6)

    @staticmethod
    def mldsa(set: MLDSAParameterSet) -> KeyAlgorithm:
        return KeyAlgorithm.new(7, set)

    @staticmethod
    def slhdsa(set: SLHDSAParameterSet, pre_hash: bool = False) -> KeyAlgorithm:
        return KeyAlgorithm.new(9 if pre_hash else 8, set)

    @staticmethod
    def mlkem(set: MLKEMParameterSet) -> KeyAlgorithm:
        return KeyAlgorithm.new(10, set)

    @staticmethod
    def from_der(data: bytes | bytearray | memoryview) -> KeyAlgorithm:
        return KeyAlgorithm(Handle.create("umilib_auth_cert_key_key_algorithm_from_der", *Bytes.readable(data)))

    def to_der(self) -> bytes:
        return self.library.output("umilib_auth_cert_key_key_algorithm_to_der", self.handle)

    def signs(self, signature: SignatureAlgorithm) -> bool:
        """Whether a key of the algorithm makes signatures of ``signature``."""
        return self.library.value("umilib_auth_cert_key_key_algorithm_signs", ctypes.c_bool, self.handle, signature)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, KeyAlgorithm) and self.to_der() == other.to_der()

    def __hash__(self) -> int:
        return hash(self.to_der())


class PublicKey(Handle):
    """A validated public key and its algorithm."""

    FREE = "umilib_auth_cert_key_public_key_free"

    @staticmethod
    def from_der(data: bytes | bytearray | memoryview) -> PublicKey:
        """The key of a DER ``SubjectPublicKeyInfo``."""
        return PublicKey(Handle.create("umilib_auth_cert_key_public_key_from_der", *Bytes.readable(data)))

    @staticmethod
    def from_pem(text: str) -> PublicKey:
        """The key of PEM text (``PUBLIC KEY``)."""
        return PublicKey(Handle.create("umilib_auth_cert_key_public_key_from_pem", *Text.encode(text)))

    def to_der(self) -> bytes:
        return self.library.output("umilib_auth_cert_key_public_key_to_der", self.handle)

    def to_pem(self) -> str:
        return self.library.output("umilib_auth_cert_key_public_key_to_pem", self.handle).decode("ascii")

    @property
    def key(self) -> bytes:
        """The bytes of the ``subjectPublicKey``."""
        return self.library.output("umilib_auth_cert_key_public_key_key", self.handle)

    @property
    def algorithm(self) -> KeyAlgorithm:
        return KeyAlgorithm(Handle.create("umilib_auth_cert_key_public_key_algorithm", self.handle))

    def verify(self, algorithm: SignatureAlgorithm, message: bytes | bytearray | memoryview, signature: bytes | bytearray | memoryview) -> None:
        """Returns if ``signature`` is a signature of ``message``; raises ``InvalidSignature`` (or ``Mismatch``) otherwise."""
        self.library.call("umilib_auth_cert_key_public_key_verify", self.handle, algorithm, *Bytes.readable(message), *Bytes.readable(signature))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PublicKey) and self.to_der() == other.to_der()

    def __hash__(self) -> int:
        return hash(self.to_der())


class PrivateKey(Handle):
    """A private key and its algorithm."""

    FREE = "umilib_auth_cert_key_private_key_free"

    @staticmethod
    def generate(algorithm: KeyAlgorithm, random: Any) -> PrivateKey:
        """A new key of ``algorithm`` (not RSA) drawn from the generator ``random``."""
        handle, name, length = random.source()
        return PrivateKey(Handle.create("umilib_auth_cert_key_private_key_generate", algorithm, handle, name, length))

    @staticmethod
    def generate_rsa(algorithm: KeyAlgorithm, bits: int, random: Any) -> PrivateKey:
        """A new RSA key of ``bits`` bits for ``algorithm`` (RSA or RSASSA-PSS)."""
        handle, name, length = random.source()
        return PrivateKey(Handle.create("umilib_auth_cert_key_private_key_generate_rsa", algorithm, bits, handle, name, length))

    @staticmethod
    def from_pkcs8_der(data: bytes | bytearray | memoryview) -> PrivateKey:
        return PrivateKey(Handle.create("umilib_auth_cert_key_private_key_from_pkcs8_der", *Bytes.readable(data)))

    @staticmethod
    def from_pkcs8_ber(data: bytes | bytearray | memoryview) -> PrivateKey:
        """The key of a ``OneAsymmetricKey`` in BER (DER included), as RFC 5958 requires receivers to accept."""
        return PrivateKey(Handle.create("umilib_auth_cert_key_private_key_from_pkcs8_ber", *Bytes.readable(data)))

    @staticmethod
    def from_encrypted_pkcs8_ber(data: bytes | bytearray | memoryview, password: bytes, config: PBES2Config = PBES2Config()) -> PrivateKey:
        return PrivateKey(
            Handle.create("umilib_auth_cert_key_private_key_from_encrypted_pkcs8_ber", *Bytes.readable(data), *Bytes.readable(password), config.structure())
        )

    @staticmethod
    def from_pem(text: str) -> PrivateKey:
        """The key of PEM text: ``PRIVATE KEY``, ``RSA PRIVATE KEY`` or ``EC PRIVATE KEY``."""
        return PrivateKey(Handle.create("umilib_auth_cert_key_private_key_from_pem", *Text.encode(text)))

    @staticmethod
    def from_encrypted_pkcs8_der(data: bytes | bytearray | memoryview, password: bytes, config: PBES2Config = PBES2Config()) -> PrivateKey:
        return PrivateKey(
            Handle.create("umilib_auth_cert_key_private_key_from_encrypted_pkcs8_der", *Bytes.readable(data), *Bytes.readable(password), config.structure())
        )

    @staticmethod
    def from_encrypted_pem(text: str, password: bytes, config: PBES2Config = PBES2Config()) -> PrivateKey:
        return PrivateKey(
            Handle.create("umilib_auth_cert_key_private_key_from_encrypted_pem", *Text.encode(text), *Bytes.readable(password), config.structure())
        )

    def to_pkcs8_der(self) -> bytes:
        return self.library.output("umilib_auth_cert_key_private_key_to_pkcs8_der", self.handle)

    def to_pem(self) -> str:
        return self.library.output("umilib_auth_cert_key_private_key_to_pem", self.handle).decode("ascii")

    def to_encrypted_pkcs8_der(self, password: bytes, random: Any, config: PBES2Config = PBES2Config()) -> bytes:
        handle, name, length = random.source()
        out = Buffer()
        self.library.call(
            "umilib_auth_cert_key_private_key_to_encrypted_pkcs8_der", self.handle, *Bytes.readable(password), config.structure(), handle, name, length, ctypes.byref(out)
        )
        return self.library.take(out)

    def public_key(self) -> PublicKey:
        return PublicKey(Handle.create("umilib_auth_cert_key_private_key_public_key", self.handle))

    @property
    def algorithm(self) -> KeyAlgorithm:
        return KeyAlgorithm(Handle.create("umilib_auth_cert_key_private_key_algorithm", self.handle))

    def sign(self, algorithm: SignatureAlgorithm, message: bytes | bytearray | memoryview, random: Any) -> bytes:
        """The signature of ``message``; raises ``Mismatch`` if the key does not make such signatures."""
        handle, name, length = random.source()
        out = Buffer()
        self.library.call("umilib_auth_cert_key_private_key_sign", self.handle, algorithm, *Bytes.readable(message), handle, name, length, ctypes.byref(out))
        return self.library.take(out)


__all__ = [
    "HashAlgorithm",
    "KeyAlgorithm",
    "KeyLimits",
    "KeyStatusError",
    "MLDSAParameterSet",
    "MLKEMParameterSet",
    "NamedCurve",
    "PBES2Cipher",
    "PBES2Config",
    "PrivateKey",
    "PublicKey",
    "SLHDSAParameterSet",
    "SignatureAlgorithm",
]
