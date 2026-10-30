"""Random bit generation: the deterministic random bit generators of NIST SP 800-90A. Mirrors ``umilib::crypto::random``.

``HMACDRBG[SHA256](entropy, nonce, personalization)`` is
``HMACDRBG::<SHA256>::new(...)``, and ``CTRDRBG[AES256](...)`` is CTR_DRBG over
a 128-bit block cipher. A generator expands the entropy it is given;
take that entropy from ``secrets.token_bytes`` or the operating system.
Generators cannot be copied: two copies would generate the same bytes.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any, ClassVar

from umilib.crypto import BlockCipherClass, Specialization
from umilib.ffi import Bytes, FFIError, Fields, Handle, Library, Text
from umilib.hash import CryptographicDigest


class RandomError(FFIError):
    """An error of random generation; ``name`` is the variant, such as ``ReseedRequired``."""


Library.register_error("crypto.random", RandomError)


@dataclass(frozen=True)
class DRBGConfig:
    """The limits of a generator, which may be tightened but not loosened
    beyond SP 800-90A table 2; :meth:`default` has the loosest."""

    reseed_interval: int
    maximum_request: int

    @classmethod
    def default(cls) -> DRBGConfig:
        """2^48 requests between reseeds and 2^16 bytes per request."""
        return DRBGConfig.from_structure(Library.default().function("umilib_crypto_random_drbg_config_default")())

    def structure(self) -> Any:
        structure = Library.default().type("umilib_crypto_random_DRBGConfig")()
        Fields.assign(structure, "reseed_interval", self.reseed_interval)
        Fields.assign(structure, "maximum_request", self.maximum_request)
        return structure

    @classmethod
    def from_structure(cls, structure: Any) -> DRBGConfig:
        return cls(structure.reseed_interval, structure.maximum_request)

    def clamped(self) -> DRBGConfig:
        """The configuration with every limit within table 2."""
        function = Library.default().function("umilib_crypto_random_drbg_config_clamped")
        return DRBGConfig.from_structure(function(self.structure()))


class Random(Handle):
    """A source of random bytes, as the Rust trait ``Random``."""

    def fill(self, out: bytearray) -> None:
        """Fills ``out`` with random bytes."""
        raise NotImplementedError

    def source(self) -> tuple[Any, Any, int]:
        """The arguments by which the C ABI takes the generator: its handle and the C type name of the
        handle, as bytes and length. Only the generators of umilib have them."""
        raise TypeError(f"{type(self).__name__} is not a generator of umilib; use one of umilib.crypto.random")

    def bytes(self, length: int) -> bytes:
        """``length`` random bytes."""
        out = bytearray(length)
        self.fill(out)
        return bytes(out)

    def next_u32(self) -> int:
        return int.from_bytes(self.bytes(4), "little")

    def next_u64(self) -> int:
        return int.from_bytes(self.bytes(8), "little")


class DRBG(Random):
    """A deterministic random bit generator, as the Rust trait ``DRBG``:
    ``HMACDRBG[H]`` is the generator over the hash function class ``H``, and
    ``CTRDRBG[C]`` over the block cipher class ``C``."""

    PREFIX: ClassVar[str] = ""
    #: The C type name of the handle, such as ``umilib_crypto_random_HMACDRBG``.
    C_TYPE: ClassVar[str] = ""
    #: The hash function or the block cipher of the generator.
    PRIMITIVE: ClassVar[Any] = None

    def __init_subclass__(cls, **options: Any) -> None:
        super().__init_subclass__(**options)
        if cls.PREFIX:
            cls.FREE = f"{cls.PREFIX}_free"

    def __class_getitem__(cls, primitive: type) -> Any:
        """The class of the generator over ``primitive``."""
        if not cls.PREFIX:
            raise TypeError("choose a generator, as in HMACDRBG[SHA256]")
        cls.require(primitive)
        return Specialization.of(cls, (primitive,), {"PRIMITIVE": primitive})

    @classmethod
    def require(cls, primitive: Any) -> None:
        """Raises ``TypeError`` unless ``primitive`` is a cryptographic hash function class."""
        if not (isinstance(primitive, type) and issubclass(primitive, CryptographicDigest) and primitive.C_TYPE):
            raise TypeError(f"{cls.__name__} needs a hash function class, such as {cls.__name__}[SHA256]")

    @classmethod
    def primitive_name(cls) -> tuple[Any, int]:
        if cls.PRIMITIVE is None:
            raise TypeError(f"choose the primitive first, as in {cls.__name__}[SHA256](entropy)")
        return Text.encode(cls.PRIMITIVE.C_TYPE)

    def __init__(
        self,
        entropy: bytes | bytearray | memoryview,
        nonce: bytes | bytearray | memoryview = b"",
        personalization: bytes | bytearray | memoryview = b"",
        config: DRBGConfig | None = None,
    ) -> None:
        """Instantiates the generator; fails with ``EntropyLength`` if the
        entropy is shorter than the security strength, and with
        ``NonceLength`` if the nonce with it is shorter than 3/2 of it."""
        name, name_length = self.primitive_name()
        structure = (config or DRBGConfig.default()).structure()
        arguments = []
        for data in (entropy, nonce, personalization):
            arguments.extend(Bytes.readable(data))
        super().__init__(Handle.create(f"{self.PREFIX}_with_config", name, name_length, ctypes.byref(structure), *arguments))

    @classmethod
    def new(cls, entropy: bytes, nonce: bytes = b"", personalization: bytes = b"") -> Any:
        return cls(entropy, nonce, personalization)

    @classmethod
    def with_config(cls, config: DRBGConfig, entropy: bytes, nonce: bytes = b"", personalization: bytes = b"") -> Any:
        return cls(entropy, nonce, personalization, config)

    def source(self) -> tuple[Any, Any, int]:
        name, length = Text.encode(self.C_TYPE)
        return self.handle, name, length

    def reseed(self, entropy: bytes | bytearray | memoryview, additional: bytes | bytearray | memoryview = b"") -> None:
        """Mixes fresh entropy and optional additional input into the state."""
        entropy_data, entropy_length = Bytes.readable(entropy)
        data, length = Bytes.readable(additional)
        self.library.call(f"{self.PREFIX}_reseed", self.handle, entropy_data, entropy_length, data, length)

    def generate(self, out: bytearray, additional: bytes | bytearray | memoryview = b"") -> None:
        """Fills ``out`` with one request, of at most the maximum request size."""
        data, length = Bytes.readable(additional)
        self.library.call(f"{self.PREFIX}_generate", self.handle, Bytes.mutable(out), len(out), data, length)

    def fill(self, out: bytearray) -> None:
        """Fills ``out``, of any length, with requests of the maximum size."""
        self.library.call(f"{self.PREFIX}_fill", self.handle, Bytes.mutable(out), len(out))

    def uninstantiate(self) -> None:
        """Erases the state; every later request raises ``Uninstantiated``."""
        self.library.call(f"{self.PREFIX}_uninstantiate", self.handle)

    def is_instantiated(self) -> bool:
        return self.library.value(f"{self.PREFIX}_is_instantiated", ctypes.c_bool, self.handle)

    def config(self) -> DRBGConfig:
        structure = Library.default().type("umilib_crypto_random_DRBGConfig")()
        self.library.call(f"{self.PREFIX}_config", self.handle, ctypes.byref(structure))
        return DRBGConfig.from_structure(structure)

    def security_strength(self) -> int:
        """The security strength in bits (``DRBG::SECURITY_STRENGTH``)."""
        return self.library.value(f"{self.PREFIX}_security_strength", ctypes.c_size_t, self.handle)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(..)"


class HMACDRBG(DRBG):
    """HMAC_DRBG (SP 800-90A section 10.1.2)."""

    PREFIX = "umilib_crypto_random_hmac_drbg"
    C_TYPE = "umilib_crypto_random_HMACDRBG"


class HashDRBG(DRBG):
    """Hash_DRBG (SP 800-90A section 10.1.1)."""

    PREFIX = "umilib_crypto_random_hash_drbg"
    C_TYPE = "umilib_crypto_random_HashDRBG"


class CTRDRBG(DRBG):
    """CTR_DRBG (SP 800-90A section 10.2.1) over a 128-bit block cipher with one key size, with the
    derivation function, or without it through :meth:`instantiate_without_derivation`."""

    PREFIX = "umilib_crypto_random_ctr_drbg"
    C_TYPE = "umilib_crypto_random_CTRDRBG"

    @classmethod
    def require(cls, primitive: Any) -> None:
        """Raises ``TypeError`` unless ``primitive`` is a block cipher class with 16-byte blocks."""
        BlockCipherClass.require(primitive, "CTRDRBG", 16)

    @classmethod
    def instantiate_without_derivation(
        cls,
        config: DRBGConfig,
        entropy: bytes | bytearray | memoryview,
        personalization: bytes | bytearray | memoryview = b"",
    ) -> Any:
        """CTR_DRBG without the derivation function (section 10.2.1.3.1): ``entropy`` has exactly
        seedlen bytes (16 and the key length), ``personalization`` at most seedlen."""
        name, name_length = cls.primitive_name()
        structure = config.structure()
        entropy_data, entropy_length = Bytes.readable(entropy)
        data, length = Bytes.readable(personalization)
        state = cls.__new__(cls)
        Handle.__init__(
            state,
            Handle.create(f"{cls.PREFIX}_instantiate_without_derivation", name, name_length, ctypes.byref(structure), entropy_data, entropy_length, data, length),
        )
        return state


__all__ = ["CTRDRBG", "DRBG", "DRBGConfig", "HMACDRBG", "HashDRBG", "Random", "RandomError"]
