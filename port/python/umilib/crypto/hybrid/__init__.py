"""Post-quantum/traditional hybrids: the key agreements of RFC 10024 for TLS 1.3 as KEMs. Mirrors
``umilib::crypto::hybrid``.

``HybridKEM[X25519MLKEM768]`` is a :class:`~umilib.crypto.KeyEncapsulation` whose encapsulation key is
the client's key_exchange, whose ciphertext is the server's, and whose shared secret is the
concatenation of the two secrets in the order of the group.
"""

from __future__ import annotations

from typing import Any, ClassVar

from umilib.crypto import KeyEncapsulation, Names
from umilib.ffi import Marker


class HybridKEMParameters(Marker, abstract=True):
    """A hybrid group, named by its C type name, with its TLS NamedGroup ``CODEPOINT``."""

    CODEPOINT: ClassVar[int] = 0


class X25519MLKEM768(HybridKEMParameters):
    """X25519MLKEM768 (RFC 10024): ML-KEM-768 first, then X25519."""

    CODEPOINT = 0x11EC


class SecP256r1MLKEM768(HybridKEMParameters):
    """SecP256r1MLKEM768 (RFC 10024): secp256r1 first, then ML-KEM-768."""

    CODEPOINT = 0x11EB


class SecP384r1MLKEM1024(HybridKEMParameters):
    """SecP384r1MLKEM1024 (RFC 10024): secp384r1 first, then ML-KEM-1024."""

    CODEPOINT = 0x11ED


class HybridKEM(KeyEncapsulation):
    """The hybrid group of ``HybridKEM[P]`` as a KEM."""

    PREFIX = "umilib_crypto_hybrid_hybrid_kem"

    def __class_getitem__(cls, group: Any) -> Any:
        group = Names.require(group, HybridKEMParameters, "HybridKEM")
        return cls.specialize((group,), cls.SIZES, {"__doc__": f"{group.__name__} as a KEM."})


__all__ = ["HybridKEM", "HybridKEMParameters", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768"]
