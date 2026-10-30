"""SLH-DSA, the stateless hash-based digital signature algorithm of FIPS 205. Mirrors
``umilib::crypto::slhdsa``.

``SLHDSA[SLHDSA_SHAKE_128f]`` is a :class:`~umilib.crypto.ContextSignatureScheme`: its keys are the
encodings of FIPS 205 (a private key is read only if PK.root is the root its seeds generate);
:meth:`SLHDSA.key_gen_internal` makes the private key of SK.seed, SK.prf and PK.seed.
"""

from __future__ import annotations

from typing import Any

from umilib.crypto import ContextSignatureScheme, Names, SigningKey
from umilib.ffi import Bytes, Marker
from umilib.secret import Secret


class SLHDSAParameters(Marker, abstract=True):
    """A parameter set of SLH-DSA (FIPS 205 table 2), named by its C type name."""


class SLHDSA_SHA2_128s(SLHDSAParameters):
    """SLH-DSA-SHA2-128s, of security category 1."""

class SLHDSA_SHAKE_128s(SLHDSAParameters):
    """SLH-DSA-SHAKE-128s, of security category 1."""

class SLHDSA_SHA2_128f(SLHDSAParameters):
    """SLH-DSA-SHA2-128f, of security category 1."""

class SLHDSA_SHAKE_128f(SLHDSAParameters):
    """SLH-DSA-SHAKE-128f, of security category 1."""

class SLHDSA_SHA2_192s(SLHDSAParameters):
    """SLH-DSA-SHA2-192s, of security category 3."""

class SLHDSA_SHAKE_192s(SLHDSAParameters):
    """SLH-DSA-SHAKE-192s, of security category 3."""

class SLHDSA_SHA2_192f(SLHDSAParameters):
    """SLH-DSA-SHA2-192f, of security category 3."""

class SLHDSA_SHAKE_192f(SLHDSAParameters):
    """SLH-DSA-SHAKE-192f, of security category 3."""

class SLHDSA_SHA2_256s(SLHDSAParameters):
    """SLH-DSA-SHA2-256s, of security category 5."""

class SLHDSA_SHAKE_256s(SLHDSAParameters):
    """SLH-DSA-SHAKE-256s, of security category 5."""

class SLHDSA_SHA2_256f(SLHDSAParameters):
    """SLH-DSA-SHA2-256f, of security category 5."""

class SLHDSA_SHAKE_256f(SLHDSAParameters):
    """SLH-DSA-SHAKE-256f, of security category 5."""


class SLHDSA(ContextSignatureScheme):
    """SLH-DSA with the parameter set of ``SLHDSA[P]``."""

    PREFIX = "umilib_crypto_slhdsa_slhdsa"

    def __class_getitem__(cls, parameters: Any) -> Any:
        parameters = Names.require(parameters, SLHDSAParameters, "SLHDSA")
        return cls.specialize((parameters,), cls.SIZES, {"__doc__": f"SLH-DSA with {parameters.__name__}."})

    @classmethod
    def key_gen_internal(cls, sk_seed: bytes | bytearray, sk_prf: bytes | bytearray, pk_seed: bytes | bytearray) -> SigningKey:
        """slh_keygen_internal (FIPS 205 algorithm 18) of SK.seed, SK.prf and PK.seed (n bytes each);
        raises ``InvalidKey`` for other lengths. The secrets given as ``bytearray`` are zeroized afterwards."""
        key = SigningKey.allocate(cls, cls.SIGNING_KEY_SIZE)
        seed = Secret(sk_seed if isinstance(sk_seed, bytearray) else bytearray(sk_seed))
        prf = Secret(sk_prf if isinstance(sk_prf, bytearray) else bytearray(sk_prf))
        public_data, public_length = Bytes.readable(pk_seed)
        with seed, prf:
            with seed.locked(), prf.locked():
                seed_data, seed_length = seed.location()
                prf_data, prf_length = prf.location()
                with key.writable() as (out, size):
                    cls.call("key_gen_internal", seed_data, seed_length, prf_data, prf_length, public_data, public_length, out, size)
        return key


__all__ = [
    "SLHDSA",
    "SLHDSAParameters",
    "SLHDSA_SHA2_128s",
    "SLHDSA_SHAKE_128s",
    "SLHDSA_SHA2_128f",
    "SLHDSA_SHAKE_128f",
    "SLHDSA_SHA2_192s",
    "SLHDSA_SHAKE_192s",
    "SLHDSA_SHA2_192f",
    "SLHDSA_SHAKE_192f",
    "SLHDSA_SHA2_256s",
    "SLHDSA_SHAKE_256s",
    "SLHDSA_SHA2_256f",
    "SLHDSA_SHAKE_256f",
]
