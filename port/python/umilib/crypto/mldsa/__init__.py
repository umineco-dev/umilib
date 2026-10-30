"""ML-DSA, the module-lattice-based digital signature algorithm of FIPS 204. Mirrors
``umilib::crypto::mldsa``.

``MLDSA[MLDSA65]`` is a :class:`~umilib.crypto.ContextSignatureScheme`: its keys are the encodings of
FIPS 204 (a private key is read only if its s1 and s2 are in range and its t0 and tr are those its
other parts define); :meth:`MLDSA.signing_key_from_seed` expands the seed ξ of 32 bytes.
"""

from __future__ import annotations

from typing import Any

from umilib.crypto import ContextSignatureScheme, Names, SigningKey
from umilib.ffi import Marker
from umilib.secret import Secret


class MLDSAParameters(Marker, abstract=True):
    """A parameter set of ML-DSA (FIPS 204 table 1), named by its C type name."""


class MLDSA44(MLDSAParameters):
    """ML-DSA-44, of security category 2."""


class MLDSA65(MLDSAParameters):
    """ML-DSA-65, of security category 3."""


class MLDSA87(MLDSAParameters):
    """ML-DSA-87, of security category 5."""


class MLDSA(ContextSignatureScheme):
    """ML-DSA with the parameter set of ``MLDSA[P]``."""

    PREFIX = "umilib_crypto_mldsa_mldsa"

    def __class_getitem__(cls, parameters: Any) -> Any:
        parameters = Names.require(parameters, MLDSAParameters, "MLDSA")
        return cls.specialize((parameters,), cls.SIZES, {"__doc__": f"ML-DSA with {parameters.__name__}."})

    @classmethod
    def signing_key_from_seed(cls, seed: bytes | bytearray) -> SigningKey:
        """The private key of the seed ξ of 32 bytes (FIPS 204 algorithm 6); raises ``InvalidKey`` for
        another length. A ``bytearray`` is zeroized afterwards."""
        key = SigningKey.allocate(cls, cls.SIGNING_KEY_SIZE)
        source = Secret(seed if isinstance(seed, bytearray) else bytearray(seed))
        with source:
            with source.locked():
                data, length = source.location()
                with key.writable() as (out, size):
                    cls.call("signing_key_from_seed", data, length, out, size)
        return key


__all__ = ["MLDSA", "MLDSA44", "MLDSA65", "MLDSA87", "MLDSAParameters"]
