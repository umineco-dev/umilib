"""GOST R 34.10-2012 signatures (RFC 7091). Mirrors ``umilib::crypto::gostr3410``.

``GOSTR3410[GOST256A, Streebog256]`` signs on a curve of
:mod:`umilib.crypto.curve.gost` with a hash function, Streebog of the size
of the curve for the standard (RFC 9215 section 2): signing keys are
little-endian scalars, verifying keys x || y little-endian and signatures
s || r big-endian.
"""

from __future__ import annotations

from typing import Any

from umilib.crypto import Names, SignatureScheme, Specialization
from umilib.hash import CryptographicDigest
from umilib.math.ec import WeierstrassCurve


class GOSTR3410(SignatureScheme):
    """GOST R 34.10-2012 on the curve and with the hash function of ``GOSTR3410[C, H]``."""

    PREFIX = "umilib_crypto_gostr3410_gostr3410"

    def __class_getitem__(cls, parameters: Any) -> Any:
        curve, hash = Specialization.pair(parameters, "GOSTR3410")
        curve = Names.require(curve, WeierstrassCurve, "GOSTR3410")
        hash = Names.require(hash, CryptographicDigest, "GOSTR3410")
        attributes = {"__doc__": f"GOST R 34.10-2012 on {curve.__name__} with {hash.__name__}."}
        return cls.specialize((curve, hash), cls.SIZES, attributes)


__all__ = ["GOSTR3410"]
