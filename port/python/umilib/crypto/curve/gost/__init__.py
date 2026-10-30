"""The elliptic curves of GOST R 34.10-2012 (RFC 7836, RFC 4357). Mirrors ``umilib::crypto::curve::gost``."""

from __future__ import annotations

from umilib.math.ec import WeierstrassCurve


class GOST256A(WeierstrassCurve):
    """id-tc26-gost-3410-2012-256-paramSetA (RFC 7836 appendix A.2, the Weierstrass form of a twisted Edwards curve, cofactor 4)."""


class GOST256B(WeierstrassCurve):
    """id-tc26-gost-3410-2012-256-paramSetB (RFC 4357 section 11.4, id-GostR3410-2001-CryptoPro-A-ParamSet)."""


class GOST256C(WeierstrassCurve):
    """id-tc26-gost-3410-2012-256-paramSetC (RFC 4357 section 11.4, id-GostR3410-2001-CryptoPro-B-ParamSet)."""


class GOST256D(WeierstrassCurve):
    """id-tc26-gost-3410-2012-256-paramSetD (RFC 4357 section 11.4, id-GostR3410-2001-CryptoPro-C-ParamSet)."""


class GOST512A(WeierstrassCurve):
    """id-tc26-gost-3410-12-512-paramSetA (RFC 7836 appendix A.1)."""


class GOST512B(WeierstrassCurve):
    """id-tc26-gost-3410-12-512-paramSetB (RFC 7836 appendix A.1)."""


class GOST512C(WeierstrassCurve):
    """id-tc26-gost-3410-2012-512-paramSetC (RFC 7836 appendix A.2, the Weierstrass form of a twisted Edwards curve, cofactor 4)."""


__all__ = ["GOST256A", "GOST256B", "GOST256C", "GOST256D", "GOST512A", "GOST512B", "GOST512C"]
