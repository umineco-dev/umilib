"""ECDSA (FIPS 186-5) with deterministic nonces (RFC 6979). Mirrors ``umilib::crypto::ecdsa``.

``ECDSA[P256, SHA256]`` is ECDSA on a Weierstrass curve of
:mod:`umilib.crypto.curve` with a hash function of :mod:`umilib.hash`:
signing keys are big-endian scalars, verifying keys SEC 1 points and
signatures r || s (IEEE P1363), which :class:`ECDSASignature` converts to and
from DER.
"""

from __future__ import annotations

from typing import Any, ClassVar

from umilib.crypto import Names, SignatureScheme, Specialization
from umilib.ffi import Bytes, Library, Text
from umilib.hash import CryptographicDigest
from umilib.math.ec import WeierstrassCurve

P = "umilib_crypto_ecdsa_ecdsa"


class ECDSA(SignatureScheme):
    """ECDSA on the curve and with the hash function of ``ECDSA[C, H]``."""

    PREFIX = P

    def __class_getitem__(cls, parameters: Any) -> Any:
        curve, hash = Specialization.pair(parameters, "ECDSA")
        curve = Names.require(curve, WeierstrassCurve, "ECDSA")
        hash = Names.require(hash, CryptographicDigest, "ECDSA")
        return cls.specialize((curve, hash), cls.SIZES, {"__doc__": f"ECDSA on {curve.__name__} with {hash.__name__}."})


class ECDSASignature:
    """A signature (r, s) on the curve of ``ECDSASignature[C]``, held as r || s; the C ABI has its
    conversions, and so its validation, with ``codec-asn1-der``."""

    CURVE: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    def __class_getitem__(cls, curve: Any) -> Any:
        curve = Names.require(curve, WeierstrassCurve, "ECDSASignature")
        return Specialization.of(cls, (curve,), {"CURVE": curve})

    def __init__(self, data: bytes) -> None:
        self.data = data

    @classmethod
    def curve_name(cls) -> tuple[Any, int]:
        return Text.encode(Specialization.require(cls.CURVE, "ECDSASignature").C_TYPE)

    @classmethod
    def from_bytes(cls, data: bytes | bytearray | memoryview) -> Any:
        """The signature of r || s; raises ``InvalidSignature`` unless 1 <= r, s < n."""
        signature = cls(bytes(data))
        signature.to_der()
        return signature

    def to_bytes(self) -> bytes:
        return self.data

    @classmethod
    def from_der(cls, der: bytes | bytearray | memoryview) -> Any:
        """The signature of the DER ``ECDSA-Sig-Value`` (RFC 3279 section 2.2.3); raises
        ``InvalidSignature`` for another encoding or values out of range."""
        name, length = cls.curve_name()
        data, data_length = Bytes.readable(der)
        return cls(Library.default().output(f"{P}_signature_from_der", name, length, data, data_length))

    def to_der(self) -> bytes:
        """The DER ``ECDSA-Sig-Value``."""
        name, length = self.curve_name()
        data, data_length = Bytes.readable(self.data)
        return Library.default().output(f"{P}_signature_to_der", name, length, data, data_length)

    def __eq__(self, other: object) -> bool:
        if type(other) is not type(self):
            return NotImplemented
        return self.data == other.data  # type: ignore[attr-defined]

    def __hash__(self) -> int:
        return hash((type(self), self.data))

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.data.hex()})"


__all__ = ["ECDSA", "ECDSASignature"]
