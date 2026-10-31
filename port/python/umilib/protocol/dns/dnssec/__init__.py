"""DNSSEC (RFC 4033, RFC 4034, RFC 4035): verifying RRsets, checking keys against their DS records
or trust anchors (RFC 9718), the denials of NSEC, NSEC3 (RFC 5155) and Compact Denial (RFC 9824),
private keys, and a validating stub resolver. Mirrors ``umilib::protocol::dns::dnssec``.

Records are zone-file text, one a line; private keys the text of the private key format v1.2. A
bogus result raises :class:`umilib.protocol.dns.DNSError` (``Bogus``) whose ``code`` is the extended
error of RFC 8914. Signing a zone is :meth:`umilib.protocol.dns.DNSZone.sign`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import enum
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, Fields, Handle, Library, Text
from umilib.protocol.dns import DNSClass, DNSError, DNSResolver, DNSResolverConfig, DNSUpstream


class DNSSECAlgorithm(enum.IntEnum):
    """The algorithms RFC 9904 says to implement for validation."""

    RSASHA1 = 5
    RSASHA1_NSEC3_SHA1 = 7
    RSASHA256 = 8
    RSASHA512 = 10
    ECDSAP256SHA256 = 13
    ECDSAP384SHA384 = 14
    ED25519 = 15
    ED448 = 16


class DNSSECDigest(enum.IntEnum):
    """The digests of DS records RFC 9904 says to implement."""

    SHA1 = 1
    SHA256 = 2
    SHA384 = 4


class DNSSECProofKind(enum.IntEnum):
    """What a denial proves (:meth:`DNSSECValidator.prove`)."""

    NONEXISTENCE = 0
    NODATA = 1
    EXPANSION = 2
    UNSIGNED_DELEGATION = 3


@dataclasses.dataclass
class DNSSECLimits:
    """The limits of a validator (RFC 9276 §3.2 for NSEC3 iterations; KeyTrap for verifications)."""

    minimum_rsa_bits: int = 1024
    insecure_nsec3_iterations: int = 50
    bogus_nsec3_iterations: int = 150
    maximum_verifications: int = 8
    clock_skew: int = 0
    maximum_rsa_exponent_bits: int = 64


@dataclasses.dataclass(frozen=True)
class DNSSECVerified:
    """An RRset verified: the TTL it keeps, the key's tag, and the closest encloser of a wildcard's expansion."""

    ttl: int
    key_tag: int
    closest_encloser: str | None


class DNSSECValidator(Handle):
    """A DNSSEC validator (RFC 4035 §5)."""

    FREE = "umilib_protocol_dns_dnssec_dnssec_validator_free"

    def __init__(self) -> None:
        super().__init__(Handle.create("umilib_protocol_dns_dnssec_dnssec_validator_new"))

    @staticmethod
    def raise_bogus(error: DNSError, code: ctypes.c_uint16) -> None:
        error.code = code.value
        raise error

    def set_algorithms(self, algorithms: list[int], digests: list[int]) -> None:
        a = (ctypes.c_uint8 * max(len(algorithms), 1))(*algorithms)
        d = (ctypes.c_uint8 * max(len(digests), 1))(*digests)
        self.library.call("umilib_protocol_dns_dnssec_dnssec_validator_set_algorithms", self.handle, a, len(algorithms), d, len(digests))

    @property
    def limits(self) -> DNSSECLimits:
        structure = self.library.type("umilib_protocol_dns_dnssec_DNSSECLimits")()
        self.library.call("umilib_protocol_dns_dnssec_dnssec_validator_limits", self.handle, ctypes.byref(structure))
        return DNSSECLimits(*(getattr(structure, field.name) for field in dataclasses.fields(DNSSECLimits)))

    @limits.setter
    def limits(self, limits: DNSSECLimits) -> None:
        structure = self.library.type("umilib_protocol_dns_dnssec_DNSSECLimits")()
        for field in dataclasses.fields(limits):
            Fields.assign(structure, field.name, getattr(limits, field.name))
        self.library.call("umilib_protocol_dns_dnssec_dnssec_validator_set_limits", self.handle, structure)

    def verify(self, records: list[str], signatures: list[str], keys: list[str], time: int) -> DNSSECVerified:
        """Verifies the RRset ``records`` with ``signatures`` made by ``keys`` (RFC 4035 §5.3)."""
        out, encloser, code = self.library.type("umilib_protocol_dns_dnssec_DNSSECVerified")(), Buffer(), ctypes.c_uint16()
        try:
            self.library.call(
                "umilib_protocol_dns_dnssec_dnssec_validator_verify", self.handle, *Text.encode("\n".join(records)), *Text.encode("\n".join(signatures)),
                *Text.encode("\n".join(keys)), time, ctypes.byref(out), ctypes.byref(encloser), ctypes.byref(code),
            )  # fmt: skip
        except DNSError as error:
            self.raise_bogus(error, code)
        name = self.library.take(encloser).decode()
        return DNSSECVerified(out.ttl, out.key_tag, name if out.expanded else None)

    def verify_keys(self, keys: list[str], signatures: list[str], anchors: list[str], time: int) -> tuple[bool, int]:
        """Checks ``keys`` against the DS or DNSKEY records ``anchors`` (RFC 4035 §5.2): whether
        secure, and if not the extended error that tells why."""
        secure, code = ctypes.c_bool(), ctypes.c_uint16()
        try:
            self.library.call(
                "umilib_protocol_dns_dnssec_dnssec_validator_verify_keys", self.handle, *Text.encode("\n".join(keys)), *Text.encode("\n".join(signatures)),
                *Text.encode("\n".join(anchors)), time, ctypes.byref(secure), ctypes.byref(code),
            )  # fmt: skip
        except DNSError as error:
            self.raise_bogus(error, code)
        return secure.value, code.value

    def prove(self, kind: DNSSECProofKind, name: str, zone: str, records: list[str], record_type: int = 0, encloser: str | None = None) -> tuple[bool, int]:
        """Proves the denial ``kind`` of ``name`` in ``zone`` with the NSEC and NSEC3 ``records``
        (verified): whether secure, and if not an extended error or 0."""
        secure, code = ctypes.c_bool(), ctypes.c_uint16()
        try:
            self.library.call(
                "umilib_protocol_dns_dnssec_dnssec_validator_prove", self.handle, int(kind), *Text.encode(name), record_type, *Text.encode(encloser or ""),
                *Text.encode(zone), *Text.encode("\n".join(records)), ctypes.byref(secure), ctypes.byref(code),
            )  # fmt: skip
        except DNSError as error:
            self.raise_bogus(error, code)
        return secure.value, code.value


class DNSSECPrivateKey:
    """Private keys in the text of the private key format v1.2."""

    @staticmethod
    def generate(algorithm: DNSSECAlgorithm, random: Any, bits: int = 0) -> str:
        """A new key of ``algorithm`` (an RSA modulus of ``bits``), drawn from ``random``."""
        return Library.default().output("umilib_protocol_dns_dnssec_dnssec_private_key_generate", int(algorithm), bits, *random.source()).decode()

    @staticmethod
    def dnskey(key: str, origin: str, flags: int = 257, ttl: int = 3600) -> str:
        """The DNSKEY record of ``key`` at ``origin``."""
        return Library.default().output("umilib_protocol_dns_dnssec_dnssec_private_key_dnskey", *Text.encode(key), *Text.encode(origin), flags, ttl).decode().strip()

    @staticmethod
    def delegation(key: str, origin: str, flags: int = 257, digest: DNSSECDigest = DNSSECDigest.SHA256, ttl: int = 3600) -> str:
        """The DS record of ``digest`` of that DNSKEY (RFC 4034 §5)."""
        return Library.default().output(
            "umilib_protocol_dns_dnssec_dnssec_private_key_delegation", *Text.encode(key), *Text.encode(origin), flags, int(digest), ttl
        ).decode().strip()


class DNSSECTrustAnchor:
    """Trust anchors (RFC 9718)."""

    @staticmethod
    def root(time: int) -> list[str]:
        """The DS records of the root's anchors valid at ``time``."""
        return Library.default().output("umilib_protocol_dns_dnssec_dnssec_trust_anchor_root", time).decode().splitlines()

    @staticmethod
    def parse(xml: str, time: int) -> tuple[str, list[str]]:
        """The zone and the DS records valid at ``time`` of the anchors of ``xml``."""
        zone, out = Buffer(), Buffer()
        Library.default().call("umilib_protocol_dns_dnssec_dnssec_trust_anchor_parse", *Text.encode(xml), time, ctypes.byref(zone), ctypes.byref(out))
        return Library.default().take(zone).decode(), Library.default().take(out).decode().splitlines()


class DNSSECStatus(enum.Enum):
    SECURE = "secure"
    INSECURE = "insecure"


class DNSSECResolver(DNSResolver):
    """A validating stub resolver (RFC 4035 §4.9.3): it asks with DO and CD and validates every
    answer from a trust anchor down. Its methods take ``time`` (seconds since 1970) too."""

    FREE = "umilib_protocol_dns_dnssec_dnssec_resolver_free"
    PREFIX: ClassVar[str] = "umilib_protocol_dns_dnssec_dnssec_resolver"

    def __init__(
        self,
        upstreams: list[DNSUpstream],
        random: Any,
        config: DNSResolverConfig | None = None,
        validator: DNSSECValidator | None = None,
        anchors: str | None = None,
    ) -> None:
        validator = validator or DNSSECValidator()
        Handle.__init__(
            self,
            Handle.create(
                f"{self.PREFIX}_new", (config or DNSResolverConfig()).to_structure(), *DNSUpstream.array(upstreams), validator.handle,
                *Text.encode(anchors or ""), *random.source(),
            ),  # fmt: skip
        )

    def resolve(self, name: str, kind: int, now: int, time: int, random: Any, klass: int = DNSClass.IN) -> int:  # type: ignore[override]
        return self.library.value(f"{self.PREFIX}_resolve", ctypes.c_uint64, self.handle, *Text.encode(name), kind, klass, now, time, *random.source())

    def receive(self, query: int, upstream: int, transport: Any, data: bytes, now: int, time: int, random: Any) -> None:  # type: ignore[override]
        self.library.call(f"{self.PREFIX}_receive", self.handle, query, upstream, int(transport), *Bytes.readable(data), now, time, *random.source())

    def expire(self, now: int, time: int, random: Any) -> None:  # type: ignore[override]
        self.library.call(f"{self.PREFIX}_expire", self.handle, now, time, *random.source())

    def cancel(self, query: int) -> None:
        raise NotImplementedError("a validating resolver's query is not cancelled")

    def poll_event(self) -> tuple[int, tuple[bytes, DNSSECStatus, int] | DNSError] | None:  # type: ignore[override]
        """The next answered question: its handle and its response, whether secure and the extended
        error of an insecure one; or the error it failed with (``Bogus`` with its ``code``)."""
        found, query, error, secure, code, out = ctypes.c_bool(), ctypes.c_uint64(), ctypes.c_void_p(), ctypes.c_bool(), ctypes.c_uint16(), Buffer()
        self.library.call(
            f"{self.PREFIX}_poll_event", self.handle, ctypes.byref(found), ctypes.byref(query), ctypes.byref(error), ctypes.byref(secure),
            ctypes.byref(code), ctypes.byref(out),
        )  # fmt: skip
        data = self.library.take(out)
        if not found.value:
            return None
        if error.value:
            try:
                self.library.check(error.value)
            except DNSError as failure:
                failure.code = code.value
                return query.value, failure
        return query.value, (data, DNSSECStatus.SECURE if secure.value else DNSSECStatus.INSECURE, code.value)
