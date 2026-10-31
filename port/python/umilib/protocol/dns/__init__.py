"""The Domain Name System (RFC 1034, RFC 1035): messages, zone files, an authoritative server and a
stub resolver without I/O, and their transports in the subpackages. Mirrors ``umilib::protocol::dns``.

Names and records are their presentation format (RFC 1035 §5.1): records one a line, absolute
names, as a zone file has them. Times are nanoseconds of the caller's monotonic clock (``now``) and,
for cookies, seconds since 1970 (``time``). What needs randomness takes a generator of
:mod:`umilib.crypto.random` as ``random``, as in Rust. Errors are :class:`DNSError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import enum
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Text
from umilib.protocol.ip import IPEndpoint, IPEndpointPattern


class DNSError(FFIError):
    """An error of DNS: ``Malformed``, ``Syntax``, ``TooLarge``, ``State``, ``Config``, ``Bogus`` or ``Timeout``."""


Library.register_error("protocol.dns", DNSError)


class DNSType(int):
    """A type of resource record (RFC 1035 §3.2.2, IANA's registry)."""

    A: ClassVar[DNSType]
    NS: ClassVar[DNSType]
    CNAME: ClassVar[DNSType]
    SOA: ClassVar[DNSType]
    PTR: ClassVar[DNSType]
    MX: ClassVar[DNSType]
    TXT: ClassVar[DNSType]
    AAAA: ClassVar[DNSType]
    SRV: ClassVar[DNSType]
    DNAME: ClassVar[DNSType]
    OPT: ClassVar[DNSType]
    DS: ClassVar[DNSType]
    RRSIG: ClassVar[DNSType]
    NSEC: ClassVar[DNSType]
    DNSKEY: ClassVar[DNSType]
    NSEC3: ClassVar[DNSType]
    TLSA: ClassVar[DNSType]
    SVCB: ClassVar[DNSType]
    HTTPS: ClassVar[DNSType]
    AXFR: ClassVar[DNSType]
    ANY: ClassVar[DNSType]
    CAA: ClassVar[DNSType]


for _name, _value in [
    ("A", 1), ("NS", 2), ("CNAME", 5), ("SOA", 6), ("PTR", 12), ("MX", 15), ("TXT", 16), ("AAAA", 28), ("SRV", 33),
    ("DNAME", 39), ("OPT", 41), ("DS", 43), ("RRSIG", 46), ("NSEC", 47), ("DNSKEY", 48), ("NSEC3", 50), ("TLSA", 52),
    ("SVCB", 64), ("HTTPS", 65), ("AXFR", 252), ("ANY", 255), ("CAA", 257),
]:  # fmt: skip
    setattr(DNSType, _name, DNSType(_value))


class DNSClass(int):
    """A class (RFC 1035 §3.2.4): IN of the Internet, CH, HS."""

    IN: ClassVar[DNSClass]
    CH: ClassVar[DNSClass]
    HS: ClassVar[DNSClass]


DNSClass.IN, DNSClass.CH, DNSClass.HS = DNSClass(1), DNSClass(3), DNSClass(4)


class DNSResponseCode(int):
    """A response code (RFC 1035 §4.1.1, RFC 6891 §6.1.3)."""

    NOERROR: ClassVar[DNSResponseCode]
    FORMERR: ClassVar[DNSResponseCode]
    SERVFAIL: ClassVar[DNSResponseCode]
    NXDOMAIN: ClassVar[DNSResponseCode]
    NOTIMP: ClassVar[DNSResponseCode]
    REFUSED: ClassVar[DNSResponseCode]
    BADVERS: ClassVar[DNSResponseCode]


for _name, _value in [("NOERROR", 0), ("FORMERR", 1), ("SERVFAIL", 2), ("NXDOMAIN", 3), ("NOTIMP", 4), ("REFUSED", 5), ("BADVERS", 16)]:
    setattr(DNSResponseCode, _name, DNSResponseCode(_value))


class DNSTransport(enum.IntEnum):
    """How messages are carried."""

    UDP = 0
    TCP = 1
    TLS = 2
    HTTPS = 3
    QUIC = 4


class DNSSection(enum.IntEnum):
    """A section of a message's records."""

    ANSWER = 0
    AUTHORITY = 1
    ADDITIONAL = 2


@dataclasses.dataclass
class DNSHeader:
    """The header of a message (RFC 1035 §4.1.1), the response code whole."""

    id: int = 0
    response: bool = False
    opcode: int = 0
    authoritative: bool = False
    truncated: bool = False
    recursion_desired: bool = False
    recursion_available: bool = False
    authentic_data: bool = False
    checking_disabled: bool = False
    rcode: int = 0

    FIELDS: ClassVar[tuple[str, ...]] = (
        "id", "response", "opcode", "authoritative", "truncated", "recursion_desired", "recursion_available",
        "authentic_data", "checking_disabled", "rcode",
    )  # fmt: skip

    @classmethod
    def from_structure(cls, structure: Any) -> DNSHeader:
        return cls(*(getattr(structure, name) for name in cls.FIELDS))

    def to_structure(self) -> Any:
        structure = Library.default().type("umilib_protocol_dns_DNSHeader")()
        for name in self.FIELDS:
            Fields.assign(structure, name, getattr(self, name))
        return structure


@dataclasses.dataclass
class DNSEDNS:
    """The EDNS of a message (RFC 6891 §6.1) but its options."""

    udp_size: int = 1232
    version: int = 0
    dnssec_ok: bool = False


class DNSMessage(Handle):
    """A DNS message (RFC 1035 §4.1)."""

    FREE = "umilib_protocol_dns_dns_message_free"
    UDP_SIZE: ClassVar[int] = 512
    MAXIMUM_SIZE: ClassVar[int] = 65535

    @classmethod
    def query(cls, name: str, kind: int, klass: int = DNSClass.IN, id: int = 0) -> DNSMessage:
        """A query of ``id`` for ``name``, of ``kind`` and ``klass``, with recursion desired."""
        return cls(Handle.create("umilib_protocol_dns_dns_message_query", *Text.encode(name), kind, klass, id))

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> DNSMessage:
        """The message of ``data``; raises ``Malformed``."""
        return cls(Handle.create("umilib_protocol_dns_dns_message_decode", *Bytes.readable(data)))

    def encode(self, limit: int = 65535) -> bytes:
        """The message in at most ``limit`` bytes, whole RRsets left out from the end (RFC 2181 §9)."""
        return self.library.output("umilib_protocol_dns_dns_message_encode", self.handle, limit)

    @property
    def header(self) -> DNSHeader:
        structure = self.library.type("umilib_protocol_dns_DNSHeader")()
        self.library.call("umilib_protocol_dns_dns_message_header", self.handle, ctypes.byref(structure))
        return DNSHeader.from_structure(structure)

    @header.setter
    def header(self, header: DNSHeader) -> None:
        self.library.call("umilib_protocol_dns_dns_message_set_header", self.handle, header.to_structure())

    @property
    def edns(self) -> DNSEDNS | None:
        structure = self.library.type("umilib_protocol_dns_DNSEDNS")()
        self.library.call("umilib_protocol_dns_dns_message_edns", self.handle, ctypes.byref(structure))
        return DNSEDNS(structure.udp_size, structure.version, structure.dnssec_ok) if structure.present else None

    @edns.setter
    def edns(self, edns: DNSEDNS | None) -> None:
        structure = self.library.type("umilib_protocol_dns_DNSEDNS")()
        if edns is not None:
            structure.present = True
            Fields.assign(structure, "udp_size", edns.udp_size)
            Fields.assign(structure, "version", edns.version)
            structure.dnssec_ok = edns.dnssec_ok
        self.library.call("umilib_protocol_dns_dns_message_set_edns", self.handle, structure)

    def option(self, code: int) -> bytes | None:
        """The data of the EDNS option ``code``, if there is one."""
        return self.library.optional("umilib_protocol_dns_dns_message_option", Buffer, self.handle, code)

    def set_option(self, code: int, data: bytes) -> None:
        """Sets the option ``code``, the only one of it; adds EDNS if there is none."""
        self.library.call("umilib_protocol_dns_dns_message_set_option", self.handle, code, *Bytes.readable(data))

    @property
    def question(self) -> tuple[str, DNSType, DNSClass] | None:
        """The question: its name, type and class."""
        found, name, kind, klass = ctypes.c_bool(), Buffer(), ctypes.c_uint16(), ctypes.c_uint16()
        self.library.call(
            "umilib_protocol_dns_dns_message_question", self.handle, ctypes.byref(found), ctypes.byref(name), ctypes.byref(kind), ctypes.byref(klass)
        )
        text = self.library.take(name).decode()
        return (text, DNSType(kind.value), DNSClass(klass.value)) if found.value else None

    def records(self, section: DNSSection) -> list[str]:
        """The records of ``section``, each in its presentation format."""
        return self.library.output("umilib_protocol_dns_dns_message_records", self.handle, int(section)).decode().splitlines()

    @property
    def answers(self) -> list[str]:
        return self.records(DNSSection.ANSWER)

    @property
    def authorities(self) -> list[str]:
        return self.records(DNSSection.AUTHORITY)

    @property
    def additionals(self) -> list[str]:
        return self.records(DNSSection.ADDITIONAL)

    def add_records(self, section: DNSSection, records: str | list[str]) -> None:
        """Adds the records of zone-file text (absolute names; TTL 0 where none) to ``section``; raises ``Syntax``."""
        text = records if isinstance(records, str) else "\n".join(records)
        self.library.call("umilib_protocol_dns_dns_message_add_records", self.handle, int(section), *Text.encode(text))


class DNSZoneFile:
    """The reading of zone files (RFC 1035 §5)."""

    @staticmethod
    def parse(text: str, origin: str | None = None, default_ttl: int | None = None) -> list[str]:
        """The records of ``text``, absolute, one a line; raises ``Syntax`` (its line in ``line``)."""
        line, out = ctypes.c_size_t(), Buffer()
        try:
            Library.default().call(
                "umilib_protocol_dns_dns_zone_file_parse", *Text.encode(text), *Text.encode(origin or ""), default_ttl is not None,
                default_ttl or 0, ctypes.byref(line), ctypes.byref(out),
            )  # fmt: skip
        except DNSError as error:
            error.line = line.value
            raise
        return Library.default().take(out).decode().splitlines()


@dataclasses.dataclass
class DNSZone:
    """The data of a zone: its origin and zone-file text (relative names of the origin)."""

    origin: str
    text: str

    def sign(self, keys: list[tuple[str, int]], inception: int, expiration: int, random: Any) -> list[str]:
        """The zone signed (RFC 4035 §2) by ``keys``, each a private key's text and its DNSKEY flags,
        valid from ``inception`` to ``expiration`` (seconds since 1970), the signatures' randomness
        drawn from ``random``: its records one a line."""
        texts = [key.encode() for key, _ in keys]
        array = (ctypes.c_char_p * max(len(texts), 1))(*texts)
        flags = (ctypes.c_uint16 * max(len(keys), 1))(*(flag for _, flag in keys))
        return Library.default().output(
            "umilib_protocol_dns_dnssec_dns_zone_sign", *Text.encode(self.origin), *Text.encode(self.text), array, flags, len(keys), inception,
            expiration, *random.source(),
        ).decode().splitlines()  # fmt: skip


@dataclasses.dataclass
class DNSAuthorityConfig:
    """What an authoritative server does beyond its zones; durations in milliseconds (0: none)."""

    minimal: bool = True
    udp_size: int = 1232
    maximum_chain: int = 16
    padding: int = 468
    transfer_size: int = 16384
    keepalive: int = 10_000

    def to_structure(self) -> Any:
        structure = Library.default().type("umilib_protocol_dns_DNSAuthorityConfig")()
        for field in dataclasses.fields(self):
            Fields.assign(structure, field.name, getattr(self, field.name))
        return structure


class DNSAuthority(Handle):
    """An authoritative name server (RFC 1034 §4.3.2) of the zones added to it."""

    FREE = "umilib_protocol_dns_dns_authority_free"

    def __init__(self, config: DNSAuthorityConfig | None = None) -> None:
        super().__init__(Handle.create("umilib_protocol_dns_dns_authority_new", (config or DNSAuthorityConfig()).to_structure()))

    def add_zone(self, origin: str, text: str) -> None:
        """Adds the zone of ``origin`` and the zone-file ``text``; raises ``Syntax`` or ``Config``."""
        self.library.call("umilib_protocol_dns_dns_authority_add_zone", self.handle, *Text.encode(origin), *Text.encode(text))

    def set_cookie_secrets(self, secrets: list[bytes]) -> None:
        """The secrets of server cookies (RFC 9018 §5), the first the current one; none ignores cookies."""
        if any(len(secret) != 16 for secret in secrets):
            raise ValueError("a cookie secret is 16 bytes")
        self.library.call("umilib_protocol_dns_dns_authority_set_cookie_secrets", self.handle, *Bytes.readable(b"".join(secrets)))

    def set_transfers(self, patterns: list[IPEndpointPattern]) -> None:
        """The clients that may transfer zones (RFC 5936)."""
        kind = self.library.type("umilib_protocol_ip_IPEndpointPattern")
        array = (kind * max(len(patterns), 1))(*(pattern.to_structure() for pattern in patterns))
        self.library.call("umilib_protocol_dns_dns_authority_set_transfers", self.handle, array, len(patterns))

    def respond(self, query: bytes, peer: IPEndpoint, transport: DNSTransport, time: int = 0) -> list[bytes]:
        """The responses to ``query`` from ``peer`` over ``transport``: none to what is not a query,
        several for a zone transfer."""
        framed = self.library.output("umilib_protocol_dns_dns_authority_respond", self.handle, *Bytes.readable(query), peer.to_structure(), int(transport), time)
        responses = []
        while framed:
            length = int.from_bytes(framed[:2], "big")
            responses.append(framed[2 : 2 + length])
            framed = framed[2 + length :]
        return responses


@dataclasses.dataclass
class DNSResolverConfig:
    """How a resolver asks; durations in milliseconds, the cache's TTLs in seconds."""

    timeout: int = 2000
    maximum_timeout: int = 8000
    rounds: int = 2
    edns: bool = True
    udp_size: int = 1232
    recursion_desired: bool = True
    dnssec_ok: bool = False
    checking_disabled: bool = False
    cookies: bool = True
    padding: int = 128
    maximum_queries: int = 1024
    cache_entries: int = 4096
    cache_maximum_ttl: int = 86400
    cache_minimum_ttl: int = 0
    cache_maximum_negative_ttl: int = 10800
    cache_failure_ttl: int = 5

    def to_structure(self) -> Any:
        structure = Library.default().type("umilib_protocol_dns_DNSResolverConfig")()
        for field in dataclasses.fields(self):
            Fields.assign(structure, field.name, getattr(self, field.name))
        return structure


@dataclasses.dataclass(frozen=True)
class DNSUpstream:
    """A server a resolver asks."""

    endpoint: IPEndpoint
    transport: DNSTransport = DNSTransport.UDP

    @staticmethod
    def array(upstreams: list[DNSUpstream]) -> tuple[Any, int]:
        kind = Library.default().type("umilib_protocol_dns_DNSUpstream")
        structures = []
        for upstream in upstreams:
            structure = kind()
            structure.endpoint = upstream.endpoint.to_structure()
            structure.transport = int(upstream.transport)
            structures.append(structure)
        return (kind * max(len(structures), 1))(*structures), len(structures)


@dataclasses.dataclass(frozen=True)
class DNSTransmission:
    """A query to send: of which query, to which server, how, and its bytes."""

    query: int
    upstream: int
    transport: DNSTransport
    message: bytes


class DNSResolver(Handle):
    """A stub resolver without I/O (RFC 1034 §5.3.1): it makes queries, takes responses and the time,
    and tells the answers."""

    FREE = "umilib_protocol_dns_dns_resolver_free"
    PREFIX: ClassVar[str] = "umilib_protocol_dns_dns_resolver"

    def __init__(self, upstreams: list[DNSUpstream], random: Any, config: DNSResolverConfig | None = None) -> None:
        """A resolver of ``upstreams``, its cookie secret drawn from ``random``."""
        super().__init__(
            Handle.create(f"{self.PREFIX}_new", (config or DNSResolverConfig()).to_structure(), *DNSUpstream.array(upstreams), *random.source())
        )

    def resolve(self, name: str, kind: int, now: int, random: Any, klass: int = DNSClass.IN) -> int:
        """Starts resolving, the query's ID drawn from ``random``; the query's handle. Raises
        ``State`` at the limit of queries."""
        return self.library.value(f"{self.PREFIX}_resolve", ctypes.c_uint64, self.handle, *Text.encode(name), kind, klass, now, *random.source())

    def transmit(self) -> DNSTransmission | None:
        """The next query to send, or ``None``."""
        found, structure, message = ctypes.c_bool(), self.library.type("umilib_protocol_dns_DNSTransmission")(), Buffer()
        self.library.call(f"{self.PREFIX}_transmit", self.handle, ctypes.byref(found), ctypes.byref(structure), ctypes.byref(message))
        data = self.library.take(message)
        return DNSTransmission(structure.query, structure.upstream, DNSTransport(structure.transport), data) if found.value else None

    def receive(self, query: int, upstream: int, transport: DNSTransport, data: bytes, now: int, random: Any) -> None:
        """Takes a response; one that does not match its query is ignored."""
        self.library.call(f"{self.PREFIX}_receive", self.handle, query, upstream, int(transport), *Bytes.readable(data), now, *random.source())

    def poll_timeout(self) -> int | None:
        return self.library.optional(f"{self.PREFIX}_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int, random: Any) -> None:
        self.library.call(f"{self.PREFIX}_expire", self.handle, now, *random.source())

    def cancel(self, query: int) -> None:
        self.library.call(f"{self.PREFIX}_cancel", self.handle, query)

    def poll_event(self) -> tuple[int, bytes | DNSError] | None:
        """The next answered query: its handle and its response, or the error it failed with."""
        found, query, error, out = ctypes.c_bool(), ctypes.c_uint64(), ctypes.c_void_p(), Buffer()
        self.library.call(f"{self.PREFIX}_poll_event", self.handle, ctypes.byref(found), ctypes.byref(query), ctypes.byref(error), ctypes.byref(out))
        data = self.library.take(out)
        if not found.value:
            return None
        if error.value:
            try:
                self.library.check(error.value)
            except DNSError as failure:
                return query.value, failure
        return query.value, data
