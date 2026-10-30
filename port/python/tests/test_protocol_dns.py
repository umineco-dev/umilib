"""Tests of umilib.protocol.dns: messages, zone files, an authoritative server and a resolver
exchanging, DNSSEC keys, signing and validation, and the transports' parts (RFC 1035, RFC 4035,
RFC 5452, RFC 7766, RFC 8484, RFC 9718)."""

import pytest

from umilib.protocol.dns import (
    DNSAuthority,
    DNSClass,
    DNSEDNS,
    DNSError,
    DNSHeader,
    DNSMessage,
    DNSResolver,
    DNSResolverConfig,
    DNSSection,
    DNSTransport,
    DNSType,
    DNSUpstream,
    DNSZone,
    DNSZoneFile,
)
from umilib.crypto.random import HMACDRBG
from umilib.hash.sha.v2 import SHA256
from umilib.protocol.ip import IPEndpoint, IPEndpointPattern

ZONE = """@ 3600 IN SOA ns admin 1 3600 600 86400 300
@ 3600 IN NS ns
ns 3600 IN A 192.0.2.53
www 300 IN A 192.0.2.80
www 300 IN A 192.0.2.81"""

PEER = IPEndpoint.parse("198.51.100.1:40000")


def generator(seed: int) -> HMACDRBG:
    return HMACDRBG[SHA256](bytes([seed]) * 32, bytes([seed]) * 16, b"dns tests")


def authority():
    server = DNSAuthority()
    server.add_zone("example.", ZONE)
    return server


def test_messages():
    # RFC 1035 §4.1: a query, RD set; EDNS (RFC 6891) and its options.
    message = DNSMessage.query("www.example.", DNSType.A, DNSClass.IN, 0x1234)
    header = message.header
    assert (header.id, header.response, header.recursion_desired, header.rcode) == (0x1234, False, True, 0)
    assert message.question == ("www.example.", DNSType.A, DNSClass.IN)
    assert message.edns is None
    message.edns = DNSEDNS(1232, 0, True)
    message.set_option(10, b"\x01" * 8)
    decoded = DNSMessage.decode(message.encode(512))
    assert decoded.edns == DNSEDNS(1232, 0, True)
    assert decoded.option(10) == b"\x01" * 8 and decoded.option(12) is None
    # Records as their presentation format.
    decoded.add_records(DNSSection.ANSWER, ["www.example. 300 IN A 192.0.2.80", "www.example. 300 IN AAAA 2001:db8::1"])
    assert decoded.answers == ["www.example. 300 IN A 192.0.2.80", "www.example. 300 IN AAAA 2001:db8::1"]
    # A response code above 15 is EDNS's (RFC 6891 §6.1.3).
    decoded.header = DNSHeader(id=1, response=True, rcode=16)
    assert DNSMessage.decode(decoded.encode()).header.rcode == 16
    with pytest.raises(DNSError) as error:
        DNSMessage.query("www..example.", DNSType.A)
    assert error.value.name == "Syntax"
    with pytest.raises(DNSError) as error:
        DNSMessage.decode(b"\x00\x01")
    assert error.value.name == "Malformed"


def test_zone_files():
    records = DNSZoneFile.parse(ZONE, "example.")
    assert len(records) == 5 and records[0].startswith("example. 3600 IN SOA ns.example. admin.example. 1")
    with pytest.raises(DNSError) as error:
        DNSZoneFile.parse("@ 3600 IN SOA ns admin 1 3600 600 86400 300\nwww 300 IN A x", "example.")
    assert (error.value.name, error.value.line) == ("Syntax", 2)


def test_an_authority_and_a_resolver():
    server = authority()
    random = generator(7)
    resolver = DNSResolver([DNSUpstream(IPEndpoint.parse("192.0.2.53:53"))], random)
    query = resolver.resolve("www.example.", DNSType.A, 0, random)
    transmission = resolver.transmit()
    assert (transmission.query, transmission.upstream, transmission.transport) == (query, 0, DNSTransport.UDP)
    sent = DNSMessage.decode(transmission.message)
    assert sent.header.id != 0 and sent.edns.udp_size == 1232
    responses = server.respond(transmission.message, PEER, DNSTransport.UDP)
    resolver.receive(query, 0, DNSTransport.UDP, responses[0], 1, random)
    answered, response = resolver.poll_event()
    assert answered == query
    response = DNSMessage.decode(response)
    assert response.header.authoritative and len(response.answers) == 2
    # A name error (RFC 2308): the SOA, of TTL min(TTL, MINIMUM).
    nxdomain = server.respond(DNSMessage.query("none.example.", DNSType.A).encode(), PEER, DNSTransport.UDP)[0]
    nxdomain = DNSMessage.decode(nxdomain)
    assert nxdomain.header.rcode == 3 and nxdomain.authorities[0].startswith("example. 300 IN SOA")
    # Unanswered: Timeout after the rounds (RFC 1536).
    query = resolver.resolve("www.example.", DNSType.AAAA, 0, random)
    while (deadline := resolver.poll_timeout()) is not None:
        resolver.expire(deadline, random)
    _, failure = resolver.poll_event()
    assert isinstance(failure, DNSError) and failure.name == "Timeout"
    # RFC 5936: transfers to the clients allowed only.
    axfr = DNSMessage.query("example.", DNSType.AXFR).encode()
    assert DNSMessage.decode(server.respond(axfr, PEER, DNSTransport.TCP)[0]).header.rcode == 5
    server.set_transfers([IPEndpointPattern()])
    messages = [DNSMessage.decode(response) for response in server.respond(axfr, PEER, DNSTransport.TCP)]
    records = [record for message in messages for record in message.answers]
    assert " SOA " in records[0] and " SOA " in records[-1] and len(records) == 6
    with pytest.raises(DNSError) as error:
        server.add_zone("other.", "www 300 IN A 192.0.2.1")
    assert error.value.name == "Config"
    with pytest.raises(DNSError):
        DNSResolver([], random, DNSResolverConfig())
    # RFC 9018 §5: secrets of 16 bytes, the first the current one.
    server.set_cookie_secrets([b"\x01" * 16, b"\x02" * 16])
    with pytest.raises(ValueError):
        server.set_cookie_secrets([b"\x01" * 15])
    server.set_cookie_secrets([])


def test_dnssec():
    from umilib.protocol.dns.dnssec import DNSSECAlgorithm, DNSSECPrivateKey, DNSSECProofKind, DNSSECTrustAnchor, DNSSECValidator

    random = generator(9)
    key = DNSSECPrivateKey.generate(DNSSECAlgorithm.ED25519, random)
    assert key.startswith("Private-key-format: v1.2\nAlgorithm: 15 (ED25519)\n")
    dnskey = DNSSECPrivateKey.dnskey(key, "example.", 257)
    ds = DNSSECPrivateKey.delegation(key, "example.", 257)
    assert dnskey.startswith("example. 3600 IN DNSKEY 257 3 15 ") and " DS " in ds
    signed = DNSZone("example.", ZONE).sign([(key, 257)], 1000, 2_000_000_000, random)
    of = lambda kind: [line for line in signed if line.split()[3] == kind]
    signatures, keys = of("RRSIG"), of("DNSKEY")
    validator = DNSSECValidator()
    www = [line for line in of("A") if line.startswith("www.")]
    verified = validator.verify(www, signatures, keys, 5000)
    assert (verified.ttl, verified.closest_encloser) == (300, None)
    with pytest.raises(DNSError) as error:
        validator.verify([line.replace("192.0.2.80", "192.0.2.99") for line in www], signatures, keys, 5000)
    assert (error.value.name, error.value.code) == ("Bogus", 6)
    # RFC 4034 §3.1.5: an expired signature, Signature Expired (RFC 8914 §4.8).
    with pytest.raises(DNSError) as error:
        validator.verify(www, signatures, keys, 2_000_000_001)
    assert error.value.code == 7
    assert validator.verify_keys(keys, signatures, [ds], 5000) == (True, 0)
    assert validator.prove(DNSSECProofKind.NONEXISTENCE, "none.example.", "example.", of("NSEC") + signatures) == (True, 0)
    limits = validator.limits
    limits.clock_skew = 10
    validator.limits = limits
    assert validator.limits.clock_skew == 10
    root = DNSSECTrustAnchor.root(1_793_222_185)
    assert any("20326 8 2" in line for line in root) and any("38696 8 2" in line for line in root)


def test_transports():
    from umilib.protocol.dns.https import DNSHTTPS
    from umilib.protocol.dns.tcp import DNSTCPFramer, DNSTCPServer
    from umilib.protocol.dns.udp import DNSUDP

    query = DNSMessage.query("www.example.", DNSType.A, id=5).encode()
    framed = DNSTCPFramer.frame(query)
    assert framed[:2] == len(query).to_bytes(2, "big")
    connection = DNSTCPServer(PEER, now=0)
    connection.receive(framed, authority(), now=0)
    framer = DNSTCPFramer()
    framer.receive(connection.transmit())
    assert len(DNSMessage.decode(framer.next_message()).answers) == 2
    assert framer.next_message() is None
    assert connection.is_idle(10_000_000_001)
    assert DNSUDP.accepts(IPEndpoint.parse("192.0.2.53:53"), IPEndpoint.parse("192.0.2.53:53"))
    assert not DNSUDP.accepts(IPEndpoint.parse("192.0.2.53:5353"), IPEndpoint.parse("192.0.2.53:53"))
    # RFC 8484 §4.1.1: the GET of www.example.com A.
    example = DNSMessage.query("www.example.com.", DNSType.A).encode()
    path = DNSHTTPS.get_path(example)
    assert path == "/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
    assert DNSHTTPS.query("GET", path) == example
    assert DNSHTTPS.query("POST", "/dns-query", "text/plain", example) == 415
    assert DNSHTTPS.query("PUT", "/dns-query", DNSHTTPS.MEDIA_TYPE, example) == 405
    DNSHTTPS.check_response(200, DNSHTTPS.MEDIA_TYPE, example)
    with pytest.raises(DNSError):
        DNSHTTPS.check_response(404, DNSHTTPS.MEDIA_TYPE, example)
