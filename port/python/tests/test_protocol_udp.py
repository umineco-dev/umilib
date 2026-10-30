"""Tests of umilib.protocol.udp and the endpoints of umilib.protocol.ip: the datagrams of the Linux
kernel with their checksums computed independently, the zero checksum of RFC 6936 §4, jumbograms
(RFC 2675 §4), endpoints against Python's ipaddress, and the rules that route datagrams."""

import ipaddress

import pytest
from test_protocol_ip import reference_checksum
from vectors import ROOT

from umilib.protocol.ip import IPAddress, IPEndpoint, IPEndpointPattern, IPError, IPv4Address, IPv6Address
from umilib.protocol.udp import UDPConfig, UDPDatagram, UDPError, UDPHeader, UDPRequest, UDPRule


def frames():
    entries, description = [], []
    for line in (ROOT / "protocol/udp/linux.txt").read_text().splitlines():
        if line.startswith("# "):
            description.append(line[2:])
        elif line.strip():
            entries.append(("\n".join(description), bytes.fromhex(line)))
            description = []
    return entries


def datagrams():
    """The unfragmented UDP datagrams of the capture: (description, source, destination, bytes)."""
    found = []
    for description, frame in frames():
        packet = frame[14:]
        if frame[12:14] == b"\x08\x00" and packet[9] == 17 and int.from_bytes(packet[6:8], "big") & 0x3FFF == 0:
            length = (packet[0] & 15) * 4
            found.append((description, IPv4Address(packet[12:16]), IPv4Address(packet[16:20]), packet[length : int.from_bytes(packet[2:4], "big")]))
        elif frame[12:14] == b"\x86\xdd" and packet[6] == 17:
            found.append((description, IPv6Address(packet[8:24]), IPv6Address(packet[24:40]), packet[40 : 40 + int.from_bytes(packet[4:6], "big")]))
    return found


def checksum(source, destination, data):
    """The checksum of RFC 768 computed independently, all ones for zero."""
    if isinstance(source, IPv4Address):
        pseudo = source.octets + destination.octets + bytes([0, 17]) + len(data).to_bytes(2, "big")
    else:
        pseudo = source.octets + destination.octets + len(data).to_bytes(4, "big") + bytes([0, 0, 0, 17])
    return reference_checksum(pseudo + data[:6] + b"\0\0" + data[8:]) or 0xFFFF


def test_linux_datagrams():
    config = UDPConfig(zero_checksum_receive_ports=(7003,))
    seen = datagrams()
    assert len(seen) == 18
    for description, source, destination, data in seen:
        datagram = UDPDatagram.decode(data, source, destination, config)
        header = UDPHeader.decode(data)
        assert header.length == len(data) and datagram.length() == len(data)
        if datagram.checksummed:
            assert header.checksum == checksum(source, destination, data), description
            assert datagram.encode(source, destination) == data
        assert header.to_bytes() == data[:8]
    # The echoes are what `reply` writes.
    requests = [entry for entry in seen if UDPHeader.decode(entry[3]).destination_port in (7001, 7002, 7003)]
    assert len(requests) == 8
    for _, source, destination, data in requests:
        request = UDPDatagram.decode(data, source, destination, config)
        answer = next(entry[3] for entry in seen if entry[1] == destination and UDPHeader.decode(entry[3]).destination_port == request.source_port)
        assert request.reply(request.payload).encode(destination, source) == answer


def test_zero_checksums():
    seen = {UDPHeader.decode(data).source_port: (source, destination, data) for _, source, destination, data in datagrams()}
    # RFC 768: over IPv4, a zero checksum is none.
    source, destination, data = seen[40007]
    datagram = UDPDatagram.decode(data, source, destination)
    assert not datagram.checksummed and datagram.payload == b"no checksum"
    assert datagram.encode(source, destination) == data
    # RFC 6936 §4 (2, 3, 5, 6): over IPv6, only on the ports that allow it.
    source, destination, data = seen[40008]
    with pytest.raises(UDPError) as error:
        UDPDatagram.decode(data, source, destination)
    assert error.value.name == "ZeroChecksum"
    datagram = UDPDatagram.decode(data, source, destination, UDPConfig(zero_checksum_receive_ports=(7003,)))
    with pytest.raises(UDPError) as error:
        datagram.encode(source, destination)
    assert error.value.name == "ZeroChecksum"
    assert datagram.encode(source, destination, UDPConfig(zero_checksum_send_ports=(40008,))) == data


def test_rules_of_rfc_768():
    source, destination = IPv4Address.parse("192.0.2.1"), IPv4Address.parse("192.0.2.2")
    datagram = UDPDatagram(1, 2, True, b"data")
    data = datagram.encode(source, destination)
    assert data[4:6] == bytes([0, 12])
    assert UDPDatagram.decode(data + bytes(5), source, destination) == datagram
    for broken, name in ((data[:7], "Length"), (data[:4] + bytes([0, 7]) + bytes(2) + data[8:], "Length"), (data[:-1] + b"x", "Checksum")):
        with pytest.raises(UDPError) as error:
            UDPDatagram.decode(broken, source, destination)
        assert error.value.name == name
    with pytest.raises(UDPError) as error:
        datagram.encode(source, IPv6Address.parse("2001:db8::2"))
    assert error.value.name == "Family"
    # A computed checksum of zero is sent as all ones.
    for word in range(0x10000):
        candidate = UDPDatagram(1000, 2000, True, word.to_bytes(2, "big"))
        if candidate.header(source, destination).checksum == 0xFFFF:
            break
    assert checksum(source, destination, candidate.encode(source, destination)) == 0xFFFF
    assert UDPDatagram.decode(candidate.encode(source, destination), source, destination).checksummed


def test_jumbograms():
    # RFC 2675 §4: over IPv6, a length above 65,535 is sent as zero.
    source, destination = IPv6Address.parse("2001:db8::1"), IPv6Address.parse("2001:db8::2")
    datagram = UDPDatagram(1, 2, True, bytes(70_000))
    data = datagram.encode(source, destination)
    assert data[4:6] == bytes(2) and UDPHeader.decode(data).checksum == checksum(source, destination, data)
    assert UDPDatagram.decode(data, source, destination) == datagram
    with pytest.raises(UDPError) as error:
        datagram.encode(IPv4Address.parse("192.0.2.1"), IPv4Address.parse("192.0.2.2"))
    assert error.value.name == "Length"


def test_endpoints_and_rules():
    # RFC 3986 §3.2.2, with the text of RFC 5952 (§5 for the IPv4-mapped form).
    for text, written in (("192.0.2.1:53", "192.0.2.1:53"), ("[2001:DB8:0::1]:443", "[2001:db8::1]:443"), ("[::ffff:192.0.2.1]:80", "[::ffff:192.0.2.1]:80")):
        endpoint = IPEndpoint.parse(text)
        host, port = text.rsplit(":", 1)
        assert endpoint.port == int(port) and endpoint.address == IPAddress.parse(host.strip("[]"))
        assert endpoint.address.octets == ipaddress.ip_address(host.strip("[]")).packed
        assert str(endpoint) == written
    assert sorted([IPEndpoint.parse("[::1]:1"), IPEndpoint.parse("192.0.2.1:2"), IPEndpoint.parse("192.0.2.1:1")])[0] == IPEndpoint.parse("192.0.2.1:1")
    for text in ("2001:db8::1:443", "192.0.2.1", "192.0.2.1:65536", "[192.0.2.1]:53"):
        with pytest.raises(IPError):
            IPEndpoint.parse(text)
    pattern = IPEndpointPattern.ports(5000, 5999).with_prefix(IPv4Address.parse("198.51.100.0"), 24)
    assert pattern.matches(IPEndpoint.parse("198.51.100.7:5000"))
    assert pattern.matches(IPEndpoint.parse("[::ffff:198.51.100.7]:5999"))
    assert not pattern.matches(IPEndpoint.parse("198.51.101.7:5000")) and not pattern.matches(IPEndpoint.parse("198.51.100.7:6000"))
    assert IPEndpointPattern.ANY.matches(IPEndpoint.parse("[2001:db8::7]:0"))
    request = UDPRequest(IPEndpoint.parse("[2001:db8::53]:53"), IPEndpoint.parse("[2001:db8:1::9]:40000"))
    rule = UDPRule.new(IPEndpointPattern.port(53).with_address(IPv6Address.parse("2001:db8::53")))
    assert rule.matches(request) and not UDPRule.new(IPEndpointPattern.port(853)).matches(request)
    assert rule.with_remote(IPEndpointPattern.ANY.with_prefix(IPv6Address.parse("2001:db8:1::"), 48)).matches(request)
    assert not rule.with_remote(IPEndpointPattern.ANY.with_prefix(IPv6Address.parse("2001:db8:2::"), 48)).matches(request)


def test_mapped_prefixes_and_ranges():
    # RFC 4291 §2.5.5.2: a prefix of at least 96 bits of IPv4-mapped addresses is an IPv4 prefix.
    mapped = IPv6Address.parse("::ffff:198.51.100.0")
    assert mapped.to_canonical_prefix(120) == (IPv4Address.parse("198.51.100.0"), 24)
    net = IPEndpointPattern.ANY.with_prefix(mapped, 120)
    assert net == IPEndpointPattern.ANY.with_prefix(IPv4Address.parse("198.51.100.7"), 24)
    assert net.matches(IPEndpoint.parse("198.51.100.7:1")) and net.matches(IPEndpoint.parse("[::ffff:198.51.100.7]:1"))
    assert not IPEndpointPattern.ANY.with_prefix(IPv6Address.parse("::"), 0).matches(IPEndpoint.parse("198.51.100.7:1"))
    assert not IPv4Address.parse("192.0.2.1").has_prefix(IPv6Address.parse("::"), 0)
    # Values that do not fit their C fields are refused, not wrapped.
    for call in (
        lambda: UDPDatagram(70000, 53).encode(IPv4Address.parse("192.0.2.1"), IPv4Address.parse("192.0.2.2")),
        lambda: UDPDatagram.decode(bytes(8), IPv6Address.parse("::1"), IPv6Address.parse("::1"), UDPConfig(zero_checksum_receive_ports=(70000,))),
        lambda: IPEndpoint(IPv4Address.parse("192.0.2.1"), 65536).to_structure(),
        lambda: IPEndpointPattern(None, 0, 70000).matches(IPEndpoint.parse("192.0.2.1:1")),
        lambda: IPEndpointPattern((IPv4Address.parse("192.0.2.1"), 256)).to_structure(),
    ):
        with pytest.raises(OverflowError):
            call()


def test_sources_that_name_no_single_host():
    # RFC 1122 §4.1.3.6: none is sent from, nor received from, a broadcast or multicast address.
    datagram = UDPDatagram(1, 2, True, b"x")
    for bad, destination in ((IPv4Address.parse("224.0.0.1"), IPv4Address.parse("192.0.2.2")),
                             (IPv4Address.parse("255.255.255.255"), IPv4Address.parse("192.0.2.2")),
                             (IPv6Address.parse("ff02::1"), IPv6Address.parse("2001:db8::2"))):
        with pytest.raises(UDPError) as error:
            datagram.encode(bad, destination)
        assert error.value.name == "Source"
        with pytest.raises(UDPError) as error:
            UDPDatagram.check_source(bad)
        assert error.value.name == "Source"
    UDPDatagram.check_source(IPv4Address.parse("0.0.0.0"))
    assert UDPDatagram.is_ipv6(IPv6Address.parse("::1"), IPv6Address.parse("::1"))
    with pytest.raises(UDPError) as error:
        UDPDatagram.is_ipv6(IPv4Address.parse("192.0.2.1"), IPv6Address.parse("::1"))
    assert error.value.name == "Family"
