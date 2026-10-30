"""Tests of umilib.protocol.ip, umilib.protocol.ip.v4 and umilib.protocol.ip.v6: the text forms of
RFC 4291 and RFC 5952, the checksum of RFC 1071 and RFC 1624 against an independent computation, and
headers, fragmentation and reassembly against packets of the Linux kernel."""

import datetime
import ipaddress
import random

import pytest
from vectors import ROOT

from umilib.protocol.ip import IPAddress, IPError, IPFragmentBuffer, IPProtocol, IPPseudoHeader, IPv4Address, IPv6Address, InternetChecksum
from umilib.protocol.ip.v4 import IPv4Error, IPv4Fragmenter, IPv4Header, IPv4OptionKind, IPv4Options, IPv4Reassembler, IPv4ReassemblyConfig
from umilib.protocol.ip.v6 import (
    IPv6Error,
    IPv6ExtensionHeaders,
    IPv6FragmentHeader,
    IPv6Fragmenter,
    IPv6Header,
    IPv6Option,
    IPv6OptionKind,
    IPv6OptionsHeader,
    IPv6Reassembler,
    IPv6RoutingHeader,
)


def frames():
    """The frames of the Linux capture: (description, bytes)."""
    entries, description = [], []
    for line in (ROOT / "protocol/ethernet/linux.txt").read_text().splitlines():
        if line.startswith("# "):
            description.append(line[2:])
        elif line.strip():
            entries.append(("\n".join(description), bytes.fromhex(line)))
            description = []
    return entries


def packets(ether_type):
    """The packets of ``ether_type`` in the capture, after the Ethernet header and its tags."""
    found = []
    for description, frame in frames():
        offset = 12
        while int.from_bytes(frame[offset : offset + 2], "big") in (0x8100, 0x88A8):
            offset += 4
        if int.from_bytes(frame[offset : offset + 2], "big") == ether_type:
            found.append((description, frame[offset + 2 :]))
    return found


def reference_checksum(data):
    """The checksum of RFC 1071 computed independently, 16 bits at a time."""
    if len(data) % 2:
        data += b"\0"
    total = sum(int.from_bytes(data[index : index + 2], "big") for index in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def test_checksum_rfc1071_example():
    checksum = InternetChecksum()
    checksum.update(bytes([0x00, 0x01, 0xF2]))
    checksum.update(bytes([0x03, 0xF4, 0xF5, 0xF6, 0xF7]))
    assert checksum.sum16() == 0xDDF2
    assert checksum.finish() == 0xDDF2 ^ 0xFFFF


def test_checksum_matches_an_independent_computation():
    generator = random.Random(1071)
    for length in [0, 1, 2, 3, 7, 64, 1001, 70000]:
        data = bytes(generator.randrange(256) for _ in range(length))
        assert InternetChecksum.checksum(data) == reference_checksum(data)
        split = InternetChecksum()
        for start in range(0, length, 37):
            split.update(data[start : start + 37])
        assert split.finish() == reference_checksum(data)
    assert InternetChecksum.fold(0x1_FFFF) == 0x0001


def test_checksum_rfc1624_example():
    assert InternetChecksum.adjust(0xDD2F, 0x5555, 0x3285) == 0x0000
    data = bytearray(random.Random(1624).randbytes(40))
    before = InternetChecksum.checksum(data)
    old = bytes(data[10:14])
    data[10:14] = b"\x12\x34\x56\x78"
    assert InternetChecksum.adjust_bytes(before, old, bytes(data[10:14])) == reference_checksum(bytes(data))
    assert InternetChecksum.adjust_bytes(before, b"\0\0", b"\0") is None


@pytest.mark.parametrize(
    "text",
    ["2001:db8::1", "::", "::1", "1::", "2001:db8:0:1:1:1:1:1", "2001:0:0:1::1", "2001:db8::1:0:0:1", "fe80::3656:78ff:fe9a:bcde", "::ffff:192.0.2.1"],
)
def test_ipv6_canonical_text_matches_python(text):
    # RFC 5952; Python's ipaddress follows it too.
    address = IPv6Address.parse(text)
    assert str(address) == str(ipaddress.IPv6Address(text))
    assert address.octets == ipaddress.IPv6Address(text).packed


def test_ipv6_forms_and_errors():
    assert IPv6Address.parse("2001:DB8:0:0:8:800:200C:417A") == IPv6Address.parse("2001:db8::8:800:200c:417a")
    assert IPv6Address.parse("::13.1.68.3").to_words()[6:] == [0x0D01, 0x4403]
    for text in ["", ":::", "1::2::3", "12345::", "1:2:3:4:5:6:7:8::", "::1.2.3", "::1%eth0"]:
        with pytest.raises(IPError) as error:
            IPv6Address.parse(text)
        assert error.value.name == "Syntax"


def test_ipv4_text_and_classification():
    address = IPv4Address.parse("192.0.2.1")
    assert str(address) == "192.0.2.1" and address.octets == bytes([192, 0, 2, 1])
    assert address.is_documentation() and not address.is_private()
    assert IPv4Address.parse("172.16.5.4").is_private() and IPv4Address.parse("127.1.2.3").is_loopback()
    assert IPv4Address.BROADCAST.is_broadcast() and IPv4Address.parse("224.0.0.1").is_multicast()
    for text in ["01.2.3.4", "1.2.3", "256.0.0.1", "1.2.3.4 "]:
        with pytest.raises(IPError):
            IPv4Address.parse(text)
    assert address.prefix(24) == IPv4Address.parse("192.0.2.0")
    assert address.has_prefix(IPv4Address.parse("192.0.0.0"), 16)
    assert IPv4Address.mask(20) == 0xFFFFF000
    assert address.to_ipv6_mapped() == IPv6Address.parse("::ffff:192.0.2.1")
    assert IPv6Address.parse("::ffff:192.0.2.1").to_canonical() == address


def test_ipv6_special_addresses():
    assert IPv6Address.parse("4037::01:800:200E:8C6C").solicited_node() == IPv6Address.parse("ff02::1:ff0e:8c6c")
    assert IPv6Address.parse("ff15::1").multicast_scope() == 5 and IPv6Address.LOOPBACK.multicast_scope() is None
    assert IPv6Address.parse("fd00::1").is_unique_local() and IPv6Address.parse("fe80::1").is_link_local()
    assert IPv6Address.parse("3fff::1").is_documentation() and not IPv6Address.parse("3fff:1000::").is_documentation()
    identifier = bytes([0x36, 0x56, 0x78, 0xFF, 0xFE, 0x9A, 0xBC, 0xDE])
    assert str(IPv6Address.link_local(identifier)) == "fe80::3656:78ff:fe9a:bcde"
    assert IPAddress.parse("2001:db8::1").version() == 6 and IPAddress.parse("10.0.0.1").version() == 4
    assert IPAddress.from_octets(bytes(16)) == IPv6Address.UNSPECIFIED
    with pytest.raises(IPError):
        IPAddress.from_octets(bytes(5))


def test_protocols_and_pseudo_headers():
    assert str(IPProtocol.TCP) == "TCP" and str(IPProtocol(200)) == "200" and IPProtocol.ICMPV6 == 58
    source, destination = IPv4Address.parse("192.0.2.1"), IPv4Address.parse("198.51.100.2")
    header = IPPseudoHeader(source, destination, IPProtocol.UDP, 0x1234)
    assert header.to_bytes() == bytes([192, 0, 2, 1, 198, 51, 100, 2, 0, 17, 0x12, 0x34])
    assert header.checksum().sum16() == reference_checksum(header.to_bytes()) ^ 0xFFFF
    v6 = IPPseudoHeader(IPv6Address.parse("2001:db8::1"), IPv6Address.parse("2001:db8::2"), IPProtocol.TCP, 0x01020304)
    assert v6.to_bytes()[32:] == bytes([1, 2, 3, 4, 0, 0, 0, 6])
    with pytest.raises(IPError) as error:
        IPPseudoHeader(source, IPv6Address.LOOPBACK, IPProtocol.UDP, 8)
    assert error.value.name == "Family"


def test_fragment_buffer_refuses_parts_of_fragments():
    # RFC 8200 section 4.5: only an exact duplicate is not an overlap.
    buffer = IPFragmentBuffer()
    assert not buffer.insert(0, b"a" * 16, False, 100)
    assert not buffer.insert(0, b"a" * 16, False, 100)
    with pytest.raises(IPError) as error:
        buffer.insert(8, b"a" * 8, False, 100)
    assert error.value.name == "Overlap"
    assert not buffer.insert(1000, b"", False, 2000) and len(buffer.data) == 16
    assert buffer.memory() >= 16
    assert buffer.check(16, b"b" * 8, False, 100) >= 8 and buffer.check(0, b"a" * 16, False, 100) == 0
    with pytest.raises(IPError):
        buffer.check(4, b"a" * 8, False, 100)


def test_reassembly_abandons_overlapping_datagrams_and_drops_the_oldest():
    source, destination = IPv4Address.parse("192.0.2.1"), IPv4Address.parse("192.0.2.2")
    reassembler = IPv4Reassembler(IPv4ReassemblyConfig(maximum_datagrams=1))
    fragment = IPv4Header.new(source, destination, IPProtocol.UDP, 16)
    fragment.more_fragments = True
    assert reassembler.receive(fragment, bytes(16), 0) is None
    fragment.fragment_offset = 1
    with pytest.raises(IPError) as error:
        reassembler.receive(fragment, bytes(16), 0)
    assert error.value.name == "Overlap"
    fragment.fragment_offset, fragment.more_fragments = 4, False
    with pytest.raises(IPError):
        reassembler.receive(fragment, bytes(8), 0)
    with pytest.raises(IPv4Error) as error:
        reassembler.receive(fragment, bytes(8), 60_000_000_000)
    assert error.value.name == "Expired"
    key, reassembly = reassembler.expire(60_000_000_000)
    assert reassembly.abandoned and reassembly.first()[0] is None
    for identification in (1, 2):
        fragment = IPv4Header.new(source, destination, IPProtocol.UDP, 8)
        fragment.identification, fragment.more_fragments = identification, True
        assert reassembler.receive(fragment, bytes(8), identification) is None
    key, reassembly = reassembler.expire(1 << 62)
    assert key.identification == 2 and reassembler.expire(1 << 62) is None


def test_fields_out_of_range_are_refused():
    header = IPv4Header.new(IPv4Address.parse("192.0.2.1"), IPv4Address.parse("192.0.2.2"), IPProtocol.UDP, 0)
    header.fragment_offset = 70000
    with pytest.raises(OverflowError):
        header.encode()
    with pytest.raises(OverflowError):
        IPv6FragmentHeader(IPProtocol.UDP, 1 << 16, False, 1).encode()


def test_fragment_buffer():
    buffer = IPFragmentBuffer()
    assert not buffer.insert(16, b"c" * 8, True, 100)
    assert buffer.length == 24
    assert not buffer.insert(0, b"a" * 8, False, 100)
    with pytest.raises(IPError) as error:
        buffer.insert(4, b"x" * 8, False, 100)
    assert error.value.name == "Overlap"
    assert buffer.insert(8, b"b" * 8, False, 100)
    assert buffer.data == b"a" * 8 + b"b" * 8 + b"c" * 8
    assert buffer.is_complete() and buffer.received_length() == 24


def test_ipv4_linux_packets_round_trip():
    seen = packets(0x0800)
    assert len(seen) >= 20
    for description, data in seen:
        header, payload = IPv4Header.decode(data)
        assert header.encode() == data[: header.header_length()], description
        assert len(payload) == header.payload_length()


def test_ipv4_record_route_options():
    _, data = next(entry for entry in packets(0x0800) if "options (NOP,RR" in entry[0])
    header, _ = IPv4Header.decode(data)
    options = list(header.options)
    assert [option.kind for option in options] == [IPv4OptionKind.RECORD_ROUTE]
    assert options[0].data[1:5] == bytes([192, 0, 2, 1])
    assert not IPv4OptionKind.RECORD_ROUTE.is_copied() and IPv4OptionKind.LOOSE_SOURCE_ROUTE.is_copied()
    assert IPv4OptionKind.TIMESTAMP.class_() == 2 and IPv4OptionKind.TIMESTAMP.number() == 4


def test_ipv4_fragments_of_linux():
    fragments = [IPv4Header.decode(data) for _, data in packets(0x0800) if "flags [+]" in _ or "offset 2960" in _]
    by_identification = {}
    for header, payload in fragments:
        by_identification.setdefault(header.identification, []).append((header, payload))
    assert len(by_identification) == 2
    for parts in by_identification.values():
        reassembler = IPv4Reassembler()
        result = None
        for header, payload in reversed(parts):
            result = reassembler.receive(header, payload, 0) or result
        whole, data = result
        assert len(data) == 3008 and reference_checksum(data) == 0
        ours = list(IPv4Fragmenter(whole, data, 1500))
        assert [(header.encode(), payload) for header, payload in ours] == [(header.encode(), payload) for header, payload in parts]


def test_ipv4_errors_and_limits():
    header = IPv4Header.new(IPv4Address.parse("192.0.2.1"), IPv4Address.parse("192.0.2.2"), IPProtocol.UDP, 4)
    data = bytearray(header.encode() + b"\1\2\3\4")
    data[8] ^= 1
    with pytest.raises(IPv4Error) as error:
        IPv4Header.decode(bytes(data))
    assert error.value.name == "Checksum"
    header.dont_fragment = True
    with pytest.raises(IPv4Error) as error:
        IPv4Fragmenter(header, bytes(400), 100)
    assert error.value.name == "Fragment"
    options = IPv4Options()
    options.push(IPv4OptionKind.ROUTER_ALERT, b"\0\0")
    assert options.padded_length() == 4 and options.as_bytes() == bytes([148, 4, 0, 0])
    config = IPv4ReassemblyConfig(timeout=datetime.timedelta(seconds=90))
    reassembler = IPv4Reassembler(config)
    fragment = IPv4Header.new(IPv4Address.parse("192.0.2.1"), IPv4Address.parse("192.0.2.2"), IPProtocol.UDP, 8)
    fragment.more_fragments = True
    assert reassembler.receive(fragment, bytes(8), 1000) is None
    assert reassembler.poll_timeout() == 1000 + 90_000_000_000
    assert reassembler.expire(1000) is None
    key, reassembly = reassembler.expire(1000 + 90_000_000_000)
    assert key.identification == 0
    first, received = reassembly.first()
    assert first is not None and first.fragment_offset == 0 and received == bytes(8)


def test_ipv6_linux_packets_and_options():
    seen = packets(0x86DD)
    assert len(seen) >= 20
    for description, data in seen:
        header, payload = IPv6Header.decode(data)
        assert header.encode() == data[:40], description
        assert len(payload) == header.payload_length
    _, data = next(entry for entry in seen if "HBH (rtalert" in entry[0])
    header, payload = IPv6Header.decode(data)
    chain = list(IPv6ExtensionHeaders(header.next_header, payload))
    assert [extension.kind for extension in chain] == [IPProtocol.HOP_BY_HOP_OPTIONS]
    options = list(IPv6OptionsHeader.decode(chain[0].bytes))
    assert options == [IPv6Option(IPv6OptionKind.ROUTER_ALERT, b"\0\0", 2)]
    assert IPv6ExtensionHeaders.upper_layer(header.next_header, payload) == (IPProtocol.ICMPV6, 8)
    assert IPv6OptionKind.JUMBO_PAYLOAD.action() == 3 and not IPv6OptionKind.ROUTER_ALERT.may_change()


def test_ipv6_fragments_of_linux():
    parts = {}
    for _, data in packets(0x86DD):
        header, payload = IPv6Header.decode(data)
        if header.next_header == IPProtocol.IPV6_FRAGMENT:
            parts.setdefault(IPv6FragmentHeader.decode(payload).identification, []).append((header, payload, data))
    assert len(parts) == 2
    for identification, fragments in parts.items():
        reassembler = IPv6Reassembler()
        result = None
        for header, payload, _ in fragments[::-1]:
            result = reassembler.receive(header, payload, 0) or result
        whole, payload = result
        assert whole.next_header == IPProtocol.ICMPV6 and len(payload) == 3008
        pseudo = IPPseudoHeader(whole.source, whole.destination, IPProtocol.ICMPV6, len(payload))
        checksum = pseudo.checksum()
        checksum.update(payload)
        assert checksum.sum16() == 0xFFFF
        assert list(IPv6Fragmenter(whole, payload, identification, 1500)) == [data for _, _, data in fragments]


def test_ipv6_headers_and_errors():
    options = IPv6OptionsHeader(IPProtocol.ICMPV6, IPv6Option.encode(IPv6OptionKind.ROUTER_ALERT, b"\0\0")).encode()
    assert options == bytes([58, 0, 5, 2, 0, 0, 1, 0])
    assert IPv6Option.encode_padding(1) == b"\0" and IPv6Option.encode_padding(3) == b"\1\1\0"
    routing = IPv6RoutingHeader(IPProtocol.UDP, 4, 1, bytes(4) + IPv6Address.parse("2001:db8::99").octets)
    assert IPv6RoutingHeader.decode(routing.encode()) == routing
    fragment = IPv6FragmentHeader(IPProtocol.TCP, 0x1ABC, True, 0xDEADBEEF)
    assert fragment.encode() == bytes([6, 0, 0xD5, 0xE1, 0xDE, 0xAD, 0xBE, 0xEF])
    assert IPv6FragmentHeader.decode(fragment.encode()) == fragment and not fragment.is_atomic()
    with pytest.raises(IPv6Error) as error:
        IPv6Header.decode(bytes([0x40]) + bytes(39))
    assert error.value.name == "Version"
    with pytest.raises(IPv6Error) as error:
        list(IPv6ExtensionHeaders(IPProtocol.IPV6_DESTINATION_OPTIONS, bytes([0, 0, 1, 4, 0, 0, 0, 0, 17, 0, 1, 4, 0, 0, 0, 0])))
    assert error.value.name == "ExtensionHeader"
