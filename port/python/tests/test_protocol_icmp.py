"""Tests of umilib.protocol.icmp, umilib.protocol.icmp.v4 and umilib.protocol.icmp.v6: the messages of
the Linux kernel and radvd with their checksums computed independently, the rules of error messages
of RFC 1122 §3.2.2 and RFC 4443 §2.4, the extensions of RFC 4884, the token bucket of RFC 4443 §2.4 (f),
the validity checks of Neighbor Discovery (RFC 4861) and the Neighbor Cache of RFC 4861 Appendix C."""

import dataclasses
import datetime

import pytest
from test_protocol_ip import reference_checksum
from vectors import ROOT

from umilib.protocol.icmp import ICMPError, ICMPExtensionObject, ICMPExtensions, ICMPRateLimitConfig, ICMPRateLimiter
from umilib.protocol.icmp.v4 import ICMPv4Code, ICMPv4Message, ICMPv4Type
from umilib.protocol.icmp.v6 import (
    ICMPv6Code,
    ICMPv6Message,
    ICMPv6Type,
    NDPMessage,
    NDPNeighborAdvertisement,
    NDPNeighborSolicitation,
    NDPOption,
    NDPOptionKind,
    NDPOptions,
    NDPPreference,
    NDPPrefixInformation,
    NDPRecursiveDNSServers,
    NDPRedirect,
    NDPRouteInformation,
    NDPRouterAdvertisement,
    NeighborCache,
    NeighborConfig,
    NeighborEvent,
    NeighborReception,
    NeighborResolution,
    NeighborState,
)
from umilib.protocol.ip import IPProtocol, IPv4Address, IPv6Address
from umilib.protocol.ip.v4 import IPv4Header
from umilib.protocol.ip.v6 import IPv6Error, IPv6ExtensionHeaders, IPv6Header

LINK = bytes([2, 0, 0, 0, 0, 2])
OTHER = bytes([2, 0, 0, 0, 0, 3])
MILLISECOND = 1_000_000


def address(text):
    return IPv6Address.parse(text)


def frames():
    """The frames of the ICMP capture: (description, bytes)."""
    entries, description = [], []
    for line in (ROOT / "protocol/icmp/linux.txt").read_text().splitlines():
        if line.startswith("# "):
            description.append(line[2:])
        elif line.strip():
            entries.append(("\n".join(description), bytes.fromhex(line)))
            description = []
    return entries


def packets(ether_type):
    found = []
    for description, frame in frames():
        offset = 12
        while int.from_bytes(frame[offset : offset + 2], "big") in (0x8100, 0x88A8):
            offset += 4
        if int.from_bytes(frame[offset : offset + 2], "big") == ether_type:
            found.append((description, frame[offset + 2 :]))
    return found


def messages_v4():
    found = []
    for description, packet in packets(0x0800):
        header, payload = IPv4Header.decode(packet)
        if header.protocol == IPProtocol.ICMP and not header.more_fragments and header.fragment_offset == 0:
            found.append((description, header, payload))
    return found


def messages_v6():
    found = []
    for description, packet in packets(0x86DD):
        header, payload = IPv6Header.decode(packet)
        try:
            extensions = list(IPv6ExtensionHeaders(header.next_header, payload))
            protocol, offset = IPv6ExtensionHeaders.upper_layer(header.next_header, payload)
        except IPv6Error:
            continue  # the packets Linux answers with a Parameter Problem
        if any(extension.kind == IPProtocol.IPV6_FRAGMENT for extension in extensions):
            continue  # a fragment holds a part of a message, whose checksum cannot be checked alone
        if protocol == IPProtocol.ICMPV6:
            found.append((description, header, payload[offset:]))
    return found


def checksum_v6(source, destination, message):
    """The checksum of RFC 4443 §2.3 computed independently: the pseudo-header of RFC 8200 §8.1."""
    pseudo = bytes(source) + bytes(destination) + len(message).to_bytes(4, "big") + bytes([0, 0, 0, 58])
    return reference_checksum(pseudo + message[:2] + b"\0\0" + message[4:])


def ndp_header(source, destination, length):
    return dataclasses.replace(IPv6Header.new(address(source), address(destination), IPProtocol.ICMPV6, length), hop_limit=NDPMessage.HOP_LIMIT)


def test_linux_icmpv4_messages():
    messages = messages_v4()
    assert len(messages) >= 12
    for description, _, data in messages:
        assert int.from_bytes(data[2:4], "big") == reference_checksum(data[:2] + b"\0\0" + data[4:]), description
        message = ICMPv4Message.decode(data)
        assert message.encode() == data, description
        first = description.splitlines()[1] if "\n" in description else description
        if ", id " in first:
            identifier, sequence = first.split(", id ")[1].split(", seq ")
            assert (message.identifier(), message.sequence()) == (int(identifier), int(sequence.split(",")[0]))
    find = lambda text: next(ICMPv4Message.decode(data) for description, _, data in messages if text in description)
    # RFC 1191 §4 and RFC 792.
    assert find("need to frag (mtu 576)").next_hop_mtu() == 576
    assert find("redirect 203.0.113.3 to host 192.0.2.3").gateway() == IPv4Address.parse("192.0.2.3")
    # RFC 792: the reply has the identifier, sequence number and data of the request.
    checked = 0
    for _, header, data in messages:
        request = ICMPv4Message.decode(data)
        reply = request.echo_reply()
        for _, other, answer in messages:
            if reply and other.source == header.destination and ICMPv4Message.decode(answer).kind == ICMPv4Type.ECHO_REPLY:
                if ICMPv4Message.decode(answer).echo_reply() is None and ICMPv4Message.decode(answer).query() == request.query():
                    assert reply.encode() == answer
                    checked += 1
                    break
    assert checked >= 3


def test_linux_icmpv4_errors_quote_their_datagram():
    checked = 0
    for description, _, data in messages_v4():
        message = ICMPv4Message.decode(data)
        if not message.kind.is_error():
            continue
        invoking, quoted = message.invoking()
        assert len(quoted) >= ICMPv4Message.MINIMUM_QUOTE, description
        assert f"id {invoking.identification}" in description.splitlines()[2]
        original, extensions = message.original()
        if "Multi-Part extension v2" in description:
            assert len(original) == message.rest[1] * 4 and len(original) >= 128
            objects = list(extensions)
            assert objects[0].class_ == ICMPExtensionObject.INTERFACE_INFORMATION
        else:
            assert extensions is None
        checked += 1
    assert checked >= 6


def test_icmpv4_fields_and_checks():
    data = ICMPv4Message.echo_request(0x1234, 1, b"data").encode()
    assert data[:2] == bytes([8, 0]) and reference_checksum(data) == 0
    with pytest.raises(ICMPError) as error:
        ICMPv4Message.decode(data[:7])
    assert error.value.name == "Length"
    with pytest.raises(ICMPError) as error:
        ICMPv4Message.decode(data[:9] + bytes([data[9] ^ 1]) + data[10:])
    assert error.value.name == "Checksum"
    reply = ICMPv4Message(ICMPv4Type.TIMESTAMP_REPLY, 0, bytes([0, 7, 0, 9]), bytes([0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]))
    assert reply.timestamps() == (1, 2, 3) and (reply.identifier(), reply.sequence()) == (7, 9)
    assert ICMPv4Message(ICMPv4Type.PARAMETER_PROBLEM, 0, bytes([12, 0, 0, 0])).pointer() == 12
    echo = ICMPv4Message.echo_request(1, 2)
    assert (echo.next_hop_mtu(), echo.gateway(), echo.pointer(), echo.echo_reply().echo_reply()) == (None, None, None, None)
    # RFC 1122 §3.2.2 and RFC 6918.
    assert all(ICMPv4Type(kind).is_error() for kind in (3, 4, 5, 11, 12))
    assert not any(ICMPv4Type(kind).is_error() for kind in (0, 8, 9, 10, 13, 14, 42, 43))
    assert ICMPv4Type.SOURCE_QUENCH.is_deprecated() and not ICMPv4Type.ECHO_REQUEST.is_deprecated()
    assert ICMPv4Type.TIME_EXCEEDED.is_extensible() and not ICMPv4Type.REDIRECT.is_extensible()
    assert ICMPv4Code.FRAGMENTATION_NEEDED == 4


def test_icmpv4_errors_are_not_sent_about_everything():
    # RFC 1122 §3.2.2.
    udp = bytes(8)
    datagram = lambda source, destination, protocol, payload: IPv4Header.new(IPv4Address(bytes(source)), IPv4Address(bytes(destination)), protocol, len(payload))
    unicast = datagram([192, 0, 2, 1], [192, 0, 2, 2], IPProtocol.UDP, udp)
    assert ICMPv4Message.may_report(unicast, udp, False) and not ICMPv4Message.may_report(unicast, udp, True)
    error, echo = bytes([3, 3]) + bytes(6), bytes([8]) + bytes(7)
    assert not ICMPv4Message.may_report(datagram([192, 0, 2, 1], [192, 0, 2, 2], IPProtocol.ICMP, error), error, False)
    assert ICMPv4Message.may_report(datagram([192, 0, 2, 1], [192, 0, 2, 2], IPProtocol.ICMP, echo), echo, False)
    for destination in ([255, 255, 255, 255], [224, 0, 0, 1]):
        assert not ICMPv4Message.may_report(datagram([192, 0, 2, 1], destination, IPProtocol.UDP, udp), udp, False)
    for source in ([0, 0, 0, 0], [127, 0, 0, 1], [224, 0, 0, 1], [240, 0, 0, 1]):
        assert not ICMPv4Message.may_report(datagram(source, [192, 0, 2, 2], IPProtocol.UDP, udp), udp, False)
    assert not ICMPv4Message.may_report(dataclasses.replace(unicast, fragment_offset=1), udp, False)
    assert ICMPv4Message.may_report(dataclasses.replace(unicast, more_fragments=True), udp, False)
    # RFC 1812 §4.3.2.3.
    assert len(ICMPv4Message.quote(bytes(1500), 20)) == 576 - 20 - 8
    assert len(ICMPv4Message.quote(bytes(100), 20)) == 100


def test_extensions():
    # RFC 4884 §7 and §8.
    objects = ICMPExtensionObject(ICMPExtensionObject.INTERFACE_INFORMATION, 0x0B, bytes([1, 2, 3, 4])).encode()
    assert objects == bytes([0, 8, 2, 0x0B, 1, 2, 3, 4])
    data = ICMPExtensions(0, objects).encode()
    assert data[0] == 0x20 and reference_checksum(data) == 0
    assert list(ICMPExtensions.decode(data)) == [ICMPExtensionObject(2, 0x0B, bytes([1, 2, 3, 4]))]
    assert ICMPExtensions.decode(data[:2] + b"\0\0" + data[4:]).objects == objects
    for changed, name in ((data[:7] + bytes([data[7] ^ 1]), "Checksum"), (bytes([0x10]) + data[1:], "Version")):
        with pytest.raises(ICMPError) as error:
            ICMPExtensions.decode(changed)
        assert error.value.name == name
    with pytest.raises(ICMPError) as error:
        ICMPExtensionObject(1, 1, bytes(3)).encode()
    assert error.value.name == "Length"
    # RFC 4884 §4: padded to the word and to 128 bytes, the length in words.
    extensions = ICMPExtensions(0, objects)
    for original, word, expected in ((20, 4, 32), (130, 4, 33), (128, 8, 16), (200, 8, 25)):
        datagram = bytes(index % 256 for index in range(original))
        attribute, body = extensions.encode_body(datagram, word)
        assert attribute == expected
        quoted, found = ICMPExtensions.split_body(body, attribute, word)
        assert quoted[:original] == datagram and not any(quoted[original:]) and len(quoted) == attribute * word
        assert found.objects == objects
    assert ICMPExtensions.split_body(bytes([1, 2, 3]), 0, 4) == (bytes([1, 2, 3]), None)


def test_rate_limiter_is_a_token_bucket():
    # RFC 4443 §2.4 (f): the example of B = 10 and N = 10 a second.
    config = ICMPRateLimitConfig()
    assert (config.burst, config.interval) == (10, datetime.timedelta(milliseconds=100))
    limiter = ICMPRateLimiter(config, 1000)
    assert sum(limiter.allow(1000) for _ in range(15)) == 10
    assert not limiter.allow(1000 + 99 * MILLISECOND) and limiter.allow(1000 + 100 * MILLISECOND)
    idle = ICMPRateLimiter(config, 0)
    assert sum(idle.allow(10**15) for _ in range(30)) == 10
    assert not ICMPRateLimiter(ICMPRateLimitConfig(burst=0), 0).allow(10**15)


def test_linux_icmpv6_messages():
    messages = messages_v6()
    assert len(messages) >= 30
    for description, header, data in messages:
        assert int.from_bytes(data[2:4], "big") == checksum_v6(header.source, header.destination, data), description
        message = ICMPv6Message.decode(data, header.source, header.destination)
        assert message.encode(header.source, header.destination) == data, description
        with pytest.raises(ICMPError) as error:
            ICMPv6Message.decode(data, header.source, IPv6Address.LOOPBACK)
        assert error.value.name == "Checksum"
    checked = 0
    for _, header, data in messages:
        request = ICMPv6Message.decode(data, header.source, header.destination)
        reply = request.echo_reply()
        for _, other, answer in messages:
            if reply and (other.source, other.destination) == (header.destination, header.source):
                answered = ICMPv6Message.decode(answer, other.source, other.destination)
                if answered.kind == ICMPv6Type.ECHO_REPLY and answered.echo() == request.echo():
                    assert reply.encode(other.source, other.destination) == answer
                    checked += 1
    assert checked >= 2


def test_linux_icmpv6_errors():
    messages = messages_v6()
    find = lambda text: next((header, data) for description, header, data in messages if text in description)
    cases = [
        ("time exceeded in-transit for", ICMPv6Type.TIME_EXCEEDED, ICMPv6Code.HOP_LIMIT_EXCEEDED),
        ("time exceeded in-transit (reassembly)", ICMPv6Type.TIME_EXCEEDED, ICMPv6Code.REASSEMBLY_TIME_EXCEEDED),
        ("packet too big, mtu 1280", ICMPv6Type.PACKET_TOO_BIG, 0),
        ("unreachable port", ICMPv6Type.DESTINATION_UNREACHABLE, ICMPv6Code.PORT_UNREACHABLE),
        ("parameter problem, next header - octet 6", ICMPv6Type.PARAMETER_PROBLEM, ICMPv6Code.UNRECOGNIZED_NEXT_HEADER),
        ("parameter problem, option - octet 42", ICMPv6Type.PARAMETER_PROBLEM, ICMPv6Code.UNRECOGNIZED_OPTION),
    ]
    for text, kind, code in cases:
        header, data = find(text)
        message = ICMPv6Message.decode(data, header.source, header.destination)
        assert (message.kind, message.code) == (kind, code) and message.kind.is_error()
        assert IPv6Header.LENGTH + len(data) <= ICMPv6Message.MAXIMUM_ERROR_LENGTH
        assert message.invoking()[0].source == header.destination
    decoded = lambda text: ICMPv6Message.decode(find(text)[1], find(text)[0].source, find(text)[0].destination)
    assert decoded("packet too big, mtu 1280").mtu() == 1280
    assert decoded("next header - octet 6").pointer() == 6
    assert decoded("option - octet 42").pointer() == 42


def test_icmpv6_errors_are_not_sent_about_everything():
    # RFC 4443 §2.4 (e).
    header = lambda source, destination, next_header: IPv6Header.new(address(source), address(destination), next_header, 8)
    error = lambda kind, code, rest=bytes(4): ICMPv6Message(ICMPv6Type(kind), code, rest)
    udp = bytes(8)
    unreachable = error(ICMPv6Type.DESTINATION_UNREACHABLE, ICMPv6Code.PORT_UNREACHABLE)
    report = ICMPv6Message.may_report
    assert report(header("2001:db8::1", "2001:db8::2", IPProtocol.UDP), udp, False, unreachable)
    for kind in (1, 2, 3, 4, 100, 137):
        assert not report(header("2001:db8::1", "2001:db8::2", IPProtocol.ICMPV6), bytes([kind]) + bytes(7), False, unreachable)
    assert report(header("2001:db8::1", "2001:db8::2", IPProtocol.ICMPV6), bytes([128]) + bytes(7), False, unreachable)
    # A type that cannot be read, as in a fragment other than the first, may be an error.
    fragment = lambda offset: bytes([58, 0]) + (offset << 3).to_bytes(2, "big") + bytes([0, 0, 0, 1, 128]) + bytes(7)
    fragmented = header("2001:db8::1", "2001:db8::2", IPProtocol.IPV6_FRAGMENT)
    assert report(fragmented, fragment(0), False, unreachable) and not report(fragmented, fragment(1), False, unreachable)
    group = header("2001:db8::1", "ff0e::1", IPProtocol.UDP)
    assert not report(group, udp, False, unreachable)
    assert report(group, udp, False, error(ICMPv6Type.PACKET_TOO_BIG, 0, bytes([0, 0, 5, 0])))
    # Only an unrecognized option whose type has its highest two bits 10 (RFC 8200 §4.2).
    options = lambda kind: bytes([17, 0, kind]) + bytes(5)
    destination = header("2001:db8::1", "ff0e::1", IPProtocol.IPV6_DESTINATION_OPTIONS)
    problem = error(ICMPv6Type.PARAMETER_PROBLEM, ICMPv6Code.UNRECOGNIZED_OPTION, (42).to_bytes(4, "big"))
    assert report(destination, options(0x80), True, problem)
    assert not any(report(destination, options(kind), False, problem) for kind in (0x00, 0x40, 0xC0))
    assert not report(group, udp, False, error(ICMPv6Type.PARAMETER_PROBLEM, ICMPv6Code.UNRECOGNIZED_NEXT_HEADER))
    assert not report(header("::", "2001:db8::2", IPProtocol.UDP), udp, False, unreachable)
    assert len(ICMPv6Message.quote(bytes(3000), 0)) == 1280 - 40 - 8
    assert ICMPv6Message.quote_length(3000, 2**64 - 1) == 0
    # RFC 4443 §2.1 and RFC 4884 §4.6.
    assert ICMPv6Type(127).is_error() and not ICMPv6Type(128).is_error()
    assert ICMPv6Type.DESTINATION_UNREACHABLE.is_extensible() and not ICMPv6Type.PACKET_TOO_BIG.is_extensible()


def test_router_advertisement_of_radvd():
    header, data = next((header, data) for description, header, data in messages_v6() if "router advertisement" in description)
    message = ICMPv6Message.decode(data, header.source, header.destination)
    advertisement = NDPRouterAdvertisement.decode(message, header)
    assert (advertisement.current_hop_limit, advertisement.managed_flag, advertisement.other_flag, advertisement.preference) == (64, False, False, 0)
    assert (advertisement.router_lifetime, advertisement.reachable_time, advertisement.retransmission_timer) == (12, 30000, 1000)
    options = {option.kind: option for option in NDPOptions(advertisement.options)}
    prefix = NDPPrefixInformation.decode(options[NDPOptionKind.PREFIX_INFORMATION].data)
    assert (prefix.prefix, prefix.prefix_length, prefix.on_link, prefix.autonomous) == (address("2001:db8:1::"), 64, True, True)
    assert (prefix.valid_lifetime, prefix.preferred_lifetime) == (86400, 14400)
    route = NDPRouteInformation.decode(options[NDPOptionKind.ROUTE_INFORMATION].data)
    assert (route.prefix, route.prefix_length, route.preference, route.lifetime) == (address("2001:db8:2::"), 64, 0, 12)
    servers = NDPRecursiveDNSServers.decode(options[NDPOptionKind.RECURSIVE_DNS_SERVERS].data)
    assert servers.lifetime == 12 and list(servers) == [address("2001:db8:1::53")]
    assert options[NDPOptionKind.MTU].mtu() == 1500
    assert advertisement.source_link_address() == bytes([2, 0, 0, 0, 1, 1])
    assert advertisement.encode(header.source, header.destination) == data
    assert prefix.encode()[2:] == options[NDPOptionKind.PREFIX_INFORMATION].data
    assert route.encode()[2:] == options[NDPOptionKind.ROUTE_INFORMATION].data
    assert servers.encode()[2:] == options[NDPOptionKind.RECURSIVE_DNS_SERVERS].data


def test_neighbor_discovery_messages_of_linux():
    counts = {kind: 0 for kind in (ICMPv6Type.NEIGHBOR_SOLICITATION, ICMPv6Type.NEIGHBOR_ADVERTISEMENT)}
    for description, header, data in messages_v6():
        message = ICMPv6Message.decode(data, header.source, header.destination)
        if message.kind == ICMPv6Type.NEIGHBOR_SOLICITATION:
            solicitation = NDPNeighborSolicitation.decode(message, header)
            assert str(solicitation.target) == description.split("who has ")[1].split()[0]
            if header.source.is_unspecified():
                assert NDPNeighborSolicitation.is_duplicate_address_detection(header)
                assert header.destination == solicitation.target.solicited_node()
                assert NDPMessage.is_solicited_node(header.destination)
                assert solicitation.source_link_address() is None
            assert solicitation.encode(header.source, header.destination) == data
        elif message.kind == ICMPv6Type.NEIGHBOR_ADVERTISEMENT:
            advertisement = NDPNeighborAdvertisement.decode(message, header)
            assert str(advertisement.target) == description.split("tgt is ")[1].replace(",", " ").split()[0]
            assert advertisement.solicited_flag == ("solicited" in description)
            assert advertisement.override_flag == ("override" in description)
            assert advertisement.encode(header.source, header.destination) == data
        else:
            continue
        counts[message.kind] += 1
    assert all(count >= 2 for count in counts.values())


def test_neighbor_discovery_validity_checks():
    # RFC 4861 §7.1.1 and §7.1.2.
    slla = NDPOption.encode(NDPOptionKind.SOURCE_LINK_ADDRESS, bytes([2, 0, 0, 0, 0, 1]))
    assert slla == bytes([1, 1, 2, 0, 0, 0, 0, 1])

    def solicitation(target, options, source, destination, hop_limit=255):
        data = NDPNeighborSolicitation(address(target), options).encode(address(source), address(destination))
        header = dataclasses.replace(ndp_header(source, destination, len(data)), hop_limit=hop_limit)
        return NDPNeighborSolicitation.decode(ICMPv6Message.decode(data, header.source, header.destination), header)

    def invalid(function, *arguments, **options):
        with pytest.raises(ICMPError) as error:
            function(*arguments, **options)
        assert error.value.name == "Invalid"

    assert solicitation("fe80::2", slla, "fe80::1", "ff02::1:ff00:2").target == address("fe80::2")
    invalid(solicitation, "fe80::2", slla, "fe80::1", "ff02::1:ff00:2", hop_limit=254)
    invalid(solicitation, "ff02::1", b"", "fe80::1", "ff02::1:ff00:1")
    invalid(solicitation, "fe80::2", bytes([1]) + bytes(7), "fe80::1", "ff02::1:ff00:2")
    assert solicitation("fe80::2", b"", "::", "ff02::1:ff00:2").target == address("fe80::2")
    invalid(solicitation, "fe80::2", b"", "::", "fe80::2")
    invalid(solicitation, "fe80::2", slla, "::", "ff02::1:ff00:2")
    invalid(NDPNeighborSolicitation.decode, ICMPv6Message.echo_request(1, 1, bytes(16)), ndp_header("fe80::1", "fe80::2", 24))

    def advertisement(destination, **fields):
        values = {"router_flag": False, "solicited_flag": True, "override_flag": True, "target": address("fe80::2")} | fields
        data = NDPNeighborAdvertisement(**values).encode(address("fe80::2"), address(destination))
        header = ndp_header("fe80::2", destination, len(data))
        return NDPNeighborAdvertisement.decode(ICMPv6Message.decode(data, header.source, header.destination), header)

    assert advertisement("fe80::1").solicited_flag
    invalid(advertisement, "ff02::1")
    assert not advertisement("ff02::1", solicited_flag=False).solicited_flag
    invalid(advertisement, "fe80::1", target=address("ff02::5"))
    # RFC 4861 §6.1.2: from a link-local address.
    router = NDPRouterAdvertisement(64, True, False, NDPPreference.HIGH, 0, 1800, 0, 0)
    for source, valid in (("fe80::1", True), ("2001:db8::1", False)):
        data = router.encode(address(source), address("ff02::1"))
        header = ndp_header(source, "ff02::1", len(data))
        message = ICMPv6Message.decode(data, header.source, header.destination)
        if valid:
            assert NDPRouterAdvertisement.decode(message, header) == router and message.rest[1] == 0x88
        else:
            invalid(NDPRouterAdvertisement.decode, message, header)

    # RFC 4861 §8.1: to a link-local router or to the destination itself.
    def redirect(target, destination):
        data = NDPRedirect(address(target), address(destination)).encode(address("fe80::1"), address("2001:db8::9"))
        header = ndp_header("fe80::1", "2001:db8::9", len(data))
        return NDPRedirect.decode(ICMPv6Message.decode(data, header.source, header.destination), header)

    assert redirect("fe80::3", "2001:db8:3::3").target == address("fe80::3")
    assert redirect("2001:db8:3::3", "2001:db8:3::3").destination == address("2001:db8:3::3")
    invalid(redirect, "2001:db8::7", "2001:db8:3::3")
    invalid(redirect, "fe80::3", "ff0e::1")


def test_options():
    # RFC 4861 §4.6: in units of 8 bytes, the type and length octets included.
    long = NDPOption.encode(200, bytes([9]) * 7)
    assert len(long) == 16 and long[1] == 2 and not any(long[9:])
    both = NDPOption.encode(1, bytes(6)) + long
    assert [len(option.data) for option in NDPOptions(both)] == [6, 14]
    with pytest.raises(ICMPError) as error:
        NDPOptions.check(bytes([1, 2]) + bytes(6))
    assert error.value.name == "Invalid"
    # RFC 4191 §2.3: as many bytes of the prefix as the length needs.
    for length, units in ((0, 1), (48, 2), (64, 2), (96, 3)):
        data = NDPRouteInformation(length, 3, 600, address("2001:db8:aaaa:bbbb:cccc::")).encode()
        assert len(data) == units * 8
        decoded = NDPRouteInformation.decode(data[2:])
        assert decoded.prefix == address("2001:db8:aaaa:bbbb:cccc::").prefix(length) and decoded.preference == 3
    # RFC 8106 §5.1 and RFC 4861 §4.6.2.
    for function, data in ((NDPRecursiveDNSServers.decode, bytes([0, 0, 0, 0, 0, 1])), (NDPPrefixInformation.decode, bytes(29))):
        with pytest.raises(ICMPError) as error:
            function(data)
        assert error.value.name == "Invalid"
    information = NDPPrefixInformation(64, True, False, 0x30, NDPPrefixInformation.INFINITY, 3600, address("2001:db8::"))
    assert NDPPrefixInformation.decode(information.encode()[2:]) == information
    # RFC 4861 §4.6.2: the bits after the prefix length are sent as zero and ignored.
    wide = dataclasses.replace(information, prefix=address("2001:db8::ffff"))
    assert NDPPrefixInformation.decode(wide.encode()[2:]) == information
    for invalid in (dataclasses.replace(information, prefix_length=129), dataclasses.replace(information, valid_lifetime=60)):
        with pytest.raises(ICMPError) as error:
            invalid.encode()
        assert error.value.name == "Invalid"
    # RFC 4191 §2.3: lengths of whole units only, and no reserved preference.
    for length in range(23, 30):
        with pytest.raises(ICMPError):
            NDPRouteInformation.decode(bytes([128]) + bytes(length - 1))
    with pytest.raises(ICMPError):
        NDPRouteInformation.decode(bytes([0, NDPPreference.RESERVED << 3, 0, 0, 0, 0]))
    with pytest.raises(ICMPError):
        NDPRouteInformation(0, NDPPreference.RESERVED, 0, IPv6Address.UNSPECIFIED).encode()


def test_router_advertisement_preference_and_flags():
    # RFC 4191 §2.2: a reserved preference reads as medium, as does any with a router lifetime of 0.
    source, group = address("fe80::1"), address("ff02::1")
    for flags, lifetime, preference in ((0x08, 30, NDPPreference.HIGH), (0x10, 30, NDPPreference.MEDIUM), (0x08, 0, NDPPreference.MEDIUM)):
        message = ICMPv6Message(ICMPv6Type.ROUTER_ADVERTISEMENT, 0, bytes([64, flags, 0, lifetime]), bytes(8))
        assert NDPRouterAdvertisement.decode(message, ndp_header("fe80::1", "ff02::1", 16)).preference == preference
    # The H and P flags are kept (RFC 6275, RFC 4389).
    advertisement = NDPRouterAdvertisement(64, False, False, NDPPreference.LOW, 0x24, 30, 0, 0)
    data = advertisement.encode(source, group)
    assert data[5] == 0x18 | 0x24
    header = ndp_header("fe80::1", "ff02::1", len(data))
    assert NDPRouterAdvertisement.decode(ICMPv6Message.decode(data, source, group), header) == advertisement
    for invalid in (dataclasses.replace(advertisement, preference=NDPPreference.RESERVED), dataclasses.replace(advertisement, router_lifetime=0)):
        with pytest.raises(ICMPError) as error:
            invalid.encode(source, group)
        assert error.value.name == "Invalid"


def test_neighbor_cache_resolution_and_reachability():
    # RFC 4861 §10 and Appendix C.
    config = NeighborConfig()
    assert (config.reachable_time, config.retransmission_timer, config.delay_first_probe_time) == (
        datetime.timedelta(seconds=30),
        datetime.timedelta(seconds=1),
        datetime.timedelta(seconds=5),
    )
    at = lambda milliseconds: 1 + milliseconds * MILLISECOND
    target = address("fe80::2")
    option = NDPOption.encode(NDPOptionKind.TARGET_LINK_ADDRESS, LINK)
    advertisement = lambda solicited, override, options=option, router=False: NDPNeighborAdvertisement(router, solicited, override, target, options)
    with NeighborCache() as cache:
        assert cache.resolve(target, b"\x01", at(0)) == (NeighborResolution.SOLICIT, None)
        assert cache.resolve(target, b"\x02", at(0)) == (NeighborResolution.PENDING, None)
        assert cache.poll(at(999)) is None
        for milliseconds in (1000, 2000):
            event = cache.poll(at(milliseconds))
            assert (event.kind, event.target, event.link) == (NeighborEvent.SOLICIT, target, None)
        event = cache.poll(at(3000))
        assert (event.kind, event.packets) == (NeighborEvent.UNREACHABLE, [b"\x02"])
        assert cache.lookup(target) is None
        cache.resolve(target, b"\x03", at(0))
        assert cache.receive_advertisement(advertisement(True, False), at(10)) == NeighborReception([b"\x03"], False)
        assert cache.resolve(target, None, at(20)) == (NeighborResolution.RESOLVED, LINK)
        assert cache.lookup(target) == (LINK, NeighborState.REACHABLE)
        # §7.3.3: STALE after ReachableTime, DELAY when used, PROBE after DELAY_FIRST_PROBE_TIME.
        assert cache.poll_timeout() == at(10 + 30_000)
        assert cache.poll(at(30_010)) is None and cache.lookup(target)[1] == NeighborState.STALE
        cache.resolve(target, None, at(40_000))
        assert cache.lookup(target)[1] == NeighborState.DELAY
        event = cache.poll(at(45_000))
        assert (event.kind, event.link) == (NeighborEvent.SOLICIT, LINK) and cache.lookup(target)[1] == NeighborState.PROBE
        cache.receive_advertisement(advertisement(True, False, b""), at(45_100))
        assert cache.lookup(target) == (LINK, NeighborState.REACHABLE)
        # §7.2.5: S=0 O=1 with a different address: the new address, STALE.
        different = NDPOption.encode(NDPOptionKind.TARGET_LINK_ADDRESS, OTHER)
        cache.receive_advertisement(advertisement(False, True, different), at(45_200))
        assert cache.lookup(target) == (OTHER, NeighborState.STALE)
        cache.confirm(target, at(45_300))
        assert cache.lookup(target) == (OTHER, NeighborState.REACHABLE)
        assert cache.remove(target) and not cache.remove(target)


def test_neighbor_cache_learning_and_limits():
    at = lambda milliseconds: 1 + milliseconds * MILLISECOND
    with NeighborCache() as cache:
        assert cache.learn(address("fe80::2"), LINK, None, at(0)) == NeighborReception([], False)
        assert cache.lookup(address("fe80::2")) == (LINK, NeighborState.STALE)
        cache.resolve(address("fe80::3"), b"\x07", at(0))
        assert cache.learn(address("fe80::3"), OTHER, True, at(1)).packets == [b"\x07"]
        # RFC 4861 §6.2.6: a Router Solicitation makes the sender a host; §7.2.5: report the change.
        assert cache.learn(address("fe80::3"), None, False, at(2)) == NeighborReception([], True)
        with pytest.raises(ValueError):
            cache.learn(address("fe80::4"), bytes(5), None, at(1))
    with NeighborCache(NeighborConfig(maximum_entries=2, maximum_queued=2)) as cache:
        for index in (1, 2, 3):
            cache.learn(address(f"fe80::{index}"), LINK, None, at(index))
        assert cache.lookup(address("fe80::3")) is None  # learning pushes no entry out
        assert cache.resolve(address("fe80::4"), None, at(4))[0] == NeighborResolution.SOLICIT
        assert cache.lookup(address("fe80::1")) is None and cache.lookup(address("fe80::2")) is not None
        for packet in (b"\x01", b"\x02", b"\x03"):
            cache.resolve(address("fe80::4"), packet, at(5))
        option = NDPOption.encode(NDPOptionKind.TARGET_LINK_ADDRESS, LINK)
        released = cache.receive_advertisement(NDPNeighborAdvertisement(False, True, False, address("fe80::4"), option), at(6))
        assert released.packets == [b"\x02", b"\x03"]
    # RFC 6583 §7.1: unanswered resolutions go first, and their packets are reported (RFC 4861 §7.2.2).
    with NeighborCache(NeighborConfig(maximum_entries=2)) as cache:
        cache.learn(address("fe80::1"), LINK, True, at(0))
        cache.resolve(address("2001:db8::1"), b"\x01", at(1))
        cache.resolve(address("2001:db8::2"), b"\x02", at(2))
        assert cache.lookup(address("fe80::1")) is not None and cache.poll_timeout() == 0
        event = cache.poll(at(2))
        assert (event.kind, event.target, event.packets) == (NeighborEvent.UNREACHABLE, address("2001:db8::1"), [b"\x01"])
    with NeighborCache(NeighborConfig(maximum_entries=0)) as cache:
        with pytest.raises(ICMPError) as error:
            cache.resolve(address("fe80::4"), None, at(0))
        assert error.value.name == "Limit"


def test_malformed_extensions_keep_the_quote():
    # RFC 4884 §9: the extensions are checked, and the quote before them still identifies the flow.
    datagram = IPv4Header.new(IPv4Address.parse("192.0.2.1"), IPv4Address.parse("198.51.100.1"), IPProtocol.UDP, 8)
    body = (datagram.encode() + bytes(8)).ljust(128, b"\0") + bytes([0x20, 0, 0xFF, 0xFF, 0, 8, 2, 1, 9, 9, 9, 9])
    message = ICMPv4Message(ICMPv4Type.TIME_EXCEEDED, 0, bytes([0, 32, 0, 0]), body)
    with pytest.raises(ICMPError) as error:
        message.original()
    assert error.value.name == "Checksum"
    invoking, _ = message.invoking()
    assert (invoking.source, invoking.destination) == (datagram.source, datagram.destination)


def test_structure_checks():
    # RFC 4884 §4, §7, §8.
    assert ICMPExtensions.WORDS == (4, 8) and ICMPExtensionObject.UNIT == 4
    ICMPExtensions.check_word(8)
    ICMPExtensions(0, bytes([0, 8, 2, 1, 9, 9, 9, 9])).check()
    for call, name in ((lambda: ICMPExtensions.check_word(16), "Invalid"), (lambda: ICMPExtensions(0, b"").check(), "Length")):
        with pytest.raises(ICMPError) as error:
            call()
        assert error.value.name == name
    # Bits with a field of their own are refused in `flags`.
    information = NDPPrefixInformation(64, True, True, 0x10, 600, 300, address("2001:db8::"))
    information.check()
    assert NDPPrefixInformation.FLAGS == 0x3F and NDPRouterAdvertisement.FLAGS == 0x27
    for invalid in (dataclasses.replace(information, flags=0x80), dataclasses.replace(information, preferred_lifetime=601)):
        with pytest.raises(ICMPError):
            invalid.check()
    advertisement = NDPRouterAdvertisement(64, False, False, NDPPreference.MEDIUM, 0x80, 30, 0, 0)
    with pytest.raises(ICMPError):
        advertisement.encode(address("fe80::1"), address("ff02::1"))
