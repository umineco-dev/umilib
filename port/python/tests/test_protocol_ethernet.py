"""Tests of umilib.protocol.ethernet and umilib.protocol.arp: frames and ARP packets of the Linux
kernel, the frame check sequence against zlib's CRC-32, and the cache of RFC 826 and RFC 1122."""

import datetime
import zlib

import pytest
from test_protocol_ip import frames

from umilib.protocol.arp import ARPCache, ARPConfig, ARPEvent, ARPOperation, ARPPacket, ARPResolution
from umilib.protocol.ethernet import EtherType, EthernetError, EthernetFrame, EthernetHeader, MACAddress, VLANTag
from umilib.protocol.ip import IPv4Address


def test_linux_frames_round_trip():
    seen = frames()
    assert len(seen) >= 50
    for description, frame in seen:
        header, data = EthernetHeader.decode(frame)
        assert header.encode() == frame[: header.length()], description
        assert str(header.source) == description.split(" > ")[0]
        assert len(data) == len(frame) - header.length()
    tagged = [EthernetHeader.decode(frame)[0] for description, frame in seen if "vlan 200" in description and "vlan 300" in description]
    assert tagged and all([tag.identifier for tag in header.tags] == [200, 300] for header in tagged)
    assert tagged[0].tags[0].protocol == EtherType.SERVICE_VLAN and tagged[0].tags[1].protocol == EtherType.VLAN


def test_mac_addresses():
    address = MACAddress.parse("34-56-78-9A-BC-DE")
    assert str(address) == "34:56:78:9a:bc:de"
    assert address.modified_eui64() == bytes([0x36, 0x56, 0x78, 0xFF, 0xFE, 0x9A, 0xBC, 0xDE])
    assert MACAddress.BROADCAST.is_broadcast() and MACAddress.parse("02:00:00:00:00:01").is_local()
    assert MACAddress.from_ipv4_multicast(bytes([239, 255, 255, 250])) == MACAddress.parse("01:00:5e:7f:ff:fa")
    assert MACAddress.from_ipv6_multicast(bytes(12) + bytes([0xFF, 0, 0, 2])) == MACAddress.parse("33:33:ff:00:00:02")
    with pytest.raises(EthernetError) as error:
        MACAddress.parse("02:00:00:00:00")
    assert error.value.name == "Syntax"


def test_tags_and_types():
    tag = VLANTag.from_control(0x8100, 0xB064)
    assert (tag.priority, tag.drop_eligible, tag.identifier) == (5, True, 100) and tag.control() == 0xB064
    assert VLANTag(EtherType.VLAN, 8, False, 1).control() is None
    assert VLANTag(EtherType.VLAN, 0, False, 4095).control() is None
    with pytest.raises(OverflowError):
        VLANTag(EtherType.VLAN, 0, False, 70000).to_structure()
    with pytest.raises(EthernetError) as error:
        EthernetHeader(MACAddress.BROADCAST, MACAddress.ZERO, EtherType.VLAN).encode()
    assert error.value.name == "Tag"
    assert EtherType(1500).is_length() and EtherType.IPV6.is_ether_type() and EtherType.SERVICE_VLAN.is_tag()
    header = EthernetHeader(MACAddress.BROADCAST, MACAddress.ZERO, EtherType(1520))
    with pytest.raises(EthernetError) as error:
        header.encode()
    assert error.value.name == "EtherType"


def test_frame_check_sequence_matches_zlib():
    for _, frame in frames()[:10]:
        assert EthernetFrame.fcs(frame) == zlib.crc32(frame).to_bytes(4, "little")
        assert EthernetFrame.verify(frame + EthernetFrame.fcs(frame))
        assert not EthernetFrame.verify(frame + bytes(4))
    assert EthernetFrame.padding(42) == 18 and EthernetFrame.padding(1514) == 0


def arp_packets():
    return [ARPPacket.decode(EthernetHeader.decode(frame)[1]) for _, frame in frames() if EthernetHeader.decode(frame)[0].ether_type == EtherType.ARP]


def test_linux_arp_requests_are_answered_as_linux_does():
    packets = arp_packets()
    answered = 0
    for index, request in enumerate(packets):
        if request.operation != ARPOperation.REQUEST:
            continue
        reply = next(
            packet
            for packet in packets[index:]
            if packet.operation == ARPOperation.REPLY and packet.sender_protocol == request.target_protocol and packet.target_protocol == request.sender_protocol
        )
        cache = ARPCache()
        reception = cache.receive(request, reply.sender_hardware, [reply.sender_protocol], 0)
        assert reception.reply == reply and reception.reply.encode() == reply.encode()
        assert not reception.conflict
        assert cache.lookup(request.sender_protocol, 0) == request.sender_hardware
        answered += 1
    assert answered >= 5


def test_cache_resolution_and_limits():
    config = ARPConfig(timeout=datetime.timedelta(seconds=30), maximum_queued=2)
    cache = ARPCache(config)
    target = IPv4Address.parse("192.0.2.9")
    assert cache.resolve(target, b"first", 0) == (ARPResolution.REQUEST, None)
    assert cache.resolve(target, b"second", 0) == (ARPResolution.PENDING, None)
    assert cache.resolve(target, b"third", 0) == (ARPResolution.PENDING, None)
    assert cache.poll(999_999_999) is None
    event = cache.poll(1_000_000_000)
    assert (event.kind, event.address) == (ARPEvent.REQUEST, target)
    reply = ARPPacket.ethernet_request(MACAddress.parse("02:00:00:00:00:09"), target, IPv4Address.parse("192.0.2.1"))
    reply = ARPPacket(reply.hardware_type, reply.protocol_type, ARPOperation.REPLY, reply.sender_hardware, reply.sender_protocol, reply.target_hardware, reply.target_protocol)
    reception = cache.receive(reply, MACAddress.parse("02:00:00:00:00:01"), [IPv4Address.parse("192.0.2.1")], 0)
    assert reception.resolved == [b"second", b"third"]
    assert cache.resolve(target, None, 0) == (ARPResolution.RESOLVED, MACAddress.parse("02:00:00:00:00:09"))
    assert cache.lookup(target, 30_000_000_000) is None
    probe = ARPPacket.ethernet_request(MACAddress.parse("02:00:00:00:00:05"), IPv4Address.UNSPECIFIED, IPv4Address.parse("192.0.2.1"))
    assert probe.is_probe() and not probe.is_announcement()
    other = ARPCache(ARPConfig(maximum_requests=1))
    other.resolve(target, b"lost", 0)
    event = other.poll(1_000_000_000)
    assert (event.kind, event.packets) == (ARPEvent.UNREACHABLE, [b"lost"])
    cache.insert_static(IPv4Address.parse("192.0.2.200"), MACAddress.parse("02:00:00:00:00:c8"))
    assert cache.lookup(IPv4Address.parse("192.0.2.200"), 1 << 62) == MACAddress.parse("02:00:00:00:00:c8")
    assert cache.remove(IPv4Address.parse("192.0.2.200")) and not cache.remove(IPv4Address.parse("192.0.2.200"))
