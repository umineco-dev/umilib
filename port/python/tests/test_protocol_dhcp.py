"""Tests of umilib.protocol.dhcp: DUIDs (RFC 9915 §11), the messages and options of DHCPv4 (RFC 2131,
RFC 2132, RFC 3396, RFC 3442) and of DHCPv6 (RFC 9915), and clients and servers exchanging, checked
against the rules of the RFCs with bytes read independently of umilib."""

import dataclasses
import datetime

import pytest

from umilib.crypto.random import HMACDRBG
from umilib.hash.sha.v2 import SHA256
from umilib.protocol.dhcp import DHCPDUID, DHCPError
from umilib.protocol.dhcp.v4 import (
    DHCPv4BindingState,
    DHCPv4Client,
    DHCPv4ClientConfig,
    DHCPv4ClientEventKind,
    DHCPv4ClientState,
    DHCPv4Message,
    DHCPv4MessageType,
    DHCPv4OptionCode,
    DHCPv4Options,
    DHCPv4Route,
    DHCPv4Server,
    DHCPv4ServerConfig,
)
from umilib.protocol.dhcp.v6 import (
    DHCPv6Client,
    DHCPv6ClientConfig,
    DHCPv6ClientEventKind,
    DHCPv6ClientState,
    DHCPv6IA,
    DHCPv6IAAddress,
    DHCPv6IAPrefix,
    DHCPv6Message,
    DHCPv6MessageType,
    DHCPv6OptionCode,
    DHCPv6Options,
    DHCPv6RelayMessage,
    DHCPv6Server,
    DHCPv6ServerConfig,
    DHCPv6StatusCode,
)
from umilib.protocol.ethernet import MACAddress
from umilib.protocol.ip import IPv4Address, IPv6Address

SECOND = 1_000_000_000
HARDWARE = MACAddress(bytes([2, 0, 0, 0, 0, 1]))
SERVER = IPv4Address(bytes([192, 0, 2, 1]))


def random(label: bytes = b"dhcp") -> HMACDRBG:
    return HMACDRBG[SHA256](b"0123456789abcdef0123456789abcdef", b"nonce of 16 byte", label)


def at(seconds: int) -> int:
    return seconds * SECOND


def v4(last: int) -> IPv4Address:
    return IPv4Address(bytes([192, 0, 2, last]))


def v6(last: int) -> IPv6Address:
    return IPv6Address(bytes([0x20, 0x01, 0x0D, 0xB8] + [0] * 11 + [last]))


def option(area: bytes, code: int) -> bytes | None:
    """The data of option ``code`` of an options area, its parts joined (RFC 3396 §7), read independently."""
    found, index = None, 0
    while index < len(area) and area[index] != 255:
        if area[index] == 0:
            index += 1
            continue
        length = area[index + 1]
        if area[index] == code:
            found = (found or b"") + area[index + 2 : index + 2 + length]
        index += 2 + length
    return found


def options_of(message: bytes) -> bytes:
    """The options area of a DHCPv4 message, after its 236 bytes of header and the magic cookie."""
    assert message[236:240] == bytes([99, 130, 83, 99])
    return message[240:]


def v6_options(data: bytes) -> list[tuple[int, bytes]]:
    """The DHCPv6 options of ``data`` (RFC 9915 §21.1), read independently."""
    found, index = [], 0
    while index < len(data):
        length = int.from_bytes(data[index + 2 : index + 4], "big")
        found.append((int.from_bytes(data[index : index + 2], "big"), data[index + 4 : index + 4 + length]))
        index += 4 + length
    return found


def get(options: list[tuple[int, bytes]], code: int) -> bytes | None:
    return next((data for found, data in options if found == code), None)


# DUIDs (RFC 9915 §11)


@pytest.mark.parametrize(
    ("duid", "expected"),
    [
        (DHCPDUID.llt(1, 0x0102_0304, b"\xaa" * 6), bytes([0, 1, 0, 1, 1, 2, 3, 4]) + b"\xaa" * 6),
        (DHCPDUID.en(9, b"\x01\x02\x03"), bytes([0, 2, 0, 0, 0, 9, 1, 2, 3])),
        (DHCPDUID.ll(DHCPDUID.ETHERNET, b"\xbb" * 6), bytes([0, 3, 0, 1]) + b"\xbb" * 6),
        (DHCPDUID.uuid(b"\x07" * 16), bytes([0, 4]) + b"\x07" * 16),
        (DHCPDUID(9, b"\x01"), bytes([0, 9, 1])),
    ],
)
def test_duids_of_each_type(duid, expected):
    # §11.2–§11.4, RFC 6355 §4: the type, then each type's fields.
    assert duid.encode() == expected
    assert DHCPDUID.decode(expected) == duid


@pytest.mark.parametrize("data", [bytes([0, 9]), bytes(131), bytes([0, 1, 0, 1, 0]), bytes([0, 3, 0, 1]), bytes([0, 4, 1, 2])])
def test_duids_of_wrong_lengths(data):
    # §11.1: 2 bytes of type and 1 to 128 of data; each known type has its least length.
    with pytest.raises(DHCPError) as error:
        DHCPDUID.decode(data)
    assert error.value.name == "Malformed"


def test_duid_limits_and_time():
    assert len(DHCPDUID(9, bytes(128)).encode()) == DHCPDUID.MAXIMUM_LENGTH
    # §11.1–§11.4: data of 1 to 128 bytes; DUID-LLT, DUID-EN and DUID-LL end in their variable part.
    empty = (DHCPDUID.llt(1, 0, b""), DHCPDUID.en(9, b""), DHCPDUID.ll(1, b""), DHCPDUID(9))
    for duid in (DHCPDUID(9, bytes(129)), DHCPDUID.uuid(bytes(15)), *empty):
        with pytest.raises(DHCPError):
            duid.encode()
    # §11.2: seconds since 2000-01-01 00:00 UTC, modulo 2^32.
    assert DHCPDUID.time_of(946_684_800 + 5) == 5
    assert DHCPDUID.time_of(946_684_800 + (1 << 32) + 7) == 7


# DHCPv4 messages and options (RFC 2131 §2, RFC 2132, RFC 3396, RFC 3442)


def test_a_message_of_rfc_2131():
    message = DHCPv4Message.request(DHCPv4MessageType.DISCOVER, HARDWARE, 0x1234_5678)
    message.secs, message.flags = 3, DHCPv4Message.BROADCAST
    message.options.set(DHCPv4OptionCode.HOST_NAME, b"\x07" * 300)
    data = message.encode()
    assert data[:12] == bytes([1, 1, 6, 0, 0x12, 0x34, 0x56, 0x78, 0, 3, 0x80, 0])
    assert data[28:34] == HARDWARE.octets
    # RFC 2131 §3: the magic cookie; RFC 3396 §6: an option longer than 255 bytes in parts.
    area = options_of(data)
    assert area[:3] == bytes([53, 1, 1])
    assert area[3:5] == bytes([12, 255]) and area[260:262] == bytes([12, 45])
    assert option(area, 12) == b"\x07" * 300
    read = DHCPv4Message.decode(data)
    assert read == message
    assert read.message_type() == DHCPv4MessageType.DISCOVER and read.is_broadcast()
    assert read.hardware_address() == HARDWARE.octets
    # RFC 1542 §2.1: at least 300 bytes.
    assert len(DHCPv4Message.request(DHCPv4MessageType.DISCOVER, HARDWARE, 1).encode()) == DHCPv4Message.MINIMUM_LENGTH


def test_overload_and_malformed_messages():
    data = DHCPv4Message.request(DHCPv4MessageType.DISCOVER, HARDWARE, 1).encode()
    # RFC 2131 §4.1: overloaded `file` options are read after the options field; the field is then empty.
    overloaded = bytearray(data[:240])
    overloaded[108:115] = bytes([12, 4]) + b"host" + bytes([255])
    overloaded += bytes([53, 1, 1, 52, 1, 1, 255])
    read = DHCPv4Message.decode(bytes(overloaded))
    assert read.file == bytes(128)
    assert read.options.get(DHCPv4OptionCode.HOST_NAME) == b"host"
    assert read.options.get(DHCPv4OptionCode.OVERLOAD) is None
    # Without the magic cookie (BOOTP), cut short, of another op, or with an option cut short.
    for broken in (data[:239], data[:236] + bytes(4) + data[240:], bytes([3]) + data[1:], data[:240] + bytes([12, 20, 1])):
        with pytest.raises(DHCPError) as error:
            DHCPv4Message.decode(broken)
        assert error.value.name == "Malformed"


def test_options_and_client_keys():
    # RFC 2132 §2: PAD is dropped; RFC 3396 §7: the parts of an option are joined.
    options = DHCPv4Options.decode(bytes([0, 0, 3, 4, 192, 0, 2, 1, 0, 3, 4, 192, 0, 2, 2, 255, 9]))
    assert options.addresses(DHCPv4OptionCode.ROUTER) == [v4(1), v4(2)]
    assert options.encode() == bytes([3, 8, 192, 0, 2, 1, 192, 0, 2, 2, 255])
    options.set_time(DHCPv4OptionCode.LEASE_TIME, datetime.timedelta(hours=1))
    options.set_time(DHCPv4OptionCode.RENEWAL_TIME, None)
    assert options.get(DHCPv4OptionCode.LEASE_TIME) == (3600).to_bytes(4, "big")
    assert options.time(DHCPv4OptionCode.RENEWAL_TIME) == DHCPv4Options.INFINITY
    assert options.time(DHCPv4OptionCode.REBINDING_TIME) is None
    # RFC 2132 §9.10: a maximum message size below 576 is not one.
    options.set(DHCPv4OptionCode.MAXIMUM_MESSAGE_SIZE, (575).to_bytes(2, "big"))
    assert options.maximum_message_size() is None
    # RFC 2131 §4.2, RFC 4361 §6.1: a client is known by its client identifier, or by its hardware type and address.
    message = DHCPv4Message.request(DHCPv4MessageType.DISCOVER, HARDWARE, 1)
    assert message.client_key() == bytes([0, 1]) + HARDWARE.octets
    message.options.set(DHCPv4OptionCode.CLIENT_IDENTIFIER, b"\xff\x00\x00\x00\x01" + bytes([0, 3, 0, 1]) + HARDWARE.octets)
    assert message.client_key() == message.options.get(DHCPv4OptionCode.CLIENT_IDENTIFIER)
    # RFC 6842 §3: the reply echoes the client identifier.
    reply = DHCPv4Message.reply(message, DHCPv4MessageType.OFFER)
    assert reply.op == DHCPv4Message.BOOTREPLY and reply.xid == 1
    assert reply.options.get(DHCPv4OptionCode.CLIENT_IDENTIFIER) == message.options.get(DHCPv4OptionCode.CLIENT_IDENTIFIER)


def test_classless_static_routes():
    # RFC 3442 §2: a prefix length, the significant octets of the destination, the router.
    data = bytes([8, 10, 10, 0, 0, 1, 24, 192, 168, 1, 10, 0, 0, 2, 0, 10, 0, 0, 254])
    options = DHCPv4Options()
    options.set(DHCPv4OptionCode.CLASSLESS_STATIC_ROUTE, data)
    routes = options.routes()
    assert routes == [
        DHCPv4Route(IPv4Address(bytes([10, 0, 0, 0])), 8, IPv4Address(bytes([10, 0, 0, 1]))),
        DHCPv4Route(IPv4Address(bytes([192, 168, 1, 0])), 24, IPv4Address(bytes([10, 0, 0, 2]))),
        DHCPv4Route(IPv4Address.UNSPECIFIED, 0, IPv4Address(bytes([10, 0, 0, 254]))),
    ]
    # The bits of a destination beyond its prefix are not sent.
    written = DHCPv4Options()
    written.set_routes([DHCPv4Route(IPv4Address(bytes([10, 1, 2, 3])), 8, IPv4Address(bytes([10, 0, 0, 1]))), *routes[1:]])
    assert written.get(DHCPv4OptionCode.CLASSLESS_STATIC_ROUTE) == data
    for broken in (bytes([33, 1, 2, 3, 4, 5, 10, 0, 0, 1]), bytes([24, 192, 168, 1, 10, 0, 0])):
        options.set(DHCPv4OptionCode.CLASSLESS_STATIC_ROUTE, broken)
        with pytest.raises(DHCPError):
            options.routes()


# DHCPv4 clients and servers (RFC 2131 §3, §4)


def server_config(**changes) -> DHCPv4ServerConfig:
    options = DHCPv4Options()
    options.set_address(DHCPv4OptionCode.SUBNET_MASK, IPv4Address(bytes([255, 255, 255, 0])))
    options.set_addresses(DHCPv4OptionCode.ROUTER, [SERVER])
    values = dict(
        address=SERVER, first=v4(100), last=v4(102), reservations=(), lease=datetime.timedelta(hours=1),
        offer_time=datetime.timedelta(minutes=1), decline_time=datetime.timedelta(minutes=10), options=options, authoritative=True,
    )  # fmt: skip
    values.update(changes)
    return DHCPv4ServerConfig(**values)


def v4_client() -> DHCPv4Client:
    return DHCPv4Client(DHCPv4ClientConfig(HARDWARE, host_name=b"host", parameters=(1, 3, 6)), 0)


def run_v4(client: DHCPv4Client, server: DHCPv4Server, now: int, generator: HMACDRBG) -> None:
    while (transmission := client.transmit()) is not None:
        if (reply := server.receive(transmission.data, now)) is not None:
            client.receive(reply.data, now, generator)


def events(client) -> list:
    out = []
    while (event := client.poll_event()) is not None:
        out.append(event)
    return out


def test_a_lease_from_discover_to_release():
    generator = random(b"test_a_lease_from_discover_to_release")
    server, client = DHCPv4Server(server_config()), v4_client()
    client.start(None, 0, generator)
    assert client.state == DHCPv4ClientState.SELECTING
    # RFC 2131 §4.4.1: DHCPDISCOVER is broadcast, with the options asked for (RFC 2132 §9.8).
    discover = client.transmit()
    assert discover.destination == IPv4Address.BROADCAST
    area = options_of(discover.data)
    assert discover.data[:3] == bytes([1, 1, 6]) and discover.data[12:16] == bytes(4)
    assert (option(area, 53), option(area, 55), option(area, 12)) == (bytes([1]), bytes([1, 3, 6]), b"host")
    # §4.3.1, table 3: the OFFER carries the lease time and the server identifier; unicast to the
    # hardware address of a client that did not ask for broadcast (§4.1).
    offer = server.receive(discover.data, 0)
    assert (offer.destination, offer.port, offer.link) == (v4(100), 68, HARDWARE)
    offered = offer.message
    assert (offered.op, offered.xid, offered.yiaddr) == (2, discover.message.xid, v4(100))
    assert option(options_of(offer.data), 54) == SERVER.octets
    assert option(options_of(offer.data), 51) == (3600).to_bytes(4, "big")
    assert server.binding(v4(100)).state == DHCPv4BindingState.OFFERED
    client.receive(offer.data, 0, generator)
    assert client.state == DHCPv4ClientState.REQUESTING
    # §4.3.2, table 5: the REQUEST of SELECTING, broadcast, of the offer's xid, naming the server and the
    # address, ciaddr zero.
    request = client.transmit()
    assert request.destination == IPv4Address.BROADCAST
    area = options_of(request.data)
    assert request.message.xid == offered.xid and request.message.ciaddr == IPv4Address.UNSPECIFIED
    assert (option(area, 53), option(area, 54), option(area, 50)) == (bytes([3]), SERVER.octets, v4(100).octets)
    ack = server.receive(request.data, at(1))
    assert ack.message.message_type() == DHCPv4MessageType.ACK
    binding = server.binding(v4(100))
    assert (binding.state, binding.expires, binding.client) == (DHCPv4BindingState.BOUND, at(1) + at(3600), bytes([0, 1]) + HARDWARE.octets)
    # The bindings are the caller's to keep: read, given to another server, and the same there.
    restored = DHCPv4Server(server_config())
    for address, kept in server.bindings.items():
        restored.set_binding(address, kept)
    assert restored.bindings == server.bindings == {v4(100): binding}
    restored.remove_binding(v4(100))
    assert restored.bindings == {}
    client.receive(ack.data, at(1), generator)
    # §4.4.1: the lease runs from when the request was sent; §4.4.5: T1 and T2 default to half and seven eighths.
    [event] = events(client)
    assert event.kind == DHCPv4ClientEventKind.BOUND
    lease = event.lease
    assert (lease.address, lease.server, lease.acquired) == (v4(100), SERVER, 0)
    assert (lease.lease, lease.renewal, lease.rebinding) == (
        datetime.timedelta(seconds=3600), datetime.timedelta(seconds=1800), datetime.timedelta(seconds=3150),
    )  # fmt: skip
    assert lease.options.addresses(DHCPv4OptionCode.ROUTER) == [SERVER]
    assert client.lease == lease
    assert (client.state, client.poll_timeout()) == (DHCPv4ClientState.BOUND, lease.at(lease.renewal))
    # §4.4.5: RENEWING at T1, unicast to the server, the address in ciaddr, no server identifier (§4.3.2).
    client.expire(at(1800), generator)
    assert client.state == DHCPv4ClientState.RENEWING
    renew = client.transmit()
    assert (renew.destination, renew.message.ciaddr) == (SERVER, v4(100))
    assert option(options_of(renew.data), 54) is None and option(options_of(renew.data), 50) is None
    reply = server.receive(renew.data, at(1800))
    assert (reply.destination, reply.link) == (v4(100), None)
    client.receive(reply.data, at(1800), generator)
    assert events(client)[0].lease.acquired == at(1800)
    # §4.4.6: DHCPRELEASE to the server, with ciaddr and the server identifier; nothing answers it.
    client.release(at(2000))
    release = client.transmit()
    assert (release.destination, release.message.ciaddr, release.message.message_type()) == (SERVER, v4(100), DHCPv4MessageType.RELEASE)
    assert server.receive(release.data, at(2000)) is None
    assert server.binding(v4(100)).expires == at(2000)
    assert (client.state, client.poll_timeout(), client.lease) == (DHCPv4ClientState.INIT, None, None)
    with pytest.raises(DHCPError) as error:
        client.release(at(2001))
    assert error.value.name == "State"


def test_declines_refusals_and_information():
    generator = random(b"test_declines_refusals_and_information")
    server, client = DHCPv4Server(server_config()), v4_client()
    client.start(None, 0, generator)
    run_v4(client, server, 0, generator)
    assert events(client)[0].lease.address == v4(100)
    # RFC 2131 §4.4.1, table 5: DHCPDECLINE, broadcast, naming the address and the server, without the
    # options asked for; discovery again after ten seconds (§3.1.5).
    client.decline(at(5), generator)
    decline = client.transmit()
    area = options_of(decline.data)
    assert decline.destination == IPv4Address.BROADCAST and decline.message.ciaddr == IPv4Address.UNSPECIFIED
    assert (option(area, 53), option(area, 50), option(area, 54)) == (bytes([4]), v4(100).octets, SERVER.octets)
    assert option(area, 55) is None and option(area, 57) is None
    assert client.poll_timeout() == at(15)
    # §4.3.3: the server marks the address as not available.
    assert server.receive(decline.data, at(5)) is None
    binding = server.binding(v4(100))
    assert (binding.state, binding.client, binding.expires) == (DHCPv4BindingState.DECLINED, b"", at(605))
    client.expire(at(15), generator)
    run_v4(client, server, at(15), generator)
    assert events(client)[0].lease.address == v4(101)
    # §3.2, §4.3.2: INIT-REBOOT asks for the previous address without a server identifier; the authoritative
    # server refuses one not of its network, broadcast (§4.1), and the client discovers again.
    rebooting = v4_client()
    previous = IPv4Address(bytes([198, 51, 100, 7]))
    rebooting.start(previous, at(20), generator)
    assert rebooting.state == DHCPv4ClientState.REBOOTING
    request = rebooting.transmit()
    assert option(options_of(request.data), 54) is None and option(options_of(request.data), 50) == previous.octets
    nak = server.receive(request.data, at(20))
    assert (nak.destination, nak.link, nak.message.message_type()) == (IPv4Address.BROADCAST, None, DHCPv4MessageType.NAK)
    assert option(options_of(nak.data), 51) is None
    rebooting.receive(nak.data, at(20), generator)
    assert [event.kind for event in events(rebooting)] == [DHCPv4ClientEventKind.REFUSED]
    assert rebooting.state == DHCPv4ClientState.SELECTING
    # §3.4, §4.3.5: DHCPINFORM of a configured address in ciaddr; the ACK goes to it, without a lease time.
    # The client, discovering again, informs under an xid of its own, and its exchange goes on.
    inform = rebooting.inform(v4(50), at(21), generator)
    assert rebooting.state == DHCPv4ClientState.SELECTING
    discover = rebooting.transmit()
    assert discover.message.message_type() == DHCPv4MessageType.DISCOVER and discover.message.xid != inform.message.xid
    assert (inform.message.ciaddr, inform.message.message_type()) == (v4(50), DHCPv4MessageType.INFORM)
    assert option(options_of(inform.data), 50) is None
    ack = server.receive(inform.data, at(21))
    assert (ack.destination, ack.port, ack.link) == (v4(50), 68, None)
    assert ack.message.yiaddr == IPv4Address.UNSPECIFIED and option(options_of(ack.data), 51) is None
    assert ack.message.options.addresses(DHCPv4OptionCode.ROUTER) == [SERVER]


def test_retransmissions_reservations_and_errors():
    generator = random(b"test_retransmissions_reservations_and_errors")
    # RFC 2131 §4.1: the first retransmission after 4 s, randomized by up to a second; §2: secs counts
    # the seconds since the client began.
    client = v4_client()
    client.start(None, 0, generator)
    first = client.transmit()
    timeout = client.poll_timeout()
    assert at(3) <= timeout <= at(5)
    client.expire(timeout, generator)
    second = client.transmit()
    assert (first.message.secs, second.message.secs) == (0, timeout // SECOND)
    # A reservation by client key; a relayed request answered to the relay's port 67 (§4.1).
    server = DHCPv4Server(server_config(reservations=((bytes([0, 1]) + HARDWARE.octets, v4(150)),)))
    relay = IPv4Address(bytes([198, 51, 100, 1]))
    discover = DHCPv4Message.request(DHCPv4MessageType.DISCOVER, HARDWARE, 9)
    discover.giaddr = relay
    offer = server.receive(discover.encode(), 0)
    assert (offer.destination, offer.port, offer.message.yiaddr) == (relay, 67, v4(150))
    # A BOOTREPLY is not answered.
    assert server.receive(offer.data, 0) is None
    with pytest.raises(DHCPError) as error:
        DHCPv4Server(server_config(first=v4(102), last=v4(100)))
    assert error.value.name == "Config"
    # The configuration of a server of a pool, which offers from it.
    config = DHCPv4ServerConfig.new(SERVER, v4(100), v4(102))
    assert (config.address, config.first, config.last, config.reservations) == (SERVER, v4(100), v4(102), ())
    assert config.offer_time > datetime.timedelta(0) and config.decline_time > datetime.timedelta(0)
    assert config.lease is None or config.lease > datetime.timedelta(0)
    offer = DHCPv4Server(config).receive(DHCPv4Message.request(DHCPv4MessageType.DISCOVER, HARDWARE, 3).encode(), 0)
    assert offer.message.yiaddr == v4(100)
    with pytest.raises(OverflowError):
        DHCPv4Client(DHCPv4ClientConfig(HARDWARE, maximum_message_size=1 << 16), 0)


# DHCPv6 (RFC 9915)


def duid(last: int) -> DHCPDUID:
    return DHCPDUID.ll(DHCPDUID.ETHERNET, bytes([2, 0, 0, 0, 0, last]))


PREFIX = IPv6Address(bytes([0x20, 0x01, 0x0D, 0xB8, 0x10] + [0] * 11))


def v6_server(**changes) -> DHCPv6Server:
    options = DHCPv6Options()
    options.push(DHCPv6OptionCode.DNS_SERVERS, v6(53).octets)
    values = dict(
        addresses=(v6(100), v6(101)), prefixes=(PREFIX, 48, 56), preferred=3000, valid=4000, t1=1000, t2=1600,
        preference=0, rapid_commit=False, options=options,
    )  # fmt: skip
    values.update(changes)
    return DHCPv6Server(dataclasses.replace(DHCPv6ServerConfig.new(duid(0x53)), **values))


def test_messages_of_rfc_9915():
    # §8: the type, 24 bits of transaction ID, then the options (§21.1).
    message = DHCPv6Message.new(DHCPv6MessageType.SOLICIT, 0x12_3456)
    message.options.push(DHCPv6OptionCode.CLIENT_ID, duid(1).encode())
    message.options.push(DHCPv6OptionCode.ELAPSED_TIME, bytes(2))
    data = message.encode()
    assert data[:8] == bytes([1, 0x12, 0x34, 0x56, 0, 1, 0, 10])
    assert DHCPv6Message.decode(data) == message
    assert DHCPv6Message.decode(data).options.duid(DHCPv6OptionCode.CLIENT_ID) == duid(1)
    for broken in (data[:3], data[:-1]):
        with pytest.raises(DHCPError):
            DHCPv6Message.decode(broken)
    for wrong in (DHCPv6Message(DHCPv6MessageType.SOLICIT, 1 << 24), DHCPv6Message(DHCPv6MessageType.RELAY_FORW, 0)):
        with pytest.raises(DHCPError) as error:
            wrong.encode()
        assert error.value.name == "Malformed"
    # §9: relay messages, their hop count and addresses, and the relayed message (§21.10).
    relay = DHCPv6RelayMessage(DHCPv6MessageType.RELAY_FORW, 1, v6(1), v6(2))
    relay.options.push(DHCPv6OptionCode.RELAY_MSG, data)
    encoded = relay.encode()
    assert encoded[:2] == bytes([12, 1]) and encoded[2:18] == v6(1).octets and encoded[18:34] == v6(2).octets
    assert len(encoded) == 34 + 4 + len(data)
    assert DHCPv6RelayMessage.decode(encoded).relayed() == data
    with pytest.raises(DHCPError):
        DHCPv6Message.decode(encoded)
    with pytest.raises(DHCPError):
        DHCPv6RelayMessage.decode(data)


def test_ias_and_status_codes():
    # §21.4, §21.6: an IA_NA, its T1 and T2, and its address of two lifetimes; §21.13: a status.
    ia = DHCPv6IA.new(DHCPv6OptionCode.IA_NA, 7)
    ia.t1, ia.t2 = 100, 200
    held = DHCPv6IAAddress(v6(9), 300, 400)
    assert held.encode() == v6(9).octets + (300).to_bytes(4, "big") + (400).to_bytes(4, "big")
    ia.options.push(DHCPv6OptionCode.IAADDR, held.encode())
    ia.options.push(DHCPv6OptionCode.STATUS_CODE, DHCPv6StatusCode.new(DHCPv6StatusCode.SUCCESS, "ok").encode())
    option = ia.encode()
    assert option.code == DHCPv6OptionCode.IA_NA and option.data[:12] == bytes([0, 0, 0, 7, 0, 0, 0, 100, 0, 0, 0, 200])
    read = DHCPv6IA.decode(DHCPv6OptionCode.IA_NA, option.data)
    assert read == ia
    assert (read.addresses(), read.options.status(), read.lifetimes()) == ([held], DHCPv6StatusCode(0, "ok"), [(300, 400)])
    with pytest.raises(DHCPError):
        DHCPv6IA.decode(DHCPv6OptionCode.IA_NA, bytes(11))
    # §21.22: an IA Prefix of at most 128 bits.
    prefix = DHCPv6IAPrefix(1, 2, 56, PREFIX)
    assert prefix.encode() == bytes([0, 0, 0, 1, 0, 0, 0, 2, 56]) + PREFIX.octets
    assert DHCPv6IAPrefix.decode(prefix.encode()) == prefix
    with pytest.raises(DHCPError):
        DHCPv6IAPrefix.decode(bytes(8) + bytes([129]) + bytes(16))
    with pytest.raises(DHCPError):
        DHCPv6IAPrefix(1, 2, 129, PREFIX).encode()
    assert DHCPv6StatusCode.decode(bytes([0, 2]) + b"none") == DHCPv6StatusCode(DHCPv6StatusCode.NO_ADDRS_AVAIL, "none")
    with pytest.raises(DHCPError):
        DHCPv6StatusCode.decode(bytes([0]))


def test_addresses_and_a_prefix_from_solicit_to_release():
    generator = random(b"test_addresses_and_a_prefix_from_solicit_to_release")
    server = v6_server()
    client = DHCPv6Client(DHCPv6ClientConfig(duid(1), 1, prefix=True, prefix_length=56), 0)
    client.start(0, generator)
    # §18.2.1: the first Solicit after a random delay of up to a second.
    assert client.transmit() is None
    delay = client.poll_timeout()
    assert delay <= at(1)
    client.expire(delay, generator)
    solicit = client.transmit()
    options = v6_options(solicit[4:])
    assert solicit[0] == DHCPv6MessageType.SOLICIT
    # §16, §18.2.1: the client's DUID and no server's; the elapsed time, 0 at first (§21.9); an IA_NA
    # of T1 and T2 0, and an IA_PD with the prefix length as a hint.
    assert get(options, DHCPv6OptionCode.CLIENT_ID) == duid(1).encode()
    assert get(options, DHCPv6OptionCode.SERVER_ID) is None
    assert get(options, DHCPv6OptionCode.ELAPSED_TIME) == bytes(2)
    assert get(options, DHCPv6OptionCode.IA_NA) == bytes([0, 0, 0, 1]) + bytes(8)
    assert DHCPv6IA.decode(DHCPv6OptionCode.IA_PD, get(options, DHCPv6OptionCode.IA_PD)).prefixes()[0].length == 56
    # §18.3.1: an Advertise of the same transaction with both DUIDs; §18.2.9: below preference 255, the
    # client waits out the first timeout.
    advertise = server.receive(solicit, delay)
    assert advertise[0] == DHCPv6MessageType.ADVERTISE and advertise[1:4] == solicit[1:4]
    assert get(v6_options(advertise[4:]), DHCPv6OptionCode.SERVER_ID) == duid(0x53).encode()
    client.receive(advertise, delay, generator)
    assert client.state == DHCPv6ClientState.SOLICITING
    first = client.poll_timeout()
    client.expire(first, generator)
    assert client.state == DHCPv6ClientState.REQUESTING
    # §18.2.2: a Request of a new transaction to the server chosen.
    request = DHCPv6Message.decode(client.transmit())
    assert request.kind == DHCPv6MessageType.REQUEST and request.transaction != int.from_bytes(solicit[1:4], "big")
    assert request.options.duid(DHCPv6OptionCode.SERVER_ID) == duid(0x53)
    client.receive(server.receive(request.encode(), first), first, generator)
    # §18.2.10.1: bound; T1 and T2 of the IAs, the valid lifetime, from the exchange's start.
    [event] = events(client)
    lease = event.lease
    assert event.kind == DHCPv6ClientEventKind.BOUND and lease.server == duid(0x53)
    assert (lease.acquired, lease.renewal, lease.rebinding, lease.valid) == (
        first, datetime.timedelta(seconds=1000), datetime.timedelta(seconds=1600), datetime.timedelta(seconds=4000),
    )  # fmt: skip
    assert lease.addresses() == [DHCPv6IAAddress(v6(100), 3000, 4000)]
    # The bindings are the caller's to keep: an address and a prefix, given back to another server.
    kept = server.bindings
    assert [(binding.address, binding.length, binding.kind) for binding in kept] == [
        (PREFIX, 56, DHCPv6OptionCode.IA_PD), (v6(100), None, DHCPv6OptionCode.IA_NA),
    ] or [(binding.address, binding.length, binding.kind) for binding in kept] == [
        (v6(100), None, DHCPv6OptionCode.IA_NA), (PREFIX, 56, DHCPv6OptionCode.IA_PD),
    ]  # fmt: skip
    restored = v6_server()
    for binding in kept:
        restored.set_binding(binding)
    assert restored.bindings == kept
    restored.remove_binding(v6(100))
    assert [binding.length for binding in restored.bindings] == [56]
    assert lease.prefixes() == [DHCPv6IAPrefix(3000, 4000, 56, PREFIX)]
    assert lease.options.addresses(DHCPv6OptionCode.DNS_SERVERS) == [v6(53)]
    assert client.lease == lease
    assert (client.state, client.poll_timeout()) == (DHCPv6ClientState.BOUND, lease.at(lease.renewal))
    # §18.2.4: Renew at T1, to the server, with its DUID.
    client.expire(lease.at(lease.renewal), generator)
    renew = DHCPv6Message.decode(client.transmit())
    assert (renew.kind, renew.options.duid(DHCPv6OptionCode.SERVER_ID)) == (DHCPv6MessageType.RENEW, duid(0x53))
    # §18.2.7: Release, with the server's DUID and the IAs; its Reply ends the lease.
    now = lease.at(lease.renewal) + SECOND
    client.release(now, generator)
    release = DHCPv6Message.decode(client.transmit())
    assert release.kind == DHCPv6MessageType.RELEASE and release.options.contains(DHCPv6OptionCode.IA_NA)
    reply = DHCPv6Message.decode(server.receive(release.encode(), now))
    assert reply.options.status().code == DHCPv6StatusCode.SUCCESS
    client.receive(reply.encode(), now, generator)
    assert [event.kind for event in events(client)] == [DHCPv6ClientEventKind.RELEASED]
    assert (client.state, client.poll_timeout(), client.lease) == (DHCPv6ClientState.INIT, None, None)
    for call in (lambda: client.release(now, generator), lambda: client.confirm(now, generator), lambda: client.decline([v6(100)], now, generator)):
        with pytest.raises(DHCPError) as error:
            call()
        assert error.value.name == "State"


def test_rapid_commit_declines_and_information():
    generator = random(b"test_rapid_commit_declines_and_information")
    # §18.2.1, §18.3.1: Rapid Commit on both ends, a Reply to the Solicit.
    server = v6_server(rapid_commit=True)
    client = DHCPv6Client(DHCPv6ClientConfig(duid(2), 1, rapid_commit=True), 0)
    client.start(0, generator)
    client.expire(at(1), generator)
    solicit = DHCPv6Message.decode(client.transmit())
    assert solicit.options.get(DHCPv6OptionCode.RAPID_COMMIT) == b""
    reply = DHCPv6Message.decode(server.receive(solicit.encode(), at(1)))
    assert reply.kind == DHCPv6MessageType.REPLY and reply.options.contains(DHCPv6OptionCode.RAPID_COMMIT)
    client.receive(reply.encode(), at(1), generator)
    assert events(client)[0].kind == DHCPv6ClientEventKind.BOUND
    # §18.2.8: Decline of an address DAD found in use; the server will not lease it again (§18.3.8).
    client.decline([v6(100)], at(2), generator)
    decline = client.transmit()
    assert decline[0] == DHCPv6MessageType.DECLINE
    client.receive(server.receive(decline, at(2)), at(2), generator)
    assert events(client)[0].kind == DHCPv6ClientEventKind.RELEASED
    assert client.state == DHCPv6ClientState.SOLICITING
    again = DHCPv6Message.decode(server.receive(client.transmit(), at(3)))
    assert again.options.ias(DHCPv6OptionCode.IA_NA)[0].addresses()[0].address == v6(101)
    # §18.2.6: neither addresses nor prefixes, an Information-request without IAs; §21.23: without an
    # Information Refresh Time, the configuration is kept IRT_DEFAULT, 86400 s.
    stateless = DHCPv6Client(DHCPv6ClientConfig(duid(3), 0, addresses=False), 0)
    stateless.start(0, generator)
    stateless.expire(at(1), generator)
    request = DHCPv6Message.decode(stateless.transmit())
    assert request.kind == DHCPv6MessageType.INFORMATION_REQUEST
    assert not any(request.options.contains(code) for code in (DHCPv6OptionCode.IA_NA, DHCPv6OptionCode.IA_PD, DHCPv6OptionCode.SERVER_ID))
    stateless.receive(server.receive(request.encode(), at(1)), at(1), generator)
    [event] = events(stateless)
    assert event.kind == DHCPv6ClientEventKind.INFORMED
    assert event.options.addresses(DHCPv6OptionCode.DNS_SERVERS) == [v6(53)]
    assert (stateless.state, stateless.poll_timeout()) == (DHCPv6ClientState.INFORMED, at(1) + at(86_400))


def test_the_checks_of_section_16_and_relays():
    # The configuration of a server, given a pool: the preferred lifetime is not past the valid one (§21.6).
    config = DHCPv6ServerConfig.new(duid(0x53))
    assert (config.duid, config.addresses, config.prefixes) == (duid(0x53), None, None)
    assert 0 < config.preferred <= config.valid
    pool = DHCPv6Server(dataclasses.replace(config, addresses=(v6(100), v6(101))))
    server = v6_server()
    solicit = DHCPv6Message.new(DHCPv6MessageType.SOLICIT, 7)
    solicit.options.push(DHCPv6OptionCode.CLIENT_ID, duid(4).encode())
    solicit.options.push(DHCPv6OptionCode.ELAPSED_TIME, bytes(2))
    solicit.options.push(DHCPv6OptionCode.IA_NA, DHCPv6IA.new(DHCPv6OptionCode.IA_NA, 1).encode().data)
    advertise = DHCPv6Message.decode(pool.receive(solicit.encode(), 0))
    assert advertise.kind == DHCPv6MessageType.ADVERTISE
    assert advertise.options.ias(DHCPv6OptionCode.IA_NA)[0].addresses()[0].address == v6(100)
    # §18.3.9: every IA is answered; past `maximum_ias`, with NoAddrsAvail.
    few = DHCPv6Server(dataclasses.replace(config, addresses=(v6(100), v6(101)), maximum_ias=1))
    two = DHCPv6Message(solicit.kind, 7, DHCPv6Options([*solicit.options.entries]))
    two.options.push(DHCPv6OptionCode.IA_NA, DHCPv6IA.new(DHCPv6OptionCode.IA_NA, 2).encode().data)
    ias = DHCPv6Message.decode(few.receive(two.encode(), 0)).options.ias(DHCPv6OptionCode.IA_NA)
    assert [(ia.iaid, len(ia.addresses())) for ia in ias] == [(1, 1), (2, 0)]
    assert ias[1].options.status().code == DHCPv6StatusCode.NO_ADDRS_AVAIL
    # §16: a Solicit with a Server Identifier or without a Client Identifier, a Request without the
    # server's identifier: discarded.
    with_server = DHCPv6Message(solicit.kind, 7, DHCPv6Options([*solicit.options.entries]))
    with_server.options.push(DHCPv6OptionCode.SERVER_ID, duid(0x53).encode())
    anonymous = DHCPv6Message(solicit.kind, 7, DHCPv6Options([*solicit.options.entries]))
    anonymous.options.remove(DHCPv6OptionCode.CLIENT_ID)
    request = DHCPv6Message(DHCPv6MessageType.REQUEST, 7, solicit.options)
    for discarded in (with_server, anonymous, request):
        assert server.receive(discarded.encode(), 0) is None
    # §19.3: a Relay-forward is answered in a Relay-reply of the same addresses and Interface-Id.
    relay = DHCPv6RelayMessage(DHCPv6MessageType.RELAY_FORW, 0, v6(1), IPv6Address.parse("fe80::1"))
    relay.options.push(DHCPv6OptionCode.INTERFACE_ID, b"eth0")
    relay.options.push(DHCPv6OptionCode.RELAY_MSG, solicit.encode())
    reply = DHCPv6RelayMessage.decode(server.receive(relay.encode(), 0))
    assert (reply.kind, reply.hops, reply.link, reply.peer) == (DHCPv6MessageType.RELAY_REPL, 0, relay.link, relay.peer)
    assert reply.options.get(DHCPv6OptionCode.INTERFACE_ID) == b"eth0"
    advertise = DHCPv6Message.decode(reply.relayed())
    assert (advertise.kind, advertise.transaction) == (DHCPv6MessageType.ADVERTISE, 7)
    assert advertise.options.duid(DHCPv6OptionCode.CLIENT_ID) == duid(4)
    # A pool backwards, a delegated prefix shorter than its prefix.
    for changes in (dict(addresses=(v6(101), v6(100))), dict(prefixes=(PREFIX, 60, 56))):
        with pytest.raises(DHCPError) as error:
            v6_server(**changes)
        assert error.value.name == "Config"
    server.expire(at(1))
