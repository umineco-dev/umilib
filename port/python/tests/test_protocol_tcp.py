"""Tests of umilib.protocol.tcp: the segments of the Linux kernel with their checksums computed
independently, the rules of options (RFC 9293 §3.2, RFC 7323, RFC 2018), sequence numbers (RFC 9293
§3.4), the retransmission timer (RFC 6298), congestion control (RFC 5681, RFC 9438), and connections
and a listener driven from Python (RFC 9293 §3.5, §3.6)."""

import datetime
import re

import pytest
from test_protocol_ip import reference_checksum
from vectors import ROOT

from umilib.protocol.ip import IPEndpoint, IPEndpointPattern, IPv4Address, IPv6Address
from umilib.protocol.tcp import (
    TCPCloseReason,
    TCPCongestion,
    TCPCongestionKind,
    TCPConfig,
    TCPConnection,
    TCPError,
    TCPEvent,
    TCPFlags,
    TCPHeader,
    TCPICMPError,
    TCPISNGenerator,
    TCPListener,
    TCPOption,
    TCPOptionKind,
    TCPOptions,
    TCPOptionSet,
    TCPRetransmissionTimer,
    TCPRule,
    TCPSACKBlock,
    TCPSegment,
    TCPSequence,
    TCPState,
    TCPTimestamps,
)


def segments():
    """The TCP segments of the capture: (tcpdump's TCP line, source, destination, bytes)."""
    found, description = [], []
    for line in (ROOT / "protocol/tcp/linux.txt").read_text().splitlines():
        if line.startswith("# "):
            description.append(line[2:])
            continue
        if not line.strip():
            continue
        frame, text = bytes.fromhex(line), next(entry for entry in description if "Flags [" in entry)
        text, description = text[text.index("Flags [") :], []
        packet = frame[14:]
        if frame[12:14] == b"\x08\x00":
            length = (packet[0] & 15) * 4
            found.append((text, IPv4Address(packet[12:16]), IPv4Address(packet[16:20]), packet[length : int.from_bytes(packet[2:4], "big")]))
        else:
            found.append((text, IPv6Address(packet[8:24]), IPv6Address(packet[24:40]), packet[40 : 40 + int.from_bytes(packet[4:6], "big")]))
    return found


def pseudo_header(source, destination, length):
    if isinstance(source, IPv4Address):
        return source.octets + destination.octets + bytes([0, 6]) + length.to_bytes(2, "big")
    return source.octets + destination.octets + length.to_bytes(4, "big") + bytes([0, 0, 0, 6])


def test_linux_segments():
    seen = segments()
    assert len(seen) == 241
    for text, source, destination, data in seen:
        header = TCPHeader.decode(data)
        assert header.checksum == reference_checksum(pseudo_header(source, destination, len(data)) + data[:16] + b"\0\0" + data[18:]), text
        segment = TCPSegment.decode(data, source, destination)
        assert segment.encode(source, destination) == data
        assert str(segment.window) == re.search(r"win (\d+)", text).group(1)
        options = segment.option_set()
        assert options.encode() == segment.options, text
        mss = re.search(r"mss (\d+)", text)
        assert options.mss == (int(mss.group(1)) if mss else None)
        stamps = re.search(r"TS val (\d+) ecr (\d+)", text)
        assert options.timestamps == (TCPTimestamps(int(stamps.group(1)), int(stamps.group(2))) if stamps else None)
        assert options.sack_permitted == ("sackOK" in text)
    with pytest.raises(TCPError) as error:
        TCPSegment.decode(seen[0][3][:-1] + bytes([seen[0][3][-1] ^ 1]), seen[0][1], seen[0][2])
    assert error.value.name == "Checksum"


def test_options():
    # RFC 9293 §3.2 (MUST-7, MUST-64, MUST-68), RFC 7323 §2.3, RFC 2018 §3.
    data = bytes([1, 2, 4, 5, 0xB4, 3, 3, 7, 0, 9])
    assert [option.kind for option in TCPOptions(data)] == [TCPOptionKind.NOP, TCPOptionKind.MSS, TCPOptionKind.WINDOW_SCALE]
    assert TCPOptionSet.decode(data) == TCPOptionSet(mss=1460, window_scale=7)
    for illegal in (bytes([2]), bytes([2, 0]), bytes([2, 1]), bytes([200, 4, 0])):
        with pytest.raises(TCPError) as error:
            TCPOptions.check(illegal)
        assert error.value.name == "Option"
    assert TCPOptionSet.decode(bytes([3, 3, 15])).window_scale == 14
    assert TCPOptionSet.decode(bytes([200, 4, 1, 2, 2, 3, 5])) == TCPOptionSet()
    blocks = (TCPSACKBlock(100, 200), TCPSACKBlock(300, 400))
    full = TCPOptionSet(timestamps=TCPTimestamps(7, 9)).with_sack(blocks)
    assert len(full.encode()) == 12 + 4 + 16 and TCPOptionSet.decode(full.encode()) == full
    with pytest.raises(TCPError):
        full.with_sack([TCPSACKBlock(1, 2)] * 4).encode()
    assert TCPOption.encode(200, bytes([1, 2])) == bytes([200, 4, 1, 2])
    # length() counts what encode() would write, also past the 40 bytes it refuses.
    assert full.length() == len(full.encode())
    assert full.with_sack([TCPSACKBlock(1, 2)] * 4).length() == 12 + 4 + 32


def test_segments_and_resets():
    source, destination = IPv4Address.parse("192.0.2.1"), IPv4Address.parse("192.0.2.2")
    segment = TCPSegment(40000, 80, TCPSequence(1000), TCPSequence(0), TCPFlags.SYN, 65535, 0, bytes([2, 4, 5, 0xB4]))
    data = segment.encode(source, destination)
    assert data[12] == 6 << 4 and TCPSegment.decode(data, source, destination) == segment
    assert segment.sequence_length() == 1
    # RFC 9293 §3.10.7.1.
    reset = segment.reset_reply()
    assert (reset.flags, reset.sequence, reset.acknowledgment) == (TCPFlags.RST.union(TCPFlags.ACK), 0, 1001)
    acked = TCPSegment(40000, 80, TCPSequence(5), TCPSequence(77), TCPFlags.ACK)
    assert (acked.reset_reply().flags, acked.reset_reply().sequence) == (TCPFlags.RST, 77)
    assert TCPSegment.reset(1, 2, 3).reset_reply() is None
    # RFC 9293 §3.4: modulo 2^32.
    a = TCPSequence(0xFFFFFFF0)
    b = a.add(32)
    assert b == 16 and a.is_before(b) and b.distance(a) == 32 and b.is_in(a, b.add(1)) and not a.is_after(b)


def test_retransmission_timer_and_congestion():
    # RFC 6298.
    timer = TCPRetransmissionTimer(*(datetime.timedelta(seconds=value) for value in (1, 1, 60)), datetime.timedelta(milliseconds=1))
    timer.sample(datetime.timedelta(milliseconds=100))
    assert (timer.smoothed, timer.variation) == (datetime.timedelta(milliseconds=100), datetime.timedelta(milliseconds=50))
    assert timer.current() == datetime.timedelta(seconds=1)
    timer.expire()
    assert timer.current() == datetime.timedelta(seconds=2) and timer.backoff == 1
    # RFC 5681 §3.1 and RFC 9438 Figure 5.
    assert [TCPCongestion.initial_window(mss) for mss in (536, 1460, 3000)] == [2144, 4380, 6000]
    reno = TCPCongestion(TCPCongestionKind.NEW_RENO, 4000)
    reno.acknowledge(2000, 1000, datetime.timedelta(milliseconds=50), False, 0)
    assert reno.window() == 5000
    reno.congestion(8000, 1000, False, 0)
    assert (reno.window(), reno.threshold()) == (4000, 4000)
    cubic = TCPCongestion(TCPCongestionKind.CUBIC, 100_000)
    cubic.congestion(100_000, 1000, False, 0)
    assert (cubic.window(), cubic.threshold()) == (70_000, 70_000)
    cubic.timeout(50_000, 1000, 0)
    assert (cubic.window(), cubic.threshold()) == (1000, 35_000)


def test_isn_and_config():
    # RFC 6528: M ticks every 4 microseconds.
    generator = TCPISNGenerator(bytes(range(16)))
    local, remote = IPEndpoint.parse("192.0.2.1:1"), IPEndpoint.parse("192.0.2.2:2")
    assert generator.generate(local, remote, 4000) == generator.generate(local, remote, 0).add(1)
    assert generator.generate(remote, local, 0) != generator.generate(local, remote, 0)
    assert TCPConfig.default() == TCPConfig()
    assert TCPConfig().keepalive is False and TCPConfig().keepalive_idle >= datetime.timedelta(hours=2)


def exchange(a, b, a_end, b_end, now, drop=lambda data: False, seen=None):
    """Moves what each side has to send to the other until neither has more, appending each segment
    and its sender to ``seen``."""
    while True:
        moved = 0
        for sender, receiver, source, destination in ((a, b, a_end, b_end), (b, a, b_end, a_end)):
            while (sent := sender.transmit(now)) is not None:
                data, transmission = sent
                assert transmission.length == len(data)
                moved += 1
                segment = TCPSegment.decode(data, source.address, destination.address)
                if seen is not None:
                    seen.append((source, segment))
                if not drop(data):
                    receiver.receive(segment, False, now)
        if moved == 0:
            return


def events(connection):
    return list(iter(connection.poll_event, None))


def test_connections():
    # RFC 9293 §3.5 and §3.6.
    a_end, b_end = IPEndpoint.parse("192.0.2.1:40000"), IPEndpoint.parse("192.0.2.2:80")
    a = TCPConnection.connect(TCPConfig(), a_end, b_end, 1000, 0)
    syn, _ = a.transmit(0)
    b = TCPConnection.accept(TCPConfig(), b_end, a_end, TCPSegment.decode(syn, a_end.address, b_end.address), 5000, 0)
    assert (a.state, b.state) == (TCPState.SYN_SENT, TCPState.SYN_RECEIVED)
    exchange(a, b, a_end, b_end, 1_000_000)
    assert (a.state, b.state) == (TCPState.ESTABLISHED, TCPState.ESTABLISHED)
    info = a.info()
    assert info.sack and info.timestamps and info.window_scaling and info.peer_mss == 1460 and info.iss == 1000
    assert events(b)[0] == TCPEvent.CONNECTED and (a.local, a.remote) == (a_end, b_end)
    assert a.send(b"hello, tcp") == 10
    exchange(a, b, a_end, b_end, 2_000_000)
    assert b.read(100) == b"hello, tcp"
    # RFC 8201 §4 and RFC 1191: Packet Too Big about a segment in flight lowers the MTU, never raises it.
    assert a.info().mtu == 1500
    # Nagle off (MUST-17), so that the small segment leaves while "hello, tcp" is unacknowledged.
    a.set_config(TCPConfig(nagle=False), 2_000_000)
    assert a.config.nagle is False
    a.send(b"x" * 100)
    lost, _ = a.transmit(2_000_000)
    flight = TCPSegment.decode(lost, a_end.address, b_end.address).sequence
    a.receive_error(TCPICMPError.packet_too_big(1200), flight, 2_000_000)
    a.receive_error(TCPICMPError.packet_too_big(1400), flight, 2_000_000)
    a.receive_error(TCPICMPError.packet_too_big(1000), flight.add(1_000_000), 2_000_000)
    assert a.info().mtu == 1200
    exchange(a, b, a_end, b_end, 2_500_000)
    assert b.read(1000) == b"x" * 100
    a.close()
    exchange(a, b, a_end, b_end, 3_000_000)
    b.close()
    seen = []
    exchange(a, b, a_end, b_end, 4_000_000, seen=seen)
    assert (a.state, b.state) == (TCPState.TIME_WAIT, TCPState.CLOSED)
    assert TCPEvent.closed(TCPCloseReason.NORMAL) in events(b)
    with pytest.raises(TCPError) as error:
        a.send(b"late")
    assert error.value.name == "State"
    # RFC 6191 §2: a SYN with a newer timestamp may reopen TIME-WAIT; an older one may not.
    recent = [segment for source, segment in seen if source == b_end][-1].option_set().timestamps.value
    for value, accepted in ((recent + 1, True), (recent - 1, False)):
        options = TCPOptionSet(timestamps=TCPTimestamps(value % 2**32, 0)).encode()
        syn = TCPSegment(80, 40000, TCPSequence(1), TCPSequence(0), TCPFlags.SYN, 1000, 0, options)
        assert a.accepts_syn(syn) is accepted
    # RFC 9293 §3.10.4, §3.10.5: CLOSE and ABORT of a closed connection fail.
    for operation in (b.close, b.abort):
        with pytest.raises(TCPError) as error:
            operation()
        assert error.value.name == "State"
    # MUST-46: an active OPEN to an address of no single host.
    with pytest.raises(TCPError) as error:
        TCPConnection.connect(TCPConfig(), a_end, IPEndpoint.parse("224.0.0.1:80"), 1, 0)
    assert error.value.name == "Address"


def test_listener_and_rule():
    server, client = IPEndpoint.parse("192.0.2.2:80"), IPEndpoint.parse("192.0.2.1:40000")
    listener = TCPListener(TCPConfig(), IPEndpointPattern.port(80), 4, bytes(16))
    a = TCPConnection.connect(TCPConfig(), client, server, 7, 0)
    syn, _ = a.transmit(0)
    listener.receive(TCPSegment.decode(syn, client.address, server.address), server, client, False, 0)
    assert listener.pending == 1
    local, remote, synack, _ = listener.transmit(0)
    assert (local, remote) == (server, client)
    a.receive(TCPSegment.decode(synack, server.address, client.address), False, 1)
    ack, _ = a.transmit(1)
    listener.receive(TCPSegment.decode(ack, client.address, server.address), server, client, False, 1)
    accepted = listener.accept()
    assert accepted.state == TCPState.ESTABLISHED and listener.accept() is None and listener.ready == 0
    assert listener.matches(server) and not listener.matches(client)
    assert TCPRule.new(IPEndpointPattern.port(80)).matches(accepted)
    assert not TCPRule.new(IPEndpointPattern.port(81)).matches(accepted)


def test_configurations_that_cannot_work():
    # TCPConfig::check: what cannot work is refused with Config; the RFCs' values are the defaults.
    a_end, b_end = IPEndpoint.parse("192.0.2.1:40000"), IPEndpoint.parse("192.0.2.2:80")
    zero = datetime.timedelta(0)
    for broken in (
        TCPConfig(mtu=67), TCPConfig(receive_buffer=0), TCPConfig(keepalive_probes=0),
        TCPConfig(minimum_rto=zero, initial_rto=zero), TCPConfig(receive_buffer=(65535 << 14) + 1),
    ):  # fmt: skip
        with pytest.raises(TCPError) as error:
            TCPConnection.connect(broken, a_end, b_end, 1, 0)
        assert error.value.name == "Config"
        with pytest.raises(TCPError):
            TCPListener(broken, IPEndpointPattern.port(80), 4, bytes(16))
    a = TCPConnection.connect(TCPConfig(hard_error_abort=True), a_end, b_end, 1, 0)
    assert a.config.hard_error_abort is True
    with pytest.raises(TCPError):
        a.set_config(TCPConfig(send_buffer=0), 1)
    assert a.config == TCPConfig(hard_error_abort=True)
