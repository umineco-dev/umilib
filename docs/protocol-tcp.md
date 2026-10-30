# TCP: `umilib::protocol::tcp`

`protocol-tcp` (no `std`) is the Transmission Control Protocol (RFC 9293)
over IPv4 and IPv6, without doing any I/O. It has these parts:

| Type | What it is |
| --- | --- |
| `TCPSegment`, `TCPHeader` | A segment whose data offset and checksum are checked when read and computed when written, and its raw header |
| `TCPOptions`, `TCPOptionSet` | The options, and those this crate understands: MSS, Window Scale, SACK-Permitted, SACK, Timestamps |
| `TCPSequence`, `TCPFlags` | Sequence numbers compared modulo 2^32, and the control bits |
| `TCPConnection` | A connection and its state machine (RFC 9293 §3.10) |
| `TCPListener` | A passive OPEN: the connections being set up until they are accepted |
| `TCPConfig` | Every limit and time of the connection |
| `TCPISNGenerator` | Initial sequence numbers (RFC 6528) |
| `TCPRetransmissionTimer` | The RTO (RFC 6298) |
| `TCPCongestionControl`, `TCPNewReno`, `TCPCUBIC` | Congestion control (RFC 5681, RFC 9438) |
| `TCPRule` | The rule that routes connections by their endpoints |

## Segments

A `TCPSegment` has the fields of RFC 9293 §3.1, its options as bytes
(`options`), and its data (`payload`), both borrowed from the input. The data
offset and the checksum are not fields: `decode` checks them, and `encode`
computes them over the pseudo-header of the addresses that carry the segment.
The sender must compute the checksum (MUST-2) and the receiver must check it
(MUST-3).

```rust
use umilib::protocol::tcp::TCPSegment;

let segment = TCPSegment::decode(ip_payload, source, destination)?;
let options = segment.option_set()?;          // MSS, Window Scale, SACK, Timestamps
segment.encode(source, destination, &mut buffer)?;
```

`decode` fails with one of these:

- `TCPError::Length`: fewer than 20 bytes, or a data offset below 5 words or
  beyond the bytes.
- `TCPError::Checksum`.
- `TCPError::Option`: an option of an illegal length (MUST-7).
- `TCPError::Family`: addresses of two versions.

The reserved bits are ignored when read and sent as zero. `TCPHeader`
reads the 20 bytes as they are, checking nothing. That is what the quote of
an ICMP error needs.

`sequence_length()` is SEG.LEN: the data, plus one each for SYN and FIN.
`TCPSegment::reset` builds a reset. `reset_reply()` is the reset that
answers a segment for which no connection exists (RFC 9293 §3.10.7.1).

## Options

`TCPOptions` iterates over the options; No-Operation is included, and End of
Option List ends them. An option need not start on a word boundary
(MUST-64). `TCPOptionSet` reads and writes the options this crate
understands:

| Option | RFC | Notes |
| --- | --- | --- |
| Maximum Segment Size | RFC 9293 §3.2 | |
| Window Scale | RFC 7323 §2 | A shift count above 14 reads as 14 |
| SACK-Permitted | RFC 2018 §2 | |
| SACK | RFC 2018 §3 | Up to 4 blocks |
| Timestamps | RFC 7323 §3 | |

When reading:

- An unknown option is ignored (MUST-6), and so is a known option of the
  wrong size, as Linux does.
- An option of an illegal length makes `decode` fail with `TCPError::Option`
  (MUST-7).

`encode` writes the options in Linux's layout, so that a segment built here
looks like one from Linux. Each group is aligned to 4 bytes with
No-Operation:

1. MSS.
2. SACK-Permitted and Timestamps together, or SACK-Permitted alone.
3. Window Scale.
4. The SACK blocks.

It fails with `TCPError::Option` if the options do not fit in 40 bytes.

## Connections

A `TCPConnection` is given the segments that arrive, the time
(`runtime::Instant` of your clock) and the application's data. It writes the
segments to send. You do the rest:

- demultiplex segments to connections by their endpoints;
- build the IP header around each segment written;
- call `transmit` until it returns `None`, after every input and whenever
  `poll_timeout` comes. The inputs are `receive`, `send`, `send_urgent`,
  `close`, `abort`, `receive_error` and `set_config`. `poll_timeout` gives
  the timers only, so a caller that skips `transmit` after an input leaves
  its segments unsent until the next timer.

Give the connection every segment that arrived before you transmit, so that
their acknowledgments are combined (MUST-58, MUST-59).

```rust
use umilib::protocol::tcp::{TCPConfig, TCPConnection, TCPEvent, TCPISNGenerator};

let isn = TCPISNGenerator::new(key_from_your_random_source);
let mut connection = TCPConnection::connect(TCPConfig::default(), local, remote, isn.generate(local, remote, now), now)?;
loop {
    while let Some(sent) = connection.transmit(now, &mut buffer)? {
        // buffer holds one segment; sent.ect says whether to mark its IP header ECT(0)
        send_in_ip_packet(&buffer, sent.ect);
        buffer.clear();
    }
    // wait for a packet or for connection.poll_timeout(), then:
    connection.receive(&segment, ce_in_ip_header, now);
    while let Some(event) = connection.poll_event() {
        match event {
            TCPEvent::Readable => { connection.read(&mut data); }
            TCPEvent::Closed(reason) => return Ok(reason),
            _ => {}
        }
    }
}
```

What the application can do:

- `send` takes as much data as the send buffer holds and returns how much.
  `send_urgent` sends data as urgent (MUST-30, MUST-31): the urgent pointer
  names the octet after it (MUST-62).
- `read` returns what arrived, in order.
- `readable`, `writable` and `urgent_remaining` (MUST-33) tell how much can be
  read, how much room there is to send, and how many urgent bytes remain
  unread.
- `close` closes the sending half: a FIN follows the data, and reading goes
  on.
- `abort` sends a reset.

`close` and `abort` fail with `TCPError::State` once the connection is
closed ("connection does not exist", RFC 9293 §3.10.4, §3.10.5). A second
`close` fails the same way.

`poll_event` reports these events:

| Event | Meaning |
| --- | --- |
| `Connected` | The handshake completed |
| `Readable` | Data can be read |
| `Writable` | Room was freed in the send buffer |
| `Urgent` | The urgent pointer arrived or moved (MUST-32) |
| `PeerClosed` | The peer sent a FIN; no more data will arrive |
| `Trouble` | A soft error (MUST-47) |
| `Closed(reason)` | The connection is closed (MUST-12) |

`Readable`, `Writable`, `Urgent` and `Trouble` say that something is so, not
how often. While one is waiting, the same event is not queued again, so a
connection holds a few events at most, whether or not you poll them.
`Connected`, `PeerClosed` and `Closed` come once.

`Trouble` reports that a segment was retransmitted R1 times (SHLD-9) or that
an ICMP soft error arrived (SHLD-25).

The reasons of `Closed` are `Normal`, `Reset`, `Refused`, `Timeout`, `Aborted`
and `Unreachable`.

`receive_error` takes an ICMP error about a segment the connection sent
(MUST-54):

- The error is acted on only if its sequence number is in flight (RFC 5927).
- A soft error is reported and the connection goes on (MUST-56).
- A hard error closes a connection that is not yet established. In
  synchronized states it is reported as `Trouble`, as RFC 5927 §4.2
  advises, unless `hard_error_abort` is set: then it closes the connection
  with `Unreachable`, as SHLD-26 says. The default keeps a guessed ICMP
  error from ending the connection.
- Packet Too Big lowers the MTU (`path_mtu`) and, once the connection is
  synchronized, resends what no longer fits (RFC 1191, RFC 8201). A larger MTU reported later is ignored
  (RFC 8201 §4).

ICMP Source Quench must be silently ignored (MUST-55); do not pass it on.

`TCPConnection` implements `ip::IPEndpoints`, so a `TCPRule` routes it.

### Opening and listening

`TCPConnection::connect` opens actively. It refuses a remote address that
names no single host (MUST-46). `TCPListener` handles a passive OPEN for the
local endpoints of a pattern:

- A SYN opens a connection in SYN-RECEIVED, as long as the backlog has room.
- The listener holds each connection until you accept it. It gives the
  connection its segments and runs its timers, both while the connection is
  set up and after it is established, so data that comes before `accept` is
  received and acknowledged.
- An ACK for no connection is answered with a reset. At most `backlog`
  resets wait to be sent.
- A reset is ignored.
- A SYN in the window of a connection being set up returns it to LISTEN:
  the listener forgets it (RFC 9293 §3.10.7.4).
- A SYN to or from an address of no single host is ignored (MUST-57,
  MUST-63). `TCPConnection::accept` refuses it too, with
  `TCPError::Address`.

`accept` returns the established connections, in order. From then on you
give them their segments yourself. `pending()` counts the connections being
set up, and `ready` holds the endpoints of those waiting to be accepted.
`TCPListener::new` fails with `TCPError::Config` for a configuration that
cannot work. A listener never affects another connection
(MUST-41), and it accepts while other connections on its port are being set
up (MUST-42).

When a SYN arrives for the endpoints of a connection in TIME-WAIT, ask
`accepts_syn`, which follows RFC 6191 §2 (SHLD-4). If it returns true, drop
the old connection and give the SYN to the listener.

### What the connection does

- **The handshake** (RFC 9293 §3.5) exchanges the options: MSS (MUST-14),
  Window Scale, SACK-Permitted and Timestamps when `TCPConfig` enables them,
  and ECN when asked (RFC 3168). Without an MSS option, the peer's MSS is 536
  bytes for IPv4 and 1,220 for IPv6 (MUST-15). Simultaneous opens and
  closes work as RFC 9293 Figures 7 and 13 show.
- **Reliability**: out-of-order data is held (SHLD-31) and reported with
  SACK blocks, the latest first (RFC 2018 §4). At most
  `receive_buffer / 64` blocks of it are held. A segment that would make
  another block is dropped, and the peer sends it again. This keeps a peer
  that sends tiny segments from making the connection hold more memory or
  do more work than the buffer allows. The retransmission timer
  follows RFC 6298 and Karn's algorithm (MUST-18). The RTT is taken from
  timestamps when they are in use (RFC 7323 §4).
- **Loss recovery**:
  - Fast retransmit after three duplicate ACKs (RFC 5681 §3.2). Without
    SACK, a duplicate ACK is one that changes nothing (RFC 5681 §2) and
    Limited Transmit sends a segment for each of the first two (RFC 3042).
  - With SACK, the recovery of RFC 6675:
    - A duplicate is an ACK that SACKs data not SACKed before (§2).
    - Limited Transmit sends while cwnd − pipe is at least a segment.
    - The recovery starts on the third duplicate, or once IsLost says the
      first segment is lost. It sends again the segment at SND.UNA, up to
      the SACKed data.
    - Then, while cwnd − pipe is at least a segment, it sends what NextSeg
      names: lost data, then new data, then other unSACKed data, and once a
      rescue retransmission of the highest unSACKed data, which does not
      repeat the segment of the entry.
  - Without SACK, NewReno (RFC 6582).
  - After a timeout, duplicate ACKs for the data sent before it start no
    recovery (`recover`, RFC 6582 §3.2, RFC 6675 §5.1).
  - A loss in the last segments of the data is found only by the
    retransmission timer. RACK-TLP (RFC 8985) is not implemented.
- **Congestion control** (MUST-19):
  - CUBIC by default; NewReno with `TCPCongestionKind::NewReno`. Your own
    is any type that implements `TCPCongestionControl`, through
    `connect_with` and `accept_with`.
  - The initial window is that of RFC 5681 §3.1, or `initial_window`. It is
    one segment after a lost SYN.
  - After an RTO with no data sent, cwnd restarts (RFC 5681 §4.1).
  - The answers to window probes are not duplicate ACKs: a closed window is
    not a loss.
  - With ECN (RFC 3168 §6.1):
    - An ECE reduces cwnd as a loss does, and the ACK that carries it does
      not grow cwnd.
    - Losses and ECEs reduce cwnd once per window of data together.
    - With cwnd at one segment, an ECE holds new data until the RTO has
      passed.
    - Only new data carries ECT(0) and CWR: not retransmissions, and not
      window probes (§6.1.6).
- **Sending rules**:
  - Nagle (SHLD-7, off with `nagle: false`, MUST-17).
  - The sender's and the receiver's SWS avoidance (MUST-38, MUST-39).
  - The last buffered segment is pushed (MUST-61).
  - The window is never shrunk (SHLD-14), and a shrinking window from the
    peer is survived (MUST-34).
- **Acknowledgments**:
  - Delayed by at most `delayed_ack` (40 ms by default; MUST-40 requires
    less than 0.5 s).
  - Sent at once for every second full-sized segment (SHLD-19), for
    out-of-order data, and for a filled hole.
  - A window update is sent when reading opens the window enough.
  - With the receive window at zero, a segment at RCV.NXT still has its
    ACK, URG and RST processed, and is acknowledged; its data is not taken
    (RFC 9293 §3.10.7.4).
  - A FIN beyond the window is not taken yet, and is acknowledged so that
    the peer sends it again.
- **Zero windows** are probed with one byte, at intervals that double
  (MUST-35, MUST-36, SHLD-30). The connection stays open as long as the
  probes are answered (MUST-37). Once nothing has been received for
  `user_timeout` (R2), it closes with `Timeout`.
- **Attacks** (RFC 5961): a reset is believed only at RCV.NXT, and another in
  the window is answered with a challenge ACK. A SYN in a synchronized
  state gets a challenge ACK. ACKs outside [SND.UNA − MAX.SND.WND, SND.NXT]
  are refused. The challenge ACKs are limited to `challenge_acks` a second.
- **Timestamps**: PAWS drops old segments (RFC 7323 §5). Once timestamps are
  in use, a segment without them is dropped (§3.2).
- **Giving up** (MUST-20):
  - After `retries` (R1) retransmissions, `Trouble` is reported.
  - After `user_timeout` (R2, 100 s; MUST-21) the connection closes with
    `Timeout`. For a SYN, R2 is `connect_timeout` (3 minutes, MUST-23).
- **Keep-alives** are off by default (MUST-24, MUST-25). Once on:
  - They are sent only when nothing is outstanding (MUST-26).
  - The first is sent after `keepalive_idle` (two hours by default, MUST-27,
    MUST-28).
  - They are segments of SND.NXT − 1 without data (SHLD-12).
  - The connection is given up only after `keepalive_probes` go unanswered
    (MUST-29).
- **TIME-WAIT** lasts `time_wait`, 2 MSL = 4 minutes (MUST-13). The remote
  FIN sent again restarts it; another FIN does not.
- **An illegal option length** in a segment resets the connection (MUST-7).

These are left to you, because they belong to the IP layer or to the
application:

- choosing the source address (MUST-44);
- the DSCP and the TTL of the packets (MUST-48, MUST-49);
- source routes (MUST-51 to MUST-53);
- ignoring Source Quench (MUST-55).

Not implemented, all optional:

- the half-duplex close (MAY-1);
- sending D-SACK (RFC 2883);
- TCP Fast Open (RFC 7413, Experimental);
- HyStart++ (RFC 9406);
- Proportional Rate Reduction (RFC 6937, Experimental);
- RACK-TLP (RFC 8985).

## The configuration

`TCPConfig` holds every limit and time, with these defaults:

| Field | Default | Rule |
| --- | --- | --- |
| `mtu` | 1500 | The MSS advertised is the MTU less 40 (IPv4) or 60 (IPv6) bytes |
| `send_buffer`, `receive_buffer` | 256 KiB | The window scale follows the receive buffer |
| `window_scale`, `timestamps`, `sack` | on | RFC 7323, RFC 2018 |
| `ecn` | `Accept` | RFC 3168: used when the peer asks; `Request` asks; `Off` never |
| `nagle` | on | SHLD-7, MUST-17 |
| `delayed_ack` | 40 ms | Below 0.5 s (MUST-40) |
| `initial_rto`, `minimum_rto`, `maximum_rto` | 1 s, 1 s, 60 s | RFC 6298 (2.1), (2.4), (2.5) |
| `clock_granularity` | 1 ms | G of RFC 6298 |
| `congestion` | `CUBIC` | RFC 9438 |
| `initial_window` | `None` | RFC 5681 §3.1 |
| `retries` | 3 | R1 (SHLD-10) |
| `user_timeout` | 100 s | R2 (SHLD-11) |
| `connect_timeout` | 180 s | R2 of a SYN (MUST-23) |
| `keepalive` | off | MUST-25 |
| `keepalive_idle`, `keepalive_interval`, `keepalive_probes` | 2 h, 75 s, 9 | MUST-28, MUST-29 |
| `time_wait` | 240 s | 2 MSL (MUST-13) |
| `challenge_acks` | 1000 a second | RFC 5961 §7 |
| `hard_error_abort` | off | SHLD-26 when on; RFC 5927 §4.2 when off |

The defaults follow the RFCs named. You may choose values that do not,
such as a shorter `connect_timeout`. `TCPConfig::check` refuses only values
that cannot work, with `TCPError::Config`:

- an MTU below 68;
- a buffer that is empty or larger than `TCPConfig::MAXIMUM_BUFFER`
  (65535 << 14 bytes, the largest window);
- no keep-alive probe;
- a minimum RTO of zero;
- RTO bounds that are reversed or exclude the initial RTO;
- a clock granularity of zero;
- an initial window of zero.
`connect`, `accept`, `set_config` and `TCPListener::new` check it.

RFC 6298 asks for a minimum RTO of 1 second. Linux uses 200 ms; set
`minimum_rto` to that for the same behaviour.

`set_config` changes the configuration of a running connection, for
example to turn Nagle off (MUST-17) or keep-alives on (MUST-24). It fails
with `TCPError::Config` and leaves the configuration unchanged if the new
one cannot work.

- The buffers take their new sizes, and the window already advertised is
  not taken back.
- What the connection chose when it was made stays, and reads back as it
  was: the handshake options (`window_scale`, `timestamps`, `sack`,
  `ecn`) and `congestion`.
- The RTO's bounds and granularity apply from the next RTO; the RTT
  measured is kept.
- A lower `mtu` takes effect at once. A higher one does not raise the MTU
  above what Packet Too Big reported. `mtu()` is the MTU the segments are
  sized for.

## C and Python

The C functions are `umilib_protocol_tcp_*` (`include/umilib/protocol/tcp.h`):

- A segment is an `umilib_protocol_tcp_TCPSegment` of its fields, with its
  options and data passed beside it. `decode` writes their offsets in the
  bytes.
- Connections, listeners, congestion controls and ISN generators are
  handles.
- The configuration, the retransmission timer and the option set are
  structures; durations are in nanoseconds.
- `umilib_protocol_tcp_tcp_connection_info` returns what the connection
  holds, and the events are numbers.

The Python package `umilib.protocol.tcp` has the same classes:

- `TCPConnection.transmit(now)` returns the segment and a `TCPTransmission`.
- `TCPConnection.info()` returns what the connection holds.
- An event is a `TCPEvent`, whose `name` is that of the Rust variant.
- `TCPCongestion` is the congestion control of a kind.
- `TCPListener.matches(local)` tells whether an endpoint is the listener's.

`connect_with` and `accept_with`, which take a congestion control of your
own, are Rust only: C and Python choose the congestion control by
`TCPConfig.congestion`.
