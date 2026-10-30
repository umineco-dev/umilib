# QUIC: `umilib::protocol::quic`

`protocol-quic` (no `std`) is QUIC without doing any I/O: version 1 (RFC
9000, RFC 9001, RFC 9002; feature `protocol-quic-v1`) and version 2 (RFC
9369; feature `protocol-quic-v2`). `protocol-quic` is both. TLS 1.3 secures
it (`protocol-tls-v1_3`).

| Type | What it is |
| --- | --- |
| `QUICEndpoint` | The connections of one socket: datagrams in and out, routing by connection ID, Version Negotiation, Retry, stateless resets, accepting connections |
| `QUICEndpointConfig` | An endpoint's configuration: the connections', the TLS configuration of those it accepts, address validation |
| `QUICConnection` | A connection: datagrams in and out, streams, DATAGRAM frames, events, timers |
| `QUICConfig` | The limits, timeouts and flags of connections, from which their transport parameters are made |
| `QUICEvent`, `QUICCloseReason` | What happened on a connection |
| `QUICRule` | The rule that routes connections by server name, ALPN and version |
| `QUICStreamID` | A stream ID and what its bits say |
| `QUICPacket`, `QUICHeader`, `QUICFrame`, `QUICTransportParameters`, `QUICVarint`, ... | The codecs, for tools that read or write packets |
| `QUICSecret`, `QUICPacketKey`, `QUICHeaderProtection`, `QUICRetryIntegrity` | Packet protection (RFC 9001 §5), usable on its own |
| `QUICRecovery`, `QUICNewReno`, `QUICPacer`, `QUICRTT` | Loss detection and congestion control (RFC 9002) |
| `QUICVersionProfile`, `v1::QUICv1`, `v2::QUICv2` | What differs between the versions |

## What is implemented

- The handshake with TLS 1.3 (RFC 9001), every cipher suite of TLS 1.3 but
  TLS_AES_128_CCM_8_SHA256, which has no header protection.
- Streams of both kinds, flow control of streams and of the connection,
  resets and STOP_SENDING (RFC 9000 §2–§4).
- Connection IDs issued and retired, stateless resets (§5.1, §10.3).
- Address validation: the amplification limit, Retry, NEW_TOKEN (§8.1);
  path validation and the migration of clients (§8.2, §9).
- Loss detection, probe timeouts, NewReno, persistent congestion and pacing
  (RFC 9002); delayed acknowledgments and ECN counts reported (RFC 9000
  §13.2, §13.4).
- Key updates (RFC 9001 §6), the AEAD usage limits (§6.6).
- 0-RTT with session tickets (RFC 9001 §4.6), its limits remembered and
  checked (RFC 9000 §7.4.1).
- Version Negotiation with its downgrade protection (RFC 9368 §4); version 2.
- DATAGRAM frames (RFC 9221), the greasing of the QUIC bit (RFC 9287), the
  latency spin bit (RFC 9000 §17.4).

Not implemented:

- Compatible version negotiation (RFC 9368 §2.3): a client lists only its
  chosen version in its Version Information, so a server never converts it;
  a server keeps the version of the client's first packet.
- A client's move to a server's preferred address (RFC 9000 §9.6), which is
  optional: a client keeps the address it connected to and holds the
  address's connection ID like the others. A server advertises one with
  `QUICConfig::preferred_address`, and the application receives there too.
- Sending ECN codepoints (and their validation, RFC 9000 §13.4.2): datagrams
  go without ECN; the counts a peer reports are read for congestion control.
- Extensions still in drafts: multipath, ACK frequency, reliable stream
  resets, QUIC-LB, qlog.

## A client and a server

```rust
use std::sync::Arc;
use umilib::protocol::quic::{QUICConfig, QUICECN, QUICEndpoint, QUICEndpointConfig, QUICEvent};

let config = Arc::new(QUICConfig::default());
// TLS: an application protocol is required (RFC 9001 §8.1).
let mut tls_server = TLSServerConfig::new(certificates);
tls_server.config.protocols = vec![b"my-protocol".to_vec()];
let mut server = QUICEndpoint::new(QUICEndpointConfig::new(config.clone(), Some(Arc::new(tls_server))), random)?;
let mut client = QUICEndpoint::new(QUICEndpointConfig::new(config, None), random_too)?;
let connection = client.connect(tls_client, Some("example.com"), server_address, None, random_three, now, time)?;
// The caller's loop: datagrams in, datagrams out, timers.
let mut out = Vec::new();
while let Some(transmission) = client.transmit(now, &mut out) {
    socket.send_to(&out, transmission.destination)?;
}
client.receive(&datagram, from, QUICECN::NotECT, now, time);
if let Some(deadline) = client.poll_timeout() { /* call client.expire(deadline, time) then */ }
```

`now` is the caller's monotonic clock (`runtime::Instant`), `time` seconds
since 1970, for certificates and tokens. After each `receive` or `expire`,
call `transmit` until it returns `None`.

Once `QUICEvent::Connected` arrives, `connection.open_stream(bidirectional)`,
`stream_send(stream, data, fin)` and `stream_read(stream, buffer)` move data;
`send_datagram` and `read_datagram` carry DATAGRAM frames when both ends
set `max_datagram_frame_size`: one larger than the peer allows, or than one
packet carries, is refused, as DATAGRAM frames are never split (RFC 9221
§5). `close(error, reason, now)` closes with the application's error. A
server takes new connections with `endpoint.accept()`.

`stream_stop(stream, error)` stops reading a stream: what arrives on it
afterwards is dropped and still gives the peer its flow control credit back,
and the stream ends once its size is known, by its end or by the peer's
RESET_STREAM; STOP_SENDING goes only while the size is not known (RFC 9000
§3.5). `update_keys(now)` updates the 1-RTT keys once the handshake is
confirmed and a packet sent with the current keys was acknowledged (RFC 9001
§6.1); the connection also updates them on its own before the AEAD's limit.

## Configuration

Every limit is a field of `QUICConfig` (see its documentation): the windows
of flow control, the streams the peer may open, the idle timeout, the size
of datagrams (1200 by default: the size every path carries, RFC 9000 §14),
the initial RTT, pacing, the spin bit, the greasing of the QUIC bit and of
transport parameters, and the limits of buffers that a peer could otherwise
make grow. `QUICConfig::check` refuses values that cannot work.

Address validation is the endpoint's: with `token_key` (32 bytes, shared by
the servers of a deployment) a server sends NEW_TOKEN tokens to its clients
and, with `retry`, sends a Retry to clients without a valid token before
keeping any state (RFC 9000 §8.1). `QUICConfig::reset_key` makes stateless
reset tokens derivable after a restart (RFC 9000 §10.3.2).

## 0-RTT

A client whose TLS configuration keeps session tickets and allows early data
(`TLSClientConfig::sessions`, `early_data`) opens streams and writes to them
right after `connect`: their data goes in 0-RTT packets with the limits the
server gave in the earlier connection. If the server refuses 0-RTT, the
connection says so with `QUICEvent::ZeroRTTRejected`: the streams are gone,
and the application sends again what it still wants (RFC 9001 §4.6.2). A
server accepts 0-RTT with tickets, an anti-replay record and
`maximum_early_data` above 0 in its TLS configuration, and only from tickets
it issued with the same limits.

0-RTT data can be replayed: only requests that are safe to repeat belong in
it (RFC 9001 §9.2).

## Routing

`QUICRule` routes connections, once their handshake completed, by the
server name the client asked for, the application protocol negotiated and
the version: HTTP/3 (`h3`) to one service and DNS over QUIC (`doq`) to
another on one port.

## C and Python

The C ABI (`ffi`) exposes configurations and endpoints as handles and an
endpoint's connections as numbers: `umilib_protocol_quic_quic_endpoint_*`
and `umilib_protocol_quic_quic_connection_*` (see `include/`). Python has the
same classes in `umilib.protocol.quic`.
