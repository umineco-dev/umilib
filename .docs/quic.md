# QUIC

How `protocol::quic` is built and why. The user's view is `docs/protocol-quic.md`.

## Shape

- **No I/O, like TCP and TLS.** `QUICConnection` takes datagrams
  (`receive`), makes datagrams (`transmit`), and is told the time; a
  `QUICEndpoint` routes the datagrams of one socket to its connections and
  answers what none takes. The caller's clock is `runtime::Instant`.
- **One transport, versions as data.** Versions 1 and 2 differ in their
  Version field, long header types, Initial salt, HKDF labels and Retry key
  only (RFC 9369 §3), so a version is a `QUICVersionProfile` of constants
  that the `v1` and `v2` modules define, and the root module is the whole
  transport. A version that changes more than these needs code of its own;
  a profile keeps the place where it plugs in. Unknown versions are never
  assumed to be either: they get Version Negotiation.
- **TLS gives secrets, QUIC protects packets.** TLS runs in its QUIC mode
  (`TLSQUIC`, `protocol::tls::quic`): handshake bytes by encryption level,
  secrets by level and direction, no records. The connection derives keys
  with the profile's labels (`QUICSecret`) and keeps the CRYPTO streams.
- **Building blocks are usable alone**: the range set, the send and receive
  buffers of streams, flow control credits, the recovery (RTT, loss
  detection, NewReno, pacer), packet protection and tokens are types of
  their own, each with its RFC rule.

## Decisions

### TLS in QUIC mode (RFC 9001 §4, §8)

- The QUIC rules live in TLS where they must: the `quic_transport_parameters`
  extension (refused over records, required with QUIC), TLS 1.3 only, ALPN
  required, no middlebox compatibility mode (a session ID is
  PROTOCOL_VIOLATION), no EndOfEarlyData, KeyUpdate refused, no
  post-handshake authentication, tickets of `max_early_data_size`
  0xffffffff. Everything else of TLS is unchanged; key installation goes
  through one function (`TLS13Authentication::install`) that either keys
  records or hands the secret over.
- A ClientHello after a HelloRetryRequest keeps the transport parameters
  (`illegal_parameter` otherwise): RFC 9846 §4.1.2 lists what it may
  change. A server under QUIC never requests a certificate after the
  handshake, even from a client that offers post_handshake_auth; a
  NewSessionTicket's early_data extension, when there, must be 0xffffffff;
  a HelloRequest is `unexpected_message`, not TLS 1.2's request to ignore;
  `TLSConnection::receive` (records) is refused.
- A ticket of a connection over records can resume one over QUIC: TLS sees
  no difference (RFC 9001 does not forbid it), and 0-RTT still needs the
  same application protocol and the same `TLSSession::application`, which
  QUIC fills with its limits, so such a ticket never carries early data.
  Rejected alternative: a marker of the transport in tickets — it would add
  a field to every ticket for a case that has no risk left.
- `TLSError::Transport` is a rule of the carrier broken (QUIC's
  PROTOCOL_VIOLATION), not a TLS alert. A key change with handshake data of
  the previous level left over is this error under QUIC and
  `unexpected_message` over records (`TLSRecordLayer::check_boundary`).
- **0-RTT's state is `TLSSession::application`**: what a server seals in its
  tickets and compares before accepting early data, and what a client keeps
  with them. QUIC puts the limits of the server's transport parameters
  there (`QUICConnection::remembered`): the server refuses 0-RTT if its
  limits changed, and the client applies the remembered limits to its 0-RTT
  data, then checks that the server kept them (RFC 9000 §7.4.1). Rejected
  alternative: an opaque per-protocol "early data context" on the server
  only — the client still needs the remembered values.

### Connections

- **The server's 1-RTT keys wait for both directions.** TLS gives the
  server's write secret before the read secret; the connection builds the
  1-RTT keys (with the next read key, RFC 9001 §6.3) once both are there.
  So the server sends nothing in 1-RTT before the handshake completes
  (0.5-RTT data). The gain of 0.5-RTT is small, and keeping key phases whole
  avoids a half-built state.
- **One packet per space per datagram**, coalesced in the order Initial,
  Handshake, application (RFC 9000 §12.2). Frames are chosen first, then
  the header (whose Length is then known) and the protection. Datagrams with
  an ack-eliciting Initial, a PATH_CHALLENGE or a PATH_RESPONSE are padded to
  1200 bytes in their last packet (§8.2, §14.1).
- **Acknowledgments**: Initial and Handshake at once, application packets
  after two ack-eliciting ones, out of order or CE-marked at once, the rest
  within max_ack_delay (§13.2.1). An ACK goes along with anything else sent.
  Ranges are kept up to `maximum_received_ranges`, the oldest dropped with a
  floor below which packets count as duplicates (§13.2.3); once an ACK of
  ours is acknowledged, its ranges are dropped (§13.2.4).
- **Loss recovery is RFC 9002 Appendix A**, per space, with the probe
  timeout of the application space armed only once the handshake is
  confirmed. Probes resend the CRYPTO data in flight rather than only PING,
  so that a lost flight is repaired by the probe itself. The backoff counts
  for the loss detection timer only: the idle timeout, closing and draining,
  and the life of old keys count in three probe timeouts without backoff
  (`QUICRecovery::base_probe_timeout`). Rejected alternative: the backed-off
  value, which RFC 9000 §10.1 could be read to allow — against a peer that
  vanished it grows faster than the time spent, so the idle timeout never
  fires. `pto_count` is reset by an acknowledgment only once the peer
  validated this end's address (RFC 9002 Appendix A.7).
- **Packets neither ack-eliciting nor in flight are not kept** (ACK-only
  packets): nothing of them goes again, and peers need not acknowledge them
  (RFC 9000 §13.2.1), so a receiver that only acknowledges would otherwise
  keep every one of them. Their ACK frames then never trim the ranges
  reported; `maximum_received_ranges` bounds those.
- **Duplicates**: once an ACK frame of this end is acknowledged, the ranges
  below its largest are dropped, and packets below it count as duplicates
  (`QUICReceivedPackets::floor`). A late packet below it that never arrived
  is dropped too: RFC 9000 §12.3 requires discarding a packet unless it is
  certain that its number was not processed, and the ranges that would tell
  are gone. Rejected alternative: a floor for reporting only, which would
  accept such packets but not acknowledge them, against §13.2.1.
- **The congestion window holds**: data goes only within what the window
  has left (RFC 9002 §7), probes excepted; acknowledgments go regardless. A
  server sends no ack-eliciting Initial while its amplification budget is
  below 1200 bytes, as such a datagram must reach 1200 (RFC 9000 §14.1).
- **Timers wait only for what can be sent**: the deadline of an
  acknowledgment counts only for a space that can carry it now (1-RTT for
  the application space: 0-RTT packets carry no ACK), and neither it nor
  pacing counts while the amplification limit stops all sending; otherwise
  `poll_timeout` would return a time already past again and again.
- **Persistent congestion** is judged on the packets one acknowledgment or
  timeout declares lost, with the acknowledged ones of the same event
  excluding it: a packet acknowledged earlier between two lost ones would
  have had the first declared lost then.
- **Pacing** spreads datagrams at 1.25 × cwnd / smoothed_rtt with a burst of
  the initial window. Its release time is a timer only when the congestion
  window has room and data waits; a full window waits for acknowledgments.
  The wait is rounded up and the credit earned rounded down, so that the
  credit at the release time is always enough: rounding both down left it a
  byte short forever, a timer firing every few hundred nanoseconds.
- **Key updates**: the next read key is computed ahead, the previous one is
  kept for three probe timeouts (§6.5). A packet of the other phase is the
  previous phase's when its number is below the first of the current phase,
  or when no packet of the current phase came yet — after this end's own
  update, the peer's packets of the old phase keep coming until it sees the
  update. A packet that opens with the old key though newer keys protected
  lower numbers is KEY_UPDATE_ERROR (§6.5). An update by the peer is followed
  even before this end confirmed the handshake: RFC 9001 forbids initiating
  one then, not answering. This end updates only once a packet it sent with
  the current keys was acknowledged (§6.1), so never twice in a row; it does
  on its own at nine tenths of the AEAD's confidentiality limit. The
  integrity limit is the smallest of the keys used so far, across all keys
  (§6.6).
- **Migration**: only after the handshake is confirmed, and only of clients
  (RFC 9000 §9). A server moves to a new address only for the highest
  numbered packet that is not probing (§9.3), so that a late packet from the
  old address does not move it back; it takes a new connection ID when it
  has one, validates the path with PATH_CHALLENGE, limits itself to three
  times what came from it until then, and resets congestion control and RTT
  unless only the port changed (§9.4). A PATH_RESPONSE goes to the address
  its challenge came from (§8.2.2): there with the rest when the server moved
  there, alone otherwise (§9.1), then within three times the datagram that
  carried the challenge (`QUICPathResponse::limit`), padded to 1200 bytes
  only within that (§8.2.1), so that a forged source address gains nothing.
- **Connection IDs**: of the peer's, only the token of the one in use
  identifies a stateless reset (§10.3.1). A retired ID stays retired: the
  sequence numbers received since Retire Prior To are kept as ranges, so a
  NEW_CONNECTION_ID sent again does not bring one back (§5.1.2). Retirements
  not yet acknowledged are limited to twice `active_connection_id_limit`, as
  §5.1.2 asks endpoints to allow, beyond which the peer is closed with
  CONNECTION_ID_LIMIT_ERROR. A preferred address carries the server's ID of
  sequence 1 (§5.1.1): a server makes it when configured with one, a client
  holds it like any other but does not move to the address (§9.6 makes that
  optional).
- **Streams that stop**: `stream_stop` drops what arrives afterwards, which
  counts as read so that the connection's credit comes back (§4.1); the
  stream ends once its size is known. Rejected alternative: holding the
  stream until a RESET_STREAM, which a peer whose data was all sent never
  sends (§3.5), so its credit and stream slot stayed taken. A RESET_STREAM
  once all data arrived changes nothing (§3.2 lets an implementation choose),
  and the application reads the data.
- **Coalesced packets after a CONNECTION_CLOSE** are not read: a peer that
  closed sent nothing more that counts (§10.2.2). Long header packets whose
  Source Connection ID is not the peer's first are dropped (§7.2).
- **Version Negotiation restarts the client in place** (RFC 9368 §2.4 allows
  one object for the two conceptual connections): it keeps what it needs to
  start again (`QUICRestart`) and checks the server's Version Information
  against the choice it would have made (§4). It ignores a Version
  Negotiation that lists the version it tried, and any after a Retry or a
  first restart.
- **Retry**: the client keeps no packet number reset and resends its CRYPTO
  data and 0-RTT under the new Initial keys (RFC 9000 §17.2.5.3); it still
  learns the server's Source Connection ID from the server's first Initial,
  which the transport parameters then authenticate (§7.3).
- **Extension frames** can be sent (`send_extension_frame`, RFC 9000
  §19.21): ack-eliciting, congestion controlled, not sent again. Receiving
  unknown frame types is still FRAME_ENCODING_ERROR. The tests use it to send
  frames that break rules.

### Endpoints

- **Stateless work stays stateless.** Version Negotiation goes only to
  datagrams of 1200 bytes and more (RFC 9000 §14.1) and lists a reserved
  version (§6.3); Retry keeps no state, its token being sealed with
  AES-256-GCM under the deployment's key (the client's address as
  associated data, the original and Retry connection IDs, the port and the
  version inside). NEW_TOKEN tokens bind the address but not the port, as
  later connections come from other ports, and last a day.
- **Version Negotiation is never answered with another** (RFC 9000 §6.1),
  and a client takes one only if it carries its connection IDs back,
  swapped (§17.2.1).
- **An invalid Retry token is refused at once**: a token of this server of
  the Retry kind that does not hold for the Initial (another Destination
  Connection ID, another version, too old) is answered with an Initial
  carrying CONNECTION_CLOSE with INVALID_TOKEN, sealed with the Initial keys
  of the client's ID, keeping no state (§8.1.2). Tokens that do not open
  are taken as no token (§8.1.3): they may come from another server.
- **Routes change by difference**: the endpoint keeps the IDs routed to each
  connection, so that updating one connection's routes does not walk all.
- **A stateless reset reaches its connection by its token**: an unroutable
  datagram from a connection's peer is offered to the connection, which
  closes if the last 16 bytes are a token of the peer (§10.3.1). Resets are
  sent only with `reset_key`, smaller than what triggered them, and never to
  datagrams of 22 bytes or less.
- Closed connections stay until the application has taken their events.

## Tests

- RFC 9001 Appendix A and RFC 9369 Appendix A: Initial secrets and keys, the
  client's and server's Initial packets byte for byte, the Retry Integrity
  Tag, and the ChaCha20 short header packet with its key update, for both
  versions.
- The frame table of RFC 9000 §12.4 read from the RFC text and compared with
  `QUICFrameType::permits` and the N, C, P and F columns.
- Codecs against the RFC's examples (varints, packet numbers, the
  ClientHello's transport parameters of RFC 9001 Appendix A.2) and every
  rule that makes a frame or parameter malformed.
- TLS in QUIC mode on its own (`tests/protocol/tls/quic.rs`).
- Connections over a simulated network with latency and seeded random loss;
  the rules of each frame checked by a client that breaks them; endpoints
  for Retry, NEW_TOKEN, Version Negotiation, stateless resets, 0-RTT accepted
  and rejected, NAT rebinding and active migration, key updates, DATAGRAM
  frames and the greasing of the QUIC bit.
- Fuzz targets: `protocol-quic-codec` (round trips of frames, parameters and
  varints; packet numbers recovered) and `protocol-quic-connection` (any
  datagram to both ends, and real handshakes whose datagrams are changed).
- Interoperability: `examples/quic.sh` runs `examples/quic.rs` against
  itself (versions 1 and 2, Retry, DATAGRAM frames), OpenSSL's QUIC client
  (`s_client -quic`: a stream echoed, with and without Retry) and curl's
  (ngtcp2: the handshake and HTTP/3's streams, Retry, Version Negotiation to
  a server of version 2 only). Neither has a QUIC server on the command
  line, so the client is checked against this crate's server only. Until
  HTTP/3 exists, the server reads curl's streams and never answers
  (`--sink`); curl then closes with NO_ERROR when its time runs out. Echoing
  curl's request back makes its HTTP/3 layer close with INTERNAL_ERROR, as
  the echo is not a response.
