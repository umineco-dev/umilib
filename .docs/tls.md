# TLS

How `protocol::tls` is built and why. The user's view is `docs/protocol-tls.md`.

## Shape

- **No I/O.** `TLSConnection` takes bytes (`receive`) and gives bytes
  (`transmit`), like the TCP connection: the same code serves a socket, a
  QUIC stream later, and uKernel. Randomness (`Random`) and the time
  (seconds) are given to it.
- **One driver, engines per version.** `TLSConnection` reads records
  (`TLSRecordLayer`), joins handshake messages (`TLSHandshakeReassembler`)
  and hands them to a `Box<dyn TLSHandshakeProtocol>`, which returns its next
  state: `TLSClientStart`/`TLSServerStart` (the hellos, shared by the
  versions), then `TLS13Client`/`TLS13Server`/`TLS12Client`/`TLS12Server`,
  then `TLS13Established`/`TLS12Established`. A version is a module of its
  own; the root never knows a version's states. A new version is a new
  module and a match arm in the two start states.
- **Record protection is a trait** (`TLSRecordProtector`): the layer
  installs a reader and a writer and does not know the version's nonce or
  additional data. The writer is replaced at each key change; a
  ChangeCipherSpec is never protected.
- **Errors carry their alert.** `TLSError::Protocol(alert)` is decided where
  the rule is checked, with the alert the RFC names there, so the driver
  sends the right alert without a mapping table.

## Decisions

### TLS 1.2

- **Only ECDHE with AEAD** (RFC 9325 §4.1): no RSA key exchange, no CBC,
  no DHE (finite-field DHE in TLS 1.2 has no negotiated groups and the
  Raccoon attack), no static ECDH.
- **The extended main secret is required by default** (RFC 7627, RFC 9325
  §3.5): without it the triple handshake attack works. A peer without it
  fails with `handshake_failure`; `require_extended_main_secret: false`
  allows it for old peers.
- **Renegotiation is refused, not implemented**: it brings the bugs of two
  handshakes on one connection for almost no use. Secure renegotiation is
  still signalled (an empty `renegotiation_info`), which RFC 9325 requires;
  a renegotiation is answered with the warning `no_renegotiation`.
- **No TLS 1.2 resumption.** Session IDs need a server cache, RFC 5077
  tickets carry the main secret (no forward secrecy unless keys rotate
  fast), and RFC 9846 obsoletes both. TLS 1.3 resumption covers clients that
  can resume.
- **A HelloRequest during the handshake is ignored** (RFC 5246 §7.4.1.1)
  and not hashed.
- **The certificate's curve must be one the client lists** (RFC 8422 §5.3).
  Our client lists P-256 alongside X25519 by default for that reason.
- The server marks its random with the downgrade sentinel only when TLS 1.3
  is enabled in its configuration (it is then "a TLS 1.3 server"); the
  client checks it only when it offered TLS 1.3.

### Record size limit

- The own limit is enforced **only after the peer has seen it**: before,
  a peer without RFC 8449 may send 2^14 bytes. The layer starts with 2^14
  and the engines lower it when the extension is acknowledged.
- A client offering TLS 1.3 and 1.2 advertises `limit + 1` (the value of
  TLS 1.3, which counts the content type). If TLS 1.2 is negotiated it
  accepts `limit + 1` bytes: one byte more than configured, rather than
  refusing records the server sized from the value it saw.
- Values above the version's maximum are clamped, not refused (RFC 8449 §4
  lets a client refuse; a server must not).

### Resumption and early data

- **Tickets are self-encrypted** (`TLSTicketKeys`, AES-256-GCM, a 16-byte
  key name, a random nonce): no server-side state, and rotation by key name.
  The state (`TLSSessionState`) carries the PSK, the time, the suite, the
  ALPN, the name asked for, and the peer's chain (so that a resumed session
  still has `peer_certificates`). `TLSTicketer` lets an application use a
  shared store instead.
- **The name asked for must match** the ticket's (RFC 6066 §3 rules for
  resumption): a ticket issued for one host is not used for another.
- **A server that requires client certificates does not resume a session
  without one**: otherwise a ticket issued under `Optional` (or before the
  configuration changed) would skip the requirement.
- **`psk_dhe_ke` only by default**: `psk_ke` has no forward secrecy. Both
  ends can enable it in `psk_modes`; a `psk_ke` ClientHello may then omit
  `key_share`, `supported_groups` and `signature_algorithms` (RFC 9846 §9.2),
  so the server's selection treats them as optional when a PSK is offered.
- **The client offers one ticket** and removes it from its store (single
  use, RFC 9846 Appendix C.4). Several identities would only help servers
  that lost a key.
- **Anti-replay is ClientHello recording keyed by the binder** (RFC 9846
  §8.2): the binder is unique per ClientHello and authenticated. Recording
  is bounded by the freshness window (§8.3); when the record is full, early
  data is refused, which is always safe. Times are whole seconds, so the
  freshness window should be at least a few seconds (10 by default).
- **Early data is accepted only from the first identity, without a
  HelloRetryRequest, of the ticket's suite and ALPN, fresh, and not a
  replay**, and only when the server configured `maximum_early_data`.
- **Refused early data is skipped** up to the configured maximum: records
  that do not decrypt with the handshake keys, and after a
  HelloRetryRequest unprotected application data records. A skipped record
  counts as its plaintext (`TLSRecordLayer::skipped`, at least one byte, so
  that a run of tiny records cannot go on for ever).
- **The client sends early data only before the ServerHello.** It could
  continue until the server's Finished, but the gain is small and the
  state machine simpler.

### Post-handshake authentication

- Only one request at a time: the server waits for the answer before
  asking again. Multiple outstanding requests (allowed by RFC 9846) would
  need a table of transcripts for little use.
- Each request continues the handshake's transcript (through the client's
  Finished), as §4.4 defines; the request context is 32 random bytes.

### OCSP stapling

- Asking is off by default: a client that asks and verifies may fail on a
  bad staple, which the application should choose.
- With `auth-cert-ocsp`, `TLSPathVerifier` uses the staple as a revocation
  source of path validation, with revocation checking on for that
  validation but not required: a staple that says nothing current about the
  certificate leaves the decision to the configuration.

### ECH (RFC 9849)

- **The codecs are always compiled; HPKE only with `crypto-hpke`.** The
  configuration and status types exist without it, so configurations do not
  change shape with features.
- **HPKE is chosen at run time** (`TLSECHCipher`): macros expand the KEM,
  KDF and AEAD identifiers to the generic `HPKE<K, F, A>`, and the contexts
  are boxed behind `TLSECHSealer`/`TLSECHOpener`.
- **The ClientHelloOuter** has the public name, a fresh random, the inner
  session ID, the same key shares (so a server that rejects ECH completes
  the handshake), `early_data` and a GREASE `pre_shared_key` when the inner
  has them (§6.1), and **neither ALPN nor `post_handshake_auth`**, which
  could identify the service (§10.5).
- **The client does not compress** inner extensions (`ech_outer_extensions`):
  the saving is a hybrid key share's size and the risk is linking inner and
  outer. The server **does** expand them (other clients do), in linear time
  with a cursor over the outer extensions (Appendix A), refusing references
  that are missing, repeated, out of order, or to ECH itself.
- **Only a server that can use TLS 1.3 accepts ECH**: the inner hello offers
  only TLS 1.3, so a TLS 1.2-only server that opened it could not complete.
  It uses the outer hello instead, and the client sees a rejection.
- **A rejection completes the handshake, then fails with `ech_required`**
  (§6.1.6): the client sends its Finished (so the server sees a normal end
  and then the alert), but never reports success, keeps no ticket, and sends
  no certificate (§6.1.7). The retry configurations are in the session for
  the application.
- The HelloRetryRequest's confirmation is computed over the restarted
  transcript (`message_hash` of ClientHelloInner1, then the
  HelloRetryRequest with the confirmation zeroed), as RFC 8446 §4.4.1 defines
  the transcript after a retry.
- GREASE is off by default, like the other options that change what a
  ClientHello looks like.

### Robustness (from the independent review)

- **The record boundary of a ServerHello is a TLS 1.3 rule** (RFC 9846
  §5.1: keys change after it). TLS 1.2 servers may send their whole flight
  in one record (RFC 5246 §6.2.1), so the check waits for the version.
- **Records and handshake messages are read at an offset** and the buffers
  compacted once per call: draining each record from the front made a burst
  of tiny records cost quadratic time.
- **Records that change nothing are counted** (`maximum_ignored_records`):
  warning alerts, ChangeCipherSpecs and HelloRequests are allowed by the
  RFCs but would otherwise let a peer keep a connection busy for ever (the
  "SSL Death Alert" class). Application data resets the count.
- **Duplicate checks sort** instead of comparing each entry with the
  previous ones: a 64 KiB ClientHello holds 16,000 extensions.
- **After the peer's close_notify everything is ignored**, and after one's
  own nothing is sent, not even an alert or the KeyUpdate a peer asked for
  (RFC 9846 §6.1).
- **A protected ChangeCipherSpec is refused** (RFC 9846 §5).
- **The server's record limit waits for the end of accepted early data**:
  the client sized its 0-RTT records before it saw the limit; refused early
  data may come in records of the largest size.
- **A ticket's allowance of early data is honoured** although the server's
  configuration may have lowered it since; refused early data is skipped up
  to the larger of both.
- **ClientHello recording keeps a binder 2 × window + 2 seconds**: a
  ClientHello may arrive up to a window early, and its replay up to a window
  late, so a record of one window could forget a binder whose replay is
  still fresh.
- **ECH's rejection is published only at `ech_required`**, after the
  server's Finished: an attacker without the public name's certificate
  could otherwise make an application retry with its configurations or
  without ECH (RFC 9849 §6.1.6: "MUST NOT use the retry configurations").
- **A client that sent early data fails when TLS 1.2 is chosen** (RFC 9846
  Appendix E.3).
- **Each end signs only with its own `signature_schemes`**, intersected with
  the peer's.

### C ABI

- A connection's randomness is an HMAC-DRBG seeded with at least 48 bytes
  from the caller (32 of entropy, 16 of nonce, SP 800-90A §8.6.7): the C
  ABI has no OS access without `platform`, and a DRBG avoids a callback per
  random byte.
- A failed connection's alert is read with `..._connection_error` instead of
  one status per alert: statuses are static.
- `TLSCertifiedKey` takes ownership of the private key handle (private keys
  cannot be cloned); copies made for configurations go through PKCS #8.

## Rejected alternatives

- **A typestate API** (`TLSClient<Handshaking>` → `TLSClient<Open>`): it
  does not fit a connection driven by bytes that arrive at any time, nor the
  C ABI.
- **One state machine for both versions** with `if version` branches: the
  versions share little after the hellos, and branches would mix their rules.
- **Keeping all handshake messages for TLS 1.2's CertificateVerify** on
  every connection: only kept while a client certificate can come.

## Tests

- RFC 8448: every secret of every trace; the client of sections 3, 4 (0-RTT
  resumption, from the ticket the section 3 client stores) and 7 byte for
  byte; the server of section 4 up to its reading of the early data and the
  refusal of a replay.
- Loopback tests for every group, suite and key of both versions, the
  checks of ClientHellos and ServerHellos crafted to break one rule each,
  resumption, early data, ECH (accepted, rejected with retry configurations,
  after a HelloRetryRequest, by TLS 1.2, GREASE), OCSP responses made by
  OpenSSL (`certificates/ocsp.sh`), record size limits, post-handshake
  authentication and routing.
- No ECH test vectors exist in RFC 9849; interoperability is the external
  check: `examples/tls.sh` runs `examples/tls.rs` against OpenSSL 4.1
  (`s_client`, `s_server`, `ech`) and curl in both directions (groups and
  hybrids, suites of both versions, ALPN, client and post-handshake
  authentication, resumption and early data, OCSP, KeyUpdate, ECH accepted
  and rejected). OpenSSL's client compresses `supported_versions` into its
  ClientHelloInner by reference to the outer one, so its inner hello offers
  TLS 1.2 unless TLS 1.2 is disabled; umilib refuses it (`illegal_parameter`,
  RFC 9849 §7.1) rather than relax a MUST, and the script checks both.
- Fuzz targets: `protocol-tls-codec` (round trips) and
  `protocol-tls-handshake` (real handshakes with corrupted flights).
