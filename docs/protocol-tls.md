# TLS: `umilib::protocol::tls`

`protocol-tls` (no `std`) is Transport Layer Security without doing any
I/O: TLS 1.3 (RFC 9846, feature `protocol-tls-v1_3`) and TLS 1.2 (RFC 5246,
feature `protocol-tls-v1_2`). `protocol-tls` is both. TLS 1.0 and 1.1 are not
implemented (RFC 8996).

| Type | What it is |
| --- | --- |
| `TLSConnection` | A client or a server connection: bytes in, bytes out, application data, events |
| `TLSConfig` | What both ends configure: versions, cipher suites, groups, signature schemes, ALPN, limits |
| `TLSClientConfig`, `TLSServerConfig` | The configurations of each end |
| `TLSPathVerifier`, `TLSCertificateVerifier` | The check of a peer's certificate chain, and the trait to replace it |
| `TLSCertifiedKey` | A certificate chain and its private key, with an OCSP response to staple |
| `TLSSession` | What was negotiated (`connection.session`) |
| `TLSTicketKeys`, `TLSTicketer` | How a server seals session tickets |
| `TLSSessionCache`, `TLSSessionStore` | Where a client keeps tickets |
| `TLSReplayCache`, `TLSAntiReplay` | How a server refuses replayed early data |
| `TLSECHConfig`, `TLSECHKey`, `TLSECHStatus` | Encrypted ClientHello (RFC 9849) |
| `TLSRule`, `TLSNamePattern` | The rule that routes connections by server name and ALPN |
| `TLSClientHello`, `TLSServerHello`, `TLSExtension`, `TLSRecord`, ... | The codecs of the messages, for tools that read or write them |
| `v1_3::*`, `v1_2::*` | The messages, key schedules and state machines of each version |

## What is implemented

| | TLS 1.3 | TLS 1.2 |
| --- | --- | --- |
| Key exchange | X25519, X448, P-256, P-384, P-521, FFDHE (with `crypto-dh`), X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 (RFC 10024, with `crypto-hybrid`) | ECDHE over X25519, X448, P-256, P-384, P-521 only |
| Cipher suites | AES-128/256-GCM, ChaCha20-Poly1305, AES-128-CCM and CCM_8 (with `crypto-mode-ccm`) | ECDHE_ECDSA and ECDHE_RSA with AES-128/256-GCM and ChaCha20-Poly1305 (RFC 9325) |
| Certificates | RSA (PKCS #1 v1.5 for certificates only, PSS), ECDSA P-256/384/521, Ed25519, Ed448 | The same; RSASSA-PKCS1-v1_5 also signs |
| Client authentication | In the handshake and after it (RFC 9846 §4.6.2) | In the handshake |
| Resumption | Tickets, PSK with (EC)DHE or alone, 0-RTT | No (see below) |
| Other | HelloRetryRequest, KeyUpdate, exporters, middlebox compatibility, ECH | Extended main secret, secure renegotiation signalling, downgrade protection, exporters |

Both: ALPN (RFC 7301), `server_name` (RFC 6066), `record_size_limit` (RFC
8449), OCSP stapling (`status_request`, RFC 6066 §8).

Not implemented, on purpose:

- TLS 1.2 resumption (session IDs, RFC 5077 tickets) and renegotiation: a
  HelloRequest or a new ClientHello after the handshake is answered with the
  warning `no_renegotiation`.
- External PSKs (keys agreed outside TLS). Their safe use needs the importer
  of RFC 9258; resumption PSKs are all this crate makes.
- Signature schemes of ML-DSA and the key exchange of ML-KEM alone, which
  are not RFCs yet.
- Raw public keys (RFC 7250), compression, and TLS 1.2 key exchanges other
  than ECDHE.

## A connection

A connection does no I/O. Give it what arrives with `receive`, and send what
`transmit` writes after each call that may produce bytes (`receive`, `send`,
`close`, `update_keys`, `request_certificate`):

```rust
use std::sync::Arc;
use umilib::protocol::tls::{TLSClientConfig, TLSConnection, TLSEvent, TLSPathVerifier};

let verifier = Arc::new(TLSPathVerifier::servers(anchors));
let config = Arc::new(TLSClientConfig::new(verifier));
let mut connection = TLSConnection::client(config, Some("example.com"), random, now_seconds)?;
loop {
    let mut out = Vec::new();
    connection.transmit(&mut out)?;
    socket.write_all(&out)?;
    let read = socket.read(&mut buffer)?;
    connection.receive(&buffer[..read])?;
    while let Some(event) = connection.poll_event() {
        match event {
            TLSEvent::Connected => connection.send(b"GET / HTTP/1.1\r\n...")?,
            TLSEvent::Readable => { let count = connection.read(&mut data); /* ... */ }
            TLSEvent::PeerClosed => { /* no more data will come */ }
            TLSEvent::Authenticated => { /* a server's certificate request was answered */ }
        }
    }
}
```

`random` is any `Random + Send` (`platform::native::Random`, the operating system's, with `platform`).
`time` is seconds since 1970: certificates are checked at that time, and
tickets age from it. A server is `TLSConnection::server(config, random, time)`.

When `receive` fails, the alert the error calls for is queued: send what
`transmit` writes, then close the transport. `TLSError::Protocol(alert)` is
something the peer did wrong, `TLSError::Alert(alert)` an alert the peer
sent; `connection.error` keeps the error.

`close` sends `close_notify`; reading goes on until the peer closes too
(`PeerClosed`). `export(label, context, out)` derives keying material (RFC
9846 §7.5, RFC 5705); in TLS 1.3 no context and an empty context are the
same, in TLS 1.2 they are not.

## Configuration

`TLSConfig::default()` has every version, cipher suite, group and signature
scheme compiled in, most preferred first. Everything is a field:

| Field | Default |
| --- | --- |
| `versions` | TLS 1.3, TLS 1.2 |
| `cipher_suites` | The TLS 1.3 suites (CCM_8 left out), then the TLS 1.2 ones with ECDHE_RSA_WITH_AES_128_GCM first (RFC 9325 §4.2.1) |
| `groups` | X25519MLKEM768, X25519, P-256, P-384, P-521, X448 |
| `signature_schemes` | ECDSA, RSA-PSS, RSA-PKCS1 (TLS 1.2 only), EdDSA |
| `protocols` | None (no ALPN) |
| `maximum_handshake_message` | 64 KiB |
| `record_size_limit` | 2^14 |
| `maximum_buffered_data` | 1 MiB of unread application data |
| `maximum_key_updates` | 32 KeyUpdates in a row without data |
| `require_extended_main_secret` | Yes (TLS 1.2, RFC 7627) |
| `maximum_ignored_records` | 32 records in a row that change nothing (warning alerts, ChangeCipherSpecs, HelloRequests) without application data between |
| `psk_modes` | `psk_dhe_ke` only |

`TLSClientConfig::new(verifier)` adds the client's settings:
`key_share_groups` (the first two groups when the first is a hybrid, the
first otherwise), `certificate`, `middlebox_compatibility` (on),
`send_server_name` (on), `request_certificate_status` (off),
`post_handshake_authentication` (off), `sessions` (none), `early_data`
(off), `ech_configs` (none), `ech_grease` (off).

`TLSServerConfig::new(certificates)` adds the server's:
`client_authentication` (`Off`, `Optional`, `Required`), `client_verifier`,
`prefer_own_cipher_suites` (on), `tickets` (none), `ticket_count` (2),
`ticket_lifetime` (7200 s), `maximum_early_data` (0), `anti_replay`,
`freshness_window` (10 s), `ech_keys`.

`check()` refuses what cannot work (`TLSError::Config`); `TLSConnection`
checks it.

The server chooses the certificate that names the `server_name` the client
asked for and signs with a scheme both the client and its own
`signature_schemes` accept; otherwise the first that signs.
`session.server_name` is the name the client asked for, whether or not a
certificate names it. In TLS 1.2 the certificate must also suit the cipher suite (an
RSA key for ECDHE_RSA, an ECDSA or EdDSA key for ECDHE_ECDSA) and an ECDSA
certificate's curve must be one the client lists (RFC 8422 §5.3).

## Certificates

`TLSPathVerifier::servers(anchors)` validates the server's chain to a trust
anchor (RFC 5280) for the Web PKI and the name connected to (RFC 9525): a
DNS name, or an IP address, which is never sent as `server_name`.
`TLSPathVerifier::clients(anchors)` validates clients' chains with
`id-kp-clientAuth`. Its `config` is the template of every validation.
Implement `TLSCertificateVerifier` for pinning or other policies.

A client that sets `request_certificate_status` asks for an OCSP response
(RFC 6066 §8); a server staples `TLSCertifiedKey::ocsp` when asked. With
`auth-cert-ocsp`, `TLSPathVerifier` checks the stapled response:
`certificate_revoked` if it says so, `bad_certificate_status_response` if it
cannot be read or its signer is not authorized. The response is in
`session.certificate_status`.

## Client authentication

`client_authentication: Required` or `Optional` with a `client_verifier`
asks for the client's certificate in the handshake. A client without one
that fits sends none; `Required` then fails with `certificate_required`
(TLS 1.3) or `handshake_failure` (TLS 1.2).

In TLS 1.3, a client with `post_handshake_authentication` lets the server
call `request_certificate()` at any time; the client answers with its
`certificate` (or none), and the server gets `TLSEvent::Authenticated` with
the chain in `session.peer_certificates`.

## Resumption and early data (TLS 1.3)

A server with `tickets` (`TLSTicketKeys` seals tickets with AES-256-GCM)
sends `ticket_count` NewSessionTickets after each handshake. A client with
`sessions` (a `TLSSessionCache`, or your own `TLSSessionStore`) keeps them by
the name connected to, and offers one (once: it is taken from the store) the
next time. `session.resumed` says whether the server accepted it; a resumed
session is authenticated by its key, and its `peer_certificates` are those of
the original handshake. Rotate ticket keys by putting the new key first in
`TLSTicketKeys::keys` and keeping the old one until its tickets expire.

A server that requires client certificates does not resume a session that
had none.

Early data (0-RTT) is sent before the handshake completes: a client with
`early_data` calls `send` right after creating the connection, within the
ticket's `maximum_early_data`. **Early data can be replayed by an attacker**
(RFC 9846 §8): send only what is safe to repeat. A server accepts it only
with `maximum_early_data` above 0 and an `anti_replay` (`TLSReplayCache`
records each ClientHello for twice its window and two seconds, as long as a
replay of it could still be fresh, and refuses a second one), from a fresh
ticket of the same suite and ALPN. A ticket's allowance of early data holds
even if the server now allows less; refused early data is skipped. The server
reads accepted early data before `Connected`. `session.early_data` is then
`Accepted` or `Rejected`; a client whose early data was rejected must send it
again after `Connected` if it still wants to.

## Encrypted ClientHello (RFC 9849)

A server's ECH configuration (an `ECHConfigList`, usually from its DNS HTTPS
record) in `TLSClientConfig::ech_configs` encrypts the ClientHello with HPKE
(`crypto-hpke`): the network sees only the configuration's public name. A
server holds `TLSECHKey`s (`TLSECHCipher::generate` makes one; the
configuration to publish is `key.config`).

- Accepted: `session.ech` is `Accepted`, and the connection is to the name
  asked for.
- Rejected (the server could not decrypt): the handshake completes for the
  public name, then the connection fails with `ech_required`, and only then
  is `session.ech` `Rejected { retry_configs }`: open a new connection with
  `retry_configs` if the server sent them, and without ECH otherwise. A
  connection that fails in any other way leaves `session.ech` at `Offered`:
  a server that did not prove it holds the public name cannot disable ECH
  nor give configurations (RFC 9849 §6.1.6).

`ech_grease` sends a GREASE extension when no configuration is used, so that
connections without ECH look like those with it.

A ClientHelloInner must offer only TLS 1.3 (RFC 9849 §6.1), and a server
refuses one that offers TLS 1.2 with `illegal_parameter` (§7.1). OpenSSL 4.1's
client offers in its inner hello the versions of its outer one, TLS 1.2
included, unless TLS 1.2 is disabled (`-tls1_3`, or a minimum version of TLS
1.3): umilib's server refuses it as the RFC requires.

## Record size limit

`record_size_limit` below 2^14 is advertised (RFC 8449); it applies once the
peer has acknowledged it. Each end writes records within the limit the peer
advertised.

## TLS 1.2

TLS 1.2 is for peers that lack TLS 1.3. It requires the extended main
secret (RFC 7627) unless `require_extended_main_secret` is off, signals
secure renegotiation and refuses renegotiation (RFC 5746), refuses SHA-1
signatures (RFC 9155), and answers a fallback signal with
`inappropriate_fallback` when it could have used TLS 1.3 (RFC 7507). A
server that supports TLS 1.3 marks the random of a TLS 1.2 ServerHello, and a
client that offered TLS 1.3 refuses such a ServerHello (RFC 9846 §4.2.3).

## Routing

`TLSRule::new(TLSNamePattern::parse("*.example.com")).with_protocol(b"h2")`
matches a ClientHello (before the handshake: the name asked for and the
protocols offered) or a `TLSSession` (after it: the name and the protocol
negotiated). `*.example.com` matches one label (`a.example.com`, not
`example.com` nor `a.b.example.com`); `TLSNamePattern::None` matches a client
that sent no name.

## C and Python

The C functions are `umilib_protocol_tls_*` (`include/umilib/protocol/tls.h`):
handles for the configurations, verifier, certified key, ECH key, connection
and rule; a connection's randomness is an HMAC-DRBG seeded by the caller with
at least 48 bytes from the operating system. `umilib.protocol.tls` mirrors
them in Python; `TLSConnection.close()` sends `close_notify` and `free()`
releases the object.
