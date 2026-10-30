# CoAP

How `protocol::coap` is built and why. The user's view is `docs/protocol-coap.md`.

## Shape

- **One endpoint is client and server.** CoAP's message layer is the same
  for both (RFC 7252 §4): Message IDs, retransmission, deduplication, ACK
  and RST. Requests and responses ride on it. `CoAPEndpoint` owns the
  message layer, and requests and exchanges are `u64` handles. A separate
  client and server would have duplicated the message layer, and a device
  that observes one resource and serves another needs both on one port.
- **Resources are the application's.** The endpoint tells requests and
  takes responses. `CoAPObservers` and `CoAPBlockwise` are helpers the
  application drives, not parts of the endpoint. A server built in would
  have decided routing, caching and storage for everyone. `CoAPRule`
  routes with `service::Router` instead.
- **No I/O.** Datagrams in, datagrams out, the time in `runtime::Instant`.

## Decisions

- **Deduplication keeps the reply.** A received Confirmable or
  Non-confirmable message is remembered by (peer, Message ID) for
  EXCHANGE_LIFETIME or NON_LIFETIME, with the ACK or piggybacked response
  sent for it. A duplicate gets the same bytes again (§4.5) and is not told
  to the application.
- **What ends with an event.** A Confirmable message ends with an ACK, a
  RST or a `Timeout` after MAX_RETRANSMIT. A request ends with its
  response, or with a `Timeout` after EXCHANGE_LIFETIME if only acknowledged.
  A Non-confirmable response or notification is kept only to match a RST
  (§4.3) for NON_LIFETIME, then forgotten without an event. Telling a
  `Timeout` for it was a bug: `CoAPObservers::handle` took it as the end of
  the observation, which ended every Non-confirmable observation after 145
  seconds (RFC 7641 §4.5 ends one only for a RST or an unacknowledged
  Confirmable notification).
- **The initial timeout is drawn in nanoseconds,** from ACK_TIMEOUT to
  ACK_TIMEOUT × ACK_RANDOM_FACTOR. Milliseconds were used first; they made
  an ACK_TIMEOUT below 1 ms a timeout of zero.
- **RST where §4.2 and §4.3 call for it.** These are answered with RST:
  a Confirmable message that cannot be read or processed, an empty message
  (a ping when Confirmable, §4.3), a Confirmable response no request
  awaits, and a Non-confirmable notification no observation awaits (so that
  a server learns that an observation it still notifies has been
  cancelled, RFC 7641 §3.6). A Non-confirmable message that cannot be read,
  or a Non-confirmable response without Observe that no request awaits, is
  ignored (§4.3 makes the RST optional).
- **Tokens up to `maximum_token`.** It is 8 by default, as RFC 7252 allows,
  and longer with RFC 8974. A longer token is a message-format error (RST)
  to an endpoint of 8-byte tokens, but an endpoint of extended tokens must
  not reject it, as that would say it has none (RFC 8974 §2.3): it answers
  4.00. Decoding refuses lengths over 65804.
- **NSTART counts every outstanding interaction** (§4.7): a request until
  it is acknowledged or answered, and a Confirmable separate response or
  notification until it is acknowledged (RFC 7641 §4.5.1). Counting only
  requests until their response let notifications pile up, and kept a
  request acknowledged by an empty ACK counted until its separate response.
- **Critical options (§5.4.1):** 4.02 only to a Confirmable request; a
  Non-confirmable request and a response are rejected, and a piggybacked
  response is rejected by ignoring its ACK, so the request is sent again.
  A piggybacked response of another token is ignored the same way.
- **What is malformed for its type is ignored** (§4.2): an ACK that is not
  empty nor a response, a RST that is not empty.
- **The duplicates remembered are bounded** (`maximum_seen`): when full,
  the message remembered for the shortest time left is forgotten.
- **An exchange stays until its response is written,** so that a response
  that cannot be encoded can be replaced by another rather than lost.
- **Blocks are tracked by offset, not by count** (`CoAPBlockwise`). A
  receiver may ask for smaller blocks as it goes (RFC 7959 §2.4), and the
  next block's number is the body so far divided by the size asked for.
  Counting blocks received was the first design; it asked for the wrong
  block once the size changed, which the interoperability runs found.
- **An observer keeps only the notifications that may still end it:**
  those its endpoint keeps, or has an event of not yet taken. The first
  design kept every notification's handle, which grew without bound.
- **Observe freshness follows RFC 7641 §3.4 exactly.** Order is 24-bit
  serial order, unless 128 seconds have passed since the freshest. A stale
  notification is dropped.
- **The corrections of draft-ietf-core-corr-clar are not followed,** since
  it is not an RFC. Where it differs from RFC 7252, RFC 7252 is followed.

## The C ABI

Messages, options, endpoints, observers and links are handles; a message
gives out a copy of its options and takes them back to change them. A
function that needs randomness takes a generator of `crypto::random` as in
Rust (`.docs/dns.md` gives the reasons).

## Not implemented

CoAPS and OSCORE (they need DTLS), CoAP over TCP/TLS/WebSockets (RFC 8323),
group communication, proxying and caching, Q-Block (RFC 9177).
