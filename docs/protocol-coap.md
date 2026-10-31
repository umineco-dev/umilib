# CoAP: `umilib::protocol::coap`

`protocol-coap` (no `std`) is the Constrained Application Protocol over UDP
(RFC 7252) without doing any I/O: messages and options, an endpoint that is
client and server at once, observation (RFC 7641), block-wise transfers
(RFC 7959), the CoRE Link Format (RFC 6690) and routing.

| Type | What it is |
| --- | --- |
| `CoAPMessage` | A message: type, code, Message ID, token (up to 65804 bytes, RFC 8974), options, payload |
| `CoAPType`, `CoAPCode`, `CoAPContentFormat` | The registries of types, codes and content formats |
| `CoAPOptions`, `CoAPOptionNumber` | Options in order, their properties (critical, unsafe, NoCacheKey) and the formats of RFC 7252 table 4 |
| `CoAPBlock` | The value of a Block1 or Block2 option |
| `CoAPEndpoint`, `CoAPConfig` | The message layer: retransmission, deduplication, responses, NSTART |
| `CoAPObservers` | The observers of a server's resources |
| `CoAPBlockwise` | A body sent or received block by block |
| `CoAPLink` | A link of the CoRE Link Format |
| `CoAPRule` | Routes requests by path and method |

## Messages

`CoAPMessage::decode` refuses what RFC 7252 §3 does not allow: another
version, a token longer than 8 bytes without RFC 8974, an empty message
with a token, options or a payload, the payload marker without a payload,
option deltas and lengths of 15. `CoAPOptions` keeps options in the order
of their numbers. `check` finds the critical option for which a message
must be rejected: one the endpoint does not know, or of a wrong length or
format (§5.4.1). `usable` is the options without the elective ones to
ignore (unknown, out of their definition, or repeated, §5.4.5).

```rust
use umilib::protocol::coap::{CoAPCode, CoAPMessage, CoAPType};

let mut request = CoAPMessage::new(CoAPType::Confirmable, CoAPCode::GET, 0);
request.options.set_uri("/sensors/temperature", None);
let bytes = request.encode()?;
```

## The endpoint

```rust
use umilib::protocol::coap::{CoAPConfig, CoAPEndpoint, CoAPEvent};

let mut endpoint = CoAPEndpoint::new(CoAPConfig::default(), &mut random)?;
let handle = endpoint.request(server, request, now, &mut random)?;
// for each datagram received: endpoint.receive(peer, &bytes, now, &mut random)
// at endpoint.poll_timeout(): endpoint.expire(now)
while let Some(transmission) = endpoint.transmit() { /* send transmission.message to transmission.peer */ }
while let Some(event) = endpoint.poll_event() {
    match event {
        CoAPEvent::Request { exchange, peer, message } => endpoint.respond(exchange, response, now, &mut random)?,
        CoAPEvent::Response { request, message } => { /* the response to `request`, or a notification */ }
        CoAPEvent::Timeout { message } | CoAPEvent::Reset { message } => { /* gone unanswered or rejected */ }
    }
}
```

- A Confirmable message is sent again after ACK_TIMEOUT to ACK_TIMEOUT ×
  ACK_RANDOM_FACTOR, doubling, MAX_RETRANSMIT times, then `Timeout` (§4.2).
- A duplicate of a message received within EXCHANGE_LIFETIME (or
  NON_LIFETIME) is not told again. A duplicate Confirmable request is
  answered with the same ACK or response (§4.5).
- `respond` piggybacks the response in the ACK if the request is still
  unacknowledged. After `ack_delay` the endpoint acknowledges the request
  alone, and the response goes separately, Confirmable for a Confirmable
  request (§5.2).
- `ignore` answers a request with nothing: for a server that does not
  respond (RFC 7967 No-Response, a multicast request it has nothing for,
  §8.2). A Confirmable request not yet acknowledged gets an empty ACK, so
  that its client stops retransmitting it. Every `Request` event should end
  with `respond` or `ignore`; a request neither answered nor ignored is
  forgotten after EXCHANGE_LIFETIME (Confirmable) or NON_LIFETIME
  (Non-confirmable), when its client no longer waits for it, and
  `respond` then fails with `State`.
- At most `maximum_incoming` (1024) requests await an answer. Past it, a
  Confirmable request is answered 5.03 Service Unavailable and a
  Non-confirmable one is ignored, without a `Request` event.
- A Confirmable message that cannot be processed, or a response or
  notification no request awaits, is answered with RST (§4.2, RFC 7641
  §3.6). A Confirmable request with a critical option it cannot process is
  answered 4.02 Bad Option; a Non-confirmable one, or a response, is
  rejected (§5.4.1). An ACK that is not empty nor a response, a RST that
  is not empty, and a piggybacked response of another token are ignored.
- At most NSTART interactions with a peer are outstanding (§4.7): requests
  not yet acknowledged or answered, and Confirmable separate responses and
  notifications not yet acknowledged (RFC 7641 §4.5.1); more wait.
  `cancel` lets the next go.
- The token of a request is 8 random bytes when it has none (§5.3.1).
- The first Message ID is random (§4.4).

`CoAPConfig` holds the transmission parameters of §4.8 (ACK_TIMEOUT 2 s,
ACK_RANDOM_FACTOR 1.5, MAX_RETRANSMIT 4, NSTART 1, EXCHANGE_LIFETIME
247 s, NON_LIFETIME 145 s), the delay before a separate response, the
longest token taken (8; up to 65804 with RFC 8974: an endpoint of extended
tokens answers a longer one 4.00 Bad Request, §2.3), the most messages
remembered to find duplicates (`maximum_seen`, 8192), and the most requests
awaiting an answer (`maximum_incoming`, 1024).

## Observation and blocks

A client observes a resource with `Observe: 0` in its GET. Its
notifications come as `Response` events of the request's handle, a stale
one dropped by the rule of RFC 7641 §3.4 (24-bit serial order, or 128
seconds). `cancel` forgets the observation, so that the next notification
is rejected with RST.

A server keeps `CoAPObservers`. `register` takes a request; GET with
`Observe: 0` registers, with 1 deregisters. `notify` sends a response to
every observer of a path with the next Observe value. A notification is
Confirmable at least once every `confirm_interval` (a day, §4.5). An error
response ends the observations. `handle` takes the endpoint's events: a RST
or an unacknowledged Confirmable notification ends that observer (§3.6,
§4.5). A Non-confirmable notification never does.

`CoAPBlockwise::respond` gives a large body block by block in Block2 (RFC
7959 §2.4). Its `receive` puts a body together in order, all blocks of one
ETag, up to its `maximum`. `next_request` is the request of the next block,
of any size the body so far is a multiple of (smaller blocks may be asked
for as it goes).

## Trying it

`examples/coap.rs` is a server and a client; `examples/coap.sh` runs them
against libcoap's coap-client and coap-server (in Docker) and against
themselves.

## Link Format and routing

`CoAPLink::parse` and `CoAPLink::format` read and write the links of RFC
6690 (`/.well-known/core`, `CoAPLink::WELL_KNOWN_CORE`). `CoAPRule` is a
[`service::Rule`](service.md) of requests: a path (its Uri-Path segments
first) and, if given, a method.

## FFI and Python

The C ABI (`include/umilib/protocol/coap.h`) and `umilib.protocol.coap`
mirror the types above. Messages, options, endpoints, observers and links
are handles. A function that needs randomness takes a generator of
`crypto::random`, as in Rust. In Python, `CoAPCode.class_()` and
`CoAPLink.with_()` carry a trailing underscore, because `class` and `with`
are keywords.

## Not implemented

CoAP over DTLS (CoAPS) and OSCORE (RFC 8613), which need DTLS; CoAP over
TCP, TLS and WebSockets (RFC 8323); group communication (RFC 7390);
proxying and caching (RFC 7252 §5.6, §5.7, a server's or proxy's to do with
Max-Age and ETag); Block1 on the server side beyond `CoAPBlockwise::receive`;
Q-Block (RFC 9177).
