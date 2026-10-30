# HTTP, HPACK, QPACK and WebSocket

How `protocol::http`, `codec::hpack`, `codec::qpack` and
`protocol::websocket` are built and why. The users' view is
`docs/protocol-http.md`, `docs/codec-hpack.md`, `docs/codec-qpack.md` and
`docs/protocol-websocket.md`.

## Shape

- **Semantics once, versions apart.** The root module holds what RFC 9110
  defines for every version: methods, status codes, fields, targets,
  messages, structured fields, priorities, content codings, the rule of
  routers. Each version is its own module and its own feature. A version
  never assumes another: HTTP/3 is chosen by the ALPN `h3` and nothing else
  (a QUIC connection of another protocol is not HTTP/3), HTTP/2 by `h2` or
  prior knowledge, and a message of a version a module does not speak is
  refused (505 from an HTTP/1.1 server for a major version other than 1).
- **One interface for the application.** `HTTPConnection` (send a request,
  a response, content, trailers; read content; reset; poll events; shut
  down) is the same for every version. What differs is how bytes move:
  HTTP/1.1 and HTTP/2 take and give bytes of a stream (`receive`,
  `transmit`), HTTP/3 works on a `QUICConnection`.
- **`H3Session` borrows.** A `QUICEndpoint` owns its connections and routes
  datagrams to them, so HTTP/3 cannot own its QUIC connection.
  `H3Connection` is the state of HTTP/3; `H3Session { connection, quic }`
  joins it to the connection for the length of a call. Rejected
  alternatives: an `H3Connection` that owns the `QUICConnection` (the
  endpoint could no longer route to it, and a server's connections are made
  by the endpoint), and one that holds an index into an endpoint (it would
  tie HTTP/3 to `QUICEndpoint` and need the endpoint in every call anyway).
- **Pull, not push, for content.** A connection keeps what arrived and
  emits `Data`; the application reads with `read_data`. HTTP/2 and HTTP/3
  give flow control credit back as the application reads, so a slow reader
  slows the peer instead of growing buffers; HTTP/1.1 stops taking bytes
  (`wants_receive`) beyond `maximum_buffered_content`.
- **No private helpers.** Pieces that HTTP/2 and HTTP/3 share —
  pseudo-header fields and their rules (`HTTPPseudoField`), the
  connection-specific fields they forbid — are public types of the root
  module; HPACK's integers and strings are public types that QPACK uses.

## HPACK and QPACK

- **The Huffman code is a canonical code.** RFC 7541 Appendix B is a
  canonical prefix code (checked against the table: code values follow from
  the lengths), so HPACK's code is `codec-huffman-canonical` given the 257
  lengths. That module was generalized for it: codes of up to 32 bits (HPACK
  has codes of 30 bits), most-significant-bit-first bit order in
  `BitWriter`, and a decoding table that falls back to a search by length
  for codes longer than its direct bits. Rejected alternative: a decoding
  table of HPACK's own, which would duplicate what the canonical module
  does and leave it unable to read long codes.
- **String limits leave room for 431.** A decoder's
  `maximum_string_length` is a bound on work; a field larger than the
  field-section limit must be answered with 431 (RFC 9113 §8.2.3, RFC 9114
  §4.2.2), which needs the block decoded whole so the table stays in step.
  HTTP/2's default string limit is therefore the field-block limit, and
  HTTP/3's twice the section limit plus 64; `FieldListTooLarge` is reported
  after decoding, never before.
- **What the encoders index.** Fields of at most `maximum_indexed_size`
  (1024 bytes with the 32 of overhead) enter the dynamic table; larger ones
  are literals without indexing, so one large cookie does not evict the
  table. Sensitive fields are never indexed (RFC 7541 §7.1.3, RFC 9204
  §7.1.3).
- **QPACK acknowledges inserts at once.** The decoder writes an Insert
  Count Increment when inserts arrive, even when a Section Acknowledgment
  would later imply it. RFC 9204 §2.2.2.3 allows either; acknowledging at
  once lets the encoder use the entries sooner, and a redundant increment
  costs one byte. Rejected alternative: deferring increments until no
  acknowledgment covers them, which needs the decoder to predict sections.
- **QPACK blocks only within the peer's limit.** The encoder refers to
  unacknowledged entries only on streams already blocking or while fewer
  than SETTINGS_QPACK_BLOCKED_STREAMS streams are (RFC 9204 §2.1.2), and
  never evicts an entry a section still refers to.

## HTTP/1.1

- **Smuggling.** The framing rules of RFC 9112 §6.3 are followed strictly:
  Transfer-Encoding and Content-Length together close the connection after
  the exchange (§6.1), a transfer coding other than a final chunked is 501
  or an error, several differing Content-Lengths are an error, a bare CR is
  an error everywhere, obsolete line folding in a request is an error (a
  client replaces it with spaces in responses, §5.2). A server answers what
  it cannot read with 400, 408, 414, 431, 501 or 505 and closes.
- **Order.** Responses go out in the order of requests whatever order the
  application gives them in (§9.3.2): each exchange buffers its bytes, and
  `transmit` stops at the first exchange whose message is not complete.
- **Tunnels follow RFC 9931.** A client's CONNECT or Upgrade request is its
  head alone; `end` false keeps the stream for the tunnel, as over HTTP/2
  and HTTP/3, so the application uses the same calls for every version; the
  tunnel takes no data before the 2xx or 101 (`State`), because a server
  that refuses would read optimistic data as requests (§4, §8). A server
  holds what follows such a request unread until its final response: the
  tunnel's if accepted, HTTP/1.1 again after a refused Upgrade (§5), and
  nothing after a refused CONNECT, which closes the connection (§8, a MUST
  for proxies). Rejected alternatives: buffering the client's early tunnel
  data until the response (it hides when data is really sent and must be
  dropped on refusal), and letting a client put content in an Upgrade
  request (RFC 9931 §7.1 restricts every registered upgrade token to GET
  without content; such a request is refused with `Malformed`).
- **100-continue** is sent when the application first reads the content of
  a request that expects it (`continue_automatically`), so an application
  that answers without reading (417, 413) never asks for the content.

## HTTP/2

- **Settings.** A client sends SETTINGS_ENABLE_PUSH 0 and a server never
  sends it (RFC 9113 §6.5.2: a server must not send 1, and 1 is the initial
  value). Values of the configuration larger than the settings' 32 bits are
  sent as 2^32 - 1. SETTINGS_NO_RFC7540_PRIORITIES is sent (RFC 9218 §2.1)
  and PRIORITY frames are read and ignored.
- **Floods.** Each of the known floods has its own limit: resets per window
  (rapid reset), acknowledgments owed for PING and SETTINGS, the size of a
  field block across CONTINUATION frames. Each ends the connection with
  ENHANCE_YOUR_CALM.
- **Closing.** `shutdown` sends GOAWAY with the last stream processed; the
  connection closes once the streams under way end (`finish`), so a
  response is never cut by the close.

## HTTP/3

- The control stream starts with SETTINGS, then a frame of a reserved type
  when `grease` is on (RFC 9114 §7.2.8); SETTINGS carries a reserved
  setting too (§7.2.4.1). A stream of an unknown type is abandoned with
  STOP_SENDING of H3_STREAM_CREATION_ERROR (§6.2) and what still arrives on
  it is discarded: its entry stays, so those bytes are never read as the
  type of a new stream (a reserved type's payload may begin with 0x00, the
  control stream's type). Unknown frames are skipped.
- The QUIC connection closes only after the send halves of the request
  streams reached a terminal state, so the last response is delivered
  before CONNECTION_CLOSE.
- Push is off: a client never sends MAX_PUSH_ID, so a server cannot push.

## WebSocket

- **Strict framing.** Every rule of RFC 6455 §5 that a sender must follow
  is checked on receipt and fails the connection: masking by role, reserved
  bits without an extension that defines them, reserved opcodes, control
  frames fragmented or over 125 bytes, a 64-bit length with its top bit
  set, and a length not in the fewest bytes (§5.2 says the minimal number of
  bytes MUST be used; accepting others would let two readers disagree on
  nothing, but a strict reader is the low-risk choice and costs nothing).
- **UTF-8 as it arrives.** Text is validated incrementally, frame by frame,
  so an invalid message fails at the first bad byte (§8.1) instead of after
  the whole message was buffered.
- **Bombs.** permessage-deflate inflates within `maximum_message_size`; a
  message that would exceed it fails with 1009 without being expanded.
- **The handshake is HTTP's.** `protocol-websocket` knows nothing of HTTP;
  `protocol-http-websocket` makes and checks the requests and responses of
  every version (RFC 6455 §4, RFC 8441, RFC 9220), and the WebSocket bytes
  travel as the content of the stream.

## What the reviews changed, and why

- **Events are never dropped.** A queue that drops past `maximum_events`
  loses requests, ends and messages (a flood of Pings would hide the text
  after it). Every connection now stops reading when the limit is reached
  and goes on when the application takes events (`poll_event` resumes,
  `wants_receive` tells the caller to wait). Rejected: an unbounded queue
  (a peer could grow it while the application is busy) and dropping only
  some kinds (every kind carries state the application needs).
- **Room made, reading resumes.** HTTP/1.1 processes what it holds again
  when the application reads content, a response frees the pipeline, or
  events are taken: before, bytes already received waited for more bytes
  that never came.
- **One policy for content not read.** Once a server's response is whole,
  the rest of the request is dropped in every version (HTTP/1.1 reads it to
  its end, HTTP/2 RST_STREAM(NO_ERROR) as RFC 9113 §8.1 allows, HTTP/3
  STOP_SENDING(H3_NO_ERROR), RFC 9114 §4.1.1); before, a stream kept its
  unread content for ever, holding concurrency and flow control. Tunnels
  are excepted. HTTP/1.1 used to drop the request as soon as the response
  head went out, unlike the others; it now waits for the whole response.
  A client keeps a whole response after RST_STREAM(NO_ERROR) (RFC 9113
  §8.1: it must not discard it).
- **Sending is checked as receiving is.** `HTTPContentLength` counts what a
  message carries against its Content-Length and whether it may have
  content, the same for HTTP/2 and HTTP/3 (HTTP/1.1's framing does it).
- **HTTP/2.** A HEADERS of a self-dependent priority is a stream error
  after its block is decoded, so HPACK stays in step (RFC 9113 §4.3). A
  stream window below 65535 holds once SETTINGS is acknowledged (§6.9.2);
  streams opened before get the difference then. DATA refused as malformed
  is credited back to the connection's window.
- **HTTP/3.** A server takes request streams when QUIC opens them, in order,
  not when their bytes come (a stream whose bytes come after a later one's
  was lost). An error of one stream resets it and the rest of the events
  go on. Unknown error codes are H3_NO_ERROR (RFC 9114 §8). Frames of
  unknown types on the control stream are skipped as they come, whatever
  their size. A peer's RESET_STREAM is read (QUIC forgets a half only once
  its reset is read) and this end's half is reset too. MAX_PUSH_ID may not
  fall. A 431 drops the rest of its stream.
- **HPACK and QPACK** copy no entry for a field past the limit, and QPACK
  acknowledges a section too large after decoding it (RFC 9204 §2.2.2.1).
  QPACK keeps a partial encoder instruction in place instead of copying it
  on every call, and refuses one longer than the table could hold.
- **HTTP/1.1** remembers how far a head was scanned, so a head that comes a
  byte at a time is scanned once; it reads content without copying the rest
  of the input at each step; it ignores Upgrade in HTTP/1.0 (RFC 9110 §7.8).
- **WebSocket** answers Pings while its own Close waits for the peer's (RFC
  6455 §5.5.2), reads blocks after one with BFINAL (`DeflateDecompressor::resume`,
  RFC 7692 §7.2.1), and a client keeps to the hints of its own offer
  (§7.1.1.1, §7.1.2.2).

## The C ABI

- HTTP/1.1 and HTTP/2 export the functions of `HTTPConnection` for their
  connection handles through one macro, `ffi_http_connection!`, which calls
  `FFIHTTPConnection` with a `&mut dyn HTTPConnection`; a version cannot
  drift from the others. HTTP/3's functions take the `H3Connection`, the
  `QUICEndpoint` and the connection's number and build an `H3Session` for
  each call (`FFIH3Session::with`).
- Events are structures; the request, response or trailers of an event are
  handles the caller releases.
- Timeouts cross as milliseconds with 0 for none (`FFIHTTPTimeout`): an
  `Option<Duration>` has no C layout.
- WebSocket connections and handshakes seed an HMAC-DRBG (SHA-256) from at
  least 48 bytes the caller gives, as TLS and QUIC do; that is why
  `protocol-websocket` depends on `hash-sha-v2`.

## Tests

- RFC 7541 Appendix C and RFC 9204 Appendix B byte for byte, the Huffman
  table of RFC 7541 Appendix B, the structured field tests of the HTTP
  working group (`tests/vectors/protocol/http/structured-field-tests`), RFC
  6455 §5.7 and §1.3, RFC 7692 §7.2.3, RFC 9931 Figure 1.
- Interoperability (`examples/http.sh`): curl over HTTP/1.1, HTTP/2 and
  HTTP/3, Python's `http.client` and a WebSocket client written with
  Python's standard library, and a browser.
