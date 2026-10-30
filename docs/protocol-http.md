# HTTP: `umilib::protocol::http`

`protocol-http` (no `std`) is HTTP without doing any I/O: the semantics
every version shares (RFC 9110) in the root module, and one module per
version:

| Feature | Module | Specification |
| --- | --- | --- |
| `protocol-http-v1` | `v1` | HTTP/1.1 (RFC 9112), with RFC 9931's rules for tunnels |
| `protocol-http-v2` | `v2` | HTTP/2 (RFC 9113) with HPACK (RFC 7541, `codec-hpack`) |
| `protocol-http-v3` | `v3` | HTTP/3 (RFC 9114) over QUIC (`protocol-quic-v1`) with QPACK (RFC 9204, `codec-qpack`) |
| `protocol-http-websocket` | `websocket` | WebSocket's opening handshake (RFC 6455 §4, RFC 8441, RFC 9220); see [protocol-websocket.md](protocol-websocket.md) |

`protocol-http` is all four; the root module is there whenever one of them
is. `protocol-http1`, `protocol-http2` and `protocol-http3` are aliases of
the version features.

| Type | What it is |
| --- | --- |
| `HTTPConnection` | The interface of every version's connection: requests, responses, content, trailers, resets, events |
| `v1::H1Connection`, `v2::H2Connection` | HTTP/1.1 and HTTP/2 over a byte stream (TCP, TLS) |
| `v3::H3Connection`, `v3::H3Session` | HTTP/3: the state, and the state joined to its `QUICConnection` |
| `HTTPEvent` | What a connection tells its application |
| `HTTPRequest`, `HTTPResponse` | The heads of messages: method, scheme, authority, path, `:protocol`, fields; status, fields |
| `HTTPFields`, `HTTPField` | Header and trailer sections; names lowercased and checked, values checked (RFC 9110 §5) |
| `HTTPMethod`, `HTTPStatus`, `HTTPVersion` | Methods (QUERY of RFC 10008 included), status codes and reason phrases, versions |
| `HTTPAuthority`, `HTTPTarget` | Authorities and request targets (RFC 9110 §4.2, RFC 9112 §3.2) |
| `HTTPRule` | The rule that routes requests by host, path, method and fields |
| `HTTPStructuredField` and its items | Structured Field Values (RFC 9651) |
| `HTTPPriority` | Extensible priorities (RFC 9218) |
| `HTTPContentCoding`, `HTTPContentDecoder`, `HTTPContentEncoder`, `HTTPAcceptEncoding` | Content codings (gzip, deflate, br, zstd) and their negotiation |
| `HTTPConfig`, `v1::H1Config`, `v2::H2Config`, `v3::H3Config` | Limits, timeouts and settings |
| `HTTPError` | What went wrong |

## Connections

A connection does no I/O. The caller gives it what arrives, sends what it
writes, and calls `expire` at `poll_timeout`; the application uses the
common interface, `HTTPConnection`, whatever the version:

- `send_request(request, end)` (a client) starts an exchange on a new
  stream; `send_response(stream, response, end)` (a server) answers one,
  interim (1xx) responses first. `end` says the message has no content.
- `send_data(stream, data, end)` writes content and returns how much was
  taken, which flow control and buffers may make less than all: write the
  rest after a `Writable` event. `send_trailers` ends a message with a
  trailer section.
- `poll_event` returns `Request`, `Response`, `Data` (read it with
  `read_data`), `Trailers`, `End`, `Reset`, `Writable`, `GoAway` and
  `Closed`.
- `reset` abandons a stream; `shutdown` takes no new exchanges and closes
  once those under way finish. A server's `reset(stream, HTTPReset::NoError)`
  says the rest of the request is not needed: its response still goes out
  whole. A reset of a stream already over does nothing.
- Once a server's response is whole, the rest of its request is not
  delivered (HTTP/1.1 reads it to its end and drops it, HTTP/2 sends
  RST_STREAM of NO_ERROR, HTTP/3 STOP_SENDING of H3_NO_ERROR); a tunnel's
  two ways end apart. Read the content before ending the response.
- What is sent is checked against its head in every version: content of
  the length its Content-Length says, none in a response to HEAD or of 204
  or 304 (`Malformed` otherwise).
- Events are never dropped. When `maximum_events` wait, reading stops until
  the application takes them: `wants_receive` (HTTP/1.1, HTTP/2) is false
  meanwhile, and HTTP/3 takes no more of QUIC's events.

### HTTP/1.1 and HTTP/2

```rust
use umilib::protocol::http::v2::{H2Config, H2Connection};
use umilib::protocol::http::{HTTPConnection, HTTPEvent, HTTPMethod, HTTPRequest, HTTPResponse, HTTPStatus};
use umilib::runtime::Instant;

let now = Instant::from_nanos(1);
let mut client = H2Connection::client(H2Config::default(), now);
let mut server = H2Connection::server(H2Config::default(), now);
let stream = client.send_request(&HTTPRequest::new(HTTPMethod::GET, b"https", b"example.com", b"/"), true).unwrap();
let mut wire = Vec::new();
for _ in 0..4 {
    client.transmit(&mut wire);
    server.receive(&wire, now);
    wire.clear();
    while let Some(event) = server.poll_event() {
        if let HTTPEvent::Request { stream, request, .. } = event {
            assert_eq!(request.path, b"/");
            server.send_response(stream, &HTTPResponse::new(HTTPStatus::OK), false).unwrap();
            server.send_data(stream, b"hello", true).unwrap();
        }
    }
    server.transmit(&mut wire);
    client.receive(&wire, now);
    wire.clear();
}
let mut body = [0; 16];
let count = client.read_data(stream, &mut body).unwrap();
assert_eq!(&body[..count], b"hello");
```

`H1Connection` is used the same way (`H1Connection::client(H1Config,
now)`); it also has `receive_close` for the end of the byte stream and
`wants_receive`, false while the application has not read content that
arrived. With either, close the transport once `wants_close` is true and
what `transmit` wrote is sent. The version is chosen before: by ALPN over
TLS (`h2`, `http/1.1`; `HTTPVersion::from_protocol`), or by prior knowledge.

### HTTP/3

`H3Connection` is the state of HTTP/3 on one `QUICConnection` of a
`QUICEndpoint`. `H3Session::new(&mut state, quic)` joins them for as long
as a call takes; it is the `HTTPConnection`. After the endpoint takes
datagrams or fires timers, call `H3Session::process(now)`: it reads the
QUIC connection's events, the control and QPACK streams and the request
streams. The QUIC events HTTP/3 does not handle (DATAGRAM frames, say) are
kept for `H3Session::poll_quic_event`. ALPN must be `h3`; a connection of
another protocol is not HTTP/3 and is not to be given to `H3Connection`.

## What each version implements

HTTP/1.1:

- Persistent connections and pipelining (at most `maximum_pipelined`
  exchanges at once); responses go out in the order of their requests.
- The framing rules against request smuggling (RFC 9112 §6.1, §6.3,
  §11.2): Transfer-Encoding and Content-Length together close the
  connection after the exchange; a transfer coding other than chunked last
  is refused; a bare CR is refused, and obsolete line folding too in
  requests (a client replaces it in responses with spaces, §5.2).
- 100-continue (sent automatically when the application first reads, with
  `continue_automatically`), interim responses, trailers.
- A server answers what it cannot read with 400, 408 (a head that comes too
  slowly), 414, 431, 501 or 505 and closes.
- CONNECT and Upgrade: see "Tunnels" below; an Upgrade in an HTTP/1.0
  request is ignored (RFC 9110 §7.8).

HTTP/2:

- SETTINGS (and SETTINGS_TIMEOUT), flow control of streams and of the
  connection, PING, GOAWAY, RST_STREAM, CONTINUATION.
- Priorities of RFC 9218 (the `priority` field and PRIORITY_UPDATE);
  SETTINGS_NO_RFC7540_PRIORITIES is sent and the frames of RFC 7540's
  scheme are ignored. Content is sent in the order of urgency.
- Defenses against floods: too many resets in a window, control frames that
  await acknowledgment, field blocks larger than `maximum_field_block`
  (ENHANCE_YOUR_CALM); a header section too large is answered with 431.
- Extended CONNECT (RFC 8441) when `enable_connect_protocol`.
- Server push is off: a client sends SETTINGS_ENABLE_PUSH 0 and a server
  never pushes.

HTTP/3:

- The control stream with SETTINGS (greased, RFC 9114 §7.2.4.1, §7.2.8),
  the QPACK streams, request streams, GOAWAY, unknown frames and stream
  types ignored.
- Extended CONNECT (RFC 9220) when `enable_connect_protocol`.
- Server push is off: a client never sends MAX_PUSH_ID.

Not implemented: caching (RFC 9111), server push, the priority signals of
RFC 7540, HTTP/2 over cleartext by Upgrade (`h2c`, removed by RFC 9113).

## Tunnels

CONNECT (RFC 9110 §9.3.6), Upgrade (§7.8) and extended CONNECT (RFC 8441,
RFC 9220) make a stream a tunnel. Every version follows the same rules:

- Send the request with `end` false to keep the stream open for the
  tunnel; `end` true ends this end's side of it.
- Write the tunnel's bytes with `send_data` once the `Response` event says
  101 (an Upgrade over HTTP/1.1) or 2xx arrived. Over HTTP/1.1, a request
  that opens a tunnel is its head alone and `send_data` fails with `State`
  before that response: data sent sooner could be read as requests by a
  server that refuses (RFC 9931 §4, §8). A request opening a tunnel may not
  carry a Content-Length above 0.
- A refused request (another status) ends its exchange as any other; the
  HTTP/1.1 connection stays usable (RFC 9931 §5).

## Routing

`HTTPRule` is the rule of a `service::Router` over `HTTPRequest`s:

```rust
use umilib::protocol::http::{HTTPMethod, HTTPRule};
use umilib::service::Pattern;

let oauth = HTTPRule::new(Pattern::exact(b"auth.example.com"), Pattern::prefix(b"/oauth/"))
    .with_method(HTTPMethod::POST)
    .with_field(b"content-type", Pattern::prefix(b"application/x-www-form-urlencoded"));
```

The host is compared without case or port, from the authority or the Host
field; a request with neither matches only `Pattern::any()`. The path is
matched with its query and without decoding percent-escapes, so
`/a%2Fb` is not `/a/b`. A field matches if any of its lines matches.

## Content codings

`HTTPContentDecoder::new(content_encoding, limit)` decodes the codings of a
Content-Encoding field in order, with at most `limit` bytes of output, so a
small response cannot expand into gigabytes. The codings available are
those whose codec features are on: `gzip` (`codec-gzip`), `deflate` (the
zlib format, `codec-zlib`), `br` (`codec-brotli`) and `zstd`
(`codec-zstandard`, within the window of 8 MiB of RFC 9659).
`HTTPAcceptEncoding::parse(value).choose(&offered)` picks the coding of a
response.

## Limits

| Field | Default | What it limits |
| --- | --- | --- |
| `HTTPConfig::maximum_field_section_size` | 64 KiB | A header or trailer section (431, or an error) |
| `HTTPConfig::maximum_target_length` | 8 KiB | A request target (414) |
| `HTTPConfig::maximum_buffered_content` | 1 MiB | Content held for the application before it reads; beyond it, flow control (or reading, in HTTP/1.1) waits |
| `HTTPConfig::maximum_events` | 4096 | Events queued: reading pauses at it until the application takes them |
| `H1Config::idle_timeout`, `head_timeout` | 60 s, 30 s | An idle connection, a head that arrives slowly (408) |
| `H2Config::max_concurrent_streams` | 100 | Streams the peer may open |
| `H2Config::initial_window_size`, `connection_window` | 1 MiB, 4 MiB | Flow control |
| `H2Config::maximum_resets`, `reset_window` | 1000 per 10 s | Streams the peer may reset |
| `H2Config::maximum_field_block` | 256 KiB | A field block, coded |
| `H3Config::qpack_decoder` | 4 KiB table, 16 blocked streams | QPACK's SETTINGS |

## C and Python

The C ABI is `include/umilib/protocol/http.h` and the headers of each
version. Fields, requests, responses and rules are handles; a connection of
HTTP/1.1 or HTTP/2 is a handle with the functions of `HTTPConnection`
(`..._send_request`, `..._poll_event`, ...); HTTP/3's take the
`H3Connection`, the `QUICEndpoint` and the connection's number. Events are
`umilib_protocol_http_HTTPEvent` structures, with the request, response or
trailers in handles the caller releases. Timeouts cross as milliseconds, 0
for none.

Python has the same names in `umilib.protocol.http` and its version
packages; `H3Session(connection, quic)` takes the `QUICConnection` of
`umilib.protocol.quic`.
