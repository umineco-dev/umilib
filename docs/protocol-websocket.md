# WebSocket: `umilib::protocol::websocket` and `umilib::protocol::http::websocket`

`protocol-websocket` (no `std`) is the WebSocket protocol (RFC 6455) after
its opening handshake, with permessage-deflate (RFC 7692). It does no I/O
and needs no HTTP. `protocol-http-websocket` is the opening handshake over
HTTP: an Upgrade over HTTP/1.1 (RFC 6455 §4), an extended CONNECT over
HTTP/2 (RFC 8441) or HTTP/3 (RFC 9220).

| Type | What it is |
| --- | --- |
| `WebSocketConnection` | A connection: bytes in and out, messages, Ping, the closing handshake, events |
| `WebSocketRole` | A client (whose frames are masked) or a server |
| `WebSocketEvent` | A text or binary message, a Ping or Pong, or the end with its code and reason |
| `WebSocketConfig` | Limits: message and frame sizes, the deflate level, events |
| `WebSocketDeflateParameters` | The parameters of permessage-deflate, their negotiation |
| `WebSocketFrameHeader`, `WebSocketOpcode`, `WebSocketCloseCode` | The codec of frames, for tools |
| `http::websocket::WebSocketHandshake` | The steps of the opening handshake, for both ends |
| `http::websocket::WebSocketOffer`, `WebSocketAgreement` | What a client offers, and what both ends agreed |

## A handshake over HTTP/1.1, then messages

```rust
use umilib::protocol::http::v1::{H1Config, H1Connection};
use umilib::protocol::http::websocket::WebSocketHandshake;
use umilib::protocol::http::{HTTPConnection, HTTPEvent, HTTPVersion};
use umilib::protocol::websocket::{WebSocketConfig, WebSocketConnection, WebSocketDeflateParameters, WebSocketRole};
# fn random() -> Box<dyn umilib::crypto::random::Random + Send> { unimplemented!() }
# let now = umilib::runtime::Instant::from_nanos(1);
# let mut client = H1Connection::client(H1Config::default(), now);
# let mut server = H1Connection::server(H1Config::default(), now);

// The client: GET with Upgrade and a key; `end` false keeps the stream for the tunnel.
let deflate = WebSocketDeflateParameters::default();
let (request, key) = WebSocketHandshake::request(b"http", b"example.com", b"/chat", &["chat"], Some(deflate), &mut *random()).unwrap();
let stream = client.send_request(&request, false).unwrap();

// The server: check the request, agree, answer 101.
# let (served, received) = (umilib::protocol::http::HTTPStreamID(0), request.clone());
let offer = match WebSocketHandshake::check_request(&received, HTTPVersion::HTTP1_1) {
    Ok(offer) => offer,
    // 400, 426 with the version this end speaks (§4.4), or 505 for a version of
    // HTTP other than 1.0, 1.1, 2 and 3: send it and stop.
    Err(refusal) => {
        server.send_response(served, &refusal, true).unwrap();
        return;
    }
};
let agreement = WebSocketHandshake::agree(&offer, &["chat"], true);
server.send_response(served, &WebSocketHandshake::response(&offer, &agreement).unwrap(), false).unwrap();

// The client, given the 101: check it, then speak WebSocket on the stream.
# let response = WebSocketHandshake::response(&offer, &agreement).unwrap();
let agreed = WebSocketHandshake::check_response(&response, Some(&key), &["chat"], Some(&deflate)).unwrap();
let mut websocket = WebSocketConnection::new(WebSocketRole::Client, WebSocketConfig::default(), agreed.deflate, random()).unwrap();
websocket.send_text("hello").unwrap();
let mut bytes = Vec::new();
websocket.transmit(&mut bytes);
client.send_data(stream, &bytes, false).unwrap();
```

The bytes of the WebSocket connection travel as the stream's content:
`send_data` and `read_data` of the HTTP connection, whatever its version.
Over HTTP/2 and HTTP/3, `connect_request` makes the extended CONNECT
(`:protocol` websocket, no key), a server needs `enable_connect_protocol`
in its configuration, and the server answers 200; `check_response` takes no
key. Over HTTP/1.1 the client writes no frame before the 101 (RFC 6455
§4.1; `send_data` refuses with `State` before it).

## The connection

- `receive` takes what arrives, `transmit` writes what to send,
  `poll_event` returns messages. A Ping is answered with a Pong
  automatically (§5.5.2); the closing handshake echoes the peer's Close
  (§5.5.1). Close the transport when `wants_close` is true, after sending
  what `transmit` wrote; give the transport's end to `receive_close`.
- `send_text`, `send_binary`, `send_ping` and `close(code, reason)` send;
  messages are split into frames of `maximum_frame_size`. A Ping is
  answered until the peer's Close arrives, after this end's own too.
- Events are never dropped: when `maximum_events` wait, reading stops
  until the application takes them (`wants_receive` is false meanwhile).
- A connection fails, sending a Close with the code and closing, on any
  frame that breaks the rules: a server's frame masked or a client's not
  (§5.1); reserved bits without an extension, reserved opcodes, control
  frames fragmented or longer than 125 bytes, lengths not in the fewest
  bytes (§5.2, §5.5); a continuation of nothing or a message inside another
  (§5.4); text that is not UTF-8, found as soon as its bytes arrive (1007,
  §8.1); a Close of a code that is not to be sent (§7.4); a message larger
  than `maximum_message_size`, decompressed (1009). A transport that ends
  without a Close is 1006 (§7.1.5).

## permessage-deflate

`WebSocketDeflateParameters` are the parameters of RFC 7692 §7.1:
`server_no_context_takeover`, `client_no_context_takeover`,
`server_max_window_bits` and `client_max_window_bits` (`Some(None)` for the
parameter without a value). A client keeps to the hints of its own offer —
no context takeover, a window of at most the bits it offered — whether the
response repeats them or not (§7.1.1.1, §7.1.2.2): `check_response` gives
the parameters it uses. `WebSocketHandshake::agree` accepts the
client's first valid offer; an offer with invalid parameters is declined,
not an error (§5). A message is compressed as one block whose final four
bytes are removed (§7.2.1); with context takeover the window carries from
message to message, so repeated messages shrink. A message may hold blocks
with BFINAL set: the next block follows at the next byte (§7.2.1). The decompressed size is
checked against `maximum_message_size` as the message inflates, so a
compressed bomb fails with 1009 without being expanded.

## C and Python

The C ABI is `include/umilib/protocol/websocket.h` and
`include/umilib/protocol/http/websocket.h`. A connection is a handle seeded
with at least 48 bytes from the operating system for its masks; the deflate
parameters are a structure in which a window of 0 bits is none given, and
`has_client_max_window_bits` with 0 is the parameter without a value.
Python has the same names in `umilib.protocol.websocket` and
`umilib.protocol.http.websocket`; there `client_max_window_bits` is `None`
when absent and `0` for the parameter without a value.
