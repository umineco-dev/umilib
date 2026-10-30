//! WebSocket (RFC 6455) and permessage-deflate (RFC 7692): the frames of
//! RFC 6455 §5.7 and RFC 7692 §7.2.3, and every rule that fails a connection.

use umilib::protocol::websocket::{
    WebSocketCloseCode, WebSocketConfig, WebSocketConnection, WebSocketDeflateParameters, WebSocketEvent,
    WebSocketFrameHeader, WebSocketOpcode, WebSocketRole, WebSocketState,
};

use crate::tls::handshake::Fixture;

fn connection(role: WebSocketRole) -> WebSocketConnection {
    WebSocketConnection::new(role, WebSocketConfig::default(), None, Fixture::random(1)).unwrap()
}

fn deflating(role: WebSocketRole, parameters: WebSocketDeflateParameters) -> WebSocketConnection {
    WebSocketConnection::new(role, WebSocketConfig::default(), Some(parameters), Fixture::random(2)).unwrap()
}

fn events(connection: &mut WebSocketConnection) -> Vec<WebSocketEvent> {
    std::iter::from_fn(|| connection.poll_event()).collect()
}

fn output(connection: &mut WebSocketConnection) -> Vec<u8> {
    let mut out = Vec::new();
    connection.transmit(&mut out);
    out
}

/// The code a connection fails with when given `bytes`, and the Close it sends.
fn failure(role: WebSocketRole, bytes: &[u8]) -> WebSocketCloseCode {
    let mut connection = connection(role);
    connection.receive(bytes);
    let closed = events(&mut connection).into_iter().find_map(|event| match event {
        WebSocketEvent::Closed { code, .. } => Some(code),
        _ => None,
    });
    let code = closed.unwrap_or_else(|| panic!("no failure for {bytes:02x?}"));
    let sent = output(&mut connection);
    let (header, length) = WebSocketFrameHeader::decode(&sent).unwrap().unwrap();
    assert_eq!(header.opcode, WebSocketOpcode::CLOSE);
    let mut payload = sent[length..].to_vec();
    if let Some(mask) = header.mask {
        WebSocketFrameHeader::apply_mask(mask, 0, &mut payload);
    }
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), code.0, "the Close carries the code");
    assert!(connection.wants_close());
    code
}

#[test]
fn the_frames_of_section_5_7() {
    // RFC 6455 §5.7: what a client receives unmasked, and a server masked.
    let mut client = connection(WebSocketRole::Client);
    client.receive(&[0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    client.receive(&[0x01, 0x03, 0x48, 0x65, 0x6c]);
    client.receive(&[0x80, 0x02, 0x6c, 0x6f]);
    client.receive(&[0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    let mut binary = vec![0x82, 0x7E, 0x01, 0x00];
    binary.extend(vec![7u8; 256]);
    client.receive(&binary);
    let mut large = vec![0x82, 0x7F, 0, 0, 0, 0, 0, 1, 0, 0];
    large.extend(vec![9u8; 65536]);
    client.receive(&large);
    assert_eq!(
        events(&mut client),
        [
            WebSocketEvent::Text("Hello".into()),
            WebSocketEvent::Text("Hello".into()),
            WebSocketEvent::Ping(b"Hello".to_vec()),
            WebSocketEvent::Binary(vec![7; 256]),
            WebSocketEvent::Binary(vec![9; 65536]),
        ]
    );
    // The Ping's Pong (§5.5.2), masked as a client's frames are.
    let pong = output(&mut client);
    let (header, length) = WebSocketFrameHeader::decode(&pong).unwrap().unwrap();
    assert_eq!((header.opcode, header.fin, header.mask.is_some()), (WebSocketOpcode::PONG, true, true));
    let mut payload = pong[length..].to_vec();
    WebSocketFrameHeader::apply_mask(header.mask.unwrap(), 0, &mut payload);
    assert_eq!(payload, b"Hello");
    let mut server = connection(WebSocketRole::Server);
    server.receive(&[0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]);
    server.receive(&[0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]);
    assert_eq!(events(&mut server), [WebSocketEvent::Text("Hello".into()), WebSocketEvent::Pong(b"Hello".to_vec())]);
    // A server's frames are not masked, lengths in the fewest bytes (§5.2).
    server.send_text("Hello").unwrap();
    server.send_binary(&[0; 256]).unwrap();
    let sent = output(&mut server);
    assert_eq!(&sent[..7], [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    assert_eq!(&sent[7..11], [0x82, 0x7E, 0x01, 0x00]);
}

#[test]
fn a_client_and_a_server() {
    let config = WebSocketConfig { maximum_frame_size: 1000, ..WebSocketConfig::default() };
    let mut client = WebSocketConnection::new(WebSocketRole::Client, config, None, Fixture::random(3)).unwrap();
    let mut server = WebSocketConnection::new(WebSocketRole::Server, config, None, Fixture::random(4)).unwrap();
    let text = "héllo ".repeat(1000);
    client.send_text(&text).unwrap();
    client.send_binary(&[1, 2, 3]).unwrap();
    client.send_ping(b"are you there").unwrap();
    let bytes = output(&mut client);
    // Fragmented (§5.4): split at whatever bytes, a character included.
    for chunk in bytes.chunks(7) {
        server.receive(chunk);
    }
    assert_eq!(
        events(&mut server),
        [
            WebSocketEvent::Text(text),
            WebSocketEvent::Binary(vec![1, 2, 3]),
            WebSocketEvent::Ping(b"are you there".to_vec())
        ]
    );
    client.receive(&output(&mut server));
    assert_eq!(events(&mut client), [WebSocketEvent::Pong(b"are you there".to_vec())]);
    // The closing handshake (§7.1.2): the Close is echoed, both end.
    client.close(WebSocketCloseCode::NORMAL, "bye").unwrap();
    assert_eq!(client.state, WebSocketState::Closing);
    server.receive(&output(&mut client));
    assert_eq!(
        events(&mut server),
        [WebSocketEvent::Closed { code: WebSocketCloseCode::NORMAL, reason: "bye".into() }]
    );
    assert!(!server.wants_close(), "its Close first");
    client.receive(&output(&mut server));
    assert!(server.wants_close() && client.wants_close());
    assert_eq!(
        events(&mut client),
        [WebSocketEvent::Closed { code: WebSocketCloseCode::NORMAL, reason: String::new() }]
    );
    // A transport that ends without Close is 1006 (§7.1.5).
    let mut lost = connection(WebSocketRole::Client);
    lost.receive_close();
    assert_eq!(
        events(&mut lost),
        [WebSocketEvent::Closed { code: WebSocketCloseCode::ABNORMAL, reason: String::new() }]
    );
}

#[test]
fn failures() {
    use WebSocketRole::{Client, Server};
    // §5.1: a server's frames unmasked, a client's masked.
    assert_eq!(
        failure(Client, &[0x81, 0x85, 0, 0, 0, 0, b'H', b'e', b'l', b'l', b'o']),
        WebSocketCloseCode::PROTOCOL_ERROR
    );
    assert_eq!(failure(Server, &[0x81, 0x05, b'H', b'e', b'l', b'l', b'o']), WebSocketCloseCode::PROTOCOL_ERROR);
    // §5.2: reserved bits without an extension, reserved opcodes.
    for first in [0xC1u8, 0xA1, 0x91, 0x83, 0x87, 0x8B, 0x8F] {
        assert_eq!(failure(Client, &[first, 0x00]), WebSocketCloseCode::PROTOCOL_ERROR, "{first:#x}");
    }
    // §5.5: control frames fragmented or longer than 125 bytes.
    assert_eq!(failure(Client, &[0x09, 0x00]), WebSocketCloseCode::PROTOCOL_ERROR);
    let mut long = vec![0x89, 0x7E, 0x00, 0x7E];
    long.extend([0; 126]);
    assert_eq!(failure(Client, &long), WebSocketCloseCode::PROTOCOL_ERROR);
    // §5.4: a continuation of nothing, a message inside another.
    assert_eq!(failure(Client, &[0x80, 0x01, b'x']), WebSocketCloseCode::PROTOCOL_ERROR);
    assert_eq!(failure(Client, &[0x01, 0x01, b'x', 0x81, 0x01, b'y']), WebSocketCloseCode::PROTOCOL_ERROR);
    // §5.2: a 64-bit length with its top bit set, and lengths not in the fewest bytes.
    assert_eq!(failure(Client, &[0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0]), WebSocketCloseCode::PROTOCOL_ERROR);
    assert_eq!(failure(Client, &[0x82, 0x7E, 0x00, 0x7D]), WebSocketCloseCode::PROTOCOL_ERROR);
    assert_eq!(failure(Client, &[0x82, 0x7F, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]), WebSocketCloseCode::PROTOCOL_ERROR);
    // §8.1: text that is not UTF-8 fails at once, even before its message ends.
    assert_eq!(failure(Client, &[0x81, 0x02, 0xC3, 0x28]), WebSocketCloseCode::INVALID_PAYLOAD);
    assert_eq!(failure(Client, &[0x01, 0x02, b'a', 0xFF]), WebSocketCloseCode::INVALID_PAYLOAD);
    assert_eq!(failure(Client, &[0x81, 0x01, 0xC3]), WebSocketCloseCode::INVALID_PAYLOAD);
    // §5.5.1, §7.4: a Close of one byte, of a code not to send, or a reason not UTF-8.
    assert_eq!(failure(Client, &[0x88, 0x01, 0x03]), WebSocketCloseCode::PROTOCOL_ERROR);
    for code in [999u16, 1004, 1005, 1006, 1015, 2999, 5000] {
        let bytes = code.to_be_bytes();
        assert_eq!(failure(Client, &[0x88, 0x02, bytes[0], bytes[1]]), WebSocketCloseCode::PROTOCOL_ERROR, "{code}");
    }
    assert_eq!(failure(Client, &[0x88, 0x03, 0x03, 0xE8, 0xFF]), WebSocketCloseCode::INVALID_PAYLOAD);
    // §7.4.1: a message over the limit is 1009.
    let config = WebSocketConfig { maximum_message_size: 10, ..WebSocketConfig::default() };
    let mut small = WebSocketConnection::new(Client, config, None, Fixture::random(5)).unwrap();
    small.receive(&[0x82, 0x0B, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(events(&mut small).contains(&WebSocketEvent::Closed {
        code: WebSocketCloseCode::MESSAGE_TOO_BIG,
        reason: "a frame larger than the limit".into()
    }));
    // Codes valid to send, and those not (§7.4.2).
    let mut client = connection(Client);
    assert!(client.close(WebSocketCloseCode::NO_STATUS, "").is_err());
    assert!(client.close(WebSocketCloseCode(4000), &"x".repeat(124)).is_err());
    assert!(client.send_ping(&[0; 126]).is_err());
}

#[test]
fn the_deflate_examples_of_section_7_2_3() {
    // RFC 7692 §7.2.3.1: "Hello" in one block; fragmented, RSV1 on the first frame only.
    let parameters = WebSocketDeflateParameters::default();
    let mut client = deflating(WebSocketRole::Client, parameters);
    client.receive(&[0xc1, 0x07, 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]);
    client.receive(&[0x41, 0x03, 0xf2, 0x48, 0xcd]);
    client.receive(&[0x80, 0x04, 0xc9, 0xc9, 0x07, 0x00]);
    // §7.2.3.2: the second "Hello" refers to the first through the shared window.
    client.receive(&[0xc1, 0x05, 0xf2, 0x00, 0x11, 0x00, 0x00]);
    // §7.2.3.3: a block with no compression.
    client.receive(&[0xc1, 0x0b, 0x00, 0x05, 0x00, 0xfa, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00]);
    // §7.2.3.4: the last block with BFINAL set.
    client.receive(&[0xc1, 0x08, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00]);
    let hello = WebSocketEvent::Text("Hello".into());
    assert_eq!(events(&mut client), [hello.clone(), hello.clone(), hello.clone(), hello.clone(), hello]);
    // RSV1 without permessage-deflate, or on a continuation, fails (RFC 7692 §6).
    let mut plain = connection(WebSocketRole::Client);
    plain.receive(&[0xc1, 0x07, 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]);
    assert!(matches!(events(&mut plain)[0], WebSocketEvent::Closed { code: WebSocketCloseCode::PROTOCOL_ERROR, .. }));
    let mut deflate = deflating(WebSocketRole::Client, parameters);
    deflate.receive(&[0x41, 0x03, 0xf2, 0x48, 0xcd, 0xc0, 0x04, 0xc9, 0xc9, 0x07, 0x00]);
    assert!(matches!(events(&mut deflate)[0], WebSocketEvent::Closed { code: WebSocketCloseCode::PROTOCOL_ERROR, .. }));
}

#[test]
fn deflated_messages_both_ways() {
    // RFC 7692 §7.2: messages compressed and back, with and without context takeover.
    for no_context_takeover in [false, true] {
        let parameters = WebSocketDeflateParameters {
            server_no_context_takeover: no_context_takeover,
            client_no_context_takeover: no_context_takeover,
            server_max_window_bits: Some(10),
            client_max_window_bits: Some(Some(9)),
        };
        let mut client = deflating(WebSocketRole::Client, parameters);
        let mut server = deflating(WebSocketRole::Server, parameters);
        let message = "a repeated message, ".repeat(200);
        let mut sizes = Vec::new();
        for _ in 0..3 {
            client.send_text(&message).unwrap();
            let bytes = output(&mut client);
            sizes.push(bytes.len());
            server.receive(&bytes);
            assert_eq!(events(&mut server), [WebSocketEvent::Text(message.clone())]);
            server.send_binary(message.as_bytes()).unwrap();
            client.receive(&output(&mut server));
            assert_eq!(events(&mut client), [WebSocketEvent::Binary(message.as_bytes().to_vec())]);
        }
        assert!(sizes[0] < message.len() / 4, "compressed: {sizes:?}");
        if no_context_takeover {
            assert_eq!(sizes[1], sizes[0], "each message alone");
        } else {
            assert!(sizes[1] < sizes[0], "the window is shared: {sizes:?}");
        }
    }
    // A bomb: far more than the limit once inflated is 1009.
    let config = WebSocketConfig { maximum_message_size: 1000, ..WebSocketConfig::default() };
    let parameters = WebSocketDeflateParameters::default();
    let mut sender = deflating(WebSocketRole::Server, parameters);
    let mut receiver =
        WebSocketConnection::new(WebSocketRole::Client, config, Some(parameters), Fixture::random(6)).unwrap();
    sender.send_binary(&vec![0; 100_000]).unwrap();
    receiver.receive(&output(&mut sender));
    assert!(matches!(
        events(&mut receiver)[0],
        WebSocketEvent::Closed { code: WebSocketCloseCode::MESSAGE_TOO_BIG, .. }
    ));
}

#[test]
fn deflate_parameters() {
    // RFC 7692 §7.1: flags without values, windows of 8 to 15, nothing repeated or unknown.
    let pair = |name: &str, value: Option<&str>| (name.to_string(), value.map(str::to_string));
    let parsed = WebSocketDeflateParameters::parse(&[
        pair("client_max_window_bits", None),
        pair("server_no_context_takeover", None),
    ])
    .unwrap();
    assert_eq!(parsed.client_max_window_bits, Some(None));
    assert!(parsed.server_no_context_takeover);
    for invalid in [
        vec![pair("server_max_window_bits", Some("7"))],
        vec![pair("server_max_window_bits", Some("16"))],
        vec![pair("server_max_window_bits", Some("010"))],
        vec![pair("server_max_window_bits", None)],
        vec![pair("client_no_context_takeover", Some("1"))],
        vec![pair("server_no_context_takeover", None), pair("server_no_context_takeover", None)],
        vec![pair("unknown", None)],
    ] {
        assert!(WebSocketDeflateParameters::parse(&invalid).is_err(), "{invalid:?}");
    }
    // §7.1.2.2: a limit of the client's window only if it offered to take one.
    let offer = WebSocketDeflateParameters::default();
    let response =
        WebSocketDeflateParameters { client_max_window_bits: Some(Some(10)), ..WebSocketDeflateParameters::default() };
    assert!(WebSocketDeflateParameters::check_response(&offer, &response).is_err());
    let offer =
        WebSocketDeflateParameters { client_max_window_bits: Some(None), ..WebSocketDeflateParameters::default() };
    assert!(WebSocketDeflateParameters::check_response(&offer, &response).is_ok());
    assert_eq!(WebSocketDeflateParameters::accept(&offer).client_max_window_bits, None);
}

#[test]
fn deflate_blocks_after_a_final_one() {
    // RFC 7692 §7.2.1: after a block with BFINAL, the next block follows at
    // the next byte; §7.2.3.5: two blocks in one message.
    let mut client = deflating(WebSocketRole::Client, WebSocketDeflateParameters::default());
    // "Hel" in a block with BFINAL, then "lo" in one without (fixed Huffman codes).
    client.receive(&[0xc1, 0x09, 0xf3, 0x48, 0xcd, 0x01, 0x00, 0xca, 0xc9, 0x07, 0x00]);
    client.receive(&[0xc1, 0x0d, 0xf2, 0x48, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0xc9, 0xc9, 0x07, 0x00]);
    // Context takeover goes on across a message that ended with BFINAL (§7.2.3.2 after §7.2.3.4).
    client.receive(&[0xc1, 0x08, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00]);
    client.receive(&[0xc1, 0x05, 0xf2, 0x00, 0x11, 0x00, 0x00]);
    let hello = WebSocketEvent::Text("Hello".into());
    assert_eq!(events(&mut client), [hello.clone(), hello.clone(), hello.clone(), hello]);
}

#[test]
fn pongs_until_the_peer_closes() {
    // RFC 6455 §5.5.2: a Ping is answered with a Pong unless a Close arrived,
    // this end's own Close sent or not.
    let mut server = connection(WebSocketRole::Server);
    server.close(WebSocketCloseCode::NORMAL, "").unwrap();
    output(&mut server);
    server.receive(&[0x89, 0x80, 1, 2, 3, 4]);
    let pong = output(&mut server);
    assert_eq!(&pong[..2], [0x8A, 0x00], "{pong:02x?}");
    server.receive(&[0x88, 0x82, 0, 0, 0, 0, 0x03, 0xE8]);
    events(&mut server);
    server.receive(&[0x89, 0x80, 1, 2, 3, 4]);
    assert!(output(&mut server).is_empty(), "nothing after the peer's Close");
}

#[test]
fn events_are_never_dropped() {
    // Every message is delivered, however many Pings come before it:
    // reading stops while the events wait.
    let config = WebSocketConfig { maximum_events: 16, ..WebSocketConfig::default() };
    let mut server = WebSocketConnection::new(WebSocketRole::Server, config, None, Fixture::random(7)).unwrap();
    let mut bytes = [0x89, 0x80, 1, 2, 3, 4].repeat(100);
    bytes.extend_from_slice(&[0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]);
    server.receive(&bytes);
    assert!(!server.wants_receive());
    let received = events(&mut server);
    assert_eq!(received.len(), 101);
    assert_eq!(received.last(), Some(&WebSocketEvent::Text("Hello".into())));
    assert!(server.wants_receive());
}

#[test]
fn hints_of_the_offer() {
    // RFC 7692 §7.1.1.1, §7.1.2.2: a client keeps to its own offer's
    // client_no_context_takeover and client_max_window_bits, repeated in
    // the response or not.
    let offer = WebSocketDeflateParameters {
        client_no_context_takeover: true,
        client_max_window_bits: Some(Some(10)),
        ..WebSocketDeflateParameters::default()
    };
    let used = WebSocketDeflateParameters::default().with_hints(&offer);
    assert!(used.client_no_context_takeover);
    assert_eq!(used.client_max_window_bits, Some(Some(10)));
    let response =
        WebSocketDeflateParameters { client_max_window_bits: Some(Some(9)), ..WebSocketDeflateParameters::default() };
    assert_eq!(response.with_hints(&offer).client_max_window_bits, Some(Some(9)), "the smaller");
}
