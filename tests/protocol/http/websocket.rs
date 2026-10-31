//! WebSocket's opening handshake over HTTP (RFC 6455 §4, RFC 8441, RFC
//! 9220), with the key and accept value of RFC 6455 §1.3, over HTTP/1.1
//! and HTTP/2 connections, then messages on their streams.

use umilib::protocol::http::v1::{H1Config, H1Connection};
use umilib::protocol::http::v2::{H2Config, H2Connection};
use umilib::protocol::http::websocket::{WebSocketAgreement, WebSocketHandshake, WebSocketOffer};
use umilib::protocol::http::{HTTPConnection, HTTPEvent, HTTPMethod, HTTPRequest, HTTPStatus, HTTPVersion};
use umilib::protocol::websocket::{
    WebSocketConfig, WebSocketConnection, WebSocketDeflateParameters, WebSocketEvent, WebSocketRole,
};
use umilib::runtime::Instant;

use crate::tls::handshake::Fixture;

#[test]
fn the_accept_value_of_section_1_3() {
    assert_eq!(WebSocketHandshake::accept(b"dGhlIHNhbXBsZSBub25jZQ=="), b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

fn offer_of(request: &HTTPRequest, version: HTTPVersion) -> Result<WebSocketOffer, u16> {
    WebSocketHandshake::check_request(request, version).map_err(|response| response.status.0)
}

#[test]
fn requests_a_server_checks() {
    // RFC 6455 §4.2.1: GET over HTTP/1.1, Upgrade and Connection, a key of
    // 16 bytes, version 13 (else 426 and the version, §4.4).
    let mut random = Fixture::random(1);
    let deflate =
        WebSocketDeflateParameters { client_max_window_bits: Some(None), ..WebSocketDeflateParameters::default() };
    let (request, key) = WebSocketHandshake::request(
        b"http",
        b"server.example.com",
        b"/chat",
        &["chat", "superchat"],
        Some(deflate),
        &mut *random,
    )
    .unwrap();
    let offer = offer_of(&request, HTTPVersion::HTTP1_1).unwrap();
    assert_eq!(offer.key.as_deref(), Some(key.as_slice()));
    assert_eq!(offer.protocols, ["chat", "superchat"]);
    assert_eq!(offer.deflate, [deflate]);
    let invalid = |change: &dyn Fn(&mut HTTPRequest)| {
        let mut request = request.clone();
        change(&mut request);
        offer_of(&request, HTTPVersion::HTTP1_1).unwrap_err()
    };
    assert_eq!(invalid(&|request| request.method = HTTPMethod::POST), 400);
    assert_eq!(
        invalid(&|request| {
            request.fields.remove(b"upgrade");
        }),
        400
    );
    assert_eq!(invalid(&|request| request.fields.set(b"connection", b"keep-alive").unwrap()), 400);
    assert_eq!(invalid(&|request| request.fields.set(b"sec-websocket-key", b"c2hvcnQ=").unwrap()), 400);
    assert_eq!(invalid(&|request| request.fields.set(b"sec-websocket-version", b"8").unwrap()), 426);
    assert_eq!(offer_of(&request, HTTPVersion::HTTP1_0).unwrap_err(), 400);
    // A version of HTTP whose handshake is not known is not taken for a known one.
    for version in
        [HTTPVersion { major: 1, minor: 2 }, HTTPVersion { major: 4, minor: 0 }, HTTPVersion { major: 0, minor: 9 }]
    {
        assert_eq!(offer_of(&request, version).unwrap_err(), 505, "{version:?}");
    }
    let refused = WebSocketHandshake::check_request(
        &{
            let mut request = request.clone();
            request.fields.set(b"sec-websocket-version", b"8").unwrap();
            request
        },
        HTTPVersion::HTTP1_1,
    )
    .unwrap_err();
    assert_eq!(refused.fields.get(b"sec-websocket-version"), Some(&b"13"[..]));
    // An offer of invalid parameters is declined, not an error (RFC 7692 §5).
    let mut bad_offer = request.clone();
    bad_offer
        .fields
        .set(b"sec-websocket-extensions", b"permessage-deflate; server_max_window_bits=99, permessage-deflate")
        .unwrap();
    assert_eq!(offer_of(&bad_offer, HTTPVersion::HTTP1_1).unwrap().deflate, [WebSocketDeflateParameters::default()]);
    // RFC 8441 §4: an extended CONNECT of :protocol websocket, without a key.
    let connect = WebSocketHandshake::connect_request(b"https", b"server.example.com", b"/chat", &[], None).unwrap();
    assert_eq!(offer_of(&connect, HTTPVersion::HTTP2).unwrap().key, None);
    assert_eq!(offer_of(&request, HTTPVersion::HTTP2).unwrap_err(), 400);
}

#[test]
fn responses_a_client_checks() {
    // RFC 6455 §4.1: 101 with the accept value of its key; a subprotocol and
    // an extension of those offered only.
    let mut random = Fixture::random(2);
    let deflate = WebSocketDeflateParameters::default();
    let (request, key) =
        WebSocketHandshake::request(b"http", b"a", b"/", &["chat"], Some(deflate), &mut *random).unwrap();
    let offer = offer_of(&request, HTTPVersion::HTTP1_1).unwrap();
    let agreement = WebSocketHandshake::agree(&offer, &["superchat", "chat"], true);
    assert_eq!(agreement, WebSocketAgreement { protocol: Some("chat".into()), deflate: Some(deflate) });
    let response = WebSocketHandshake::response(&offer, &agreement).unwrap();
    assert_eq!(response.status, HTTPStatus::SWITCHING_PROTOCOLS);
    assert_eq!(
        WebSocketHandshake::check_response(&response, Some(&key), &["chat"], Some(&deflate)).unwrap(),
        agreement
    );
    assert!(
        WebSocketHandshake::check_response(&response, Some(b"dGhlIHNhbXBsZSBub25jZQ=="), &["chat"], Some(&deflate))
            .is_err()
    );
    assert!(WebSocketHandshake::check_response(&response, Some(&key), &["other"], Some(&deflate)).is_err());
    assert!(WebSocketHandshake::check_response(&response, Some(&key), &["chat"], None).is_err());
    let mut ok = response.clone();
    ok.status = HTTPStatus::OK;
    assert!(WebSocketHandshake::check_response(&ok, Some(&key), &["chat"], Some(&deflate)).is_err());
    assert!(WebSocketHandshake::check_response(&ok, None, &["chat"], Some(&deflate)).is_ok());
    assert!(
        WebSocketHandshake::response(&offer, &WebSocketAgreement { protocol: Some("other".into()), deflate: None })
            .is_err()
    );
}

/// Messages both ways between a client and a server WebSocket over `move_bytes`.
fn talk(
    client: &mut WebSocketConnection,
    server: &mut WebSocketConnection,
    mut move_bytes: impl FnMut(Vec<u8>, bool) -> Vec<u8>,
) {
    client.send_text("hello over HTTP").unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    server.receive(&move_bytes(out, true));
    assert_eq!(server.poll_event(), Some(WebSocketEvent::Text("hello over HTTP".into())));
    server.send_binary(b"and back").unwrap();
    let mut out = Vec::new();
    server.transmit(&mut out);
    client.receive(&move_bytes(out, false));
    assert_eq!(client.poll_event(), Some(WebSocketEvent::Binary(b"and back".to_vec())));
}

fn read_all(connection: &mut dyn HTTPConnection, stream: umilib::protocol::http::HTTPStreamID) -> Vec<u8> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let count = connection.read_data(stream, &mut buffer).unwrap();
        if count == 0 {
            return data;
        }
        data.extend_from_slice(&buffer[..count]);
    }
}

#[test]
fn over_http_1_1() {
    // RFC 6455 §4: Upgrade, 101, then the tunnel carries the frames (RFC 9112 §6.3).
    let now = Instant::from_nanos(1);
    let mut client = H1Connection::client(H1Config::default(), now);
    let mut server = H1Connection::server(H1Config::default(), now);
    let deflate = WebSocketDeflateParameters::default();
    let (request, key) =
        WebSocketHandshake::request(b"http", b"a", b"/chat", &[], Some(deflate), &mut *Fixture::random(3)).unwrap();
    let stream = client.send_request(&request, false).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    server.receive(&out, now);
    let Some(HTTPEvent::Request { stream: served, request: received, .. }) = server.poll_event() else { panic!() };
    let offer = WebSocketHandshake::check_request(&received, HTTPVersion::HTTP1_1).unwrap();
    let agreement = WebSocketHandshake::agree(&offer, &[], true);
    server.send_response(served, &WebSocketHandshake::response(&offer, &agreement).unwrap(), false).unwrap();
    let mut out = Vec::new();
    server.transmit(&mut out);
    client.receive(&out, now);
    let Some(HTTPEvent::Response { response, .. }) = client.poll_event() else { panic!() };
    let agreed = WebSocketHandshake::check_response(&response, Some(&key), &[], Some(&deflate)).unwrap();
    let mut websocket_client =
        WebSocketConnection::new(WebSocketRole::Client, WebSocketConfig::default(), agreed.deflate, Fixture::random(4))
            .unwrap();
    let mut websocket_server = WebSocketConnection::new(
        WebSocketRole::Server,
        WebSocketConfig::default(),
        agreement.deflate,
        Fixture::random(5),
    )
    .unwrap();
    talk(&mut websocket_client, &mut websocket_server, |bytes, from_client| {
        let (from, to, from_stream, to_stream) = if from_client {
            (&mut client, &mut server, stream, served)
        } else {
            (&mut server, &mut client, served, stream)
        };
        from.send_data(from_stream, &bytes, false).unwrap();
        let mut out = Vec::new();
        from.transmit(&mut out);
        to.receive(&out, now);
        read_all(to, to_stream)
    });
}

#[test]
fn over_http_2() {
    // RFC 8441: SETTINGS_ENABLE_CONNECT_PROTOCOL, an extended CONNECT, 200, then the stream's DATA.
    let now = Instant::from_nanos(1);
    let mut client = H2Connection::client(H2Config::default(), now);
    let mut server = H2Connection::server(H2Config { enable_connect_protocol: true, ..H2Config::default() }, now);
    let exchange = |client: &mut H2Connection, server: &mut H2Connection| {
        for _ in 0..10 {
            let mut out = Vec::new();
            client.transmit(&mut out);
            server.receive(&out, now);
            let mut back = Vec::new();
            server.transmit(&mut back);
            client.receive(&back, now);
        }
    };
    exchange(&mut client, &mut server);
    let request = WebSocketHandshake::connect_request(b"https", b"a", b"/chat", &[], None).unwrap();
    let stream = client.send_request(&request, false).unwrap();
    exchange(&mut client, &mut server);
    let Some(HTTPEvent::Request { stream: served, request: received, .. }) = server.poll_event() else { panic!() };
    let offer = WebSocketHandshake::check_request(&received, HTTPVersion::HTTP2).unwrap();
    let response = WebSocketHandshake::response(&offer, &WebSocketHandshake::agree(&offer, &[], false)).unwrap();
    assert_eq!(response.status, HTTPStatus::OK);
    server.send_response(served, &response, false).unwrap();
    exchange(&mut client, &mut server);
    let Some(HTTPEvent::Response { response, .. }) = client.poll_event() else { panic!() };
    WebSocketHandshake::check_response(&response, None, &[], None).unwrap();
    let mut websocket_client =
        WebSocketConnection::new(WebSocketRole::Client, WebSocketConfig::default(), None, Fixture::random(6)).unwrap();
    let mut websocket_server =
        WebSocketConnection::new(WebSocketRole::Server, WebSocketConfig::default(), None, Fixture::random(7)).unwrap();
    talk(&mut websocket_client, &mut websocket_server, |bytes, from_client| {
        if from_client {
            client.send_data(stream, &bytes, false).unwrap();
        } else {
            server.send_data(served, &bytes, false).unwrap();
        }
        exchange(&mut client, &mut server);
        if from_client { read_all(&mut server, served) } else { read_all(&mut client, stream) }
    });
}
