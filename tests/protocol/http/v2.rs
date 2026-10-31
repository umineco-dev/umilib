//! HTTP/2 (RFC 9113): a client and a server together, and a server given
//! frames that break the rules, its answers (RST_STREAM, GOAWAY) compared
//! with the errors the RFC names.

use std::time::Duration;

use umilib::codec::hpack::{HPACKEncoder, HPACKEncoderConfig, HPACKField};
use umilib::protocol::http::v2::{
    H2Config, H2Connection, H2ErrorCode, H2Frame, H2FrameHeader, H2FrameType, H2PriorityField, H2SettingID,
};
use umilib::protocol::http::{
    HTTPConnection, HTTPEvent, HTTPFields, HTTPMethod, HTTPPriority, HTTPRequest, HTTPReset, HTTPResponse, HTTPStatus,
    HTTPStreamID,
};
use umilib::runtime::Instant;

fn now() -> Instant {
    Instant::from_nanos(1_000_000_000)
}

/// A client and a server whose bytes move at once.
struct Pair {
    client: H2Connection,
    server: H2Connection,
}

impl Pair {
    fn new(client: H2Config, server: H2Config) -> Pair {
        let mut pair =
            Pair { client: H2Connection::client(client, now()), server: H2Connection::server(server, now()) };
        pair.run();
        pair
    }

    fn default() -> Pair {
        Pair::new(H2Config::default(), H2Config::default())
    }

    fn run(&mut self) {
        for _ in 0..10_000 {
            let mut bytes = Vec::new();
            self.client.transmit(&mut bytes);
            let moved = !bytes.is_empty();
            self.server.receive(&bytes, now());
            let mut back = Vec::new();
            self.server.transmit(&mut back);
            self.client.receive(&back, now());
            if !moved && back.is_empty() {
                return;
            }
        }
        panic!("never quiet");
    }

    fn events(connection: &mut H2Connection) -> Vec<HTTPEvent> {
        std::iter::from_fn(|| connection.poll_event()).collect()
    }
}

fn read_all(connection: &mut H2Connection, stream: HTTPStreamID) -> Vec<u8> {
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

fn request(path: &str) -> HTTPRequest {
    HTTPRequest::new(HTTPMethod::GET, b"https", b"example.com", path.as_bytes())
}

fn first_request(events: &[HTTPEvent]) -> (HTTPStreamID, HTTPRequest) {
    events
        .iter()
        .find_map(|event| match event {
            HTTPEvent::Request { stream, request, .. } => Some((*stream, request.clone())),
            _ => None,
        })
        .expect("a request")
}

/// The frames of `bytes`: their headers and payloads.
fn frames(bytes: &[u8]) -> Vec<(H2FrameHeader, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut offset = 0;
    while let Some(header) = H2FrameHeader::decode(&bytes[offset..]) {
        let end = offset + 9 + header.length as usize;
        frames.push((header, bytes[offset + 9..end].to_vec()));
        offset = end;
    }
    frames
}

/// A raw client: the preface and SETTINGS, then `frames`; the server's answer.
fn raw(
    config: H2Config,
    build: impl FnOnce(&mut HPACKEncoder, &mut Vec<u8>),
) -> (H2Connection, Vec<(H2FrameHeader, Vec<u8>)>) {
    let mut server = H2Connection::server(config, now());
    let mut bytes = H2Connection::PREFACE.to_vec();
    H2Frame::Settings { ack: false, settings: vec![] }.encode(&mut bytes);
    let mut encoder = HPACKEncoder::new(HPACKEncoderConfig::default(), 4096);
    build(&mut encoder, &mut bytes);
    server.receive(&bytes, now());
    let mut out = Vec::new();
    server.transmit(&mut out);
    (server, frames(&out))
}

fn headers(encoder: &mut HPACKEncoder, stream: u32, fields: &[(&[u8], &[u8])], end_stream: bool, out: &mut Vec<u8>) {
    let fields: Vec<HPACKField> = fields.iter().map(|(name, value)| HPACKField::new(name, value)).collect();
    let mut block = Vec::new();
    encoder.encode(&fields, &mut block);
    H2Frame::Headers { stream, block: &block, end_stream, end_headers: true, priority: None }.encode(out);
}

const GET: [(&[u8], &[u8]); 4] =
    [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"example.com"), (b":path", b"/")];

/// The error code of the GOAWAY the server sent.
fn goaway(frames: &[(H2FrameHeader, Vec<u8>)]) -> Option<H2ErrorCode> {
    frames
        .iter()
        .find(|(header, _)| header.frame_type == H2FrameType::GOAWAY)
        .map(|(_, payload)| H2ErrorCode(u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]])))
}

/// The error code of the RST_STREAM the server sent on `stream`.
fn reset(frames: &[(H2FrameHeader, Vec<u8>)], stream: u32) -> Option<H2ErrorCode> {
    frames
        .iter()
        .find(|(header, _)| header.frame_type == H2FrameType::RST_STREAM && header.stream == stream)
        .map(|(_, payload)| H2ErrorCode(u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])))
}

#[test]
fn prefaces_and_settings() {
    // RFC 9113 §3.4: the client's magic and SETTINGS, the server's SETTINGS,
    // both acknowledged (§6.5.3); RFC 9218 §2.1: no RFC 7540 priorities.
    let pair = Pair::default();
    assert!(pair.client.settings_since.is_none() && pair.server.settings_since.is_none());
    assert_eq!(pair.server.peer.max_concurrent_streams, Some(100));
    assert!(!pair.server.peer.enable_push, "push is off (RFC 9113 §8.4)");
    assert!(pair.client.peer.no_rfc7540_priorities && pair.server.peer.no_rfc7540_priorities);
    let mut client = H2Connection::client(H2Config::default(), now());
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert!(out.starts_with(H2Connection::PREFACE));
    assert_eq!(frames(&out[24..])[0].0.frame_type, H2FrameType::SETTINGS);
}

#[test]
fn an_exchange_with_content_and_trailers() {
    let mut pair = Pair::default();
    let mut post = HTTPRequest::new(HTTPMethod::POST, b"https", b"example.com", b"/upload");
    post.fields.append(b"content-type", b"text/plain").unwrap();
    let stream = pair.client.send_request(&post, false).unwrap();
    pair.client.send_data(stream, b"hello, ", false).unwrap();
    pair.client.send_data(stream, b"server", false).unwrap();
    pair.client.send_trailers(stream, &HTTPFields::new().with(b"x-sum", b"13").unwrap()).unwrap();
    pair.run();
    let events = Pair::events(&mut pair.server);
    let (served, received) = first_request(&events);
    assert_eq!(
        (received.method, received.scheme.as_deref(), received.authority.as_deref(), received.path.as_slice()),
        (HTTPMethod::POST, Some(&b"https"[..]), Some(&b"example.com"[..]), &b"/upload"[..])
    );
    assert_eq!(read_all(&mut pair.server, served), b"hello, server");
    assert!(
        events.contains(&HTTPEvent::Trailers {
            stream: served,
            fields: HTTPFields::new().with(b"x-sum", b"13").unwrap()
        })
    );
    assert!(events.contains(&HTTPEvent::End { stream: served }));
    pair.server.send_response(served, &HTTPResponse::new(HTTPStatus::EARLY_HINTS), false).unwrap();
    pair.server.send_response(served, &HTTPResponse::new(HTTPStatus::OK), false).unwrap();
    pair.server.send_data(served, b"done", true).unwrap();
    pair.run();
    let events = Pair::events(&mut pair.client);
    let statuses: Vec<u16> = events
        .iter()
        .filter_map(|event| match event {
            HTTPEvent::Response { response, .. } => Some(response.status.0),
            _ => None,
        })
        .collect();
    assert_eq!(statuses, [103, 200]);
    assert_eq!(read_all(&mut pair.client, stream), b"done");
    assert!(pair.client.streams.is_empty() && pair.server.streams.is_empty());
    // No 101 in HTTP/2 (§8.6).
    let next = pair.client.send_request(&request("/"), true).unwrap();
    pair.run();
    let served = first_request(&Pair::events(&mut pair.server)).0;
    assert!(pair.server.send_response(served, &HTTPResponse::new(HTTPStatus::SWITCHING_PROTOCOLS), false).is_err());
    let _ = next;
}

#[test]
fn flow_control_moves_large_content() {
    // RFC 9113 §6.9: windows smaller than the content; WINDOW_UPDATE as it is read.
    let small = H2Config { initial_window_size: 20_000, connection_window: 30_000, ..H2Config::default() };
    let mut pair = Pair::new(small, small);
    let data: Vec<u8> = (0..1_000_000u32).map(|index| (index % 253) as u8).collect();
    let stream =
        pair.client.send_request(&HTTPRequest::new(HTTPMethod::PUT, b"https", b"example.com", b"/big"), false).unwrap();
    let mut written = 0;
    let mut received = Vec::new();
    let mut served = None;
    for _ in 0..10_000 {
        if written < data.len() {
            written += pair.client.send_data(stream, &data[written..], true).unwrap();
        }
        pair.run();
        for event in Pair::events(&mut pair.server) {
            if let HTTPEvent::Request { stream, .. } = event {
                served = Some(stream);
            }
        }
        if let Some(served) = served {
            received.extend(read_all(&mut pair.server, served));
        }
        if received.len() == data.len() {
            break;
        }
        // Neither end may send past what the other allows.
        assert!(pair.client.send_window >= 0 && pair.server.receive_window >= 0);
    }
    assert!(received == data);
}

#[test]
fn malformed_requests_are_reset() {
    // RFC 9113 §8.1.1, §8.2, §8.3.1: each is a stream error of PROTOCOL_ERROR.
    let cases: Vec<Vec<(&[u8], &[u8])>> = vec![
        vec![(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/"), (b"X-Upper", b"1")],
        vec![(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/"), (b"connection", b"keep-alive")],
        vec![(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/"), (b"transfer-encoding", b"chunked")],
        vec![(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/"), (b"te", b"gzip")],
        vec![(b":method", b"GET"), (b"accept", b"*/*"), (b":scheme", b"https"), (b":path", b"/")],
        vec![(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/"), (b":status", b"200")],
        vec![(b":method", b"GET"), (b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/")],
        vec![(b":scheme", b"https"), (b":path", b"/")],
        vec![(b":method", b"GET"), (b":path", b"/")],
        vec![(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"")],
        vec![(b":method", b"CONNECT"), (b":authority", b"example.com:443"), (b":path", b"/")],
        vec![
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/"),
            (b":protocol", b"websocket"),
        ],
        vec![
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"a.example"),
            (b":path", b"/"),
            (b"host", b"b.example"),
        ],
        vec![(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"user@example.com"), (b":path", b"/")],
    ];
    for fields in cases {
        let (server, frames) = raw(H2Config::default(), |encoder, out| headers(encoder, 1, &fields, true, out));
        assert_eq!(reset(&frames, 1), Some(H2ErrorCode::PROTOCOL_ERROR), "{fields:?}");
        assert_eq!(goaway(&frames), None, "{fields:?}");
        assert!(server.streams.is_empty());
    }
    // Content of another length than Content-Length (§8.1.1).
    let fields = [GET[0], GET[1], GET[2], GET[3], (b"content-length", b"10")];
    let (_, frames) = raw(H2Config::default(), |encoder, out| {
        headers(encoder, 1, &fields, false, out);
        H2Frame::Data { stream: 1, data: b"short", end_stream: true, length: 5 }.encode(out);
    });
    assert_eq!(reset(&frames, 1), Some(H2ErrorCode::PROTOCOL_ERROR));
}

#[test]
fn connection_errors() {
    // RFC 9113 §3.4, §4.2, §5.1, §5.1.1, §6: each answered with GOAWAY and its code.
    /// What a case writes after the preface.
    type Build = Box<dyn Fn(&mut HPACKEncoder, &mut Vec<u8>)>;
    let cases: Vec<(&str, H2ErrorCode, Build)> = vec![
        (
            "DATA on stream 0",
            H2ErrorCode::PROTOCOL_ERROR,
            Box::new(|_, out| H2Frame::Data { stream: 0, data: b"x", end_stream: false, length: 1 }.encode(out)),
        ),
        (
            "DATA on an idle stream",
            H2ErrorCode::PROTOCOL_ERROR,
            Box::new(|_, out| H2Frame::Data { stream: 1, data: b"x", end_stream: false, length: 1 }.encode(out)),
        ),
        (
            "HEADERS on a server's stream",
            H2ErrorCode::PROTOCOL_ERROR,
            Box::new(|encoder, out| headers(encoder, 2, &GET, true, out)),
        ),
        (
            "a frame too large",
            H2ErrorCode::FRAME_SIZE_ERROR,
            Box::new(|_, out| H2Frame::write(H2FrameType(0x21), 0, 0, &vec![0; 20_000], out)),
        ),
        (
            "SETTINGS of 5 bytes",
            H2ErrorCode::FRAME_SIZE_ERROR,
            Box::new(|_, out| H2Frame::write(H2FrameType::SETTINGS, 0, 0, &[0; 5], out)),
        ),
        (
            "SETTINGS on a stream",
            H2ErrorCode::PROTOCOL_ERROR,
            Box::new(|_, out| H2Frame::write(H2FrameType::SETTINGS, 0, 1, &[], out)),
        ),
        (
            "a window above 2^31 - 1",
            H2ErrorCode::FLOW_CONTROL_ERROR,
            Box::new(|_, out| {
                H2Frame::Settings { ack: false, settings: vec![(H2SettingID::INITIAL_WINDOW_SIZE, 1 << 31)] }
                    .encode(out)
            }),
        ),
        (
            "a frame size too small",
            H2ErrorCode::PROTOCOL_ERROR,
            Box::new(|_, out| {
                H2Frame::Settings { ack: false, settings: vec![(H2SettingID::MAX_FRAME_SIZE, 100)] }.encode(out)
            }),
        ),
        (
            "ENABLE_PUSH of 2",
            H2ErrorCode::PROTOCOL_ERROR,
            Box::new(|_, out| {
                H2Frame::Settings { ack: false, settings: vec![(H2SettingID::ENABLE_PUSH, 2)] }.encode(out)
            }),
        ),
        (
            "a connection window increment of 0",
            H2ErrorCode::PROTOCOL_ERROR,
            Box::new(|_, out| H2Frame::write(H2FrameType::WINDOW_UPDATE, 0, 0, &[0; 4], out)),
        ),
        (
            "a connection window past 2^31 - 1",
            H2ErrorCode::FLOW_CONTROL_ERROR,
            Box::new(|_, out| H2Frame::WindowUpdate { stream: 0, increment: 0x7FFF_FFFF }.encode(out)),
        ),
        (
            "PING of 7 bytes",
            H2ErrorCode::FRAME_SIZE_ERROR,
            Box::new(|_, out| H2Frame::write(H2FrameType::PING, 0, 0, &[0; 7], out)),
        ),
        (
            "PUSH_PROMISE from a client",
            H2ErrorCode::PROTOCOL_ERROR,
            Box::new(|_, out| H2Frame::write(H2FrameType::PUSH_PROMISE, 4, 1, &[0, 0, 0, 2], out)),
        ),
        (
            "CONTINUATION alone",
            H2ErrorCode::PROTOCOL_ERROR,
            Box::new(|_, out| H2Frame::Continuation { stream: 1, block: &[], end_headers: true }.encode(out)),
        ),
        (
            "a frame inside a field block",
            H2ErrorCode::PROTOCOL_ERROR,
            Box::new(|encoder, out| {
                let fields: Vec<HPACKField> = GET.iter().map(|(name, value)| HPACKField::new(name, value)).collect();
                let mut block = Vec::new();
                encoder.encode(&fields, &mut block);
                H2Frame::Headers { stream: 1, block: &block, end_stream: true, end_headers: false, priority: None }
                    .encode(out);
                H2Frame::Ping { ack: false, data: [0; 8] }.encode(out);
            }),
        ),
        (
            "a field block that does not decode",
            H2ErrorCode::COMPRESSION_ERROR,
            Box::new(|_, out| {
                H2Frame::Headers { stream: 1, block: &[0x80], end_stream: true, end_headers: true, priority: None }
                    .encode(out)
            }),
        ),
        (
            "RST_STREAM on an idle stream",
            H2ErrorCode::PROTOCOL_ERROR,
            Box::new(|_, out| H2Frame::ResetStream { stream: 1, code: H2ErrorCode::CANCEL }.encode(out)),
        ),
        (
            "padding as long as the payload",
            H2ErrorCode::PROTOCOL_ERROR,
            Box::new(|encoder, out| {
                headers(encoder, 1, &GET, false, out);
                H2Frame::write(H2FrameType::DATA, 0x8, 1, &[5, 1, 2], out);
            }),
        ),
        (
            "PRIORITY_UPDATE of stream 0",
            H2ErrorCode::PROTOCOL_ERROR,
            Box::new(|_, out| H2Frame::PriorityUpdate { prioritized: 0, value: b"u=1" }.encode(out)),
        ),
    ];
    for (name, code, build) in cases {
        let (server, frames) = raw(H2Config::default(), |encoder, out| build(encoder, out));
        assert_eq!(goaway(&frames), Some(code), "{name}");
        assert!(server.is_closed(), "{name}");
    }
    // An invalid preface (§3.4), and SETTINGS not first.
    let mut server = H2Connection::server(H2Config::default(), now());
    server.receive(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", now());
    assert!(server.is_closed());
    let mut server = H2Connection::server(H2Config::default(), now());
    let mut bytes = H2Connection::PREFACE.to_vec();
    H2Frame::Ping { ack: false, data: [0; 8] }.encode(&mut bytes);
    server.receive(&bytes, now());
    assert!(server.is_closed());
}

#[test]
fn stream_errors() {
    // §6.9: DATA past a stream's window is FLOW_CONTROL_ERROR; §5.1: DATA
    // after END_STREAM is STREAM_CLOSED; a window increment of 0 on a
    // stream is PROTOCOL_ERROR; §6.3: PRIORITY not of 5 bytes is FRAME_SIZE_ERROR.
    // §6.9.2: a window below the initial one holds once the client
    // acknowledged it; before, the client may send what the initial allows.
    let small = H2Config { initial_window_size: 10, ..H2Config::default() };
    let post = [(&b":method"[..], &b"POST"[..]), GET[1], GET[2], GET[3]];
    let (_, frames) = raw(small, |encoder, out| {
        H2Frame::Settings { ack: true, settings: vec![] }.encode(out);
        headers(encoder, 1, &post, false, out);
        H2Frame::Data { stream: 1, data: &[0; 11], end_stream: false, length: 11 }.encode(out);
    });
    assert_eq!(reset(&frames, 1), Some(H2ErrorCode::FLOW_CONTROL_ERROR));
    let (_, frames) = raw(small, |encoder, out| {
        headers(encoder, 1, &post, false, out);
        for _ in 0..3 {
            H2Frame::Data { stream: 1, data: &[0; 13000], end_stream: false, length: 13000 }.encode(out);
        }
        H2Frame::Settings { ack: true, settings: vec![] }.encode(out);
        H2Frame::Data { stream: 1, data: &[0; 1], end_stream: false, length: 1 }.encode(out);
    });
    assert_eq!(reset(&frames, 1), Some(H2ErrorCode::FLOW_CONTROL_ERROR), "past the window once it holds");
    let (_, frames) = raw(small, |encoder, out| {
        headers(encoder, 1, &post, false, out);
        for _ in 0..3 {
            H2Frame::Data { stream: 1, data: &[0; 13000], end_stream: false, length: 13000 }.encode(out);
        }
    });
    assert_eq!(reset(&frames, 1), None, "within the initial window, before the acknowledgment");
    assert_eq!(goaway(&frames), None);
    let (_, frames) = raw(H2Config::default(), |encoder, out| {
        headers(encoder, 1, &GET, true, out);
        H2Frame::Data { stream: 1, data: b"late", end_stream: false, length: 4 }.encode(out);
    });
    assert_eq!(reset(&frames, 1), Some(H2ErrorCode::STREAM_CLOSED));
    let (_, frames) = raw(H2Config::default(), |encoder, out| {
        headers(encoder, 1, &GET, false, out);
        H2Frame::write(H2FrameType::WINDOW_UPDATE, 0, 1, &[0; 4], out);
    });
    assert_eq!(reset(&frames, 1), Some(H2ErrorCode::PROTOCOL_ERROR));
    let (_, frames) = raw(H2Config::default(), |encoder, out| {
        headers(encoder, 1, &GET, false, out);
        H2Frame::write(H2FrameType::PRIORITY, 0, 1, &[0; 4], out);
    });
    assert_eq!(reset(&frames, 1), Some(H2ErrorCode::FRAME_SIZE_ERROR));
    // §5.1.2: past SETTINGS_MAX_CONCURRENT_STREAMS, REFUSED_STREAM.
    let few = H2Config { max_concurrent_streams: 1, ..H2Config::default() };
    let (_, frames) = raw(few, |encoder, out| {
        headers(encoder, 1, &[(b":method", b"POST"), GET[1], GET[2], GET[3]], false, out);
        headers(encoder, 3, &GET, true, out);
    });
    assert_eq!(reset(&frames, 3), Some(H2ErrorCode::REFUSED_STREAM));
}

#[test]
fn field_blocks_across_frames() {
    // §4.3, §6.10: a block larger than a frame goes in CONTINUATION frames.
    let mut pair = Pair::default();
    let mut large = request("/");
    large.fields.append(b"x-large", &vec![b'v'; 40_000]).unwrap();
    let stream = pair.client.send_request(&large, true).unwrap();
    let mut out = Vec::new();
    pair.client.transmit(&mut out);
    let continuations =
        frames(&out).iter().filter(|(header, _)| header.frame_type == H2FrameType::CONTINUATION).count();
    assert!(continuations >= 2, "{continuations}");
    pair.server.receive(&out, now());
    let (_, received) = first_request(&Pair::events(&mut pair.server));
    assert_eq!(received.fields.get(b"x-large").map(<[u8]>::len), Some(40_000));
    let _ = stream;
}

#[test]
fn field_sections_too_large() {
    // RFC 9113 §8.2.3, RFC 6585 §5: 431, the stream ended; the connection goes on.
    let mut pair = Pair::default();
    let mut large = request("/");
    large.fields.append(b"x-large", &vec![b'v'; 70_000]).unwrap();
    let stream = pair.client.send_request(&large, true).unwrap();
    pair.run();
    let events = Pair::events(&mut pair.client);
    assert!(events.iter().any(|event| matches!(event, HTTPEvent::Response { stream: s, response, .. } if *s == stream && response.status == HTTPStatus::REQUEST_HEADER_FIELDS_TOO_LARGE)), "{events:?}");
    let next = pair.client.send_request(&request("/next"), true).unwrap();
    pair.run();
    assert_eq!(first_request(&Pair::events(&mut pair.server)).1.path, b"/next");
    let _ = next;
}

#[test]
fn going_away() {
    // RFC 9113 §6.8: GOAWAY; no new streams; those above its last stream were not processed.
    let mut pair = Pair::default();
    let first = pair.client.send_request(&request("/1"), true).unwrap();
    pair.run();
    let (served, _) = first_request(&Pair::events(&mut pair.server));
    pair.server.shutdown();
    let late = pair.client.send_request(&request("/late"), true).unwrap();
    pair.run();
    let events = Pair::events(&mut pair.client);
    assert!(events.contains(&HTTPEvent::GoAway { last: served }), "{events:?}");
    // §8.7: the request not processed is refused, and may be retried.
    assert!(events.contains(&HTTPEvent::Reset { stream: late, code: 0x7 }), "{events:?}");
    assert!(!pair.client.streams.contains_key(&(late.0 as u32)));
    assert!(pair.client.send_request(&request("/after"), true).is_err());
    // The stream under way still finishes; then both close.
    pair.server.send_response(served, &HTTPResponse::new(HTTPStatus::OK), true).unwrap();
    pair.run();
    assert!(
        Pair::events(&mut pair.client)
            .iter()
            .any(|event| matches!(event, HTTPEvent::Response { stream, .. } if *stream == first))
    );
    assert!(pair.server.is_closed() && pair.server.wants_close());
    assert!(pair.client.is_closed());
}

#[test]
fn resets_and_floods() {
    // §8.1: a server stops an upload with RST_STREAM of NO_ERROR after its response.
    let mut pair = Pair::default();
    let stream =
        pair.client.send_request(&HTTPRequest::new(HTTPMethod::POST, b"https", b"example.com", b"/"), false).unwrap();
    pair.run();
    let (served, _) = first_request(&Pair::events(&mut pair.server));
    pair.server.send_response(served, &HTTPResponse::new(HTTPStatus::CONTENT_TOO_LARGE), true).unwrap();
    pair.server.reset(served, HTTPReset::NoError).unwrap();
    pair.run();
    let events = Pair::events(&mut pair.client);
    assert!(events.contains(&HTTPEvent::Reset { stream, code: 0 }), "{events:?}");
    // Requests reset at once, too many of them: ENHANCE_YOUR_CALM (CVE-2023-44487).
    let config = H2Config { maximum_resets: 10, ..H2Config::default() };
    let (_, frames) = raw(config, |encoder, out| {
        for stream in (1..40).step_by(2) {
            headers(encoder, stream, &GET, false, out);
            H2Frame::ResetStream { stream, code: H2ErrorCode::CANCEL }.encode(out);
        }
    });
    assert_eq!(goaway(&frames), Some(H2ErrorCode::ENHANCE_YOUR_CALM));
    // Requests the server is made to reset with frames that are stream errors (a WINDOW_UPDATE
    // of 0, §6.9), too many of them: the same limit (CVE-2025-8671).
    let config = H2Config { maximum_resets: 10, ..H2Config::default() };
    let (_, frames) = raw(config, |encoder, out| {
        for stream in (1..40).step_by(2) {
            headers(encoder, stream, &GET, false, out);
            H2Frame::write(H2FrameType::WINDOW_UPDATE, 0, stream, &[0; 4], out);
        }
    });
    assert_eq!(reset(&frames, 1), Some(H2ErrorCode::PROTOCOL_ERROR));
    assert_eq!(goaway(&frames), Some(H2ErrorCode::ENHANCE_YOUR_CALM));
    // PINGs without reading the answers: ENHANCE_YOUR_CALM (§10.5).
    let (_, frames) = raw(H2Config::default(), |_, out| {
        for _ in 0..100 {
            H2Frame::Ping { ack: false, data: [7; 8] }.encode(out);
        }
    });
    assert_eq!(goaway(&frames), Some(H2ErrorCode::ENHANCE_YOUR_CALM));
    // CONTINUATION without end (CVE-2024-27316).
    let config = H2Config { maximum_field_block: 1000, ..H2Config::default() };
    let (_, frames) = raw(config, |_, out| {
        H2Frame::Headers { stream: 1, block: &[0; 500], end_stream: false, end_headers: false, priority: None }
            .encode(out);
        for _ in 0..3 {
            H2Frame::Continuation { stream: 1, block: &[0; 500], end_headers: false }.encode(out);
        }
    });
    assert_eq!(goaway(&frames), Some(H2ErrorCode::ENHANCE_YOUR_CALM));
}

#[test]
fn pings_are_answered() {
    let (_, frames) = raw(H2Config::default(), |_, out| H2Frame::Ping { ack: false, data: *b"12345678" }.encode(out));
    let answer = frames.iter().find(|(header, _)| header.frame_type == H2FrameType::PING).unwrap();
    assert_eq!((answer.0.flags, answer.1.as_slice()), (0x1, &b"12345678"[..]));
}

#[test]
fn priorities_order_the_content() {
    // RFC 9218 §4, §10: the more urgent response's content goes first.
    let mut pair = Pair::default();
    let mut low = request("/low");
    low.fields.append(b"priority", b"u=7").unwrap();
    let mut high = request("/high");
    high.fields.append(b"priority", b"u=0").unwrap();
    pair.client.send_request(&low, true).unwrap();
    pair.client.send_request(&high, true).unwrap();
    pair.run();
    let served: Vec<(HTTPStreamID, HTTPRequest)> = Pair::events(&mut pair.server)
        .into_iter()
        .filter_map(|event| match event {
            HTTPEvent::Request { stream, request, .. } => Some((stream, request)),
            _ => None,
        })
        .collect();
    for (stream, request) in &served {
        pair.server.send_response(*stream, &HTTPResponse::new(HTTPStatus::OK), false).unwrap();
        pair.server.send_data(*stream, &vec![request.path[1]; 5000], true).unwrap();
    }
    assert_eq!(pair.server.streams[&(served[1].0.0 as u32)].priority, HTTPPriority { urgency: 0, incremental: false });
    let mut out = Vec::new();
    pair.server.transmit(&mut out);
    let data: Vec<u32> = frames(&out)
        .iter()
        .filter(|(header, _)| header.frame_type == H2FrameType::DATA)
        .map(|(header, _)| header.stream)
        .collect();
    assert_eq!(data.first(), Some(&(served[1].0.0 as u32)), "the urgent stream first: {data:?}");
}

#[test]
fn extended_connect() {
    // RFC 8441 §3, §4: with SETTINGS_ENABLE_CONNECT_PROTOCOL from the
    // server, a client may send :protocol; without, it may not.
    let mut connect = HTTPRequest::new(HTTPMethod::CONNECT, b"https", b"example.com", b"/chat");
    connect.protocol = Some(b"websocket".to_vec());
    let mut pair = Pair::default();
    assert!(pair.client.send_request(&connect, false).is_err());
    let server = H2Config { enable_connect_protocol: true, ..H2Config::default() };
    let mut pair = Pair::new(H2Config::default(), server);
    let stream = pair.client.send_request(&connect, false).unwrap();
    pair.run();
    let (served, received) = first_request(&Pair::events(&mut pair.server));
    assert_eq!(received.protocol.as_deref(), Some(&b"websocket"[..]));
    pair.server.send_response(served, &HTTPResponse::new(HTTPStatus::OK), false).unwrap();
    pair.server.send_data(served, b"tunnel", false).unwrap();
    pair.run();
    assert_eq!(read_all(&mut pair.client, stream), b"tunnel");
}

#[test]
fn timeouts() {
    // §6.5.3: SETTINGS not acknowledged in time is SETTINGS_TIMEOUT.
    let config = H2Config { settings_timeout: Some(Duration::from_secs(5)), ..H2Config::default() };
    let mut server = H2Connection::server(config, now());
    assert_eq!(server.poll_timeout(), Some(now() + Duration::from_secs(5)));
    server.expire(now() + Duration::from_secs(5));
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert_eq!(goaway(&frames(&out)), Some(H2ErrorCode::SETTINGS_TIMEOUT));
    // An idle connection goes away cleanly.
    let mut pair =
        Pair::new(H2Config::default(), H2Config { idle_timeout: Some(Duration::from_secs(30)), ..H2Config::default() });
    let deadline = pair.server.poll_timeout().unwrap();
    pair.server.expire(deadline);
    let mut out = Vec::new();
    pair.server.transmit(&mut out);
    assert_eq!(goaway(&frames(&out)), Some(H2ErrorCode::NO_ERROR));
    assert_eq!(Pair::events(&mut pair.server).last(), Some(&HTTPEvent::Closed { error: None }));
}

#[test]
fn hpack_stays_in_step_after_a_stream_error() {
    // §4.3: a field block is decoded even when its stream is discarded;
    // §5.3.1: a stream that depends on itself is a stream error.
    let (server, frames) = raw(H2Config::default(), |encoder, out| {
        let fields: Vec<HPACKField> = [GET[0], GET[1], GET[2], GET[3], (b"x-inserted", b"by stream 1")]
            .iter()
            .map(|(n, v)| HPACKField::new(n, v))
            .collect();
        let mut block = Vec::new();
        encoder.encode(&fields, &mut block);
        let priority = Some(H2PriorityField { exclusive: false, dependency: 1, weight: 16 });
        H2Frame::Headers { stream: 1, block: &block, end_stream: true, end_headers: true, priority }.encode(out);
        // Stream 3 refers to the entry stream 1's block inserted.
        headers(encoder, 3, &[GET[0], GET[1], GET[2], GET[3], (b"x-inserted", b"by stream 1")], true, out);
    });
    assert_eq!(reset(&frames, 1), Some(H2ErrorCode::PROTOCOL_ERROR));
    assert_eq!(goaway(&frames), None, "no COMPRESSION_ERROR");
    let mut server = server;
    let (stream, request) = first_request(&Pair::events(&mut server));
    assert_eq!(stream, HTTPStreamID(3));
    assert_eq!(request.fields.get(b"x-inserted"), Some(&b"by stream 1"[..]));
}

#[test]
fn content_unread_after_a_whole_response() {
    // §8.1: once a server's response is whole, the rest of the request is
    // not needed: RST_STREAM of NO_ERROR, and the stream is gone, its
    // content credited back to the connection.
    let mut pair = Pair::default();
    let stream = pair.client.send_request(&HTTPRequest::new(HTTPMethod::POST, b"https", b"a", b"/"), false).unwrap();
    pair.client.send_data(stream, &[7; 1000], false).unwrap();
    pair.run();
    let (served, _) = first_request(&Pair::events(&mut pair.server));
    pair.server.send_response(served, &HTTPResponse::new(HTTPStatus::NOT_FOUND), true).unwrap();
    pair.run();
    assert!(pair.server.streams.is_empty(), "the stream is forgotten");
    assert!(Pair::events(&mut pair.client).contains(&HTTPEvent::Reset { stream, code: 0 }));
    // With the request already whole: no reset, the stream is forgotten all the same.
    let stream = pair.client.send_request(&HTTPRequest::new(HTTPMethod::POST, b"https", b"a", b"/"), false).unwrap();
    pair.client.send_data(stream, b"whole", true).unwrap();
    pair.run();
    let (served, _) = first_request(&Pair::events(&mut pair.server));
    pair.server.send_response(served, &HTTPResponse::new(HTTPStatus::NO_CONTENT), true).unwrap();
    pair.run();
    assert!(pair.server.streams.is_empty());
    // A reset of NO_ERROR before the response is whole waits for it (§8.1).
    let stream = pair.client.send_request(&HTTPRequest::new(HTTPMethod::POST, b"https", b"a", b"/"), false).unwrap();
    pair.run();
    let (served, _) = first_request(&Pair::events(&mut pair.server));
    let mut response = HTTPResponse::new(HTTPStatus::CONTENT_TOO_LARGE);
    response.fields.append(b"content-length", b"4").unwrap();
    pair.server.send_response(served, &response, false).unwrap();
    pair.server.reset(served, HTTPReset::NoError).unwrap();
    pair.server.send_data(served, b"full", true).unwrap();
    pair.run();
    let events = Pair::events(&mut pair.client);
    assert!(events.contains(&HTTPEvent::End { stream }), "the response arrived whole: {events:?}");
    assert_eq!(read_all(&mut pair.client, stream), b"full");
}

#[test]
fn content_this_end_sends_is_checked() {
    // §8.1.1: content of the length its Content-Length says, none in a
    // response to HEAD or of 204 or 304.
    let mut pair = Pair::default();
    let stream = pair.client.send_request(&HTTPRequest::new(HTTPMethod::HEAD, b"https", b"a", b"/"), true).unwrap();
    pair.run();
    let (served, _) = first_request(&Pair::events(&mut pair.server));
    let mut response = HTTPResponse::new(HTTPStatus::OK);
    response.fields.append(b"content-length", b"5").unwrap();
    pair.server.send_response(served, &response, false).unwrap();
    assert!(matches!(
        pair.server.send_data(served, b"hello", true),
        Err(umilib::protocol::http::HTTPError::Malformed(_))
    ));
    assert_eq!(pair.server.send_data(served, b"", true), Ok(0));
    pair.run();
    assert!(Pair::events(&mut pair.client).contains(&HTTPEvent::End { stream }));
    let mut post = HTTPRequest::new(HTTPMethod::POST, b"https", b"a", b"/");
    post.fields.append(b"content-length", b"10").unwrap();
    let stream = pair.client.send_request(&post, false).unwrap();
    assert!(pair.client.send_data(stream, b"short", true).is_err());
    assert!(pair.client.send_data(stream, b"0123456789x", false).is_err());
    assert_eq!(pair.client.send_data(stream, b"0123456789", true), Ok(10));
    assert!(pair.client.send_request(&post, true).is_err(), "no content where 10 bytes are announced");
}

#[test]
fn malformed_data_is_credited_back() {
    // §6.9: DATA counts against the connection's window even when its
    // stream is reset; what is not kept is credited back.
    let config = H2Config { connection_window: 65535, ..H2Config::default() };
    let (_, frames) = raw(config, |encoder, out| {
        for stream in (1..200u32).step_by(2) {
            let mut fields = GET.to_vec();
            fields.push((b"content-length", b"0"));
            headers(encoder, stream, &fields, false, out);
            H2Frame::Data { stream, data: &[0; 1000], end_stream: true, length: 1000 }.encode(out);
        }
    });
    assert_eq!(goaway(&frames), None, "content longer than Content-Length, credited back");
    assert_eq!(reset(&frames, 1), Some(H2ErrorCode::PROTOCOL_ERROR));
}

#[test]
fn events_are_never_dropped() {
    // Every request is delivered: reading stops while the events wait.
    let config = H2Config {
        http: umilib::protocol::http::HTTPConfig { maximum_events: 4, ..Default::default() },
        ..H2Config::default()
    };
    let (mut server, _) = raw(config, |encoder, out| {
        for stream in (1..60u32).step_by(2) {
            headers(encoder, stream, &GET, true, out);
        }
    });
    assert!(!server.wants_receive());
    let requests = Pair::events(&mut server).iter().filter(|event| matches!(event, HTTPEvent::Request { .. })).count();
    assert_eq!(requests, 30);
}
