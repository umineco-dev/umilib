//! HTTP/3 (RFC 9114) over the QUIC connections of the QUIC tests: a client
//! and a server together, and a server given streams and frames that break
//! the rules by a client that writes QUIC streams itself.

use umilib::codec::hpack::HPACKField;
use umilib::codec::qpack::{QPACKEncoder, QPACKEncoderConfig};
use umilib::protocol::http::v3::{H3Config, H3Connection, H3ErrorCode, H3FrameHeader, H3FrameType, H3Session};
use umilib::protocol::http::{
    HTTPConnection, HTTPEvent, HTTPFields, HTTPMethod, HTTPRequest, HTTPResponse, HTTPStatus, HTTPStreamID,
};
use umilib::protocol::quic::{QUICCloseReason, QUICConfig, QUICConnection, QUICEvent, QUICStreamID, QUICVarint};

use crate::quic::connection::Network;

/// A QUIC network and the HTTP/3 layers of both ends.
struct Pair {
    network: Network,
    client: H3Connection,
    server: H3Connection,
}

impl Pair {
    fn new(client: H3Config, server: H3Config) -> Pair {
        let mut network = Network::new(QUICConfig::default());
        network.run();
        let now = network.now;
        let mut pair =
            Pair { network, client: H3Connection::client(client, now), server: H3Connection::server(server, now) };
        pair.run();
        pair
    }

    fn default() -> Pair {
        Pair::new(H3Config::default(), H3Config::default())
    }

    /// Both ends process, then the network moves and its timers fire, a few times over.
    fn run(&mut self) {
        for _ in 0..40 {
            let now = self.network.now;
            H3Session::new(&mut self.client, &mut self.network.client).process(now);
            if let Some(server) = self.network.server.as_mut() {
                H3Session::new(&mut self.server, server).process(now);
            }
            self.network.run();
            Pair::tick(&mut self.network);
        }
    }

    /// Fires the timers of the next second (pacing, acknowledgments, losses),
    /// never jumping to the idle timeout.
    fn tick(network: &mut Network) {
        let server = network.server.as_ref().and_then(QUICConnection::poll_timeout);
        let next = [network.client.poll_timeout(), server].into_iter().flatten().min();
        if next.is_some_and(|next| next.saturating_duration_since(network.now) < std::time::Duration::from_secs(1)) {
            network.tick();
        }
    }

    fn client(&mut self) -> H3Session<'_> {
        H3Session::new(&mut self.client, &mut self.network.client)
    }

    fn server(&mut self) -> H3Session<'_> {
        H3Session::new(&mut self.server, self.network.server.as_mut().unwrap())
    }
}

fn drain(session: &mut H3Session<'_>) -> Vec<HTTPEvent> {
    std::iter::from_fn(|| session.poll_event()).collect()
}

fn read_all(session: &mut H3Session<'_>, stream: HTTPStreamID) -> Vec<u8> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let count = session.read_data(stream, &mut buffer).unwrap();
        if count == 0 {
            return data;
        }
        data.extend_from_slice(&buffer[..count]);
    }
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

fn request(path: &str) -> HTTPRequest {
    HTTPRequest::new(HTTPMethod::GET, b"https", b"example.com", path.as_bytes())
}

#[test]
fn settings_on_control_streams() {
    // RFC 9114 §6.2.1: each end's control stream starts with SETTINGS;
    // RFC 9204 §5: the QPACK settings take effect; a reserved setting is ignored.
    let pair = Pair::default();
    let peer = pair.server.peer.expect("the client's SETTINGS");
    assert_eq!(peer.qpack_max_table_capacity, 4096);
    assert_eq!(peer.qpack_blocked_streams, 16);
    assert!(pair.client.peer.is_some());
    assert!(
        pair.client.peer_control.is_some() && pair.client.peer_encoder.is_some() && pair.client.peer_decoder.is_some()
    );
    assert_eq!(pair.client.encoder.table.capacity, 4096);
}

#[test]
fn exchanges_with_content_and_trailers() {
    let mut pair = Pair::default();
    let mut post = HTTPRequest::new(HTTPMethod::POST, b"https", b"example.com", b"/upload");
    post.fields.append(b"content-type", b"text/plain").unwrap();
    let stream = pair.client().send_request(&post, false).unwrap();
    assert_eq!(stream.0 % 4, 0, "a client-initiated bidirectional stream (RFC 9114 §6.1)");
    let data: Vec<u8> = (0..200_000u32).map(|index| index as u8).collect();
    let mut written = 0;
    while written < data.len() {
        written += pair.client().send_data(stream, &data[written..], false).unwrap();
        pair.run();
    }
    pair.client().send_trailers(stream, &HTTPFields::new().with(b"x-sum", b"1").unwrap()).unwrap();
    let mut received = Vec::new();
    let mut served = None;
    let mut events_seen = Vec::new();
    for _ in 0..50 {
        pair.run();
        let mut server = pair.server();
        let new = drain(&mut server);
        if served.is_none() {
            served = new.iter().find_map(|event| match event {
                HTTPEvent::Request { stream, .. } => Some(*stream),
                _ => None,
            });
        }
        events_seen.extend(new);
        if let Some(served) = served {
            received.extend(read_all(&mut server, served));
        }
        if events_seen.iter().any(|event| matches!(event, HTTPEvent::End { .. })) {
            break;
        }
    }
    let served = served.unwrap();
    assert!(received == data, "{} of {} bytes", received.len(), data.len());
    assert!(
        events_seen
            .contains(&HTTPEvent::Trailers { stream: served, fields: HTTPFields::new().with(b"x-sum", b"1").unwrap() })
    );
    let mut server = pair.server();
    server.send_response(served, &HTTPResponse::new(HTTPStatus::EARLY_HINTS), false).unwrap();
    server.send_response(served, &HTTPResponse::new(HTTPStatus::OK), false).unwrap();
    server.send_data(served, b"done", true).unwrap();
    assert!(server.send_response(served, &HTTPResponse::new(HTTPStatus::OK), true).is_err());
    pair.run();
    let mut client = pair.client();
    let events = drain(&mut client);
    let statuses: Vec<u16> = events
        .iter()
        .filter_map(|event| match event {
            HTTPEvent::Response { response, .. } => Some(response.status.0),
            _ => None,
        })
        .collect();
    assert_eq!(statuses, [103, 200]);
    assert_eq!(read_all(&mut client, stream), b"done");
    assert!(events.contains(&HTTPEvent::End { stream }));
    // No 101 in HTTP/3 (RFC 9114 §4.5).
    let next = pair.client().send_request(&request("/"), true).unwrap();
    pair.run();
    let (served, _) = first_request(&drain(&mut pair.server()));
    assert!(pair.server().send_response(served, &HTTPResponse::new(HTTPStatus::SWITCHING_PROTOCOLS), true).is_err());
    let _ = next;
}

#[test]
fn qpack_tables_carry_repeated_fields() {
    // RFC 9204: repeated fields go through the dynamic table, its encoder
    // and decoder streams keeping both ends in step.
    let mut pair = Pair::default();
    for index in 0..20 {
        let mut get = request(&format!("/item/{}", index % 3));
        get.fields.append(b"user-agent", b"umilib test agent").unwrap();
        get.fields.append(b"x-custom", b"a value repeated on every request").unwrap();
        let stream = pair.client().send_request(&get, true).unwrap();
        pair.run();
        let (served, received) = first_request(&drain(&mut pair.server()));
        assert_eq!(received.fields.get(b"x-custom"), Some(&b"a value repeated on every request"[..]));
        pair.server().send_response(served, &HTTPResponse::new(HTTPStatus::NO_CONTENT), true).unwrap();
        pair.run();
        assert!(
            drain(&mut pair.client())
                .iter()
                .any(|event| matches!(event, HTTPEvent::Response { stream: s, end: true, .. } if *s == stream))
        );
    }
    assert!(pair.client.encoder.table.inserted > 2);
    assert_eq!(pair.client.encoder.table.entries, pair.server.decoder.table.entries);
    assert!(pair.client.encoder.sections.is_empty(), "every section acknowledged");
}

#[test]
fn going_away() {
    // RFC 9114 §5.2: GOAWAY names the first request not processed; the
    // ones before finish; no new requests; then the connection closes.
    let mut pair = Pair::default();
    let first = pair.client().send_request(&request("/1"), true).unwrap();
    pair.run();
    let (served, _) = first_request(&drain(&mut pair.server()));
    pair.server().shutdown();
    pair.run();
    let events_seen = drain(&mut pair.client());
    assert!(events_seen.contains(&HTTPEvent::GoAway { last: served }), "{events_seen:?}");
    assert!(pair.client().send_request(&request("/late"), true).is_err());
    pair.server().send_response(served, &HTTPResponse::new(HTTPStatus::OK), true).unwrap();
    pair.run();
    assert!(
        drain(&mut pair.client())
            .iter()
            .any(|event| matches!(event, HTTPEvent::Response { stream, .. } if *stream == first))
    );
    assert!(pair.server().is_closed());
}

#[test]
fn field_sections_too_large() {
    // RFC 9114 §4.2.2: a server answers 431 and goes on.
    let mut pair = Pair::default();
    let mut large = request("/");
    large.fields.append(b"x-large", &vec![b'v'; 70_000]).unwrap();
    let stream = pair.client().send_request(&large, true).unwrap();
    pair.run();
    let seen = drain(&mut pair.client());
    assert!(seen.iter().any(|event| matches!(event, HTTPEvent::Response { stream: s, response, .. } if *s == stream && response.status == HTTPStatus::REQUEST_HEADER_FIELDS_TOO_LARGE)), "{seen:?}");
    pair.client().send_request(&request("/next"), true).unwrap();
    pair.run();
    assert_eq!(first_request(&drain(&mut pair.server())).1.path, b"/next");
}

#[test]
fn extended_connect() {
    // RFC 9220 §3: :protocol only with the server's SETTINGS_ENABLE_CONNECT_PROTOCOL.
    let mut connect = HTTPRequest::new(HTTPMethod::CONNECT, b"https", b"example.com", b"/chat");
    connect.protocol = Some(b"websocket".to_vec());
    let mut pair = Pair::default();
    assert!(pair.client().send_request(&connect, false).is_err());
    let mut pair = Pair::new(H3Config::default(), H3Config { enable_connect_protocol: true, ..H3Config::default() });
    let stream = pair.client().send_request(&connect, false).unwrap();
    pair.run();
    let (served, received) = first_request(&drain(&mut pair.server()));
    assert_eq!(received.protocol.as_deref(), Some(&b"websocket"[..]));
    pair.server().send_response(served, &HTTPResponse::new(HTTPStatus::OK), false).unwrap();
    pair.server().send_data(served, b"tunnel", false).unwrap();
    pair.run();
    assert_eq!(read_all(&mut pair.client(), stream), b"tunnel");
}

// ---- A client that breaks the rules ----

/// A QUIC network with an HTTP/3 server and a client that writes its streams itself.
struct Raw {
    network: Network,
    server: H3Connection,
}

impl Raw {
    fn new() -> Raw {
        let mut network = Network::new(QUICConfig::default());
        network.run();
        let now = network.now;
        Raw { network, server: H3Connection::server(H3Config::default(), now) }
    }

    fn run(&mut self) {
        for _ in 0..20 {
            let now = self.network.now;
            if let Some(server) = self.network.server.as_mut() {
                H3Session::new(&mut self.server, server).process(now);
            }
            self.network.run();
            Pair::tick(&mut self.network);
        }
    }

    fn client(&mut self) -> &mut QUICConnection {
        &mut self.network.client
    }

    /// A unidirectional stream of the client with `bytes`, its FIN if `fin`.
    fn unidirectional(&mut self, bytes: &[u8], fin: bool) -> QUICStreamID {
        let stream = self.client().open_stream(false).unwrap();
        self.client().stream_send(stream, bytes, fin).unwrap();
        stream
    }

    /// The client's control stream with SETTINGS, then `rest`.
    fn control(&mut self, rest: &[u8]) {
        let mut bytes = vec![0x00];
        H3FrameHeader::write(H3FrameType::SETTINGS, &[], &mut bytes);
        bytes.extend_from_slice(rest);
        self.unidirectional(&bytes, false);
    }

    /// The application error the server closed the connection with.
    fn closed_with(&mut self) -> Option<u64> {
        std::iter::from_fn(|| self.network.client.poll_event()).find_map(|event| match event {
            QUICEvent::Closed { reason: QUICCloseReason::PeerApplication { error, .. } } => Some(error),
            _ => None,
        })
    }

    /// The error the server reset `stream` with.
    fn reset_with(&mut self, stream: QUICStreamID) -> Option<u64> {
        std::iter::from_fn(|| self.network.client.poll_event()).find_map(|event| match event {
            QUICEvent::StreamReset { stream: s, error } if s == stream => Some(error),
            _ => None,
        })
    }
}

/// A HEADERS frame of `fields`, without the dynamic table.
fn headers(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut encoder = QPACKEncoder::new(QPACKEncoderConfig::default());
    let fields: Vec<HPACKField> = fields.iter().map(|(name, value)| HPACKField::new(name, value)).collect();
    let section = encoder.encode(0, &fields);
    let mut frame = Vec::new();
    H3FrameHeader::write(H3FrameType::HEADERS, &section, &mut frame);
    frame
}

const GET: [(&[u8], &[u8]); 4] =
    [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"example.com"), (b":path", b"/")];

#[test]
fn connection_errors() {
    // RFC 9114 §6.2, §7.2, §8.1: each closes the connection with its code.
    let settings = {
        let mut bytes = Vec::new();
        H3FrameHeader::write(H3FrameType::SETTINGS, &[], &mut bytes);
        bytes
    };
    let frame = |frame_type: H3FrameType, payload: &[u8]| {
        let mut bytes = Vec::new();
        H3FrameHeader::write(frame_type, payload, &mut bytes);
        bytes
    };
    let setting = |id: u64, value: u64| {
        let mut payload = Vec::new();
        QUICVarint::write(&mut payload, id).unwrap();
        QUICVarint::write(&mut payload, value).unwrap();
        payload
    };
    /// What a case has the client do.
    type Build = Box<dyn Fn(&mut Raw)>;
    let cases: Vec<(&str, H3ErrorCode, Build)> = vec![
        (
            "a control stream without SETTINGS first",
            H3ErrorCode::MISSING_SETTINGS,
            Box::new(move |raw| {
                raw.unidirectional(&[&[0x00][..], &frame(H3FrameType::GOAWAY, &[0])].concat(), false);
            }),
        ),
        (
            "a second SETTINGS",
            H3ErrorCode::FRAME_UNEXPECTED,
            Box::new({
                let settings = settings.clone();
                move |raw| raw.control(&settings)
            }),
        ),
        (
            "DATA on the control stream",
            H3ErrorCode::FRAME_UNEXPECTED,
            Box::new(move |raw| raw.control(&frame(H3FrameType::DATA, b"x"))),
        ),
        (
            "a frame of HTTP/2",
            H3ErrorCode::FRAME_UNEXPECTED,
            Box::new(move |raw| raw.control(&frame(H3FrameType(0x06), &[0; 8]))),
        ),
        (
            "a setting of HTTP/2",
            H3ErrorCode::SETTINGS_ERROR,
            Box::new(move |raw| {
                raw.unidirectional(&[&[0x00][..], &frame(H3FrameType::SETTINGS, &setting(0x02, 1))].concat(), false);
            }),
        ),
        (
            "a setting repeated",
            H3ErrorCode::SETTINGS_ERROR,
            Box::new(move |raw| {
                let payload = [setting(0x06, 100), setting(0x06, 200)].concat();
                raw.unidirectional(&[&[0x00][..], &frame(H3FrameType::SETTINGS, &payload)].concat(), false);
            }),
        ),
        (
            "a second control stream",
            H3ErrorCode::STREAM_CREATION_ERROR,
            Box::new(move |raw| {
                raw.control(&[]);
                raw.control(&[]);
            }),
        ),
        (
            "a push stream of a client",
            H3ErrorCode::STREAM_CREATION_ERROR,
            Box::new(move |raw| {
                raw.unidirectional(&[0x01, 0x00], false);
            }),
        ),
        (
            "the control stream closed",
            H3ErrorCode::CLOSED_CRITICAL_STREAM,
            Box::new({
                let settings = settings.clone();
                move |raw| {
                    raw.unidirectional(&[&[0x00][..], &settings].concat(), true);
                }
            }),
        ),
        (
            "DATA before HEADERS",
            H3ErrorCode::FRAME_UNEXPECTED,
            Box::new(move |raw| {
                let stream = raw.client().open_stream(true).unwrap();
                raw.client().stream_send(stream, &frame(H3FrameType::DATA, b"x"), true).unwrap();
            }),
        ),
        (
            "a frame cut short by its stream's end",
            H3ErrorCode::FRAME_ERROR,
            Box::new(move |raw| {
                let stream = raw.client().open_stream(true).unwrap();
                let mut bytes = headers(&GET);
                bytes.truncate(bytes.len() - 1);
                raw.client().stream_send(stream, &bytes, true).unwrap();
            }),
        ),
        (
            "a frame of HTTP/2 on a request stream",
            H3ErrorCode::FRAME_UNEXPECTED,
            Box::new(move |raw| {
                let stream = raw.client().open_stream(true).unwrap();
                raw.client().stream_send(stream, &frame(H3FrameType(0x08), &[0; 4]), true).unwrap();
            }),
        ),
        (
            "PUSH_PROMISE from a client",
            H3ErrorCode::FRAME_UNEXPECTED,
            Box::new(move |raw| {
                let stream = raw.client().open_stream(true).unwrap();
                raw.client().stream_send(stream, &frame(H3FrameType::PUSH_PROMISE, &[0]), true).unwrap();
            }),
        ),
        (
            "CANCEL_PUSH of a push never allowed",
            H3ErrorCode::ID_ERROR,
            Box::new(move |raw| raw.control(&frame(H3FrameType::CANCEL_PUSH, &[3]))),
        ),
        (
            "QPACK instructions that do not decode",
            H3ErrorCode(0x201),
            Box::new(move |raw| {
                raw.control(&[]);
                raw.unidirectional(&[0x02, 0x3F, 0xFF, 0xFF, 0xFF, 0x7F], false);
            }),
        ),
    ];
    for (name, code, build) in cases {
        let mut raw = Raw::new();
        build(&mut raw);
        raw.run();
        assert_eq!(raw.closed_with(), Some(code.0), "{name}");
    }
}

#[test]
fn stream_errors_and_what_is_ignored() {
    // RFC 9114 §4.1.2: a malformed request is H3_MESSAGE_ERROR; §7.2.8 and
    // §9: frames and streams of unknown types are ignored.
    let mut raw = Raw::new();
    raw.control(&{
        let mut bytes = Vec::new();
        H3FrameHeader::write(H3FrameType::reserved(3), b"ignored", &mut bytes);
        bytes
    });
    let reserved = raw.unidirectional(&[0x21, 1, 2, 3], false);
    let stream = raw.client().open_stream(true).unwrap();
    let mut bytes = Vec::new();
    H3FrameHeader::write(H3FrameType::reserved(5), b"skipped", &mut bytes);
    bytes.extend(headers(&[GET[0], GET[1], GET[2], GET[3], (b"X-Upper", b"1")]));
    raw.client().stream_send(stream, &bytes, true).unwrap();
    raw.run();
    assert_eq!(raw.reset_with(stream), Some(H3ErrorCode::MESSAGE_ERROR.0));
    assert_eq!(raw.closed_with(), None, "the connection goes on");
    let good = raw.client().open_stream(true).unwrap();
    let mut bytes = Vec::new();
    H3FrameHeader::write(H3FrameType::reserved(1), b"", &mut bytes);
    bytes.extend(headers(&GET));
    raw.client().stream_send(good, &bytes, true).unwrap();
    raw.run();
    let server = raw.network.server.as_mut().unwrap();
    let mut session = H3Session::new(&mut raw.server, server);
    assert!(
        drain(&mut session)
            .iter()
            .any(|event| matches!(event, HTTPEvent::Request { stream, .. } if stream.0 == good.0))
    );
    let _ = reserved;
    // §6.2: what else arrives on a stream of an unknown type, sent before
    // its STOP_SENDING arrived, is discarded, never read as a stream type
    // (0x00 here, a second control stream).
    let mut raw = Raw::new();
    raw.control(&[]);
    raw.run();
    for at in [1, 4095, 4096, 4097, 8192] {
        let mut bytes = vec![0x21];
        bytes.resize(at, 0x3F);
        bytes.push(0x00);
        H3FrameHeader::write(H3FrameType::SETTINGS, &[], &mut bytes);
        bytes.resize(10_000, 0x3F);
        raw.unidirectional(&bytes, false);
        raw.run();
        assert_eq!(raw.closed_with(), None, "the connection goes on ({at})");
    }
}

/// The server's session of `raw`.
fn served(raw: &mut Raw) -> H3Session<'_> {
    H3Session::new(&mut raw.server, raw.network.server.as_mut().unwrap())
}

fn requests(events: &[HTTPEvent]) -> Vec<u64> {
    events
        .iter()
        .filter_map(|event| match event {
            HTTPEvent::Request { stream, .. } => Some(stream.0),
            _ => None,
        })
        .collect()
}

#[test]
fn request_streams_in_any_order() {
    // RFC 9000 §2.1, RFC 9114 §6.1: a request stream's bytes may arrive
    // after those of a later one; each is a request.
    let mut raw = Raw::new();
    raw.control(&[]);
    raw.run();
    let first = raw.client().open_stream(true).unwrap();
    let second = raw.client().open_stream(true).unwrap();
    raw.client().stream_send(second, &headers(&GET), true).unwrap();
    raw.run();
    raw.client().stream_send(first, &headers(&GET), true).unwrap();
    raw.run();
    let mut seen = requests(&drain(&mut served(&mut raw)));
    seen.sort();
    assert_eq!(seen, [first.0, second.0]);
}

#[test]
fn errors_of_one_stream_leave_the_others() {
    // RFC 9114 §8: a stream error ends that stream; the others are handled at once.
    let mut raw = Raw::new();
    raw.control(&[]);
    raw.run();
    let bad = raw.client().open_stream(true).unwrap();
    let good = raw.client().open_stream(true).unwrap();
    raw.client().stream_send(bad, &headers(&[GET[0], GET[1], GET[2], GET[3], (b"X-Upper", b"1")]), true).unwrap();
    raw.client().stream_send(good, &headers(&GET), true).unwrap();
    raw.network.run();
    let now = raw.network.now;
    let mut session = served(&mut raw);
    session.process(now);
    assert_eq!(requests(&drain(&mut session)), [good.0], "in the same call");
    // RFC 9114 §4.1.2: a client accepts no response whose content and Content-Length disagree.
    let mut pair = Pair::default();
    let stream = pair.client().send_request(&request("/"), true).unwrap();
    pair.run();
    let (served_stream, _) = first_request(&drain(&mut pair.server()));
    let mut response = HTTPResponse::new(HTTPStatus::OK);
    response.fields.append(b"content-length", b"5").unwrap();
    assert!(pair.server().send_response(served_stream, &response, true).is_err(), "this end checks what it sends");
    let section = pair
        .server
        .encoder
        .encode(served_stream.0, &[HPACKField::new(b":status", b"200"), HPACKField::new(b"content-length", b"5")]);
    let mut bytes = Vec::new();
    H3FrameHeader::write(H3FrameType::HEADERS, &section, &mut bytes);
    let quic = pair.network.server.as_mut().unwrap();
    quic.stream_send(QUICStreamID(served_stream.0), &bytes, true).unwrap();
    pair.run();
    let events = drain(&mut pair.client());
    assert!(events.contains(&HTTPEvent::Reset { stream, code: H3ErrorCode::MESSAGE_ERROR.0 }), "{events:?}");
}

#[test]
fn a_431_and_what_follows() {
    // RFC 9114 §4.2.2: a field section too large is answered with 431, the
    // rest of the stream is not read, and the connection goes on; RFC
    // 9204 §2.2.2.1: its section is acknowledged all the same.
    let mut pair = Pair::default();
    let mut get = request("/");
    get.fields.append(b"x-custom", b"a value repeated on every request").unwrap();
    pair.client().send_request(&get, true).unwrap();
    pair.run();
    let (served_stream, _) = first_request(&drain(&mut pair.server()));
    pair.server().send_response(served_stream, &HTTPResponse::new(HTTPStatus::NO_CONTENT), true).unwrap();
    pair.run();
    drain(&mut pair.client());
    let mut large = HTTPRequest::new(HTTPMethod::POST, b"https", b"example.com", b"/");
    large.fields.append(b"x-custom", b"a value repeated on every request").unwrap();
    large.fields.append(b"x-large", &vec![b'v'; 70_000]).unwrap();
    let stream = pair.client().send_request(&large, false).unwrap();
    for _ in 0..3 {
        pair.run();
    }
    let _ = pair.client().send_data(stream, b"content", true);
    for _ in 0..3 {
        pair.run();
    }
    let events = drain(&mut pair.client());
    assert!(
        events.iter().any(|event| matches!(event, HTTPEvent::Response { response, .. } if response.status.0 == 431)),
        "{events:?}"
    );
    assert!(!pair.client().is_closed(), "the connection goes on");
    assert!(pair.client.encoder.sections.is_empty(), "every section acknowledged");
}

#[test]
fn resets_end_both_halves() {
    // RFC 9000 §3: a stream is forgotten once both halves end; RFC 9114
    // §4.1.1: a reset request abandons the exchange.
    let mut raw = Raw::new();
    raw.control(&[]);
    raw.run();
    let stream = raw.client().open_stream(true).unwrap();
    raw.client().stream_send(stream, &headers(&GET), false).unwrap();
    raw.run();
    raw.client().stream_reset(stream, H3ErrorCode::REQUEST_CANCELLED.0).unwrap();
    raw.run();
    {
        let mut session = served(&mut raw);
        drain(&mut session);
        session.shutdown();
    }
    raw.run();
    raw.run();
    let server = raw.network.server.as_ref().unwrap();
    assert!(!server.streams.streams.keys().any(|id| id.is_bidirectional()), "QUIC forgot the stream");
    assert!(served(&mut raw).is_closed(), "the shutdown finished");
}

#[test]
fn unknown_frames_and_codes_mean_nothing() {
    // RFC 9114 §7.2.8, §9: a frame of an unknown type on the control
    // stream is skipped, however large.
    let mut raw = Raw::new();
    let mut all = vec![0x00];
    H3FrameHeader::write(H3FrameType::SETTINGS, &[], &mut all);
    H3FrameHeader::write(H3FrameType::reserved(7), &vec![0u8; 70_000], &mut all);
    H3FrameHeader::write(H3FrameType::reserved(8), b"", &mut all);
    let control = raw.client().open_stream(false).unwrap();
    let mut written = 0;
    while written < all.len() {
        written += raw.client().stream_send(control, &all[written..], false).unwrap();
        raw.run();
    }
    raw.run();
    assert_eq!(raw.closed_with(), None);
    // §8: a connection closed with an unknown code closed cleanly.
    let now = raw.network.now;
    raw.client().close(H3ErrorCode::reserved(3).0, b"", now).unwrap();
    raw.run();
    let events = drain(&mut served(&mut raw));
    assert!(events.contains(&HTTPEvent::Closed { error: None }), "{events:?}");
    // §7.2.7: MAX_PUSH_ID may not fall.
    let mut raw = Raw::new();
    let mut frames = Vec::new();
    let mut payload = Vec::new();
    QUICVarint::write(&mut payload, 10).unwrap();
    H3FrameHeader::write(H3FrameType::MAX_PUSH_ID, &payload, &mut frames);
    let mut payload = Vec::new();
    QUICVarint::write(&mut payload, 5).unwrap();
    H3FrameHeader::write(H3FrameType::MAX_PUSH_ID, &payload, &mut frames);
    raw.control(&frames);
    raw.run();
    assert_eq!(raw.closed_with(), Some(H3ErrorCode::ID_ERROR.0));
}

#[test]
fn unknown_streams_are_forgotten() {
    // RFC 9114 §6.2: streams of unknown types are not read; nothing of
    // them is kept, however many the peer opens.
    let mut raw = Raw::new();
    raw.control(&[]);
    raw.run();
    for _ in 0..5 {
        for _ in 0..50 {
            if let Ok(stream) = raw.client().open_stream(false) {
                raw.client().stream_send(stream, &[0x21, 1, 2, 3], false).unwrap();
            }
        }
        raw.run();
    }
    assert!(raw.server.unidirectional.len() <= 3, "{} entries", raw.server.unidirectional.len());
    assert_eq!(raw.closed_with(), None);
}

#[test]
fn content_unread_after_a_whole_response() {
    // RFC 9114 §4.1.1: once a server's response is whole, the rest of the
    // request is not needed: STOP_SENDING of H3_NO_ERROR, the stream forgotten.
    let mut pair = Pair::default();
    let stream = pair.client().send_request(&HTTPRequest::new(HTTPMethod::POST, b"https", b"a", b"/"), false).unwrap();
    pair.client().send_data(stream, &[7; 1000], false).unwrap();
    pair.run();
    let (served_stream, _) = first_request(&drain(&mut pair.server()));
    pair.server().send_response(served_stream, &HTTPResponse::new(HTTPStatus::NOT_FOUND), true).unwrap();
    pair.run();
    assert!(pair.server.streams.is_empty(), "the stream is forgotten");
    let events = drain(&mut pair.client());
    assert!(
        events.iter().any(|event| matches!(event, HTTPEvent::Response { response, .. } if response.status.0 == 404))
    );
}

#[test]
fn events_are_never_dropped() {
    // Every request is delivered: reading stops while the events wait.
    let config = H3Config {
        http: umilib::protocol::http::HTTPConfig { maximum_events: 2, ..Default::default() },
        ..H3Config::default()
    };
    let mut pair = Pair::new(H3Config::default(), config);
    let streams: Vec<HTTPStreamID> =
        (0..20).map(|_| pair.client().send_request(&request("/"), true).unwrap()).collect();
    pair.run();
    let mut seen = Vec::new();
    for _ in 0..100 {
        let events = drain(&mut pair.server());
        if events.is_empty() {
            pair.run();
        }
        seen.extend(requests(&events));
    }
    seen.sort();
    assert_eq!(seen, streams.iter().map(|stream| stream.0).collect::<Vec<_>>());
}
