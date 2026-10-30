//! HTTP/1.1 (RFC 9112): a server given raw bytes, its answers compared
//! with the rules; a client and a server together; framing, smuggling
//! defenses, persistence, pipelining, interim responses and tunnels.

use std::time::Duration;

use umilib::protocol::http::v1::{H1Config, H1Connection};
use umilib::protocol::http::{
    HTTPConnection, HTTPError, HTTPEvent, HTTPFields, HTTPMethod, HTTPRequest, HTTPReset, HTTPResponse, HTTPStatus,
    HTTPStreamID,
};
use umilib::runtime::Instant;

fn now() -> Instant {
    Instant::from_nanos(1_000_000_000)
}

fn drain(connection: &mut H1Connection) -> Vec<HTTPEvent> {
    std::iter::from_fn(|| connection.poll_event()).collect()
}

fn output(connection: &mut H1Connection) -> Vec<u8> {
    let mut out = Vec::new();
    connection.transmit(&mut out);
    out
}

/// A server given `bytes`: its events and what it answers by itself.
fn serve(bytes: &[u8]) -> (H1Connection, Vec<HTTPEvent>, Vec<u8>) {
    let mut server = H1Connection::server(H1Config::default(), now());
    server.receive(bytes, now());
    let events = drain(&mut server);
    let out = output(&mut server);
    (server, events, out)
}

/// The status of the response a server sends by itself to `bytes`, and whether it closes.
fn refused(bytes: &[u8]) -> (u16, bool) {
    let (server, events, out) = serve(bytes);
    assert!(
        events.iter().any(|event| matches!(event, HTTPEvent::Closed { error: Some(_) })),
        "{events:?} for {:?}",
        String::from_utf8_lossy(bytes)
    );
    let status = std::str::from_utf8(&out[9..12]).unwrap().parse().unwrap();
    assert!(out.windows(17).any(|window| window == b"connection: close"));
    (status, server.wants_close())
}

fn requests_of(events: &[HTTPEvent]) -> Vec<(HTTPStreamID, HTTPRequest, bool)> {
    events
        .iter()
        .filter_map(|event| match event {
            HTTPEvent::Request { stream, request, end } => Some((*stream, request.clone(), *end)),
            _ => None,
        })
        .collect()
}

fn read_all(connection: &mut H1Connection, stream: HTTPStreamID) -> Vec<u8> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 1000];
    loop {
        let count = connection
            .read_data(stream, &mut buffer)
            .unwrap_or_else(|error| panic!("{error:?}: {:?}", connection.error));
        if count == 0 {
            return data;
        }
        data.extend_from_slice(&buffer[..count]);
    }
}

fn response(status: u16, fields: &[(&[u8], &[u8])]) -> HTTPResponse {
    let mut response = HTTPResponse::new(HTTPStatus(status));
    for (name, value) in fields {
        response.fields.append(name, value).unwrap();
    }
    response
}

#[test]
fn the_example_of_section_2_1() {
    // RFC 9112 §2.1: the request and response of the example.
    let request = b"GET /hello.txt HTTP/1.1\r\nUser-Agent: curl/7.64.1\r\nHost: www.example.com\r\nAccept-Language: en, mi\r\n\r\n";
    let (mut server, events, _) = serve(request);
    let all = requests_of(&events);
    assert!(all.len() == 1 && all[0].2, "{events:?}");
    let (stream, request, _) = all.into_iter().next().unwrap();
    assert_eq!(request.method, HTTPMethod::GET);
    assert_eq!(request.path, b"/hello.txt");
    assert_eq!(request.authority.as_deref(), Some(&b"www.example.com"[..]));
    assert_eq!(request.scheme.as_deref(), Some(&b"http"[..]));
    assert_eq!(request.fields.get(b"accept-language"), Some(&b"en, mi"[..]));
    let content = b"Hello World! My content includes a trailing CRLF.\r\n";
    let answer = response(200, &[(b"Content-Type", b"text/plain"), (b"Content-Length", b"51")]);
    server.send_response(stream, &answer, false).unwrap();
    assert_eq!(server.send_data(stream, content, true).unwrap(), 51);
    let out = output(&mut server);
    assert_eq!(
        out,
        [&b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 51\r\n\r\n"[..], content].concat()
    );
    assert!(!server.wants_close(), "persistent by default (RFC 9112 §9.3)");
}

#[test]
fn a_client_and_a_server() {
    let mut client = H1Connection::client(H1Config::default(), now());
    let mut server = H1Connection::server(H1Config::default(), now());
    let mut request = HTTPRequest::new(HTTPMethod::POST, b"http", b"example.com:8080", b"/upload?x=1");
    request.fields.append(b"content-type", b"application/octet-stream").unwrap();
    let stream = client.send_request(&request, false).unwrap();
    let body: Vec<u8> = (0..10_000u32).map(|index| index as u8).collect();
    for chunk in body.chunks(3000) {
        client.send_data(stream, chunk, false).unwrap();
    }
    let mut trailers = HTTPFields::new();
    trailers.append(b"x-checksum", b"42").unwrap();
    client.send_trailers(stream, &trailers).unwrap();
    let bytes = output(&mut client);
    // Host from the authority, chunked as the length is not known (RFC 9112 §3.2, §6.3).
    assert!(bytes.starts_with(b"POST /upload?x=1 HTTP/1.1\r\n"));
    assert!(bytes.windows(26).any(|window| window == b"transfer-encoding: chunked"));
    assert!(bytes.windows(22).any(|window| window == b"host: example.com:8080"));
    // Byte by byte, as the network may cut it anywhere.
    for byte in &bytes {
        server.receive(std::slice::from_ref(byte), now());
    }
    let events = drain(&mut server);
    let all = requests_of(&events);
    assert!(all.len() == 1 && !all[0].2, "{events:?}");
    let (served, received, _) = all.into_iter().next().unwrap();
    assert_eq!(
        (received.method, received.path, received.authority),
        (HTTPMethod::POST, b"/upload?x=1".to_vec(), Some(b"example.com:8080".to_vec()))
    );
    assert_eq!(read_all(&mut server, served), body);
    assert!(events.contains(&HTTPEvent::Trailers { stream: served, fields: trailers }));
    assert!(events.contains(&HTTPEvent::End { stream: served }));
    server.send_response(served, &response(201, &[]), false).unwrap();
    server.send_data(served, b"created", true).unwrap();
    client.receive(&output(&mut server), now());
    let events = drain(&mut client);
    assert!(
        matches!(&events[0], HTTPEvent::Response { response, end: false, .. } if response.status == HTTPStatus::CREATED)
    );
    assert_eq!(read_all(&mut client, stream), b"created");
    assert!(events.contains(&HTTPEvent::End { stream }));
    // Both ends forgot the exchange; the connection stays open.
    assert!(client.exchanges.is_empty() && server.exchanges.is_empty());
    assert!(client.is_open() && server.is_open());
}

#[test]
fn pipelined_responses_keep_their_order() {
    // RFC 9112 §9.3.2: responses in the order of their requests, whatever
    // order the application answers in.
    let bytes =
        b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\n\r\nGET /3 HTTP/1.1\r\nHost: a\r\n\r\n";
    let (mut server, events, _) = serve(bytes);
    let requests = requests_of(&events);
    assert_eq!(requests.len(), 3);
    for (stream, request, _) in requests.iter().rev() {
        let body = request.path.clone();
        server.send_response(*stream, &response(200, &[(b"content-length", b"2")]), false).unwrap();
        server.send_data(*stream, &body, true).unwrap();
    }
    let out = String::from_utf8(output(&mut server)).unwrap();
    let order: Vec<usize> =
        ["/1", "/2", "/3"].iter().map(|path| out.find(&format!("\r\n\r\n{path}")).unwrap()).collect();
    assert!(order[0] < order[1] && order[1] < order[2], "{out}");
    // A client matches its responses to its requests in order (§9.3).
    let mut client = H1Connection::client(H1Config::default(), now());
    let streams: Vec<HTTPStreamID> = (1..=3)
        .map(|index| {
            client
                .send_request(&HTTPRequest::new(HTTPMethod::GET, b"http", b"a", format!("/{index}").as_bytes()), true)
                .unwrap()
        })
        .collect();
    assert_eq!(output(&mut client).windows(4).filter(|window| *window == b"GET ").count(), 3);
    client.receive(out.as_bytes(), now());
    for (index, stream) in streams.iter().enumerate() {
        assert_eq!(read_all(&mut client, *stream), format!("/{}", index + 1).as_bytes());
    }
}

#[test]
fn message_body_lengths() {
    // RFC 9112 §6.3: HEAD, 1xx, 204 and 304 responses have no content
    // whatever their fields say; a response without length ends with the connection.
    let mut client = H1Connection::client(H1Config::default(), now());
    let head = client.send_request(&HTTPRequest::new(HTTPMethod::HEAD, b"http", b"a", b"/"), true).unwrap();
    let get = client.send_request(&HTTPRequest::new(HTTPMethod::GET, b"http", b"a", b"/"), true).unwrap();
    let last = client.send_request(&HTTPRequest::new(HTTPMethod::GET, b"http", b"a", b"/"), true).unwrap();
    client.receive(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n", now());
    client.receive(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 1000\r\n\r\n", now());
    client.receive(b"HTTP/1.1 200 OK\r\n\r\nuntil the close", now());
    let events = drain(&mut client);
    assert!(
        events.iter().any(|event| matches!(event, HTTPEvent::Response { stream, end: true, .. } if *stream == head))
    );
    assert!(
        events.iter().any(|event| matches!(event, HTTPEvent::Response { stream, end: true, .. } if *stream == get))
    );
    assert_eq!(read_all(&mut client, last), b"until the close");
    client.receive_close(now());
    assert!(std::iter::from_fn(|| client.poll_event()).any(|event| event == HTTPEvent::End { stream: last }));
    // A response cut short by the close is an error (§8).
    let mut client = H1Connection::client(H1Config::default(), now());
    client.send_request(&HTTPRequest::new(HTTPMethod::GET, b"http", b"a", b"/"), true).unwrap();
    client.receive(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort", now());
    client.receive_close(now());
    assert!(drain(&mut client).iter().any(|event| matches!(event, HTTPEvent::Closed { error: Some(_) })));
}

#[test]
fn request_smuggling_defenses() {
    // RFC 9112 §6.1, §6.3: Transfer-Encoding with Content-Length, in
    // HTTP/1.0, not ending in chunked, or of another coding; Content-Length
    // values that disagree; each refused, and the connection closed.
    let cases: [(&[u8], u16); 9] = [
        (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\n", 400),
        (b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400),
        (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", 400),
        (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 501),
        (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd", 400),
        (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3, 4\r\n\r\nabcd", 400),
        (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +3\r\n\r\nabc", 400),
        (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcdef\r\n0\r\n\r\n", 400),
        (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nfffffffffffffffff\r\n", 431),
    ];
    for (bytes, status) in cases {
        assert_eq!(refused(bytes), (status, true), "{:?}", String::from_utf8_lossy(bytes));
    }
    // The same value twice is one value (§6.3 rule 5).
    let (mut server, events, _) = serve(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3, 3\r\n\r\nabc");
    assert_eq!(read_all(&mut server, requests_of(&events)[0].0), b"abc");
}

#[test]
fn invalid_heads() {
    // RFC 9112 §3: one space between the parts; §3.2, RFC 9110 §7.2: one
    // Host in HTTP/1.1; §5.1: no space before a colon; §5.2: no obs-fold in
    // requests; §2.2: no bare CR; RFC 9110 §5.5: field values.
    for bytes in [
        &b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n"[..],
        b"GET / HTTP/1.1 \r\nHost: a\r\n\r\n",
        b"GET / http/1.1\r\nHost: a\r\n\r\n",
        b"GET / HTTP/1.1\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost : a\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nX: 1\r\n  folded\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\rX: 1\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nX: a\x00b\r\n\r\n",
        b"GET / HTTP/1.1\r\n Host: a\r\n\r\n",
        b"GET http://user@a/ HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET * HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET a.example:80 HTTP/1.1\r\nHost: a\r\n\r\n",
    ] {
        assert_eq!(refused(bytes).0, 400, "{:?}", String::from_utf8_lossy(bytes));
    }
    // §2.3: another major version is 505; a higher minor one is 1.1 (RFC 9110 §2.5).
    assert_eq!(refused(b"GET / HTTP/2.0\r\nHost: a\r\n\r\n").0, 505);
    let (_, events, _) = serve(b"\r\n\r\nGET / HTTP/1.9\nHost: a\n\n");
    assert_eq!(requests_of(&events).len(), 1, "empty lines first and bare LF are fine (§2.2)");
    // HTTP/1.0 needs no Host; an absolute-form's authority wins over Host (§3.2.2).
    let (_, events, _) =
        serve(b"GET http://b.example/x HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.0\r\n\r\nGET /never HTTP/1.1\r\nHost: a\r\n\r\n");
    let requests = requests_of(&events);
    assert_eq!(requests[0].1.authority.as_deref(), Some(&b"b.example"[..]));
    assert_eq!(requests.len(), 2, "HTTP/1.0 without keep-alive closes after its exchange (RFC 9112 §9.3)");
}

#[test]
fn limits() {
    // RFC 9112 §3: 414 for a target too long; RFC 6585 §5: 431 for fields too large.
    let config = H1Config::default();
    let long = format!("GET /{} HTTP/1.1\r\nHost: a\r\n\r\n", "a".repeat(config.http.maximum_target_length + 1));
    assert_eq!(refused(long.as_bytes()).0, 414);
    let large =
        format!("GET / HTTP/1.1\r\nHost: a\r\nX: {}\r\n\r\n", "a".repeat(config.http.maximum_field_section_size));
    assert_eq!(refused(large.as_bytes()).0, 431);
    let endless = format!("GET / HTTP/1.1\r\nHost: a\r\nX: {}", "a".repeat(2 * config.http.maximum_field_section_size));
    assert_eq!(refused(endless.as_bytes()).0, 431);
}

#[test]
fn obsolete_folding_in_responses() {
    // RFC 9112 §5.2: a user agent replaces obs-fold with spaces.
    let mut client = H1Connection::client(H1Config::default(), now());
    let stream = client.send_request(&HTTPRequest::new(HTTPMethod::GET, b"http", b"a", b"/"), true).unwrap();
    client.receive(b"HTTP/1.1 200 OK\r\nX-Long: first\r\n\t second\r\nContent-Length: 0\r\n\r\n", now());
    let events = drain(&mut client);
    let Some(HTTPEvent::Response { response, .. }) =
        events.iter().find(|event| matches!(event, HTTPEvent::Response { stream: s, .. } if *s == stream))
    else {
        panic!()
    };
    assert_eq!(response.fields.get(b"x-long"), Some(&b"first second"[..]));
}

#[test]
fn chunked_content() {
    // RFC 9112 §7.1: sizes in hexadecimal, extensions ignored (§7.1.1),
    // trailers apart from the header (§7.1.2), the end at the last chunk.
    let bytes = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n4;name=value;quoted=\"a;b\"\r\nWiki\r\n5 ; x\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n000\r\nExpires: soon\r\n\r\n";
    let (mut server, events, _) = serve(bytes);
    let stream = requests_of(&events)[0].0;
    assert_eq!(read_all(&mut server, stream), b"Wikipedia in\r\n\r\nchunks.");
    let trailers = HTTPFields::new().with(b"expires", b"soon").unwrap();
    assert!(events.contains(&HTTPEvent::Trailers { stream, fields: trailers }));
    assert_eq!(requests_of(&events)[0].1.fields.get(b"expires"), None, "trailers are not merged into the header");
    for invalid in
        [&b"4;\r\nWiki\r\n0\r\n\r\n"[..], b"x\r\n", b"4 4\r\nWiki\r\n0\r\n\r\n", b"4;a=\"b\r\nWiki\r\n0\r\n\r\n"]
    {
        let bytes = [&b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"[..], invalid].concat();
        assert_eq!(refused(&bytes).0, 400, "{:?}", String::from_utf8_lossy(invalid));
    }
}

#[test]
fn response_framing() {
    // RFC 9112 §6: a server writes Content-Length 0 for an empty response,
    // chunked to HTTP/1.1 when the length is not known, and closes after a
    // response delimited by the close to HTTP/1.0 (which keeps alive only if asked).
    let (mut server, events, _) = serve(b"GET /a HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\nHost: a\r\n\r\n");
    let requests = requests_of(&events);
    server.send_response(requests[0].0, &response(200, &[]), true).unwrap();
    server.send_response(requests[1].0, &response(200, &[]), false).unwrap();
    server.send_data(requests[1].0, b"streamed", true).unwrap();
    let out = String::from_utf8(output(&mut server)).unwrap();
    assert!(out.starts_with("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\nHTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n8\r\nstreamed\r\n0\r\n\r\n"), "{out}");
    let (mut server, events, _) = serve(b"GET / HTTP/1.0\r\n\r\n");
    let stream = requests_of(&events)[0].0;
    server.send_response(stream, &response(200, &[]), false).unwrap();
    server.send_data(stream, b"old", true).unwrap();
    let out = output(&mut server);
    assert!(out.windows(17).any(|window| window == b"connection: close") && out.ends_with(b"\r\n\r\nold"));
    assert!(server.wants_close());
    let (mut server, events, _) = serve(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
    server.send_response(requests_of(&events)[0].0, &response(200, &[(b"content-length", b"2")]), false).unwrap();
    server.send_data(requests_of(&events)[0].0, b"ok", true).unwrap();
    assert!(output(&mut server).windows(22).any(|window| window == b"connection: keep-alive"));
    assert!(!server.wants_close());
    // Content of another length than declared is refused; 204 takes no framing (§6.1, RFC 9110 §8.6).
    let (mut server, events, _) = serve(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    let stream = requests_of(&events)[0].0;
    assert!(server.send_response(stream, &response(204, &[(b"content-length", b"0")]), true).is_err());
    server.send_response(stream, &response(200, &[(b"content-length", b"3")]), false).unwrap();
    assert!(matches!(server.send_data(stream, b"four", false), Err(HTTPError::Malformed(_))));
    assert!(server.send_data(stream, b"ab", true).is_err());
}

#[test]
fn closing() {
    // RFC 9112 §9.6: "close" from either end ends the connection after its exchange.
    let (mut server, events, _) =
        serve(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\nGET /never HTTP/1.1\r\nHost: a\r\n\r\n");
    let requests = requests_of(&events);
    assert_eq!(requests.len(), 1, "nothing after a request that closes is processed");
    assert!(!server.wants_close(), "the response first");
    server.send_response(requests[0].0, &response(200, &[]), true).unwrap();
    let out = output(&mut server);
    assert!(out.windows(17).any(|window| window == b"connection: close"));
    assert!(server.wants_close());
    // A server's shutdown: "close" in the next response.
    let (mut server, events, _) = serve(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    server.shutdown();
    server.send_response(requests_of(&events)[0].0, &response(200, &[]), true).unwrap();
    assert!(output(&mut server).windows(17).any(|window| window == b"connection: close"));
    assert!(server.wants_close());
    // A client told "close" sends nothing more; its later requests were not processed.
    let mut client = H1Connection::client(H1Config::default(), now());
    let first = client.send_request(&HTTPRequest::new(HTTPMethod::GET, b"http", b"a", b"/"), true).unwrap();
    client.send_request(&HTTPRequest::new(HTTPMethod::GET, b"http", b"a", b"/2"), true).unwrap();
    output(&mut client);
    client.receive(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", now());
    assert!(drain(&mut client).contains(&HTTPEvent::GoAway { last: first }));
    assert!(client.wants_close());
    assert!(client.send_request(&HTTPRequest::new(HTTPMethod::GET, b"http", b"a", b"/"), true).is_err());
}

#[test]
fn expect_continue() {
    // RFC 9110 §10.1.1: 100 (Continue) once the server reads the content.
    let (mut server, events, out) =
        serve(b"PUT / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n");
    assert!(out.is_empty());
    let stream = requests_of(&events)[0].0;
    assert_eq!(server.read_data(stream, &mut [0; 10]).unwrap(), 0);
    assert_eq!(output(&mut server), b"HTTP/1.1 100 Continue\r\n\r\n");
    server.receive(b"hello", now());
    assert_eq!(read_all(&mut server, stream), b"hello");
    // A final response instead: no 100, and the content still read past.
    let (mut server, events, _) =
        serve(b"PUT / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n");
    server.send_response(requests_of(&events)[0].0, &response(417, &[]), true).unwrap();
    assert!(output(&mut server).starts_with(b"HTTP/1.1 417"));
    server.receive(b"helloGET / HTTP/1.1\r\nHost: a\r\n\r\n", now());
    assert_eq!(requests_of(&std::iter::from_fn(|| server.poll_event()).collect::<Vec<_>>()).len(), 1);
}

#[test]
fn interim_responses() {
    // RFC 9110 §15.2: 1xx before the final response, to HTTP/1.1 clients.
    let mut client = H1Connection::client(H1Config::default(), now());
    let stream = client.send_request(&HTTPRequest::new(HTTPMethod::GET, b"http", b"a", b"/"), true).unwrap();
    client.receive(b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", now());
    let statuses: Vec<(u16, bool)> = drain(&mut client)
        .into_iter()
        .filter_map(|event| match event {
            HTTPEvent::Response { response, end, .. } => Some((response.status.0, end)),
            _ => None,
        })
        .collect();
    assert_eq!(statuses, [(103, false), (200, false)]);
    assert_eq!(read_all(&mut client, stream), b"ok");
}

#[test]
fn tunnels() {
    // RFC 9110 §9.3.6: CONNECT and its 2xx make a tunnel both ways; §7.8:
    // so do Upgrade and 101 (RFC 9112 §6.3 rule 2).
    let mut client = H1Connection::client(H1Config::default(), now());
    let mut server = H1Connection::server(H1Config::default(), now());
    let stream = client.send_request(&HTTPRequest::connect(b"example.com:443"), false).unwrap();
    // RFC 9931 §8: no data of the tunnel before its 2xx.
    assert_eq!(client.send_data(stream, b"early", false), Err(HTTPError::State));
    let bytes = output(&mut client);
    assert_eq!(bytes, b"CONNECT example.com:443 HTTP/1.1\r\nhost: example.com:443\r\n\r\n", "its head alone");
    server.receive(&bytes, now());
    let served = requests_of(&drain(&mut server))[0].0;
    server.send_response(served, &response(200, &[]), false).unwrap();
    server.send_data(served, b"from the server", false).unwrap();
    client.receive(&output(&mut server), now());
    assert_eq!(read_all(&mut client, stream), b"from the server");
    client.send_data(stream, b"from the client", false).unwrap();
    server.receive(&output(&mut client), now());
    assert_eq!(read_all(&mut server, served), b"from the client");
    // Upgrade, answered with 101.
    let mut client = H1Connection::client(H1Config::default(), now());
    let mut server = H1Connection::server(H1Config::default(), now());
    let mut request = HTTPRequest::new(HTTPMethod::GET, b"http", b"a", b"/chat");
    request.fields.append(b"upgrade", b"example/1").unwrap();
    request.fields.append(b"connection", b"upgrade").unwrap();
    let stream = client.send_request(&request, false).unwrap();
    // RFC 9931 §7.1: a GET with no content; §4: nothing of the new protocol before the 101.
    let bytes = output(&mut client);
    assert!(
        bytes.ends_with(b"\r\n\r\n") && !bytes.windows(17).any(|line| line.eq_ignore_ascii_case(b"transfer-encoding"))
    );
    assert_eq!(client.send_data(stream, b"early", false), Err(HTTPError::State));
    server.receive(&bytes, now());
    let served = requests_of(&drain(&mut server))[0].0;
    server
        .send_response(served, &response(101, &[(b"upgrade", b"example/1"), (b"connection", b"upgrade")]), false)
        .unwrap();
    server.send_data(served, b"new protocol", false).unwrap();
    client.receive(&output(&mut server), now());
    assert_eq!(read_all(&mut client, stream), b"new protocol");
    client.send_data(stream, b"and back", false).unwrap();
    server.receive(&output(&mut client), now());
    assert_eq!(read_all(&mut server, served), b"and back");
    // A refused upgrade leaves an ordinary exchange, and the connection, open (RFC 9931 §5).
    let mut client = H1Connection::client(H1Config::default(), now());
    let mut server = H1Connection::server(H1Config::default(), now());
    let stream = client.send_request(&request, false).unwrap();
    server.receive(&output(&mut client), now());
    let served = requests_of(&drain(&mut server))[0].0;
    server.send_response(served, &response(200, &[(b"content-length", b"2")]), false).unwrap();
    server.send_data(served, b"no", true).unwrap();
    client.receive(&output(&mut server), now());
    assert_eq!(read_all(&mut client, stream), b"no");
    assert_eq!(client.send_data(stream, b"x", false), Err(HTTPError::State));
    assert!(client.send_request(&HTTPRequest::new(HTTPMethod::GET, b"http", b"a", b"/next"), true).is_ok());
    // A request that opens a tunnel carries no content.
    let mut with_content = request.clone();
    with_content.fields.append(b"content-length", b"5").unwrap();
    assert!(matches!(client.send_request(&with_content, false), Err(HTTPError::Malformed(_))));
    // 101 without an upgrade asked for is refused on both sides.
    let (mut server, events, _) = serve(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    assert!(server.send_response(requests_of(&events)[0].0, &response(101, &[]), false).is_err());
}

#[test]
fn optimistic_transitions() {
    // RFC 9931 §4.1, Figure 1: what follows a CONNECT, sent before its
    // response, is not read as a request; a refused CONNECT closes (§8).
    let smuggled = b"CONNECT no-such-destination.example:443 HTTP/1.1\r\nHost: no-such-destination.example:443\r\n\r\n\
POST /upload HTTP/1.1\r\nHost: proxy.example\r\nContent-Length: 0\r\n\r\n";
    let (mut server, events, _) = serve(smuggled);
    let requests = requests_of(&events);
    assert_eq!(requests.len(), 1, "only the CONNECT");
    server.send_response(requests[0].0, &response(504, &[(b"content-length", b"0")]), true).unwrap();
    let out = output(&mut server);
    assert!(out.starts_with(b"HTTP/1.1 504 "));
    assert!(String::from_utf8_lossy(&out).to_ascii_lowercase().contains("connection: close"));
    assert!(requests_of(&drain(&mut server)).is_empty(), "the POST is never processed");
    assert!(server.wants_close());
    // Accepted, the same bytes are the tunnel's.
    let (mut server, events, _) = serve(smuggled);
    let served = requests_of(&events)[0].0;
    server.send_response(served, &response(200, &[]), false).unwrap();
    assert!(read_all(&mut server, served).starts_with(b"POST /upload"));
    // An Upgrade: accepted, what followed is the new protocol's; refused,
    // HTTP/1.1 goes on and it is the next request (RFC 9931 §5).
    let upgrade = b"GET /chat HTTP/1.1\r\nHost: a\r\nUpgrade: example/1\r\nConnection: upgrade\r\n\r\n\
GET /next HTTP/1.1\r\nHost: a\r\n\r\n";
    let (mut server, events, _) = serve(upgrade);
    assert_eq!(requests_of(&events).len(), 1);
    let served = requests_of(&events)[0].0;
    server
        .send_response(served, &response(101, &[(b"upgrade", b"example/1"), (b"connection", b"upgrade")]), false)
        .unwrap();
    assert!(read_all(&mut server, served).starts_with(b"GET /next"));
    let (mut server, events, _) = serve(upgrade);
    server.send_response(requests_of(&events)[0].0, &response(200, &[(b"content-length", b"0")]), true).unwrap();
    let next = requests_of(&drain(&mut server));
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].1.path, b"/next");
    assert!(!server.wants_close());
}

#[test]
fn timeouts() {
    // A head that comes too slowly is 408 (RFC 9110 §15.5.9); an idle connection closes (RFC 9112 §9.5).
    let config = H1Config {
        head_timeout: Some(Duration::from_secs(5)),
        idle_timeout: Some(Duration::from_secs(20)),
        ..H1Config::default()
    };
    let mut server = H1Connection::server(config.clone(), now());
    server.receive(b"GET / HTTP/1.1\r\nHo", now());
    let deadline = server.poll_timeout().unwrap();
    assert_eq!(deadline, now() + Duration::from_secs(5));
    server.expire(deadline);
    assert!(output(&mut server).starts_with(b"HTTP/1.1 408"));
    assert!(server.wants_close());
    let mut server = H1Connection::server(config, now());
    assert_eq!(server.poll_timeout(), Some(now() + Duration::from_secs(20)));
    server.expire(now() + Duration::from_secs(20));
    assert!(server.is_closed());
}

#[test]
fn input_waits_for_room_then_goes_on() {
    // RFC 9112 §6.3, §9.3.2: content beyond what is held for the
    // application, and requests beyond the pipeline, are read once room
    // is made, with no more bytes arriving.
    let config = H1Config {
        http: umilib::protocol::http::HTTPConfig { maximum_buffered_content: 1000, ..Default::default() },
        ..H1Config::default()
    };
    let mut server = H1Connection::server(config, now());
    let mut bytes = b"POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 5000\r\n\r\n".to_vec();
    bytes.extend(vec![b'x'; 5000]);
    server.receive(&bytes, now());
    let served = requests_of(&drain(&mut server))[0].0;
    assert_eq!(read_all(&mut server, served).len(), 5000, "all of it, a buffer at a time");
    // 17 requests at once, against a pipeline of 16.
    let mut server = H1Connection::server(H1Config::default(), now());
    server.receive(&b"GET / HTTP/1.1\r\nHost: a\r\n\r\n".repeat(17), now());
    let mut answered = 0;
    for _ in 0..4 {
        for (stream, _, _) in requests_of(&drain(&mut server)) {
            server.send_response(stream, &response(204, &[]), true).unwrap();
            answered += 1;
        }
        output(&mut server);
    }
    assert_eq!(answered, 17);
}

#[test]
fn events_are_never_dropped() {
    // Every request is delivered, however many arrive at once: reading
    // stops while the events wait.
    let config = H1Config {
        http: umilib::protocol::http::HTTPConfig { maximum_events: 4, ..Default::default() },
        maximum_pipelined: 64,
        ..H1Config::default()
    };
    let mut server = H1Connection::server(config, now());
    server.receive(&b"GET / HTTP/1.1\r\nHost: a\r\n\r\n".repeat(40), now());
    assert!(!server.wants_receive(), "not while events wait");
    let requests = requests_of(&drain(&mut server));
    assert_eq!(requests.len(), 40);
    assert!(server.wants_receive());
}

#[test]
fn content_unread_after_a_whole_response() {
    // RFC 9112 §9.3: once a server answered, the rest of the request is
    // read and dropped, and the connection goes on.
    let (mut server, events, _) =
        serve(b"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhelloGET /b HTTP/1.1\r\nHost: a\r\n\r\n");
    let requests = requests_of(&events);
    assert_eq!(requests.len(), 2);
    server.send_response(requests[0].0, &response(404, &[]), true).unwrap();
    server.send_response(requests[1].0, &response(204, &[]), true).unwrap();
    let out = output(&mut server);
    assert!(out.starts_with(b"HTTP/1.1 404") && out.windows(12).any(|window| window == b"HTTP/1.1 204"));
    assert!(server.exchanges.is_empty(), "both exchanges are over");
    assert!(!server.wants_close());
    // A response sent at once, with the content still arriving: it is read to its end.
    let (mut server, events, _) = serve(b"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nhello");
    server.send_response(requests_of(&events)[0].0, &response(413, &[]), true).unwrap();
    output(&mut server);
    server.receive(b"worldGET /b HTTP/1.1\r\nHost: a\r\n\r\n", now());
    let next = requests_of(&drain(&mut server));
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].1.path, b"/b");
}

#[test]
fn upgrades_of_http_1_0_are_ignored() {
    // RFC 9110 §7.8: a server ignores Upgrade in an HTTP/1.0 request.
    let (mut server, events, _) = serve(b"GET / HTTP/1.0\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n");
    let stream = requests_of(&events)[0].0;
    assert!(
        server
            .send_response(stream, &response(101, &[(b"upgrade", b"websocket"), (b"connection", b"upgrade")]), false)
            .is_err()
    );
}

#[test]
fn resets() {
    // RFC 9113 §8.1's NO_ERROR, for a server that answered early: the
    // response goes out whole and the connection goes on; any other reset
    // sends what was queued, then closes.
    let (mut server, events, _) = serve(b"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\nabc");
    let stream = requests_of(&events)[0].0;
    server.send_response(stream, &response(413, &[(b"content-length", b"3")]), false).unwrap();
    server.send_data(stream, b"big", true).unwrap();
    server.reset(stream, HTTPReset::NoError).unwrap();
    assert!(output(&mut server).ends_with(b"\r\n\r\nbig"));
    assert!(!server.wants_close());
    let (mut server, events, _) = serve(b"GET /a HTTP/1.1\r\nHost: a\r\n\r\n");
    let stream = requests_of(&events)[0].0;
    server.send_response(stream, &response(200, &[(b"content-length", b"10")]), false).unwrap();
    server.send_data(stream, b"part", false).unwrap();
    server.reset(stream, HTTPReset::Internal).unwrap();
    assert!(output(&mut server).ends_with(b"part"));
    assert!(server.wants_close());
    // An empty last write after a framing that ended the message.
    let (mut server, events, _) = serve(b"HEAD /a HTTP/1.1\r\nHost: a\r\n\r\n");
    let stream = requests_of(&events)[0].0;
    server.send_response(stream, &response(200, &[]), false).unwrap();
    assert_eq!(server.send_data(stream, b"", true), Ok(0));
    assert_eq!(server.send_data(stream, b"x", true), Err(HTTPError::State));
}

#[test]
fn heads_a_byte_at_a_time() {
    // RFC 9112 §2: a head may arrive in pieces of any size.
    let mut server = H1Connection::server(H1Config::default(), now());
    let head = b"GET /slow HTTP/1.1\r\nHost: a\r\nX-Long: 0123456789\r\n\r\n";
    for byte in head {
        server.receive(std::slice::from_ref(byte), now());
    }
    let requests = requests_of(&drain(&mut server));
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.fields.get(b"x-long"), Some(&b"0123456789"[..]));
}
