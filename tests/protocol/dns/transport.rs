//! The transports: TCP framing and connections (RFC 1035 §4.2.2, RFC
//! 7766, RFC 7828), DNS over TLS (RFC 7858), over HTTPS (RFC 8484) and
//! over QUIC (RFC 9250), and the source check of UDP (RFC 5452 §9.1).

use core::time::Duration;

use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::SHA256;
use umilib::protocol::dns::tcp::{DNSTCPClient, DNSTCPClientConfig, DNSTCPFramer, DNSTCPServer, DNSTCPServerConfig};
use umilib::protocol::dns::udp::DNSUDP;
use umilib::protocol::dns::{
    DNSAuthority, DNSAuthorityConfig, DNSEDNS, DNSError, DNSKeepalive, DNSMessage, DNSOptionCode, DNSPeer, DNSQuestion,
    DNSTransport, DNSType, DNSZone,
};
use umilib::protocol::ip::IPEndpoint;
use umilib::runtime::Instant;

use super::{name, zone};

fn random() -> HMACDRBG<SHA256> {
    HMACDRBG::<SHA256>::new(&[4; 32], &[4; 16], b"umilib transport tests").unwrap()
}

fn at(milliseconds: u64) -> Instant {
    Instant::from_nanos(milliseconds * 1_000_000)
}

fn authority() -> DNSAuthority {
    let text = "example. 3600 IN SOA ns.example. admin.example. 1 3600 600 86400 300\nwww.example. 300 IN A 192.0.2.1";
    DNSAuthority::new(vec![DNSZone::new(name("example."), zone(text)).unwrap()], DNSAuthorityConfig::default())
}

fn peer(transport: DNSTransport) -> DNSPeer {
    DNSPeer { endpoint: IPEndpoint::from_ascii(b"198.51.100.7:40000").unwrap(), transport }
}

fn query(text: &str, kind: DNSType) -> DNSMessage {
    let mut query = DNSMessage::query(0, DNSQuestion::new(name(text), kind));
    query.edns = Some(DNSEDNS::default());
    query
}

#[test]
fn the_framing_of_rfc_1035() {
    // §4.2.2: each message after its length in two bytes.
    assert_eq!(DNSTCPFramer::frame(&[1, 2, 3]).unwrap(), [0, 3, 1, 2, 3]);
    assert!(DNSTCPFramer::frame(&vec![0; 65536]).is_err());
    // Messages split across reads, and several in one.
    let mut framer = DNSTCPFramer::new();
    framer.receive(&[0]);
    assert!(framer.next_message().is_none());
    framer.receive(&[2, 9]);
    assert!(framer.next_message().is_none() && framer.is_partial());
    framer.receive(&[8, 0, 1, 7]);
    assert_eq!(framer.next_message(), Some(Ok(vec![9, 8])));
    assert_eq!(framer.next_message(), Some(Ok(vec![7])));
    assert!(framer.next_message().is_none() && !framer.is_partial());
    framer.receive(&[0, 0]);
    assert!(matches!(framer.next_message(), Some(Err(_))));
}

#[test]
fn pipelined_queries_of_rfc_7766() {
    let authority = authority();
    let mut random = random();
    let mut client = DNSTCPClient::new(DNSTCPClientConfig::default(), at(0));
    let mut server = DNSTCPServer::new(DNSTCPServerConfig::default(), peer(DNSTransport::TCP), at(0));
    // §6.2.1.1: several queries at once, each of its own ID.
    let ids: Vec<u16> =
        (0..3).map(|handle| client.send(handle, query("www.example.", DNSType::A), &mut random).unwrap()).collect();
    assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2]);
    assert!(!client.is_idle(at(60_000)));
    // Delivered a byte at a time, answered in order.
    for byte in client.transmit() {
        server.receive(&[byte], &authority, at(1), 0).unwrap();
    }
    let output = server.transmit();
    // Responses in any order are matched by ID.
    let mut framer = DNSTCPFramer::new();
    framer.receive(&output);
    let mut responses: Vec<Vec<u8>> = std::iter::from_fn(|| framer.next_message()).map(Result::unwrap).collect();
    assert_eq!(responses.len(), 3);
    responses.reverse();
    for response in &responses {
        client.receive(&DNSTCPFramer::frame(response).unwrap(), at(2)).unwrap();
    }
    let handles: Vec<u64> = std::iter::from_fn(|| client.poll_response()).map(|(handle, _)| handle).collect();
    assert_eq!(handles, [2, 1, 0]);
    // RFC 7828 §3.3.2: the server tells its timeout to queries that ask; the client keeps it.
    let response = DNSMessage::decode(&responses[0]).unwrap();
    assert_eq!(DNSKeepalive::timeout(&response), Ok(Some(Duration::from_secs(10))));
    assert!(!client.is_idle(at(10_001)) && client.is_idle(at(10_002)));
    // A response to no outstanding query ends the connection.
    assert!(client.receive(&DNSTCPFramer::frame(&responses[0]).unwrap(), at(3)).is_err());
    // A client stops at its limit; abandoned queries are told.
    let mut limited =
        DNSTCPClient::new(DNSTCPClientConfig { maximum_outstanding: 1, ..DNSTCPClientConfig::default() }, at(0));
    limited.send(5, query("www.example.", DNSType::A), &mut random).unwrap();
    assert_eq!(limited.send(6, query("www.example.", DNSType::A), &mut random), Err(DNSError::State));
    assert_eq!(limited.abandon(), [5]);
    // The server's connection: idle after its timeout, sooner for a query left partial.
    assert!(!server.is_idle(at(10_000)) && server.is_idle(at(10_001)));
    server.receive(&[0, 50, 1], &authority, at(20_000), 0).unwrap();
    assert!(server.is_idle(at(30_000)));
    // A query trickled in a byte at a time keeps the deadline of its first byte.
    for second in 21..29 {
        server.receive(&[1], &authority, at(second * 1000), 0).unwrap();
    }
    assert!(server.is_idle(at(30_000)));
    assert!(server.receive(&[0, 0], &DNSAuthority::default(), at(0), 0).is_err() || server.framer.is_partial());
}

#[test]
fn keepalive_of_rfc_7828() {
    let authority = authority();
    let mut asking = query("www.example.", DNSType::A);
    asking.edns.as_mut().unwrap().set_option(DNSKeepalive::query());
    // §3.3.2: told over TCP and TLS to a query that asks, never over UDP (or QUIC, RFC 9250 §5.5.2).
    for (transport, told) in
        [(DNSTransport::TCP, true), (DNSTransport::TLS, true), (DNSTransport::UDP, false), (DNSTransport::QUIC, false)]
    {
        let response = &authority.answer(&asking, &peer(transport), 0)[0].message;
        let option = response.edns.as_ref().unwrap().option(DNSOptionCode::TCP_KEEPALIVE);
        assert_eq!(option.is_some(), told, "{transport:?}");
    }
    let response = &authority.answer(&query("www.example.", DNSType::A), &peer(DNSTransport::TCP), 0)[0].message;
    assert!(response.edns.as_ref().unwrap().option(DNSOptionCode::TCP_KEEPALIVE).is_none());
    // §3.1: units of 100 milliseconds; a length other than 0 or 2 is malformed.
    assert_eq!(DNSKeepalive::response(Duration::from_millis(1250)).data, [0, 12]);
    let mut wrong = response.clone();
    wrong
        .edns
        .as_mut()
        .unwrap()
        .set_option(umilib::protocol::dns::DNSOption { code: DNSOptionCode::TCP_KEEPALIVE, data: vec![1] });
    assert!(DNSKeepalive::timeout(&wrong).is_err());
}

#[test]
fn the_source_of_rfc_5452() {
    let server = IPEndpoint::from_ascii(b"192.0.2.53:53").unwrap();
    assert!(DNSUDP::accepts(&server, &server));
    assert!(!DNSUDP::accepts(&IPEndpoint::from_ascii(b"192.0.2.53:5353").unwrap(), &server));
    assert!(!DNSUDP::accepts(&IPEndpoint::from_ascii(b"192.0.2.54:53").unwrap(), &server));
    assert!(DNSUDP::accepts(&IPEndpoint::from_ascii(b"[::ffff:192.0.2.53]:53").unwrap(), &server));
}

#[cfg(umilib_feature = "protocol-dns-https")]
mod https {
    use umilib::protocol::dns::https::DNSHTTPS;
    use umilib::protocol::dns::{DNSMessage, DNSQuestion, DNSType};
    use umilib::protocol::http::{HTTPFields, HTTPMethod, HTTPRequest, HTTPResponse, HTTPStatus};

    use super::{authority, name, peer};
    use crate::RFC;

    #[test]
    fn the_examples_of_rfc_8484() {
        // §4.1.1: the GET of www.example.com A, of ID 0 and RD.
        let query = DNSMessage::query(0, DNSQuestion::new(name("www.example.com."), DNSType::A));
        let request = DNSHTTPS::get(&query, b"dnsserver.example.net", b"/dns-query").unwrap();
        let expected = RFC::block_from("protocol/dns/rfc8484.txt", ":path = /dns-query?dns=");
        let path = expected.split_once(":path = ").unwrap().1.split("accept").next().unwrap();
        assert_eq!(String::from_utf8(request.path.clone()).unwrap(), path);
        assert_eq!(
            (request.method.clone(), request.fields.get(b"accept")),
            (HTTPMethod::GET, Some(&b"application/dns-message"[..]))
        );
        // The POST of www.example.com AAAA: its content of 33 bytes.
        let aaaa = DNSMessage::query(0, DNSQuestion::new(name("www.example.com."), DNSType::AAAA));
        let (request, content) = DNSHTTPS::post(&aaaa, b"dnsserver.example.net", b"/dns-query").unwrap();
        assert_eq!((request.method.clone(), content.len()), (HTTPMethod::POST, 33));
        assert_eq!(request.fields.get(b"content-length"), Some(&b"33"[..]));
        // The server reads both, and the response is fresh for its least TTL (§5.1).
        for (request, content) in
            [(DNSHTTPS::get(&query, b"a", b"/dns-query?other=1").unwrap(), Vec::new()), (request, content)]
        {
            assert!(DNSHTTPS::query(&request, &content).is_ok());
        }
        let www = DNSMessage::query(0, DNSQuestion::new(name("www.example."), DNSType::A));
        let bytes = authority().respond(&www.encode(512).unwrap(), &peer(super::DNSTransport::HTTPS), 0).remove(0);
        let response = DNSHTTPS::response(&bytes).unwrap();
        assert_eq!(
            (response.status, response.fields.get(b"cache-control")),
            (HTTPStatus::OK, Some(&b"max-age=300"[..]))
        );
        assert_eq!(DNSHTTPS::decode_response(&response, &bytes).unwrap().answers.len(), 1);
        // A name error, fresh for the SOA's minimum (RFC 2308 §5).
        let none = DNSMessage::query(0, DNSQuestion::new(name("none.example."), DNSType::A));
        let bytes = authority().respond(&none.encode(512).unwrap(), &peer(super::DNSTransport::HTTPS), 0).remove(0);
        assert_eq!(DNSHTTPS::response(&bytes).unwrap().fields.get(b"cache-control"), Some(&b"max-age=300"[..]));
    }

    #[test]
    fn the_requests_a_server_refuses() {
        let query = DNSMessage::query(0, DNSQuestion::new(name("www.example.com."), DNSType::A));
        let (post, content) = DNSHTTPS::post(&query, b"a", b"/dns-query").unwrap();
        let with = |method: HTTPMethod, path: &[u8], fields: HTTPFields| {
            HTTPRequest::new(method, b"https", b"a", path).with_fields(fields)
        };
        // §4.1: base64url without padding; another media type is 415.
        assert_eq!(
            DNSHTTPS::query(&with(HTTPMethod::GET, b"/dns-query", HTTPFields::new()), &[]),
            Err(HTTPStatus::BAD_REQUEST)
        );
        assert_eq!(
            DNSHTTPS::query(&with(HTTPMethod::GET, b"/dns-query?dns=AAAB==", HTTPFields::new()), &[]),
            Err(HTTPStatus::BAD_REQUEST)
        );
        assert_eq!(
            DNSHTTPS::query(&with(HTTPMethod::GET, b"/dns-query?dns=AAAB", HTTPFields::new()), &[]),
            Err(HTTPStatus::BAD_REQUEST)
        );
        let text = HTTPFields::new().with(b"content-type", b"text/plain").unwrap();
        assert_eq!(
            DNSHTTPS::query(&with(HTTPMethod::POST, b"/dns-query", text), &content),
            Err(HTTPStatus::UNSUPPORTED_MEDIA_TYPE)
        );
        let parameters = HTTPFields::new().with(b"content-type", b"Application/DNS-Message; charset=x").unwrap();
        assert!(DNSHTTPS::query(&with(HTTPMethod::POST, b"/dns-query", parameters), &content).is_ok());
        assert_eq!(
            DNSHTTPS::query(&with(HTTPMethod::PUT, b"/dns-query", post.fields.clone()), &content),
            Err(HTTPStatus::METHOD_NOT_ALLOWED)
        );
        assert_eq!(DNSHTTPS::query(&post, &content[..10]), Err(HTTPStatus::BAD_REQUEST));
        let long = format!("/dns-query?dns={}", "A".repeat(87_382));
        assert_eq!(
            DNSHTTPS::query(&with(HTTPMethod::GET, long.as_bytes(), HTTPFields::new()), &[]),
            Err(HTTPStatus::URI_TOO_LONG)
        );
        // A client takes only a 2xx of the media type (§4.2.1).
        let bytes = query.encode(512).unwrap();
        let fields = HTTPFields::new().with(b"content-type", DNSHTTPS::MEDIA_TYPE).unwrap();
        assert!(
            DNSHTTPS::decode_response(&HTTPResponse::new(HTTPStatus(404)).with_fields(fields.clone()), &bytes).is_err()
        );
        assert!(DNSHTTPS::decode_response(&HTTPResponse::new(HTTPStatus::OK), &bytes).is_err());
        assert!(DNSHTTPS::decode_response(&HTTPResponse::new(HTTPStatus::OK).with_fields(fields), &bytes).is_ok());
    }
}

#[cfg(umilib_feature = "protocol-dns-tls")]
mod tls {
    use umilib::protocol::dns::DNSTransport;
    use umilib::protocol::dns::tcp::{DNSTCPClientConfig, DNSTCPServerConfig};
    use umilib::protocol::dns::tls::{DNSTLS, DNSTLSClient, DNSTLSError, DNSTLSServer};

    use super::{DNSType, at, authority, peer, query, random};
    use crate::tls::handshake::{Fixture, Pair};

    fn pair(client_protocols: &[&[u8]], server_protocols: &[&[u8]]) -> (DNSTLSClient, DNSTLSServer) {
        let mut client = Fixture::client_config();
        client.config.protocols = client_protocols.iter().map(|protocol| protocol.to_vec()).collect();
        let mut server = Fixture::server_config("server-p256");
        server.config.protocols = server_protocols.iter().map(|protocol| protocol.to_vec()).collect();
        let pair = Pair::new(client, server, Some("server.example"));
        (
            DNSTLSClient::new(pair.client, DNSTCPClientConfig::default(), at(0)),
            DNSTLSServer::new(pair.server, DNSTCPServerConfig::default(), peer(DNSTransport::TLS), at(0)),
        )
    }

    /// Moves bytes both ways until neither has more.
    fn run(client: &mut DNSTLSClient, server: &mut DNSTLSServer) -> Result<(), DNSTLSError> {
        let authority = authority();
        loop {
            let (mut from_client, mut from_server) = (Vec::new(), Vec::new());
            client.transmit(&mut from_client)?;
            if !from_client.is_empty() {
                server.receive(&from_client, &authority, at(1), 0)?;
            }
            server.transmit(&mut from_server)?;
            if !from_server.is_empty() {
                client.receive(&from_server, at(1))?;
            }
            if from_client.is_empty() && from_server.is_empty() {
                return Ok(());
            }
        }
    }

    #[test]
    fn queries_over_tls() {
        // RFC 7858 §3.3: queries sent before the handshake completes wait; then pipelined.
        let (mut client, mut server) = pair(&[DNSTLS::ALPN], &[DNSTLS::ALPN]);
        let mut random = random();
        client.send(1, query("www.example.", DNSType::A), &mut random).unwrap();
        client.send(2, query("none.example.", DNSType::A), &mut random).unwrap();
        run(&mut client, &mut server).unwrap();
        let responses: Vec<u64> = std::iter::from_fn(|| client.poll_response()).map(|(handle, _)| handle).collect();
        assert_eq!(responses, [1, 2]);
        assert_eq!(client.tls.session.protocol.as_deref(), Some(DNSTLS::ALPN));
        // Without ALPN too.
        let (mut client, mut server) = pair(&[], &[]);
        client.send(3, query("www.example.", DNSType::A), &mut random).unwrap();
        run(&mut client, &mut server).unwrap();
        assert!(client.poll_response().is_some());
    }

    #[test]
    fn another_protocol_is_not_dns() {
        let (mut client, mut server) = pair(&[b"h2"], &[b"h2"]);
        client.send(1, query("www.example.", DNSType::A), &mut random()).unwrap();
        assert!(run(&mut client, &mut server).is_err());
    }
}

#[cfg(umilib_feature = "protocol-dns-quic")]
mod quic {
    use umilib::protocol::dns::quic::{DNSQUICConnection, DNSQUICErrorCode, DNSQUICEvent};
    use umilib::protocol::dns::{DNSAuthority, DNSAuthorityConfig, DNSMessage, DNSTransport, DNSZone};
    use umilib::protocol::quic::{QUICCloseReason, QUICConfig, QUICEvent, QUICRole};

    use super::{DNSType, authority, name, peer, query, zone};
    use crate::quic::connection::Network;

    fn network() -> Network {
        network_of(QUICConfig::default())
    }

    fn network_of(server_config: QUICConfig) -> Network {
        let (mut client, mut server) = Network::configs();
        client.config.protocols = vec![DNSQUICConnection::ALPN.to_vec()];
        server.config.protocols = vec![DNSQUICConnection::ALPN.to_vec()];
        let mut network = Network::with(QUICConfig::default(), server_config, client, server);
        network.run();
        network
    }

    /// The server's DNS answers every query it has with all its responses.
    fn serve(network: &mut Network, server: &mut DNSQUICConnection, authority: &DNSAuthority) {
        let now = network.now;
        server.process(network.server(), now).unwrap();
        while let Some(event) = server.poll_event() {
            if let DNSQUICEvent::Query { stream, message } = event {
                let responses = authority.respond(&message, &peer(DNSTransport::QUIC), 0);
                server.send_response(network.server(), stream, &responses).unwrap();
            }
        }
    }

    #[test]
    fn queries_over_quic() {
        let mut network = network();
        let mut client = DNSQUICConnection::new(QUICRole::Client);
        let mut server = DNSQUICConnection::new(QUICRole::Server);
        // RFC 9250 §4.2: a stream a query, the ID 0, no keepalive.
        let mut asked = query("www.example.", DNSType::A);
        asked.header.id = 4321;
        asked.edns.as_mut().unwrap().set_option(umilib::protocol::dns::DNSKeepalive::query());
        let first = client.send_query(&mut network.client, &asked).unwrap();
        let second = client.send_query(&mut network.client, &query("none.example.", DNSType::A)).unwrap();
        assert_ne!(first, second);
        network.run();
        serve(&mut network, &mut server, &authority());
        network.run();
        let now = network.now;
        client.process(&mut network.client, now).unwrap();
        let mut answered = Vec::new();
        while let Some(event) = client.poll_event() {
            if let DNSQUICEvent::Response { stream, message } = event {
                assert_eq!(message.header.id, 0);
                answered.push((stream, message.rcode().0));
            }
        }
        answered.sort();
        assert_eq!(answered, [(first, 0), (second, 3)]);
        // A server sends no query, and no response but to a query.
        assert!(server.send_query(network.server(), &query("www.example.", DNSType::A)).is_err());
        assert!(server.send_response(network.server(), first, &[vec![0; 12]]).is_err());
        // Both halves of the streams ended: nothing is kept of them.
        assert!(client.streams.is_empty() && server.streams.is_empty());
    }

    #[test]
    fn zone_transfers_over_quic() {
        // §4.2: every response of a zone transfer on its query's stream, in
        // order, the stream ended after the last; more than its buffer takes
        // at once is sent as it takes more.
        let mut records = String::from("example. 3600 IN SOA ns.example. admin.example. 1 3600 600 86400 300\n");
        for index in 0..400 {
            records.push_str(&format!("host{index}.example. 300 IN A 192.0.2.{}\n", index % 250));
        }
        let config = DNSAuthorityConfig {
            transfers: vec![umilib::protocol::ip::IPEndpointPattern::ANY],
            transfer_size: 2048,
            ..DNSAuthorityConfig::default()
        };
        let authority = DNSAuthority::new(vec![DNSZone::new(name("example."), zone(&records)).unwrap()], config);
        let mut network = network_of(QUICConfig { maximum_send_buffer: 1500, ..QUICConfig::default() });
        let mut client = DNSQUICConnection::new(QUICRole::Client);
        let mut server = DNSQUICConnection::new(QUICRole::Server);
        let stream = client.send_query(&mut network.client, &query("example.", DNSType::AXFR)).unwrap();
        let mut answers = Vec::new();
        let mut messages = 0;
        for _ in 0..200 {
            // Both ends take what arrives until nothing changes, so that what
            // an acknowledgment frees is written and sent; then time moves.
            loop {
                let before = (server.streams.values().map(|state| state.pending.len()).sum::<usize>(), messages);
                network.run();
                serve(&mut network, &mut server, &authority);
                let now = network.now;
                client.process(&mut network.client, now).unwrap();
                while let Some(event) = client.poll_event() {
                    if let DNSQUICEvent::Response { stream: of, message } = event {
                        assert_eq!(of, stream);
                        messages += 1;
                        answers.extend(message.answers);
                    }
                }
                network.run();
                if before == (server.streams.values().map(|state| state.pending.len()).sum::<usize>(), messages) {
                    break;
                }
            }
            if client.streams.is_empty() {
                break;
            }
            network.tick();
        }
        assert!(messages > 1, "{messages}");
        assert_eq!(answers.len(), 402);
        assert!(answers.first().unwrap().kind == DNSType::SOA && answers.last().unwrap().kind == DNSType::SOA);
        assert!(client.streams.is_empty() && server.streams.is_empty());
    }

    #[test]
    fn more_responses_than_a_query_has() {
        // §4.3: a client that receives two responses to a query for an A record closes with PROTOCOL_ERROR.
        let mut network = network();
        let mut client = DNSQUICConnection::new(QUICRole::Client);
        let mut server = DNSQUICConnection::new(QUICRole::Server);
        client.send_query(&mut network.client, &query("www.example.", DNSType::A)).unwrap();
        network.run();
        let now = network.now;
        server.process(network.server(), now).unwrap();
        let (stream, message) = std::iter::from_fn(|| server.poll_event())
            .find_map(|event| match event {
                DNSQUICEvent::Query { stream, message } => Some((stream, message)),
                _ => None,
            })
            .unwrap();
        let response = authority().respond(&message, &peer(DNSTransport::QUIC), 0).remove(0);
        server.send_response(network.server(), stream, &[response.clone(), response]).unwrap();
        network.run();
        let now = network.now;
        assert!(matches!(
            client.process(&mut network.client, now),
            Err(umilib::protocol::dns::quic::DNSQUICError::Protocol(_))
        ));
    }

    #[test]
    fn breaches_of_rfc_9250() {
        // §4.2.1: an ID other than 0 is a PROTOCOL_ERROR that closes the connection.
        let mut network = network();
        let mut server = DNSQUICConnection::new(QUICRole::Server);
        let mut bad = query("www.example.", DNSType::A);
        bad.header.id = 7;
        let bytes = umilib::protocol::dns::tcp::DNSTCPFramer::frame(&bad.encode(512).unwrap()).unwrap();
        let stream = network.client.open_stream(true).unwrap();
        network.client.stream_send(stream, &bytes, true).unwrap();
        network.run();
        let now = network.now;
        assert!(server.process(network.server(), now).is_err());
        network.run();
        let closed = Network::events(&mut network.client).into_iter().find_map(|event| match event {
            QUICEvent::Closed { reason } => Some(reason),
            _ => None,
        });
        assert!(
            matches!(closed, Some(QUICCloseReason::PeerApplication { error, .. }) if error == DNSQUICErrorCode::PROTOCOL_ERROR.0),
            "{closed:?}"
        );
        // Two messages on one stream, and a unidirectional stream, too.
        for unidirectional in [false, true] {
            let mut network = self::network();
            let mut server = DNSQUICConnection::new(QUICRole::Server);
            let message = DNSMessage::encode(&query("www.example.", DNSType::A), 512).unwrap();
            let framed = umilib::protocol::dns::tcp::DNSTCPFramer::frame(&message).unwrap();
            let stream = network.client.open_stream(!unidirectional).unwrap();
            network.client.stream_send(stream, &[framed.clone(), framed].concat(), true).unwrap();
            network.run();
            let now = network.now;
            assert!(server.process(network.server(), now).is_err());
        }
        // §4.3.3: a client asked to stop sending its query (while it still sends it).
        let mut network = self::network();
        let mut client = DNSQUICConnection::new(QUICRole::Client);
        let stream = client.send_query(&mut network.client, &query("www.example.", DNSType::A)).unwrap();
        let stop = QUICEvent::StopSending { stream, error: DNSQUICErrorCode::NO_ERROR.0 };
        assert!(matches!(
            client.handle(&mut network.client, stop),
            Err(umilib::protocol::dns::quic::DNSQUICError::Protocol(_))
        ));
    }
}
