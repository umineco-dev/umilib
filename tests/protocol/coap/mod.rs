//! Tests of `umilib::protocol::coap` against the rules and examples of RFC
//! 7252, RFC 8974, RFC 7641, RFC 7959 and RFC 6690.

use core::time::Duration;

use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::SHA256;
use umilib::protocol::coap::{
    CoAPBlock, CoAPBlockwise, CoAPCode, CoAPConfig, CoAPEndpoint, CoAPEvent, CoAPLink, CoAPMessage, CoAPObservers,
    CoAPOptionNumber, CoAPOptions, CoAPRule, CoAPTransmission, CoAPType,
};
use umilib::protocol::ip::IPEndpoint;
use umilib::runtime::Instant;
use umilib::service::Rule;

use crate::RFC;

fn random(seed: u8) -> HMACDRBG<SHA256> {
    HMACDRBG::<SHA256>::new(&[seed; 32], &[seed; 16], b"umilib coap tests").unwrap()
}

fn at(milliseconds: u64) -> Instant {
    Instant::from_nanos(milliseconds * 1_000_000)
}

fn client_address() -> IPEndpoint {
    IPEndpoint::from_ascii(b"192.0.2.2:40000").unwrap()
}

fn server_address() -> IPEndpoint {
    IPEndpoint::from_ascii(b"192.0.2.1:5683").unwrap()
}

fn get(path: &str, kind: CoAPType) -> CoAPMessage {
    let mut message = CoAPMessage::new(kind, CoAPCode::GET, 0);
    message.options.set_uri(path, None);
    message
}

#[test]
fn the_message_format_of_rfc_7252() {
    // §3: version 1, type, token length, code, Message ID, token, options by delta, payload after 0xFF.
    let mut message = get("/temperature", CoAPType::Confirmable);
    message.id = 0x7d34;
    message.token = vec![0x20];
    let bytes = message.encode().unwrap();
    let mut expected = vec![0x41, 0x01, 0x7d, 0x34, 0x20, 0xbb];
    expected.extend_from_slice(b"temperature");
    assert_eq!(bytes, expected);
    assert_eq!(CoAPMessage::decode(&bytes).unwrap(), message);
    let mut response = CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, 0x7d34);
    response.token = vec![0x20];
    response.payload = b"22.3 C".to_vec();
    assert_eq!(response.encode().unwrap()[..6], [0x61, 0x45, 0x7d, 0x34, 0x20, 0xff]);
    // §3.1: deltas and lengths of 13 and 14 extend by one and two bytes.
    for (number, length) in [(12u16, 12usize), (13, 13), (268, 268), (269, 269), (1000, 300), (65535, 1034)] {
        let mut message = CoAPMessage::new(CoAPType::NonConfirmable, CoAPCode::POST, 1);
        message.options.push(CoAPOptionNumber(number), vec![b'x'; length]);
        let bytes = message.encode().unwrap();
        assert_eq!(CoAPMessage::decode(&bytes).unwrap(), message, "{number} {length}");
    }
    // A delta or length of 15 but the marker is an error; a marker without payload too.
    for bytes in [
        vec![0x40, 0x01, 0, 1, 0xf0],
        vec![0x40, 0x01, 0, 1, 0x1f],
        vec![0x40, 0x01, 0, 1, 0xff],
        vec![0x40, 0x01, 0, 1, 0xd0],
    ] {
        assert!(CoAPMessage::decode(&bytes).is_err(), "{bytes:?}");
    }
    // Another version; a header cut short.
    assert!(CoAPMessage::decode(&[0x80, 0x01, 0, 1]).is_err());
    assert!(CoAPMessage::decode(&[0x40, 0x01, 0]).is_err());
    // §4.1: an empty message has nothing after its header.
    assert!(CoAPMessage::decode(&[0x60, 0x00, 0, 1]).is_ok());
    assert!(CoAPMessage::decode(&[0x61, 0x00, 0, 1, 9]).is_err());
    assert!(CoAPMessage::decode(&[0x60, 0x00, 0, 1, 0xff, 1]).is_err());
}

#[test]
fn extended_tokens_of_rfc_8974() {
    // §2.1: lengths up to 12 in the nibble, 13 and 14 extended, 15 reserved.
    for length in [0, 8, 9, 12, 13, 268, 269, 1000] {
        let mut message = CoAPMessage::new(CoAPType::NonConfirmable, CoAPCode::GET, 1);
        message.token = vec![7; length];
        let bytes = message.encode().unwrap();
        let nibble = bytes[0] & 15;
        let expected = if length <= 12 {
            length as u8
        } else if length <= 268 {
            13
        } else {
            14
        };
        assert_eq!(nibble, expected, "{length}");
        assert_eq!(CoAPMessage::decode(&bytes).unwrap().token.len(), length);
    }
    assert!(CoAPMessage::decode(&[0x4f, 0x01, 0, 1]).is_err());
    assert!(CoAPMessage::decode(&[0x4d, 0x01, 0, 1]).is_err());
}

#[test]
fn the_options_of_rfc_7252() {
    // §5.4.6: the properties are of the number's bits.
    assert!(CoAPOptionNumber::URI_PATH.is_critical() && CoAPOptionNumber::URI_PATH.is_unsafe());
    assert!(
        !CoAPOptionNumber::ETAG.is_critical()
            && !CoAPOptionNumber::ETAG.is_unsafe()
            && !CoAPOptionNumber::ETAG.is_no_cache_key()
    );
    assert!(CoAPOptionNumber::SIZE1.is_no_cache_key() && !CoAPOptionNumber::SIZE1.is_critical());
    // §3.2: uints without leading zeros.
    assert_eq!(CoAPOptions::uint_bytes(0), Vec::<u8>::new());
    assert_eq!(CoAPOptions::uint_bytes(0x1234), [0x12, 0x34]);
    assert_eq!(CoAPOptions::uint_of(&[0, 0, 1]), Some(1));
    // §5.4.1, §5.4.3, §5.4.5: an unknown critical option, a value out of
    // its lengths, or a non-repeatable one repeated rejects; elective ones are ignored.
    let mut options = CoAPOptions::new();
    options.set_uri("/a/b", Some("x=1&y"));
    assert_eq!(options.path(), ["a", "b"]);
    assert_eq!(options.queries(), ["x=1", "y"]);
    assert!(options.check().is_ok());
    for (number, value, rejects) in [
        (CoAPOptionNumber(9), vec![1], true),
        (CoAPOptionNumber(10), vec![1], false),
        (CoAPOptionNumber::URI_HOST, vec![], true),
        (CoAPOptionNumber::ETAG, vec![], false),
        (CoAPOptionNumber::ACCEPT, vec![1, 2, 3], true),
    ] {
        let mut changed = options.clone();
        changed.push(number, value);
        assert_eq!(changed.check().is_err(), rejects, "{number:?}");
        if !rejects {
            assert_eq!(changed.usable().entries.len(), options.entries.len());
        }
    }
    let mut repeated = CoAPOptions::new();
    repeated.push(CoAPOptionNumber::URI_HOST, b"a".to_vec());
    repeated.push(CoAPOptionNumber::URI_HOST, b"b".to_vec());
    assert!(repeated.check().is_err());
    let mut elective = CoAPOptions::new();
    elective.push(CoAPOptionNumber::MAX_AGE, vec![1]);
    elective.push(CoAPOptionNumber::MAX_AGE, vec![2]);
    assert_eq!(elective.usable().max_age(), 1);
    // §5.10.5: Max-Age is 60 without the option.
    assert_eq!(CoAPOptions::new().max_age(), 60);
}

#[test]
fn blocks_of_rfc_7959() {
    // §2.2: NUM, M and SZX; sizes of 2^(SZX + 4); SZX 7 is reserved.
    let block = CoAPBlock::new(3, true, 128).unwrap();
    assert_eq!((block.exponent, block.encode(), block.offset()), (3, vec![0x3b], 384));
    assert_eq!(CoAPBlock::decode(&[0x3b]).unwrap(), block);
    assert_eq!(CoAPBlock::decode(&[]).unwrap(), CoAPBlock::new(0, false, 16).unwrap());
    assert!(CoAPBlock::decode(&[0x07]).is_err() && CoAPBlock::decode(&[1, 2, 3, 4]).is_err());
    assert!(CoAPBlock::new(0, false, 2048).is_err() && CoAPBlock::new(1 << 20, false, 16).is_err());
    // §2.4: a server's blocks; a smaller size than asked keeps the offset.
    let body: Vec<u8> = (0..300u16).map(|value| value as u8).collect();
    let mut request = get("/large", CoAPType::Confirmable);
    request.options.set_uint(CoAPOptionNumber::SIZE2, 0);
    let mut response = CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, 0);
    CoAPBlockwise::respond(&request, &body, 128, &mut response).unwrap();
    let first = response.options.block(CoAPOptionNumber::BLOCK2).unwrap().unwrap();
    assert_eq!((first.number, first.more, first.size(), response.payload.len()), (0, true, 128, 128));
    assert_eq!(response.options.uint(CoAPOptionNumber::SIZE2), Some(300));
    request.options.set(CoAPOptionNumber::BLOCK2, CoAPBlock::new(1, false, 256).unwrap().encode());
    CoAPBlockwise::respond(&request, &body, 64, &mut response).unwrap();
    let block = response.options.block(CoAPOptionNumber::BLOCK2).unwrap().unwrap();
    assert_eq!((block.number, block.size(), response.payload[0]), (4, 64, 0));
    request.options.set(CoAPOptionNumber::BLOCK2, CoAPBlock::new(9, false, 64).unwrap().encode());
    assert!(CoAPBlockwise::respond(&request, &body, 64, &mut response).is_err());
    // A body that fits is sent whole, without Block2.
    let small = get("/small", CoAPType::Confirmable);
    let mut whole = CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, 0);
    CoAPBlockwise::respond(&small, &body[..100], 128, &mut whole).unwrap();
    assert!(!whole.options.contains(CoAPOptionNumber::BLOCK2));
    // §2.4, §2.5: a receiver takes blocks in order, of their size and ETag.
    let mut receiver = CoAPBlockwise::new(1000);
    assert_eq!(receiver.receive(CoAPBlock::new(0, true, 128).unwrap(), &body[..128], Some(&[1])), Ok(false));
    assert!(receiver.receive(CoAPBlock::new(2, true, 128).unwrap(), &body[256..], Some(&[1])).is_err());
    assert!(receiver.receive(CoAPBlock::new(1, true, 128).unwrap(), &body[128..256], Some(&[2])).is_err());
    assert_eq!(receiver.receive(CoAPBlock::new(1, true, 128).unwrap(), &body[128..256], Some(&[1])), Ok(false));
    let next = receiver.next_request(&request.options, 128).unwrap();
    assert_eq!(next.block(CoAPOptionNumber::BLOCK2).unwrap().unwrap().number, 2);
    assert_eq!(receiver.receive(CoAPBlock::new(2, false, 128).unwrap(), &body[256..], Some(&[1])), Ok(true));
    assert_eq!(receiver.body, body);
    // §2.4: a receiver may ask for smaller blocks as it goes, numbered at their own size.
    let long: Vec<u8> = (0..1000u16).map(|value| value as u8).collect();
    let mut smaller = CoAPBlockwise::new(1000);
    assert_eq!(smaller.receive(CoAPBlock::new(0, true, 256).unwrap(), &long[..256], None), Ok(false));
    let next = smaller.next_request(&request.options, 64).unwrap();
    assert_eq!(next.block(CoAPOptionNumber::BLOCK2).unwrap().unwrap().number, 4);
    assert_eq!(smaller.receive(CoAPBlock::new(4, true, 64).unwrap(), &long[256..320], None), Ok(false));
    // A larger size than the blocks received may not divide the body so far.
    assert!(smaller.next_request(&request.options, 128).is_err());
    let next = smaller.next_request(&request.options, 32).unwrap();
    assert_eq!(next.block(CoAPOptionNumber::BLOCK2).unwrap().unwrap().number, 10);
    let mut small = CoAPBlockwise::new(100);
    assert!(small.receive(CoAPBlock::new(0, true, 128).unwrap(), &body[..128], None).is_err());
}

/// A client and a server endpoint, and the datagrams between them.
struct Pair {
    client: CoAPEndpoint,
    server: CoAPEndpoint,
    random: HMACDRBG<SHA256>,
}

impl Pair {
    fn new(config: CoAPConfig) -> Pair {
        let mut random = random(1);
        Pair {
            client: CoAPEndpoint::new(config, &mut random).unwrap(),
            server: CoAPEndpoint::new(config, &mut random).unwrap(),
            random,
        }
    }

    /// Delivers what each has to send, until neither has any.
    fn run(&mut self, now: Instant) -> (usize, usize) {
        let mut counts = (0, 0);
        loop {
            let mut moved = false;
            while let Some(transmission) = self.client.transmit() {
                moved = true;
                counts.0 += 1;
                self.server.receive(client_address(), &transmission.message, now, &mut self.random);
            }
            while let Some(transmission) = self.server.transmit() {
                moved = true;
                counts.1 += 1;
                self.client.receive(server_address(), &transmission.message, now, &mut self.random);
            }
            if !moved {
                return counts;
            }
        }
    }

    fn requests(&mut self) -> Vec<(u64, CoAPMessage)> {
        std::iter::from_fn(|| self.server.poll_event())
            .filter_map(|event| match event {
                CoAPEvent::Request { exchange, message, .. } => Some((exchange, message)),
                _ => None,
            })
            .collect()
    }

    fn responses(&mut self) -> Vec<CoAPEvent> {
        std::iter::from_fn(|| self.client.poll_event()).collect()
    }
}

#[test]
fn piggybacked_and_separate_responses() {
    let mut pair = Pair::new(CoAPConfig::default());
    let mut random = random(2);
    // §5.2.1: a response in the ACK of a Confirmable request.
    let handle = pair.client.request(server_address(), get("/a", CoAPType::Confirmable), at(0), &mut random).unwrap();
    pair.run(at(0));
    let (exchange, request) = pair.requests().remove(0);
    assert_eq!((request.options.path(), request.token.len()), (vec!["a".to_string()], 8));
    let mut response = CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, 0);
    response.payload = b"one".to_vec();
    pair.server.respond(exchange, response.clone(), at(10), &mut random).unwrap();
    pair.run(at(10));
    let events = pair.responses();
    assert!(
        matches!(&events[..], [CoAPEvent::Response { request, message }] if *request == handle && message.kind == CoAPType::Acknowledgement && message.payload == b"one")
    );
    assert!(pair.client.outgoing.is_empty());
    // §5.2.2: unanswered after the ACK delay, an empty ACK, then the response Confirmable, acknowledged.
    let handle = pair.client.request(server_address(), get("/b", CoAPType::Confirmable), at(100), &mut random).unwrap();
    pair.run(at(100));
    let (exchange, _) = pair.requests().remove(0);
    pair.server.expire(at(1100));
    pair.run(at(1100));
    assert!(pair.responses().is_empty());
    assert!(pair.client.outgoing[&handle].acknowledged);
    pair.server.respond(exchange, response.clone(), at(5000), &mut random).unwrap();
    let separate = pair.server.transmissions.front().unwrap().message.clone();
    assert_eq!(CoAPMessage::decode(&separate).unwrap().kind, CoAPType::Confirmable);
    pair.run(at(5000));
    let events = pair.responses();
    assert!(matches!(&events[..], [CoAPEvent::Response { request, .. }] if *request == handle));
    assert!(pair.server.outgoing.is_empty());
    // A Non-confirmable request has a Non-confirmable response.
    let handle =
        pair.client.request(server_address(), get("/c", CoAPType::NonConfirmable), at(6000), &mut random).unwrap();
    pair.run(at(6000));
    let (exchange, _) = pair.requests().remove(0);
    pair.server.respond(exchange, response, at(6000), &mut random).unwrap();
    pair.run(at(6000));
    let events = pair.responses();
    assert!(
        matches!(&events[..], [CoAPEvent::Response { request, message }] if *request == handle && message.kind == CoAPType::NonConfirmable)
    );
    // A request is answered once.
    assert!(
        pair.server
            .respond(exchange, CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, 0), at(6000), &mut random)
            .is_err()
    );
}

#[test]
fn retransmissions_and_duplicates_of_rfc_7252() {
    let mut random = random(3);
    let mut client = CoAPEndpoint::new(CoAPConfig::default(), &mut random).unwrap();
    let handle = client.request(server_address(), get("/a", CoAPType::Confirmable), at(0), &mut random).unwrap();
    let first = client.transmit().unwrap().message;
    // §4.2: a first timeout from 2 to 3 s, doubled at each of 4 retransmissions, then a timeout.
    let mut deadline = client.poll_timeout().unwrap();
    assert!((at(2000)..=at(3000)).contains(&deadline), "{deadline:?}");
    let initial = deadline.saturating_duration_since(at(0));
    let mut sent = vec![];
    for retransmission in 1..=4u32 {
        client.expire(deadline);
        let message = client.transmit().unwrap().message;
        assert_eq!(message, first);
        sent.push(deadline);
        let next = client.poll_timeout().unwrap();
        assert_eq!(next.saturating_duration_since(deadline), initial * 2u32.pow(retransmission));
        deadline = next;
    }
    client.expire(deadline);
    assert!(client.transmit().is_none());
    assert_eq!(client.poll_event(), Some(CoAPEvent::Timeout { message: handle }));
    // §4.5: a duplicate of a Confirmable request gets the same reply, and is not told again.
    let mut server = CoAPEndpoint::new(CoAPConfig::default(), &mut random).unwrap();
    server.receive(client_address(), &first, at(0), &mut random);
    let Some(CoAPEvent::Request { exchange, .. }) = server.poll_event() else { panic!() };
    server
        .respond(exchange, CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, 0), at(0), &mut random)
        .unwrap();
    let reply = server.transmit().unwrap().message;
    server.receive(client_address(), &first, at(3000), &mut random);
    assert_eq!(server.transmit().unwrap().message, reply);
    assert!(server.poll_event().is_none());
    // Remembered for EXCHANGE_LIFETIME, then a new message.
    server.expire(at(248_000));
    server.receive(client_address(), &first, at(248_000), &mut random);
    assert!(matches!(server.poll_event(), Some(CoAPEvent::Request { .. })));
}

#[test]
fn rejections_of_rfc_7252() {
    let mut random = random(4);
    let mut server = CoAPEndpoint::new(CoAPConfig::default(), &mut random).unwrap();
    let reset_of = |bytes: &[u8]| {
        let message = CoAPMessage::decode(bytes).unwrap();
        (message.kind, message.code, message.id)
    };
    // §4.3: a ping (empty Confirmable) is answered with RST.
    server.receive(
        client_address(),
        &CoAPMessage::empty(CoAPType::Confirmable, 9).encode().unwrap(),
        at(0),
        &mut random,
    );
    assert_eq!(reset_of(&server.transmit().unwrap().message), (CoAPType::Reset, CoAPCode::EMPTY, 9));
    // §4.2: a Confirmable message that cannot be read, RST; a Non-confirmable one, nothing.
    server.receive(client_address(), &[0x40, 0x01, 0, 10, 0xf0], at(0), &mut random);
    assert_eq!(reset_of(&server.transmit().unwrap().message), (CoAPType::Reset, CoAPCode::EMPTY, 10));
    server.receive(client_address(), &[0x50, 0x01, 0, 11, 0xf0], at(0), &mut random);
    assert!(server.transmit().is_none());
    // RFC 8974 §2.2.1: a token longer than taken is a message format error.
    let mut long = get("/a", CoAPType::Confirmable);
    long.id = 12;
    long.token = vec![1; 9];
    server.receive(client_address(), &long.encode().unwrap(), at(0), &mut random);
    assert_eq!(reset_of(&server.transmit().unwrap().message), (CoAPType::Reset, CoAPCode::EMPTY, 12));
    // §5.4.1: a critical option not known: 4.02 Bad Option, piggybacked.
    let mut unknown = get("/a", CoAPType::Confirmable);
    unknown.id = 13;
    unknown.options.push(CoAPOptionNumber(9), vec![1]);
    server.receive(client_address(), &unknown.encode().unwrap(), at(0), &mut random);
    let reply = CoAPMessage::decode(&server.transmit().unwrap().message).unwrap();
    assert_eq!((reply.kind, reply.code, reply.id), (CoAPType::Acknowledgement, CoAPCode::BAD_OPTION, 13));
    assert!(server.poll_event().is_none());
    // §5.3.2: a Confirmable response of no request is rejected.
    let mut client = CoAPEndpoint::new(CoAPConfig::default(), &mut random).unwrap();
    let mut stray = CoAPMessage::new(CoAPType::Confirmable, CoAPCode::CONTENT, 14);
    stray.token = vec![5];
    client.receive(server_address(), &stray.encode().unwrap(), at(0), &mut random);
    assert_eq!(reset_of(&client.transmit().unwrap().message), (CoAPType::Reset, CoAPCode::EMPTY, 14));
    // A RST of a request ends it.
    let handle = client.request(server_address(), get("/a", CoAPType::Confirmable), at(0), &mut random).unwrap();
    let id = CoAPMessage::decode(&client.transmit().unwrap().message).unwrap().id;
    client.receive(server_address(), &CoAPMessage::empty(CoAPType::Reset, id).encode().unwrap(), at(1), &mut random);
    assert_eq!(client.poll_event(), Some(CoAPEvent::Reset { message: handle }));
}

#[test]
fn nstart_of_rfc_7252() {
    // §4.7: one interaction at a time with a peer; the next waits.
    let mut pair = Pair::new(CoAPConfig::default());
    let mut random = random(5);
    pair.client.request(server_address(), get("/a", CoAPType::Confirmable), at(0), &mut random).unwrap();
    pair.client.request(server_address(), get("/b", CoAPType::Confirmable), at(0), &mut random).unwrap();
    assert_eq!(pair.client.transmissions.len(), 1);
    pair.run(at(0));
    let (exchange, _) = pair.requests().remove(0);
    pair.server
        .respond(exchange, CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, 0), at(1), &mut random)
        .unwrap();
    pair.run(at(1));
    let requests = pair.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.options.path(), ["b"]);
}

#[test]
fn observations_of_rfc_7641() {
    let mut pair = Pair::new(CoAPConfig::default());
    let mut random = random(6);
    let mut observers = CoAPObservers::default();
    // §3.1, §4.1: GET with Observe 0 registers; the response carries Observe.
    let mut request = get("/temp", CoAPType::Confirmable);
    request.options.set_uint(CoAPOptionNumber::OBSERVE, 0);
    let handle = pair.client.request(server_address(), request, at(0), &mut random).unwrap();
    pair.run(at(0));
    let (exchange, message) = pair.requests().remove(0);
    assert!(observers.register(client_address(), &message, at(0)));
    let mut response = CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, 0);
    response.options.set_uint(CoAPOptionNumber::OBSERVE, observers.next_value());
    response.payload = b"20".to_vec();
    pair.server.respond(exchange, response.clone(), at(0), &mut random).unwrap();
    pair.run(at(0));
    assert_eq!(pair.responses().len(), 1);
    // §4.2: notifications of increasing Observe values, to the observer's token.
    let path = vec!["temp".to_string()];
    for value in [b"21", b"22"] {
        response.payload = value.to_vec();
        observers.notify(&mut pair.server, &path, &response, false, at(1000), &mut random).unwrap();
        pair.run(at(1000));
        let events = pair.responses();
        assert!(
            matches!(&events[..], [CoAPEvent::Response { request, message }] if *request == handle && message.payload == value)
        );
    }
    // §3.4: a notification older than the freshest is dropped.
    let freshest = pair.client.outgoing[&handle].freshest.unwrap().0;
    let mut stale = response.clone();
    stale.kind = CoAPType::NonConfirmable;
    stale.id = 999;
    stale.token = pair.client.outgoing[&handle].token.clone();
    stale.options.set_uint(CoAPOptionNumber::OBSERVE, freshest - 1);
    pair.client.receive(server_address(), &stale.encode().unwrap(), at(2000), &mut random);
    assert!(pair.responses().is_empty());
    // The rule's cases: serial order of 24 bits, or 128 seconds since.
    assert!(CoAPEndpoint::is_fresher(1, at(0), 2, at(0)));
    assert!(!CoAPEndpoint::is_fresher(2, at(0), 1, at(0)));
    assert!(CoAPEndpoint::is_fresher(0xFF_FFFF, at(0), 1, at(0)));
    assert!(!CoAPEndpoint::is_fresher(1, at(0), 1 + (1 << 23), at(0)));
    assert!(CoAPEndpoint::is_fresher(2, at(0), 1, at(128_001)));
    // §3.6: a client that forgets rejects the next notification, which ends the observation.
    pair.client.cancel(handle, at(3000));
    observers.notify(&mut pair.server, &path, &response, false, at(3000), &mut random).unwrap();
    pair.run(at(3000));
    let events: Vec<CoAPEvent> = std::iter::from_fn(|| pair.server.poll_event()).collect();
    let ended = events.iter().any(|event| observers.handle(event));
    assert!(ended && observers.observers.is_empty());
}

#[test]
fn the_ends_of_an_observation() {
    let mut random = random(7);
    let mut endpoint = CoAPEndpoint::new(CoAPConfig::default(), &mut random).unwrap();
    let mut observers = CoAPObservers::default();
    let mut request = get("/temp", CoAPType::Confirmable);
    request.token = vec![1];
    request.options.set_uint(CoAPOptionNumber::OBSERVE, 0);
    let path = vec!["temp".to_string()];
    let content = CoAPMessage::new(CoAPType::NonConfirmable, CoAPCode::CONTENT, 0);
    // §4.5: a Confirmable notification at least once a day, and its timeout ends the observation.
    observers.register(client_address(), &request, at(0));
    observers.notify(&mut endpoint, &path, &content, false, at(1000), &mut random).unwrap();
    assert_eq!(CoAPMessage::decode(&endpoint.transmit().unwrap().message).unwrap().kind, CoAPType::NonConfirmable);
    // Only a RST or an unacknowledged Confirmable notification ends it: a
    // Non-confirmable one past NON_LIFETIME (RFC 7252 §4.8.2) does not.
    endpoint.expire(at(1000 + 145_001));
    let events: Vec<CoAPEvent> = std::iter::from_fn(|| endpoint.poll_event()).collect();
    assert!(!events.iter().any(|event| observers.handle(event)));
    assert_eq!(observers.observers.len(), 1);
    observers.notify(&mut endpoint, &path, &content, false, at(86_400_000), &mut random).unwrap();
    assert_eq!(CoAPMessage::decode(&endpoint.transmit().unwrap().message).unwrap().kind, CoAPType::Confirmable);
    while let Some(deadline) = endpoint.poll_timeout() {
        endpoint.expire(deadline);
    }
    let events: Vec<CoAPEvent> = std::iter::from_fn(|| endpoint.poll_event()).collect();
    assert!(events.iter().any(|event| observers.handle(event)));
    assert!(observers.observers.is_empty());
    // §3.6: GET with Observe 1 deregisters; §4.2: an error notification ends them all, without Observe.
    observers.register(client_address(), &request, at(0));
    let mut deregister = request.clone();
    deregister.options.set_uint(CoAPOptionNumber::OBSERVE, 1);
    assert!(!observers.register(client_address(), &deregister, at(0)));
    assert!(observers.observers.is_empty());
    observers.register(client_address(), &request, at(0));
    let error = CoAPMessage::new(CoAPType::NonConfirmable, CoAPCode::NOT_FOUND, 0);
    endpoint.transmissions.clear();
    observers.notify(&mut endpoint, &path, &error, false, at(1), &mut random).unwrap();
    let sent = CoAPMessage::decode(&endpoint.transmit().unwrap().message).unwrap();
    assert!(sent.options.observe().is_none());
    assert!(observers.observers.is_empty());
    // A POST does not observe.
    let mut post = request.clone();
    post.code = CoAPCode::POST;
    assert!(!observers.register(client_address(), &post, at(0)));
}

#[test]
fn notifications_kept_while_they_may_end_an_observation() {
    // A server notifying for long keeps of each observer only the
    // notifications its endpoint still has (§4.5): not one per notification ever sent.
    let mut random = random(9);
    let mut endpoint = CoAPEndpoint::new(CoAPConfig::default(), &mut random).unwrap();
    let mut observers = CoAPObservers::default();
    let mut request = get("/temp", CoAPType::Confirmable);
    request.token = vec![2];
    request.options.set_uint(CoAPOptionNumber::OBSERVE, 0);
    observers.register(client_address(), &request, at(0));
    let path = vec!["temp".to_string()];
    let content = CoAPMessage::new(CoAPType::NonConfirmable, CoAPCode::CONTENT, 0);
    for second in 1..=1000u64 {
        let now = at(second * 1000);
        endpoint.expire(now);
        observers.notify(&mut endpoint, &path, &content, false, now, &mut random).unwrap();
        endpoint.transmissions.clear();
    }
    // Non-confirmable ones are kept for NON_LIFETIME (145 s), one a second.
    let kept = observers.observers[0].notifications.len();
    assert!(kept <= 147, "{kept}");
    // One timed out but not yet taken is kept, so that it ends the observation.
    let mut confirmable = CoAPMessage::new(CoAPType::Confirmable, CoAPCode::CONTENT, 0);
    confirmable.payload = b"last".to_vec();
    observers.notify(&mut endpoint, &path, &confirmable, true, at(1_001_000), &mut random).unwrap();
    while let Some(deadline) = endpoint.poll_timeout() {
        endpoint.expire(deadline);
    }
    observers.notify(&mut endpoint, &path, &content, false, at(2_000_000), &mut random).unwrap();
    let events: Vec<CoAPEvent> = std::iter::from_fn(|| endpoint.poll_event()).collect();
    assert!(events.iter().any(|event| observers.handle(event)));
    assert!(observers.observers.is_empty());
}

#[test]
fn the_initial_timeout_of_rfc_7252() {
    // §4.2: from ACK_TIMEOUT to ACK_TIMEOUT × ACK_RANDOM_FACTOR, at any resolution.
    let mut random = random(8);
    for ack_timeout in [Duration::from_micros(500), Duration::from_secs(2)] {
        let config = CoAPConfig { ack_timeout, ..CoAPConfig::default() };
        let endpoint = CoAPEndpoint::new(config, &mut random).unwrap();
        for _ in 0..64 {
            let timeout = endpoint.initial_timeout(&mut random);
            assert!(ack_timeout <= timeout && timeout <= ack_timeout * 3 / 2, "{timeout:?}");
        }
    }
}

#[test]
fn the_link_format_of_rfc_6690() {
    // §5: the examples, each a response's links.
    let lines = Vectors::lines("protocol/coap/rfc6690.txt");
    let mut examples = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if line.trim() == "RES: 2.05 Content" {
            let text: String =
                lines[index + 1..].iter().take_while(|line| !line.trim().is_empty()).map(|line| line.trim()).collect();
            examples.push(text);
        }
    }
    assert!(examples.len() >= 5);
    for text in &examples {
        let links = CoAPLink::parse(text).unwrap_or_else(|error| panic!("{error:?}: {text}"));
        assert_eq!(CoAPLink::parse(&CoAPLink::format(&links)).unwrap(), links);
    }
    let anchors = examples.iter().find(|text| text.contains("Sensor Index")).unwrap();
    let links = CoAPLink::parse(anchors).unwrap();
    assert_eq!(links.len(), 5);
    assert_eq!(
        (links[0].target.as_str(), links[0].attribute("ct"), links[0].attribute("title")),
        ("/sensors", Some(Some("40")), Some(Some("Sensor Index")))
    );
    assert_eq!(links[3].attribute("anchor"), Some(Some("/sensors/temp")));
    assert_eq!(links[3].attribute("rel"), Some(Some("describedby")));
    let space = examples.iter().find(|text| text.contains("core.sen-light")).unwrap();
    assert_eq!(CoAPLink::parse(space).unwrap()[0].attribute("rt"), Some(Some("light-lux core.sen-light")));
    // Attributes without values, quoted values with escapes.
    let links = CoAPLink::parse("</a>;obs;title=\"x\\\"y\",</b>").unwrap();
    assert_eq!(
        (links[0].attribute("obs"), links[0].attribute("title"), links.len()),
        (Some(None), Some(Some("x\"y")), 2)
    );
    // A quoted-pair quotes a character, whatever its length in UTF-8.
    let quoted = CoAPLink::parse("</a>;title=\"\\\u{1c7}x\\\"\"").unwrap();
    assert_eq!(quoted[0].attribute("title"), Some(Some("\u{1c7}x\"")));
    for malformed in ["/a", "</a", "</a>;", "</a>;=1", "</a>x", "</a>;t=\"open", "</a>;t=\"\\"] {
        assert!(CoAPLink::parse(malformed).is_err(), "{malformed}");
    }
}

#[test]
fn rules() {
    let rule = CoAPRule::new("/sensors").with_method(CoAPCode::GET);
    assert!(rule.matches(&get("/sensors/temp", CoAPType::Confirmable)));
    assert!(rule.matches(&get("/sensors", CoAPType::Confirmable)));
    assert!(!rule.matches(&get("/sensorsx", CoAPType::Confirmable)));
    assert!(!rule.matches(&get("/other", CoAPType::Confirmable)));
    let mut post = get("/sensors", CoAPType::Confirmable);
    post.code = CoAPCode::POST;
    assert!(!rule.matches(&post));
    assert!(!CoAPRule::new("/").matches(&CoAPMessage::new(CoAPType::Confirmable, CoAPCode::CONTENT, 0)));
}

/// The lines of a vector file, without the page breaks of an RFC.
struct Vectors;

impl Vectors {
    fn lines(path: &str) -> Vec<String> {
        crate::Vectors::read(path).lines().filter(|line| !RFC::is_page_break(line)).map(String::from).collect()
    }
}

#[test]
fn what_the_message_layer_refuses() {
    let mut random = random(10);
    let decode = |endpoint: &mut CoAPEndpoint| -> Vec<CoAPMessage> {
        std::iter::from_fn(|| endpoint.transmit()).map(|sent| CoAPMessage::decode(&sent.message).unwrap()).collect()
    };
    // §4.2: a RST that is not empty, and an ACK of a request's code, are silently ignored.
    let mut client = CoAPEndpoint::new(CoAPConfig::default(), &mut random).unwrap();
    let handle = client.request(server_address(), get("/a", CoAPType::Confirmable), at(0), &mut random).unwrap();
    let sent = decode(&mut client).remove(0);
    let mut reset = CoAPMessage::new(CoAPType::Reset, CoAPCode::CONTENT, sent.id);
    reset.token = sent.token.clone();
    client.receive(server_address(), &reset.encode().unwrap(), at(1), &mut random);
    let ack = CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::GET, sent.id);
    client.receive(server_address(), &ack.encode().unwrap(), at(1), &mut random);
    assert!(client.poll_event().is_none() && !client.outgoing[&handle].acknowledged);
    // §5.3.2, §5.4.1: a piggybacked response of another token, or of a critical option this end
    // cannot process, is rejected: the request is sent again.
    let mut other = CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, sent.id);
    other.token = vec![9; 8];
    client.receive(server_address(), &other.encode().unwrap(), at(1), &mut random);
    let mut critical = CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, sent.id);
    critical.token = sent.token.clone();
    critical.options.push(CoAPOptionNumber(9), vec![1]);
    client.receive(server_address(), &critical.encode().unwrap(), at(1), &mut random);
    assert!(client.poll_event().is_none() && !client.outgoing[&handle].acknowledged);
    client.expire(client.poll_timeout().unwrap());
    assert_eq!(decode(&mut client).len(), 1);
    // §5.4.1: a Non-confirmable request of an unknown critical option is rejected, not answered 4.02.
    let mut server = CoAPEndpoint::new(CoAPConfig::default(), &mut random).unwrap();
    let mut request = get("/a", CoAPType::NonConfirmable);
    request.id = 77;
    request.token = vec![1];
    request.options.push(CoAPOptionNumber(9), vec![1]);
    server.receive(client_address(), &request.encode().unwrap(), at(0), &mut random);
    let replies = decode(&mut server);
    assert!(replies.iter().all(|reply| reply.kind == CoAPType::Reset) && server.poll_event().is_none());
    // RFC 8974 §2.3: an endpoint of extended tokens answers a token too long for it 4.00, not RST.
    let config = CoAPConfig { maximum_token: 16, ..CoAPConfig::default() };
    let mut extended = CoAPEndpoint::new(config, &mut random).unwrap();
    let mut long = get("/a", CoAPType::Confirmable);
    long.id = 78;
    long.token = vec![2; 20];
    extended.receive(client_address(), &long.encode().unwrap(), at(0), &mut random);
    let reply = decode(&mut extended).remove(0);
    assert_eq!((reply.kind, reply.code), (CoAPType::Acknowledgement, CoAPCode::BAD_REQUEST));
    // §4.5: no more messages remembered than configured.
    let config = CoAPConfig { maximum_seen: 2, ..CoAPConfig::default() };
    let mut small = CoAPEndpoint::new(config, &mut random).unwrap();
    for id in 0..5u16 {
        let mut ping = CoAPMessage::empty(CoAPType::Confirmable, id);
        ping.id = id;
        small.receive(client_address(), &ping.encode().unwrap(), at(u64::from(id)), &mut random);
    }
    assert_eq!(small.seen.len(), 2);
}

#[test]
fn nstart_for_every_interaction() {
    let mut random = random(11);
    // RFC 7641 §4.5.1: Confirmable notifications to a client wait for NSTART as requests do.
    let mut server = CoAPEndpoint::new(CoAPConfig::default(), &mut random).unwrap();
    let mut notification = CoAPMessage::new(CoAPType::Confirmable, CoAPCode::CONTENT, 0);
    notification.token = vec![3];
    notification.options.set_uint(CoAPOptionNumber::OBSERVE, 1);
    for _ in 0..5 {
        server.notify(client_address(), notification.clone(), at(0), &mut random).unwrap();
    }
    let sent: Vec<CoAPTransmission> = std::iter::from_fn(|| server.transmit()).collect();
    assert_eq!((sent.len(), server.waiting.len()), (1, 4));
    let id = CoAPMessage::decode(&sent[0].message).unwrap().id;
    server.receive(
        client_address(),
        &CoAPMessage::empty(CoAPType::Acknowledgement, id).encode().unwrap(),
        at(1),
        &mut random,
    );
    assert_eq!(std::iter::from_fn(|| server.transmit()).count(), 1);
    // §4.7: a request acknowledged with an empty ACK is no longer outstanding; one cancelled lets the next go.
    let mut client = CoAPEndpoint::new(CoAPConfig::default(), &mut random).unwrap();
    let first = client.request(server_address(), get("/a", CoAPType::Confirmable), at(0), &mut random).unwrap();
    client.request(server_address(), get("/b", CoAPType::Confirmable), at(0), &mut random).unwrap();
    assert_eq!(std::iter::from_fn(|| client.transmit()).count(), 1);
    client.cancel(first, at(1));
    assert_eq!(std::iter::from_fn(|| client.transmit()).count(), 1);
}

#[test]
fn a_response_that_cannot_be_written() {
    // The exchange stays when its response cannot be written, so that another can answer it.
    let mut pair = Pair::new(CoAPConfig::default());
    let mut random = random(12);
    pair.client.request(server_address(), get("/a", CoAPType::Confirmable), at(0), &mut random).unwrap();
    pair.run(at(0));
    let (exchange, _) = pair.requests().remove(0);
    let mut huge = CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, 0);
    huge.options.push(CoAPOptionNumber(65000), vec![0; 70_000]);
    assert!(pair.server.respond(exchange, huge, at(0), &mut random).is_err());
    let fine = CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, 0);
    assert!(pair.server.respond(exchange, fine, at(0), &mut random).is_ok());
    pair.run(at(0));
    assert_eq!(pair.responses().len(), 1);
}

#[test]
fn requests_left_unanswered() {
    let mut random = random(13);
    let sent = |endpoint: &mut CoAPEndpoint| -> Vec<CoAPMessage> {
        std::iter::from_fn(|| endpoint.transmit()).map(|sent| CoAPMessage::decode(&sent.message).unwrap()).collect()
    };
    let requests = |endpoint: &mut CoAPEndpoint| -> Vec<u64> {
        std::iter::from_fn(|| endpoint.poll_event())
            .filter_map(|event| match event {
                CoAPEvent::Request { exchange, .. } => Some(exchange),
                _ => None,
            })
            .collect()
    };
    let config = CoAPConfig::default();
    // RFC 7967 §2, RFC 7252 §8.2: a server may choose not to respond. A Confirmable request it does not
    // answer is acknowledged by an empty ACK, so that its client stops retransmitting it (§4.2); a
    // Non-confirmable one gets nothing.
    let mut server = CoAPEndpoint::new(config, &mut random).unwrap();
    let mut confirmable = get("/a", CoAPType::Confirmable);
    confirmable.id = 1;
    confirmable.token = vec![1];
    let mut non = get("/a", CoAPType::NonConfirmable);
    non.id = 2;
    non.token = vec![2];
    server.receive(client_address(), &confirmable.encode().unwrap(), at(0), &mut random);
    server.receive(client_address(), &non.encode().unwrap(), at(0), &mut random);
    let exchanges = requests(&mut server);
    assert_eq!(exchanges.len(), 2);
    server.ignore(exchanges[0]).unwrap();
    let acks = sent(&mut server);
    assert_eq!(acks.len(), 1);
    assert_eq!((acks[0].kind, acks[0].code, acks[0].id), (CoAPType::Acknowledgement, CoAPCode::EMPTY, 1));
    // §4.5: a duplicate gets the same reply.
    server.receive(client_address(), &confirmable.encode().unwrap(), at(1), &mut random);
    assert_eq!(sent(&mut server), acks);
    server.ignore(exchanges[1]).unwrap();
    assert!(sent(&mut server).is_empty());
    let unknown = CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, 0);
    assert!(server.respond(exchanges[0], unknown.clone(), at(2), &mut random).is_err());
    assert!(server.ignore(exchanges[0]).is_err());
    assert!(server.incoming.is_empty());
    // §4.8.2: a client waits for a response at most EXCHANGE_LIFETIME (Confirmable) or NON_LIFETIME
    // (Non-confirmable); a request still unanswered then is forgotten.
    let mut server = CoAPEndpoint::new(config, &mut random).unwrap();
    server.receive(client_address(), &confirmable.encode().unwrap(), at(0), &mut random);
    server.receive(client_address(), &non.encode().unwrap(), at(0), &mut random);
    let exchanges = requests(&mut server);
    let milliseconds = |duration: Duration| duration.as_millis() as u64;
    let (exchange_lifetime, non_lifetime) = (milliseconds(config.exchange_lifetime), milliseconds(config.non_lifetime));
    server.expire(at(non_lifetime - 1));
    assert_eq!(server.incoming.len(), 2);
    server.expire(at(non_lifetime));
    assert_eq!(server.incoming.len(), 1);
    assert!(server.respond(exchanges[1], unknown.clone(), at(non_lifetime), &mut random).is_err());
    assert!(server.poll_timeout().is_some_and(|due| due <= at(exchange_lifetime)));
    server.expire(at(exchange_lifetime));
    assert!(server.incoming.is_empty());
    assert!(server.respond(exchanges[0], unknown, at(exchange_lifetime), &mut random).is_err());
    // No more requests awaiting an answer than configured: past it, a Confirmable request is answered
    // 5.03 Service Unavailable (§5.9.3.4) and a Non-confirmable one is ignored (§4.3 needs no reply).
    let config = CoAPConfig { maximum_incoming: 2, ..CoAPConfig::default() };
    let mut server = CoAPEndpoint::new(config, &mut random).unwrap();
    for id in 10..13u16 {
        let mut request = get("/a", CoAPType::NonConfirmable);
        request.id = id;
        request.token = vec![id as u8];
        server.receive(client_address(), &request.encode().unwrap(), at(0), &mut random);
    }
    assert_eq!((requests(&mut server).len(), server.incoming.len()), (2, 2));
    assert!(sent(&mut server).is_empty());
    let mut request = get("/a", CoAPType::Confirmable);
    request.id = 20;
    request.token = vec![20];
    server.receive(client_address(), &request.encode().unwrap(), at(0), &mut random);
    assert!(requests(&mut server).is_empty());
    let refusal = sent(&mut server);
    assert_eq!(refusal.len(), 1);
    assert_eq!(
        (refusal[0].kind, refusal[0].code, refusal[0].id, refusal[0].token.as_slice()),
        (CoAPType::Acknowledgement, CoAPCode::SERVICE_UNAVAILABLE, 20, &[20u8][..])
    );
    assert_eq!(server.incoming.len(), 2);
}
