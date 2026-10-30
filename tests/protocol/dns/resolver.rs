//! The stub resolver and its cache, with authoritative servers in memory:
//! the rules of RFC 1034 §5.3.1, RFC 1536, RFC 2308 §5, RFC 5452, RFC
//! 6891 §7, RFC 7766 §5, RFC 7873 §5.3, RFC 8467 and RFC 9520.

use core::time::Duration;

use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::SHA256;
use umilib::protocol::dns::{
    DNSAuthority, DNSAuthorityConfig, DNSCache, DNSCacheConfig, DNSData, DNSError, DNSMessage, DNSOptionCode, DNSPeer,
    DNSQuestion, DNSRecord, DNSResolver, DNSResolverConfig, DNSResolverEvent, DNSResponseCode, DNSTransmission,
    DNSTransport, DNSType, DNSUpstream, DNSZone,
};
use umilib::protocol::ip::IPEndpoint;
use umilib::runtime::Instant;

use super::{name, zone};

fn random() -> HMACDRBG<SHA256> {
    HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"umilib resolver tests").unwrap()
}

fn at(seconds: u64) -> Instant {
    Instant::from_nanos(seconds * 1_000_000_000)
}

fn server() -> DNSAuthority {
    let text = "example. 3600 IN SOA ns.example. admin.example. 1 3600 600 86400 300
www.example. 120 IN A 192.0.2.1
www.example. 120 IN A 192.0.2.2";
    let mut records = zone(text);
    for index in 0..60 {
        records.push(DNSRecord::new(name("big.example."), 60, DNSData::TXT(vec![vec![b'x'; 40], vec![index]])));
    }
    let zone = DNSZone::new(name("example."), records).unwrap();
    DNSAuthority::new(vec![zone], DNSAuthorityConfig { cookie_secrets: vec![[9; 16]], ..DNSAuthorityConfig::default() })
}

fn upstream(port: u16, transport: DNSTransport) -> DNSUpstream {
    DNSUpstream {
        endpoint: IPEndpoint::from_ascii(format!("192.0.2.53:{port}").as_bytes()).unwrap(),
        transport,
        name: None,
    }
}

fn resolver(upstreams: Vec<DNSUpstream>) -> DNSResolver {
    DNSResolver::new(DNSResolverConfig { upstreams, ..DNSResolverConfig::default() }, &mut random()).unwrap()
}

fn question(text: &str, kind: DNSType) -> DNSQuestion {
    DNSQuestion::new(name(text), kind)
}

/// The response of `server` to `transmission`, as a client at 198.51.100.1 sends it.
fn answer(server: &DNSAuthority, transmission: &DNSTransmission) -> Vec<u8> {
    let peer =
        DNSPeer { endpoint: IPEndpoint::from_ascii(b"198.51.100.1:40000").unwrap(), transport: transmission.transport };
    server.respond(&transmission.message, &peer, 1_700_000_000).remove(0)
}

fn resolved(resolver: &mut DNSResolver) -> Result<DNSMessage, DNSError> {
    match resolver.poll_event() {
        Some(DNSResolverEvent::Resolved { result, .. }) => result,
        None => panic!("nothing resolved"),
    }
}

#[test]
fn a_question_answered_and_cached() {
    let server = server();
    let mut random = random();
    let mut resolver = resolver(vec![upstream(53, DNSTransport::UDP)]);
    let query = resolver.resolve(question("www.example.", DNSType::A), at(0), &mut random).unwrap();
    let transmission = resolver.transmit().unwrap();
    assert_eq!((transmission.query, transmission.upstream, transmission.transport), (query, 0, DNSTransport::UDP));
    assert!(resolver.transmit().is_none());
    // The query: RD, EDNS of 1232 bytes (RFC 9715), a client cookie (RFC 7873 §5.1).
    let sent = DNSMessage::decode(&transmission.message).unwrap();
    assert!(sent.header.recursion_desired && !sent.header.response);
    let edns = sent.edns.as_ref().unwrap();
    assert_eq!(edns.udp_size, 1232);
    assert_eq!(edns.option(DNSOptionCode::COOKIE).unwrap().len(), 8);
    resolver.receive(query, 0, DNSTransport::UDP, &answer(&server, &transmission), at(1), &mut random);
    let response = resolved(&mut resolver).unwrap();
    assert_eq!(response.answers.len(), 2);
    assert!(resolver.queries.is_empty() && resolver.poll_timeout().is_none());
    // RFC 1035 §7.4: from the cache, with the TTL less the time kept; then expired.
    resolver.resolve(question("WWW.example.", DNSType::A), at(31), &mut random).unwrap();
    assert!(resolver.transmit().is_none());
    assert!(resolved(&mut resolver).unwrap().answers.iter().all(|record| record.ttl == 90));
    resolver.resolve(question("www.example.", DNSType::A), at(121), &mut random).unwrap();
    assert!(resolver.transmit().is_some());
    // The server's cookie is learned and sent back (RFC 7873 §5.3).
    let cookie = resolver.cookies[0].clone();
    assert_eq!(cookie.server.as_ref().map(Vec::len), Some(16));
}

#[test]
fn responses_that_do_not_match() {
    let server = server();
    let mut random = random();
    let mut resolver = resolver(vec![upstream(53, DNSTransport::UDP), upstream(54, DNSTransport::UDP)]);
    let query = resolver.resolve(question("www.example.", DNSType::A), at(0), &mut random).unwrap();
    let transmission = resolver.transmit().unwrap();
    let bytes = answer(&server, &transmission);
    // RFC 5452 §9.1: another ID, another question, another server or transport, not a response.
    let mut other_id = bytes.clone();
    other_id[0] ^= 1;
    let other_question = answer(
        &server,
        &DNSTransmission {
            message: DNSMessage::query(
                DNSMessage::decode(&transmission.message).unwrap().header.id,
                question("big.example.", DNSType::TXT),
            )
            .encode(512)
            .unwrap(),
            ..transmission.clone()
        },
    );
    for (upstream, transport, bytes) in [
        (0, DNSTransport::UDP, other_id),
        (0, DNSTransport::UDP, other_question),
        (1, DNSTransport::UDP, bytes.clone()),
        (0, DNSTransport::TCP, bytes.clone()),
        (0, DNSTransport::UDP, transmission.message.clone()),
        (0, DNSTransport::UDP, vec![1, 2, 3]),
    ] {
        resolver.receive(query, upstream, transport, &bytes, at(1), &mut random);
        assert!(resolver.poll_event().is_none());
    }
    // A response whose client cookie is not the resolver's (RFC 7873 §5.3).
    let mut forged = DNSMessage::decode(&bytes).unwrap();
    forged
        .edns
        .as_mut()
        .unwrap()
        .set_option(umilib::protocol::dns::DNSOption { code: DNSOptionCode::COOKIE, data: vec![7; 24] });
    resolver.receive(query, 0, DNSTransport::UDP, &forged.encode(4096).unwrap(), at(1), &mut random);
    assert!(resolver.poll_event().is_none());
    resolver.receive(query, 0, DNSTransport::UDP, &bytes, at(1), &mut random);
    assert!(resolved(&mut resolver).is_ok());
    // The server gave its cookie: a response without one is discarded (RFC 7873 §5.3).
    assert!(resolver.cookies[0].server.is_some());
    let query = resolver.resolve(question("www.example.", DNSType::AAAA), at(2), &mut random).unwrap();
    let transmission = resolver.transmit().unwrap();
    let mut stripped = DNSMessage::decode(&answer(&server, &transmission)).unwrap();
    stripped.edns.as_mut().unwrap().options.retain(|option| option.code != DNSOptionCode::COOKIE);
    resolver.receive(query, 0, DNSTransport::UDP, &stripped.encode(4096).unwrap(), at(3), &mut random);
    assert!(resolver.poll_event().is_none());
    resolver.receive(query, 0, DNSTransport::UDP, &answer(&server, &transmission), at(3), &mut random);
    assert!(resolved(&mut resolver).is_ok());
}

#[test]
fn truncation_and_formerr() {
    let server = server();
    let mut random = random();
    let mut resolver = resolver(vec![upstream(53, DNSTransport::UDP)]);
    // RFC 7766 §5: a truncated response over UDP is asked again over TCP.
    let query = resolver.resolve(question("big.example.", DNSType::TXT), at(0), &mut random).unwrap();
    let udp = resolver.transmit().unwrap();
    let truncated = answer(&server, &udp);
    assert!(DNSMessage::decode(&truncated).unwrap().header.truncated);
    resolver.receive(query, 0, DNSTransport::UDP, &truncated, at(1), &mut random);
    let tcp = resolver.transmit().unwrap();
    assert_eq!((tcp.upstream, tcp.transport), (0, DNSTransport::TCP));
    resolver.receive(query, 0, DNSTransport::TCP, &answer(&server, &tcp), at(1), &mut random);
    assert_eq!(resolved(&mut resolver).unwrap().answers.len(), 60);
    // RFC 6891 §7: a FORMERR without OPT to a query with it is asked again without EDNS,
    // from a server that gave no cookie (one that did speaks EDNS, RFC 7873 §5.3).
    let mut resolver = self::resolver(vec![upstream(53, DNSTransport::UDP)]);
    let query = resolver.resolve(question("www.example.", DNSType::AAAA), at(2), &mut random).unwrap();
    let first = resolver.transmit().unwrap();
    let sent = DNSMessage::decode(&first.message).unwrap();
    let mut formerr = DNSMessage::response(&DNSMessage { edns: None, ..sent.clone() }, DNSResponseCode::FORMERR);
    formerr.header.id = sent.header.id;
    resolver.receive(query, 0, DNSTransport::UDP, &formerr.encode(512).unwrap(), at(2), &mut random);
    let second = resolver.transmit().unwrap();
    assert!(DNSMessage::decode(&second.message).unwrap().edns.is_none());
    resolver.receive(query, 0, DNSTransport::UDP, &answer(&server, &second), at(2), &mut random);
    let response = resolved(&mut resolver).unwrap();
    // A no-data answer: cached for min(SOA TTL, MINIMUM) (RFC 2308 §5).
    assert_eq!((response.rcode(), response.answers.len()), (DNSResponseCode::NOERROR, 0));
    let cached = resolver.cache.entries.values().find(|entry| entry.stored == at(2)).unwrap();
    assert_eq!(cached.expires, at(302));
}

#[test]
fn timeouts_failures_and_rounds() {
    let mut random = random();
    let mut resolver = resolver(vec![upstream(53, DNSTransport::UDP), upstream(54, DNSTransport::UDP)]);
    let query = resolver.resolve(question("www.example.", DNSType::A), at(0), &mut random).unwrap();
    // RFC 1536 §1: the next server after the timeout, twice as long in the next round.
    let mut order = Vec::new();
    while let Some(transmission) = resolver.transmit() {
        order.push((transmission.upstream, resolver.poll_timeout().unwrap()));
        let deadline = resolver.poll_timeout().unwrap();
        resolver.expire(deadline, &mut random);
    }
    assert_eq!(order, [(0, at(2)), (1, at(4)), (0, at(8)), (1, at(12))]);
    let Some(DNSResolverEvent::Resolved { query: done, result, .. }) = resolver.poll_event() else { panic!() };
    assert_eq!((done, result), (query, Err(DNSError::Timeout)));
    // RFC 9520 §3: the failure is cached briefly.
    resolver.resolve(question("www.example.", DNSType::A), at(13), &mut random).unwrap();
    assert_eq!(resolved(&mut resolver), Err(DNSError::Timeout));
    resolver.resolve(question("www.example.", DNSType::A), at(18), &mut random).unwrap();
    assert!(resolver.transmit().is_some());
    // A SERVFAIL goes to the next server at once; if all fail, it is the answer.
    let server = server();
    let mut resolver = self::resolver(vec![upstream(53, DNSTransport::UDP), upstream(54, DNSTransport::UDP)]);
    let query = resolver.resolve(question("www.example.", DNSType::A), at(0), &mut random).unwrap();
    let first = resolver.transmit().unwrap();
    let sent = DNSMessage::decode(&first.message).unwrap();
    let servfail = DNSMessage::response(&sent, DNSResponseCode::SERVFAIL).encode(512).unwrap();
    resolver.receive(query, 0, DNSTransport::UDP, &servfail, at(0), &mut random);
    let second = resolver.transmit().unwrap();
    assert_eq!(second.upstream, 1);
    resolver.receive(query, 1, DNSTransport::UDP, &answer(&server, &second), at(0), &mut random);
    assert_eq!(resolved(&mut resolver).unwrap().answers.len(), 2);
    let mut resolver = self::resolver(vec![upstream(53, DNSTransport::UDP)]);
    resolver.config.rounds = 1;
    let query = resolver.resolve(question("www.example.", DNSType::A), at(0), &mut random).unwrap();
    let sent = DNSMessage::decode(&resolver.transmit().unwrap().message).unwrap();
    let refused = DNSMessage::response(&sent, DNSResponseCode::REFUSED).encode(512).unwrap();
    resolver.receive(query, 0, DNSTransport::UDP, &refused, at(0), &mut random);
    assert_eq!(resolved(&mut resolver).unwrap().rcode(), DNSResponseCode::REFUSED);
    // RFC 6891 §6.1.3: BADVERS, a server of no version asked in, goes to the next server too.
    let mut resolver = self::resolver(vec![upstream(53, DNSTransport::UDP), upstream(54, DNSTransport::UDP)]);
    let query = resolver.resolve(question("www.example.", DNSType::A), at(0), &mut random).unwrap();
    let sent = DNSMessage::decode(&resolver.transmit().unwrap().message).unwrap();
    let mut badvers = DNSMessage::response(&sent, DNSResponseCode::NOERROR);
    badvers.set_rcode(DNSResponseCode::BADVERS);
    resolver.receive(query, 0, DNSTransport::UDP, &badvers.encode(512).unwrap(), at(0), &mut random);
    assert!(resolver.poll_event().is_none());
    assert_eq!(resolver.transmit().unwrap().upstream, 1);
}

#[test]
fn bad_cookies_of_rfc_7873() {
    let server = server();
    let mut random = random();
    let mut resolver = resolver(vec![upstream(53, DNSTransport::UDP)]);
    let query = resolver.resolve(question("www.example.", DNSType::A), at(0), &mut random).unwrap();
    let sent = DNSMessage::decode(&resolver.transmit().unwrap().message).unwrap();
    // §5.3: BADCOOKIE with the server's cookie: asked again with it, then over TCP.
    let mut bad = DNSMessage::response(&sent, DNSResponseCode::BADCOOKIE);
    let mut cookie = resolver.cookies[0].clone();
    cookie.server = Some(vec![5; 16]);
    bad.edns.as_mut().unwrap().set_option(cookie.encode());
    resolver.receive(query, 0, DNSTransport::UDP, &bad.encode(512).unwrap(), at(0), &mut random);
    let again = resolver.transmit().unwrap();
    let resent = DNSMessage::decode(&again.message).unwrap();
    assert_eq!(resent.edns.unwrap().option(DNSOptionCode::COOKIE).unwrap().len(), 24);
    let mut bad = DNSMessage::response(&DNSMessage::decode(&again.message).unwrap(), DNSResponseCode::BADCOOKIE);
    bad.edns.as_mut().unwrap().set_option(cookie.encode());
    resolver.receive(query, 0, DNSTransport::UDP, &bad.encode(512).unwrap(), at(0), &mut random);
    let tcp = resolver.transmit().unwrap();
    assert_eq!(tcp.transport, DNSTransport::TCP);
    resolver.receive(query, 0, DNSTransport::TCP, &answer(&server, &tcp), at(0), &mut random);
    assert!(resolved(&mut resolver).is_ok());
}

#[test]
fn encrypted_transports() {
    let mut random = random();
    let mut resolver = resolver(vec![
        upstream(853, DNSTransport::TLS),
        upstream(443, DNSTransport::HTTPS),
        upstream(853, DNSTransport::QUIC),
    ]);
    resolver.resolve(question("www.example.", DNSType::A), at(0), &mut random).unwrap();
    // RFC 8467 §4.1: a query padded to a multiple of 128 bytes; no cookie over TLS.
    let tls = resolver.transmit().unwrap();
    assert_eq!(tls.message.len() % 128, 0);
    let sent = DNSMessage::decode(&tls.message).unwrap();
    let edns = sent.edns.unwrap();
    assert!(edns.option(DNSOptionCode::COOKIE).is_none() && edns.option(DNSOptionCode::PADDING).is_some());
    assert_ne!(sent.header.id, 0);
    // RFC 8484 §4.1 and RFC 9250 §4.2.1: an ID of 0.
    for transport in [DNSTransport::HTTPS, DNSTransport::QUIC] {
        let deadline = resolver.poll_timeout().unwrap();
        resolver.expire(deadline, &mut random);
        let transmission = resolver.transmit().unwrap();
        assert_eq!(transmission.transport, transport);
        assert_eq!(DNSMessage::decode(&transmission.message).unwrap().header.id, 0);
    }
}

#[test]
fn limits_and_cancellation() {
    let mut random = random();
    assert!(DNSResolver::new(DNSResolverConfig::default(), &mut random).is_err());
    let mut resolver = resolver(vec![upstream(53, DNSTransport::UDP)]);
    resolver.config.maximum_queries = 2;
    let first = resolver.resolve(question("a.example.", DNSType::A), at(0), &mut random).unwrap();
    resolver.resolve(question("b.example.", DNSType::A), at(0), &mut random).unwrap();
    assert_eq!(resolver.resolve(question("c.example.", DNSType::A), at(0), &mut random), Err(DNSError::State));
    resolver.cancel(first);
    assert_eq!(resolver.transmissions.len(), 1);
    resolver.resolve(question("c.example.", DNSType::A), at(0), &mut random).unwrap();
    resolver.expire(at(100), &mut random);
    resolver.expire(at(200), &mut random);
    assert!(resolver.poll_event().is_some() && resolver.poll_event().is_some() && resolver.poll_event().is_none());
}

#[test]
fn the_cache_of_rfc_2308() {
    let server = server();
    let peer =
        DNSPeer { endpoint: IPEndpoint::from_ascii(b"198.51.100.1:5300").unwrap(), transport: DNSTransport::TCP };
    let respond = |text: &str, kind: DNSType| {
        let query = DNSMessage::query(1, question(text, kind));
        server.answer(&query, &peer, 0).remove(0).message
    };
    let mut cache = DNSCache::new(DNSCacheConfig { maximum_entries: 2, ..DNSCacheConfig::default() });
    // §5: NXDOMAIN for the SOA's TTL or MINIMUM, whichever is less; capped.
    let nxdomain = respond("none.example.", DNSType::A);
    assert_eq!(cache.lifetime(&nxdomain), Some(Duration::from_secs(300)));
    cache.config.maximum_negative_ttl = Duration::from_secs(60);
    assert_eq!(cache.lifetime(&nxdomain), Some(Duration::from_secs(60)));
    // Without an SOA, a negative answer is not kept.
    let mut bare = nxdomain.clone();
    bare.authorities.clear();
    assert_eq!(cache.lifetime(&bare), None);
    // A positive answer for its least TTL, capped.
    let positive = respond("www.example.", DNSType::A);
    assert_eq!(cache.lifetime(&positive), Some(Duration::from_secs(120)));
    cache.config.maximum_ttl = Duration::from_secs(100);
    assert_eq!(cache.lifetime(&positive), Some(Duration::from_secs(100)));
    // The entries: by question without case; when full, the first to expire goes.
    cache.insert(&question("www.example.", DNSType::A), Ok(positive.clone()), at(0));
    cache.insert(&question("none.example.", DNSType::A), Ok(nxdomain.clone()), at(0));
    cache.insert(&question("WWW.example.", DNSType::A), Ok(positive.clone()), at(1));
    assert_eq!(cache.entries.len(), 2);
    assert!(
        cache.get(&question("none.example.", DNSType::A), at(1)).is_some(),
        "a name of other case replaces its own entry"
    );
    // A record's TTL is at most the time it is still kept (120 s capped to 100 s).
    let kept = cache.get(&question("www.example.", DNSType::A), at(1)).unwrap().unwrap();
    assert!(kept.answers.iter().all(|record| record.ttl <= 100));
    cache.insert(&question("other.example.", DNSType::A), Err(DNSError::Timeout), at(2));
    assert!(cache.get(&question("none.example.", DNSType::A), at(2)).is_none());
    assert_eq!(cache.get(&question("other.example.", DNSType::A), at(6)), Some(Err(DNSError::Timeout)));
    assert_eq!(cache.get(&question("other.example.", DNSType::A), at(7)), None);
    // A failure TTL of zero keeps no failure.
    cache.config.failure_ttl = Duration::ZERO;
    cache.insert(&question("fail.example.", DNSType::A), Err(DNSError::Timeout), at(8));
    assert!(cache.get(&question("fail.example.", DNSType::A), at(8)).is_none());
}
