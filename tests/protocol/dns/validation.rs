//! The validating resolver and zone signing, with zones in memory: a
//! signed root, a signed zone below it with a wildcard and an unsigned
//! delegation, and an unsigned zone (RFC 4035 §2, §4.9.3, §5).

use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::SHA256;
use umilib::protocol::dns::dnssec::{
    DNSSECAlgorithm, DNSSECConfig, DNSSECDigest, DNSSECKey, DNSSECKeyDigest, DNSSECPrivateKey, DNSSECResolver,
    DNSSECResolverEvent, DNSSECSigner, DNSSECStatus, DNSSECTrustAnchor, DNSSECValidator,
};
use umilib::protocol::dns::{
    DNSAuthority, DNSAuthorityConfig, DNSData, DNSError, DNSMessage, DNSName, DNSPeer, DNSQuestion, DNSRecord,
    DNSResolverConfig, DNSResponseCode, DNSTransport, DNSType, DNSUpstream, DNSZone,
};
use umilib::protocol::ip::IPEndpoint;
use umilib::runtime::Instant;

use super::{name, zone};

const INCEPTION: u32 = 1_700_000_000;
const EXPIRATION: u32 = 1_700_000_000 + 30 * 86_400;
const TIME: u64 = 1_700_000_000 + 86_400;

fn random(seed: u8) -> HMACDRBG<SHA256> {
    HMACDRBG::<SHA256>::new(&[seed; 32], &[seed; 16], b"umilib validation tests").unwrap()
}

fn signer(origin: &str, flags: u16, seed: u8) -> DNSSECSigner {
    let key = DNSSECPrivateKey::generate(DNSSECAlgorithm::ED25519, 0, &mut random(seed)).unwrap();
    DNSSECSigner::new(name(origin), DNSSECKey::ZONE | flags, key)
}

fn unsigned(origin: &str, text: &str) -> DNSZone {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    DNSZone::new(name(origin), zone(&lines.join("\n"))).unwrap()
}

/// The zones, the root's trust anchor, and the server of them all, which
/// answers as a recursive resolver would.
fn world() -> (DNSAuthority, DNSSECTrustAnchor) {
    let root_ksk = signer(".", DNSSECKey::SECURE_ENTRY_POINT, 1);
    let root_zsk = signer(".", 0, 2);
    let example = signer("example.", DNSSECKey::SECURE_ENTRY_POINT, 3);
    let example_ds = example.delegation(DNSSECDigest::SHA256, 3600).unwrap();
    let root = unsigned(
        ".",
        &format!(
            ". 86400 IN SOA a.root. admin.root. 1 1800 900 604800 86400
            . 86400 IN NS a.root.
            a.root. 86400 IN A 192.0.2.1
            example. 3600 IN NS ns.example.
            {example_ds}
            ns.example. 3600 IN A 192.0.2.2
            insecure. 3600 IN NS ns.insecure.
            ns.insecure. 3600 IN A 192.0.2.3"
        ),
    );
    let root = root.sign(&[root_ksk.clone_key(), root_zsk.clone_key()], INCEPTION, EXPIRATION, &mut random(9)).unwrap();
    let example_zone = unsigned(
        "example.",
        "example. 3600 IN SOA ns.example. admin.example. 1 3600 600 86400 300
        example. 3600 IN NS ns.example.
        ns.example. 3600 IN A 192.0.2.2
        www.example. 300 IN A 192.0.2.80
        alias.example. 300 IN CNAME www.example.
        *.wild.example. 300 IN TXT \"wild\"
        *.cdn.example. 300 IN CNAME a.root.
        sub.example. 3600 IN NS ns.sub.example.
        ns.sub.example. 3600 IN A 192.0.2.4",
    )
    .sign(&[example.clone_key()], INCEPTION, EXPIRATION, &mut random(9))
    .unwrap();
    let insecure = unsigned(
        "insecure.",
        "insecure. 3600 IN SOA ns.insecure. admin.insecure. 1 3600 600 86400 300
        insecure. 3600 IN NS ns.insecure.
        www.insecure. 300 IN A 192.0.2.81
        alias.insecure. 300 IN CNAME www.example.",
    );
    let sub = unsigned(
        "sub.example.",
        "sub.example. 3600 IN SOA ns.sub.example. admin.sub.example. 1 3600 600 86400 300
        sub.example. 3600 IN NS ns.sub.example.
        www.sub.example. 300 IN A 192.0.2.82",
    );
    let DNSData::DS { key_tag, algorithm, digest_type, digest } =
        root_ksk.delegation(DNSSECDigest::SHA256, 0).unwrap().data
    else {
        unreachable!()
    };
    let anchor = DNSSECTrustAnchor {
        zone: DNSName::root(),
        digests: vec![DNSSECKeyDigest {
            id: "test".into(),
            valid_from: 0,
            valid_until: None,
            key_tag,
            algorithm,
            digest_type,
            digest,
            public_key: None,
        }],
    };
    let server = DNSAuthority::new(vec![root, example_zone, insecure, sub], DNSAuthorityConfig::default());
    (server, anchor)
}

trait CloneKey {
    fn clone_key(&self) -> DNSSECSigner;
}

impl CloneKey for DNSSECSigner {
    /// A signer of the same key (a private key is not `Clone`, so that it is not copied by accident).
    fn clone_key(&self) -> DNSSECSigner {
        DNSSECSigner::new(self.zone.clone(), self.flags, DNSSECPrivateKey::parse(&self.key.format()).unwrap())
    }
}

/// Resolves `question` through `server`, its responses changed by `change`.
fn resolve_with(
    server: &DNSAuthority,
    anchor: &DNSSECTrustAnchor,
    question: DNSQuestion,
    time: u64,
    change: &dyn Fn(&DNSQuestion, &mut DNSMessage),
) -> Result<(DNSMessage, DNSSECStatus), DNSError> {
    let mut random = random(7);
    let upstream = DNSUpstream {
        endpoint: IPEndpoint::from_ascii(b"192.0.2.53:53").unwrap(),
        transport: DNSTransport::TCP,
        name: None,
    };
    let config = DNSResolverConfig { upstreams: vec![upstream], ..DNSResolverConfig::default() };
    let mut resolver = DNSSECResolver::new(config, DNSSECConfig::default(), anchor.clone(), &mut random).unwrap();
    let now = Instant::from_nanos(1);
    let query = resolver.resolve(question.clone(), now, time, &mut random).unwrap();
    let peer =
        DNSPeer { endpoint: IPEndpoint::from_ascii(b"198.51.100.1:5000").unwrap(), transport: DNSTransport::TCP };
    let mut rounds = 0;
    while let Some(transmission) = resolver.transmit() {
        rounds += 1;
        assert!(rounds < 100);
        // The queries ask with DO and CD (RFC 4035 §3.2.2, §4.9.2).
        let sent = DNSMessage::decode(&transmission.message).unwrap();
        assert!(sent.edns.as_ref().unwrap().dnssec_ok && sent.header.checking_disabled);
        let mut response = server.answer(&sent, &peer, 0).remove(0).message;
        change(&sent.questions[0], &mut response);
        let bytes = response.encode(65535).unwrap();
        resolver.receive(
            transmission.query,
            transmission.upstream,
            transmission.transport,
            &bytes,
            now,
            time,
            &mut random,
        );
    }
    match resolver.poll_event() {
        Some(DNSSECResolverEvent::Resolved { query: done, question: asked, result }) => {
            assert_eq!((done, asked), (query, question));
            assert!(resolver.poll_event().is_none());
            result
        }
        None => panic!("not resolved"),
    }
}

fn resolve(
    server: &DNSAuthority,
    anchor: &DNSSECTrustAnchor,
    text: &str,
    kind: DNSType,
) -> Result<(DNSMessage, DNSSECStatus), DNSError> {
    resolve_with(server, anchor, DNSQuestion::new(name(text), kind), TIME, &|_, _| {})
}

#[test]
fn a_signed_zone() {
    let (server, _) = world();
    let zone = server.zones.iter().find(|zone| zone.origin == name("example.")).unwrap();
    // RFC 4035 §2.3: the chain of the authoritative names in canonical
    // order (RFC 4034 §6.1), the cut's NSEC with NS (and no DS), none below the cut.
    let chain: Vec<String> = zone
        .records()
        .filter(|record| record.kind == DNSType::NSEC)
        .map(|record| format!("{} {}", record.name, record.data.display(record.kind)))
        .collect();
    assert_eq!(
        chain,
        [
            "example. alias.example. NS SOA RRSIG NSEC DNSKEY",
            "alias.example. *.cdn.example. CNAME RRSIG NSEC",
            "*.cdn.example. ns.example. CNAME RRSIG NSEC",
            "ns.example. sub.example. A RRSIG NSEC",
            "sub.example. *.wild.example. NS RRSIG NSEC",
            "*.wild.example. www.example. TXT RRSIG NSEC",
            "www.example. example. A RRSIG NSEC",
        ]
    );
    // RFC 9077 §3.3: the NSEC TTL is the lesser of the SOA's TTL and minimum.
    assert!(zone.records().filter(|record| record.kind == DNSType::NSEC).all(|record| record.ttl == 300));
    // Every authoritative RRset is signed; the cut's NS and the glue are not.
    let validator = DNSSECValidator::default();
    let keys: Vec<DNSRecord> = zone.rrset(&name("example."), DNSType::DNSKEY).cloned().collect();
    let signatures: Vec<DNSRecord> = zone.records().filter(|record| record.kind == DNSType::RRSIG).cloned().collect();
    for (owner, kind, signed) in [
        ("example.", DNSType::SOA, true),
        ("example.", DNSType::DNSKEY, true),
        ("www.example.", DNSType::A, true),
        ("*.wild.example.", DNSType::TXT, true),
        ("sub.example.", DNSType::NSEC, true),
        ("sub.example.", DNSType::NS, false),
        ("ns.sub.example.", DNSType::A, false),
    ] {
        let set: Vec<DNSRecord> = zone.rrset(&name(owner), kind).cloned().collect();
        assert_eq!(validator.verify(&set, &signatures, &keys, INCEPTION + 1).is_ok(), signed, "{owner} {kind}");
    }
    assert!(!zone.has(&name("ns.sub.example."), DNSType::NSEC));
}

#[test]
fn secure_answers() {
    let (server, anchor) = world();
    // A positive answer, its TTL kept.
    let (response, status) = resolve(&server, &anchor, "www.example.", DNSType::A).unwrap();
    assert_eq!(status, DNSSECStatus::Secure);
    assert!(response.header.authentic_data);
    assert_eq!(
        (response.answers.iter().filter(|record| record.kind == DNSType::A).count(), response.answers[0].ttl),
        (1, 300)
    );
    // A CNAME and its target.
    let (response, status) = resolve(&server, &anchor, "alias.example.", DNSType::A).unwrap();
    assert_eq!(status, DNSSECStatus::Secure);
    assert!(response.answers.iter().any(|record| record.kind == DNSType::CNAME));
    // A name error, no data, a wildcard and its no data.
    for (text, kind, rcode) in [
        ("nothing.example.", DNSType::A, DNSResponseCode::NXDOMAIN),
        ("www.example.", DNSType::TXT, DNSResponseCode::NOERROR),
        ("a.wild.example.", DNSType::TXT, DNSResponseCode::NOERROR),
        ("a.b.wild.example.", DNSType::A, DNSResponseCode::NOERROR),
        ("example.", DNSType::DNSKEY, DNSResponseCode::NOERROR),
        ("nothing.", DNSType::A, DNSResponseCode::NXDOMAIN),
    ] {
        let (response, status) =
            resolve(&server, &anchor, text, kind).unwrap_or_else(|error| panic!("{text} {kind}: {error:?}"));
        assert_eq!((response.rcode(), status), (rcode, DNSSECStatus::Secure), "{text} {kind}");
        assert!(response.header.authentic_data);
    }
}

#[test]
fn insecure_answers() {
    let (server, anchor) = world();
    // RFC 4035 §5.2: below a delegation the parent proves to have no DS.
    for text in ["www.insecure.", "www.sub.example.", "nothing.insecure."] {
        let (response, status) =
            resolve(&server, &anchor, text, DNSType::A).unwrap_or_else(|error| panic!("{text}: {error:?}"));
        assert_eq!(status, DNSSECStatus::Insecure(None), "{text}");
        assert!(!response.header.authentic_data);
    }
    // Below no trust anchor.
    let anchor = DNSSECTrustAnchor { zone: name("other."), ..anchor };
    assert_eq!(resolve(&server, &anchor, "www.example.", DNSType::A).unwrap().1, DNSSECStatus::Insecure(None));
}

#[test]
fn bogus_answers() {
    let (server, anchor) = world();
    let question = |text: &str, kind: DNSType| DNSQuestion::new(name(text), kind);
    let bogus = |result: Result<(DNSMessage, DNSSECStatus), DNSError>| matches!(result, Err(DNSError::Bogus { .. }));
    // A changed record.
    let change = |asked: &DNSQuestion, response: &mut DNSMessage| {
        if asked.kind == DNSType::A {
            for record in &mut response.answers {
                if record.kind == DNSType::A {
                    record.data = DNSData::A([203, 0, 113, 1].into());
                }
            }
        }
    };
    assert!(bogus(resolve_with(&server, &anchor, question("www.example.", DNSType::A), TIME, &change)));
    // Signatures removed from a signed zone.
    let strip = |_: &DNSQuestion, response: &mut DNSMessage| {
        response.answers.retain(|record| record.kind != DNSType::RRSIG || record.name.is_root());
        response.authorities.retain(|record| record.kind != DNSType::RRSIG || record.name.is_root());
    };
    assert!(bogus(resolve_with(&server, &anchor, question("www.example.", DNSType::A), TIME, &strip)));
    assert!(bogus(resolve_with(&server, &anchor, question("nothing.example.", DNSType::A), TIME, &strip)));
    // A denial removed: NXDOMAIN without its NSEC.
    let deny = |asked: &DNSQuestion, response: &mut DNSMessage| {
        if asked.kind == DNSType::A {
            response.authorities.retain(|record| {
                record.kind == DNSType::SOA
                    || matches!(&record.data, DNSData::RRSIG(rrsig) if rrsig.type_covered == DNSType::SOA)
            });
        }
    };
    assert!(bogus(resolve_with(&server, &anchor, question("nothing.example.", DNSType::A), TIME, &deny)));
    // A DS removed from the root's referral: example. would look unsigned, but the root's denial lacks.
    let no_ds = |asked: &DNSQuestion, response: &mut DNSMessage| {
        if asked.kind == DNSType::DS {
            response.answers.clear();
        }
    };
    assert!(bogus(resolve_with(&server, &anchor, question("www.example.", DNSType::A), TIME, &no_ds)));
    // A time after the signatures expire; an anchor of another key.
    assert!(bogus(resolve_with(
        &server,
        &anchor,
        question("www.example.", DNSType::A),
        u64::from(EXPIRATION) + 1,
        &|_, _| {}
    )));
    let mut other = anchor.clone();
    other.digests[0].digest[0] ^= 1;
    assert!(bogus(resolve(&server, &other, "www.example.", DNSType::A)));
}

#[test]
fn errors_of_the_resolver_pass_through() {
    let (server, anchor) = world();
    let refuse = |_: &DNSQuestion, response: &mut DNSMessage| response.set_rcode(DNSResponseCode::REFUSED);
    // A server that refuses: its refusal, not authenticated.
    let (response, status) =
        resolve_with(&server, &anchor, DNSQuestion::new(name("www.example."), DNSType::A), TIME, &refuse).unwrap();
    assert_eq!(
        (response.rcode(), status, response.header.authentic_data),
        (DNSResponseCode::REFUSED, DNSSECStatus::Insecure(None), false)
    );
}

/// `response` to `asked` completed as a recursive resolver would: the
/// CNAME chain it ends in followed through the zones of `server` (RFC 1034 §4.3.2).
fn recursive(server: &DNSAuthority, asked: &DNSQuestion, response: &mut DNSMessage) {
    let peer =
        DNSPeer { endpoint: IPEndpoint::from_ascii(b"198.51.100.1:5000").unwrap(), transport: DNSTransport::TCP };
    for _ in 0..8 {
        let last = DNSSECResolver::chain_end(&response.answers, &asked.name);
        let answered = response.answers.iter().any(|record| record.name == last && record.kind == asked.kind);
        if last == asked.name || answered || asked.kind == DNSType::CNAME {
            return;
        }
        let mut query = DNSMessage::query(1, DNSQuestion::new(last, asked.kind));
        query.edns = Some(umilib::protocol::dns::DNSEDNS { dnssec_ok: true, ..Default::default() });
        let next = server.answer(&query, &peer, 0).remove(0).message;
        response.set_rcode(next.rcode());
        response.answers.extend(next.answers);
        response.authorities.extend(next.authorities);
    }
}

#[test]
fn chains_across_zones() {
    let (server, anchor) = world();
    let through = |asked: &DNSQuestion, response: &mut DNSMessage| recursive(&server, asked, response);
    let ask =
        |text: &str, kind: DNSType| resolve_with(&server, &anchor, DNSQuestion::new(name(text), kind), TIME, &through);
    // RFC 4035 §5.2: an unsigned CNAME of an insecure zone into a signed one is insecure, not bogus,
    // though the question of its DS meets the CNAME too.
    let (response, status) = ask("alias.insecure.", DNSType::A).unwrap();
    assert_eq!(status, DNSSECStatus::Insecure(None));
    assert!(response.answers.iter().any(|record| record.data == DNSData::A([192, 0, 2, 80].into())));
    // A wildcard's CNAME into another signed zone, ending in no data there: secure,
    // each denial by the records its zone signs (RFC 4035 §5.3.4, §5.4).
    let (response, status) = ask("x.cdn.example.", DNSType::AAAA).unwrap();
    assert_eq!((response.rcode(), status), (DNSResponseCode::NOERROR, DNSSECStatus::Secure));
    let (_, status) = ask("x.cdn.example.", DNSType::A).unwrap();
    assert_eq!(status, DNSSECStatus::Secure);
}

#[test]
fn questions_of_cname_and_any() {
    let (server, anchor) = world();
    // RFC 1034 §4.3.2: a CNAME question is answered by the CNAME, not followed.
    let (response, status) = resolve(&server, &anchor, "alias.example.", DNSType::CNAME).unwrap();
    assert_eq!(status, DNSSECStatus::Secure);
    assert!(response.answers.iter().any(|record| record.kind == DNSType::CNAME));
    let (_, status) = resolve(&server, &anchor, "www.example.", DNSType::ANY).unwrap();
    assert_eq!(status, DNSSECStatus::Secure);
}

#[test]
fn rcodes_that_contradict_answers() {
    // RFC 6604 §3: NXDOMAIN is of the last name of the chain; with an answer there it is forged.
    let (server, anchor) = world();
    let forge = |asked: &DNSQuestion, response: &mut DNSMessage| {
        if asked.kind == DNSType::A {
            response.set_rcode(DNSResponseCode::NXDOMAIN);
        }
    };
    let result = resolve_with(&server, &anchor, DNSQuestion::new(name("www.example."), DNSType::A), TIME, &forge);
    assert!(matches!(result, Err(DNSError::Bogus { .. })), "{result:?}");
}

#[test]
fn what_a_secure_answer_carries() {
    let (server, anchor) = world();
    // RFC 4035 §5.3.3: TTLs at most the signatures' original TTL; §3.2.3: AD only of what is
    // validated, so what was added to the authority and additional sections is not kept.
    let add = |asked: &DNSQuestion, response: &mut DNSMessage| {
        if asked.kind == DNSType::A {
            for record in &mut response.answers {
                if record.kind == DNSType::A {
                    record.ttl = 2_000_000_000;
                }
            }
            response.authorities.push(DNSRecord::new(name("example."), 86_400, DNSData::NS(name("evil.attacker."))));
            response.additionals.push(DNSRecord::new(
                name("evil.attacker."),
                86_400,
                DNSData::A([203, 0, 113, 6].into()),
            ));
        }
    };
    let (response, status) =
        resolve_with(&server, &anchor, DNSQuestion::new(name("www.example."), DNSType::A), TIME, &add).unwrap();
    assert_eq!(status, DNSSECStatus::Secure);
    assert!(response.answers.iter().all(|record| record.ttl <= 300));
    assert!(response.authorities.iter().all(|record| record.data != DNSData::NS(name("evil.attacker."))));
    assert!(response.additionals.is_empty());
    // A denial keeps the records that prove it, of their zone.
    let (response, _) = resolve(&server, &anchor, "nothing.example.", DNSType::A).unwrap();
    assert!(response.authorities.iter().any(|record| record.kind == DNSType::NSEC));
    assert!(response.authorities.iter().any(|record| record.kind == DNSType::SOA));
}

#[test]
fn responses_asked_to_validate_expire() {
    // RFC 9520 §3.2: a failure is kept a few seconds; an answer as long as its TTL (RFC 2308 §5).
    let (_, anchor) = world();
    let upstream = DNSUpstream {
        endpoint: IPEndpoint::from_ascii(b"192.0.2.53:53").unwrap(),
        transport: DNSTransport::UDP,
        name: None,
    };
    let config = DNSResolverConfig { upstreams: vec![upstream], ..DNSResolverConfig::default() };
    let failure = config.cache.failure_ttl;
    let mut resolver = DNSSECResolver::new(config, DNSSECConfig::default(), anchor, &mut random(3)).unwrap();
    let now = Instant::from_nanos(1);
    let question = DNSQuestion::new(DNSName::root(), DNSType::DNSKEY);
    resolver.keep(question.clone(), Err(DNSError::Timeout), now);
    assert!(
        resolver
            .fetch(question.clone(), now)
            .is_err_and(|step| !matches!(step, umilib::protocol::dns::dnssec::DNSSECStep::Need(_)))
    );
    let later = now.saturating_add(failure.max(DNSSECResolver::MINIMUM_HOLD));
    assert!(matches!(resolver.fetch(question.clone(), later), Err(umilib::protocol::dns::dnssec::DNSSECStep::Need(_))));
    // No more than the cache keeps.
    resolver.resolver.config.cache.maximum_entries = 2;
    for index in 0..5u8 {
        let name = DNSName::parse(&format!("n{index}."), None).unwrap();
        resolver.keep(DNSQuestion::new(name, DNSType::DS), Err(DNSError::Timeout), now);
    }
    assert_eq!(resolver.responses.len(), 2);
}
