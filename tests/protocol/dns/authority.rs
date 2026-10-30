//! The authoritative server: the responses of RFC 4035 Appendix B and RFC
//! 5155 Appendix B from the zones of their Appendix A, and the rules of RFC
//! 1034 §4.3.2, RFC 4592, RFC 6672, RFC 6891, RFC 7873, RFC 9018, RFC 9471,
//! RFC 5936, RFC 7830 and RFC 9824.

use umilib::protocol::dns::{
    DNSAuthority, DNSAuthorityConfig, DNSClass, DNSCookie, DNSData, DNSDescent, DNSEDNS, DNSExtendedError, DNSMessage,
    DNSOpcode, DNSOptionCode, DNSPeer, DNSQuestion, DNSRecord, DNSResponseCode, DNSToken, DNSTransport, DNSType,
    DNSZone,
};
use umilib::protocol::ip::{IPEndpoint, IPEndpointPattern};

use super::{Response, example_zone, name, rfc, zone};

fn peer(transport: DNSTransport) -> DNSPeer {
    DNSPeer { endpoint: IPEndpoint::from_ascii(b"198.51.100.100:5353").unwrap(), transport }
}

fn query(name_text: &str, kind: DNSType, dnssec: bool) -> DNSMessage {
    let mut query = DNSMessage::query(7, DNSQuestion::new(name(name_text), kind));
    query.edns = Some(DNSEDNS { dnssec_ok: dnssec, ..DNSEDNS::default() });
    query
}

/// The records as text, sorted: sections compared without their order.
fn sorted(records: &[DNSRecord]) -> Vec<String> {
    let mut lines: Vec<String> = records.iter().map(ToString::to_string).collect();
    lines.sort();
    lines
}

/// Checks that a server of the zone answers each example as it is.
fn check_examples(path: &str, first: &str, headings: &[&str]) {
    let zone = DNSZone::new(name("example."), example_zone(path, first)).unwrap();
    let authority =
        DNSAuthority::new(vec![zone], DNSAuthorityConfig { minimal: false, ..DNSAuthorityConfig::default() });
    let lines: Vec<String> = rfc(path)
        .into_iter()
        // RFC 5155 B.6 has an RRSIG without the "(" that its ")" closes.
        .map(|line| if line.ends_with("RRSIG NSEC3 7 2 3600") { format!("{line} (") } else { line })
        .collect();
    for heading in headings {
        let example = Response::parse(&lines, heading);
        let mut query = DNSMessage::query(7, example.question.clone());
        query.edns = Some(DNSEDNS { dnssec_ok: true, ..DNSEDNS::default() });
        let response = authority.answer(&query, &peer(DNSTransport::TCP), 0).remove(0).message;
        assert_eq!(response.rcode().0, example.rcode, "{path} {heading}");
        assert_eq!(response.header.authoritative, example.authoritative, "{path} {heading}");
        assert_eq!(sorted(&response.answers), sorted(&example.answers), "{path} {heading} answers");
        assert_eq!(sorted(&response.authorities), sorted(&example.authorities), "{path} {heading} authorities");
        // The examples differ in whether the addresses of the apex's NS
        // are added: those may be, beyond what the example has.
        let extra: Vec<&DNSRecord> =
            response.additionals.iter().filter(|record| !example.additionals.contains(record)).collect();
        assert!(
            example.additionals.iter().all(|record| response.additionals.contains(record)),
            "{path} {heading} additionals"
        );
        for record in extra {
            assert!(
                ["ns1.example.", "ns2.example."].contains(&record.name.to_string().as_str()),
                "{path} {heading}: {record}"
            );
        }
        assert!(response.edns.as_ref().unwrap().dnssec_ok);
    }
}

#[test]
fn the_responses_of_rfc_4035() {
    let headings = ["B.1.  ", "B.2.  ", "B.3.  ", "B.4.  ", "B.5.  ", "B.6.  ", "B.7.  ", "B.8.  "];
    check_examples("protocol/dns/rfc4035.txt", "example.       3600 IN SOA", &headings);
}

#[test]
fn the_responses_of_rfc_5155() {
    let headings = ["B.1.  ", "B.2.  ", "B.2.1.  ", "B.3.  ", "B.4.  ", "B.5.  ", "B.6.  "];
    check_examples("protocol/dns/rfc5155.txt", "example. 3600  IN SOA", &headings);
}

/// A zone of the rules below.
fn rules_zone() -> DNSZone {
    // The lines without their indentation, which would be blank owners.
    let text = "example. 3600 IN SOA ns.example. admin.example. 1 3600 600 86400 300
         example. 3600 IN NS ns.example.
         ns.example. 3600 IN A 192.0.2.53
         www.example. 3600 IN CNAME web.example.
         web.example. 3600 IN A 192.0.2.80
         out.example. 3600 IN CNAME www.example.net.
         loop1.example. 3600 IN CNAME loop2.example.
         loop2.example. 3600 IN CNAME loop1.example.
         old.example. 3600 IN DNAME new.example.
         new.example. 3600 IN TXT \"new\"
         a.new.example. 3600 IN A 192.0.2.1
         *.wild.example. 3600 IN TXT \"wild\"
         *.wild.example. 3600 IN MX 10 web.example.
         sub.wild.example. 3600 IN TXT \"sub\"
         x.y.z.example. 3600 IN A 192.0.2.2
         child.example. 3600 IN NS ns.child.example.
         child.example. 3600 IN NS ns.example.
         child.example. 3600 IN NS ns.example.net.
         ns.child.example. 3600 IN A 192.0.2.54
         ns.child.example. 3600 IN AAAA 2001:db8::54
         deep.child.example. 3600 IN A 192.0.2.99";
    let records = zone(&text.lines().map(str::trim).collect::<Vec<_>>().join("\n"));
    DNSZone::new(name("example."), records).unwrap()
}

fn lookup(zone: &DNSZone, text: &str, kind: DNSType) -> umilib::protocol::dns::DNSLookup {
    zone.lookup(&name(text), kind, false, true, 16)
}

#[test]
fn the_lookups_of_rfc_1034() {
    let zone = rules_zone();
    // §4.3.2: an answer; NODATA and NXDOMAIN with the SOA of TTL min(TTL, MINIMUM) (RFC 2308 §3).
    let result = lookup(&zone, "web.example.", DNSType::A);
    assert_eq!((result.rcode, result.authoritative, result.answers.len()), (DNSResponseCode::NOERROR, true, 1));
    let result = lookup(&zone, "web.example.", DNSType::AAAA);
    assert_eq!((result.rcode, result.answers.len()), (DNSResponseCode::NOERROR, 0));
    assert_eq!((result.authorities[0].kind, result.authorities[0].ttl), (DNSType::SOA, 300));
    let result = lookup(&zone, "nothing.example.", DNSType::A);
    assert_eq!(result.rcode, DNSResponseCode::NXDOMAIN);
    // An empty non-terminal exists (RFC 4592 §2.2.2, RFC 8020).
    for ent in ["y.z.example.", "z.example."] {
        assert_eq!(lookup(&zone, ent, DNSType::A).rcode, DNSResponseCode::NOERROR, "{ent}");
    }
    // A CNAME is followed in the zone, and ends at a name outside it.
    let result = lookup(&zone, "www.example.", DNSType::A);
    let kinds: Vec<DNSType> = result.answers.iter().map(|record| record.kind).collect();
    assert_eq!(kinds, [DNSType::CNAME, DNSType::A]);
    assert_eq!(lookup(&zone, "www.example.", DNSType::CNAME).answers.len(), 1);
    assert_eq!(lookup(&zone, "out.example.", DNSType::A).answers.len(), 1);
    // A loop ends at the limit.
    assert!(zone.lookup(&name("loop1.example."), DNSType::A, false, true, 4).answers.len() <= 5);
    // RFC 6604 §2.1: NXDOMAIN after a CNAME is of the last name.
    let records = zone_with("dangling.example. 3600 IN CNAME missing.example.");
    let result = records.lookup(&name("dangling.example."), DNSType::A, false, true, 16);
    assert_eq!((result.rcode, result.answers.len()), (DNSResponseCode::NXDOMAIN, 1));
    // A referral (§4.3.2 step 3b): not authoritative, the NS, in-domain glue first (RFC 9471 §2.1), then sibling glue.
    for below in ["child.example.", "deep.child.example.", "a.b.child.example."] {
        let result = lookup(&zone, below, DNSType::A);
        assert_eq!((result.rcode, result.authoritative), (DNSResponseCode::NOERROR, false), "{below}");
        assert!(result.answers.is_empty());
        assert_eq!(result.authorities.len(), 3);
        assert_eq!(result.glue, 2);
        let glue: Vec<String> = result.additionals.iter().map(|record| record.name.to_string()).collect();
        assert_eq!(glue, ["ns.child.example.", "ns.child.example.", "ns.example."]);
    }
    // But a DS at a cut is the parent's (RFC 4035 §3.1.4.1).
    let result = lookup(&zone, "child.example.", DNSType::DS);
    assert_eq!((result.authoritative, result.authorities[0].kind), (true, DNSType::SOA));
    assert_eq!(zone.descend(&name("child.example."), DNSType::DS), DNSDescent::Authoritative);
    assert_eq!(zone.descend(&name("child.example."), DNSType::NS), DNSDescent::Cut(name("child.example.")));
}

/// The rules zone with `text` added.
fn zone_with(text: &str) -> DNSZone {
    let mut records: Vec<DNSRecord> = rules_zone().records().cloned().collect();
    records.extend(zone(text));
    DNSZone::new(name("example."), records).unwrap()
}

#[test]
fn wildcards_of_rfc_4592_and_dname_of_rfc_6672() {
    let zone = rules_zone();
    // RFC 4592 §3.3.3: a wildcard answers names below its closest encloser that do not exist.
    for below in ["a.wild.example.", "a.b.wild.example."] {
        let result = lookup(&zone, below, DNSType::TXT);
        assert_eq!(result.answers.len(), 1, "{below}");
        assert_eq!(result.answers[0].name, name(below));
        assert_eq!(result.answers[0].data, DNSData::TXT(vec![b"wild".to_vec()]));
    }
    // Not a name that exists, nor a name below it (§2.2.1: the closest encloser is sub.wild.example.).
    assert_eq!(lookup(&zone, "sub.wild.example.", DNSType::TXT).answers[0].data, DNSData::TXT(vec![b"sub".to_vec()]));
    assert_eq!(lookup(&zone, "a.sub.wild.example.", DNSType::TXT).rcode, DNSResponseCode::NXDOMAIN);
    assert_eq!(lookup(&zone, "sub.wild.example.", DNSType::MX).answers.len(), 0);
    // A wildcard without the type is NODATA; ANY gives all its RRsets.
    let result = lookup(&zone, "a.wild.example.", DNSType::A);
    assert_eq!((result.rcode, result.answers.len()), (DNSResponseCode::NOERROR, 0));
    assert_eq!(lookup(&zone, "a.wild.example.", DNSType::ANY).answers.len(), 2);
    // The wildcard itself answers as itself.
    assert_eq!(lookup(&zone, "*.wild.example.", DNSType::TXT).answers[0].name, name("*.wild.example."));
    // RFC 6672 §3.2: a DNAME, the CNAME it synthesizes of its TTL, then the target's answer.
    let result = lookup(&zone, "a.old.example.", DNSType::A);
    let kinds: Vec<DNSType> = result.answers.iter().map(|record| record.kind).collect();
    assert_eq!(kinds, [DNSType::DNAME, DNSType::CNAME, DNSType::A]);
    assert_eq!(result.answers[1].data, DNSData::CNAME(name("a.new.example.")));
    assert_eq!((result.answers[1].name.clone(), result.answers[1].ttl), (name("a.old.example."), 3600));
    // The DNAME's owner itself is not redirected.
    assert_eq!(lookup(&zone, "old.example.", DNSType::DNAME).answers.len(), 1);
    assert_eq!(lookup(&zone, "old.example.", DNSType::TXT).rcode, DNSResponseCode::NOERROR);
    // §2.2: a substituted name too long is YXDOMAIN: of 247 bytes below a
    // DNAME whose target is 36 bytes longer than its owner.
    let target = "e".repeat(40);
    let zone = zone_with(&format!("far.example. 3600 IN DNAME {target}.example."));
    let prefix = format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(40));
    let long = name(&format!("{prefix}.far.example."));
    assert_eq!(long.wire().len(), 246);
    assert_eq!(zone.lookup(&long, DNSType::A, false, true, 16).rcode, DNSResponseCode::YXDOMAIN);
    let short = name(&format!("{}.far.example.", "a".repeat(63)));
    assert_eq!(zone.lookup(&short, DNSType::A, false, true, 16).rcode, DNSResponseCode::NXDOMAIN);
}

#[test]
fn zones_that_are_not_valid() {
    let soa = "example. 3600 IN SOA ns.example. admin.example. 1 3600 600 86400 300\n";
    for text in [
        "",
        "example. 3600 IN NS ns.example.",
        &format!("{soa}{}", soa.replace(" 1 3600", " 2 3600")),
        &format!("{soa}other. 3600 IN A 192.0.2.1"),
        &format!("{soa}www.example. 3600 IN CNAME a.example.\nwww.example. 3600 IN A 192.0.2.1"),
        &format!("{soa}www.example. 3600 IN CNAME a.example.\nwww.example. 3600 IN CNAME b.example."),
        &format!("{soa}www.example. 3600 CH TXT \"other class\""),
    ] {
        assert!(DNSZone::new(name("example."), zone(text)).is_err(), "{text}");
    }
    // Duplicates are one record (RFC 2181 §5).
    let zone = DNSZone::new(
        name("example."),
        zone(&format!("{soa}{soa}www.example. 60 IN A 192.0.2.1\nwww.example. 60 IN A 192.0.2.1")),
    )
    .unwrap();
    assert_eq!(zone.records().count(), 2);
}

fn authority(config: DNSAuthorityConfig) -> DNSAuthority {
    DNSAuthority::new(vec![rules_zone()], config)
}

#[test]
fn the_checks_of_a_query() {
    let server = authority(DNSAuthorityConfig::default());
    let tcp = peer(DNSTransport::TCP);
    let rcode = |query: &DNSMessage| server.answer(query, &tcp, 0)[0].message.rcode();
    // RFC 1035 §4.1.1: a response is not answered.
    let mut response = query("web.example.", DNSType::A, false);
    response.header.response = true;
    assert!(server.answer(&response, &tcp, 0).is_empty());
    assert!(server.respond(&response.encode(512).unwrap(), &tcp, 0).is_empty());
    // An opcode not implemented; a query of two questions (RFC 9619 §4).
    let mut notify = query("web.example.", DNSType::A, false);
    notify.header.opcode = DNSOpcode::NOTIFY;
    assert_eq!(rcode(&notify), DNSResponseCode::NOTIMP);
    let mut two = query("web.example.", DNSType::A, false);
    two.questions.push(DNSQuestion::new(name("ns.example."), DNSType::A));
    assert_eq!(rcode(&two), DNSResponseCode::FORMERR);
    // Bytes that are not a message, but have a header: FORMERR of that ID.
    let mut bytes = query("web.example.", DNSType::A, false).encode(512).unwrap();
    bytes.truncate(15);
    let responses = server.respond(&bytes, &tcp, 0);
    let decoded = DNSMessage::decode(&responses[0]).unwrap();
    assert_eq!((decoded.header.id, decoded.rcode()), (7, DNSResponseCode::FORMERR));
    assert!(server.respond(&bytes[..5], &tcp, 0).is_empty());
    // RFC 6891 §6.1.3: an EDNS version above 0 is BADVERS, in version 0.
    let mut version = query("web.example.", DNSType::A, false);
    version.edns.as_mut().unwrap().version = 1;
    let response = &server.answer(&version, &tcp, 0)[0].message;
    assert_eq!((response.rcode(), response.edns.as_ref().unwrap().version), (DNSResponseCode::BADVERS, 0));
    // RFC 9824 §3.5: NXNAME, as other meta-types, is FORMERR with Invalid Query Type.
    for kind in [DNSType::NXNAME, DNSType::OPT, DNSType(200)] {
        let response = &server.answer(&query("web.example.", kind, false), &tcp, 0)[0].message;
        assert_eq!(response.rcode(), DNSResponseCode::FORMERR);
        let errors = response.edns.as_ref().unwrap().extended_errors();
        assert_eq!(errors[0].info_code, DNSExtendedError::INVALID_QUERY_TYPE);
    }
    // A name of no zone is refused; a class of another zone too.
    assert_eq!(rcode(&query("example.net.", DNSType::A, false)), DNSResponseCode::REFUSED);
    let mut chaos = query("web.example.", DNSType::A, false);
    chaos.questions[0].class = DNSClass::CH;
    assert_eq!(rcode(&chaos), DNSResponseCode::REFUSED);
    // The header: the ID, RD and CD of the query, QR and AA set, RA clear (RFC 1035 §4.1.1, RFC 4035 §3.1.6).
    let mut flags = query("web.example.", DNSType::A, false);
    flags.header.checking_disabled = true;
    let response = &server.answer(&flags, &tcp, 0)[0].message;
    let header = response.header;
    assert!(header.response && header.authoritative && header.recursion_desired && header.checking_disabled);
    assert!(!header.recursion_available && !header.authentic_data);
    assert_eq!((header.id, response.questions.clone()), (7, flags.questions.clone()));
    // EDNS in the response only if in the query (RFC 6891 §7), of the server's size.
    assert_eq!(response.edns.as_ref().unwrap().udp_size, DNSEDNS::DEFAULT_UDP_SIZE);
    let mut plain = query("web.example.", DNSType::A, false);
    plain.edns = None;
    assert!(server.answer(&plain, &tcp, 0)[0].message.edns.is_none());
}

#[test]
fn truncation_and_glue_of_rfc_9471() {
    let mut records: Vec<DNSRecord> = rules_zone().records().cloned().collect();
    for index in 0..40 {
        records.push(DNSRecord::new(name("big.example."), 60, DNSData::TXT(vec![vec![b'x'; 50], vec![index]])));
        records.push(DNSRecord::new(name("ns.child.example."), 60, DNSData::A([192, 0, 2, index].into())));
    }
    let server =
        DNSAuthority::new(vec![DNSZone::new(name("example."), records).unwrap()], DNSAuthorityConfig::default());
    let udp = peer(DNSTransport::UDP);
    let decode = |bytes: &[u8]| DNSMessage::decode(bytes).unwrap();
    // Over UDP without EDNS, 512 bytes; with EDNS, its size up to the server's.
    let mut plain = query("big.example.", DNSType::TXT, false);
    plain.edns = None;
    let bytes = server.respond(&plain.encode(512).unwrap(), &udp, 0).remove(0);
    assert!(bytes.len() <= 512 && decode(&bytes).header.truncated);
    // The RRset does not fit whole, so none of it is sent (RFC 2181 §9).
    let edns = query("big.example.", DNSType::TXT, false);
    let bytes = server.respond(&edns.encode(512).unwrap(), &udp, 0).remove(0);
    assert!(decode(&bytes).header.truncated && decode(&bytes).answers.is_empty());
    let small = query("web.example.", DNSType::A, false);
    assert!(!decode(&server.respond(&small.encode(512).unwrap(), &udp, 0).remove(0)).header.truncated);
    let bytes = server.respond(&edns.encode(512).unwrap(), &peer(DNSTransport::TCP), 0).remove(0);
    assert!(!decode(&bytes).header.truncated && decode(&bytes).answers.len() == 40);
    // A referral whose in-domain glue does not fit is truncated (RFC 9471 §3).
    let mut referral = query("www.child.example.", DNSType::A, false);
    referral.edns = None;
    let bytes = server.respond(&referral.encode(512).unwrap(), &udp, 0).remove(0);
    let response = decode(&bytes);
    assert!(response.header.truncated && response.additionals.len() < 42, "{}", response.additionals.len());
}

#[test]
fn cookies_of_rfc_7873_and_rfc_9018() {
    let hex = |text: &str| DNSToken::hex(text.as_bytes()).unwrap();
    let secret = |text: &str| -> [u8; 16] { hex(text).try_into().unwrap() };
    let respond = |secrets: Vec<[u8; 16]>, address: &str, cookie: &str, now: u32| -> Vec<u8> {
        let server = authority(DNSAuthorityConfig { cookie_secrets: secrets, ..DNSAuthorityConfig::default() });
        let mut query = query("web.example.", DNSType::A, false);
        let data = hex(cookie);
        query.edns.as_mut().unwrap().set_option(umilib::protocol::dns::DNSOption { code: DNSOptionCode::COOKIE, data });
        let peer =
            DNSPeer { endpoint: IPEndpoint::from_ascii(address.as_bytes()).unwrap(), transport: DNSTransport::UDP };
        let response = &server.answer(&query, &peer, now)[0].message;
        response.edns.as_ref().unwrap().option(DNSOptionCode::COOKIE).unwrap().to_vec()
    };
    // Appendix A.1: a client cookie alone gets a server cookie.
    let first = secret("e5e973e5a6b2a43f48e7dc849e37bfcf");
    assert_eq!(
        respond(vec![first], "198.51.100.100:53", "2464c4abcf10c957", 1559731985),
        hex("2464c4abcf10c957010000005cf79f111f8130c3eee29480")
    );
    // A.2: 40 minutes later, a new one.
    let cookie = "2464c4abcf10c957010000005cf79f111f8130c3eee29480";
    assert_eq!(
        respond(vec![first], "198.51.100.100:53", cookie, 1559734385),
        hex("2464c4abcf10c957010000005cf7a871d4a564a1442aca77")
    );
    // Earlier than half an hour, the same one.
    assert_eq!(respond(vec![first], "198.51.100.100:53", cookie, 1559731985 + 600), hex(cookie));
    // A.3: another client, whose cookie has reserved bytes set.
    let other = "fc93fc62807ddb8601abcdef5cf78f71a314227b6679ebf5";
    assert_eq!(
        respond(vec![first], "203.0.113.203:53", other, 1559734700),
        hex("fc93fc62807ddb86010000005cf7a9acf73a7810aca2381e")
    );
    // A.4: IPv6, a cookie of the previous secret is renewed with the current one.
    let previous = secret("dd3bdf9344b678b185a6f5cb60fca715");
    let current = secret("445536bcd2513298075a5d379663c962");
    let cookie = "22681ab97d52c298010000005cf7c57926556bd0934c72f8";
    let address = "[2001:db8:220:1:59de:d0f4:8769:82b8]:53";
    assert_eq!(
        respond(vec![current, previous], address, cookie, 1559741961),
        hex("22681ab97d52c298010000005cf7c609a6bb79d16625507a")
    );
    // The checks of a server cookie: its secret, client, address, version and time (RFC 9018 §4.3, §4.4).
    let parsed = DNSCookie::decode(&hex("2464c4abcf10c957010000005cf79f111f8130c3eee29480")).unwrap();
    let address = IPEndpoint::from_ascii(b"198.51.100.100:53").unwrap().address;
    assert_eq!(parsed.check_server(&[first], &address, 1559731985), Some((1559731985, 0)));
    assert_eq!(parsed.check_server(&[previous, first], &address, 1559731985 + 3600), Some((1559731985, 1)));
    assert_eq!(parsed.check_server(&[first], &address, 1559731985 + 3601), None);
    assert_eq!(parsed.check_server(&[first], &address, 1559731985 - 300), Some((1559731985, 0)));
    assert_eq!(parsed.check_server(&[first], &address, 1559731985 - 301), None);
    assert_eq!(parsed.check_server(&[previous], &address, 1559731985), None);
    let elsewhere = IPEndpoint::from_ascii(b"198.51.100.101:53").unwrap().address;
    assert_eq!(parsed.check_server(&[first], &elsewhere, 1559731985), None);
    // RFC 7873 §5.2.2: a cookie of a wrong length is FORMERR; without secrets, cookies are ignored.
    let server = authority(DNSAuthorityConfig { cookie_secrets: vec![first], ..DNSAuthorityConfig::default() });
    let mut bad = query("web.example.", DNSType::A, false);
    bad.edns
        .as_mut()
        .unwrap()
        .set_option(umilib::protocol::dns::DNSOption { code: DNSOptionCode::COOKIE, data: vec![1; 9] });
    assert_eq!(server.answer(&bad, &peer(DNSTransport::UDP), 0)[0].message.rcode(), DNSResponseCode::FORMERR);
    let plain = authority(DNSAuthorityConfig::default());
    let response = &plain.answer(&bad, &peer(DNSTransport::UDP), 0)[0].message;
    assert!(response.edns.as_ref().unwrap().option(DNSOptionCode::COOKIE).is_none());
    assert_eq!(response.rcode(), DNSResponseCode::NOERROR);
    // RFC 7873 §5.4: no question but a cookie: the server cookie, NOERROR; BADCOOKIE for an
    // invalid server cookie sent; without cookies, a query without question is FORMERR.
    let ask = |server: &DNSAuthority, cookie: &str| {
        let mut edns = DNSEDNS::default();
        edns.set_option(umilib::protocol::dns::DNSOption { code: DNSOptionCode::COOKIE, data: hex(cookie) });
        let message = DNSMessage { edns: Some(edns), ..DNSMessage::default() };
        let peer =
            DNSPeer { endpoint: IPEndpoint::from_ascii(b"198.51.100.100:53").unwrap(), transport: DNSTransport::UDP };
        server.answer(&message, &peer, 1559731985)[0].message.clone()
    };
    let response = ask(&server, "2464c4abcf10c957");
    assert_eq!(response.rcode(), DNSResponseCode::NOERROR);
    assert!(response.answers.is_empty());
    assert_eq!(
        response.edns.as_ref().unwrap().option(DNSOptionCode::COOKIE).unwrap(),
        hex("2464c4abcf10c957010000005cf79f111f8130c3eee29480")
    );
    assert_eq!(ask(&server, "2464c4abcf10c957010000005cf79f111f8130c3eee29480").rcode(), DNSResponseCode::NOERROR);
    assert_eq!(ask(&server, "2464c4abcf10c957010000005cf79f111f8130c3eee29481").rcode(), DNSResponseCode::BADCOOKIE);
    assert_eq!(ask(&plain, "2464c4abcf10c957").rcode(), DNSResponseCode::FORMERR);
}

#[test]
fn padding_of_rfc_7830_and_rfc_8467() {
    let server = authority(DNSAuthorityConfig::default());
    let mut padded = query("web.example.", DNSType::A, false);
    padded
        .edns
        .as_mut()
        .unwrap()
        .set_option(umilib::protocol::dns::DNSOption { code: DNSOptionCode::PADDING, data: vec![] });
    let bytes = padded.encode(512).unwrap();
    // Over an encrypted transport, a response padded to a multiple of 468 bytes (RFC 8467 §4.1).
    let response = server.respond(&bytes, &peer(DNSTransport::TLS), 0).remove(0);
    assert_eq!(response.len() % 468, 0);
    let decoded = DNSMessage::decode(&response).unwrap();
    assert!(decoded.edns.unwrap().option(DNSOptionCode::PADDING).unwrap().iter().all(|byte| *byte == 0));
    // Not over an unencrypted transport, nor without the option (RFC 7830 §4).
    assert_ne!(server.respond(&bytes, &peer(DNSTransport::TCP), 0)[0].len() % 468, 0);
    let plain = query("web.example.", DNSType::A, false).encode(512).unwrap();
    assert_ne!(server.respond(&plain, &peer(DNSTransport::TLS), 0)[0].len() % 468, 0);
}

#[test]
fn zone_transfers_of_rfc_5936() {
    let allowed = IPEndpointPattern::ANY.with_prefix(IPEndpoint::from_ascii(b"198.51.100.0:0").unwrap().address, 24);
    let server =
        authority(DNSAuthorityConfig { transfers: vec![allowed], transfer_size: 512, ..DNSAuthorityConfig::default() });
    let tcp = peer(DNSTransport::TCP);
    let responses = server.answer(&query("example.", DNSType::AXFR, false), &tcp, 0);
    assert!(responses.len() > 1);
    let records: Vec<DNSRecord> = responses.iter().flat_map(|response| response.message.answers.clone()).collect();
    // §2.2: the SOA first and last, every record once between.
    assert_eq!((records.first().unwrap().kind, records.last().unwrap().kind), (DNSType::SOA, DNSType::SOA));
    assert_eq!(records.len(), rules_zone().records().count() + 1);
    for response in &responses {
        assert!(response.message.header.authoritative && response.message.rcode() == DNSResponseCode::NOERROR);
        assert!(response.encode(512, 0).unwrap().len() <= 512);
    }
    // Refused to others; NOTAUTH for a name that is not a zone's origin; FORMERR over UDP (§4.2).
    let elsewhere =
        DNSPeer { endpoint: IPEndpoint::from_ascii(b"203.0.113.1:53").unwrap(), transport: DNSTransport::TCP };
    assert_eq!(
        server.answer(&query("example.", DNSType::AXFR, false), &elsewhere, 0)[0].message.rcode(),
        DNSResponseCode::REFUSED
    );
    assert_eq!(
        authority(DNSAuthorityConfig::default()).answer(&query("example.", DNSType::AXFR, false), &tcp, 0)[0]
            .message
            .rcode(),
        DNSResponseCode::REFUSED
    );
    assert_eq!(
        server.answer(&query("web.example.", DNSType::AXFR, false), &tcp, 0)[0].message.rcode(),
        DNSResponseCode::NOTAUTH
    );
    assert_eq!(
        server.answer(&query("example.net.", DNSType::AXFR, false), &tcp, 0)[0].message.rcode(),
        DNSResponseCode::NOTAUTH
    );
    let udp = peer(DNSTransport::UDP);
    assert_eq!(
        server.answer(&query("example.", DNSType::AXFR, false), &udp, 0)[0].message.rcode(),
        DNSResponseCode::FORMERR
    );
    // RFC 1995 §4: IXFR over UDP is answered with the SOA alone.
    let response = &server.answer(&query("example.", DNSType::IXFR, false), &udp, 0)[0].message;
    assert_eq!((response.answers.len(), response.answers[0].kind), (1, DNSType::SOA));
}

#[test]
fn the_zones_of_a_server() {
    let parent = rules_zone();
    let child = DNSZone::new(
        name("child.example."),
        zone("child.example. 3600 IN SOA ns.child.example. admin.child.example. 1 3600 600 86400 300\nwww.child.example. 60 IN A 192.0.2.7"),
    )
    .unwrap();
    let server = DNSAuthority::new(vec![parent, child], DNSAuthorityConfig::default());
    // The longest origin answers; a DS is the parent's (RFC 4035 §3.1.4.1).
    assert_eq!(server.zone(&name("www.child.example."), DNSType::A).unwrap().origin, name("child.example."));
    assert_eq!(server.zone(&name("child.example."), DNSType::SOA).unwrap().origin, name("child.example."));
    assert_eq!(server.zone(&name("child.example."), DNSType::DS).unwrap().origin, name("example."));
    assert_eq!(server.zone(&name("example."), DNSType::DS).unwrap().origin, name("example."));
    let tcp = peer(DNSTransport::TCP);
    let response = &server.answer(&query("www.child.example.", DNSType::A, false), &tcp, 0)[0].message;
    assert!(response.header.authoritative && response.answers.len() == 1);
    let _ = DNSToken::time;
}

#[test]
fn sibling_glue_of_rfc_9471() {
    // RFC 9471 §2.3: two delegations whose name servers are below each other's cut; each
    // referral carries the other's addresses, which a resolver cannot find otherwise.
    let text = "test. 3600 IN SOA ns.test. admin.test. 1 3600 600 86400 300
test. 3600 IN NS ns.test.
ns.test. 3600 IN A 192.0.2.1
foo.test. 3600 IN NS ns1.bar.test.
ns1.foo.test. 3600 IN A 192.0.2.10
bar.test. 3600 IN NS ns1.foo.test.
ns1.bar.test. 3600 IN A 192.0.2.20";
    let authority =
        DNSAuthority::new(vec![DNSZone::new(name("test."), zone(text)).unwrap()], DNSAuthorityConfig::default());
    let referral = authority.answer(&query("www.bar.test.", DNSType::A, false), &peer(DNSTransport::UDP), 0).remove(0);
    assert!(referral.message.authorities.iter().any(|record| record.data == DNSData::NS(name("ns1.foo.test."))));
    assert!(referral.message.additionals.iter().any(|record| record.name == name("ns1.foo.test.")));
    let referral = authority.answer(&query("www.foo.test.", DNSType::A, false), &peer(DNSTransport::UDP), 0).remove(0);
    assert!(referral.message.additionals.iter().any(|record| record.name == name("ns1.bar.test.")));
}

#[test]
fn an_nsec3_zone_without_its_chain() {
    // A zone of NSEC3PARAM whose chain is not there yet (or of another salt) is answered,
    // without a proof it cannot make, rather than not at all.
    let text = "example. 3600 IN SOA ns.example. admin.example. 1 3600 600 86400 300
example. 3600 IN NS ns.example.
example. 0 IN NSEC3PARAM 1 0 0 -
ns.example. 3600 IN A 192.0.2.1";
    let authority =
        DNSAuthority::new(vec![DNSZone::new(name("example."), zone(text)).unwrap()], DNSAuthorityConfig::default());
    for (text, kind) in [("example.", DNSType::TXT), ("example.", DNSType::DS), ("none.example.", DNSType::A)] {
        let response = authority.answer(&query(text, kind, true), &peer(DNSTransport::TCP), 0).remove(0);
        assert!(response.message.header.authoritative, "{text} {kind}");
    }
}
