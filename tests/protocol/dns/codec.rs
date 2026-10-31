//! The codec: names, messages, records and their presentation format.

use umilib::protocol::dns::{
    DNSClass, DNSCookie, DNSData, DNSEDNS, DNSError, DNSExtendedError, DNSMessage, DNSName, DNSOptionCode, DNSQuestion,
    DNSRecord, DNSResponseCode, DNSRule, DNSServiceBinding, DNSServiceKey, DNSToken, DNSType, DNSTypeBitmap,
    DNSZoneFile,
};
use umilib::service::Rule;

use super::{name, rfc, zone};
use crate::Vectors;

#[test]
fn names() {
    // RFC 1035 §2.3.4: labels of at most 63 bytes, names of at most 255.
    let label = "a".repeat(63);
    assert!(DNSName::parse(&format!("{label}.example."), None).is_ok());
    assert!(DNSName::parse(&format!("a{label}.example."), None).is_err());
    let long = format!("{label}.{label}.{label}.{}.", "a".repeat(61));
    assert_eq!(name(&long).wire().len(), 255);
    assert!(DNSName::parse(&format!("a{long}"), None).is_err());
    // §5.1: escapes; RFC 4343: comparison without ASCII case, case kept.
    let escaped = name("a\\.b\\065\\\\c.Example.");
    assert_eq!(escaped.labels().next(), Some(&b"a.bA\\c"[..]));
    assert_eq!(escaped.to_string(), "a\\.bA\\\\c.Example.");
    assert_eq!(name("WWW.example.COM."), name("www.example.com."));
    assert_eq!(name("WWW.example.").to_string(), "WWW.example.");
    assert!(DNSName::parse("a..b.", None).is_err());
    assert!(DNSName::parse("relative", None).is_err());
    assert_eq!(DNSName::parse("www", Some(&name("example."))).unwrap(), name("www.example."));
    // RFC 4034 §6.1: the canonical order of its example.
    let lines = rfc("protocol/dns/rfc4034.txt");
    let start = lines.iter().position(|line| line.trim() == "example").unwrap();
    let names: Vec<DNSName> = lines[start..start + 9].iter().map(|line| name(&format!("{}.", line.trim()))).collect();
    let mut sorted = names.clone();
    sorted.reverse();
    sorted.sort();
    assert_eq!(sorted, names);
    assert!(name("a.b.example.").is_subdomain_of(&name("Example.")));
    assert!(!name("aexample.").is_subdomain_of(&name("example.")));
}

#[test]
fn compression() {
    // RFC 1035 §4.1.4: F.ISI.ARPA, then FOO.F.ISI.ARPA and ARPA as pointers.
    let mut message = DNSMessage::query(1, DNSQuestion::new(name("F.ISI.ARPA."), DNSType::A));
    message.answers.push(DNSRecord::new(name("FOO.F.ISI.ARPA."), 60, DNSData::NS(name("ARPA."))));
    let bytes = message.encode(512).unwrap();
    let question = &bytes[12..];
    assert_eq!(&question[..12], b"\x01F\x03ISI\x04ARPA\x00");
    // The owner: "FOO" and a pointer to offset 12 (F.ISI.ARPA).
    assert_eq!(&question[16..22], b"\x03FOO\xC0\x0C");
    // The NS data: a pointer to ARPA at offset 12 + 6.
    assert_eq!(&bytes[bytes.len() - 2..], [0xC0, 0x12]);
    assert_eq!(DNSMessage::decode(&bytes).unwrap(), message);
    // Pointers only backward: forward, to itself, or a loop is refused.
    let mut looped = bytes.clone();
    let at = 12;
    looped[at..at + 2].copy_from_slice(&[0xC0, 0x0C]);
    assert!(DNSMessage::decode(&looped).is_err());
    assert!(DNSName::decode(&[0x40, 0x00], 0).is_err(), "a reserved label type");
    assert!(DNSName::decode(&[0x01], 0).is_err(), "cut short");
}

#[test]
fn the_generic_format_of_rfc_3597() {
    // §5: `\# length hex` for any type, and the known type of it read as such.
    let records = zone(
        "a.example. CLASS32 TYPE731 \\# 6 abcd ( ef 01 23 45 )\n\
         b.example. HS TYPE62347 \\# 0\n\
         e.example. IN A \\# 4 0A000001\n\
         e.example. CLASS1 TYPE1 10.0.0.2\n",
    );
    assert_eq!(records[0].class, DNSClass(32));
    assert_eq!(records[0].data, DNSData::Unknown(vec![0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]));
    assert_eq!(records[0].to_string(), "a.example. 3600 CLASS32 TYPE731 \\# 6 ABCDEF012345");
    assert_eq!(records[1].data, DNSData::Unknown(Vec::new()));
    assert_eq!(records[2].data, DNSData::A("10.0.0.1".parse().unwrap()));
    assert_eq!(records[3].data, DNSData::A("10.0.0.2".parse().unwrap()));
    // §5: the generic form is the RDATA uncompressed, even of a type whose names are compressed in
    // messages: a SOA whose RNAME points at its MNAME is refused, written whole it is read.
    let pointer = "s.example. SOA \\# 25 016100 C000 0000000100000002000000030000000400000005\n";
    assert!(DNSZoneFile::new(None).parse(pointer).is_err());
    let whole = zone("s.example. SOA \\# 26 016100 016100 0000000100000002000000030000000400000005\n");
    assert!(
        matches!(&whole[0].data, DNSData::SOA(soa) if soa.rname == name("a.") && soa.serial == 1),
        "{:?}",
        whole[0].data
    );
    // §4: names in the data of types after RFC 1035 are never compressed.
    let mut message = DNSMessage::query(1, DNSQuestion::new(name("example."), DNSType::SRV));
    message.answers.push(DNSRecord::new(
        name("example."),
        60,
        DNSData::SRV { priority: 1, weight: 2, port: 3, target: name("example.") },
    ));
    let bytes = message.encode(512).unwrap();
    assert!(bytes.ends_with(b"\x07example\x00"));
}

#[test]
fn the_records_of_rfc_4034() {
    let text = Vectors::read("protocol/dns/rfc4034.txt");
    let between = |start: &str, end: &str| {
        let from = text.find(start).unwrap();
        let to = from + text[from..].find(end).unwrap();
        text[from..to].lines().map(str::trim_start).collect::<Vec<_>>().join("\n")
    };
    // §2.3, §3.3, §4.3, §5.4.
    let dnskey = &zone(&between("   example.com. 86400 IN DNSKEY", "   The first four"))[0];
    let DNSData::DNSKEY { flags, protocol, algorithm, public_key } = &dnskey.data else { panic!() };
    assert_eq!((*flags, *protocol, *algorithm, public_key.len()), (256, 3, 5, 130));
    let rrsig = &zone(&between("   host.example.com. 86400 IN RRSIG", "   The first four"))[0];
    let DNSData::RRSIG(signature) = &rrsig.data else { panic!() };
    assert_eq!(
        (signature.type_covered, signature.algorithm, signature.labels, signature.key_tag),
        (DNSType::A, 5, 3, 2642)
    );
    assert_eq!(signature.signer, name("example.com."));
    // 2003-03-22 17:31:03 UTC.
    assert_eq!(signature.expiration, 1_048_354_263);
    assert_eq!(DNSToken::format_time(signature.inception), "20030220173103");
    let nsec = &zone(&between("   alfa.example.com. 86400 IN NSEC", "   The first four"))[0];
    let mut rdata = Vec::new();
    nsec.data.encode(DNSType::NSEC, &mut rdata, None);
    let wire = between("0x04 'h'", "Assuming");
    let expected: Vec<u8> = wire
        .split_whitespace()
        .map(|item| match item.strip_prefix("0x") {
            Some(hex) => u8::from_str_radix(hex, 16).unwrap(),
            None => item.trim_matches('\'').as_bytes()[0],
        })
        .collect();
    assert_eq!(rdata, expected);
    let DNSData::NSEC { types, .. } = &nsec.data else { panic!() };
    assert_eq!(types.types, [DNSType::A, DNSType::MX, DNSType::RRSIG, DNSType::NSEC, DNSType(1234)]);
    let ds = &zone(&between("   dskey.example.com. 86400 IN DS", "   The first four"))[0];
    assert_eq!(ds.to_string(), "dskey.example.com. 86400 IN DS 60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118");
    // Every record back from its text and its wire form.
    for record in [dnskey, rrsig, nsec, ds] {
        assert_eq!(&zone(&record.to_string())[0], record);
        let mut message = DNSMessage::default();
        message.answers.push(record.clone());
        assert_eq!(DNSMessage::decode(&message.encode(65535).unwrap()).unwrap().answers[0], *record);
    }
    // §4.1.2: windows in order, of 1 to 32 bytes, the last byte not zero.
    assert!(DNSTypeBitmap::decode(&[0, 1, 0]).is_err());
    assert!(DNSTypeBitmap::decode(&[1, 1, 0x40, 0, 1, 0x40]).is_err());
    assert!(DNSTypeBitmap::decode(&[0, 33]).is_err());
}

/// The figures of RFC 9460 Appendix D: their presentation forms, and the generic form of RFC 3597.
fn figures(section: &str, end: &str) -> Vec<(Vec<String>, Option<String>)> {
    let lines = rfc("protocol/dns/rfc9460.txt");
    let start = lines.iter().position(|line| line.starts_with(section)).unwrap();
    let stop = start + lines[start..].iter().position(|line| line.starts_with(end)).unwrap();
    let mut figures = Vec::new();
    let mut presentations = Vec::new();
    let mut generic: Option<String> = None;
    let mut current = String::new();
    let mut in_generic = false;
    for line in &lines[start + 1..stop] {
        let trimmed = line.trim_start();
        if trimmed.starts_with("Figure") {
            if !current.is_empty() {
                presentations.push(core::mem::take(&mut current));
            }
            figures.push((core::mem::take(&mut presentations), generic.take()));
            continue;
        }
        if trimmed.starts_with("example.com.") {
            if !current.is_empty() {
                presentations.push(core::mem::take(&mut current));
            }
            current = format!("{trimmed}\n");
        } else if trimmed.starts_with("\\#") {
            if !current.is_empty() {
                presentations.push(core::mem::take(&mut current));
            }
            in_generic = true;
            generic = Some(format!("example.com. TYPE64 {trimmed}\n"));
        } else if in_generic {
            let generic = generic.as_mut().unwrap();
            generic.push_str(trimmed);
            generic.push('\n');
            if trimmed == ")" {
                in_generic = false;
            }
        } else if !current.is_empty() && !trimmed.starts_with('\\') && !trimmed.is_empty() {
            current.push_str(trimmed);
            current.push('\n');
        } else if trimmed.starts_with('\\') && !current.is_empty() {
            presentations.push(core::mem::take(&mut current));
        }
    }
    figures
}

#[test]
fn the_test_vectors_of_rfc_9460() {
    // Appendix D.1 and D.2: each presentation form is the generic one.
    let valid = figures("D.1.", "D.3.");
    assert_eq!(valid.len(), 9);
    for (presentations, generic) in valid {
        let generic = zone(&generic.unwrap());
        let DNSData::SVCB(expected) = &generic[0].data else { panic!("{generic:?}") };
        for presentation in &presentations {
            let parsed = zone(presentation);
            let DNSData::SVCB(binding) = &parsed[0].data else { panic!() };
            assert_eq!(binding, expected, "{presentation}");
            // Back from its own presentation form.
            let text = parsed[0].to_string();
            assert_eq!(zone(&text)[0].data, parsed[0].data, "{text}");
        }
    }
    // D.3: each failure case is refused.
    let failures = figures("D.3.", "Acknowledgments");
    let cases: Vec<String> = failures.into_iter().flat_map(|(presentations, _)| presentations).collect();
    assert_eq!(cases.len(), 10);
    for case in cases {
        assert!(DNSZoneFile::new(None).parse(&case).is_err(), "{case}");
    }
    // §2.2, §7: the typed values.
    let binding = &zone("example.com. HTTPS 1 . alpn=h2,h3 port=8443 ipv4hint=192.0.2.1 ech=AEn+DQBF")[0];
    let DNSData::SVCB(binding) = &binding.data else { panic!() };
    assert_eq!(binding.alpn(), [b"h2".to_vec(), b"h3".to_vec()]);
    assert_eq!(binding.port(), Some(8443));
    assert_eq!(binding.ech(), Some(&[0x00, 0x49, 0xfe, 0x0d, 0x00, 0x45][..]));
    assert!(DNSServiceBinding::decode_params(1, name("."), &[0, 3, 0, 1, 0]).is_err(), "a port of 1 byte");
    assert!(
        DNSServiceBinding::decode_params(1, name("."), &[0, 3, 0, 2, 0, 1, 0, 1, 0, 2, 0, 1]).is_err(),
        "keys out of order"
    );
    assert_eq!(DNSServiceKey::parse("key65535"), Err(DNSError::Syntax("the invalid key")));
}

#[test]
fn zone_files() {
    // RFC 1035 §5: $ORIGIN, $TTL (RFC 2308 §4), @, blank owners, parentheses, comments.
    let records = DNSZoneFile::new(None)
        .parse(
            "$ORIGIN example.\n\
             $TTL 1h\n\
             @ IN SOA ns admin.example. ( 2026102901 ; serial\n\
                 7200 3600 1209600 300 )\n\
             \tNS ns\n\
             ns 300 A 192.0.2.53\n\
             \tAAAA 2001:db8::53\n\
             www IN 60 CNAME @\n\
             txt TXT \"a \\\"quoted\\\" string\" \"two\" ; a comment\n\
             _sip._udp SRV 0 5 5060 sip\n",
        )
        .unwrap();
    assert_eq!(records.len(), 7);
    assert_eq!(records[0].ttl, 3600);
    assert_eq!(records[1].name, name("example."));
    assert_eq!(records[1].data, DNSData::NS(name("ns.example.")));
    assert_eq!((records[3].name.clone(), records[3].ttl), (name("ns.example."), 3600));
    assert_eq!(records[4].data, DNSData::CNAME(name("example.")));
    assert_eq!(records[5].data, DNSData::TXT(vec![b"a \"quoted\" string".to_vec(), b"two".to_vec()]));
    let error = DNSZoneFile::new(None).parse("a. 60 IN A 1.2.3.4\nb. 60 IN A 300.1.1.1\n").unwrap_err();
    assert_eq!(error.line, 2);
    assert!(DNSZoneFile::new(None).parse("$INCLUDE other.zone\n").is_err());
    assert!(DNSZoneFile::new(None).parse("a. 60 IN A ( 1.2.3.4\n").is_err(), "an unclosed parenthesis");
    assert_eq!(DNSToken::ttl("1w2d3h4m5s"), Ok(604800 + 2 * 86400 + 3 * 3600 + 4 * 60 + 5));
    // ANY names a class and a type: before a type it is the class.
    let any =
        DNSZoneFile::new(None).parse("a. 60 ANY A 192.0.2.1\nb. 60 IN ANY \\# 0\nc. 60 ANY TYPE65280 \\# 0\n").unwrap();
    assert_eq!((any[0].class, any[0].kind), (DNSClass::ANY, DNSType::A));
    assert_eq!((any[1].class, any[1].kind), (DNSClass::IN, DNSType::ANY));
    assert_eq!((any[2].class, any[2].kind), (DNSClass::ANY, DNSType(65280)));
    // A TTL is 32 bits (RFC 2181 §8): more, in any unit, is not one.
    assert!(DNSToken::ttl("4294967296").is_err());
    assert!(DNSToken::ttl("7102w").is_err());
    assert!(DNSToken::ttl("30500000000000000w").is_err());
}

#[test]
fn messages() {
    let mut query = DNSMessage::query(0xBEEF, DNSQuestion::new(name("example."), DNSType::AAAA));
    query.edns = Some(DNSEDNS { dnssec_ok: true, ..DNSEDNS::default() });
    let bytes = query.encode(512).unwrap();
    assert_eq!(&bytes[..12], [0xBE, 0xEF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
    assert_eq!(DNSMessage::decode(&bytes).unwrap(), query);
    // RFC 6891 §6.1.3: the extended response code.
    let mut response = DNSMessage::response(&query, DNSResponseCode::BADVERS);
    assert_eq!(response.header.rcode, 0);
    assert_eq!(response.rcode(), DNSResponseCode::BADVERS);
    response = DNSMessage::decode(&response.encode(512).unwrap()).unwrap();
    assert_eq!(response.rcode(), DNSResponseCode::BADVERS);
    assert!(response.header.response && response.header.recursion_desired);
    // §6.1.1: one OPT, in the additional section, owned by the root.
    let mut twice = bytes.clone();
    twice[11] = 2;
    twice.extend_from_slice(&bytes[bytes.len() - 11..]);
    assert!(DNSMessage::decode(&twice).is_err());
    let mut owned = bytes[..bytes.len() - 11].to_vec();
    owned.extend_from_slice(b"\x01a\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00");
    assert!(DNSMessage::decode(&owned).is_err());
    // RFC 9619 §3: a query has one question.
    let mut two = query.clone();
    two.questions.push(DNSQuestion::new(name("other."), DNSType::A));
    assert!(DNSMessage::decode(&two.encode(512).unwrap()).is_err());
    assert!(DNSMessage::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(DNSMessage::decode(&trailing).is_err());
}

#[test]
fn truncation() {
    // RFC 2181 §9: whole RRsets are left out; TC for the answer section,
    // not for the additional; RFC 6891 §7: the OPT stays.
    let mut response = DNSMessage::response(
        &DNSMessage {
            edns: Some(DNSEDNS::default()),
            ..DNSMessage::query(1, DNSQuestion::new(name("big.example."), DNSType::TXT))
        },
        DNSResponseCode::NOERROR,
    );
    for index in 0..20u8 {
        response.answers.push(DNSRecord::new(name("big.example."), 60, DNSData::TXT(vec![vec![index; 100]])));
    }
    let bytes = response.encode(512).unwrap();
    assert!(bytes.len() <= 512);
    let truncated = DNSMessage::decode(&bytes).unwrap();
    assert!(truncated.header.truncated);
    assert!(truncated.answers.is_empty(), "the RRset does not fit: none of it");
    assert!(truncated.edns.is_some());
    let mut additional = DNSMessage::response(
        &DNSMessage::query(1, DNSQuestion::new(name("a.example."), DNSType::NS)),
        DNSResponseCode::NOERROR,
    );
    additional.answers.push(DNSRecord::new(name("a.example."), 60, DNSData::NS(name("ns.a.example."))));
    for index in 0..40u8 {
        additional.additionals.push(DNSRecord::new(
            name(&format!("h{index}.a.example.")),
            60,
            DNSData::A([192, 0, 2, index].into()),
        ));
    }
    let decoded = DNSMessage::decode(&additional.encode(512).unwrap()).unwrap();
    assert!(!decoded.header.truncated && decoded.answers.len() == 1 && decoded.additionals.len() < 40);
}

#[test]
fn edns_options() {
    // RFC 7873 §4: a client cookie of 8 bytes, a server's of 8 to 32.
    assert!(DNSCookie::decode(&[0; 8]).unwrap().server.is_none());
    assert_eq!(DNSCookie::decode(&[1; 24]).unwrap().server.unwrap().len(), 16);
    for length in [0, 7, 9, 15, 41] {
        assert!(DNSCookie::decode(&vec![0; length]).is_err(), "{length}");
    }
    // RFC 8914 §2: code and text.
    let error = DNSExtendedError { info_code: DNSExtendedError::DNSSEC_BOGUS, text: "expired".into() };
    let mut edns = DNSEDNS::default();
    edns.set_option(error.encode());
    edns.set_option(DNSCookie { client: [7; 8], server: None }.encode());
    let mut message = DNSMessage::query(1, DNSQuestion::new(name("a."), DNSType::A));
    message.edns = Some(edns);
    let decoded = DNSMessage::decode(&message.encode(512).unwrap()).unwrap();
    let edns = decoded.edns.unwrap();
    assert_eq!(edns.extended_errors(), [error]);
    assert_eq!(edns.cookie().unwrap().unwrap().client, [7; 8]);
    assert!(edns.option(DNSOptionCode::PADDING).is_none());
    assert_eq!(DNSEDNS { udp_size: 100, ..DNSEDNS::default() }.payload_size(), 512);
}

#[test]
fn rules() {
    let query = |text: &str, kind| DNSMessage::query(1, DNSQuestion::new(name(text), kind));
    let rule = DNSRule::new(name("Example.com.")).with_type(DNSType::A);
    assert!(rule.matches(&query("www.example.COM.", DNSType::A)));
    assert!(!rule.matches(&query("www.example.com.", DNSType::AAAA)));
    assert!(!rule.matches(&query("example.org.", DNSType::A)));
    assert!(!rule.matches(&DNSMessage::default()));
    assert!(DNSRule::default().matches(&query("anything.", DNSType::MX)));
}

#[test]
fn names_in_data_of_rfc_3597() {
    // §4: a receiver decompresses the names of RFC 1035's types (MUST) and of SRV, NAPTR, RP,
    // AFSDB, RT, SIG, PX and NXT (SHOULD); data of a type it does not know is kept whole.
    let question = [&[0u8, 1, 0x84, 0, 0, 1, 0, 3, 0, 0, 0, 0][..], &[7], b"example", &[0, 0, 7, 0, 1]].concat();
    let answer = |kind: u16, rdata: &[u8]| {
        [&[0xC0u8, 12][..], &kind.to_be_bytes(), &[0, 1, 0, 0, 0, 60], &(rdata.len() as u16).to_be_bytes(), rdata]
            .concat()
    };
    let bytes =
        [question.clone(), answer(7, &[0xC0, 12]), answer(33, &[0, 1, 0, 2, 0, 3, 0xC0, 12]), answer(99, &[1, 2, 3])]
            .concat();
    let message = DNSMessage::decode(&bytes).unwrap();
    assert_eq!(message.answers[0].data, DNSData::Unknown(b"\x07example\x00".to_vec()));
    assert_eq!(message.answers[1].data, DNSData::SRV { priority: 1, weight: 2, port: 3, target: name("example.") });
    assert_eq!(message.answers[2].data, DNSData::Unknown(vec![1, 2, 3]));
    // Written again, the names are not compressed (RFC 3597 §4), and read again the same.
    let again = DNSMessage::decode(&message.encode(512).unwrap()).unwrap();
    assert_eq!(again.answers, message.answers);
    // RFC 4034 §6.2: the canonical form lowercases the names of RP, AFSDB, RT, KX, PX, MINFO and MB too.
    let rp = DNSData::Unknown(b"\x04MAIL\x07EXAMPLE\x00\x03TXT\x07Example\x00".to_vec());
    assert_eq!(rp.canonical(DNSType(17)), b"\x04mail\x07example\x00\x03txt\x07example\x00".to_vec());
    let afsdb = DNSData::Unknown(b"\x00\x01\x02NS\x00".to_vec());
    assert_eq!(afsdb.canonical(DNSType(18)), b"\x00\x01\x02ns\x00".to_vec());
    // Not of other types, whose data is not known to hold names.
    assert_eq!(DNSData::Unknown(b"ABC".to_vec()).canonical(DNSType(99)), b"ABC".to_vec());
}

#[test]
fn rrsig_times_are_dates() {
    // RFC 4034 §3.2: YYYYMMDDHHmmSS is a date of the calendar; 31 February is none, a sign is no digit.
    assert!(DNSToken::time("20230228235959").is_ok());
    assert!(DNSToken::time("20240229000000").is_ok());
    assert!(DNSToken::time("20230229000000").is_err());
    assert!(DNSToken::time("20230231000000").is_err());
    assert!(DNSToken::time("20230431000000").is_err());
    assert!(DNSToken::time("+20201010000000").is_err());
    assert!(DNSToken::time("+2021010000000").is_err());
}

#[test]
fn malformed_data_of_known_types() {
    // RFC 9460 §2.2: an SVCB record whose parameters are malformed is ignored, not the message. So is
    // the data of every type whose bytes stand alone, of no name compressed (RFC 3597 §4) or lowercased
    // (RFC 4034 §6.2): a CAA tag not of letters and digits (RFC 8659 §4.1), an NSEC3 of an empty hash
    // (RFC 5155 §3.2), an A not of 4 bytes (RFC 1035 §3.4.1). Each is kept as its bytes, written again
    // the same, and the records beside it are read.
    let question = [&[0u8, 1, 0x84, 0, 0, 1, 0, 6, 0, 0, 0, 0][..], &[7], b"example", &[0, 0, 1, 0, 1]].concat();
    let answer = |kind: u16, rdata: &[u8]| {
        [&[0xC0u8, 12][..], &kind.to_be_bytes(), &[0, 1, 0, 0, 0, 60], &(rdata.len() as u16).to_be_bytes(), rdata]
            .concat()
    };
    let malformed: [(u16, &[u8]); 5] = [
        (64, &[0, 1, 0, 0, 3, 0, 1, 80]),
        (65, &[0, 1, 0, 0, 3, 0, 2, 0, 80, 0, 1, 0, 2, 0, 1]),
        (257, b"\x00\x03a-bvalue"),
        (50, &[1, 0, 0, 0, 0, 0]),
        (1, &[192, 0, 2]),
    ];
    let mut bytes = question.clone();
    for (kind, rdata) in malformed {
        bytes.extend_from_slice(&answer(kind, rdata));
    }
    bytes.extend_from_slice(&answer(1, &[192, 0, 2, 1]));
    let message = DNSMessage::decode(&bytes).unwrap();
    for (record, (kind, rdata)) in message.answers.iter().zip(malformed) {
        assert_eq!((record.kind, &record.data), (DNSType(kind), &DNSData::Unknown(rdata.to_vec())), "{kind}");
        assert_eq!(record.data.canonical(record.kind), rdata, "{kind}");
    }
    assert_eq!(message.answers[5].data, DNSData::A("192.0.2.1".parse().unwrap()));
    assert_eq!(DNSMessage::decode(&message.encode(65535).unwrap()).unwrap(), message);
    // RFC 3597 §5: the generic form of the same data is read as the wire form is, and written back so.
    for (kind, rdata) in malformed {
        let kind = DNSType(kind);
        let hex: String = rdata.iter().map(|byte| format!("{byte:02x}")).collect();
        let text = format!("example. 60 IN {kind} \\# {} {hex}\n", rdata.len());
        let records = DNSZoneFile::new(None).parse(&text).unwrap();
        assert_eq!(records[0].data, DNSData::Unknown(rdata.to_vec()), "{text}");
        let again = DNSZoneFile::new(None).parse(&format!("{}\n", records[0])).unwrap();
        assert_eq!(again[0].data, records[0].data, "{text}");
    }
    // Data of a type of names compressed or lowercased cannot stand alone: malformed, the message is.
    let mut bytes = question.clone();
    bytes[7] = 1;
    bytes.extend_from_slice(&answer(15, &[0, 10]));
    assert!(DNSMessage::decode(&bytes).is_err());
    assert!(DNSZoneFile::new(None).parse("example. 60 IN MX \\# 2 000a\n").is_err());
    // RFC 9460 §7.2: a port of another length than 2 bytes is no port.
    let mut binding = DNSServiceBinding::new(1, name("."));
    for value in [&[][..], &[1], &[1, 2, 3]] {
        binding.set(DNSServiceKey::PORT, value);
        assert_eq!(binding.port(), None, "{value:?}");
    }
    binding.set(DNSServiceKey::PORT, &[0x01, 0xBB]);
    assert_eq!(binding.port(), Some(443));
}
