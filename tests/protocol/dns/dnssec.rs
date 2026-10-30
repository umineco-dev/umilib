//! DNSSEC: keys and their examples (RFC 4034, 5702, 6605, 8080), the
//! signed zones and responses of RFC 4035 and RFC 5155, trust anchors (RFC
//! 9718), records captured from the Internet, and the rules of RFC 4035 §5,
//! RFC 6840, RFC 9276 and RFC 9824.

use umilib::codec::base::base32::Base32;
use umilib::codec::base::{Encoding, Padding};
use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::SHA256;
use umilib::protocol::dns::dnssec::{
    DNSSECAlgorithm, DNSSECConfig, DNSSECDigest, DNSSECKey, DNSSECKeyDigest, DNSSECPrivateKey, DNSSECProof,
    DNSSECSigner, DNSSECTrust, DNSSECTrustAnchor, DNSSECValidator,
};
use umilib::protocol::dns::{
    DNSData, DNSError, DNSExtendedError, DNSNSEC3, DNSName, DNSRRSIG, DNSRecord, DNSToken, DNSType,
};

use super::{Response, example_zone, name, rfc, zone};
use crate::Vectors;

fn random() -> HMACDRBG<SHA256> {
    random_of(3)
}

/// A random generator of its own `seed`, so that keys of different seeds differ.
fn random_of(seed: u8) -> HMACDRBG<SHA256> {
    HMACDRBG::<SHA256>::new(&[seed; 32], &[5; 16], b"umilib dnssec tests").unwrap()
}

/// A validator that accepts the RSA keys of 512 bits of the examples,
/// which RFC 3110 §2 allows.
fn validator() -> DNSSECValidator {
    DNSSECValidator::new(DNSSECConfig { minimum_rsa_bits: 512, ..DNSSECConfig::default() })
}

/// The records of `records` owned by `owner` of type `kind`.
fn of(records: &[DNSRecord], owner: &DNSName, kind: DNSType) -> Vec<DNSRecord> {
    records.iter().filter(|record| record.name == *owner && record.kind == kind).cloned().collect()
}

fn signatures(records: &[DNSRecord]) -> Vec<DNSRecord> {
    records.iter().filter(|record| record.kind == DNSType::RRSIG).cloned().collect()
}

fn rrsig(record: &DNSRecord) -> &DNSRRSIG {
    match &record.data {
        DNSData::RRSIG(rrsig) => rrsig,
        _ => panic!("not an RRSIG: {record}"),
    }
}

/// The RRsets of `records` but RRSIG, in order of appearance.
fn rrsets(records: &[DNSRecord]) -> Vec<Vec<DNSRecord>> {
    let mut sets: Vec<Vec<DNSRecord>> = Vec::new();
    for record in records.iter().filter(|record| record.kind != DNSType::RRSIG) {
        match sets.iter_mut().find(|set| set[0].same_set(record)) {
            Some(set) => set.push(record.clone()),
            None => sets.push(vec![record.clone()]),
        }
    }
    sets
}

fn bogus_code(result: Result<impl core::fmt::Debug, DNSError>) -> u16 {
    match result {
        Err(DNSError::Bogus { code, .. }) => code,
        other => panic!("not bogus: {other:?}"),
    }
}

/// The examples of the section of `path` from `start` to `end`: each
/// private key (of the format v1.2) and the records after it.
fn key_examples(
    path: &str,
    start: &str,
    end: &str,
    fix: impl Fn(&str) -> String,
) -> Vec<(DNSSECPrivateKey, Vec<DNSRecord>)> {
    let lines = rfc(path);
    let from = lines.iter().position(|line| line.starts_with(start)).unwrap();
    let to = from + lines[from..].iter().position(|line| line.starts_with(end)).unwrap_or(lines.len() - from);
    let mut examples: Vec<(String, String)> = Vec::new();
    let mut in_key = false;
    for line in &lines[from + 1..to] {
        if line.trim_start().starts_with("Private-key-format") {
            examples.push((String::new(), String::new()));
            in_key = true;
        }
        if in_key {
            if line.trim().is_empty() {
                in_key = false;
            } else {
                examples.last_mut().unwrap().0.push_str(&format!("{line}\n"));
            }
        } else if !super::is_prose(line)
            && !line.trim().is_empty()
            && !line.starts_with(|first: char| first.is_ascii_digit())
            && let Some(example) = examples.last_mut()
        {
            example.1.push_str(&format!("{line}\n"));
        }
    }
    examples
        .into_iter()
        .map(|(key, records)| {
            (DNSSECPrivateKey::parse(&key).unwrap_or_else(|error| panic!("{error:?}: {key}")), zone(&fix(&records)))
        })
        .collect()
}

/// Checks a key example: the key gives its DNSKEY and DS, and the RRSIG
/// verifies; a deterministic algorithm signs the same signature again.
fn check_key_example(key: DNSSECPrivateKey, records: &[DNSRecord]) {
    let dnskey = records.iter().find(|record| record.kind == DNSType::DNSKEY).unwrap();
    let fields = DNSSECKey::from_data(&dnskey.data).unwrap();
    assert_eq!(key.algorithm(), fields.algorithm);
    assert_eq!(key.public_key().encode(), fields.public_key, "{dnskey}");
    for ds in records.iter().filter(|record| record.kind == DNSType::DS) {
        let DNSData::DS { digest_type, key_tag, .. } = ds.data else { unreachable!() };
        assert_eq!(key_tag, fields.tag());
        assert_eq!(DNSSECDigest(digest_type).delegation(&ds.name, &fields), Some(ds.data.clone()), "{ds}");
    }
    let signature = records.iter().find(|record| record.kind == DNSType::RRSIG).unwrap();
    let covered = of(records, &signature.name, rrsig(signature).type_covered);
    let now = rrsig(signature).inception + 1;
    let verified = validator()
        .verify(&covered, std::slice::from_ref(signature), std::slice::from_ref(dnskey), now)
        .unwrap_or_else(|error| panic!("{error:?}: {signature}"));
    assert_eq!((verified.key_tag, verified.signer.clone()), (fields.tag(), dnskey.name.clone()));
    let signer = DNSSECSigner::new(dnskey.name.clone(), fields.flags, key);
    let mut random = random();
    let signed = signer.sign(&covered, rrsig(signature).inception, rrsig(signature).expiration, &mut random).unwrap();
    validator().verify(&covered, std::slice::from_ref(&signed), std::slice::from_ref(dnskey), now).unwrap();
    let deterministic =
        !matches!(fields.algorithm, DNSSECAlgorithm::ECDSAP256SHA256 | DNSSECAlgorithm::ECDSAP384SHA384);
    if deterministic {
        assert_eq!(signed, *signature);
    } else {
        assert_eq!(
            DNSRRSIG { signature: vec![], ..rrsig(&signed).clone() },
            DNSRRSIG { signature: vec![], ..rrsig(signature).clone() }
        );
    }
    // The private key round-trips its text.
    let text = signer.key.format();
    assert_eq!(DNSSECPrivateKey::parse(&text).unwrap().public_key(), signer.key.public_key());
}

#[test]
fn key_tags_and_delegations() {
    // RFC 4034 §5.4: the DS of the key of tag 60485.
    let lines = rfc("protocol/dns/rfc4034.txt");
    let start =
        lines.iter().position(|line| line.trim_start().starts_with("dskey.example.com. 86400 IN DNSKEY")).unwrap();
    let end = start + lines[start..].iter().position(|line| line.contains("98631FAD1A292118 )")).unwrap();
    let records = zone(&lines[start..=end].join("\n"));
    let key = DNSSECKey::from_data(&records[0].data).unwrap();
    assert_eq!(key.tag(), 60485);
    assert!(key.is_zone_key() && !key.is_secure_entry_point() && !key.is_revoked());
    assert_eq!(DNSSECDigest::SHA1.delegation(&records[0].name, &key), Some(records[1].data.clone()));
    // RFC 4034 Appendix B.1: RSA/MD5 takes the tag from the modulus.
    let md5 = DNSSECKey { algorithm: DNSSECAlgorithm::RSAMD5, public_key: &[1, 3, 0xAB, 0xCD, 0xEF, 0x12], ..key };
    assert_eq!(md5.tag(), 0xCDEF);
    // The root's keys of 2017 and 2024 are those of IANA's trust anchors.
    let captured = zone(&Vectors::read("protocol/dns/captured.txt"));
    let anchors = DNSSECTrustAnchor::root().delegations(1_793_222_185);
    for (tag, anchor) in [20326, 38696].into_iter().zip(&anchors) {
        let dnskey = captured
            .iter()
            .filter(|record| record.kind == DNSType::DNSKEY && record.name.is_root())
            .find(|record| DNSSECKey::from_data(&record.data).unwrap().tag() == tag)
            .unwrap();
        let fields = DNSSECKey::from_data(&dnskey.data).unwrap();
        assert!(fields.is_secure_entry_point());
        assert_eq!(DNSSECDigest::SHA256.delegation(&DNSName::root(), &fields), Some(anchor.data.clone()));
        assert!(DNSSECValidator::names(anchor, &fields));
    }
    // A DS of another digest or tag does not name the key.
    let DNSData::DS { key_tag, algorithm, digest_type, ref digest } = records[1].data else { unreachable!() };
    let mut wrong = digest.clone();
    wrong[0] ^= 1;
    for data in [
        DNSData::DS { key_tag, algorithm, digest_type, digest: wrong },
        DNSData::DS { key_tag: key_tag ^ 1, algorithm, digest_type, digest: digest.clone() },
        DNSData::DS { key_tag, algorithm: 8, digest_type, digest: digest.clone() },
    ] {
        assert!(!DNSSECValidator::names(&DNSRecord::new(records[1].name.clone(), 0, data), &key));
    }
}

#[test]
fn the_key_examples_of_rfc_5702_6605_and_8080() {
    let none = |text: &str| text.to_string();
    let examples = [
        key_examples("protocol/dns/rfc5702.txt", "6.  Examples", "7.  ", none),
        key_examples("protocol/dns/rfc6605.txt", "6.  Examples", "7.  ", none),
        // RFC 8080 as Erratum 4935 corrects it: its RRSIG records lacked
        // their algorithm and had one label too many.
        // (It keeps their "(" before the signature that no ")" closes.)
        key_examples("protocol/dns/rfc8080-errata4935.txt", "6.  Examples", "7.  ", |text| {
            text.replace("example.com. (", "example.com.")
        }),
    ];
    let counts: Vec<usize> = examples.iter().map(Vec::len).collect();
    assert_eq!(counts, [2, 2, 4]);
    for (key, records) in examples.into_iter().flatten() {
        check_key_example(key, &records);
    }
}

#[test]
fn generated_keys() {
    let mut random = random();
    for algorithm in [
        DNSSECAlgorithm::ECDSAP256SHA256,
        DNSSECAlgorithm::ECDSAP384SHA384,
        DNSSECAlgorithm::ED25519,
        DNSSECAlgorithm::ED448,
    ] {
        let key = DNSSECPrivateKey::generate(algorithm, 0, &mut random).unwrap();
        let signer = DNSSECSigner::new(name("example."), DNSSECKey::ZONE, key);
        let records = vec![DNSRecord::new(name("www.example."), 300, DNSData::A("192.0.2.1".parse().unwrap()))];
        let signature = signer.sign(&records, 1000, 2000, &mut random).unwrap();
        assert_eq!(rrsig(&signature).algorithm, algorithm.0);
        let keys = [signer.dnskey(300)];
        validator().verify(&records, std::slice::from_ref(&signature), &keys, 1500).unwrap();
        assert_eq!(DNSSECPrivateKey::parse(&signer.key.format()).unwrap().public_key(), signer.key.public_key());
    }
    // An algorithm not implemented, or RSA above 4096 bits, cannot be generated.
    assert!(DNSSECPrivateKey::generate(DNSSECAlgorithm::DSA, 0, &mut random).is_err());
    assert!(DNSSECPrivateKey::generate(DNSSECAlgorithm::RSASHA256, 8192, &mut random).is_err());
}

#[test]
fn rsa_public_keys_of_rfc_3110() {
    // RFC 3110 §2: the exponent's length in one byte, or zero and two bytes.
    let modulus = [&[0xC1][..], &[0x5A; 62], &[0x01]].concat();
    let short = [&[1u8, 3][..], &modulus].concat();
    let key = umilib::protocol::dns::dnssec::DNSSECPublicKey::decode(DNSSECAlgorithm::RSASHA256, &short).unwrap();
    assert_eq!((key.bits(), key.encode()), (512, short.clone()));
    let long = [&[0u8, 0, 1, 3][..], &modulus].concat();
    let key = umilib::protocol::dns::dnssec::DNSSECPublicKey::decode(DNSSECAlgorithm::RSASHA256, &long).unwrap();
    assert_eq!(key.encode(), short);
    for malformed in [
        vec![],
        vec![1, 3],
        [&[1u8, 0][..], &modulus].concat(),
        [&[1u8, 3, 0][..], &modulus].concat(),
        [&[1u8, 3][..], &modulus[..32]].concat(),
    ] {
        assert!(
            umilib::protocol::dns::dnssec::DNSSECPublicKey::decode(DNSSECAlgorithm::RSASHA256, &malformed).is_err()
        );
    }
    // RSASHA512 keys are of 1024 bits at least (RFC 5702 §2).
    assert!(umilib::protocol::dns::dnssec::DNSSECPublicKey::decode(DNSSECAlgorithm::RSASHA512, &short).is_err());
    // ECDSA keys are x and y, of the curve's size each (RFC 6605 §4).
    assert!(
        umilib::protocol::dns::dnssec::DNSSECPublicKey::decode(DNSSECAlgorithm::ECDSAP256SHA256, &[4; 64]).is_err()
    );
    // An exponent of more bits than the validator takes makes the key unusable, as a
    // modulus of too few does: such keys cost hundreds of times more to verify with.
    let modulus = [&[0xC1][..], &[0x5A; 254], &[0x01]].concat();
    let usable = |exponent: &[u8]| {
        let field = [&[exponent.len() as u8][..], exponent, &modulus].concat();
        let key = DNSSECKey {
            flags: DNSSECKey::ZONE,
            protocol: 3,
            algorithm: DNSSECAlgorithm::RSASHA256,
            public_key: &field,
        };
        DNSSECValidator::default().usable_key(&key).is_some()
    };
    assert!(usable(&[1, 0, 1]));
    assert!(usable(&[0x80, 0, 0, 0, 0, 0, 0, 1]));
    assert!(!usable(&[1, 0, 0, 0, 0, 0, 0, 0, 1]));
    assert!(!usable(&[&[0x7F][..], &[0xFF; 200]].concat()));
}

/// The time of the signatures of RFC 4035 Appendix A.
fn rfc_4035_now() -> u32 {
    DNSToken::time("20040420000000").unwrap()
}

#[test]
fn the_signed_zone_of_rfc_4035() {
    let records = example_zone("protocol/dns/rfc4035.txt", "example.       3600 IN SOA");
    let apex = name("example.");
    let keys = of(&records, &apex, DNSType::DNSKEY);
    assert_eq!(keys.len(), 2);
    let signatures = signatures(&records);
    let now = rfc_4035_now();
    let mut verified = 0;
    for set in rrsets(&records) {
        let result = validator().verify(&set, &signatures, &keys, now);
        let owner = &set[0].name;
        // RFC 4035 §2.2: delegations and glue are not signed.
        let cut = [name("a.example."), name("b.example.")].iter().any(|cut| owner.is_subdomain_of(cut));
        let unsigned = cut && set[0].kind != DNSType::DS && set[0].kind != DNSType::NSEC;
        match unsigned {
            true => assert_eq!(bogus_code(result), DNSExtendedError::RRSIGS_MISSING, "{}", set[0]),
            false => {
                let result = result.unwrap_or_else(|error| panic!("{error:?}: {}", set[0]));
                assert_eq!(result.ttl, 3600);
                verified += 1;
            }
        }
    }
    // The 26 RRsets that Appendix A lists with an RRSIG.
    assert_eq!(verified, 26);
    // The apex's keys are trusted through a DS of its SEP key.
    let sep = keys.iter().find(|key| DNSSECKey::from_data(&key.data).unwrap().is_secure_entry_point()).unwrap();
    for digest in [DNSSECDigest::SHA1, DNSSECDigest::SHA256, DNSSECDigest::SHA384] {
        let ds = DNSRecord::new(
            apex.clone(),
            3600,
            digest.delegation(&apex, &DNSSECKey::from_data(&sep.data).unwrap()).unwrap(),
        );
        let trust = validator().verify_keys(&keys, &signatures, &[ds], now).unwrap();
        assert!(
            matches!(trust, DNSSECTrust::Secure(ref verified) if verified.key_tag == DNSSECKey::from_data(&sep.data).unwrap().tag())
        );
    }
}

/// Verifies every RRset of `records` with `keys` and gives the records.
fn verified(records: &[DNSRecord], keys: &[DNSRecord], now: u32) -> Vec<DNSRecord> {
    let signatures = signatures(records);
    for set in rrsets(records) {
        validator().verify(&set, &signatures, keys, now).unwrap_or_else(|error| panic!("{error:?}: {}", set[0]));
    }
    records.to_vec()
}

#[test]
fn the_responses_of_rfc_4035() {
    let path = "protocol/dns/rfc4035.txt";
    let zone_records = example_zone(path, "example.       3600 IN SOA");
    let apex = name("example.");
    let keys = of(&zone_records, &apex, DNSType::DNSKEY);
    let now = rfc_4035_now();
    let validator = validator();
    // B.1: an answer.
    let answer = Response::of(path, "B.1.  ");
    let result = validator.verify(&answer.answers[..1], &signatures(&answer.answers), &keys, now).unwrap();
    assert_eq!(result.closest_encloser, None);
    verified(&answer.records(), &keys, now);
    // B.2: a name error.
    let response = Response::of(path, "B.2.  ");
    let records = verified(&response.authorities, &keys, now);
    assert_eq!(validator.prove_nonexistence(&response.question.name, &apex, &records), Ok(DNSSECProof::Secure));
    // Not of a name that exists, nor without the NSEC of the wildcard.
    assert!(validator.prove_nonexistence(&name("ns1.example."), &apex, &records).is_err());
    let without_wildcard: Vec<DNSRecord> = records.iter().filter(|record| record.name != apex).cloned().collect();
    assert_eq!(
        bogus_code(validator.prove_nonexistence(&response.question.name, &apex, &without_wildcard)),
        DNSExtendedError::NSEC_MISSING
    );
    // B.3: no data.
    let response = Response::of(path, "B.3.  ");
    let records = verified(&response.authorities, &keys, now);
    assert_eq!(
        validator.prove_nodata(&response.question.name, response.question.kind, &apex, &records),
        Ok(DNSSECProof::Secure)
    );
    assert!(validator.prove_nodata(&response.question.name, DNSType::A, &apex, &records).is_err());
    // B.4: a referral to a signed zone, whose DS verifies.
    let response = Response::of(path, "B.4.  ");
    let ds = of(&response.authorities, &name("a.example."), DNSType::DS);
    assert_eq!(ds.len(), 1);
    validator.verify(&ds, &signatures(&response.authorities), &keys, now).unwrap();
    assert!(validator.prove_unsigned_delegation(&name("a.example."), &apex, &zone_records).is_err());
    // B.5: a referral to an unsigned zone.
    let response = Response::of(path, "B.5.  ");
    let records =
        [of(&response.authorities, &name("b.example."), DNSType::NSEC), signatures(&response.authorities)].concat();
    let records = verified(&records, &keys, now);
    assert_eq!(validator.prove_unsigned_delegation(&name("b.example."), &apex, &records), Ok(DNSSECProof::Secure));
    // The NSEC of a cut denies DS there, but nothing else at or below it (RFC 6840 §4.1).
    assert_eq!(validator.prove_nodata(&name("b.example."), DNSType::DS, &apex, &records), Ok(DNSSECProof::Secure));
    assert!(validator.prove_nodata(&name("b.example."), DNSType::A, &apex, &records).is_err());
    // B.6: a wildcard expansion; the verified answer tells the closest encloser.
    let response = Response::of(path, "B.6.  ");
    let result = validator.verify(&response.answers[..1], &signatures(&response.answers), &keys, now).unwrap();
    assert_eq!(result.closest_encloser, Some(name("w.example.")));
    let records = verified(&response.authorities, &keys, now);
    let question = &response.question.name;
    assert_eq!(validator.prove_expansion(question, &name("w.example."), &apex, &records), Ok(DNSSECProof::Secure));
    // Not if the expansion claims another wildcard.
    assert!(validator.prove_expansion(question, &apex, &apex, &records).is_err());
    // B.7: a wildcard no data.
    let response = Response::of(path, "B.7.  ");
    let records = verified(&response.authorities, &keys, now);
    assert_eq!(
        validator.prove_nodata(&response.question.name, response.question.kind, &apex, &records),
        Ok(DNSSECProof::Secure)
    );
    assert!(validator.prove_nodata(&response.question.name, DNSType::MX, &apex, &records).is_err());
    // B.8: a DS denied by the zone below the cut is not a denial (RFC 4035 §3.1.4.1).
    let response = Response::of(path, "B.8.  ");
    let records = verified(&response.authorities, &keys, now);
    assert!(validator.prove_nodata(&response.question.name, DNSType::DS, &apex, &records).is_err());
}

#[test]
fn the_hashes_and_responses_of_rfc_5155() {
    let path = "protocol/dns/rfc5155.txt";
    let apex = name("example.");
    // Appendix A: the hashes of the owner names, salt aabbccdd and 12 iterations.
    let lines = rfc(path);
    let mut hashes: Vec<(DNSName, String)> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(rest) = line.trim().trim_start_matches(';').trim_start().strip_prefix("H(") else { continue };
        let (owner, hash) = rest.split_once(')').unwrap();
        let hash = match hash.trim() {
            "" => lines[index + 1].trim().trim_start_matches([';', ' ', '=']).trim(),
            hash => hash.trim_start_matches(['=', ' ']).trim(),
        };
        hashes.push((name(&format!("{owner}.")), hash.to_string()));
    }
    assert_eq!(hashes.len(), 21);
    for (owner, hash) in &hashes {
        let digest = DNSNSEC3::digest(DNSNSEC3::SHA1, 12, &[0xAA, 0xBB, 0xCC, 0xDD], owner).unwrap();
        assert_eq!(DNSNSEC3::owner(&digest, &apex).unwrap(), name(&format!("{hash}.example.")), "{owner}");
        assert_eq!(DNSNSEC3::owner_hash(&name(&format!("{}.example.", hash.to_uppercase()))), Some(digest));
    }
    let zone_records = example_zone(path, "example. 3600  IN SOA");
    let keys = of(&zone_records, &apex, DNSType::DNSKEY);
    let now = DNSToken::time("20100101000000").unwrap();
    let signatures = signatures(&zone_records);
    let mut count = 0;
    for set in rrsets(&zone_records) {
        if validator().verify(&set, &signatures, &keys, now).is_ok() {
            count += 1;
        }
    }
    assert!(count >= 30, "{count}");
    let validator = validator();
    // B.1: a name error; the next closer name is in an Opt-Out span, where
    // an unsigned delegation may be, so the proof is insecure.
    let response = Response::of(path, "B.1.  ");
    let records = verified(&response.authorities, &keys, now);
    assert_eq!(validator.prove_nonexistence(&response.question.name, &apex, &records), Ok(DNSSECProof::Insecure(None)));
    assert!(validator.prove_nonexistence(&name("x.w.example."), &apex, &records).is_err());
    // B.2 and B.2.1: no data, at a name and at an empty non-terminal.
    for heading in ["B.2.  ", "B.2.1.  "] {
        let response = Response::of(path, heading);
        let records = verified(&response.authorities, &keys, now);
        let question = &response.question;
        assert_eq!(
            validator.prove_nodata(&question.name, question.kind, &apex, &records),
            Ok(DNSSECProof::Secure),
            "{heading}"
        );
    }
    // B.3: a referral to an unsigned zone in an Opt-Out span.
    let response = Response::of(path, "B.3.  ");
    assert_eq!(of(&response.authorities, &name("c.example."), DNSType::NS).len(), 2);
    let nsec3: Vec<DNSRecord> = response
        .authorities
        .iter()
        .filter(|record| record.kind == DNSType::NSEC3 || record.kind == DNSType::RRSIG)
        .cloned()
        .collect();
    let nsec3 = verified(&nsec3, &keys, now);
    assert_eq!(
        validator.prove_unsigned_delegation(&name("c.example."), &apex, &nsec3),
        Ok(DNSSECProof::Insecure(None))
    );
    assert_eq!(
        validator.prove_nodata(&name("c.example."), DNSType::DS, &apex, &nsec3),
        Ok(DNSSECProof::Insecure(None))
    );
    // B.4: a wildcard expansion.
    let response = Response::of(path, "B.4.  ");
    let result = validator.verify(&response.answers[..1], &self::signatures(&response.answers), &keys, now).unwrap();
    let encloser = result.closest_encloser.unwrap();
    assert_eq!(encloser, name("w.example."));
    let records = verified(&response.authorities, &keys, now);
    let proof = validator.prove_expansion(&response.question.name, &encloser, &apex, &records).unwrap();
    assert_eq!(proof, DNSSECProof::Insecure(None));
    // B.5: a wildcard no data.
    let response = Response::of(path, "B.5.  ");
    let records = verified(&response.authorities, &keys, now);
    let question = &response.question;
    assert_eq!(validator.prove_nodata(&question.name, question.kind, &apex, &records), Ok(DNSSECProof::Insecure(None)));
    assert!(validator.prove_nodata(&question.name, DNSType::MX, &apex, &records).is_err());
    // B.6: a DS denied by the zone below its cut. (Its last RRSIG lacks
    // the "(" that its ")" closes.)
    let fixed: Vec<String> = lines
        .iter()
        .map(|line| if line.ends_with("RRSIG NSEC3 7 2 3600") { format!("{line} (") } else { line.clone() })
        .collect();
    let response = Response::parse(&fixed, "B.6.  ");
    let records = verified(&response.authorities, &keys, now);
    assert!(validator.prove_nodata(&response.question.name, DNSType::DS, &apex, &records).is_err());
}

#[test]
fn records_captured_from_the_internet() {
    let records = zone(&Vectors::read("protocol/dns/captured.txt"));
    let now = 1_793_222_185;
    let validator = DNSSECValidator::default();
    let signatures = signatures(&records);
    let trusted = |zone: &DNSName, anchors: &[DNSRecord]| -> Vec<DNSRecord> {
        let keys = of(&records, zone, DNSType::DNSKEY);
        let trust = validator.verify_keys(&keys, &signatures, anchors, now as u32).unwrap();
        assert!(matches!(trust, DNSSECTrust::Secure(_)), "{zone}: {trust:?}");
        keys
    };
    let delegation = |zone: &DNSName, keys: &[DNSRecord]| -> Vec<DNSRecord> {
        let ds = of(&records, zone, DNSType::DS);
        validator.verify(&ds, &signatures, keys, now as u32).unwrap_or_else(|error| panic!("{zone}: {error:?}"));
        ds
    };
    let root = trusted(&DNSName::root(), &DNSSECTrustAnchor::root().delegations(now));
    let com = trusted(&name("com."), &delegation(&name("com."), &root));
    let org = trusted(&name("org."), &delegation(&name("org."), &root));
    let ietf = trusted(&name("ietf.org."), &delegation(&name("ietf.org."), &org));
    let isc = trusted(&name("isc.org."), &delegation(&name("isc.org."), &org));
    validator.verify(&of(&records, &name("ietf.org."), DNSType::A), &signatures, &ietf, now as u32).unwrap();
    // .com's NSEC3 chain is Opt-Out (RFC 5155 §6): its name errors are insecure.
    let denial: Vec<DNSRecord> = records.iter().filter(|record| record.kind == DNSType::NSEC3).cloned().collect();
    for set in rrsets(&denial) {
        validator.verify(&set, &signatures, &com, now as u32).unwrap();
    }
    let proof = validator.prove_nonexistence(&name("nonexistent-umilib.com."), &name("com."), &denial).unwrap();
    assert_eq!(proof, DNSSECProof::Insecure(None));
    // isc.org's NSEC chain denies a name and a type securely.
    let denial: Vec<DNSRecord> = records
        .iter()
        .filter(|record| record.kind == DNSType::NSEC && record.name.is_subdomain_of(&name("isc.org.")))
        .cloned()
        .collect();
    for set in rrsets(&denial) {
        validator.verify(&set, &signatures, &isc, now as u32).unwrap();
    }
    assert_eq!(
        validator.prove_nonexistence(&name("nonexistent-umilib.isc.org."), &name("isc.org."), &denial),
        Ok(DNSSECProof::Secure)
    );
    assert_eq!(
        validator.prove_nodata(&name("isc.org."), DNSType::TLSA, &name("isc.org."), &denial),
        Ok(DNSSECProof::Secure)
    );
    assert!(validator.prove_nodata(&name("isc.org."), DNSType::MX, &name("isc.org."), &denial).is_err());
    // A week later, the root's signatures have expired.
    let later = now as u32 + 30 * 86_400;
    let keys = of(&records, &DNSName::root(), DNSType::DNSKEY);
    let result = validator.verify_keys(&keys, &signatures, &DNSSECTrustAnchor::root().delegations(now), later);
    assert_eq!(bogus_code(result), DNSExtendedError::SIGNATURE_EXPIRED);
}

/// A zone of one key of Ed25519, and the signer.
fn signed() -> (DNSSECSigner, Vec<DNSRecord>) {
    let mut random = random();
    let key = DNSSECPrivateKey::generate(DNSSECAlgorithm::ED25519, 0, &mut random).unwrap();
    let signer = DNSSECSigner::new(name("example."), DNSSECKey::ZONE | DNSSECKey::SECURE_ENTRY_POINT, key);
    let keys = vec![signer.dnskey(3600)];
    (signer, keys)
}

#[test]
fn the_checks_of_a_signature() {
    let (signer, keys) = signed();
    let mut random = random();
    let records = vec![
        DNSRecord::new(name("www.example."), 300, DNSData::A("192.0.2.1".parse().unwrap())),
        DNSRecord::new(name("WWW.example."), 300, DNSData::A("192.0.2.2".parse().unwrap())),
    ];
    let signature = signer.sign(&records, 1000, 2000, &mut random).unwrap();
    let validator = DNSSECValidator::default();
    // RFC 4034 §6.3: the order and the case of the records do not matter.
    let reordered = vec![records[1].clone(), records[0].clone()];
    let result = validator.verify(&reordered, std::slice::from_ref(&signature), &keys, 1500).unwrap();
    // RFC 4035 §5.3.3: the TTL is at most the time left.
    assert_eq!(result.ttl, 300);
    assert_eq!(validator.verify(&records, std::slice::from_ref(&signature), &keys, 1900).unwrap().ttl, 100);
    // A changed record, and one more record, do not verify.
    let mut changed = records.clone();
    changed[1].data = DNSData::A("192.0.2.3".parse().unwrap());
    assert_eq!(
        bogus_code(validator.verify(&changed, std::slice::from_ref(&signature), &keys, 1500)),
        DNSExtendedError::DNSSEC_BOGUS
    );
    let more =
        [records.clone(), vec![DNSRecord::new(name("www.example."), 300, DNSData::A("192.0.2.4".parse().unwrap()))]]
            .concat();
    assert!(validator.verify(&more, std::slice::from_ref(&signature), &keys, 1500).is_err());
    // RFC 4035 §5.3.1: the validity period, in serial arithmetic (RFC 1982).
    assert_eq!(
        bogus_code(validator.verify(&records, std::slice::from_ref(&signature), &keys, 999)),
        DNSExtendedError::SIGNATURE_NOT_YET_VALID
    );
    assert_eq!(
        bogus_code(validator.verify(&records, std::slice::from_ref(&signature), &keys, 2001)),
        DNSExtendedError::SIGNATURE_EXPIRED
    );
    let skewed = DNSSECValidator::new(DNSSECConfig { clock_skew: 10, ..DNSSECConfig::default() });
    assert!(skewed.verify(&records, std::slice::from_ref(&signature), &keys, 995).is_ok());
    assert!(skewed.verify(&records, std::slice::from_ref(&signature), &keys, 2005).is_ok());
    let wrapped = signer.sign(&records, u32::MAX - 100, 100, &mut random).unwrap();
    assert!(validator.verify(&records, std::slice::from_ref(&wrapped), &keys, 0).is_ok());
    assert!(validator.verify(&records, &[wrapped], &keys, 200).is_err());
    let backwards = signer.sign(&records, 2000, 1000, &mut random).unwrap();
    assert_eq!(
        bogus_code(validator.verify(&records, &[backwards], &keys, 1500)),
        DNSExtendedError::SIGNATURE_EXPIRED_BEFORE_VALID
    );
    // Labels above the owner's, a signer above which the owner is not.
    let mut labels = signature.clone();
    let DNSData::RRSIG(ref mut data) = labels.data else { unreachable!() };
    data.labels = 3;
    assert!(validator.verify(&records, &[labels], &keys, 1500).is_err());
    let mut other = signature.clone();
    let DNSData::RRSIG(ref mut data) = other.data else { unreachable!() };
    data.signer = name("other.");
    assert!(validator.verify(&records, &[other], &keys, 1500).is_err());
    // No signature, or none of the RRset's type.
    assert_eq!(bogus_code(validator.verify(&records, &[], &keys, 1500)), DNSExtendedError::RRSIGS_MISSING);
    let mx =
        vec![DNSRecord::new(name("www.example."), 300, DNSData::MX { preference: 1, exchange: name("mx.example.") })];
    assert_eq!(
        bogus_code(validator.verify(&mx, std::slice::from_ref(&signature), &keys, 1500)),
        DNSExtendedError::RRSIGS_MISSING
    );
    // No key of the tag; a key that is not a zone key (RFC 4034 §2.1.1), revoked (RFC 5011 §2.1) or of another protocol.
    assert_eq!(
        bogus_code(validator.verify(&records, std::slice::from_ref(&signature), &[], 1500)),
        DNSExtendedError::DNSKEY_MISSING
    );
    for flags in [0, DNSSECKey::ZONE | DNSSECKey::REVOKE] {
        let key = DNSSECPrivateKey::parse(&signer.key.format()).unwrap();
        let other = DNSSECSigner::new(name("example."), flags, key);
        let signature = other.sign(&records, 1000, 2000, &mut random).unwrap();
        let code = bogus_code(validator.verify(&records, &[signature], &[other.dnskey(3600)], 1500));
        let expected =
            if flags == 0 { DNSExtendedError::NO_ZONE_KEY_BIT_SET } else { DNSExtendedError::DNSKEY_MISSING };
        assert_eq!(code, expected);
    }
    let mut protocol = keys[0].clone();
    let DNSData::DNSKEY { protocol: ref mut field, .. } = protocol.data else { unreachable!() };
    *field = 2;
    assert!(validator.verify(&records, std::slice::from_ref(&signature), &[protocol], 1500).is_err());
    // An algorithm not in use.
    let policy =
        DNSSECValidator::new(DNSSECConfig { algorithms: vec![DNSSECAlgorithm::RSASHA256], ..DNSSECConfig::default() });
    assert!(policy.verify(&records, std::slice::from_ref(&signature), &keys, 1500).is_err());
    // One valid signature is enough (RFC 6840 §5.11).
    let mut broken = signature.clone();
    let DNSData::RRSIG(ref mut data) = broken.data else { unreachable!() };
    data.signature[0] ^= 1;
    assert!(validator.verify(&records, &[broken.clone(), signature.clone()], &keys, 1500).is_ok());
    // But no more than the configured number of verifications (KeyTrap).
    let many: Vec<DNSRecord> = (0..9)
        .map(|index| {
            let mut copy = broken.clone();
            let DNSData::RRSIG(ref mut data) = copy.data else { unreachable!() };
            data.signature[1] = index;
            copy
        })
        .collect();
    let error = validator.verify(&records, &[many.clone(), vec![signature.clone()]].concat(), &keys, 1500);
    assert_eq!(bogus_code(error), DNSExtendedError::DNSSEC_BOGUS);
    assert!(validator.verify(&records, &[many[..7].to_vec(), vec![signature.clone()]].concat(), &keys, 1500).is_ok());
    // A wildcard's records verify at any name it expands to, with the closest encloser.
    let wildcard = vec![DNSRecord::new(name("*.example."), 300, DNSData::A("192.0.2.9".parse().unwrap()))];
    let signature = signer.sign(&wildcard, 1000, 2000, &mut random).unwrap();
    assert_eq!(rrsig(&signature).labels, 1);
    let expanded = vec![DNSRecord::new(name("a.b.example."), 300, DNSData::A("192.0.2.9".parse().unwrap()))];
    let signature = DNSRecord { name: name("a.b.example."), ..signature };
    let result = validator.verify(&expanded, &[signature], &keys, 1500).unwrap();
    assert_eq!(result.closest_encloser, Some(name("example.")));
}

#[test]
fn the_checks_of_keys_against_delegations() {
    let (signer, keys) = signed();
    let mut random = random();
    let signatures = vec![signer.sign(&keys, 1000, 2000, &mut random).unwrap()];
    let validator = DNSSECValidator::default();
    let ds = |digest: DNSSECDigest| signer.delegation(digest, 3600).unwrap();
    for digest in DNSSECDigest::IMPLEMENTED {
        assert!(matches!(validator.verify_keys(&keys, &signatures, &[ds(digest)], 1500), Ok(DNSSECTrust::Secure(_))));
    }
    // A key itself as the anchor.
    assert!(matches!(validator.verify_keys(&keys, &signatures, &keys, 1500), Ok(DNSSECTrust::Secure(_))));
    // RFC 4509 §3: with a DS of SHA-256, one of SHA-1 is ignored.
    let mut wrong = ds(DNSSECDigest::SHA256);
    let DNSData::DS { ref mut digest, .. } = wrong.data else { unreachable!() };
    digest[0] ^= 1;
    let result = validator.verify_keys(&keys, &signatures, &[ds(DNSSECDigest::SHA1), wrong.clone()], 1500);
    assert_eq!(bogus_code(result), DNSExtendedError::DNSKEY_MISSING);
    assert!(matches!(
        validator.verify_keys(&keys, &signatures, &[ds(DNSSECDigest::SHA1), wrong, ds(DNSSECDigest::SHA384)], 1500),
        Ok(DNSSECTrust::Secure(_))
    ));
    // A DS of a digest or algorithm not in use makes the zone insecure (RFC 4035 §5.2).
    let unknown = DNSRecord::new(
        name("example."),
        3600,
        DNSData::DS { key_tag: signer.tag(), algorithm: 15, digest_type: 3, digest: vec![0; 32] },
    );
    assert_eq!(
        validator.verify_keys(&keys, &signatures, &[unknown], 1500),
        Ok(DNSSECTrust::Insecure(DNSExtendedError::UNSUPPORTED_DS_DIGEST_TYPE))
    );
    let policy = DNSSECValidator::new(DNSSECConfig { digests: vec![DNSSECDigest::SHA256], ..DNSSECConfig::default() });
    assert_eq!(
        policy.verify_keys(&keys, &signatures, &[ds(DNSSECDigest::SHA1)], 1500),
        Ok(DNSSECTrust::Insecure(DNSExtendedError::UNSUPPORTED_DS_DIGEST_TYPE))
    );
    let policy = DNSSECValidator::new(DNSSECConfig {
        algorithms: vec![DNSSECAlgorithm::ECDSAP256SHA256],
        ..DNSSECConfig::default()
    });
    assert_eq!(
        policy.verify_keys(&keys, &signatures, &[ds(DNSSECDigest::SHA256)], 1500),
        Ok(DNSSECTrust::Insecure(DNSExtendedError::UNSUPPORTED_DNSKEY_ALGORITHM))
    );
    // A DNSKEY RRset not signed by the key the DS names is bogus.
    let key = DNSSECPrivateKey::generate(DNSSECAlgorithm::ED25519, 0, &mut random_of(4)).unwrap();
    let other = DNSSECSigner::new(name("example."), DNSSECKey::ZONE | DNSSECKey::SECURE_ENTRY_POINT, key);
    let all = [keys.clone(), vec![other.dnskey(3600)]].concat();
    let by_other = vec![other.sign(&all, 1000, 2000, &mut random).unwrap()];
    assert_eq!(
        bogus_code(validator.verify_keys(&all, &by_other, &[ds(DNSSECDigest::SHA256)], 1500)),
        DNSExtendedError::DNSKEY_MISSING
    );
    let by_both = [by_other, vec![signer.sign(&all, 1000, 2000, &mut random).unwrap()]].concat();
    assert!(matches!(
        validator.verify_keys(&all, &by_both, &[ds(DNSSECDigest::SHA256)], 1500),
        Ok(DNSSECTrust::Secure(_))
    ));
    // No anchor of the zone at all is not a proof of anything.
    assert!(validator.verify_keys(&keys, &signatures, &[], 1500).is_err());
}

#[test]
fn denials_of_rfc_6840_and_rfc_9824() {
    let validator = DNSSECValidator::default();
    let apex = name("example.com.");
    let nsec = |text: &str| zone(text);
    // RFC 6840 §4.1: an NSEC of a zone cut denies nothing below it, nor
    // anything but DS at it.
    let cut = nsec(
        "sub.example.com. NSEC zzz.example.com. NS RRSIG NSEC\nexample.com. NSEC sub.example.com. NS SOA RRSIG NSEC DNSKEY",
    );
    assert!(validator.prove_nonexistence(&name("a.sub.example.com."), &apex, &cut).is_err());
    assert!(validator.prove_nodata(&name("sub.example.com."), DNSType::A, &apex, &cut).is_err());
    assert_eq!(validator.prove_nodata(&name("sub.example.com."), DNSType::DS, &apex, &cut), Ok(DNSSECProof::Secure));
    assert_eq!(validator.prove_unsigned_delegation(&name("sub.example.com."), &apex, &cut), Ok(DNSSECProof::Secure));
    // Nor does one of a DNAME (RFC 6672 §5.3.4).
    let dname = nsec(
        "d.example.com. NSEC zzz.example.com. DNAME RRSIG NSEC\nexample.com. NSEC d.example.com. NS SOA RRSIG NSEC DNSKEY",
    );
    assert!(validator.prove_nonexistence(&name("a.d.example.com."), &apex, &dname).is_err());
    // A denial needs the name in the zone.
    assert!(validator.prove_nonexistence(&name("a.example.net."), &apex, &cut).is_err());
    // RFC 9824 §3: Compact Denial with NXNAME, of a name and of an empty non-terminal.
    let compact = nsec("a.example.com. NSEC a\\000.example.com. RRSIG NSEC NXNAME");
    assert_eq!(validator.prove_nonexistence(&name("a.example.com."), &apex, &compact), Ok(DNSSECProof::Secure));
    assert_eq!(validator.prove_nodata(&name("a.example.com."), DNSType::A, &apex, &compact), Ok(DNSSECProof::Secure));
    let empty = nsec("b.example.com. NSEC b\\000.example.com. RRSIG NSEC");
    assert_eq!(validator.prove_nodata(&name("b.example.com."), DNSType::A, &apex, &empty), Ok(DNSSECProof::Secure));
    assert!(validator.prove_nonexistence(&name("b.example.com."), &apex, &empty).is_err());
    // §3.4: the referral of an unsigned delegation.
    let referral = nsec("sub.example.com. 300 IN NSEC sub\\000.example.com. NS RRSIG NSEC");
    assert_eq!(
        validator.prove_unsigned_delegation(&name("sub.example.com."), &apex, &referral),
        Ok(DNSSECProof::Secure)
    );
    // §4: the NSEC3 of a name that does not exist, of the parameters "1 0 0 -".
    let lines = rfc("protocol/dns/rfc9824.txt");
    let start = lines
        .iter()
        .position(|line| line.trim_start().starts_with("H64KFA4P1ACER2EBPS9QSDK6DNP8B3JQ.example.com."))
        .unwrap();
    let records = zone(&lines[start..start + 2].join("\n"));
    let DNSData::NSEC3(ref data) = records[0].data else { unreachable!() };
    assert_eq!(DNSNSEC3::owner(&data.hash(&name("a.example.com.")).unwrap(), &apex).unwrap(), records[0].name);
    assert_eq!(validator.prove_nonexistence(&name("a.example.com."), &apex, &records), Ok(DNSSECProof::Secure));
    assert_eq!(validator.prove_nodata(&name("a.example.com."), DNSType::TXT, &apex, &records), Ok(DNSSECProof::Secure));
}

/// An NSEC3 of `owner` in example. of `iterations` and no salt, to the next hash `next`.
fn nsec3(owner: &str, iterations: u16, next: &[u8], types: &str) -> DNSRecord {
    let hash = DNSNSEC3::digest(DNSNSEC3::SHA1, iterations, &[], &name(owner)).unwrap();
    let owner = DNSNSEC3::owner(&hash, &name("example.")).unwrap();
    let next = Base32::new(Base32::HEX_ALPHABET, Padding::Forbidden).encode(next);
    zone(&format!("{owner} NSEC3 1 0 {iterations} - {next} {types}")).remove(0)
}

#[test]
fn nsec3_parameters_of_rfc_9276_and_rfc_5155() {
    let validator = DNSSECValidator::default();
    let apex = name("example.");
    // A chain of the apex alone: it covers every other hash.
    let alone = |iterations: u16| {
        let next = DNSNSEC3::digest(1, iterations, &[], &apex).unwrap();
        vec![nsec3("example.", iterations, &next, "NS SOA RRSIG DNSKEY NSEC3PARAM")]
    };
    assert_eq!(validator.prove_nonexistence(&name("a.example."), &apex, &alone(0)), Ok(DNSSECProof::Secure));
    assert_eq!(validator.prove_nodata(&apex, DNSType::A, &apex, &alone(0)), Ok(DNSSECProof::Secure));
    // RFC 5155 Erratum 3441: no data at an empty non-terminal of unsigned
    // delegations is an Opt-Out span over it; without Opt-Out, nothing proves it.
    let mut opt_out = alone(0);
    let DNSData::NSEC3(ref mut data) = opt_out[0].data else { unreachable!() };
    data.flags = DNSNSEC3::OPT_OUT;
    assert_eq!(
        validator.prove_nodata(&name("a.example."), DNSType::A, &apex, &opt_out),
        Ok(DNSSECProof::Insecure(None))
    );
    assert!(validator.prove_nodata(&name("a.example."), DNSType::A, &apex, &alone(0)).is_err());
    // RFC 9276 §3.2: more iterations than the limits make it insecure, then bogus.
    assert_eq!(validator.prove_nonexistence(&name("a.example."), &apex, &alone(50)), Ok(DNSSECProof::Secure));
    assert_eq!(
        validator.prove_nonexistence(&name("a.example."), &apex, &alone(51)),
        Ok(DNSSECProof::Insecure(Some(DNSExtendedError::UNSUPPORTED_NSEC3_ITERATIONS)))
    );
    assert_eq!(
        bogus_code(validator.prove_nonexistence(&name("a.example."), &apex, &alone(151))),
        DNSExtendedError::UNSUPPORTED_NSEC3_ITERATIONS
    );
    // RFC 5155 §8.1 and §8.2: NSEC3 of an unknown hash or flags are ignored.
    let mut unknown = alone(0);
    let DNSData::NSEC3(ref mut data) = unknown[0].data else { unreachable!() };
    data.algorithm = 2;
    assert_eq!(
        bogus_code(validator.prove_nonexistence(&name("a.example."), &apex, &unknown)),
        DNSExtendedError::NSEC_MISSING
    );
    let mut flags = alone(0);
    let DNSData::NSEC3(ref mut data) = flags[0].data else { unreachable!() };
    data.flags = 2;
    assert!(validator.prove_nonexistence(&name("a.example."), &apex, &flags).is_err());
    // Records of different parameters are bogus (RFC 5155 §8.2 allows it).
    let mixed = [alone(0), alone(1)].concat();
    assert!(validator.prove_nonexistence(&name("a.example."), &apex, &mixed).is_err());
    // An NSEC3 of a zone other than the one denying is not used.
    assert!(validator.prove_nonexistence(&name("a.sub.example."), &name("sub.example."), &alone(0)).is_err());
}

#[test]
fn trust_anchors_of_rfc_9718() {
    let published = DNSSECTrustAnchor::parse(&Vectors::read("protocol/dns/root-anchors.xml")).unwrap();
    assert_eq!(published.zone, DNSName::root());
    assert_eq!(published.digests.len(), 3);
    let now = 1_793_222_185;
    assert_eq!(published.delegations(now), DNSSECTrustAnchor::root().delegations(now));
    let anchors: Vec<u16> =
        published.digests.iter().filter(|digest| digest.is_valid(now)).map(|digest| digest.key_tag).collect();
    assert_eq!(anchors, [20326, 38696]);
    // KSK-2010 was valid until 2019-01-11; KSK-2024 from 2024-07-18.
    let in_2015 = DNSSECTrustAnchor::time("2015-01-01T00:00:00+00:00").unwrap();
    let tags: Vec<u16> =
        published.digests.iter().filter(|digest| digest.is_valid(in_2015)).map(|digest| digest.key_tag).collect();
    assert_eq!(tags, [19036]);
    assert_eq!(published.digests[0].valid_until, Some(DNSSECTrustAnchor::time("2019-01-11T00:00:00Z").unwrap()));
    // The public keys and flags, which give the digests.
    for digest in &published.digests[1..] {
        let (flags, ref key) = *digest.public_key.as_ref().unwrap();
        let fields = DNSSECKey { flags, protocol: 3, algorithm: DNSSECAlgorithm(digest.algorithm), public_key: key };
        assert_eq!(fields.tag(), digest.key_tag);
        let ds = DNSSECDigest(digest.digest_type).delegation(&DNSName::root(), &fields).unwrap();
        assert!(matches!(ds, DNSData::DS { digest: ref computed, .. } if *computed == digest.digest));
    }
    // §2.3: the example, with its comment.
    let lines = Vectors::read("protocol/dns/rfc9718.txt");
    let start = lines.find("<?xml").unwrap();
    let end = lines[start..].find("</TrustAnchor>").unwrap() + start + "</TrustAnchor>".len();
    let example: String =
        lines[start..end].lines().filter(|line| !crate::RFC::is_page_break(line)).collect::<Vec<_>>().join("\n");
    let example = DNSSECTrustAnchor::parse(&example).unwrap();
    // It gives KSK-2024 without its key, which is optional (§2.1).
    assert_eq!(example.digests[..2], published.digests[..2]);
    assert_eq!(example.digests[2], DNSSECKeyDigest { public_key: None, ..published.digests[2].clone() });
    // xsd:dateTime with offsets and fractions.
    assert_eq!(DNSSECTrustAnchor::time("2017-02-02T00:00:00+00:00"), Ok(1_485_993_600));
    assert_eq!(DNSSECTrustAnchor::time("2017-02-02T09:00:00+09:00"), Ok(1_485_993_600));
    // Not of the form, wherever: fields of other than digits, and text cut inside a character.
    for text in [
        "2017-+2-02T00:00:00Z",
        "2017-02-02T00:00:0\u{e9}",
        "2017-02-02T00:00:00+\u{e9}:00",
        "2017-02-02T00:00:00\u{e9}",
    ] {
        assert!(DNSSECTrustAnchor::time(text).is_err(), "{text}");
    }
    assert_eq!(DNSSECTrustAnchor::time("2017-02-01T23:00:00.5-01:00"), Ok(1_485_993_600));
    for invalid in ["2017-02-02", "2017-13-02T00:00:00Z", "2017-02-02T00:00:00+0900", "2017-02-02T00:00:00."] {
        assert!(DNSSECTrustAnchor::time(invalid).is_err(), "{invalid}");
    }
    assert!(DNSSECTrustAnchor::parse("<TrustAnchor><Zone>.</Zone></TrustAnchor>").is_err());
}
