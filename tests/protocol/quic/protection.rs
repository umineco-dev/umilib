//! Packet protection with the samples of RFC 9001 Appendix A (version 1)
//! and RFC 9369 Appendix A (version 2): Initial secrets and keys, the
//! client's and server's Initial packets, the Retry Integrity Tag, and a
//! short header packet under ChaCha20-Poly1305 with its key update.

use umilib::protocol::quic::{
    QUICConnectionID, QUICHeader, QUICHeaderProtection, QUICPacket, QUICPacketNumber, QUICRetryIntegrity, QUICRole,
    QUICSecret, QUICVersion, QUICVersionProfile,
};
use umilib::protocol::tls::TLSCipherSuite;
use umilib::secret::Secret;

use super::QUICVectors;
use crate::{RFC, Vectors};

/// The sample packets of one RFC: 9001 for version 1, 9369 for version 2.
struct Sample {
    rfc: u32,
    profile: &'static QUICVersionProfile,
}

impl Sample {
    fn all() -> Vec<Sample> {
        let mut samples = Vec::new();
        if let Some(profile) = QUICVersion::V1.profile() {
            samples.push(Sample { rfc: 9001, profile });
        }
        if let Some(profile) = QUICVersion::V2.profile() {
            samples.push(Sample { rfc: 9369, profile });
        }
        samples
    }

    fn text(&self, start: &str, end: &str) -> String {
        RFC::section(&QUICVectors::path(self.rfc), start, end)
    }

    /// The hexadecimal value of `marker` in `text`: the rest of the line that
    /// is `marker` or contains it, after "=", if that is hexadecimal;
    /// otherwise the first run of lines of only "=" and hexadecimal after it.
    fn value(text: &str, marker: &str) -> Vec<u8> {
        let lines: Vec<&str> = text.lines().collect();
        let index = lines
            .iter()
            .position(|line| line.trim() == marker)
            .or_else(|| lines.iter().position(|line| line.contains(marker)))
            .unwrap_or_else(|| panic!("no {marker}"));
        let is_hex = |part: &str| !part.is_empty() && part.chars().all(|character| character.is_ascii_hexdigit());
        let hexadecimal = |line: &str| {
            let part = line.trim().trim_start_matches('=').trim().replace(' ', "");
            is_hex(&part).then_some(part)
        };
        if let Some((_, rest)) = lines[index].split_once(" = ")
            && let Some(value) = hexadecimal(rest)
        {
            return Vectors::hex(&value);
        }
        let hex: String = lines[index + 1..]
            .iter()
            .skip_while(|line| hexadecimal(line).is_none())
            .map_while(|line| hexadecimal(line))
            .collect();
        assert!(!hex.is_empty(), "no value after {marker}");
        Vectors::hex(&hex)
    }

    fn destination() -> QUICConnectionID {
        QUICConnectionID::new(&Vectors::hex("8394c8f03e515708")).unwrap()
    }
}

#[test]
fn initial_secrets_and_keys() {
    for sample in Sample::all() {
        let keys = sample.text("A.1.  Keys", "A.2.");
        for (role, start, end) in [
            (QUICRole::Client, "client_initial_secret", "The secrets for protecting server"),
            (QUICRole::Server, "server_initial_secret", "A.2."),
        ] {
            let text: String = keys
                .lines()
                .skip_while(|line| !line.contains(start))
                .take_while(|line| !line.contains(end))
                .collect::<Vec<_>>()
                .join("\n");
            let secret = QUICSecret::initial(sample.profile, &Sample::destination(), role).unwrap();
            assert_eq!(secret.secret.expose().as_slice(), Sample::value(&text, start), "{} {role:?}", sample.rfc);
            let key = secret.packet_key(sample.profile).unwrap();
            assert_eq!(key.iv.to_vec(), Sample::value(&text, "iv  = HKDF-Expand-Label"), "{}", sample.rfc);
            // The key and the header protection key show in the packets below.
            assert!(secret.header_protection(sample.profile).is_ok());
        }
    }
}

#[test]
fn client_initial() {
    for sample in Sample::all() {
        let text = sample.text("A.2.  Client Initial", "A.3.");
        let mut payload =
            Vectors::hex(&RFC::block(&QUICVectors::path(sample.rfc), "frames to make a 1162-byte payload:", None));
        payload.resize(1162, 0);
        let header = Sample::value(&text, "packet number of 2:");
        let protected =
            Vectors::hex(&RFC::block(&QUICVectors::path(sample.rfc), "The resulting protected packet is:", None));
        let secret = QUICSecret::initial(sample.profile, &Sample::destination(), QUICRole::Client).unwrap();
        let key = secret.packet_key(sample.profile).unwrap();
        let protection = secret.header_protection(sample.profile).unwrap();
        // RFC 9001 §5.4.2: the sample and its mask.
        let mask = protection.mask(&Sample::value(&text, "sample = ").try_into().unwrap());
        assert_eq!(mask.to_vec(), Sample::value(&text, "mask = AES-ECB"), "{}", sample.rfc);
        // Protecting the packet gives the bytes of the RFC.
        let mut packet = header.clone();
        packet.extend_from_slice(&payload);
        key.seal(2, header.len(), &mut packet).unwrap();
        protection.apply(&mut packet, header.len() - 4, 4).unwrap();
        assert_eq!(packet, protected, "{}", sample.rfc);
        // And the server reads it back.
        let mut received = protected.clone();
        let QUICPacket::Protected(parsed) = QUICPacket::decode(&protected, 0).unwrap() else { panic!() };
        assert_eq!(parsed.header.packet_type(), umilib::protocol::quic::QUICPacketType::Initial);
        let (length, truncated) = protection.remove(&mut received, parsed.number_offset).unwrap();
        assert_eq!((length, QUICPacketNumber::decode(truncated, length, None)), (4, 2));
        assert_eq!(received[..header.len()], header[..]);
        let plaintext = key.open(2, header.len(), &mut received).unwrap();
        assert_eq!(received[header.len()..header.len() + plaintext], payload[..]);
        // A changed byte does not authenticate.
        let mut corrupted = protected.clone();
        corrupted[100] ^= 1;
        let (length, truncated) = protection.remove(&mut corrupted, parsed.number_offset).unwrap();
        let number = QUICPacketNumber::decode(truncated, length, None);
        assert!(key.open(number, parsed.number_offset + length, &mut corrupted).is_err());
    }
}

#[test]
fn server_initial() {
    for sample in Sample::all() {
        let text = sample.text("A.3.  Server Initial", "A.4.");
        let path = QUICVectors::path(sample.rfc);
        let payload = Vectors::hex(&RFC::block(&path, "frame, a CRYPTO frame, and no PADDING frames:", None));
        let header = Sample::value(&text, "packet number of 1:");
        let protected = Vectors::hex(&RFC::block(&path, "The final protected packet is then:", None));
        let secret = QUICSecret::initial(sample.profile, &Sample::destination(), QUICRole::Server).unwrap();
        let key = secret.packet_key(sample.profile).unwrap();
        let protection = secret.header_protection(sample.profile).unwrap();
        let mut packet = header.clone();
        packet.extend_from_slice(&payload);
        key.seal(1, header.len(), &mut packet).unwrap();
        protection.apply(&mut packet, header.len() - 2, 2).unwrap();
        assert_eq!(packet, protected, "{}", sample.rfc);
        // The client reads it, its packet number in 2 bytes.
        let QUICPacket::Protected(parsed) = QUICPacket::decode(&protected, 0).unwrap() else { panic!() };
        let QUICHeader::Long(long) = parsed.header else { panic!() };
        assert_eq!(long.version, sample.profile.version);
        let mut received = protected.clone();
        let (length, truncated) = protection.remove(&mut received, parsed.number_offset).unwrap();
        assert_eq!((length, truncated), (2, 1));
        let plaintext = key.open(1, parsed.number_offset + 2, &mut received).unwrap();
        assert_eq!(&received[header.len()..header.len() + plaintext], &payload[..]);
    }
}

#[test]
fn retry_integrity() {
    for sample in Sample::all() {
        let path = QUICVectors::path(sample.rfc);
        let retry = Vectors::hex(&RFC::block(&path, "value is not included in the final Retry packet:", None));
        let (body, tag) = retry.split_at(retry.len() - 16);
        let computed = QUICRetryIntegrity::tag(sample.profile, &Sample::destination(), body).unwrap();
        assert_eq!(&computed[..], tag, "{}", sample.rfc);
        assert!(QUICRetryIntegrity::verify(sample.profile, &Sample::destination(), &retry));
        // Another original Destination Connection ID, or a changed packet, fails.
        let other = QUICConnectionID::new(&[1; 8]).unwrap();
        assert!(!QUICRetryIntegrity::verify(sample.profile, &other, &retry));
        let mut changed = retry.clone();
        changed[10] ^= 0x80;
        assert!(!QUICRetryIntegrity::verify(sample.profile, &Sample::destination(), &changed));
        assert!(!QUICRetryIntegrity::verify(sample.profile, &Sample::destination(), &retry[..15]));
        assert!(matches!(QUICPacket::decode(&retry, 0).unwrap(), QUICPacket::Retry(_)));
    }
}

#[test]
fn chacha20_short_header() {
    for sample in Sample::all() {
        let text = sample.text("A.5.  ChaCha20-Poly1305 Short Header Packet", "Appendix B");
        let secret = Secret::new(Sample::value(&text, "secret"));
        let secret = QUICSecret::new(TLSCipherSuite::TLS_CHACHA20_POLY1305_SHA256, secret).unwrap();
        let key = secret.packet_key(sample.profile).unwrap();
        assert_eq!(key.iv.to_vec(), Sample::value(&text, "iv  = HKDF-Expand-Label"));
        // The nonce of packet 654360564 (RFC 9001 §5.3).
        assert_eq!(key.nonce(654_360_564).to_vec(), Sample::value(&text, "nonce              = "));
        // The secret after a key update (RFC 9001 §6.1).
        let next = secret.next(sample.profile).unwrap();
        assert_eq!(next.secret.expose().as_slice(), Sample::value(&text, "ku  = HKDF-Expand-Label"));
        let protection = secret.header_protection(sample.profile).unwrap();
        let mask = protection.mask(&Sample::value(&text, "sample = ").try_into().unwrap());
        assert_eq!(mask.to_vec(), Sample::value(&text, "mask   = "));
        // A PING in a 3-byte packet number: the smallest packet, 21 bytes.
        let header = Sample::value(&text, "unprotected header = ");
        let mut packet = header.clone();
        packet.push(0x01);
        key.seal(654_360_564, header.len(), &mut packet).unwrap();
        assert_eq!(packet[header.len()..].to_vec(), Sample::value(&text, "payload ciphertext = "));
        protection.apply(&mut packet, 1, 3).unwrap();
        let expected = Sample::value(&text, "packet = ");
        assert_eq!(packet, expected, "{}", sample.rfc);
        assert_eq!(packet.len(), 21);
        // Read back: an empty Destination Connection ID, the key phase 0.
        let QUICPacket::Protected(parsed) = QUICPacket::decode(&expected, 0).unwrap() else { panic!() };
        let mut received = expected.clone();
        let (length, truncated) = protection.remove(&mut received, parsed.number_offset).unwrap();
        assert_eq!(received[0] & 0x04, 0);
        let number = QUICPacketNumber::decode(truncated, length, Some(654_360_563));
        assert_eq!(number, 654_360_564);
        let plaintext = key.open(number, 1 + length, &mut received).unwrap();
        assert_eq!(&received[1 + length..1 + length + plaintext], &[0x01]);
        // One byte shorter has no whole sample and is discarded (RFC 9001 §5.4.2).
        assert!(QUICHeaderProtection::sample(&expected[..20], 1).is_err());
    }
}

#[test]
fn suites_without_header_protection() {
    // RFC 9001 §5.3: TLS_AES_128_CCM_8_SHA256 has no header protection scheme.
    let secret = Secret::new(vec![0; 32]);
    assert!(QUICSecret::new(TLSCipherSuite::TLS_AES_128_CCM_8_SHA256, secret.clone()).is_err());
    for suite in [TLSCipherSuite::TLS_AES_128_GCM_SHA256, TLSCipherSuite::TLS_CHACHA20_POLY1305_SHA256] {
        assert!(QUICSecret::new(suite, secret.clone()).is_ok());
    }
    let secret = QUICSecret::new(TLSCipherSuite::TLS_AES_256_GCM_SHA384, Secret::new(vec![0; 48])).unwrap();
    assert_eq!(
        secret.next(QUICVersion::V1.profile().or(QUICVersion::V2.profile()).unwrap()).unwrap().secret.expose().len(),
        48
    );
    // RFC 9001 §6.6: the limits of AES-GCM and ChaCha20-Poly1305.
    let profile = QUICVersionProfile::ALL[0];
    let key =
        QUICSecret::initial(profile, &QUICConnectionID::EMPTY, QUICRole::Client).unwrap().packet_key(profile).unwrap();
    assert_eq!((key.confidentiality_limit(), key.integrity_limit()), (1 << 23, 1 << 52));
    let chacha = QUICSecret::new(TLSCipherSuite::TLS_CHACHA20_POLY1305_SHA256, Secret::new(vec![0; 32])).unwrap();
    let key = chacha.packet_key(profile).unwrap();
    assert_eq!(key.integrity_limit(), 1 << 36);
}

#[test]
fn packet_number_lengths_of_header_protection() {
    // RFC 9000 §17.1: packet numbers of 1 to 4 bytes; other lengths are refused, not a panic.
    let secret =
        QUICSecret::initial(Sample::all()[0].profile, &QUICConnectionID::new(&[1; 8]).unwrap(), QUICRole::Client)
            .unwrap();
    let protection = secret.header_protection(Sample::all()[0].profile).unwrap();
    let mut packet = vec![0x40; 64];
    for length in 1..=4 {
        protection.apply(&mut packet, 9, length).unwrap();
    }
    for length in [0, 5, 40] {
        assert!(protection.apply(&mut packet, 9, length).is_err());
    }
}
