//! Tests of `umilib::protocol::icmp`: the multi-part extensions of RFC 4884
//! (against the errors of the Linux kernel) and the rate limit of RFC 4443
//! §2.4 (f).

#[cfg(umilib_feature = "protocol-icmp-v4")]
mod v4;
#[cfg(umilib_feature = "protocol-icmp-v6")]
mod v6;

use std::time::Duration;

use umilib::bytes::Buffer;
use umilib::protocol::ethernet::{EtherType, EthernetHeader};
use umilib::protocol::icmp::{ICMPError, ICMPExtensionObject, ICMPExtensions, ICMPRateLimitConfig, ICMPRateLimiter};
use umilib::runtime::Instant;

use super::Capture;

/// The frames of the ICMP capture whose EtherType is `ether_type`: the
/// description and the packet after the Ethernet header.
pub fn packets(ether_type: EtherType) -> Vec<(String, Vec<u8>)> {
    let mut packets = Vec::new();
    for (description, frame) in Capture::frames("protocol/icmp/linux.txt") {
        let (header, data) = EthernetHeader::decode(&frame).unwrap();
        if header.ether_type == ether_type {
            packets.push((description, data.to_vec()));
        }
    }
    packets
}

#[test]
fn extension_structures() {
    // RFC 4884 §7: version 2, a checksum, and objects of a 4-byte header and a payload.
    let mut objects = Buffer::new();
    ICMPExtensionObject { class: ICMPExtensionObject::INTERFACE_INFORMATION, kind: 0x0B, payload: &[1, 2, 3, 4] }
        .encode(&mut objects)
        .unwrap();
    assert_eq!(objects.as_slice(), &[0, 8, 2, 0x0B, 1, 2, 3, 4]);
    let mut bytes = Buffer::new();
    ICMPExtensions { checksum: 0, objects: objects.as_slice() }.encode(&mut bytes).unwrap();
    let bytes = bytes.into_vec();
    assert_eq!(bytes[0], 0x20);
    assert!(umilib::protocol::ip::InternetChecksum::verify(&bytes));
    let decoded = ICMPExtensions::decode(&bytes).unwrap();
    let objects: Vec<_> = decoded.iter().map(Result::unwrap).collect();
    assert_eq!(objects, [ICMPExtensionObject { class: 2, kind: 0x0B, payload: &[1, 2, 3, 4] }]);
    // An all-zero checksum means none was sent.
    let mut unchecked = bytes.clone();
    unchecked[2..4].copy_from_slice(&[0, 0]);
    assert!(ICMPExtensions::decode(&unchecked).is_ok());
    let mut wrong = bytes.clone();
    wrong[7] ^= 1;
    assert_eq!(ICMPExtensions::decode(&wrong), Err(ICMPError::Checksum));
    let mut version = bytes.clone();
    version[0] = 0x10;
    assert_eq!(ICMPExtensions::decode(&version), Err(ICMPError::Version));
    // An object of a length below its header or beyond the structure.
    for length in [0u16, 3, 9] {
        let mut object = vec![0x20, 0, 0, 0];
        object.extend_from_slice(&length.to_be_bytes());
        object.extend_from_slice(&[2, 1, 0, 0]);
        assert_eq!(ICMPExtensions::decode(&object), Err(ICMPError::Length), "{length}");
    }
    assert_eq!(
        ICMPExtensionObject { class: 1, kind: 1, payload: &[0; 3] }.encode(&mut Buffer::new()),
        Err(ICMPError::Length)
    );
}

#[test]
fn extended_bodies() {
    // RFC 4884 §4: the original datagram padded to the word and to 128
    // bytes, its length in words in the length attribute.
    let objects = [0u8, 8, 2, 1, 9, 9, 9, 9];
    let extensions = ICMPExtensions { checksum: 0, objects: &objects };
    for (original, word, attribute) in [(20usize, 4usize, 32u8), (130, 4, 33), (128, 8, 16), (200, 8, 25)] {
        let data: Vec<u8> = (0..original).map(|index| index as u8).collect();
        let mut body = Buffer::new();
        assert_eq!(extensions.encode_body(&data, word, &mut body), Ok(attribute));
        let body = body.into_vec();
        let (quoted, found) = ICMPExtensions::split_body(&body, attribute, word).unwrap();
        assert_eq!(quoted.len(), attribute as usize * word);
        assert_eq!(&quoted[..original], &data[..]);
        assert!(quoted[original..].iter().all(|&byte| byte == 0));
        assert_eq!(found.unwrap().objects, &objects);
    }
    // Without the attribute the whole body is the original datagram.
    assert_eq!(ICMPExtensions::split_body(&[1, 2, 3], 0, 4), Ok((&[1u8, 2, 3][..], None)));
    assert_eq!(ICMPExtensions::split_body(&[1, 2, 3], 1, 4), Err(ICMPError::Length));
    assert_eq!(ICMPExtensions::split_body(&[0; 8], 2, 4), Ok((&[0u8; 8][..], None)));
    assert_eq!(extensions.encode_body(&[0; 2048], 8, &mut Buffer::new()), Err(ICMPError::Length));
}

#[test]
fn rate_limit_is_a_token_bucket() {
    // RFC 4443 §2.4 (f): bursts of B, an average of N a second; the example B=10, N=10/s.
    let config = ICMPRateLimitConfig::default();
    assert_eq!((config.burst, config.interval), (10, Duration::from_millis(100)));
    let start = Instant::from_nanos(1_000);
    let mut limiter = ICMPRateLimiter::new(config, start);
    assert_eq!((0..15).filter(|_| limiter.allow(start)).count(), 10);
    let at = |milliseconds: u64| start.saturating_add(Duration::from_millis(milliseconds));
    assert!(!limiter.allow(at(99)));
    assert!(limiter.allow(at(100)));
    assert!(!limiter.allow(at(150)));
    assert!(limiter.allow(at(200)));
    // Over a long time the rate is N; the bucket never holds more than B.
    let mut sent = 0;
    for step in 1..=1000u64 {
        if limiter.allow(at(200 + step * 10)) {
            sent += 1;
        }
    }
    assert!((99..=101).contains(&sent), "{sent}");
    let mut idle = ICMPRateLimiter::new(config, start);
    assert_eq!((0..30).filter(|_| idle.allow(at(1_000_000))).count(), 10);
    let mut silent = ICMPRateLimiter::new(ICMPRateLimitConfig { burst: 0, ..config }, start);
    assert!(!silent.allow(at(1_000_000)));
}

#[test]
fn extension_structures_are_checked_when_received() {
    // RFC 4884 §7: one or more objects; §8: objects of whole 32-bit words.
    let structure = |objects: &[u8]| {
        let mut bytes = vec![0x20, 0, 0, 0];
        bytes.extend_from_slice(objects);
        bytes
    };
    assert_eq!(ICMPExtensions::decode(&structure(&[])), Err(ICMPError::Length));
    assert_eq!(ICMPExtensions::decode(&structure(&[0, 6, 2, 1, 9, 9])), Err(ICMPError::Length));
    assert!(ICMPExtensions::decode(&structure(&[0, 8, 2, 1, 9, 9, 9, 9])).is_ok());
    assert_eq!(ICMPExtensions { checksum: 0, objects: &[] }.encode(&mut Buffer::new()), Err(ICMPError::Length));
    assert_eq!(
        ICMPExtensions { checksum: 0, objects: &[0, 6, 2, 1, 9, 9] }.encode(&mut Buffer::new()),
        Err(ICMPError::Length)
    );
    // §4: the original datagram before a structure has at least 128 bytes.
    let objects = [0u8, 8, 2, 1, 9, 9, 9, 9];
    let mut written = Buffer::new();
    ICMPExtensions { checksum: 0, objects: &objects }.encode(&mut written).unwrap();
    let mut short = vec![0u8; 64];
    short.extend_from_slice(written.as_slice());
    assert_eq!(ICMPExtensions::split_body(&short, 16, 4), Err(ICMPError::Length));
    let mut long = vec![0u8; 128];
    long.extend_from_slice(written.as_slice());
    assert!(ICMPExtensions::split_body(&long, 32, 4).unwrap().1.is_some());
    // The words are those of ICMP (32 bits) and ICMPv6 (64 bits) only.
    let extensions = ICMPExtensions { checksum: 0, objects: &objects };
    for word in [0usize, 1, 2, 16, 1 << 20, usize::MAX] {
        assert_eq!(extensions.encode_body(&[0; 8], word, &mut Buffer::new()), Err(ICMPError::Invalid), "{word}");
        assert_eq!(ICMPExtensions::split_body(&long, 1, word), Err(ICMPError::Invalid), "{word}");
    }
}
