//! Content codings (RFC 9110 §8.4, §12.5.3): every one this build has
//! encoded and decoded back, chains of them, their limits, and the
//! negotiation of Accept-Encoding.

use umilib::protocol::http::{
    HTTPAcceptEncoding, HTTPContentCoding, HTTPContentDecoder, HTTPContentEncoder, HTTPError,
};

fn encoded(coding: HTTPContentCoding, data: &[u8]) -> Vec<u8> {
    let mut encoder = HTTPContentEncoder::new(coding).unwrap();
    let mut out = Vec::new();
    for chunk in data.chunks(1000) {
        encoder.encode(chunk, false, &mut out).unwrap();
    }
    encoder.finish(&mut out).unwrap();
    out
}

fn decoded(codings: &[u8], data: &[u8], limit: u64) -> Result<Vec<u8>, HTTPError> {
    let mut decoder = HTTPContentDecoder::new(codings, limit)?;
    let mut out = Vec::new();
    for chunk in data.chunks(333) {
        decoder.decode(chunk, &mut out)?;
    }
    decoder.finish()?;
    Ok(out)
}

#[test]
fn every_coding_round_trips() {
    let data: Vec<u8> = (0..50_000u32).map(|index| (index * 7 % 251) as u8).collect();
    let available = HTTPContentCoding::available();
    assert_eq!(available.len(), 4, "the test runs with every codec");
    for coding in available {
        let coded = encoded(coding, &data);
        assert!(coded.len() < data.len(), "{coding:?}");
        assert_eq!(decoded(coding.name(), &coded, 1 << 20).unwrap(), data, "{coding:?}");
        // Over the limit: a decompression bomb stops there.
        assert!(matches!(decoded(coding.name(), &coded, 1000), Err(HTTPError::TooLarge(_))), "{coding:?}");
        // Cut short: the end of the content shows it.
        assert!(decoded(coding.name(), &coded[..coded.len() / 2], 1 << 20).is_err(), "{coding:?}");
    }
}

#[test]
fn chains_and_names() {
    // RFC 9110 §8.4: codings listed in the order applied, undone in reverse;
    // names compared without case; x-gzip is gzip (§8.4.1.3); identity is none.
    let data = b"chained content, chained content, chained content".repeat(20);
    let coded = encoded(HTTPContentCoding::Brotli, &encoded(HTTPContentCoding::Gzip, &data));
    assert_eq!(decoded(b"GZIP, identity, br", &coded, 1 << 20).unwrap(), data);
    assert_eq!(HTTPContentCoding::parse(b"x-gzip"), Some(HTTPContentCoding::Gzip));
    assert_eq!(decoded(b"identity", b"plain", 100).unwrap(), b"plain");
    assert!(matches!(HTTPContentDecoder::new(b"compress", 100), Err(HTTPError::ContentCoding(_))));
    let mut trailing = encoded(HTTPContentCoding::Zstandard, b"x");
    trailing.extend_from_slice(b"garbage");
    assert!(decoded(b"zstd", &trailing, 100).is_err());
}

#[test]
fn accept_encoding() {
    // RFC 9110 §12.5.3 and its examples; qvalues of §12.4.2.
    let offered = HTTPContentCoding::available();
    let choose = |value: &[u8]| HTTPAcceptEncoding::parse(value).choose(&offered);
    assert_eq!(choose(b"compress, gzip"), Some(HTTPContentCoding::Gzip));
    assert_eq!(choose(b""), None);
    assert_eq!(choose(b"*"), Some(offered[0]));
    assert_eq!(choose(b"compress;q=0.5, gzip;q=1.0"), Some(HTTPContentCoding::Gzip));
    assert_eq!(choose(b"gzip;q=1.0, identity; q=0.5, *;q=0"), Some(HTTPContentCoding::Gzip));
    assert_eq!(choose(b"gzip;q=0, br;q=0.1, zstd;q=0.2"), Some(HTTPContentCoding::Zstandard));
    assert_eq!(choose(b"br;q=0.5, identity"), None);
    assert_eq!(choose(b"*;q=0"), None);
    for (value, weight) in [(&b"1"[..], Some(1000)), (b"1.000", Some(1000)), (b"0.5", Some(500)), (b"0.001", Some(1))] {
        assert_eq!(HTTPAcceptEncoding::weight(value), weight, "{value:?}");
    }
    for invalid in [&b"1.001"[..], b".5", b"2", b"0.0001", b"0.x"] {
        assert_eq!(HTTPAcceptEncoding::weight(invalid), None, "{invalid:?}");
    }
    // A malformed weight leaves its element out.
    assert_eq!(HTTPAcceptEncoding::parse(b"gzip;q=2, br").codings, [(b"br".to_vec(), 1000)]);
}
