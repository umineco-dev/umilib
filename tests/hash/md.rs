use umilib::hash::Digest;

use crate::Vectors;

/// The test suite of appendix A.5 of RFC 1320 (MD4) or RFC 1321 (MD5):
/// lines `NAME ("message") = digest`, some of them continued on the next line.
fn suite(path: &str, name: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let text = Vectors::read(path);
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let mut cases = Vec::new();
    let prefix = format!("{name} (\"");
    for (index, line) in lines.iter().enumerate() {
        if let Some(rest) = line.strip_prefix(prefix.as_str()) {
            // Join continuation lines until the digest appears.
            let mut joined = rest.to_string();
            let mut next = index + 1;
            while !joined.contains("\") =") || joined.trim_end().ends_with('=') {
                joined.push_str(lines[next]);
                next += 1;
            }
            let (message, digest) = joined.split_once("\") =").unwrap();
            cases.push((message.as_bytes().to_vec(), Vectors::hex(digest.trim())));
        }
    }
    cases
}

#[cfg(umilib_feature = "hash-md-v4")]
#[test]
fn md4_follows_rfc1320() {
    use umilib::hash::md::v4::MD4;
    let cases = suite("hash/md/rfc1320.txt", "MD4");
    assert_eq!(cases.len(), 7);
    for (message, digest) in cases {
        assert_eq!(MD4::digest(&message).to_vec(), digest, "{}", String::from_utf8_lossy(&message));
        let mut hash = MD4::new();
        message.chunks(3).for_each(|piece| hash.update(piece));
        assert_eq!(hash.finalize().to_vec(), digest);
    }
    assert_eq!((MD4::OUTPUT_SIZE, MD4::BLOCK_SIZE), (16, 64));
}

#[cfg(umilib_feature = "hash-md-v5")]
#[test]
fn md5_follows_rfc1321() {
    use umilib::hash::md::v5::MD5;
    let cases = suite("hash/md/rfc1321.txt", "MD5");
    assert_eq!(cases.len(), 7);
    for (message, digest) in cases {
        assert_eq!(MD5::digest(&message).to_vec(), digest, "{}", String::from_utf8_lossy(&message));
        let mut hash = MD5::new();
        message.chunks(3).for_each(|piece| hash.update(piece));
        assert_eq!(hash.finalize_reset().to_vec(), digest);
    }
    // T[i] = floor(2^32 * |sin(i + 1)|), section 3.4.
    for (index, &value) in MD5::T.iter().enumerate() {
        assert_eq!(value, ((index as f64 + 1.0).sin().abs() * 4294967296.0) as u32, "T[{}]", index + 1);
    }
}
