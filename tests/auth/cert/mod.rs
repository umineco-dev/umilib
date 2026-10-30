//! Tests of `umilib::auth::cert`.

#[cfg(umilib_feature = "auth-cert-csr")]
mod csr;
#[cfg(umilib_feature = "auth-cert-key")]
mod key;
#[cfg(umilib_feature = "auth-cert-ocsp")]
mod ocsp;
#[cfg(umilib_feature = "auth-cert-path")]
mod path;
#[cfg(umilib_feature = "auth-cert-x509")]
mod x509;

use umilib::codec::asn1::ObjectIdentifier;
use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::SHA256;

/// The generator of the tests (the same bytes on every call).
pub fn random() -> HMACDRBG<SHA256> {
    random_with(7)
}

/// A generator of other bytes than [`random`] for each `seed`.
pub fn random_with(seed: u8) -> HMACDRBG<SHA256> {
    HMACDRBG::<SHA256>::new(&[seed; 32], &[9; 16], b"umilib tests").unwrap()
}

/// The files of a directory of `tests/vectors/auth/cert` (see its `SOURCE`).
pub struct Fixtures(pub &'static str);

impl Fixtures {
    /// The keys and signatures OpenSSL 3.5 made.
    pub const KEY: Fixtures = Fixtures("key/openssl");
    /// The certificates, OCSP requests and OCSP responses OpenSSL 3.5 made.
    pub const OCSP: Fixtures = Fixtures("ocsp/openssl");
    /// The certificates, CRLs and certification requests OpenSSL 3.5 made.
    pub const X509: Fixtures = Fixtures("x509/openssl");

    pub fn path(&self, name: &str) -> String {
        format!("{}/tests/vectors/auth/cert/{}/{name}", env!("CARGO_MANIFEST_DIR"), self.0)
    }

    pub fn text(&self, name: &str) -> String {
        let path = self.path(name);
        std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"))
    }

    pub fn bytes(&self, name: &str) -> Vec<u8> {
        let path = self.path(name);
        std::fs::read(&path).unwrap_or_else(|error| panic!("{path}: {error}"))
    }
}

/// DER built by hand for the tests of refusals.
pub struct DER;

impl DER {
    pub fn element(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let length = content.len();
        if length < 0x80 {
            out.push(length as u8);
        } else if length < 0x100 {
            out.extend_from_slice(&[0x81, length as u8]);
        } else {
            out.extend_from_slice(&[0x82, (length >> 8) as u8, length as u8]);
        }
        out.extend_from_slice(content);
        out
    }

    pub fn sequence(parts: &[&[u8]]) -> Vec<u8> {
        DER::element(0x30, &parts.concat())
    }

    pub fn oid(text: &str) -> Vec<u8> {
        DER::element(0x06, ObjectIdentifier::parse(text).unwrap().as_bytes())
    }

    pub fn integer(value: u8) -> Vec<u8> {
        DER::element(0x02, &[value])
    }
}

/// The PEM examples of an RFC: each with the heading of the section it
/// follows, its label and its data.
pub struct RFCExamples;

impl RFCExamples {
    /// The PEM blocks of `text`, the text of an RFC (indented, possibly cut
    /// by page breaks, whose footer and header lines are skipped).
    pub fn pem_blocks(text: &str) -> Vec<(String, String, Vec<u8>)> {
        let mut blocks = Vec::new();
        let mut heading = String::new();
        let mut lines = text.lines();
        while let Some(line) = lines.next() {
            let trimmed = line.trim();
            let starts_section = line.chars().next().is_some_and(|first| first.is_ascii_alphanumeric())
                && line
                    .split_whitespace()
                    .next()
                    .is_some_and(|number| number.ends_with('.') && number.contains(|c: char| c.is_ascii_digit()));
            if starts_section {
                heading = trimmed.to_string();
                continue;
            }
            let Some(label) = trimmed.strip_prefix("-----BEGIN ").and_then(|rest| rest.strip_suffix("-----")) else {
                continue;
            };
            let mut base64 = String::new();
            for body in lines.by_ref() {
                let body = body.trim();
                if body.starts_with("-----END ") {
                    break;
                }
                // Page footers and headers (and blank lines) are not base64.
                if body.is_empty() || body.contains(' ') || body.starts_with('\u{c}') {
                    continue;
                }
                base64.push_str(body);
            }
            let pem = format!("-----BEGIN {label}-----\n{base64}\n-----END {label}-----\n");
            let document = umilib::codec::pem::PEMDocument::decode(pem.as_bytes(), Default::default())
                .unwrap_or_else(|error| panic!("{heading}: {error:?}"));
            blocks.push((heading.clone(), label.to_string(), document.into_data()));
        }
        blocks
    }
}
