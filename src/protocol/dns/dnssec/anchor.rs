use alloc::string::String;
use alloc::vec::Vec;

use crate::calendar::Date;
use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;

use super::super::{DNSData, DNSError, DNSName, DNSRecord, DNSToken};

/// A trust anchor of a zone's key (RFC 9718 §2): the digest of a DNSKEY,
/// valid from one time to another (seconds since 1970).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSSECKeyDigest {
    pub id: String,
    pub valid_from: i64,
    pub valid_until: Option<i64>,
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
    /// The key and its flags, which RFC 9718 §2.1 makes optional.
    pub public_key: Option<(u16, Vec<u8>)>,
}

impl DNSSECKeyDigest {
    /// Whether the anchor is valid at `now`: from `valid_from` to before `valid_until` (RFC 9718 §2.2).
    pub fn is_valid(&self, now: i64) -> bool {
        self.valid_from <= now && self.valid_until.is_none_or(|until| now < until)
    }
}

/// The trust anchors of a zone, in the XML that IANA publishes for the root (RFC 9718).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSSECTrustAnchor {
    pub zone: DNSName,
    pub digests: Vec<DNSSECKeyDigest>,
}

impl DNSSECTrustAnchor {
    /// The anchors of the root zone that IANA published at
    /// <https://data.iana.org/root-anchors/root-anchors.xml> as of
    /// 2026-10-29: KSK-2017 (20326) and KSK-2024 (38696). KSK-2010
    /// (19036), valid until 2019-01-11, is left out.
    pub fn root() -> DNSSECTrustAnchor {
        let digest = |id: &str, valid_from: i64, key_tag: u16, digest: [u8; 32]| DNSSECKeyDigest {
            id: String::from(id),
            valid_from,
            valid_until: None,
            key_tag,
            algorithm: 8,
            digest_type: 2,
            digest: digest.to_vec(),
            public_key: None,
        };
        DNSSECTrustAnchor {
            zone: DNSName::root(),
            digests: alloc::vec![
                // 2017-02-02T00:00:00+00:00
                digest(
                    "Klajeyz",
                    1_485_993_600,
                    20326,
                    [
                        0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84,
                        0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D,
                    ]
                ),
                // 2024-07-18T00:00:00+00:00
                digest(
                    "Kmyv6jo",
                    1_721_260_800,
                    38696,
                    [
                        0x68, 0x3D, 0x2D, 0x0A, 0xCB, 0x8C, 0x9B, 0x71, 0x2A, 0x19, 0x48, 0xB2, 0x7F, 0x74, 0x12, 0x19,
                        0x29, 0x8D, 0x0A, 0x45, 0x0D, 0x61, 0x2C, 0x48, 0x3A, 0xF4, 0x44, 0xA4, 0xC0, 0xFB, 0x2B, 0x16,
                    ]
                ),
            ],
        }
    }

    /// The anchors of the XML document `text` (RFC 9718 §2.1): a
    /// TrustAnchor of a Zone and KeyDigest elements. Comments are skipped;
    /// the document is not checked against the whole of XML.
    pub fn parse(text: &str) -> Result<DNSSECTrustAnchor, DNSError> {
        let syntax = DNSError::Syntax("not a trust anchor document");
        let text = DNSSECTrustAnchor::without_comments(text);
        let (_, anchor) = DNSSECTrustAnchor::element(&text, "TrustAnchor").ok_or(syntax)?;
        let (_, zone) = DNSSECTrustAnchor::element(anchor, "Zone").ok_or(syntax)?;
        let zone = DNSName::parse(zone.trim(), None)?;
        let mut digests = Vec::new();
        let mut rest = anchor;
        while let Some((attributes, content)) = DNSSECTrustAnchor::element(rest, "KeyDigest") {
            let field =
                |name: &str| DNSSECTrustAnchor::element(content, name).map(|(_, value)| value.trim()).ok_or(syntax);
            let number = |name: &str| field(name)?.parse::<u16>().map_err(|_| syntax);
            let byte = |name: &str| field(name)?.parse::<u8>().map_err(|_| syntax);
            let valid_until = DNSSECTrustAnchor::attribute(attributes, "validUntil");
            let public_key = match DNSSECTrustAnchor::element(content, "PublicKey") {
                Some((_, key)) => {
                    let key: String = key.split_whitespace().collect();
                    Some((number("Flags")?, Base64::STANDARD.decode(key.as_bytes()).map_err(|_| syntax)?))
                }
                None => None,
            };
            digests.push(DNSSECKeyDigest {
                id: String::from(DNSSECTrustAnchor::attribute(attributes, "id").ok_or(syntax)?),
                valid_from: DNSSECTrustAnchor::time(
                    DNSSECTrustAnchor::attribute(attributes, "validFrom").ok_or(syntax)?,
                )?,
                valid_until: valid_until.map(DNSSECTrustAnchor::time).transpose()?,
                key_tag: number("KeyTag")?,
                algorithm: byte("Algorithm")?,
                digest_type: byte("DigestType")?,
                digest: DNSToken::hex(field("Digest")?.as_bytes())?,
                public_key,
            });
            let end = rest.find("</KeyDigest>").ok_or(syntax)?;
            rest = &rest[end + "</KeyDigest>".len()..];
        }
        if digests.is_empty() {
            return Err(syntax);
        }
        Ok(DNSSECTrustAnchor { zone, digests })
    }

    /// The anchors valid at `now` (seconds since 1970) as DS records, to
    /// check the zone's DNSKEY RRset with ([`super::DNSSECValidator::verify_keys`]).
    pub fn delegations(&self, now: i64) -> Vec<DNSRecord> {
        self.digests
            .iter()
            .filter(|digest| digest.is_valid(now))
            .map(|digest| {
                let data = DNSData::DS {
                    key_tag: digest.key_tag,
                    algorithm: digest.algorithm,
                    digest_type: digest.digest_type,
                    digest: digest.digest.clone(),
                };
                DNSRecord::new(self.zone.clone(), 0, data)
            })
            .collect()
    }

    /// `text` without its comments `<!-- ... -->`.
    pub fn without_comments(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find("<!--") {
            out.push_str(&rest[..start]);
            rest = match rest[start..].find("-->") {
                Some(end) => &rest[start + end + 3..],
                None => "",
            };
        }
        out.push_str(rest);
        out
    }

    /// The attributes and the content of the first element `name` in `text`.
    pub fn element<'a>(text: &'a str, name: &str) -> Option<(&'a str, &'a str)> {
        let mut search = 0;
        loop {
            let start = search + text[search..].find('<')? + 1;
            let after = &text[start..];
            let boundary = after.as_bytes().get(name.len()).copied();
            if after.starts_with(name) && matches!(boundary, Some(b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/')) {
                let open = start + text[start..].find('>')?;
                let attributes = &text[start + name.len()..open];
                if let Some(attributes) = attributes.strip_suffix('/') {
                    return Some((attributes, ""));
                }
                let close = alloc::format!("</{name}>");
                let end = open + 1 + text[open + 1..].find(&close)?;
                return Some((attributes, &text[open + 1..end]));
            }
            search = start;
        }
    }

    /// The value of the attribute `name` in `attributes`, quoted by `"` or `'`.
    pub fn attribute<'a>(attributes: &'a str, name: &str) -> Option<&'a str> {
        let mut rest = attributes;
        loop {
            rest = rest.trim_start();
            let (key, after) = rest.split_once('=')?;
            let after = after.trim_start();
            let quote = after.chars().next().filter(|quote| *quote == '"' || *quote == '\'')?;
            let end = after[1..].find(quote)? + 1;
            if key.trim() == name {
                return Some(&after[1..end]);
            }
            rest = &after[end + 1..];
        }
    }

    /// The seconds since 1970 of the xsd:dateTime `text`: YYYY-MM-DDTHH:MM:SS,
    /// optional fractions, then Z or an offset ±HH:MM (a time without one is taken as UTC).
    pub fn time(text: &str) -> Result<i64, DNSError> {
        let syntax = DNSError::Syntax("not a dateTime");
        let bytes = text.as_bytes();
        if bytes.len() < 19
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
        {
            return Err(syntax);
        }
        // Digits only, of any text: a field cut inside a character is not one.
        let digits = |text: &str, range: core::ops::Range<usize>| {
            let field = text.get(range).filter(|field| field.bytes().all(|byte| byte.is_ascii_digit()));
            field.and_then(|field| field.parse::<i64>().ok()).ok_or(syntax)
        };
        let field = |range: core::ops::Range<usize>| digits(text, range);
        let (year, month, day) = (field(0..4)?, field(5..7)?, field(8..10)?);
        let (hour, minute, second) = (field(11..13)?, field(14..16)?, field(17..19)?);
        // The month and the day have two digits, which fit u8.
        let date = Date::new(year, month as u8, day as u8);
        let date = date.filter(|_| hour <= 23 && minute <= 59 && second <= 60).ok_or(syntax)?;
        let mut rest = text.get(19..).ok_or(syntax)?;
        if let Some(fraction) = rest.strip_prefix('.') {
            let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                return Err(syntax);
            }
            rest = &fraction[digits..];
        }
        let offset = match rest {
            "" | "Z" => 0,
            _ => {
                let sign = match rest.as_bytes()[0] {
                    b'+' => 1,
                    b'-' => -1,
                    _ => return Err(syntax),
                };
                let zone = &rest.as_bytes()[1..];
                if zone.len() != 5 || zone[2] != b':' {
                    return Err(syntax);
                }
                let (hours, minutes) = (digits(rest, 1..3)?, digits(rest, 4..6)?);
                sign * (hours * 3_600 + minutes * 60)
            }
        };
        Ok(date.days() * 86_400 + hour * 3_600 + minute * 60 + second - offset)
    }
}
