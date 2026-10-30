//! Tests of `umilib::protocol::jwt`: JWK, JWS, JWE and JWT against RFC 7515
//! to RFC 7520, RFC 7638, RFC 7797, RFC 8037, RFC 8725, RFC 9278, RFC 9864,
//! RFC 9964, the JOSE Cookbook and Project Wycheproof.

mod jwe;
mod jwk;
mod jws;
// The tests of each module have its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod jwt;

use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::SHA256;
use umilib::protocol::jwt::JWK;

use crate::{Json, RFC, Vectors};

/// The generator of the tests (the same bytes on every run).
pub fn random() -> HMACDRBG<SHA256> {
    HMACDRBG::<SHA256>::new(&[7; 32], &[9; 16], b"umilib jwt tests").unwrap()
}

/// The generator of the decryptions, apart from that of the encryptions:
/// a key that fails to decrypt continues as a random one (RFC 7516 §11.5),
/// which the same generator would make equal to the key it replaces.
pub fn decrypting() -> HMACDRBG<SHA256> {
    HMACDRBG::<SHA256>::new(&[11; 32], &[13; 16], b"umilib jwe decryption").unwrap()
}

/// The path of a file of `tests/vectors/protocol/jwt`.
pub fn path(name: &str) -> String {
    format!("protocol/jwt/{name}")
}

/// The JWK of the JSON value `value`.
pub fn jwk(value: &Json) -> JWK {
    JWK::from_json(value.encode().as_bytes()).unwrap_or_else(|error| panic!("{}: {error:?}", value.encode()))
}

/// The members of a JSON object, sorted at every depth, for comparisons
/// that ignore the order of members.
pub fn sorted(value: &Json) -> Vec<(String, String)> {
    let Json::Object(members) = canonical(value) else { panic!("{value:?} is not an object") };
    members.into_iter().map(|(key, value)| (key, value.encode())).collect()
}

/// `value` with the members of each object sorted by name.
pub fn canonical(value: &Json) -> Json {
    match value {
        Json::Object(members) => {
            let mut members: Vec<(String, Json)> =
                members.iter().map(|(key, value)| (key.clone(), canonical(value))).collect();
            members.sort_by(|first, second| first.0.cmp(&second.0));
            Json::Object(members)
        }
        Json::Array(items) => Json::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

/// The lines of `text` after the line containing `marker`, up to the next
/// blank line once one is taken: trimmed, page breaks left out, joined.
pub fn folded(text: &str, marker: &str) -> String {
    let mut lines = text.lines().skip_while(|line| !line.contains(marker)).skip(1);
    let mut out = String::new();
    for line in lines.by_ref().filter(|line| !RFC::is_page_break(line)) {
        if line.trim().is_empty() {
            if out.is_empty() {
                continue;
            }
            break;
        }
        out.push_str(line.trim());
    }
    assert!(!out.is_empty(), "nothing after {marker}");
    out
}

/// The first JSON object of `text` from the line containing `marker`,
/// folded lines joined and page breaks left out.
pub fn object(text: &str, marker: &str) -> Json {
    let joined: String = text
        .lines()
        .skip_while(|line| !line.contains(marker))
        .filter(|line| !RFC::is_page_break(line))
        .map(str::trim)
        .collect();
    let start = joined.find('{').unwrap_or_else(|| panic!("no object after {marker}"));
    let mut depth = 0;
    for (index, character) in joined[start..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Json::from_text(&joined[start..=start + index]);
                }
            }
            _ => {}
        }
    }
    panic!("an unterminated object after {marker}")
}

/// The octets of the decimal JSON array after the line containing `marker`.
pub fn decimals(text: &str, marker: &str) -> Vec<u8> {
    let array = folded(text, marker);
    array
        .trim_matches(|character| matches!(character, '[' | ']' | '.'))
        .split(',')
        .map(|value| value.trim().parse().unwrap())
        .collect()
}

/// The octets of the first lines of hexadecimal pairs after the line
/// containing `marker`, page breaks left out.
pub fn hexadecimal(text: &str, marker: &str) -> Vec<u8> {
    let is_hexadecimal = |line: &&str| {
        let line = line.trim();
        !line.is_empty() && line.chars().all(|character| character.is_ascii_hexdigit() || character == ' ')
    };
    let digits: String = text
        .lines()
        .skip_while(|line| !line.contains(marker))
        .skip(1)
        .filter(|line| !RFC::is_page_break(line))
        .skip_while(|line| !is_hexadecimal(line))
        .take_while(is_hexadecimal)
        .collect::<String>()
        .replace(' ', "");
    Vectors::hex(&digits)
}
