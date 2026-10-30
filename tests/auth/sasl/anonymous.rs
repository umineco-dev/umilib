//! ANONYMOUS and its "trace" profile against RFC 4505.

use umilib::auth::sasl::SASLError;
use umilib::auth::sasl::anonymous::ANONYMOUSMessage;
use umilib::codec::base::Encoding;
use umilib::codec::base::base64::Base64;

const RFC4505: &str = include_str!("../../vectors/auth/sasl/rfc4505.txt");

#[test]
fn rfc_4505_section_4() {
    let response = super::exchange(RFC4505, "the trace information is")
        .into_iter()
        .find(|(side, text)| *side == 'C' && !text.contains(' '))
        .unwrap();
    let message = ANONYMOUSMessage::decode(&Base64::STANDARD.decode(response.1.as_bytes()).unwrap()).unwrap();
    assert_eq!(message.trace.as_deref(), Some("sirhc"));
    assert!(!message.is_email());
    assert_eq!(Base64::STANDARD.encode(&message.encode().unwrap()), response.1);
}

#[test]
fn trace_follows_rfc_4505_sections_2_and_3() {
    assert_eq!(ANONYMOUSMessage::decode(b"").unwrap(), ANONYMOUSMessage::new(None));
    assert!(ANONYMOUSMessage::decode(b"user@example.com").unwrap().is_email());
    // At most 255 characters, whatever their octets.
    let longest = "é".repeat(255);
    ANONYMOUSMessage::decode(longest.as_bytes()).unwrap();
    assert_eq!(ANONYMOUSMessage::decode("é".repeat(256).as_bytes()), Err(SASLError::Length));
    // The prohibited tables of §3: controls, private use, non-characters, tagging; and bidirectional text.
    for prohibited in ["a\u{0007}", "\u{E000}", "\u{FFFF}", "\u{E0001}", "\u{200E}", "\u{0627}a"] {
        assert!(ANONYMOUSMessage::decode(prohibited.as_bytes()).is_err(), "{prohibited:?}");
    }
    // No mapping and no normalization: what is sent is what is logged.
    let text = "I\u{00AD}X \u{2168}";
    assert_eq!(ANONYMOUSMessage::decode(text.as_bytes()).unwrap().trace.as_deref(), Some(text));
    // Unassigned code points are not prohibited.
    ANONYMOUSMessage::decode("\u{0221}".as_bytes()).unwrap();
}
