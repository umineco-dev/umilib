//! PLAIN against RFC 4616.

use umilib::auth::sasl::SASLError;
use umilib::auth::sasl::plain::PLAINMessage;
use umilib::codec::stringprep::Unassigned;

const RFC4616: &str = include_str!("../../vectors/auth/sasl/rfc4616.txt");

/// The message of an example of RFC 4616 §4, with `<NUL>` as NUL.
fn example(marker: &str) -> Vec<u8> {
    let line = RFC4616.lines().skip_while(|line| !line.contains(marker)).find(|line| line.contains("<NUL>")).unwrap();
    line.trim().trim_start_matches("C: ").replace("<NUL>", "\0").into_bytes()
}

#[test]
fn rfc_4616_section_4() {
    let first = example("The first example shows");
    let message = PLAINMessage::decode(&first).unwrap();
    assert_eq!((message.authzid.as_deref(), message.authcid.as_str()), (None, "tim"));
    assert_eq!(message.password.expose(), "tanstaaftanstaaf");
    assert_eq!(message.encode().unwrap().expose(), &first);
    assert!(message.verify_password("tanstaaftanstaaf"));
    assert!(!message.verify_password("tanstaaftanstaaF"));
    let second = example("The second example shows");
    let message = PLAINMessage::decode(&second).unwrap();
    assert_eq!((message.authzid.as_deref(), message.authcid.as_str()), (Some("Ursel"), "Kurt"));
    assert_eq!(message.password.expose(), "xipj3plmq");
    assert_eq!(message.encode().unwrap().expose(), &second);
}

#[test]
fn messages_follow_rfc_4616_section_2() {
    // message = [authzid] UTF8NUL authcid UTF8NUL passwd, each 1*SAFE.
    for invalid in [&b"tim\0pass"[..], b"\0\0pass", b"\0tim\0", b"a\0b\0c\0d", b"\0tim\0\xFF"] {
        assert!(PLAINMessage::decode(invalid).is_err(), "{invalid:?}");
    }
    // Servers MUST accept fields of 255 octets.
    let long = "é".repeat(127) + "x";
    assert_eq!(long.len(), 255);
    let message = PLAINMessage::new(Some(&long), &long, &long);
    let decoded = PLAINMessage::decode(message.encode().unwrap().expose()).unwrap();
    assert_eq!(decoded.authcid, long);
    assert_eq!(PLAINMessage::new(None, "", "x").encode().map(|_| ()), Err(SASLError::Length));
    assert_eq!(PLAINMessage::new(Some(""), "a", "x").encode().map(|_| ()), Err(SASLError::Length));
    assert_eq!(PLAINMessage::new(None, "a\0b", "x").encode().map(|_| ()), Err(SASLError::Format));
    // SASLprep (RFC 4013 §3): presented strings as queries, stored strings as stored.
    let message = PLAINMessage::new(None, "user", "I\u{00AD}X");
    assert!(message.verify_password("IX"));
    assert!(message.verify_password("\u{2168}"));
    assert_eq!(PLAINMessage::prepare("\u{00AA}", Unassigned::Prohibited), Ok(String::from("a")));
    assert!(PLAINMessage::prepare("\u{0007}", Unassigned::Allowed).is_err());
    assert!(PLAINMessage::prepare("\u{0627}\u{0031}", Unassigned::Allowed).is_err());
    // Preparation that results in an empty string fails verification.
    assert_eq!(PLAINMessage::prepare("\u{00AD}", Unassigned::Allowed), Err(SASLError::Length));
    assert!(!PLAINMessage::new(None, "user", "\u{00AD}").verify_password("\u{00AD}"));
    // An unassigned code point may be presented but not stored (RFC 4616 §2).
    assert!(PLAINMessage::prepare("\u{0221}", Unassigned::Allowed).is_ok());
    assert!(PLAINMessage::prepare("\u{0221}", Unassigned::Prohibited).is_err());
    assert_eq!(PLAINMessage::new(None, "U\u{0301}ser", "x").prepared_authcid(), Ok(String::from("\u{00DA}ser")));
}
