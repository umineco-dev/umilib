//! EXTERNAL against RFC 4422 appendix A.

use umilib::auth::sasl::SASLError;
use umilib::auth::sasl::external::EXTERNALMessage;

#[test]
fn rfc_4422_appendix_a() {
    // A.2: an empty response asks for the identity of the credentials.
    assert_eq!(EXTERNALMessage::decode(b"").unwrap(), EXTERNALMessage::new(None));
    assert_eq!(EXTERNALMessage::new(None).encode().unwrap(), b"");
    // A.2: the authorization identity "fred@example.com".
    let fred = EXTERNALMessage::decode(b"fred@example.com").unwrap();
    assert_eq!(fred.authzid.as_deref(), Some("fred@example.com"));
    assert_eq!(fred.encode().unwrap(), b"fred@example.com");
    // A.1: UTF-8 without NUL.
    assert_eq!(EXTERNALMessage::decode(b"a\0b"), Err(SASLError::Format));
    assert_eq!(EXTERNALMessage::decode(b"\xC3"), Err(SASLError::Format));
    assert_eq!(EXTERNALMessage::new(Some("")).encode(), Err(SASLError::Length));
}
