//! The GS2 header (RFC 5801 §4, RFC 5802 §7) and the mechanism names (RFC 4422 §3.1).

use umilib::auth::sasl::{GS2ChannelBinding, GS2Header, SASLError, SASLMechanism};

#[test]
fn headers_follow_rfc_5801_section_4() {
    let cases = [
        ("n,,", GS2Header::new(GS2ChannelBinding::Unsupported, None)),
        ("y,,", GS2Header::new(GS2ChannelBinding::NotOffered, None)),
        ("p=tls-exporter,,", GS2Header::new(GS2ChannelBinding::Required("tls-exporter".into()), None)),
        ("n,a=user@example.com,", GS2Header::new(GS2ChannelBinding::Unsupported, Some("user@example.com"))),
        ("n,a=a=2Cb=3Dc,", GS2Header::new(GS2ChannelBinding::Unsupported, Some("a,b=c"))),
        ("F,n,,", GS2Header { nonstandard: true, ..GS2Header::new(GS2ChannelBinding::Unsupported, None) }),
    ];
    for (text, header) in cases {
        assert_eq!(header.encode().unwrap(), text);
        let message = format!("{text}rest");
        assert_eq!(GS2Header::decode(&message).unwrap(), (header, "rest"), "{text}");
    }
    // saslname: '=' only before 2C or 3D; no ',' or NUL; not empty. The flag is n, y or p=cb-name.
    for text in ["n,a=a=2D,", "n,a=,", "n,user=x,", "x,,", "p=,,", "p=tls unique,,", "n", "n,a=x"] {
        assert_eq!(GS2Header::decode(text).map(|_| ()), Err(SASLError::Format), "{text}");
    }
    assert_eq!(GS2Header::new(GS2ChannelBinding::Unsupported, Some("")).encode(), Err(SASLError::Format));
    assert_eq!(GS2Header::new(GS2ChannelBinding::Required("a,b".into()), None).encode(), Err(SASLError::Format));
}

#[test]
fn mechanism_names_follow_rfc_4422_section_3_1() {
    for mechanism in SASLMechanism::ALL {
        assert!(SASLMechanism::is_name(mechanism.name()), "{}", mechanism.name());
        assert_eq!(SASLMechanism::from_name(mechanism.name()), Some(mechanism));
    }
    assert_eq!(SASLMechanism::from_name("scram-sha-256"), None, "names are upper case");
    assert!(SASLMechanism::is_name("X_TWENTY-CHARACTERS1"));
    assert!(!SASLMechanism::is_name("X_TWENTY-ONE-CHARACTE"));
    assert!(!SASLMechanism::is_name(""));
    assert!(!SASLMechanism::is_name("Plain"));
    assert!(SASLMechanism::SCRAMSHA256PLUS.is_plus() && !SASLMechanism::SCRAMSHA256.is_plus());
}
