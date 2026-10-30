//! OAUTHBEARER against RFC 7628.

use umilib::auth::sasl::oauthbearer::{OAUTHBEARERErrorResult, OAUTHBEARERMessage};
use umilib::auth::sasl::{GS2ChannelBinding, SASLError};
use umilib::codec::base::Encoding;
use umilib::codec::base::base64::Base64;

const RFC7628: &str = include_str!("../../vectors/auth/sasl/rfc7628.txt");

/// The base64 payloads of the client lines of the example after `marker`.
fn payloads(marker: &str, side: char) -> Vec<Vec<u8>> {
    super::exchange(RFC7628, marker)
        .into_iter()
        .filter(|(own, _)| *own == side)
        .filter_map(|(_, text)| text.rsplit(' ').next().and_then(|last| Base64::STANDARD.decode(last.as_bytes()).ok()))
        .filter(|payload| !payload.is_empty())
        .collect()
}

#[test]
fn rfc_7628_section_4_1() {
    let imap = payloads("4.1.  Successful Bearer Token Exchange", 'C');
    let message = OAUTHBEARERMessage::decode(imap.last().unwrap()).unwrap();
    assert_eq!(message.header.channel_binding, GS2ChannelBinding::Unsupported);
    assert_eq!(message.header.authzid.as_deref(), Some("user@example.com"));
    assert_eq!((message.host(), message.port()), (Some("server.example.com"), Some(143)));
    assert_eq!(message.bearer_token(), Some("vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg=="));
    let made = OAUTHBEARERMessage::new(
        Some("user@example.com"),
        "vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==",
        Some("server.example.com"),
        Some(143),
    );
    assert_eq!(&made.encode().unwrap(), imap.last().unwrap());
    let smtp = payloads("The same credential used in an SMTP exchange", 'C');
    assert_eq!(OAUTHBEARERMessage::decode(smtp.last().unwrap()).unwrap().port(), Some(587));
}

#[test]
fn rfc_7628_section_4_3() {
    let client = payloads("4.3.  Failed Exchange", 'C');
    let message = OAUTHBEARERMessage::decode(&client[0]).unwrap();
    assert_eq!(message.auth(), Some(""));
    assert_eq!(message.bearer_token(), None);
    // The server's error result, and the client's dummy response.
    let server = payloads("4.3.  Failed Exchange", 'S');
    let result = OAUTHBEARERErrorResult::decode(&server[0]).unwrap();
    assert_eq!(result.status, "invalid_token");
    assert_eq!(result.scope.as_deref(), Some("example_scope"));
    assert_eq!(result.openid_configuration.as_deref(), Some("https://example.com/.well-known/openid-configuration"));
    assert_eq!(OAUTHBEARERErrorResult::decode(&result.encode()).unwrap(), result);
    assert!(OAUTHBEARERMessage::is_dummy(&client[1]));
    assert_eq!(client[1], OAUTHBEARERMessage::DUMMY);
}

#[test]
fn rfc_7628_section_4_4_with_erratum_8564() {
    // The example writes the authorization identity as "user=", which the
    // GS2 header of RFC 5801 does not have; erratum 8564 corrects it to "a=".
    let client = payloads("4.4.  SMTP Example of a Failed Negotiation", 'C');
    assert_eq!(OAUTHBEARERMessage::decode(&client[0]), Err(SASLError::Format));
    let corrected = String::from_utf8(client[0].clone()).unwrap().replacen("n,user=", "n,a=", 1);
    let message = OAUTHBEARERMessage::decode(corrected.as_bytes()).unwrap();
    assert_eq!(message.header.authzid.as_deref(), Some("someuser@example.com"));
}

#[test]
fn responses_follow_rfc_7628_section_3_1() {
    // client-resp = gs2-header kvsep *kvpair kvsep; a key is letters, a value VCHAR, SP, HTAB, CR or LF.
    let valid = b"n,,\x01auth=Bearer abc\x01unknown=kept\x01\x01";
    let message = OAUTHBEARERMessage::decode(valid).unwrap();
    assert_eq!(message.get("unknown"), Some("kept"));
    assert_eq!(message.encode().unwrap(), valid);
    // auth is REQUIRED; only the dummy response has no pairs (RFC 7628 §3.1).
    assert_eq!(OAUTHBEARERMessage::decode(b"n,,\x01\x01"), Err(SASLError::Format));
    assert_eq!(OAUTHBEARERMessage::decode(b"n,,\x01host=x\x01\x01"), Err(SASLError::Format));
    for invalid in [
        &b"n,,\x01auth=x\x01"[..],
        b"n,,auth=x\x01\x01",
        b"n,,\x01au1h=x\x01\x01",
        b"n,,\x01auth=\xC3\xA9\x01\x01",
        b"n,,\x01auth=x\x01auth=y\x01\x01",
        b"n,,\x01noequals\x01\x01",
        b"\x01",
    ] {
        assert!(OAUTHBEARERMessage::decode(invalid).is_err(), "{invalid:?}");
    }
    // port: a positive decimal without leading zeros; auth: Bearer in any case (RFC 7628 §4).
    let read = |pairs: &str| OAUTHBEARERMessage::decode(format!("n,,\x01{pairs}\x01\x01").as_bytes());
    for port in ["0143", "0", "65536", "", "+1"] {
        assert_eq!(read(&format!("port={port}\x01auth=Bearer x")), Err(SASLError::Format), "{port}");
    }
    assert_eq!(read("port=1\x01auth=Bearer x").unwrap().port(), Some(1));
    let message = |pairs: &str| read(pairs).unwrap();
    assert_eq!(message("auth=BeArEr abc-._~+/=").bearer_token(), Some("abc-._~+/="));
    assert_eq!(message("auth=Bearer").bearer_token(), None);
    assert_eq!(message("auth=Bearer a=b").bearer_token(), None);
    assert_eq!(message("auth=Basic abc").bearer_token(), None);
    // What encode writes, decode reads: the same rules apply.
    assert_eq!(OAUTHBEARERMessage::new(None, "x", None, Some(0)).encode(), Err(SASLError::Format));
    let mut twice = OAUTHBEARERMessage::new(None, "x", None, None);
    twice.pairs.push((String::from("auth"), String::from("Bearer y")));
    assert_eq!(twice.encode(), Err(SASLError::Format));
    twice.pairs.clear();
    assert_eq!(twice.encode(), Err(SASLError::Format), "no auth");
    // status is required in an error result.
    assert_eq!(OAUTHBEARERErrorResult::decode(br#"{"scope":"x"}"#), Err(SASLError::Format));
    assert_eq!(OAUTHBEARERErrorResult::decode(br#"{"status":1}"#), Err(SASLError::Format));
}
