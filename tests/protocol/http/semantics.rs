//! The semantics every version shares (RFC 9110): methods, status codes,
//! versions, fields, targets and authorities, requests, and priorities (RFC 9218).

use umilib::protocol::http::{
    HTTPAuthority, HTTPError, HTTPField, HTTPFields, HTTPMethod, HTTPPriority, HTTPRequest, HTTPStatus, HTTPSyntax,
    HTTPTarget, HTTPVersion,
};

use crate::Vectors;

#[test]
fn methods() {
    // RFC 9110 §9.2.1, §9.2.2, Table 4 of §18.2, and RFC 10008 §2 (QUERY).
    let table = [
        ("GET", true, true),
        ("HEAD", true, true),
        ("POST", false, false),
        ("PUT", false, true),
        ("DELETE", false, true),
        ("CONNECT", false, false),
        ("OPTIONS", true, true),
        ("TRACE", true, true),
        ("PATCH", false, false),
        ("QUERY", true, true),
    ];
    for (name, safe, idempotent) in table {
        let method = HTTPMethod::parse(name.as_bytes()).unwrap();
        assert_eq!(method.as_bytes(), name.as_bytes());
        assert_eq!((method.is_safe(), method.is_idempotent()), (safe, idempotent), "{name}");
        assert!(!matches!(method, HTTPMethod::Other(_)), "{name}");
    }
    // Methods are case-sensitive tokens (RFC 9110 §9.1).
    assert_eq!(HTTPMethod::parse(b"get").unwrap(), HTTPMethod::Other(b"get".to_vec().into()));
    assert!(!HTTPMethod::parse(b"PROPFIND").unwrap().is_safe());
    for invalid in [&b""[..], b"GE T", b"GET\r", b"(GET)"] {
        assert!(HTTPMethod::parse(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn status_codes() {
    // RFC 9110 §15: three digits, 100 to 599; the reason phrases of its sections.
    let text = Vectors::read("protocol/http/rfc9110.txt");
    let mut checked = 0;
    for line in text.lines() {
        // Headings such as "15.3.1.  200 OK".
        let Some((number, title)) = line.strip_prefix("15.").and_then(|rest| rest.split_once(".  ")) else { continue };
        if number.matches('.').count() != 1 {
            continue;
        }
        let Some((code, reason)) = title.split_once(' ') else { continue };
        let Some(status) = HTTPStatus::parse(code.as_bytes()) else { continue };
        assert_eq!(status.reason(), reason.trim(), "{code}");
        checked += 1;
    }
    assert!(checked >= 40, "{checked} status codes");
    assert_eq!(HTTPStatus::parse(b"099"), None);
    assert_eq!(HTTPStatus::parse(b"600"), None);
    assert_eq!(HTTPStatus::parse(b"20"), None);
    assert_eq!(HTTPStatus::parse(b"2x0"), None);
    // §6.4.1: 1xx, 204 and 304 have no content.
    for (code, none) in [(100, true), (103, true), (200, false), (204, true), (205, false), (304, true), (404, false)] {
        assert_eq!(HTTPStatus(code).has_no_content(), none, "{code}");
    }
    let mut out = Vec::new();
    HTTPStatus::NOT_FOUND.write(&mut out);
    assert_eq!(out, b"404");
}

#[test]
fn versions() {
    // RFC 9112 §2.3: "HTTP/" DIGIT "." DIGIT, case-sensitive.
    assert_eq!(HTTPVersion::parse(b"HTTP/1.1"), Some(HTTPVersion::HTTP1_1));
    assert_eq!(HTTPVersion::parse(b"HTTP/1.0"), Some(HTTPVersion::HTTP1_0));
    for invalid in [&b"http/1.1"[..], b"HTTP/1.10", b"HTTP/11", b"HTTP/1", b"HTTP/ 1.1"] {
        assert_eq!(HTTPVersion::parse(invalid), None, "{invalid:?}");
    }
    // ALPN (RFC 7301 §6, RFC 9113 §3.2, RFC 9114 §3.1).
    assert_eq!(HTTPVersion::HTTP2.protocol(), Some(&b"h2"[..]));
    assert_eq!(HTTPVersion::from_protocol(b"h3"), Some(HTTPVersion::HTTP3));
    assert_eq!(HTTPVersion::from_protocol(b"h2c"), None);
    let mut out = Vec::new();
    HTTPVersion::HTTP1_1.write(&mut out);
    assert_eq!(out, b"HTTP/1.1");
}

#[test]
fn field_names_and_values() {
    // RFC 9110 §5.1: names are tokens, case-insensitive; §5.5: values have
    // no leading or trailing whitespace, no CR, LF or NUL, and may have obs-text.
    let field = HTTPField::new(b"Content-Type", b"text/html").unwrap();
    assert_eq!(field.name, b"content-type");
    for name in [&b""[..], b"content type", b"name:", b"na\xFFme"] {
        assert!(HTTPField::new(name, b"x").is_err(), "{name:?}");
    }
    for value in [&b"a\rb"[..], b"a\nb", b"a\0b", b" leading", b"trailing\t", b"\x7F"] {
        assert!(HTTPField::new(b"x", value).is_err(), "{value:?}");
    }
    for value in [&b""[..], b"a b\tc", b"caf\xC3\xA9", b"\"quoted, string\""] {
        assert!(HTTPField::new(b"x", value).is_ok(), "{value:?}");
    }
    assert_eq!(HTTPSyntax::trim(b" \t a b \t"), b"a b");
}

#[test]
fn lists_of_field_values() {
    // RFC 9110 §5.6.1: empty elements are ignored; a quoted comma is not a separator.
    assert_eq!(HTTPSyntax::list(b"foo,bar"), [&b"foo"[..], b"bar"]);
    assert_eq!(HTTPSyntax::list(b"foo ,bar,"), [&b"foo"[..], b"bar"]);
    assert_eq!(HTTPSyntax::list(b"foo , ,bar,charlie"), [&b"foo"[..], b"bar", b"charlie"]);
    assert!(HTTPSyntax::list(b", ,").is_empty());
    assert_eq!(HTTPSyntax::list(b"\"a, b\", c"), [&b"\"a, b\""[..], b"c"]);
    assert!(HTTPSyntax::list_contains(b"keep-alive, Close", b"close"));
    assert!(HTTPSyntax::list_contains(b"gzip;q=0.5, chunked", b"chunked"));
    assert!(!HTTPSyntax::list_contains(b"closed", b"close"));
}

#[test]
fn field_sections() {
    // RFC 9110 §5.2, §5.3: lines of one name combine in order, joined by commas.
    let mut fields = HTTPFields::new().with(b"Accept", b"text/html").unwrap().with(b"X-A", b"1").unwrap();
    fields.append(b"accept", b"text/plain").unwrap();
    assert_eq!(fields.combined(b"ACCEPT").unwrap(), b"text/html, text/plain");
    assert_eq!(fields.get_all(b"accept").count(), 2);
    assert!(fields.contains_token(b"accept", b"text/plain"));
    fields.set(b"accept", b"*/*").unwrap();
    assert_eq!((fields.get(b"accept"), fields.len()), (Some(&b"*/*"[..]), 2));
    assert!(fields.remove(b"x-a") && !fields.contains(b"x-a"));
    // RFC 9113 §6.5.2 sizes: name, value and 32 bytes.
    assert_eq!(fields.size(), 6 + 3 + 32);
}

#[test]
fn content_lengths() {
    // RFC 9110 §8.6: digits; a list of the same value is one value; any other is invalid.
    let length = |values: &[&[u8]]| {
        let mut fields = HTTPFields::new();
        for value in values {
            fields.append(b"content-length", value).unwrap();
        }
        fields.content_length()
    };
    assert_eq!(length(&[]), Ok(None));
    assert_eq!(length(&[b"42"]), Ok(Some(42)));
    assert_eq!(length(&[b"42, 42"]), Ok(Some(42)));
    assert_eq!(length(&[b"42", b"42"]), Ok(Some(42)));
    for invalid in
        [&[&b"42, 43"[..]][..], &[b"-1"], &[b"4 2"], &[b"0x10"], &[b""], &[b"42", b"43"], &[b"99999999999999999999"]]
    {
        assert!(matches!(length(invalid), Err(HTTPError::Malformed(_))), "{invalid:?}");
    }
}

#[test]
fn authorities() {
    // RFC 3986 §3.2.2 hosts; RFC 9110 §4.2.1: no empty host; §4.2.4: no userinfo.
    let authority = HTTPAuthority::parse(b"WWW.Example.COM:8080").unwrap();
    assert_eq!((authority.host.as_slice(), authority.port), (&b"www.example.com"[..], Some(8080)));
    assert_eq!(HTTPAuthority::parse(b"[2001:db8::1]:443").unwrap().host, b"[2001:db8::1]");
    assert_eq!(HTTPAuthority::parse(b"192.0.2.1").unwrap().port, None);
    for invalid in [
        &b""[..],
        b":80",
        b"user@example.com",
        b"example.com:65536",
        b"example.com:x",
        b"exa mple.com",
        b"[::1",
        b"[]",
        b"example.com:",
    ] {
        assert!(HTTPAuthority::parse(invalid).is_err(), "{invalid:?}");
    }
    let mut out = Vec::new();
    authority.write(&mut out);
    assert_eq!(out, b"www.example.com:8080");
}

#[test]
fn request_targets() {
    // RFC 9112 §3.2: the four forms, with the examples of §3.2.1 to §3.2.4.
    assert_eq!(HTTPTarget::parse(b"/where?q=now").unwrap(), HTTPTarget::Origin(b"/where?q=now".to_vec()));
    assert_eq!(
        HTTPTarget::parse(b"http://www.example.org/pub/WWW/TheProject.html").unwrap(),
        HTTPTarget::Absolute {
            scheme: b"http".to_vec(),
            authority: b"www.example.org".to_vec(),
            path: b"/pub/WWW/TheProject.html".to_vec()
        }
    );
    assert_eq!(
        HTTPTarget::parse(b"www.example.com:80").unwrap(),
        HTTPTarget::Authority(b"www.example.com:80".to_vec())
    );
    assert_eq!(HTTPTarget::parse(b"*").unwrap(), HTTPTarget::Asterisk);
    // An empty path is "/" (RFC 9112 §3.2.1); no fragment (RFC 9110 §4.2.4).
    let HTTPTarget::Absolute { path, .. } = HTTPTarget::parse(b"HTTPS://example.com?x").unwrap() else { panic!() };
    assert_eq!(path, b"/?x");
    for invalid in
        [&b"/a b"[..], b"/a\"b", b"/%zz", b"/a#fragment", b"http://user@example.com/", b"/\xFF", b"http:///x"]
    {
        assert!(HTTPTarget::parse(invalid).is_err(), "{invalid:?}");
    }
    assert!(HTTPTarget::check_path(b"/a/b;c=d/~e%2F?f=g&h=/i?").is_ok());
}

#[test]
fn requests() {
    // RFC 9110 §9.3.6: CONNECT names a host and port, nothing else; RFC
    // 8441 §4: an extended CONNECT has a scheme, an authority and a path;
    // RFC 9112 §3.2.4: "*" only for OPTIONS.
    assert!(HTTPRequest::connect(b"example.com:443").check().is_ok());
    assert!(HTTPRequest::connect(b"example.com").check().is_err());
    let mut tunnel = HTTPRequest::connect(b"example.com:443");
    tunnel.path = b"/".to_vec();
    assert!(tunnel.check().is_err());
    let mut websocket = HTTPRequest::new(HTTPMethod::CONNECT, b"https", b"example.com", b"/chat");
    websocket.protocol = Some(b"websocket".to_vec());
    assert!(websocket.check().is_ok());
    let mut not_connect = HTTPRequest::new(HTTPMethod::GET, b"https", b"example.com", b"/chat");
    not_connect.protocol = Some(b"websocket".to_vec());
    assert!(not_connect.check().is_err());
    assert!(HTTPRequest::new(HTTPMethod::OPTIONS, b"https", b"example.com", b"*").check().is_ok());
    assert!(HTTPRequest::new(HTTPMethod::GET, b"https", b"example.com", b"*").check().is_err());
    assert!(HTTPRequest::new(HTTPMethod::GET, b"https", b"user@example.com", b"/").check().is_err());
    let request = HTTPRequest::new(HTTPMethod::GET, b"HTTPS", b"example.com", b"/");
    assert_eq!(request.scheme.as_deref(), Some(&b"https"[..]));
    assert_eq!(request.host(), Some(&b"example.com"[..]));
}

#[test]
fn priorities() {
    // RFC 9218 §4: "u" of 0 to 7 (3 by default), "i" a boolean; members of
    // another type, out of range or unknown are ignored (§4.1, §4.2).
    assert_eq!(HTTPPriority::parse(b""), HTTPPriority { urgency: 3, incremental: false });
    assert_eq!(HTTPPriority::parse(b"u=5, i"), HTTPPriority { urgency: 5, incremental: true });
    assert_eq!(HTTPPriority::parse(b"u=0, i=?0"), HTTPPriority { urgency: 0, incremental: false });
    assert_eq!(HTTPPriority::parse(b"u=8"), HTTPPriority::default());
    assert_eq!(HTTPPriority::parse(b"u=-1, i=1"), HTTPPriority::default());
    assert_eq!(HTTPPriority::parse(b"u=1.5, x=?1, i"), HTTPPriority { urgency: 3, incremental: true });
    assert_eq!(HTTPPriority::parse(b"u=2, u=6"), HTTPPriority { urgency: 6, incremental: false });
    assert_eq!(HTTPPriority::parse(b"not a dictionary("), HTTPPriority::default());
    assert_eq!(HTTPPriority { urgency: 1, incremental: true }.serialize(), b"u=1, i");
    assert!(HTTPPriority::default().serialize().is_empty());
}
