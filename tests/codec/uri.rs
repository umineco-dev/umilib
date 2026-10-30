//! URIs against RFC 3986 (the generic syntax: §1.1.2 and §3 examples, the
//! grammar of Appendix A, §5.4 reference resolution, §6.2.2 normalization)
//! and the form encoding against the WHATWG URL Standard §5 and RFC 6749
//! Appendix B.

use umilib::codec::uri::{URIAuthority, URIError, URIForm, URIHostKind, URIPercent, URIReference};

const RFC3986: &str = include_str!("../vectors/codec/uri/rfc3986.txt");
const RFC6749: &str = include_str!("../vectors/auth/oauth/rfc6749.txt");

/// The `"reference" = "target"` lines of §5.4, from its heading to the next section.
fn resolution_examples() -> Vec<(String, String)> {
    let start = RFC3986.find("\n5.4.1.  Normal Examples").expect("§5.4.1");
    let end = RFC3986[start..].find("\n6.  Normalization").expect("§6") + start;
    let mut examples = Vec::new();
    for line in RFC3986[start..end].lines() {
        let line = line.trim();
        if !line.starts_with('"') {
            continue;
        }
        let quoted: Vec<&str> = line.split('"').collect();
        // `"ref"  =  "target"` splits into ["", ref, "  =  ", target, ...].
        if quoted.len() >= 4 && quoted[2].trim() == "=" {
            examples.push((quoted[1].to_string(), quoted[3].to_string()));
        }
    }
    examples
}

#[test]
fn resolves_the_examples_of_section_5_4() {
    let base = URIReference::parse("http://a/b/c/d;p?q").unwrap();
    let examples = resolution_examples();
    // 23 normal and 19 abnormal examples, "http:g" with the target of a strict parser.
    assert_eq!(examples.len(), 42);
    for (reference, target) in &examples {
        let parsed = URIReference::parse(reference).unwrap_or_else(|error| panic!("{reference}: {error}"));
        assert_eq!(parsed.to_string(), *reference, "recomposition of {reference}");
        let resolved = parsed.resolve(&base).unwrap();
        assert_eq!(resolved.to_string(), *target, "{reference}");
        assert_eq!(resolved, URIReference::parse(target).unwrap(), "{reference}");
    }
}

#[test]
fn resolution_needs_an_absolute_base() {
    let base = URIReference::parse("//a/b").unwrap();
    assert_eq!(URIReference::parse("g").unwrap().resolve(&base), Err(URIError::NotAbsolute));
    // The fragment of the base is not used (§5.1).
    let base = URIReference::parse("http://a/b#f").unwrap();
    assert_eq!(URIReference::parse("").unwrap().resolve(&base).unwrap().to_string(), "http://a/b");
}

#[test]
fn merges_onto_an_empty_path_after_an_authority() {
    // §5.2.3: a base with an authority and an empty path gives "/" and the reference.
    let base = URIReference::parse("http://a").unwrap();
    assert_eq!(URIReference::parse("g").unwrap().resolve(&base).unwrap().to_string(), "http://a/g");
    // Without an authority, the base path up to its last "/" (none here).
    let base = URIReference::parse("urn:x").unwrap();
    assert_eq!(URIReference::parse("g").unwrap().resolve(&base).unwrap().to_string(), "urn:g");
}

#[test]
fn a_target_never_reads_a_path_as_an_authority() {
    // "/..//g" against a base without an authority leaves the path "//g"; written as it is,
    // "a://g" would read "g" as an authority.
    let base = URIReference::parse("a:/b").unwrap();
    let target = URIReference::parse("/..//g").unwrap().resolve(&base).unwrap();
    assert!(target.authority.is_none());
    let reread = URIReference::parse(&target.to_string()).unwrap();
    assert!(reread.authority.is_none());
    assert_eq!(URIReference::remove_dot_segments(&reread.path), "//g");
}

#[test]
fn removes_dot_segments_as_section_5_2_4_shows() {
    assert_eq!(URIReference::remove_dot_segments("/a/b/c/./../../g"), "/a/g");
    assert_eq!(URIReference::remove_dot_segments("mid/content=5/../6"), "mid/6");
    assert_eq!(URIReference::remove_dot_segments(""), "");
    assert_eq!(URIReference::remove_dot_segments("/.."), "/");
    assert_eq!(URIReference::remove_dot_segments("../a"), "a");
}

#[test]
fn reads_the_examples_of_sections_1_1_2_and_3() {
    for text in [
        "ftp://ftp.is.co.za/rfc/rfc1808.txt",
        "http://www.ietf.org/rfc/rfc2396.txt",
        "ldap://[2001:db8::7]/c=GB?objectClass?one",
        "mailto:John.Doe@example.com",
        "news:comp.infosystems.www.servers.unix",
        "tel:+1-816-555-1212",
        "telnet://192.0.2.16:80/",
        "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
    ] {
        assert!(RFC3986.contains(text));
        let reference = URIReference::parse(text).unwrap_or_else(|error| panic!("{text}: {error}"));
        assert_eq!(reference.to_string(), text);
        assert!(reference.is_absolute());
    }
    let ldap = URIReference::parse("ldap://[2001:db8::7]/c=GB?objectClass?one").unwrap();
    let authority = ldap.authority.as_ref().unwrap();
    assert_eq!(authority.host, "[2001:db8::7]");
    assert_eq!(authority.host_kind(), URIHostKind::IPv6);
    assert_eq!(ldap.path, "/c=GB");
    assert_eq!(ldap.query.as_deref(), Some("objectClass?one"));
    let telnet = URIReference::parse("telnet://192.0.2.16:80/").unwrap();
    let authority = telnet.authority.as_ref().unwrap();
    assert_eq!(authority.host_kind(), URIHostKind::IPv4);
    assert_eq!(authority.port.as_deref(), Some("80"));
    let mailto = URIReference::parse("mailto:John.Doe@example.com").unwrap();
    assert!(mailto.authority.is_none());
    assert_eq!(mailto.path, "John.Doe@example.com");

    // §3: the components of the two examples.
    let foo = URIReference::parse("foo://example.com:8042/over/there?name=ferret#nose").unwrap();
    assert_eq!(foo.scheme.as_deref(), Some("foo"));
    assert_eq!(
        foo.authority,
        Some(URIAuthority { userinfo: None, host: "example.com".into(), port: Some("8042".into()) })
    );
    assert_eq!(foo.path, "/over/there");
    assert_eq!(foo.query.as_deref(), Some("name=ferret"));
    assert_eq!(foo.fragment.as_deref(), Some("nose"));
    assert!(!foo.is_absolute() && !foo.is_relative());
    let urn = URIReference::parse("urn:example:animal:ferret:nose").unwrap();
    assert_eq!(urn.scheme.as_deref(), Some("urn"));
    assert_eq!(urn.path, "example:animal:ferret:nose");
    // §3.3: "foo://info.example.com?fred" has an empty path.
    let fred = URIReference::parse("foo://info.example.com?fred").unwrap();
    assert_eq!(fred.path, "");
    assert_eq!(fred.query.as_deref(), Some("fred"));
}

#[test]
fn keeps_empty_components_apart_from_absent_ones() {
    // §5.3: an empty query or fragment is written back with its delimiter.
    let empty = URIReference::parse("http://example.com/?#").unwrap();
    assert_eq!(empty.query.as_deref(), Some(""));
    assert_eq!(empty.fragment.as_deref(), Some(""));
    assert_eq!(empty.to_string(), "http://example.com/?#");
    let absent = URIReference::parse("http://example.com/").unwrap();
    assert_eq!(absent.query, None);
    assert_ne!(empty, absent);
    let port = URIReference::parse("http://example.com:/").unwrap();
    assert_eq!(port.authority.as_ref().unwrap().port.as_deref(), Some(""));
    let empty_host = URIReference::parse("file:///etc/hosts").unwrap();
    assert_eq!(empty_host.authority.as_ref().unwrap().host, "");
    assert_eq!(empty_host.authority.as_ref().unwrap().host_kind(), URIHostKind::RegName);
}

#[test]
fn accepts_what_appendix_a_allows() {
    for text in [
        "",
        "a:b:c",
        "./a:b",
        "//[::]",
        "//[::1]:8080/x",
        "//[1:2:3:4:5:6:7:8]",
        "//[1:2:3:4:5:6:7::]",
        "//[::2:3:4:5:6:7:8]",
        "//[1:2:3:4:5:6:1.2.3.4]",
        "//[::ffff:192.0.2.1]",
        "//[v1.x]",
        "//[V1F.a:b!$]",
        "//user:pass@host:1",
        "//%41b",
        "//!$&'()*+,;=",
        "s://h/a/%2F/b;p=1?q=/?#f/?",
        "s+-.0:x",
        "?",
        "#",
        "/",
        "//",
        "s://h:99999",
    ] {
        let reference = URIReference::parse(text).unwrap_or_else(|error| panic!("{text}: {error}"));
        assert_eq!(reference.to_string(), text);
        assert_eq!(reference.check(), Ok(()));
    }
    // §3.2.2: an IPv4address is taken where the host is one; other dotted names are reg-names.
    for (host, kind) in [
        ("1.2.3.4", URIHostKind::IPv4),
        ("255.255.255.255", URIHostKind::IPv4),
        ("256.1.1.1", URIHostKind::RegName),
        ("01.2.3.4", URIHostKind::RegName),
        ("1.2.3", URIHostKind::RegName),
        ("1.2.3.4.", URIHostKind::RegName),
        ("[v7.x]", URIHostKind::IPvFuture),
    ] {
        let reference = URIReference::parse(&format!("//{host}")).unwrap();
        assert_eq!(reference.authority.unwrap().host_kind(), kind, "{host}");
    }
}

#[test]
fn rejects_what_appendix_a_does_not_allow() {
    for text in [
        ":x",
        "1a:b",
        "-:b",
        "http://a b/",
        "http://a/b c",
        "http://a/?q r",
        "http://a/#f#g",
        "http://a/é",
        "http://[::1",
        "http://[::1]x/",
        "http://[1::2::3]/",
        "http://[1:2:3:4:5:6:7:8:9]/",
        "http://[1:2:3:4:5:6:7:8::]/",
        "http://[1:2:3:4:5:6:7]/",
        "http://[12345::]/",
        "http://[:1:2:3:4:5:6:7]/",
        "http://[::1.2.3.4.5]/",
        "http://[::1.2.3.256]/",
        "http://[1.2.3.4::]/",
        "http://[1:2:3:4:5:6:7:1.2.3.4]/",
        "http://[v.x]/",
        "http://[v1.]/",
        "http://[vg.x]/",
        "http://a:8x/",
        "http://a:1:2/",
        "http://u@h@x/",
        "http://u[@h/",
        "http://a[/",
        "http://%zz/",
        "http://a/%",
        "http://a/%4",
        "http://a/?%g0",
        "http://a/#%",
    ] {
        assert!(URIReference::parse(text).is_err(), "{text}");
    }
    assert_eq!(URIReference::parse("http://a/%4x"), Err(URIError::Percent { position: 9 }));
    assert!(matches!(URIReference::parse("http://a/b c"), Err(URIError::Syntax { position: 10, .. })));
}

#[test]
fn check_refuses_components_that_read_back_as_others() {
    let mut reference = URIReference::parse("http://a/b").unwrap();
    assert_eq!(reference.check(), Ok(()));
    reference.path = "b?c".into();
    assert!(reference.check().is_err());
    reference.path = "/b".into();
    reference.authority = None;
    reference.path = "//b".into();
    assert!(reference.check().is_err());
}

#[test]
fn normalizes_as_section_6_2_2_shows() {
    // §6.2.2: the two URIs of the example are equivalent.
    let a = URIReference::parse("example://a/b/c/%7Bfoo%7D").unwrap();
    let b = URIReference::parse("eXAMPLE://a/./b/../b/%63/%7bfoo%7d").unwrap();
    assert!(RFC3986.contains("eXAMPLE://a/./b/../b/%63/%7bfoo%7d"));
    assert_eq!(a.normalize(), b.normalize());
    assert_eq!(b.normalize().to_string(), "example://a/b/c/%7Bfoo%7D");
    // §6.2.2.1: the scheme and the host in lower case, other components as they are.
    assert_eq!(
        URIReference::parse("HTTP://www.EXAMPLE.com/").unwrap().normalize().to_string(),
        "http://www.example.com/"
    );
    assert_eq!(URIReference::parse("http://h/A?B#C").unwrap().normalize().to_string(), "http://h/A?B#C");
    // The digits of a percent-encoding in a host stay in upper case.
    assert_eq!(URIReference::parse("http://%c3%a9X/").unwrap().normalize().to_string(), "http://%C3%A9x/");
    // §6.2.2.2: unreserved characters decoded, others kept encoded with upper-case digits.
    assert_eq!(
        URIReference::parse("http://h/%7e%41%2f%2F?%5f#%2d").unwrap().normalize().to_string(),
        "http://h/~A%2F%2F?_#-"
    );
    assert_eq!(URIReference::parse("http://%75@h/").unwrap().normalize().to_string(), "http://u@h/");
    // §6.2.3: an empty port is dropped with its ":".
    assert_eq!(URIReference::parse("http://example.com:/").unwrap().normalize().to_string(), "http://example.com/");
    // A relative reference keeps its dot-segments, which change its target.
    assert_eq!(URIReference::parse("../a/./b").unwrap().normalize().to_string(), "../a/./b");
    // A normalized URI is valid and normalizing it again changes nothing.
    for text in ["a:.///b", "s://h/%2e%2E/x", "S://[V1.A]/"] {
        let normalized = URIReference::parse(text).unwrap().normalize();
        assert_eq!(normalized.check(), Ok(()), "{text}");
        assert_eq!(normalized.normalize(), normalized, "{text}");
    }
}

#[test]
fn percent_encodes_as_section_2_1_says() {
    // §2.1: upper-case digits; §2.3: unreserved characters are never encoded.
    assert_eq!(URIPercent::encode_component(b"a b/~-._%\xff"), "a%20b%2F~-._%25%FF");
    assert_eq!(URIPercent::decode(b"a%20b%2f%FF").unwrap(), b"a b/\xff");
    assert_eq!(URIPercent::decode(b"%"), Err(URIError::Percent { position: 0 }));
    assert_eq!(URIPercent::decode(b"ab%4"), Err(URIError::Percent { position: 2 }));
    assert_eq!(URIPercent::decode(b"%g1"), Err(URIError::Percent { position: 0 }));
    assert_eq!(URIPercent::decode_text(b"%C3%A9").unwrap(), "é");
    assert_eq!(URIPercent::decode_text(b"%FF"), Err(URIError::UTF8));
    for byte in 0..=255u8 {
        let unreserved = byte.is_ascii_alphanumeric() || b"-._~".contains(&byte);
        let sub_delim = b"!$&'()*+,;=".contains(&byte);
        let gen_delim = b":/?#[]@".contains(&byte);
        assert_eq!(URIPercent::is_unreserved(byte), unreserved);
        assert_eq!(URIPercent::is_sub_delim(byte), sub_delim);
        assert_eq!(URIPercent::is_gen_delim(byte), gen_delim);
        assert_eq!(URIPercent::decode(URIPercent::encode_component(&[byte]).as_bytes()).unwrap(), [byte]);
    }
}

#[test]
fn form_encodes_the_example_of_rfc_6749_appendix_b() {
    assert!(RFC6749.contains("+%25%26%2B%C2%A3%E2%82%AC"));
    let value = "\u{20}\u{25}\u{26}\u{2B}\u{A3}\u{20AC}";
    assert_eq!(URIForm::encode_text(value), "+%25%26%2B%C2%A3%E2%82%AC");
    assert_eq!(URIForm::decode(b"+%25%26%2B%C2%A3%E2%82%AC").unwrap(), value);
}

#[test]
fn form_reads_the_token_request_of_rfc_6749() {
    // §4.1.3: an encoded "." reads as one.
    let body = "grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA\n     &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
    assert!(RFC6749.contains(body));
    let body = body.replace("\n     ", "");
    let pairs = URIForm::parse(body.as_bytes()).unwrap();
    assert_eq!(
        pairs,
        [
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), "SplxlOBeZQQYbYS6WxSbIA".to_string()),
            ("redirect_uri".to_string(), "https://client.example.com/cb".to_string()),
        ]
    );
}

#[test]
fn form_follows_the_whatwg_parser_and_serializer() {
    // §5.1: empty sequences are skipped, a name without "=" has an empty value, the first "="
    // splits, "+" is a space, and a "%" without two hexadecimal digits stays as it is.
    let pairs = URIForm::parse(b"&a=1&&b&c==d&e+f=g%2Bh&%zz=%4&=v").unwrap();
    let expected: Vec<(String, String)> =
        [("a", "1"), ("b", ""), ("c", "=d"), ("e f", "g+h"), ("%zz", "%4"), ("", "v")]
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
    assert_eq!(pairs, expected);
    assert_eq!(URIForm::parse(b"").unwrap(), []);
    // Octets that are not UTF-8 are refused rather than read as U+FFFD.
    assert_eq!(URIForm::parse(b"a=%FF"), Err(URIError::UTF8));
    assert_eq!(URIForm::parse(b"a=\xff"), Err(URIError::UTF8));
    // §5.2: alphanumerics and *-._ kept, a space as "+", every other octet encoded.
    assert_eq!(URIForm::encode(&[("a b", "*-._~!'()"), ("é", "")]), "a+b=*-._%7E%21%27%28%29&%C3%A9=");
    for byte in 0..=127u8 {
        let kept = byte.is_ascii_alphanumeric() || b"*-._".contains(&byte);
        assert_eq!(URIForm::is_kept(byte), kept);
        let text = char::from(byte).to_string();
        assert_eq!(URIForm::decode(URIForm::encode_text(&text).as_bytes()).unwrap(), text);
    }
}

#[test]
fn normalizing_built_references_never_panics() {
    // The fields are public: a reference built field by field may hold any text.
    for path in ["é", "%41é", "%é", "a%4é", "%%41"] {
        let reference = URIReference { scheme: Some("s".into()), path: path.into(), ..URIReference::default() };
        let normalized = reference.normalize();
        assert!(normalized.path.contains('é') || path == "%%41", "{path}");
    }
}
