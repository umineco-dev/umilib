use umilib::service::{Pattern, PatternError, PatternKind, Rule};

#[test]
fn patterns_match_as_their_kind_says() {
    let host = Pattern::suffix(b".example.com");
    assert!(host.matches_bytes(b"auth.example.com"));
    assert!(host.matches_bytes(b".example.com"));
    assert!(!host.matches_bytes(b"example.com"));
    assert!(!host.matches_bytes(b"auth.EXAMPLE.com"));
    assert!(host.clone().ignoring_ascii_case(true).matches_bytes(b"auth.EXAMPLE.com"));

    let path = Pattern::prefix(b"/oauth/");
    assert!(path.matches_bytes(b"/oauth/token"));
    assert!(path.matches_bytes(b"/oauth/"));
    assert!(!path.matches_bytes(b"/oauth"));
    assert!(!path.matches_bytes(b"/api/oauth/"));

    let exact = Pattern::exact(b"h3");
    assert!(exact.matches_bytes(b"h3"));
    assert!(!exact.matches_bytes(b"h3-29"));
    assert!(!exact.matches_bytes(b"H3"));
    assert!(exact.clone().ignoring_ascii_case(true).matches_bytes(b"H3"));
    assert!(Pattern::exact(b"").matches_bytes(b""));
    assert!(!Pattern::exact(b"").matches_bytes(b"a"));

    let any = Pattern::any();
    assert!(any.matches_bytes(b""));
    assert!(any.matches_bytes(&[0, 255, 1]));
    // Only ASCII letters are folded.
    let folded = Pattern::exact("é".as_bytes()).ignoring_ascii_case(true);
    assert!(!folded.matches_bytes("É".as_bytes()));
}

#[test]
fn patterns_are_rules_of_bytes() {
    let rule = Pattern::prefix(b"/api/");
    assert!(rule.matches(&"/api/users"));
    assert!(rule.matches(&String::from("/api/")));
    assert!(rule.matches(&b"/api/x".to_vec()));
    assert!(!Rule::<&str>::matches(&rule, &"/web/"));
}

#[test]
fn a_prefix_or_suffix_of_nothing_is_any_input() {
    assert_eq!(Pattern::prefix(b""), Pattern::any());
    assert_eq!(Pattern::suffix(b""), Pattern::any());
    assert_eq!(Pattern::new(PatternKind::Any, b"ignored"), Pattern::any());
    assert_eq!(Pattern::any().bytes(), b"");
}

#[test]
fn the_text_of_patterns() {
    let cases: &[(&[u8], PatternKind, &[u8])] = &[
        (b"*", PatternKind::Any, b""),
        (b"", PatternKind::Exact, b""),
        (b"example.com", PatternKind::Exact, b"example.com"),
        (b"*.example.com", PatternKind::Suffix, b".example.com"),
        (b"/oauth/*", PatternKind::Prefix, b"/oauth/"),
        (b"\\*", PatternKind::Exact, b"*"),
        (b"\\**", PatternKind::Prefix, b"*"),
        (b"*\\*", PatternKind::Suffix, b"*"),
        (b"a\\\\b", PatternKind::Exact, b"a\\b"),
        (b"\\a", PatternKind::Exact, b"a"),
        (b"*\\*\\*", PatternKind::Suffix, b"**"),
    ];
    for (text, kind, bytes) in cases {
        let pattern =
            Pattern::parse(text).unwrap_or_else(|error| panic!("{:?}: {error}", String::from_utf8_lossy(text)));
        assert_eq!((pattern.kind(), pattern.bytes()), (*kind, *bytes), "{:?}", String::from_utf8_lossy(text));
        assert!(!pattern.ignores_ascii_case());
        // The text of a pattern parses back to it.
        assert_eq!(Pattern::parse(&pattern.format()).unwrap(), pattern);
    }
    assert_eq!(Pattern::exact(b"a*b\\c").format(), b"a\\*b\\\\c");
    assert_eq!(Pattern::prefix(b"*").format(), b"\\**");
    assert_eq!(Pattern::suffix(b"x").format(), b"*x");
    assert_eq!(Pattern::any().format(), b"*");
}

#[test]
fn text_that_is_not_a_pattern_is_rejected() {
    for text in [&b"a*b"[..], b"**", b"*a*", b"***", b"a**"] {
        assert_eq!(Pattern::parse(text), Err(PatternError::MisplacedWildcard), "{:?}", String::from_utf8_lossy(text));
    }
    for text in [&b"\\"[..], b"a\\", b"*\\"] {
        assert_eq!(Pattern::parse(text), Err(PatternError::UnfinishedEscape), "{:?}", String::from_utf8_lossy(text));
    }
}
