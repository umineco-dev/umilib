//! String preparation against the conformance file of Unicode 3.2
//! normalization, the examples of RFC 4013 and the rules of RFC 3454 and
//! RFC 4518 (with its verified errata).

use umilib::codec::stringprep::{
    LDAPMatching, LDAPPrep, LDAPString, NormalizationForm, StringPrepError, StringPrepProfile, StringPrepTable,
    Unassigned,
};

const NORMALIZATION_TEST: &str = include_str!("../vectors/codec/stringprep/NormalizationTest-3.2.0.txt");

fn text(field: &str) -> String {
    field.split_whitespace().map(|point| char::from_u32(u32::from_str_radix(point, 16).unwrap()).unwrap()).collect()
}

#[test]
fn normalization_conforms_to_unicode_3_2() {
    // The invariants of the header of NormalizationTest-3.2.0.txt, for every line.
    let mut listed = std::collections::HashSet::new();
    let mut part = "";
    let mut lines = 0;
    for line in NORMALIZATION_TEST.lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('@') {
            part = if name.starts_with("Part1") { "Part1" } else { "" };
            continue;
        }
        let columns: Vec<String> = line.split(';').take(5).map(text).collect();
        let [c1, c2, c3, c4, c5] = [&columns[0], &columns[1], &columns[2], &columns[3], &columns[4]];
        for source in [c1, c2, c3] {
            assert_eq!(&NormalizationForm::NFC.normalize(source), c2, "NFC of {line}");
            assert_eq!(&NormalizationForm::NFD.normalize(source), c3, "NFD of {line}");
        }
        for source in [c4, c5] {
            assert_eq!(&NormalizationForm::NFC.normalize(source), c4, "NFC of {line}");
            assert_eq!(&NormalizationForm::NFD.normalize(source), c5, "NFD of {line}");
        }
        for source in [c1, c2, c3, c4, c5] {
            assert_eq!(&NormalizationForm::NFKC.normalize(source), c4, "NFKC of {line}");
            assert_eq!(&NormalizationForm::NFKD.normalize(source), c5, "NFKD of {line}");
        }
        if part == "Part1" {
            listed.insert(c1.chars().next().unwrap());
        }
        lines += 1;
    }
    assert!(lines > 15_000, "the whole file was read");
    // Part 1: every code point not listed is left unchanged by every form.
    for character in (0..=0x10FFFF).filter_map(char::from_u32).filter(|character| !listed.contains(character)) {
        let single = character.to_string();
        for form in [NormalizationForm::NFC, NormalizationForm::NFD, NormalizationForm::NFKC, NormalizationForm::NFKD] {
            assert_eq!(form.normalize(&single), single, "{form:?} of U+{:04X}", character as u32);
        }
    }
}

#[test]
fn saslprep_examples_of_rfc_4013() {
    let prepare = |text: &str| StringPrepProfile::SASLPREP.prepare(text, Unassigned::Prohibited);
    assert_eq!(prepare("I\u{00AD}X").unwrap(), "IX");
    assert_eq!(prepare("user").unwrap(), "user");
    assert_eq!(prepare("USER").unwrap(), "USER");
    assert_eq!(prepare("\u{00AA}").unwrap(), "a");
    assert_eq!(prepare("\u{2168}").unwrap(), "IX");
    assert_eq!(prepare("\u{0007}"), Err(StringPrepError::Prohibited('\u{0007}')));
    assert_eq!(prepare("\u{0627}\u{0031}"), Err(StringPrepError::Bidi));
    // RFC 3454 §6: allowed when a right-to-left character ends it, refused with a left-to-right one.
    assert_eq!(prepare("\u{0627}\u{0031}\u{0628}").unwrap(), "\u{0627}\u{0031}\u{0628}");
    assert_eq!(prepare("\u{0627}a\u{0628}"), Err(StringPrepError::Bidi));
    // §2.1: non-ASCII spaces map to SPACE; §2.3: they are prohibited only before the mapping.
    assert_eq!(prepare("a\u{00A0}b").unwrap(), "a b");
    // RFC 3454 §7: unassigned code points only in queries.
    assert_eq!(prepare("\u{0221}"), Err(StringPrepError::Unassigned('\u{0221}')));
    assert_eq!(StringPrepProfile::SASLPREP.prepare("\u{0221}", Unassigned::Allowed).unwrap(), "\u{0221}");
}

#[test]
fn tables_are_those_of_rfc_3454() {
    assert_eq!(StringPrepTable::B2.mapping('A'), Some("a"));
    assert_eq!(StringPrepTable::B2.mapping('\u{00DF}'), Some("ss"));
    assert_eq!(StringPrepTable::B2.mapping('\u{0130}'), Some("i\u{0307}"));
    assert_eq!(StringPrepTable::B3.mapping('\u{00DF}'), Some("ss"));
    assert_eq!(StringPrepTable::B2.mapping('a'), None);
    assert_eq!(StringPrepTable::B1.mapping('\u{00AD}'), Some(""));
    assert!(StringPrepTable::B1.contains('\u{FEFF}'));
    assert!(StringPrepTable::C11.contains(' ') && !StringPrepTable::C11.contains('\u{00A0}'));
    assert!(StringPrepTable::C12.contains('\u{00A0}') && StringPrepTable::C12.contains('\u{3000}'));
    assert!(StringPrepTable::C21.contains('\u{007F}') && StringPrepTable::C22.contains('\u{0080}'));
    assert!(StringPrepTable::C3.contains('\u{E000}') && StringPrepTable::C3.contains('\u{10FFFD}'));
    assert!(StringPrepTable::C4.contains('\u{FFFE}') && StringPrepTable::C4.contains('\u{10FFFF}'));
    assert!(StringPrepTable::C9.contains('\u{E0001}'));
    assert!(StringPrepTable::D1.contains('\u{05D0}') && StringPrepTable::D1.contains('\u{0627}'));
    assert!(StringPrepTable::D2.contains('a') && !StringPrepTable::D2.contains('1'));
    assert!(StringPrepTable::A1.contains('\u{0221}') && !StringPrepTable::A1.contains('a'));
}

#[test]
fn ldap_preparation_follows_rfc_4518() {
    let value = |text: &str, matching| LDAPPrep::prepare(text, matching, LDAPString::Value);
    // §2.6.1: one space at each end, inner sequences of spaces as two, two spaces for a value of none.
    assert_eq!(value("foo bar  ", LDAPMatching::Exact).unwrap(), " foo  bar ");
    assert_eq!(value("   ", LDAPMatching::Exact).unwrap(), "  ");
    assert_eq!(value("", LDAPMatching::Exact).unwrap(), "  ");
    // Substrings, with errata 1757 (inner spaces) and 1758.
    let substring = |kind| LDAPPrep::prepare("foo bar  ", LDAPMatching::Exact, kind).unwrap();
    assert_eq!(substring(LDAPString::InitialSubstring), " foo  bar ");
    assert_eq!(substring(LDAPString::AnySubstring), "foo  bar ");
    assert_eq!(substring(LDAPString::FinalSubstring), "foo  bar ");
    assert_eq!(LDAPPrep::prepare("  x", LDAPMatching::Exact, LDAPString::FinalSubstring).unwrap(), " x ");
    assert_eq!(LDAPPrep::prepare("   ", LDAPMatching::Exact, LDAPString::AnySubstring).unwrap(), " ");
    // §2.2: case folding for case ignore; white space controls to SPACE; controls, soft hyphens and
    // variation selectors (U+FE00 to U+FE0F, erratum 860) to nothing.
    assert_eq!(value("ABC Ä", LDAPMatching::CaseIgnore).unwrap(), " abc  ä ");
    assert_eq!(value("ABC", LDAPMatching::Exact).unwrap(), " ABC ");
    assert_eq!(value("a\tb\r\nc", LDAPMatching::Exact).unwrap(), " a  b  c ");
    assert_eq!(value("a\u{00AD}\u{0000}\u{200B}\u{FE00}\u{FE0F}b", LDAPMatching::Exact).unwrap(), " ab ");
    assert_eq!(value("a\u{3000}b", LDAPMatching::Exact).unwrap(), " a  b ");
    // §2.3: NFKC.
    assert_eq!(value("\u{FF21}\u{2168}", LDAPMatching::CaseIgnore).unwrap(), " aix ");
    // §2.4: unassigned (refused as such, as RFC 3454 §7 names them), private use, non-characters,
    // surrogates (impossible in Rust strings), C.8 and U+FFFD.
    assert_eq!(value("\u{0221}", LDAPMatching::Exact), Err(StringPrepError::Unassigned('\u{0221}')));
    assert_eq!(value("\u{E000}", LDAPMatching::Exact), Err(StringPrepError::Prohibited('\u{E000}')));
    assert_eq!(value("\u{FFFE}", LDAPMatching::Exact), Err(StringPrepError::Prohibited('\u{FFFE}')));
    assert_eq!(value("\u{0340}", LDAPMatching::Exact).unwrap(), " \u{0300} ", "C.8 is checked after NFKC");
    assert_eq!(value("\u{206A}", LDAPMatching::Exact).unwrap(), "  ", "mapped to nothing before C.8");
    assert_eq!(value("\u{FFFD}", LDAPMatching::Exact), Err(StringPrepError::Prohibited('\u{FFFD}')));
    // §2.5: bidirectional characters are ignored.
    assert!(value("\u{0627}1", LDAPMatching::Exact).is_ok());
    // §2.6.1: SPACE followed by a combining mark is not a space.
    assert_eq!(value(" \u{0301}a", LDAPMatching::Exact).unwrap(), "  \u{0301}a ");
    // §2.6.2 and §2.6.3.
    assert_eq!(value("  123  456  ", LDAPMatching::Numeric).unwrap(), "123456");
    assert_eq!(value("   ", LDAPMatching::Numeric).unwrap(), "");
    assert_eq!(value(" -123  456 -", LDAPMatching::TelephoneNumber).unwrap(), "123456");
    assert_eq!(value("+1 (555) 123\u{2010}4567", LDAPMatching::TelephoneNumber).unwrap(), "+1(555)1234567");
}

#[test]
fn trace_profile_of_rfc_4505_section_3() {
    // No mapping, no normalization; C.2.1, C.2.2, C.3, C.4, C.5, C.6, C.8, C.9 prohibited; bidirectional text checked.
    let trace = StringPrepProfile::TRACE;
    assert_eq!(trace.prepare("I\u{00AD}X \u{2168}", Unassigned::Allowed), Ok(String::from("I\u{00AD}X \u{2168}")));
    for (character, table) in [
        ('\u{0007}', StringPrepTable::C21),
        ('\u{0085}', StringPrepTable::C22),
        ('\u{E000}', StringPrepTable::C3),
        ('\u{FDD0}', StringPrepTable::C4),
        ('\u{FFFD}', StringPrepTable::C6),
        ('\u{200E}', StringPrepTable::C8),
        ('\u{E0001}', StringPrepTable::C9),
    ] {
        assert!(table.contains(character), "{character:?}");
        assert_eq!(
            trace.prepare(&format!("a{character}"), Unassigned::Allowed),
            Err(StringPrepError::Prohibited(character))
        );
    }
    // C.7 (inappropriate for canonical representation) and spaces are not prohibited.
    assert!(StringPrepTable::C7.contains('\u{2FF0}'));
    trace.prepare("\u{2FF0} \u{00A0}", Unassigned::Allowed).unwrap();
    assert_eq!(trace.prepare("\u{0627}a", Unassigned::Allowed), Err(StringPrepError::Bidi));
    // Unassigned code points are allowed (RFC 4505 §3).
    trace.prepare("\u{0221}", Unassigned::Allowed).unwrap();
}

#[test]
fn expansion_bounds_hold_for_every_code_point() {
    // The buffers of preparation are sized from these bounds, so that a password does not move in memory.
    let mut longest = 0;
    for point in 0..=0x10FFFFu32 {
        let Some(character) = char::from_u32(point) else { continue };
        let decomposed = NormalizationForm::NFKD.normalize(&character.to_string()).chars().count();
        longest = longest.max(decomposed);
        for table in [StringPrepTable::B1, StringPrepTable::B2, StringPrepTable::B3] {
            if let Some(mapping) = table.mapping(character) {
                assert!(mapping.len() <= StringPrepProfile::MAXIMUM_EXPANSION * character.len_utf8(), "{point:X}");
            }
        }
    }
    assert_eq!(longest, NormalizationForm::MAXIMUM_EXPANSION, "U+FDFA");
}
