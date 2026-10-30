use alloc::string::String;
use alloc::vec::Vec;

use super::{NormalizationForm, StringPrepError, StringPrepTable};

/// The matching rule a string is prepared for (RFC 4518 §2.2, §2.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LDAPMatching {
    /// caseIgnoreMatch and its kin: case folded, insignificant spaces (§2.6.1).
    CaseIgnore,
    /// caseExactMatch and its kin: insignificant spaces (§2.6.1).
    Exact,
    /// numericStringMatch: case folded, every space removed (§2.6.2).
    Numeric,
    /// telephoneNumberMatch: every space and hyphen removed (§2.6.3).
    TelephoneNumber,
}

/// What a prepared string is (RFC 4518 §2.6.1): an attribute or assertion
/// value, or a part of a substring assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LDAPString {
    Value,
    InitialSubstring,
    AnySubstring,
    FinalSubstring,
}

/// The string preparation of LDAP (RFC 4518, with its verified errata
/// 860, 1757 and 1758): the six steps that make strings comparable, which
/// RFC 5280 §7.1 requires for distinguished names. Its character
/// repertoire is Unicode 3.2.
pub struct LDAPPrep;

impl LDAPPrep {
    /// The code points mapped to nothing (§2.2): soft hyphens, joiners,
    /// variation selectors (U+FE00 to U+FE0F, erratum 860), the object
    /// replacement character, ZERO WIDTH SPACE, and the control code points
    /// other than those mapped to SPACE.
    pub const NOTHING: &'static [(u32, u32)] = &[
        (0x0000, 0x0008),
        (0x000E, 0x001F),
        (0x007F, 0x0084),
        (0x0086, 0x009F),
        (0x00AD, 0x00AD),
        (0x034F, 0x034F),
        (0x06DD, 0x06DD),
        (0x070F, 0x070F),
        (0x1806, 0x1806),
        (0x180B, 0x180E),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2063),
        (0x206A, 0x206F),
        (0xFE00, 0xFE0F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFC),
        (0x1D173, 0x1D17A),
        (0xE0001, 0xE0001),
        (0xE0020, 0xE007F),
    ];
    /// The code points mapped to SPACE (§2.2): the separators and the
    /// controls of white space.
    pub const SPACE: &'static [(u32, u32)] = &[
        (0x0009, 0x000D),
        (0x0020, 0x0020),
        (0x0085, 0x0085),
        (0x00A0, 0x00A0),
        (0x1680, 0x1680),
        (0x2000, 0x200A),
        (0x2028, 0x2029),
        (0x202F, 0x202F),
        (0x205F, 0x205F),
        (0x3000, 0x3000),
    ];
    /// The hyphens of telephone numbers (§2.6.3).
    pub const HYPHENS: &'static [char] =
        &['\u{002D}', '\u{058A}', '\u{2010}', '\u{2011}', '\u{2212}', '\u{FE63}', '\u{FF0D}'];
    /// The tables prohibited (§2.4), besides U+FFFD.
    pub const PROHIBITED: &'static [StringPrepTable] =
        &[StringPrepTable::A1, StringPrepTable::C8, StringPrepTable::C3, StringPrepTable::C4, StringPrepTable::C5];

    /// Whether `character` is a combining mark of Unicode 3.2.
    pub fn is_combining_mark(character: char) -> bool {
        StringPrepTable::ranges_contain(LDAPPrep::COMBINING_MARKS, character as u32)
    }

    /// `text`, already transcoded to Unicode (§2.1), prepared for `matching` as `kind`.
    pub fn prepare(text: &str, matching: LDAPMatching, kind: LDAPString) -> Result<String, StringPrepError> {
        let fold = matches!(matching, LDAPMatching::CaseIgnore | LDAPMatching::Numeric);
        let mut mapped = String::with_capacity(text.len());
        for character in text.chars() {
            let point = character as u32;
            if StringPrepTable::ranges_contain(LDAPPrep::NOTHING, point) {
                continue;
            }
            if StringPrepTable::ranges_contain(LDAPPrep::SPACE, point) {
                mapped.push(' ');
            } else if let Some(folded) = StringPrepTable::B2.mapping(character).filter(|_| fold) {
                mapped.push_str(folded);
            } else {
                mapped.push(character);
            }
        }
        let normalized = NormalizationForm::NFKC.normalize(&mapped);
        for character in normalized.chars() {
            if StringPrepTable::A1.contains(character) {
                return Err(StringPrepError::Unassigned(character));
            }
            let prohibited = LDAPPrep::PROHIBITED.iter().any(|table| table.contains(character));
            if prohibited || character == '\u{FFFD}' {
                return Err(StringPrepError::Prohibited(character));
            }
        }
        let characters: Vec<char> = normalized.chars().collect();
        Ok(match matching {
            LDAPMatching::CaseIgnore | LDAPMatching::Exact => LDAPPrep::handle_spaces(&characters, kind),
            LDAPMatching::Numeric => LDAPPrep::remove(&characters, |character| character == ' '),
            LDAPMatching::TelephoneNumber => {
                LDAPPrep::remove(&characters, |character| character == ' ' || LDAPPrep::HYPHENS.contains(&character))
            }
        })
    }

    /// Whether `characters[index]` is a space: SPACE followed by no combining mark (§2.6.1).
    pub fn is_space(characters: &[char], index: usize) -> bool {
        characters[index] == ' ' && characters.get(index + 1).is_none_or(|&next| !LDAPPrep::is_combining_mark(next))
    }

    /// `characters` without those `insignificant` matches when no combining mark follows them.
    pub fn remove(characters: &[char], insignificant: impl Fn(char) -> bool) -> String {
        (0..characters.len())
            .filter(|&index| {
                let followed_by_mark = characters.get(index + 1).is_some_and(|&next| LDAPPrep::is_combining_mark(next));
                !insignificant(characters[index]) || followed_by_mark
            })
            .map(|index| characters[index])
            .collect()
    }

    /// The insignificant space handling of §2.6.1 (with errata 1757 and 1758).
    pub fn handle_spaces(characters: &[char], kind: LDAPString) -> String {
        let spaces: Vec<bool> = (0..characters.len()).map(|index| LDAPPrep::is_space(characters, index)).collect();
        let Some(first) = spaces.iter().position(|&space| !space) else {
            return String::from(if kind == LDAPString::Value { "  " } else { " " });
        };
        let last = spaces.iter().rposition(|&space| !space).unwrap_or(first);
        let (leading, trailing) = (first > 0, last + 1 < characters.len());
        let mut output = String::with_capacity(characters.len() + 2);
        let starts_with_space = match kind {
            LDAPString::Value | LDAPString::InitialSubstring => true,
            LDAPString::AnySubstring | LDAPString::FinalSubstring => leading,
        };
        if starts_with_space {
            output.push(' ');
        }
        let mut index = first;
        while index <= last {
            if spaces[index] {
                // An inner sequence of spaces becomes exactly two.
                while spaces[index] {
                    index += 1;
                }
                output.push_str("  ");
                continue;
            }
            output.push(characters[index]);
            index += 1;
        }
        let ends_with_space = match kind {
            LDAPString::Value | LDAPString::FinalSubstring => true,
            LDAPString::InitialSubstring | LDAPString::AnySubstring => trailing,
        };
        if ends_with_space {
            output.push(' ');
        }
        output
    }
}
