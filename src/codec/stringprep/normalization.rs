use alloc::string::String;
use alloc::vec::Vec;

use crate::secret::Zeroize;

/// A normalization form of Unicode 3.2 (UAX #15 version 3.2), the version
/// stringprep (RFC 3454) and the profiles built on it are defined with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NormalizationForm {
    /// Canonical decomposition.
    NFD,
    /// Canonical decomposition, then canonical composition.
    NFC,
    /// Compatibility decomposition.
    NFKD,
    /// Compatibility decomposition, then canonical composition.
    NFKC,
}

impl NormalizationForm {
    /// The most code points the full decomposition of one code point has
    /// in Unicode 3.2 (NFKD of U+FDFA).
    pub const MAXIMUM_EXPANSION: usize = 18;

    pub const HANGUL_S_BASE: u32 = 0xAC00;
    pub const HANGUL_L_BASE: u32 = 0x1100;
    pub const HANGUL_V_BASE: u32 = 0x1161;
    pub const HANGUL_T_BASE: u32 = 0x11A7;
    pub const HANGUL_L_COUNT: u32 = 19;
    pub const HANGUL_V_COUNT: u32 = 21;
    pub const HANGUL_T_COUNT: u32 = 28;
    pub const HANGUL_N_COUNT: u32 = NormalizationForm::HANGUL_V_COUNT * NormalizationForm::HANGUL_T_COUNT;
    pub const HANGUL_S_COUNT: u32 = NormalizationForm::HANGUL_L_COUNT * NormalizationForm::HANGUL_N_COUNT;

    /// Whether the form decomposes compatibility mappings too.
    pub const fn is_compatibility(self) -> bool {
        matches!(self, NormalizationForm::NFKD | NormalizationForm::NFKC)
    }

    /// Whether the form composes after decomposing.
    pub const fn is_composed(self) -> bool {
        matches!(self, NormalizationForm::NFC | NormalizationForm::NFKC)
    }

    /// The canonical combining class of `character` in Unicode 3.2.
    pub fn combining_class(character: char) -> u8 {
        let point = character as u32;
        let classes = NormalizationForm::COMBINING_CLASSES;
        let found = classes.binary_search_by(|&(low, high, _)| {
            if high < point {
                core::cmp::Ordering::Less
            } else if low > point {
                core::cmp::Ordering::Greater
            } else {
                core::cmp::Ordering::Equal
            }
        });
        found.map_or(0, |index| classes[index].2)
    }

    /// The decomposition mapping of `character` (one level) and whether it
    /// is a compatibility one, if it has one.
    pub fn decomposition(character: char) -> Option<(bool, &'static str)> {
        let decompositions = NormalizationForm::DECOMPOSITIONS;
        let index = decompositions.binary_search_by_key(&(character as u32), |&(point, _, _)| point).ok()?;
        Some((decompositions[index].1, decompositions[index].2))
    }

    /// The primary composite of `first` followed by `second`, if there is one.
    pub fn composition(first: char, second: char) -> Option<char> {
        let (first, second) = (first as u32, second as u32);
        let (l, v, t, s) = (
            NormalizationForm::HANGUL_L_BASE,
            NormalizationForm::HANGUL_V_BASE,
            NormalizationForm::HANGUL_T_BASE,
            NormalizationForm::HANGUL_S_BASE,
        );
        if (l..l + NormalizationForm::HANGUL_L_COUNT).contains(&first)
            && (v..v + NormalizationForm::HANGUL_V_COUNT).contains(&second)
        {
            let lv = s
                + ((first - l) * NormalizationForm::HANGUL_V_COUNT + (second - v)) * NormalizationForm::HANGUL_T_COUNT;
            return char::from_u32(lv);
        }
        let syllable = (s..s + NormalizationForm::HANGUL_S_COUNT).contains(&first);
        if syllable
            && (first - s).is_multiple_of(NormalizationForm::HANGUL_T_COUNT)
            && (t + 1..t + NormalizationForm::HANGUL_T_COUNT).contains(&second)
        {
            return char::from_u32(first + (second - t));
        }
        let compositions = NormalizationForm::COMPOSITIONS;
        let index = compositions.binary_search_by_key(&(first, second), |&(a, b, _)| (a, b)).ok()?;
        char::from_u32(compositions[index].2)
    }

    /// Appends the full decomposition of `character` to `output`.
    pub fn decompose(self, character: char, output: &mut Vec<char>) {
        let point = character as u32;
        let s = NormalizationForm::HANGUL_S_BASE;
        if (s..s + NormalizationForm::HANGUL_S_COUNT).contains(&point) {
            let index = point - s;
            let parts = [
                NormalizationForm::HANGUL_L_BASE + index / NormalizationForm::HANGUL_N_COUNT,
                NormalizationForm::HANGUL_V_BASE
                    + (index % NormalizationForm::HANGUL_N_COUNT) / NormalizationForm::HANGUL_T_COUNT,
                NormalizationForm::HANGUL_T_BASE + index % NormalizationForm::HANGUL_T_COUNT,
            ];
            let count = if parts[2] == NormalizationForm::HANGUL_T_BASE { 2 } else { 3 };
            output.extend(parts[..count].iter().filter_map(|&part| char::from_u32(part)));
            return;
        }
        match NormalizationForm::decomposition(character) {
            Some((compatibility, mapping)) if self.is_compatibility() || !compatibility => {
                mapping.chars().for_each(|part| self.decompose(part, output));
            }
            _ => output.push(character),
        }
    }

    /// Sorts each run of non-starters by combining class, keeping the
    /// order of equal classes (the canonical ordering of UAX #15).
    pub fn order(characters: &mut [char]) {
        let mut start = 0;
        while start < characters.len() {
            if NormalizationForm::combining_class(characters[start]) == 0 {
                start += 1;
                continue;
            }
            let end = characters[start..]
                .iter()
                .position(|&character| NormalizationForm::combining_class(character) == 0)
                .map_or(characters.len(), |offset| start + offset);
            characters[start..end].sort_by_key(|&character| NormalizationForm::combining_class(character));
            start = end;
        }
    }

    /// Composes `characters`, canonically ordered, in place (UAX #15 section 5).
    pub fn compose(characters: &mut Vec<char>) {
        let Some(&first) = characters.first() else { return };
        let mut starter = 0;
        let mut starter_character = first;
        // A non-starter at the start has no starter to compose with.
        let mut last_class = match NormalizationForm::combining_class(first) {
            0 => 0,
            _ => 256,
        };
        let mut written = 1;
        for index in 1..characters.len() {
            let character = characters[index];
            let class = NormalizationForm::combining_class(character) as u16;
            let composite = NormalizationForm::composition(starter_character, character);
            match composite {
                Some(composite) if last_class < class || last_class == 0 => {
                    characters[starter] = composite;
                    starter_character = composite;
                }
                _ => {
                    if class == 0 {
                        starter = written;
                        starter_character = character;
                    }
                    last_class = class;
                    characters[written] = character;
                    written += 1;
                }
            }
        }
        characters.truncate(written);
    }

    /// `text` in this form. The working buffer is zeroized, as the text may
    /// be a password; it is sized for the longest decomposition (18 code
    /// points per code point, NFKD of U+FDFA) so that it does not move.
    pub fn normalize(self, text: &str) -> String {
        let mut characters =
            Vec::with_capacity(text.chars().count().saturating_mul(NormalizationForm::MAXIMUM_EXPANSION));
        text.chars().for_each(|character| self.decompose(character, &mut characters));
        NormalizationForm::order(&mut characters);
        if self.is_composed() {
            NormalizationForm::compose(&mut characters);
        }
        let mut normalized = String::with_capacity(characters.iter().map(|character| character.len_utf8()).sum());
        normalized.extend(characters.iter());
        characters.zeroize();
        normalized
    }
}
