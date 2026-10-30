use alloc::string::String;

use super::{NormalizationForm, StringPrepError, StringPrepTable};
use crate::secret::Zeroize;

/// What the mapping step does with the code points of a table (RFC 3454 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StringPrepMapping {
    /// Removes them.
    Nothing,
    /// Replaces them with SPACE (U+0020).
    Space,
    /// Replaces them with what the table maps them to (B.1, B.2, B.3).
    Table,
}

/// Whether a string may hold code points unassigned in Unicode 3.2 (RFC 3454 §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unassigned {
    /// Queries may hold them.
    Allowed,
    /// Stored strings may not.
    Prohibited,
}

/// A profile of stringprep (RFC 3454 §2): the mappings, the normalization,
/// the prohibited tables, and whether bidirectional text is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StringPrepProfile {
    /// Applied in order to each code point; the first table that has it decides.
    pub mappings: &'static [(StringPrepTable, StringPrepMapping)],
    pub normalization: Option<NormalizationForm>,
    pub prohibited: &'static [StringPrepTable],
    /// Whether the rules of RFC 3454 §6 apply (the profile then prohibits C.8).
    pub check_bidi: bool,
}

impl StringPrepProfile {
    /// The most bytes a mapping writes for one byte of input (B.2 maps a
    /// code point to at most four, each at most four bytes).
    pub const MAXIMUM_EXPANSION: usize = 16;

    /// SASLprep (RFC 4013): non-ASCII spaces to SPACE, B.1 to nothing, NFKC,
    /// the tables of §2.3 prohibited, bidirectional text checked.
    pub const SASLPREP: StringPrepProfile = StringPrepProfile {
        mappings: &[
            (StringPrepTable::C12, StringPrepMapping::Space),
            (StringPrepTable::B1, StringPrepMapping::Nothing),
        ],
        normalization: Some(NormalizationForm::NFKC),
        prohibited: &[
            StringPrepTable::C12,
            StringPrepTable::C21,
            StringPrepTable::C22,
            StringPrepTable::C3,
            StringPrepTable::C4,
            StringPrepTable::C5,
            StringPrepTable::C6,
            StringPrepTable::C7,
            StringPrepTable::C8,
            StringPrepTable::C9,
        ],
        check_bidi: true,
    };

    /// The "trace" profile of RFC 4505 §3, for the trace information of SASL
    /// ANONYMOUS: no mapping and no normalization, the tables of §3
    /// prohibited, bidirectional text checked.
    pub const TRACE: StringPrepProfile = StringPrepProfile {
        mappings: &[],
        normalization: None,
        prohibited: &[
            StringPrepTable::C21,
            StringPrepTable::C22,
            StringPrepTable::C3,
            StringPrepTable::C4,
            StringPrepTable::C5,
            StringPrepTable::C6,
            StringPrepTable::C8,
            StringPrepTable::C9,
        ],
        check_bidi: true,
    };

    /// `text` prepared by the profile: mapped, normalized, then checked
    /// against the prohibited tables, the unassigned code points (for a
    /// stored string) and the rules of bidirectional text.
    ///
    /// The intermediate strings are zeroized, and so is the result when a
    /// check fails, as the text may be a password.
    pub fn prepare(&self, text: &str, unassigned: Unassigned) -> Result<String, StringPrepError> {
        // A mapping writes at most four code points of four bytes (B.2): the buffer does not move.
        let mut mapped = String::with_capacity(text.len().saturating_mul(StringPrepProfile::MAXIMUM_EXPANSION));
        for character in text.chars() {
            let rule = self.mappings.iter().find(|(table, _)| table.contains(character));
            match rule {
                Some((_, StringPrepMapping::Nothing)) => {}
                Some((_, StringPrepMapping::Space)) => mapped.push(' '),
                Some((table, StringPrepMapping::Table)) => {
                    mapped.push_str(table.mapping(character).unwrap_or_default())
                }
                None => mapped.push(character),
            }
        }
        let mut prepared = match self.normalization {
            Some(form) => {
                let normalized = form.normalize(&mapped);
                mapped.zeroize();
                normalized
            }
            None => mapped,
        };
        if let Err(error) = self.check(&prepared, unassigned) {
            prepared.zeroize();
            return Err(error);
        }
        Ok(prepared)
    }

    /// The checks of a prepared string: the prohibited tables, the
    /// unassigned code points (for a stored string) and bidirectional text.
    pub fn check(&self, prepared: &str, unassigned: Unassigned) -> Result<(), StringPrepError> {
        for character in prepared.chars() {
            if self.prohibited.iter().any(|table| table.contains(character)) {
                return Err(StringPrepError::Prohibited(character));
            }
            if unassigned == Unassigned::Prohibited && StringPrepTable::A1.contains(character) {
                return Err(StringPrepError::Unassigned(character));
            }
        }
        if self.check_bidi {
            StringPrepProfile::check_bidi(prepared)?;
        }
        Ok(())
    }

    /// The rules of RFC 3454 §6: a string with a right-to-left character
    /// (D.1) has no left-to-right character (D.2), and begins and ends with
    /// a right-to-left character.
    pub fn check_bidi(text: &str) -> Result<(), StringPrepError> {
        if !text.chars().any(|character| StringPrepTable::D1.contains(character)) {
            return Ok(());
        }
        let left_to_right = text.chars().any(|character| StringPrepTable::D2.contains(character));
        let first = text.chars().next().is_some_and(|character| StringPrepTable::D1.contains(character));
        let last = text.chars().next_back().is_some_and(|character| StringPrepTable::D1.contains(character));
        if left_to_right || !first || !last {
            return Err(StringPrepError::Bidi);
        }
        Ok(())
    }
}
