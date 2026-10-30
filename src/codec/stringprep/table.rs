/// A table of RFC 3454: a set of code points (A.1, C.*, D.*) or a mapping
/// (B.1, B.2, B.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StringPrepTable {
    /// Unassigned code points in Unicode 3.2.
    A1,
    /// Commonly mapped to nothing.
    B1,
    /// Case folding for use with NFKC.
    B2,
    /// Case folding with no normalization.
    B3,
    /// ASCII space characters.
    C11,
    /// Non-ASCII space characters.
    C12,
    /// ASCII control characters.
    C21,
    /// Non-ASCII control characters.
    C22,
    /// Private use.
    C3,
    /// Non-character code points.
    C4,
    /// Surrogate codes.
    C5,
    /// Inappropriate for plain text.
    C6,
    /// Inappropriate for canonical representation.
    C7,
    /// Change display properties or are deprecated.
    C8,
    /// Tagging characters.
    C9,
    /// Characters with bidirectional property R or AL.
    D1,
    /// Characters with bidirectional property L.
    D2,
}

impl StringPrepTable {
    /// The code points of the table, as sorted ranges (for a mapping, the
    /// code points it maps are given by [`StringPrepTable::mappings`]).
    pub const fn ranges(self) -> &'static [(u32, u32)] {
        match self {
            StringPrepTable::A1 => StringPrepTable::A1_RANGES,
            StringPrepTable::C11 => StringPrepTable::C11_RANGES,
            StringPrepTable::C12 => StringPrepTable::C12_RANGES,
            StringPrepTable::C21 => StringPrepTable::C21_RANGES,
            StringPrepTable::C22 => StringPrepTable::C22_RANGES,
            StringPrepTable::C3 => StringPrepTable::C3_RANGES,
            StringPrepTable::C4 => StringPrepTable::C4_RANGES,
            StringPrepTable::C5 => StringPrepTable::C5_RANGES,
            StringPrepTable::C6 => StringPrepTable::C6_RANGES,
            StringPrepTable::C7 => StringPrepTable::C7_RANGES,
            StringPrepTable::C8 => StringPrepTable::C8_RANGES,
            StringPrepTable::C9 => StringPrepTable::C9_RANGES,
            StringPrepTable::D1 => StringPrepTable::D1_RANGES,
            StringPrepTable::D2 => StringPrepTable::D2_RANGES,
            StringPrepTable::B1 | StringPrepTable::B2 | StringPrepTable::B3 => &[],
        }
    }

    /// The mappings of B.1, B.2 and B.3, sorted by code point; empty for the other tables.
    pub const fn mappings(self) -> &'static [(u32, &'static str)] {
        match self {
            StringPrepTable::B1 => StringPrepTable::B1_MAPPINGS,
            StringPrepTable::B2 => StringPrepTable::B2_MAPPINGS,
            StringPrepTable::B3 => StringPrepTable::B3_MAPPINGS,
            _ => &[],
        }
    }

    /// Whether `ranges`, sorted and disjoint, contain `point`.
    pub fn ranges_contain(ranges: &[(u32, u32)], point: u32) -> bool {
        ranges
            .binary_search_by(|&(low, high)| {
                if high < point {
                    core::cmp::Ordering::Less
                } else if low > point {
                    core::cmp::Ordering::Greater
                } else {
                    core::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Whether the table has `character`: in its ranges, or mapped by it.
    pub fn contains(self, character: char) -> bool {
        StringPrepTable::ranges_contain(self.ranges(), character as u32) || self.mapping(character).is_some()
    }

    /// What the table maps `character` to, if it maps it ("" for B.1).
    pub fn mapping(self, character: char) -> Option<&'static str> {
        let mappings = self.mappings();
        mappings.binary_search_by_key(&(character as u32), |&(point, _)| point).ok().map(|index| mappings[index].1)
    }
}
