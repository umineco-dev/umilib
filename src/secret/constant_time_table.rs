use core::fmt;

use super::Zeroize;

/// A table of entries of `BITS` bits (1, 2, 4, 8, 16 or 32) packed into
/// `WORDS` 64-bit words, whose reads and writes take the same time for every
/// index: each one touches every word of the table and selects with masks.
///
/// Block ciphers defined by lookup tables (S-boxes) use it so that no memory
/// access depends on secret data, which a cache would reveal. A lookup costs
/// one mask for each word and one for each entry of a word; the masks come
/// from differences that pass through [`core::hint::black_box`], as in
/// [`ConstantTimeEq`](super::ConstantTimeEq). The number of entries is a
/// power of two, and an index is taken modulo it.
#[derive(Clone)]
pub struct ConstantTimeTable<const WORDS: usize, const BITS: u32> {
    words: [u64; WORDS],
}

impl<const WORDS: usize, const BITS: u32> ConstantTimeTable<WORDS, BITS> {
    /// The number of entries.
    pub const ENTRIES: usize = WORDS * (64 / BITS as usize);
    /// The number of entries in a word.
    pub const ENTRIES_PER_WORD: usize = 64 / BITS as usize;
    /// The bits of an entry.
    pub const ENTRY_MASK: u64 = (1u64 << BITS) - 1;
    const SHAPE: () = assert!(
        matches!(BITS, 1 | 2 | 4 | 8 | 16 | 32) && WORDS > 0 && (WORDS * (64 / BITS as usize)).is_power_of_two(),
        "a table has entries of 1, 2, 4, 8, 16 or 32 bits and a power of two of them"
    );

    /// The table whose entries are all zero.
    pub const fn new() -> ConstantTimeTable<WORDS, BITS> {
        #[allow(clippy::let_unit_value)]
        let () = ConstantTimeTable::<WORDS, BITS>::SHAPE;
        ConstantTimeTable { words: [0; WORDS] }
    }

    /// The table of `entries`, which must be [`ENTRIES`](Self::ENTRIES)
    /// values of at most `BITS` bits each; in a constant, a mismatch fails
    /// the compilation.
    pub const fn from_entries(entries: &[u32]) -> ConstantTimeTable<WORDS, BITS> {
        let mut table = ConstantTimeTable::<WORDS, BITS>::new();
        assert!(
            entries.len() == ConstantTimeTable::<WORDS, BITS>::ENTRIES,
            "the number of entries does not match the table"
        );
        let mut index = 0;
        while index < entries.len() {
            let entry = entries[index] as u64;
            assert!(
                entry <= ConstantTimeTable::<WORDS, BITS>::ENTRY_MASK,
                "an entry does not fit in the bits of the table"
            );
            let per_word = ConstantTimeTable::<WORDS, BITS>::ENTRIES_PER_WORD;
            table.words[index / per_word] |= entry << ((index % per_word) as u32 * BITS);
            index += 1;
        }
        table
    }

    /// The table of `entries` of at most 8 bits, as [`from_entries`](Self::from_entries).
    pub const fn from_bytes(entries: &[u8]) -> ConstantTimeTable<WORDS, BITS> {
        let mut table = ConstantTimeTable::<WORDS, BITS>::new();
        assert!(
            entries.len() == ConstantTimeTable::<WORDS, BITS>::ENTRIES,
            "the number of entries does not match the table"
        );
        let mut index = 0;
        while index < entries.len() {
            let entry = entries[index] as u64;
            assert!(
                entry <= ConstantTimeTable::<WORDS, BITS>::ENTRY_MASK,
                "an entry does not fit in the bits of the table"
            );
            let per_word = ConstantTimeTable::<WORDS, BITS>::ENTRIES_PER_WORD;
            table.words[index / per_word] |= entry << ((index % per_word) as u32 * BITS);
            index += 1;
        }
        table
    }

    /// All ones if `a == b` and zero otherwise, without branching on them.
    pub fn mask(a: usize, b: usize) -> u64 {
        let difference = core::hint::black_box((a ^ b) as u64);
        // The highest bit of `x | -x` is set exactly when `x != 0`.
        ((difference | difference.wrapping_neg()) >> 63).wrapping_sub(1)
    }

    /// The entry at `index` (modulo [`ENTRIES`](Self::ENTRIES)).
    pub fn get(&self, index: usize) -> u32 {
        let index = index & (ConstantTimeTable::<WORDS, BITS>::ENTRIES - 1);
        let per_word = ConstantTimeTable::<WORDS, BITS>::ENTRIES_PER_WORD;
        let (word_index, slot) = (index / per_word, index % per_word);
        let mut word = 0u64;
        for (position, value) in self.words.iter().enumerate() {
            word |= value & ConstantTimeTable::<WORDS, BITS>::mask(position, word_index);
        }
        let mut entry = 0u64;
        for position in 0..per_word {
            let value = (word >> (position as u32 * BITS)) & ConstantTimeTable::<WORDS, BITS>::ENTRY_MASK;
            entry |= value & ConstantTimeTable::<WORDS, BITS>::mask(position, slot);
        }
        entry as u32
    }

    /// Replaces the entry at `index` (modulo [`ENTRIES`](Self::ENTRIES)) with
    /// the low `BITS` bits of `value`.
    pub fn set(&mut self, index: usize, value: u32) {
        let index = index & (ConstantTimeTable::<WORDS, BITS>::ENTRIES - 1);
        let per_word = ConstantTimeTable::<WORDS, BITS>::ENTRIES_PER_WORD;
        let (word_index, slot) = (index / per_word, index % per_word);
        let value = value as u64 & ConstantTimeTable::<WORDS, BITS>::ENTRY_MASK;
        // The bits of the entry in its word, and its new value there.
        let (mut clear, mut insert) = (0u64, 0u64);
        for position in 0..per_word {
            let mask = ConstantTimeTable::<WORDS, BITS>::mask(position, slot);
            let shift = position as u32 * BITS;
            clear |= (ConstantTimeTable::<WORDS, BITS>::ENTRY_MASK << shift) & mask;
            insert |= (value << shift) & mask;
        }
        for (position, word) in self.words.iter_mut().enumerate() {
            let mask = ConstantTimeTable::<WORDS, BITS>::mask(position, word_index);
            *word = (*word & !(clear & mask)) | (insert & mask);
        }
    }

    /// Exchanges the entries at `first` and `second`.
    pub fn swap(&mut self, first: usize, second: usize) {
        let (a, b) = (self.get(first), self.get(second));
        self.set(first, b);
        self.set(second, a);
    }

    /// The packed words: entry `i` is bits `BITS × (i mod ENTRIES_PER_WORD)`
    /// and up of word `i / ENTRIES_PER_WORD`.
    pub fn words(&self) -> &[u64; WORDS] {
        &self.words
    }
}

impl<const WORDS: usize, const BITS: u32> Default for ConstantTimeTable<WORDS, BITS> {
    fn default() -> ConstantTimeTable<WORDS, BITS> {
        ConstantTimeTable::new()
    }
}

impl<const WORDS: usize, const BITS: u32> Zeroize for ConstantTimeTable<WORDS, BITS> {
    fn zeroize(&mut self) {
        self.words.zeroize();
    }
}

impl<const WORDS: usize, const BITS: u32> fmt::Debug for ConstantTimeTable<WORDS, BITS> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ConstantTimeTable({} entries of {BITS} bits, ..)", ConstantTimeTable::<WORDS, BITS>::ENTRIES)
    }
}
