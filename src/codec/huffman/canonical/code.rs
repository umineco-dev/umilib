use alloc::vec;
use alloc::vec::Vec;

use crate::codec::huffman::HuffmanError;

/// A canonical prefix code (RFC 1951 section 3.2.2): the lengths of the
/// codes of the symbols 0, 1, ... define the codes, the shorter ones first
/// and, among codes of one length, in the order of the symbols. A length of
/// 0 leaves a symbol without a code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HuffmanCode {
    lengths: Vec<u8>,
    codes: Vec<u32>,
    complete: bool,
}

impl HuffmanCode {
    /// The longest code (bits): 32, enough for every format of this crate
    /// (15 for Deflate and Brotli, 30 for HPACK, RFC 7541 Appendix B).
    pub const MAXIMUM_LENGTH: u32 = 32;
    /// The most symbols of an alphabet.
    pub const MAXIMUM_SYMBOLS: usize = 1 << 15;

    /// The code of the lengths `lengths` (each at most
    /// [`HuffmanCode::MAXIMUM_LENGTH`]); fails with `InvalidLengths` if they
    /// are over-subscribed. A code whose lengths leave codes unused (an
    /// incomplete code, which some formats allow) is accepted:
    /// [`HuffmanCode::is_complete`] tells.
    pub fn from_lengths(lengths: &[u8]) -> Result<HuffmanCode, HuffmanError> {
        if lengths.is_empty() || lengths.len() > HuffmanCode::MAXIMUM_SYMBOLS {
            return Err(HuffmanError::InvalidAlphabet { maximum: HuffmanCode::MAXIMUM_SYMBOLS });
        }
        let invalid = HuffmanError::InvalidLengths { maximum: HuffmanCode::MAXIMUM_LENGTH };
        const LENGTHS: usize = HuffmanCode::MAXIMUM_LENGTH as usize + 1;
        let mut counts = [0u64; LENGTHS];
        for length in lengths {
            if *length as u32 > HuffmanCode::MAXIMUM_LENGTH {
                return Err(invalid);
            }
            counts[*length as usize] += 1;
        }
        counts[0] = 0;
        // Σ 2^(32 - length) over the codes, at most 2^32.
        let full = 1u64 << HuffmanCode::MAXIMUM_LENGTH;
        let space: u64 =
            (1..LENGTHS).map(|length| counts[length] << (HuffmanCode::MAXIMUM_LENGTH as usize - length)).sum();
        if space > full {
            return Err(invalid);
        }
        // The first code of each length (RFC 1951 section 3.2.2 step 2).
        let mut next = [0u64; LENGTHS];
        let mut code = 0u64;
        for length in 1..LENGTHS {
            code = (code + counts[length - 1]) << 1;
            next[length] = code;
        }
        let mut codes = vec![0u32; lengths.len()];
        for (symbol, length) in lengths.iter().enumerate() {
            if *length > 0 {
                codes[symbol] = next[*length as usize] as u32;
                next[*length as usize] += 1;
            }
        }
        Ok(HuffmanCode { lengths: lengths.to_vec(), codes, complete: space == full })
    }

    /// A code of the symbols of `frequencies`, of lengths at most
    /// `maximum_length`, minimizing the total length of the coded data (by
    /// the package-merge algorithm). Symbols of frequency 0 get no code; an
    /// alphabet with a single used symbol gets it a code of length 1. Fails
    /// with `InvalidLengths` if `maximum_length` cannot hold the used symbols.
    pub fn from_frequencies(frequencies: &[u32], maximum_length: u32) -> Result<HuffmanCode, HuffmanError> {
        let lengths = HuffmanCode::lengths_from_frequencies(frequencies, maximum_length)?;
        HuffmanCode::from_lengths(&lengths)
    }

    /// The lengths [`HuffmanCode::from_frequencies`] assigns.
    pub fn lengths_from_frequencies(frequencies: &[u32], maximum_length: u32) -> Result<Vec<u8>, HuffmanError> {
        if frequencies.is_empty() || frequencies.len() > HuffmanCode::MAXIMUM_SYMBOLS {
            return Err(HuffmanError::InvalidAlphabet { maximum: HuffmanCode::MAXIMUM_SYMBOLS });
        }
        let maximum_length = maximum_length.min(HuffmanCode::MAXIMUM_LENGTH);
        let mut used: Vec<(u64, u16)> = frequencies
            .iter()
            .enumerate()
            .filter(|(_, frequency)| **frequency > 0)
            .map(|(symbol, frequency)| (*frequency as u64, symbol as u16))
            .collect();
        let mut lengths = vec![0u8; frequencies.len()];
        match used.len() {
            0 => return Ok(lengths),
            1 => {
                lengths[used[0].1 as usize] = 1;
                return Ok(lengths);
            }
            count if count as u64 > 1u64 << maximum_length => {
                return Err(HuffmanError::InvalidLengths { maximum: maximum_length });
            }
            _ => {}
        }
        used.sort_unstable();
        // Package-merge: the list of a level holds the leaves and the packages (pairs) of the
        // list of the level below, by weight; the 2n - 2 lightest items of the last level
        // contain each symbol as many times as its length.
        let leaves: Vec<(u64, u32)> = used.iter().map(|(weight, symbol)| (*weight, *symbol as u32)).collect();
        // An item is a leaf (its symbol) or a package (the index of its first item below, with the high bit set).
        const PACKAGE: u32 = 1 << 31;
        let mut levels: Vec<Vec<(u64, u32)>> = vec![leaves.clone()];
        for _ in 1..maximum_length {
            let below = &levels[levels.len() - 1];
            let mut list: Vec<(u64, u32)> = Vec::with_capacity(leaves.len() + below.len() / 2);
            let (mut leaf, mut pair) = (0, 0);
            while leaf < leaves.len() || pair + 1 < below.len() {
                let package_weight = if pair + 1 < below.len() { below[pair].0 + below[pair + 1].0 } else { u64::MAX };
                if leaf < leaves.len() && leaves[leaf].0 <= package_weight {
                    list.push(leaves[leaf]);
                    leaf += 1;
                } else {
                    list.push((package_weight, PACKAGE | pair as u32));
                    pair += 2;
                }
            }
            levels.push(list);
        }
        // Counts the leaves under the selected items, level by level downwards.
        let mut selected: Vec<u32> = (0..(2 * used.len() - 2) as u32).collect();
        for level in (0..levels.len()).rev() {
            let mut below = Vec::new();
            for index in selected {
                let item = levels[level][index as usize].1;
                if item & PACKAGE != 0 {
                    below.push(item & !PACKAGE);
                    below.push((item & !PACKAGE) + 1);
                } else {
                    lengths[item as usize] += 1;
                }
            }
            selected = below;
        }
        Ok(lengths)
    }

    /// The number of symbols of the alphabet.
    pub fn symbols(&self) -> usize {
        self.lengths.len()
    }

    pub fn lengths(&self) -> &[u8] {
        &self.lengths
    }

    /// The length of the code of `symbol`; 0 if it has none.
    pub fn length(&self, symbol: usize) -> u32 {
        self.lengths[symbol] as u32
    }

    /// The code of `symbol`, its first bit the most significant of its length.
    pub fn code(&self, symbol: usize) -> u32 {
        self.codes[symbol]
    }

    /// The code of `symbol` with its bits reversed, its first bit the least
    /// significant: the value to write with [`BitWriter`](crate::bytes::BitWriter).
    pub fn reversed_code(&self, symbol: usize) -> u32 {
        let length = self.length(symbol);
        if length == 0 { 0 } else { self.code(symbol).reverse_bits() >> (32 - length) }
    }

    /// The longest code.
    pub fn maximum_length(&self) -> u32 {
        self.lengths.iter().copied().max().unwrap_or(0) as u32
    }

    /// Whether the codes use every sequence of bits (Σ 2^-length = 1).
    pub fn is_complete(&self) -> bool {
        self.complete
    }
}
