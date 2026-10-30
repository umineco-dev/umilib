use alloc::vec;
use alloc::vec::Vec;

use crate::codec::CompressionError;

/// The parameters of an [`LZ77MatchFinder`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZ77MatchFinderConfig {
    /// The base-2 logarithm of the window (8 to 30): the data are kept and
    /// discarded in multiples of it.
    pub window_bits: u32,
    /// The base-2 logarithm of the chains of candidates (at most
    /// `window_bits`): candidates further back than 2^chain_bits are found
    /// only as the first of their hash.
    pub chain_bits: u32,
    /// The base-2 logarithm of the number of hash heads (8 to 24).
    pub hash_bits: u32,
    /// The farthest distance of a match, at most 2^window_bits.
    pub maximum_distance: usize,
    /// The shortest match (2 or more); the first min(minimum_length, 4) bytes are hashed.
    pub minimum_length: usize,
    /// The longest match.
    pub maximum_length: usize,
    /// The most candidates examined for a match.
    pub chain_limit: usize,
    /// A match at least this long ends the search.
    pub nice_length: usize,
}

impl LZ77MatchFinderConfig {
    /// Checks the ranges of the parameters.
    pub fn check(&self) -> Result<(), CompressionError> {
        let valid = (8..=30).contains(&self.window_bits)
            && self.chain_bits <= self.window_bits
            && (8..=24).contains(&self.hash_bits)
            && (1..=1 << self.window_bits).contains(&self.maximum_distance)
            && self.minimum_length >= 2
            && self.maximum_length >= self.minimum_length
            && self.chain_limit >= 1;
        if valid { Ok(()) } else { Err(CompressionError::InvalidParameter) }
    }

    /// The number of bytes hashed.
    pub fn hash_length(&self) -> usize {
        self.minimum_length.min(4)
    }
}

/// A match: `length` bytes equal to those `distance` bytes back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZ77Match {
    pub distance: usize,
    pub length: usize,
}

/// Finds matches for an LZ77 compressor with hash chains: the data to
/// compress are appended after the history ([`LZ77MatchFinder::append`]),
/// and [`LZ77MatchFinder::find`] searches the positions before a position
/// that share the hash of its first bytes, newest first.
///
/// Positions are indices into [`LZ77MatchFinder::data`];
/// [`LZ77MatchFinder::discard`] drops old data (in multiples of the window)
/// and the caller subtracts what it returns from its positions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZ77MatchFinder {
    config: LZ77MatchFinderConfig,
    data: Vec<u8>,
    /// Per hash, the latest position with it, plus 1 (0 for none).
    heads: Vec<u32>,
    /// Per position modulo 2^chain_bits, the previous position with its hash, plus 1.
    chains: Vec<u32>,
    /// The positions below this one are in the chains.
    inserted: usize,
}

impl LZ77MatchFinder {
    /// The multiplier of the hash (2^32 / φ).
    pub const HASH_MULTIPLIER: u32 = 0x9E37_79B1;

    /// A finder of the parameters `config`; fails with `InvalidParameter` outside their ranges.
    pub fn new(config: LZ77MatchFinderConfig) -> Result<LZ77MatchFinder, CompressionError> {
        config.check()?;
        Ok(LZ77MatchFinder {
            config,
            data: Vec::new(),
            heads: vec![0; 1 << config.hash_bits],
            chains: vec![0; 1 << config.chain_bits],
            inserted: 0,
        })
    }

    pub fn config(&self) -> &LZ77MatchFinderConfig {
        &self.config
    }

    /// The history and the data appended, from the oldest kept byte.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Appends `bytes` after the data.
    pub fn append(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    /// The hash of the bytes at `position` (which must have hash_length bytes).
    pub fn hash(&self, position: usize) -> usize {
        let length = self.config.hash_length();
        let mut word = 0u32;
        for (index, byte) in self.data[position..position + length].iter().enumerate() {
            word |= (*byte as u32) << (8 * index);
        }
        (word.wrapping_mul(LZ77MatchFinder::HASH_MULTIPLIER) >> (32 - self.config.hash_bits)) as usize
    }

    /// Adds the positions before `end` to the chains (those with fewer than
    /// hash_length bytes after them wait for more data).
    pub fn insert(&mut self, end: usize) {
        let last = (self.data.len() + 1).saturating_sub(self.config.hash_length()).min(end);
        let chain_mask = (1usize << self.config.chain_bits) - 1;
        while self.inserted < last {
            let position = self.inserted;
            let hash = self.hash(position);
            self.chains[position & chain_mask] = self.heads[hash];
            self.heads[hash] = position as u32 + 1;
            self.inserted += 1;
        }
    }

    /// The longest match for the bytes at `position`, of at most
    /// `maximum_length` bytes (and the configured maximum), among the
    /// positions before it; inserts those positions first. `None` if no
    /// match reaches the minimum length.
    pub fn find(&mut self, position: usize, maximum_length: usize) -> Option<LZ77Match> {
        self.find_within(position, maximum_length, self.config.chain_limit)
    }

    /// [`LZ77MatchFinder::find`] examining at most `chain_limit` candidates
    /// (instead of the configured limit).
    pub fn find_within(&mut self, position: usize, maximum_length: usize, chain_limit: usize) -> Option<LZ77Match> {
        self.insert(position);
        let limit = maximum_length.min(self.config.maximum_length).min(self.data.len() - position);
        if limit < self.config.minimum_length || position + self.config.hash_length() > self.data.len() {
            return None;
        }
        let chain_mask = (1usize << self.config.chain_bits) - 1;
        let lowest = position.saturating_sub(self.config.maximum_distance);
        let linked = position.saturating_sub(1 << self.config.chain_bits);
        let target = &self.data[position..position + limit];
        let mut best: Option<LZ77Match> = None;
        let mut best_length = self.config.minimum_length - 1;
        let mut candidate = self.heads[self.hash(position)] as usize;
        for _ in 0..chain_limit {
            if candidate == 0 || candidate - 1 < lowest || candidate > position {
                break;
            }
            let start = candidate - 1;
            let source = &self.data[start..start + limit];
            // The byte that would make a longer match is checked first.
            if source[best_length] == target[best_length] {
                let length = source.iter().zip(target).take_while(|(a, b)| a == b).count();
                if length > best_length {
                    best_length = length;
                    best = Some(LZ77Match { distance: position - start, length });
                    if length >= self.config.nice_length || length == limit {
                        break;
                    }
                }
            }
            // The link of a position is overwritten once a position 2^chain_bits later is inserted.
            if start < linked {
                break;
            }
            let next = self.chains[start & chain_mask] as usize;
            if next >= candidate {
                break;
            }
            candidate = next;
        }
        best
    }

    /// Drops the data more than a window before `position`, in whole
    /// windows, and returns the number of bytes dropped (0 while less than
    /// two windows precede `position`); positions after it decrease by it.
    pub fn discard(&mut self, position: usize) -> usize {
        let window = 1usize << self.config.window_bits;
        if position < 2 * window {
            return 0;
        }
        let shift = (position - window) / window * window;
        self.data.drain(..shift);
        let shift32 = shift as u32;
        for entry in self.heads.iter_mut().chain(self.chains.iter_mut()) {
            *entry = entry.saturating_sub(shift32);
        }
        // Positions never inserted before the shift are gone with their data.
        self.inserted = self.inserted.saturating_sub(shift);
        shift
    }

    /// Empties the data and the chains, keeping the parameters and the allocations.
    pub fn clear(&mut self) {
        self.data.clear();
        self.heads.fill(0);
        self.chains.fill(0);
        self.inserted = 0;
    }
}
