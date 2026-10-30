use alloc::vec;
use alloc::vec::Vec;

/// The phrases of an LZ78 dictionary as a trie: phrase k (1 to n) is a
/// phrase before it followed by a byte; phrase 0 is the empty phrase.
/// When indexed, [`LZ78Dictionary::child`] finds the phrase of a phrase and
/// a byte through an open-addressing table, so a compressor needs no
/// per-node allocation; a decompressor, which only writes phrases, needs no index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZ78Dictionary {
    capacity: u32,
    indexed: bool,
    /// Per phrase: its prefix phrase, its last byte and its length.
    prefixes: Vec<u32>,
    bytes: Vec<u8>,
    lengths: Vec<u32>,
    /// Slots of (prefix << 8 | byte) + 1 and the phrase, 0 for empty.
    keys: Vec<u64>,
    values: Vec<u32>,
}

impl LZ78Dictionary {
    /// An empty dictionary of at most `capacity` phrases, with the index of
    /// [`LZ78Dictionary::child`] if `indexed`.
    pub fn new(capacity: u32, indexed: bool) -> LZ78Dictionary {
        LZ78Dictionary {
            capacity,
            indexed,
            prefixes: vec![0],
            bytes: vec![0],
            lengths: vec![0],
            keys: Vec::new(),
            values: Vec::new(),
        }
    }

    /// The number of phrases (the empty phrase not counted).
    pub fn len(&self) -> u32 {
        (self.prefixes.len() - 1) as u32
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// The slot of the index where the key (prefix << 8 | byte) + 1 is or goes.
    pub fn slot(&self, key: u64) -> usize {
        let mask = self.keys.len() - 1;
        let mut slot = (key.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as usize & mask;
        while self.keys[slot] != 0 && self.keys[slot] != key {
            slot = (slot + 1) & mask;
        }
        slot
    }

    /// The phrase `prefix` followed by `byte`, if it is in the dictionary.
    pub fn child(&self, prefix: u32, byte: u8) -> Option<u32> {
        if self.keys.is_empty() {
            return None;
        }
        let slot = self.slot(((prefix as u64) << 8 | byte as u64) + 1);
        (self.keys[slot] != 0).then(|| self.values[slot])
    }

    /// Adds the phrase `prefix` followed by `byte` (`prefix` at most the
    /// number of phrases) and returns its number; empties the dictionary
    /// instead once it holds `capacity` phrases.
    pub fn add(&mut self, prefix: u32, byte: u8) -> u32 {
        let phrase = self.prefixes.len() as u32;
        self.prefixes.push(prefix);
        self.bytes.push(byte);
        self.lengths.push(self.lengths[prefix as usize] + 1);
        if !self.indexed {
        } else if self.keys.len() < 2 * self.prefixes.len() {
            self.grow();
        } else {
            let key = ((prefix as u64) << 8 | byte as u64) + 1;
            let slot = self.slot(key);
            self.keys[slot] = key;
            self.values[slot] = phrase;
        }
        if self.len() == self.capacity {
            self.clear();
        }
        phrase
    }

    /// Rebuilds the index at least four times larger than the phrases, keeping it at most half full.
    pub fn grow(&mut self) {
        let size = (4 * self.prefixes.len()).next_power_of_two();
        self.keys = vec![0; size];
        self.values = vec![0; size];
        for phrase in 1..self.prefixes.len() {
            let key = ((self.prefixes[phrase] as u64) << 8 | self.bytes[phrase] as u64) + 1;
            let slot = self.slot(key);
            self.keys[slot] = key;
            self.values[slot] = phrase as u32;
        }
    }

    /// The length of `phrase`.
    pub fn length(&self, phrase: u32) -> usize {
        self.lengths[phrase as usize] as usize
    }

    /// Writes the bytes of `phrase` into `out`, which must have its length.
    pub fn write(&self, mut phrase: u32, out: &mut [u8]) {
        let mut index = self.length(phrase);
        while phrase != 0 {
            index -= 1;
            out[index] = self.bytes[phrase as usize];
            phrase = self.prefixes[phrase as usize];
        }
    }

    /// Removes every phrase, keeping the capacity.
    pub fn clear(&mut self) {
        self.prefixes.truncate(1);
        self.bytes.truncate(1);
        self.lengths.truncate(1);
        self.keys.fill(0);
    }
}
