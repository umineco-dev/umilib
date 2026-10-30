use core::fmt;

/// An address (ADRS) of FIPS 205 section 4.2: 32 bytes of big-endian words
/// that locate each call of a hash function in the hypertree and FORS.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SLHDSAAddress {
    bytes: [u8; 32],
}

impl SLHDSAAddress {
    /// The type of a WOTS+ hash address.
    pub const WOTS_HASH: u32 = 0;
    /// The type of a WOTS+ public-key compression address.
    pub const WOTS_PK: u32 = 1;
    /// The type of a hash tree address.
    pub const TREE: u32 = 2;
    /// The type of a FORS tree address.
    pub const FORS_TREE: u32 = 3;
    /// The type of a FORS tree roots compression address.
    pub const FORS_ROOTS: u32 = 4;
    /// The type of a WOTS+ key generation address.
    pub const WOTS_PRF: u32 = 5;
    /// The type of a FORS key generation address.
    pub const FORS_PRF: u32 = 6;

    /// toByte(0, 32).
    pub fn new() -> SLHDSAAddress {
        SLHDSAAddress { bytes: [0; 32] }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// ADRSc of section 11.2: ADRS\[3\] || ADRS\[8:16\] || ADRS\[19\] || ADRS\[20:32\].
    pub fn compressed(&self) -> [u8; 22] {
        let mut out = [0u8; 22];
        out[0] = self.bytes[3];
        out[1..9].copy_from_slice(&self.bytes[8..16]);
        out[9] = self.bytes[19];
        out[10..].copy_from_slice(&self.bytes[20..]);
        out
    }

    /// Writes the big-endian word `value` at the byte `offset`.
    pub fn set_word(&mut self, offset: usize, value: u32) {
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    pub fn set_layer_address(&mut self, layer: u32) {
        self.set_word(0, layer);
    }

    /// The tree address, toByte(t, 12); the trees of the parameter sets have 64-bit indices.
    pub fn set_tree_address(&mut self, tree: u64) {
        self.bytes[4..8].fill(0);
        self.bytes[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    /// Sets the type and zeroes the final 12 bytes.
    pub fn set_type_and_clear(&mut self, kind: u32) {
        self.set_word(16, kind);
        self.bytes[20..].fill(0);
    }

    pub fn set_key_pair_address(&mut self, index: u32) {
        self.set_word(20, index);
    }

    pub fn key_pair_address(&self) -> u32 {
        u32::from_be_bytes([self.bytes[20], self.bytes[21], self.bytes[22], self.bytes[23]])
    }

    pub fn set_chain_address(&mut self, index: u32) {
        self.set_word(24, index);
    }

    pub fn set_tree_height(&mut self, height: u32) {
        self.set_word(24, height);
    }

    pub fn set_hash_address(&mut self, index: u32) {
        self.set_word(28, index);
    }

    pub fn set_tree_index(&mut self, index: u32) {
        self.set_word(28, index);
    }

    pub fn tree_index(&self) -> u32 {
        u32::from_be_bytes([self.bytes[28], self.bytes[29], self.bytes[30], self.bytes[31]])
    }
}

impl Default for SLHDSAAddress {
    fn default() -> SLHDSAAddress {
        SLHDSAAddress::new()
    }
}

impl fmt::Debug for SLHDSAAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SLHDSAAddress(")?;
        for byte in &self.bytes {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}
