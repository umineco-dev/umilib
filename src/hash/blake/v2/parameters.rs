use crate::hash::HashError;

/// The parameter block of BLAKE2b (64 bytes): the output and key lengths,
/// the tree parameters, the salt and the personalization. The layout is that
/// of C, for the C ABI; the block itself is [`BLAKE2bParameters::to_bytes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct BLAKE2bParameters {
    pub digest_length: u8,
    pub key_length: u8,
    pub fanout: u8,
    pub depth: u8,
    pub leaf_length: u32,
    /// The lower half of the 64-bit node offset.
    pub node_offset: u32,
    /// The upper half of the node offset, which BLAKE2Xb uses for the output length.
    pub xof_length: u32,
    pub node_depth: u8,
    pub inner_length: u8,
    pub salt: [u8; 16],
    pub personal: [u8; 16],
}

impl BLAKE2bParameters {
    /// The sequential mode (fanout and depth 1) with `digest_length` bytes of output.
    pub const fn new(digest_length: u8) -> BLAKE2bParameters {
        BLAKE2bParameters {
            digest_length,
            key_length: 0,
            fanout: 1,
            depth: 1,
            leaf_length: 0,
            node_offset: 0,
            xof_length: 0,
            node_depth: 0,
            inner_length: 0,
            salt: [0; 16],
            personal: [0; 16],
        }
    }

    /// The block in the byte order of RFC 7693 section 2.5.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0] = self.digest_length;
        bytes[1] = self.key_length;
        bytes[2] = self.fanout;
        bytes[3] = self.depth;
        bytes[4..8].copy_from_slice(&self.leaf_length.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.node_offset.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.xof_length.to_le_bytes());
        bytes[16] = self.node_depth;
        bytes[17] = self.inner_length;
        bytes[32..48].copy_from_slice(&self.salt);
        bytes[48..64].copy_from_slice(&self.personal);
        bytes
    }

    /// The parameters of a block; fails if its reserved bytes 18 to 31 are not zero.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<BLAKE2bParameters, HashError> {
        if bytes[18..32].iter().any(|&byte| byte != 0) {
            return Err(HashError::InvalidParameter);
        }
        let word = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"));
        Ok(BLAKE2bParameters {
            digest_length: bytes[0],
            key_length: bytes[1],
            fanout: bytes[2],
            depth: bytes[3],
            leaf_length: word(4),
            node_offset: word(8),
            xof_length: word(12),
            node_depth: bytes[16],
            inner_length: bytes[17],
            salt: bytes[32..48].try_into().expect("sixteen bytes"),
            personal: bytes[48..64].try_into().expect("sixteen bytes"),
        })
    }
}

/// The parameter block of BLAKE2s (32 bytes), with the layout of C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct BLAKE2sParameters {
    pub digest_length: u8,
    pub key_length: u8,
    pub fanout: u8,
    pub depth: u8,
    pub leaf_length: u32,
    /// The lower 32 bits of the 48-bit node offset.
    pub node_offset: u32,
    /// The upper 16 bits of the node offset, which BLAKE2Xs uses for the output length.
    pub xof_length: u16,
    pub node_depth: u8,
    pub inner_length: u8,
    pub salt: [u8; 8],
    pub personal: [u8; 8],
}

impl BLAKE2sParameters {
    /// The sequential mode (fanout and depth 1) with `digest_length` bytes of output.
    pub const fn new(digest_length: u8) -> BLAKE2sParameters {
        BLAKE2sParameters {
            digest_length,
            key_length: 0,
            fanout: 1,
            depth: 1,
            leaf_length: 0,
            node_offset: 0,
            xof_length: 0,
            node_depth: 0,
            inner_length: 0,
            salt: [0; 8],
            personal: [0; 8],
        }
    }

    /// The block in the byte order of RFC 7693 section 2.5.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = self.digest_length;
        bytes[1] = self.key_length;
        bytes[2] = self.fanout;
        bytes[3] = self.depth;
        bytes[4..8].copy_from_slice(&self.leaf_length.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.node_offset.to_le_bytes());
        bytes[12..14].copy_from_slice(&self.xof_length.to_le_bytes());
        bytes[14] = self.node_depth;
        bytes[15] = self.inner_length;
        bytes[16..24].copy_from_slice(&self.salt);
        bytes[24..32].copy_from_slice(&self.personal);
        bytes
    }

    /// The parameters of a block, which has no reserved bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> BLAKE2sParameters {
        let word = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"));
        BLAKE2sParameters {
            digest_length: bytes[0],
            key_length: bytes[1],
            fanout: bytes[2],
            depth: bytes[3],
            leaf_length: word(4),
            node_offset: word(8),
            xof_length: u16::from_le_bytes([bytes[12], bytes[13]]),
            node_depth: bytes[14],
            inner_length: bytes[15],
            salt: bytes[16..24].try_into().expect("eight bytes"),
            personal: bytes[24..32].try_into().expect("eight bytes"),
        }
    }
}
