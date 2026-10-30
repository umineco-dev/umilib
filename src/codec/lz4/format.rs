/// The constants of the LZ4 frame format (lz4_Frame_format.md, version
/// 1.6): a magic number, a frame descriptor (FLG, BD, the optional content
/// size and dictionary identifier, and a header checksum), data blocks
/// (a little-endian size whose highest bit marks an uncompressed block,
/// the data and an optional block checksum), an end mark of 4 zero bytes and
/// an optional content checksum (xxHash-32 with the seed 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZ4FrameFormat;

impl LZ4FrameFormat {
    /// The magic number of a frame.
    pub const MAGIC: u32 = 0x184D_2204;
    /// The magic numbers of skippable frames: this one to this one + 15.
    pub const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;
    /// The magic number of a legacy frame (blocks of at most 8 MiB, no end mark).
    pub const LEGACY_MAGIC: u32 = 0x184C_2102;
    /// The data of a block of a legacy frame.
    pub const LEGACY_BLOCK_SIZE: usize = 8 << 20;
    /// The version bits of FLG: 01.
    pub const VERSION: u8 = 0x40;
    /// The flags of FLG.
    pub const BLOCK_INDEPENDENCE: u8 = 0x20;
    pub const BLOCK_CHECKSUM: u8 = 0x10;
    pub const CONTENT_SIZE: u8 = 0x08;
    pub const CONTENT_CHECKSUM: u8 = 0x04;
    pub const DICTIONARY_IDENTIFIER: u8 = 0x01;
    /// The reserved bits of FLG and BD.
    pub const RESERVED_FLAGS: u8 = 0x02;
    pub const RESERVED_BLOCK_DESCRIPTOR: u8 = 0x8F;
    /// The bit of a block size that marks an uncompressed block.
    pub const UNCOMPRESSED: u32 = 0x8000_0000;

    /// The block maximum size of the code 4 to 7 of BD (64 KiB to 4 MiB).
    pub const fn block_size(code: u8) -> Option<usize> {
        match code {
            4..=7 => Some(1 << (8 + 2 * code as usize)),
            _ => None,
        }
    }
}

/// The block maximum sizes of a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LZ4BlockSize {
    Maximum64KiB,
    Maximum256KiB,
    Maximum1MiB,
    Maximum4MiB,
}

impl LZ4BlockSize {
    /// The code of BD (4 to 7).
    pub const fn code(&self) -> u8 {
        match self {
            LZ4BlockSize::Maximum64KiB => 4,
            LZ4BlockSize::Maximum256KiB => 5,
            LZ4BlockSize::Maximum1MiB => 6,
            LZ4BlockSize::Maximum4MiB => 7,
        }
    }

    /// The size in bytes.
    pub const fn bytes(&self) -> usize {
        1 << (8 + 2 * self.code() as usize)
    }
}
