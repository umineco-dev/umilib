use super::LZ4BlockSize;

/// The parameters of an [`LZ4Compressor`](super::LZ4Compressor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZ4Config {
    /// 0 to 12: the search of the encoder ([`LZ4Block::CHAIN_LIMITS`](super::LZ4Block::CHAIN_LIMITS)).
    pub level: u32,
    pub block_size: LZ4BlockSize,
    /// Whether each block stands alone (otherwise blocks refer to the 64 KiB before them).
    pub independent_blocks: bool,
    /// Whether each block is followed by its xxHash-32.
    pub block_checksum: bool,
    /// Whether the frame ends with the xxHash-32 of the data.
    pub content_checksum: bool,
    /// The size of the data, written in the header if given; finishing a
    /// stream of another size fails with `InvalidParameter`.
    pub content_size: Option<u64>,
    /// The dictionary: the history before the data (its last 64 KiB), and
    /// the identifier written in the header if given.
    pub dictionary: Option<alloc::vec::Vec<u8>>,
    pub dictionary_identifier: Option<u32>,
}

impl Default for LZ4Config {
    fn default() -> LZ4Config {
        LZ4Config {
            level: 1,
            block_size: LZ4BlockSize::Maximum64KiB,
            independent_blocks: true,
            block_checksum: false,
            content_checksum: true,
            content_size: None,
            dictionary: None,
            dictionary_identifier: None,
        }
    }
}

/// The limits of an [`LZ4Decompressor`](super::LZ4Decompressor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZ4DecompressorConfig {
    /// The largest block a frame may announce (larger ones fail with
    /// `LimitExceeded`): blocks are held whole, compressed and decoded.
    pub maximum_block_size: usize,
    /// Whether the input is a series of frames (and skippable frames), as
    /// the lz4 tool reads, which ends with the input; otherwise one frame,
    /// after which the input is not consumed.
    pub multiple_frames: bool,
    /// The dictionary given to the frames that use one, and the identifier
    /// it must match when a frame names one.
    pub dictionary: Option<alloc::vec::Vec<u8>>,
    pub dictionary_identifier: Option<u32>,
}

impl Default for LZ4DecompressorConfig {
    fn default() -> LZ4DecompressorConfig {
        LZ4DecompressorConfig {
            maximum_block_size: 4 << 20,
            multiple_frames: true,
            dictionary: None,
            dictionary_identifier: None,
        }
    }
}
