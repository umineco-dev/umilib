/// The constants of the Zstandard format (RFC 8878).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZstandardFormat;

impl ZstandardFormat {
    /// The magic number of a frame (section 3.1.1).
    pub const MAGIC: u32 = 0xFD2F_B528;
    /// The magic numbers of skippable frames: this one to this one + 15 (section 3.1.2).
    pub const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;
    /// The magic number of a formatted dictionary (section 5).
    pub const DICTIONARY_MAGIC: u32 = 0xEC30_A437;
    /// The largest block (section 3.1.1.2.4).
    pub const MAXIMUM_BLOCK: usize = 128 << 10;
    /// The smallest window.
    pub const MINIMUM_WINDOW: u64 = 1 << 10;
    /// The block types (section 3.1.1.2.2).
    pub const RAW_BLOCK: u8 = 0;
    pub const RLE_BLOCK: u8 = 1;
    pub const COMPRESSED_BLOCK: u8 = 2;
    /// The literals block types (section 3.1.1.3.1.1).
    pub const RAW_LITERALS: u8 = 0;
    pub const RLE_LITERALS: u8 = 1;
    pub const COMPRESSED_LITERALS: u8 = 2;
    pub const TREELESS_LITERALS: u8 = 3;
    /// The compression modes of the sequence tables (section 3.1.1.3.2.1).
    pub const PREDEFINED_MODE: u8 = 0;
    pub const RLE_MODE: u8 = 1;
    pub const FSE_MODE: u8 = 2;
    pub const REPEAT_MODE: u8 = 3;
    /// The longest Huffman code of literals (section 4.2.1).
    pub const MAXIMUM_HUFFMAN_BITS: u32 = 11;
    /// The largest accuracy logs of the tables of literals lengths, match
    /// lengths, offsets and Huffman weights.
    pub const LITERALS_LENGTH_MAXIMUM_LOG: u32 = 9;
    pub const MATCH_LENGTH_MAXIMUM_LOG: u32 = 9;
    pub const OFFSET_MAXIMUM_LOG: u32 = 8;
    pub const WEIGHTS_MAXIMUM_LOG: u32 = 6;
    /// The largest offset code supported (the reference decoder's).
    pub const MAXIMUM_OFFSET_CODE: u32 = 31;
    /// The repeat offsets of the first block (section 3.1.1.5).
    pub const INITIAL_OFFSETS: [u32; 3] = [1, 4, 8];

    /// The baselines and extra bits of the literals length codes 0 to 35 (table 16).
    pub const LITERALS_LENGTH_BASELINES: [u32; 36] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512,
        1024, 2048, 4096, 8192, 16384, 32768, 65536,
    ];
    pub const LITERALS_LENGTH_BITS: [u8; 36] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16,
    ];
    /// The baselines and extra bits of the match length codes 0 to 52 (table 17).
    pub const MATCH_LENGTH_BASELINES: [u32; 53] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771,
        65539,
    ];
    pub const MATCH_LENGTH_BITS: [u8; 53] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2,
        2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ];
    /// The default distributions (section 3.1.1.3.2.2) and their accuracy logs.
    pub const LITERALS_LENGTH_DEFAULT: [i16; 36] = [
        4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1,
    ];
    pub const LITERALS_LENGTH_DEFAULT_LOG: u32 = 6;
    pub const MATCH_LENGTH_DEFAULT: [i16; 53] = [
        1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
    ];
    pub const MATCH_LENGTH_DEFAULT_LOG: u32 = 6;
    pub const OFFSET_DEFAULT: [i16; 29] =
        [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1];
    pub const OFFSET_DEFAULT_LOG: u32 = 5;

    /// The window size of a window descriptor (section 3.1.1.1.2).
    pub const fn window_size(descriptor: u8) -> u64 {
        let log = 10 + (descriptor >> 3) as u64;
        let base = 1u64 << log;
        base + (base / 8) * (descriptor & 7) as u64
    }

    /// The code of `value` in a table of `baselines` and extra `bits`: the
    /// last code whose baseline is at most `value`.
    pub fn code(value: u32, baselines: &[u32]) -> usize {
        baselines.partition_point(|baseline| *baseline <= value) - 1
    }
}
