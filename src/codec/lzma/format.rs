/// The constants of the .lzma file format (lzma-specification, "lzma file
/// format": the properties byte, the dictionary size and the uncompressed
/// size, then the LZMA stream) and of LZMA2 streams (chunks of at most 2 MiB
/// of data and 64 KiB compressed, ended by 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZMAFormat;

impl LZMAFormat {
    /// The size of the header of a .lzma file.
    pub const HEADER_SIZE: usize = 13;
    /// The uncompressed size of a stream ended by its end marker.
    pub const UNKNOWN_SIZE: u64 = u64::MAX;
    /// The smallest dictionary; smaller declared sizes mean it.
    pub const MINIMUM_DICTIONARY: usize = 1 << 12;
    /// The most data and compressed bytes of an LZMA2 chunk.
    pub const CHUNK_DATA: usize = 1 << 21;
    pub const CHUNK_COMPRESSED: usize = 1 << 16;
    /// The control bytes of LZMA2 chunks: the end, uncompressed chunks with
    /// and without a dictionary reset, and LZMA chunks (with the reset in bits 5 and 6).
    pub const END: u8 = 0x00;
    pub const UNCOMPRESSED_RESET: u8 = 0x01;
    pub const UNCOMPRESSED: u8 = 0x02;
    pub const LZMA: u8 = 0x80;
    pub const LZMA_STATE_RESET: u8 = 0xA0;
    pub const LZMA_PROPERTIES: u8 = 0xC0;
    pub const LZMA_DICTIONARY_RESET: u8 = 0xE0;

    /// The dictionary size of the LZMA2 properties byte `byte` (0 to 40;
    /// 40 is 4 GiB - 1), as the xz format encodes it; `None` beyond 40.
    pub const fn lzma2_dictionary_size(byte: u8) -> Option<u64> {
        match byte {
            0..=39 => Some((2 | (byte as u64 & 1)) << (byte / 2 + 11)),
            40 => Some(u32::MAX as u64),
            _ => None,
        }
    }

    /// The smallest LZMA2 properties byte whose dictionary holds `size` bytes.
    pub fn lzma2_dictionary_byte(size: u64) -> u8 {
        (0..=40).find(|byte| LZMAFormat::lzma2_dictionary_size(*byte).is_some_and(|value| value >= size)).unwrap_or(40)
    }
}
