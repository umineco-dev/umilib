/// The constants of the Deflate format (RFC 1951): the window, the
/// alphabets and their extra bits (section 3.2.5), the order of the code
/// length code (section 3.2.7) and the fixed codes (section 3.2.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeflateFormat;

impl DeflateFormat {
    /// The farthest distance of a match.
    pub const WINDOW: usize = 32768;
    /// The symbol that ends a block.
    pub const END_OF_BLOCK: u16 = 256;
    /// The symbols of the literal/length alphabet; 286 and 287 do not occur in data.
    pub const LITERAL_LENGTH_SYMBOLS: usize = 288;
    /// The symbols of the distance alphabet; 30 and 31 do not occur in data.
    pub const DISTANCE_SYMBOLS: usize = 32;
    /// The most literal/length codes a dynamic block declares (HLIT + 257).
    pub const MAXIMUM_LITERAL_LENGTH_CODES: usize = 286;
    /// The most distance codes a dynamic block declares (HDIST + 1) that data can use.
    pub const MAXIMUM_DISTANCE_CODES: usize = 30;
    /// The shortest and the longest match.
    pub const MINIMUM_MATCH: usize = 3;
    pub const MAXIMUM_MATCH: usize = 258;
    /// The most bytes of a stored block.
    pub const MAXIMUM_STORED: usize = 65535;
    /// The longest code of the literal/length and distance codes, and of the code length code.
    pub const MAXIMUM_CODE_LENGTH: u32 = 15;
    pub const MAXIMUM_CODE_LENGTH_CODE_LENGTH: u32 = 7;
    /// The order of the code lengths of the code length code.
    pub const CODE_LENGTH_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
    /// The base lengths of the length symbols 257 to 285.
    pub const LENGTH_BASES: [u16; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227,
        258,
    ];
    /// The extra bits of the length symbols 257 to 285.
    pub const LENGTH_EXTRA_BITS: [u8; 29] =
        [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
    /// The base distances of the distance symbols 0 to 29.
    pub const DISTANCE_BASES: [u16; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
        6145, 8193, 12289, 16385, 24577,
    ];
    /// The extra bits of the distance symbols 0 to 29.
    pub const DISTANCE_EXTRA_BITS: [u8; 30] =
        [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
    /// The length symbol (less 257) of each length less 3.
    pub const LENGTH_INDICES: [u8; 256] = DeflateFormat::length_indices();

    /// The fixed literal/length code lengths: 8 for 0 to 143, 9 for 144 to
    /// 255, 7 for 256 to 279 and 8 for 280 to 287.
    pub const fn fixed_literal_length_lengths() -> [u8; 288] {
        let mut lengths = [8u8; 288];
        let mut symbol = 144;
        while symbol < 256 {
            lengths[symbol] = 9;
            symbol += 1;
        }
        while symbol < 280 {
            lengths[symbol] = 7;
            symbol += 1;
        }
        lengths
    }

    /// The fixed distance code lengths: 5 for the 32 symbols.
    pub const fn fixed_distance_lengths() -> [u8; 32] {
        [5; 32]
    }

    pub const fn length_indices() -> [u8; 256] {
        let mut indices = [0u8; 256];
        let mut index = 0;
        while index < 29 {
            let mut length = DeflateFormat::LENGTH_BASES[index] as usize;
            let end = if index == 28 { 259 } else { DeflateFormat::LENGTH_BASES[index + 1] as usize };
            while length < end {
                indices[length - 3] = index as u8;
                length += 1;
            }
            index += 1;
        }
        // 258 has its own symbol (285), not 284 with 31 extra.
        indices[255] = 28;
        indices
    }

    /// The length symbol (less 257) of a match of `length` (3 to 258) bytes.
    pub const fn length_index(length: usize) -> usize {
        DeflateFormat::LENGTH_INDICES[length - 3] as usize
    }

    /// The distance symbol of a distance of 1 to 32768.
    pub const fn distance_symbol(distance: usize) -> usize {
        if distance <= 4 {
            return distance - 1;
        }
        // Each pair of symbols doubles the distance; the second of a pair holds its upper half.
        let value = distance - 1;
        let bits = usize::BITS - 1 - value.leading_zeros();
        (2 * bits as usize) + ((value >> (bits - 1)) & 1)
    }
}
