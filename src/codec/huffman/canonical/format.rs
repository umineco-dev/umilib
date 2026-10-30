/// The constants of the stream format of [`CanonicalHuffmanCompressor`](super::CanonicalHuffmanCompressor)
/// and [`CanonicalHuffmanDecompressor`](super::CanonicalHuffmanDecompressor),
/// a format of this library (no standard defines one): a sequence of blocks,
/// each
///
/// 1. 1 bit, 1 for the last block of the stream;
/// 2. the code lengths of the [`SYMBOLS`](CanonicalHuffmanFormat::SYMBOLS)
///    symbols (the bytes 0 to 255, then [`END`](CanonicalHuffmanFormat::END)),
///    [`LENGTH_BITS`](CanonicalHuffmanFormat::LENGTH_BITS) bits each, which
///    define a canonical code ([`HuffmanCode`](super::HuffmanCode)) that is
///    complete or has a single code of 1 bit, `END` among its symbols;
/// 3. the codes of the bytes of the block, then the code of `END`;
/// 4. zero bits up to the next byte boundary.
///
/// Bits are packed least significant first and codes start with their
/// first bit, as in Deflate (RFC 1951 section 3.1.1); every block ends at a
/// byte boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalHuffmanFormat;

impl CanonicalHuffmanFormat {
    /// The symbol that ends a block.
    pub const END: u16 = 256;
    /// The number of symbols: the 256 bytes and `END`.
    pub const SYMBOLS: usize = 257;
    /// The bits of a code length.
    pub const LENGTH_BITS: u32 = 4;
    /// The longest code.
    pub const MAXIMUM_LENGTH: u32 = 15;
}
