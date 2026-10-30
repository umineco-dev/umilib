/// The constants of the stream format of [`AdaptiveHuffmanCompressor`](super::AdaptiveHuffmanCompressor)
/// and [`AdaptiveHuffmanDecompressor`](super::AdaptiveHuffmanDecompressor),
/// a format of this library (no standard defines one): the codes of the
/// symbols of an [`AdaptiveHuffmanTree`](super::AdaptiveHuffmanTree) of
/// [`SYMBOLS`](AdaptiveHuffmanFormat::SYMBOLS) symbols (the bytes 0 to 255,
/// [`END`](AdaptiveHuffmanFormat::END) and [`FLUSH`](AdaptiveHuffmanFormat::FLUSH)),
/// the tree updated after each. After `FLUSH` and after `END`, which ends
/// the stream, zero bits pad to the next byte boundary.
///
/// Bits are packed least significant first, as in Deflate (RFC 1951
/// section 3.1.1); a code starts with the bit of the root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdaptiveHuffmanFormat;

impl AdaptiveHuffmanFormat {
    /// The symbol that ends the stream.
    pub const END: u16 = 256;
    /// The symbol after which the stream continues at a byte boundary (a sync flush).
    pub const FLUSH: u16 = 257;
    /// The number of symbols: the 256 bytes, `END` and `FLUSH`.
    pub const SYMBOLS: usize = 258;
}
