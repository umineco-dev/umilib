/// The constants of the stream format of [`LZ77Compressor`](super::LZ77Compressor)
/// and [`LZ77Decompressor`](super::LZ77Decompressor), the triples of the
/// LZ77 algorithm (J. Ziv and A. Lempel, "A Universal Algorithm for
/// Sequential Data Compression", IEEE Trans. IT-23(3), 1977) in a format of
/// this library (no standard defines one): a sequence of tokens, each
///
/// - 2 bytes, most significant first, of a 12-bit field `D` and a 4-bit
///   length `L` (`D << 4 | L`); then
/// - if `L` is 1 to 15, a match: the `L` bytes `D + 1` bytes back (1 to
///   4096, overlapping the bytes it produces when shorter than `L`), then
///   1 byte that follows them;
/// - if `L` is 0 and `D` is 0, 1 byte;
/// - if `L` is 0 and `D` is [`END`](LZ77Format::END), nothing: the stream
///   ends. Other tokens of length 0 are invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZ77Format;

impl LZ77Format {
    /// The farthest distance of a match.
    pub const WINDOW: usize = 1 << 12;
    /// The longest match.
    pub const MAXIMUM_LENGTH: usize = 15;
    /// The field `D` of the token that ends the stream.
    pub const END: u16 = 0xFFF;
}
