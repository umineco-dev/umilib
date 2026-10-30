/// The constants of the stream format of [`LZ78Compressor`](super::LZ78Compressor)
/// and [`LZ78Decompressor`](super::LZ78Decompressor), the pairs of the
/// LZ78 algorithm (J. Ziv and A. Lempel, "Compression of Individual
/// Sequences via Variable-Rate Coding", IEEE Trans. IT-24(5), 1978) in a
/// format of this library (no standard defines one):
///
/// 1. 1 byte B (1 to [`MAXIMUM_BITS`](LZ78Format::MAXIMUM_BITS)): the
///    dictionary holds at most 2^B phrases;
/// 2. bits packed least significant first, of tokens whose fields are
///    w bits wide, w being the bits of n + 1 for the n phrases of the
///    dictionary (phrase 0 is the empty phrase and is not counted):
///    - a phrase `i` (0 to n), then a byte `c` (8 bits): writes phrase `i`
///      then `c`, and adds the phrase `i` + `c` as phrase n + 1; when the
///      dictionary then holds 2^B phrases, it is emptied;
///    - n + 1, then a phrase `i` (0 to n), then 1 bit: writes phrase `i`;
///      then, if the bit is 1, the stream ends; either way zero bits pad
///      to the next byte boundary (a bit of 0 marks a sync flush).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZ78Format;

impl LZ78Format {
    /// The largest B.
    pub const MAXIMUM_BITS: u32 = 24;

    /// The width of the fields of a token with `phrases` phrases in the dictionary.
    pub const fn width(phrases: u32) -> u32 {
        32 - (phrases + 1).leading_zeros()
    }
}
