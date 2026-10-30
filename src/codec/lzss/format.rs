/// The LZSS format of Haruhiko Okumura's public-domain `lzss.c` (the LZ77
/// variant of J. A. Storer and T. G. Szymanski, 1982), with its parameters
/// in an [`LZSSConfig`](super::LZSSConfig): a sequence of bits, packed most
/// significant bit of each byte first and padded with zero bits to a byte,
/// of tokens
///
/// - 1, then a byte (8 bits, most significant first): a literal;
/// - 0, then a position `i` of EI bits and a length `j` of EJ bits: the
///   `j + 2` bytes at the positions `i`, `i + 1`, ... of the ring buffer of
///   N = 2^EI bytes that holds the latest output.
///
/// The ring buffer starts with spaces at the positions 0 to N - F - 1 and
/// zeros after (F = 2^EJ + 1); the first byte goes to the position N - F.
/// The stream has no end marker: it ends with its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZSSFormat;

impl LZSSFormat {
    /// The shortest match (P + 1 of the reference, P = 1).
    pub const MINIMUM_LENGTH: usize = 2;
}
