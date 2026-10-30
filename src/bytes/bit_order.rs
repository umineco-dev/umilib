/// The order in which a stream of bits fills the bits of each byte, and in
/// which a value read from it holds the bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitOrder {
    /// The first bit of a byte is its least significant (Deflate, Brotli,
    /// Zstandard's forward streams); a value of several bits holds its
    /// first bit as its least significant.
    LeastSignificantFirst,
    /// The first bit of a byte is its most significant; a value of several
    /// bits holds its first bit as its most significant (Zstandard's
    /// backward streams, LZSS).
    MostSignificantFirst,
}
