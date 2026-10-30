/// The PackBits format (Apple Technical Note TN1023; TIFF 6.0 section 9): a
/// sequence of runs, each a header byte n read as a signed byte, then
///
/// - n = 0 to 127: the n + 1 bytes that follow, copied;
/// - n = -1 to -127: the byte that follows, repeated 1 - n times (2 to 128);
/// - n = -128: nothing (a no-op the packer never writes).
///
/// The format has no end marker: a stream ends with its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackBitsFormat;

impl PackBitsFormat {
    /// The longest run of either kind.
    pub const MAXIMUM_RUN: usize = 128;
    /// The header byte that does nothing.
    pub const NO_OPERATION: u8 = 0x80;
    /// The shortest run of equal bytes the compressor writes as a repeat.
    pub const MINIMUM_REPEAT: usize = 3;
}
