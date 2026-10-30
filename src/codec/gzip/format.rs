/// The constants of the gzip format (RFC 1952): a file is a series of
/// members, each a header ([`GzipHeader`](super::GzipHeader)), a Deflate
/// stream, and the CRC-32 and the size modulo 2^32 of the data (4 bytes
/// each, least significant first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GzipFormat;

impl GzipFormat {
    /// ID1 and ID2.
    pub const MAGIC: [u8; 2] = [0x1F, 0x8B];
    /// CM: Deflate.
    pub const DEFLATE: u8 = 8;
    /// The flags of FLG.
    pub const TEXT: u8 = 0x01;
    pub const HEADER_CHECKSUM: u8 = 0x02;
    pub const EXTRA: u8 = 0x04;
    pub const NAME: u8 = 0x08;
    pub const COMMENT: u8 = 0x10;
    /// The reserved bits of FLG, which must be zero.
    pub const RESERVED: u8 = 0xE0;
    /// XFL for the slowest and the fastest compression.
    pub const SLOWEST: u8 = 2;
    pub const FASTEST: u8 = 4;
}
