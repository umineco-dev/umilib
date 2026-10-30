use alloc::vec::Vec;

/// The header of a gzip member (RFC 1952 section 2.3.1), without its
/// compression method (always Deflate).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GzipHeader {
    /// FTEXT: the data are probably text.
    pub text: bool,
    /// MTIME: the modification time of the original file, in seconds since
    /// 1970 (UTC); 0 if none.
    pub modification_time: u32,
    /// XFL: 2 for the slowest compression, 4 for the fastest; 0 otherwise.
    pub extra_flags: u8,
    /// OS: the file system the member was made on; 255 if unknown.
    pub operating_system: u8,
    /// FEXTRA: the extra field (subfields of an identifier and data), at most 65535 bytes.
    pub extra: Option<Vec<u8>>,
    /// FNAME: the name of the original file, in ISO 8859-1, without a zero byte.
    pub name: Option<Vec<u8>>,
    /// FCOMMENT: a comment, in ISO 8859-1 (lines ending with LF), without a zero byte.
    pub comment: Option<Vec<u8>>,
    /// FHCRC: whether the header is followed by the low 16 bits of its CRC-32.
    pub header_checksum: bool,
}

impl GzipHeader {
    /// The operating system "unknown".
    pub const UNKNOWN_OPERATING_SYSTEM: u8 = 255;

    /// The header of a member of the operating system "unknown", with no other field.
    pub fn new() -> GzipHeader {
        GzipHeader { operating_system: GzipHeader::UNKNOWN_OPERATING_SYSTEM, ..GzipHeader::default() }
    }
}
