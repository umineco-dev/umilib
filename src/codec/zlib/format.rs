/// The constants of the zlib format (RFC 1950): a header of 2 bytes (CMF,
/// FLG) and, if FLG.FDICT is set, the Adler-32 of the preset dictionary (4
/// bytes, most significant first); a Deflate stream; the Adler-32 of the
/// data (4 bytes, most significant first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZlibFormat;

impl ZlibFormat {
    /// The compression method of CMF: Deflate.
    pub const DEFLATE: u8 = 8;
    /// The flag of FLG that announces a preset dictionary.
    pub const PRESET_DICTIONARY: u8 = 0x20;
    /// The largest CINFO: a window of 2^(CINFO + 8) bytes, at most 32 KiB.
    pub const MAXIMUM_WINDOW_INFORMATION: u8 = 7;

    /// The 2 bytes of the header of a stream with a window of 2^`window_bits`
    /// bytes, compressed at `level` (FLEVEL as zlib sets it), with a
    /// dictionary if `dictionary`; FCHECK makes CMF × 256 + FLG a multiple of 31.
    pub fn header(window_bits: u32, level: u32, dictionary: bool) -> [u8; 2] {
        let method = ZlibFormat::DEFLATE | ((window_bits - 8) as u8) << 4;
        let level_flags: u8 = match level {
            0..=1 => 0,
            2..=5 => 1,
            6 => 2,
            _ => 3,
        };
        let mut flags = level_flags << 6 | if dictionary { ZlibFormat::PRESET_DICTIONARY } else { 0 };
        flags |= (31 - ((method as u16 * 256 + flags as u16) % 31) as u8) % 31;
        [method, flags]
    }
}
