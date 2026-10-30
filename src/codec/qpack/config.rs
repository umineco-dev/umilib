/// The configuration of a [`QPACKDecoder`](super::QPACKDecoder): what it
/// advertises in SETTINGS and the limits of what it decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct QPACKDecoderConfig {
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY: 4096 bytes by default (0 turns the dynamic table off).
    pub maximum_table_capacity: usize,
    /// SETTINGS_QPACK_BLOCKED_STREAMS: 16 by default.
    pub blocked_streams: usize,
    /// The longest string, coded or decoded: 64 KiB by default.
    pub maximum_string_length: usize,
    /// The largest field section (the sum of name, value and 32 bytes per
    /// line, SETTINGS_MAX_FIELD_SECTION_SIZE): 64 KiB by default.
    pub maximum_field_list_size: usize,
}

impl Default for QPACKDecoderConfig {
    fn default() -> QPACKDecoderConfig {
        QPACKDecoderConfig {
            maximum_table_capacity: 4096,
            blocked_streams: 16,
            maximum_string_length: 1 << 16,
            maximum_field_list_size: 1 << 16,
        }
    }
}

/// The configuration of a [`QPACKEncoder`](super::QPACKEncoder).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct QPACKEncoderConfig {
    /// The largest dynamic table the encoder uses, within the decoder's
    /// maximum: 4096 bytes by default.
    pub maximum_table_capacity: usize,
    /// Whether strings are Huffman-coded when that makes them shorter: on by default.
    pub huffman: bool,
    /// The largest field (name, value and 32 bytes) inserted: 1024 by default.
    pub maximum_indexed_size: usize,
    /// Whether sections may refer to entries the decoder has not
    /// acknowledged, which can block their streams (RFC 9204 §2.1.2),
    /// within the decoder's SETTINGS_QPACK_BLOCKED_STREAMS: on by default.
    pub blocking: bool,
}

impl Default for QPACKEncoderConfig {
    fn default() -> QPACKEncoderConfig {
        QPACKEncoderConfig { maximum_table_capacity: 4096, huffman: true, maximum_indexed_size: 1024, blocking: true }
    }
}
