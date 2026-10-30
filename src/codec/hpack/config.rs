/// The configuration of an [`HPACKEncoder`](super::HPACKEncoder).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct HPACKEncoderConfig {
    /// The largest dynamic table the encoder uses, within the decoder's
    /// limit: 4096 bytes by default, the initial limit of HTTP/2 (RFC 9113 §6.5.2).
    pub maximum_table_size: usize,
    /// Whether strings are Huffman-coded when that makes them shorter: on by default.
    pub huffman: bool,
    /// The largest field (RFC 7541 §4.1 size) added to the dynamic table,
    /// so that one large value does not evict the rest: 1024 by default;
    /// larger ones go as literals without indexing.
    pub maximum_indexed_size: usize,
}

impl Default for HPACKEncoderConfig {
    fn default() -> HPACKEncoderConfig {
        HPACKEncoderConfig { maximum_table_size: 4096, huffman: true, maximum_indexed_size: 1024 }
    }
}

/// The configuration of an [`HPACKDecoder`](super::HPACKDecoder).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct HPACKDecoderConfig {
    /// The limit of the dynamic table at the start: 4096 bytes by default,
    /// HTTP/2's initial SETTINGS_HEADER_TABLE_SIZE (RFC 9113 §6.5.2).
    pub maximum_table_size: usize,
    /// The longest string, coded or decoded: 64 KiB by default.
    pub maximum_string_length: usize,
    /// The largest field list (the sum of RFC 7541 §4.1 sizes, as
    /// SETTINGS_MAX_HEADER_LIST_SIZE counts it): 64 KiB by default.
    pub maximum_field_list_size: usize,
}

impl Default for HPACKDecoderConfig {
    fn default() -> HPACKDecoderConfig {
        HPACKDecoderConfig {
            maximum_table_size: 4096,
            maximum_string_length: 1 << 16,
            maximum_field_list_size: 1 << 16,
        }
    }
}
