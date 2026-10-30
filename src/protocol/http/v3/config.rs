use crate::codec::qpack::{QPACKDecoderConfig, QPACKEncoderConfig};
use crate::protocol::http::HTTPConfig;

/// The configuration of HTTP/3 connections; every limit can be changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct H3Config {
    pub http: HTTPConfig,
    pub qpack_encoder: QPACKEncoderConfig,
    /// The decoder of field sections, whose limits are this end's
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY, SETTINGS_QPACK_BLOCKED_STREAMS and
    /// SETTINGS_MAX_FIELD_SECTION_SIZE; its strings may be as long as a
    /// HEADERS frame, so that a field too large is answered with 431, not a
    /// QPACK error that ends the connection.
    pub qpack_decoder: QPACKDecoderConfig,
    /// A server's SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220): off by default.
    pub enable_connect_protocol: bool,
    /// Whether SETTINGS carries a reserved setting, and frames of reserved
    /// types go on the control stream, as RFC 9114 §7.2.4.1 and §7.2.8 ask: on by default.
    pub grease: bool,
}

impl Default for H3Config {
    fn default() -> H3Config {
        let http = HTTPConfig::default();
        H3Config {
            http,
            qpack_encoder: QPACKEncoderConfig::default(),
            qpack_decoder: QPACKDecoderConfig {
                maximum_field_list_size: http.maximum_field_section_size,
                maximum_string_length: H3Config::maximum_frame(http.maximum_field_section_size),
                ..QPACKDecoderConfig::default()
            },
            enable_connect_protocol: false,
            grease: true,
        }
    }
}

impl H3Config {
    /// The largest HEADERS frame taken for a field section of `size`: twice
    /// it and a little, as a section's coding may be larger than its fields.
    pub const fn maximum_frame(size: usize) -> usize {
        size.saturating_mul(2).saturating_add(64)
    }
}
