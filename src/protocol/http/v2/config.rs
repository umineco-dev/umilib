use core::time::Duration;

use crate::codec::hpack::{HPACKDecoderConfig, HPACKEncoderConfig};
use crate::protocol::http::HTTPConfig;

/// The configuration of HTTP/2 connections: what this end advertises in
/// its SETTINGS and its limits on what the peer does; every one can be changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct H2Config {
    pub http: HTTPConfig,
    pub hpack_encoder: HPACKEncoderConfig,
    /// The decoder of field blocks: its table size is this end's
    /// SETTINGS_HEADER_TABLE_SIZE, its field list size its
    /// SETTINGS_MAX_HEADER_LIST_SIZE; its strings may be as long as a
    /// block, so that a field too large is answered with 431, not a
    /// COMPRESSION_ERROR that ends the connection.
    pub hpack_decoder: HPACKDecoderConfig,
    /// SETTINGS_MAX_CONCURRENT_STREAMS: 100 by default, the least RFC 9113 §6.5.2 recommends.
    pub max_concurrent_streams: u32,
    /// SETTINGS_INITIAL_WINDOW_SIZE, a stream's window: 1 MiB by default.
    pub initial_window_size: u32,
    /// The connection's window, raised by WINDOW_UPDATE at the start: 4 MiB by default.
    pub connection_window: u32,
    /// SETTINGS_MAX_FRAME_SIZE: 16 KiB by default, the initial value.
    pub max_frame_size: u32,
    /// A server's SETTINGS_ENABLE_CONNECT_PROTOCOL, which lets clients
    /// send extended CONNECT (RFC 8441): off by default.
    pub enable_connect_protocol: bool,
    /// How long the peer may take to acknowledge SETTINGS before
    /// SETTINGS_TIMEOUT (RFC 9113 §6.5.3): 10 s by default; `None` for ever.
    pub settings_timeout: Option<Duration>,
    /// How long a connection stays open without a stream: 60 s by default; `None` for ever.
    pub idle_timeout: Option<Duration>,
    /// The most streams the peer may reset, or make this end reset with
    /// frames that are stream errors, in `reset_window` before the
    /// connection closes with ENHANCE_YOUR_CALM, against floods of
    /// requests reset at once: 1000 by default.
    pub maximum_resets: u32,
    pub reset_window: Duration,
    /// The most acknowledgments of PING and SETTINGS owed and not yet
    /// written, against floods of them: 64 by default.
    pub maximum_pending_control: usize,
    /// The largest field block received in HEADERS and CONTINUATION frames,
    /// coded, against floods of CONTINUATION: 256 KiB by default.
    pub maximum_field_block: usize,
}

impl Default for H2Config {
    fn default() -> H2Config {
        let http = HTTPConfig::default();
        let maximum_field_block = 256 << 10;
        H2Config {
            http,
            hpack_encoder: HPACKEncoderConfig::default(),
            hpack_decoder: HPACKDecoderConfig {
                maximum_field_list_size: http.maximum_field_section_size,
                maximum_string_length: maximum_field_block,
                ..HPACKDecoderConfig::default()
            },
            max_concurrent_streams: 100,
            initial_window_size: 1 << 20,
            connection_window: 4 << 20,
            max_frame_size: 1 << 14,
            enable_connect_protocol: false,
            settings_timeout: Some(Duration::from_secs(10)),
            idle_timeout: Some(Duration::from_secs(60)),
            maximum_resets: 1000,
            reset_window: Duration::from_secs(10),
            maximum_pending_control: 64,
            maximum_field_block,
        }
    }
}
