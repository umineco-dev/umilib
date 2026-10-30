/// The configuration of WebSocket connections; every limit can be changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct WebSocketConfig {
    /// The largest message taken, decompressed: 16 MiB by default; a larger
    /// one closes with 1009 (RFC 6455 §7.4.1).
    pub maximum_message_size: usize,
    /// The largest payload of the frames this end sends: messages are
    /// fragmented into frames of it (RFC 6455 §5.4): 64 KiB by default.
    pub maximum_frame_size: usize,
    /// The level of permessage-deflate's compressor, 0 to 9: 6 by default.
    pub deflate_level: u32,
    /// The most events queued for the application: 4096 by default.
    pub maximum_events: usize,
}

impl Default for WebSocketConfig {
    fn default() -> WebSocketConfig {
        WebSocketConfig {
            maximum_message_size: 16 << 20,
            maximum_frame_size: 64 << 10,
            deflate_level: 6,
            maximum_events: 4096,
        }
    }
}
