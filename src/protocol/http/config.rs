/// The limits every version of HTTP keeps on what a peer sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct HTTPConfig {
    /// The largest header or trailer section taken, counted as RFC 9113
    /// §6.5.2 counts (each line's name, value and 32 bytes): 64 KiB by default.
    pub maximum_field_section_size: usize,
    /// The longest request target: 8 KiB by default, at least the 8000
    /// bytes RFC 9112 §3 asks recipients to support.
    pub maximum_target_length: usize,
    /// The content of a stream held for the application before it reads:
    /// 1 MiB by default; flow control (HTTP/2, HTTP/3) or reading (HTTP/1.1)
    /// waits for the application beyond it.
    pub maximum_buffered_content: usize,
    /// The most events queued for the application: 4096 by default.
    pub maximum_events: usize,
}

impl Default for HTTPConfig {
    fn default() -> HTTPConfig {
        HTTPConfig {
            maximum_field_section_size: 1 << 16,
            maximum_target_length: 8 << 10,
            maximum_buffered_content: 1 << 20,
            maximum_events: 4096,
        }
    }
}
