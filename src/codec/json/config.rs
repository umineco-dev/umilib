/// What [`JSONValue::decode`](super::JSONValue::decode) does when an object
/// has the same key twice. RFC 8259 says keys SHOULD be unique; I-JSON
/// (RFC 7493) requires it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DuplicateKeys {
    /// Fail with [`JSONError::DuplicateKey`](super::JSONError::DuplicateKey).
    Reject,
    /// Keep the first value.
    KeepFirst,
    /// Keep the last value.
    KeepLast,
    /// Keep every entry, in order.
    KeepAll,
}

/// Limits and options of parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JSONConfig {
    /// The deepest nesting of arrays and objects.
    pub maximum_depth: usize,
    /// The longest input, in bytes.
    pub maximum_length: usize,
    /// Whether a UTF-8 byte order mark before the text is skipped (RFC 8259
    /// section 8.1 allows ignoring it); otherwise it is an error.
    pub allow_byte_order_mark: bool,
    pub duplicate_keys: DuplicateKeys,
}

impl Default for JSONConfig {
    fn default() -> JSONConfig {
        JSONConfig {
            maximum_depth: 128,
            maximum_length: usize::MAX,
            allow_byte_order_mark: false,
            duplicate_keys: DuplicateKeys::Reject,
        }
    }
}
