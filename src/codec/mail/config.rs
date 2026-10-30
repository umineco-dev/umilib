/// The limits of reading messages: what RFC 5322 and MIME leave unbounded,
/// bounded so that a message cannot take memory or time without end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct MailConfig {
    /// The longest message read, in bytes.
    pub maximum_length: usize,
    /// The longest field, its folded lines together, in bytes.
    pub maximum_field_length: usize,
    /// The most fields of a header section.
    pub maximum_fields: usize,
    /// The most entities of a message, every part and nested message counted.
    pub maximum_parts: usize,
    /// The deepest nesting of multiparts and messages (RFC 2046 §5.1.1).
    pub maximum_depth: usize,
    /// Whether UTF-8 is taken in header fields (RFC 6532 §3); without it,
    /// only US-ASCII is (RFC 5322 §2.2).
    pub utf8: bool,
}

impl Default for MailConfig {
    fn default() -> MailConfig {
        MailConfig {
            maximum_length: 64 * 1024 * 1024,
            maximum_field_length: 64 * 1024,
            maximum_fields: 4096,
            maximum_parts: 4096,
            maximum_depth: 32,
            utf8: true,
        }
    }
}
