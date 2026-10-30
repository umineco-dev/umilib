/// How an encoding treats the padding characters that complete its last group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Padding {
    /// Encoding writes padding; decoding requires it (RFC 4648 section 3.2).
    Required,
    /// Encoding writes no padding; decoding rejects it.
    Forbidden,
    /// Encoding writes no padding; decoding accepts text with or without it.
    Indifferent,
}
