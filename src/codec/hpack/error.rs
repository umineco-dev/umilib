use core::fmt;

/// Why a field block cannot be decoded (RFC 7541 §3, §5, §6). HTTP/2
/// answers every one with COMPRESSION_ERROR, but for
/// [`HPACKError::FieldListTooLarge`], after which the decoder is still in
/// step with its encoder (RFC 9113 §6.5.2, §8.2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HPACKError {
    /// The block ends inside a representation.
    Truncated,
    /// An integer above [`HPACKInteger::MAXIMUM`](super::HPACKInteger::MAXIMUM) (RFC 7541 §5.1).
    IntegerOverflow,
    /// The index 0, or one of no entry (RFC 7541 §2.3.3, §6.1).
    InvalidIndex,
    /// A Huffman-coded string with the EOS symbol, more than 7 bits of
    /// padding, or padding other than the start of EOS (RFC 7541 §5.2).
    InvalidHuffman,
    /// A dynamic table size update above the limit, after a field line, or
    /// missing at the start of the first block after the limit fell (RFC 7541 §4.2, §6.3).
    InvalidTableSizeUpdate,
    /// A string longer than the decoder's limit.
    StringTooLong,
    /// The fields are larger than the decoder's limit of a field list; the
    /// block was decoded all the same, so the table is in step.
    FieldListTooLarge,
}

impl fmt::Display for HPACKError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            HPACKError::Truncated => "the field block ends inside a representation",
            HPACKError::IntegerOverflow => "an integer too large",
            HPACKError::InvalidIndex => "an index of no table entry",
            HPACKError::InvalidHuffman => "an invalid Huffman-coded string",
            HPACKError::InvalidTableSizeUpdate => "an invalid dynamic table size update",
            HPACKError::StringTooLong => "a string longer than the limit",
            HPACKError::FieldListTooLarge => "a field list larger than the limit",
        })
    }
}

impl core::error::Error for HPACKError {}
