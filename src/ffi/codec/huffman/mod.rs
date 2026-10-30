//! The C ABI of [`crate::codec::huffman`].

#[cfg(umilib_feature = "codec-huffman-adaptive")]
pub mod adaptive;
#[cfg(umilib_feature = "codec-huffman-canonical")]
pub mod canonical;

use crate::codec::huffman::HuffmanError;
use crate::ffi::{Module, Status, ToStatus};

/// The statuses of [`HuffmanError`], one per variant.
pub struct HuffmanStatus;

impl HuffmanStatus {
    pub const INVALID_LENGTHS: Status =
        Status::new(c"codec.huffman", c"InvalidLengths", c"the code lengths are over-subscribed or too long");
    pub const INVALID_ALPHABET: Status =
        Status::new(c"codec.huffman", c"InvalidAlphabet", c"the alphabet has no symbol or too many");
    pub const INVALID_CODE: Status = Status::new(c"codec.huffman", c"InvalidCode", c"the bits are not a code");
}

impl ToStatus for HuffmanError {
    fn to_status(&self) -> &'static Status {
        match self {
            HuffmanError::InvalidLengths { .. } => &HuffmanStatus::INVALID_LENGTHS,
            HuffmanError::InvalidAlphabet { .. } => &HuffmanStatus::INVALID_ALPHABET,
            HuffmanError::InvalidCode => &HuffmanStatus::INVALID_CODE,
        }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "huffman",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "codec-huffman-adaptive")]
        adaptive::MODULE,
        #[cfg(umilib_feature = "codec-huffman-canonical")]
        canonical::MODULE,
    ],
};
