use crate::crypto::CryptoError;
use crate::ffi::{Status, ToStatus};

/// The checks of the fixed-length arguments of the exported functions: each
/// borrows a slice as an array of `N` bytes or fails with the status of the
/// [`CryptoError`] of that kind of argument.
pub struct CryptoInput;

impl CryptoInput {
    /// A key of `N` bytes; fails with KeyLength otherwise.
    pub fn key<const N: usize>(key: &[u8]) -> Result<&[u8; N], &'static Status> {
        key.try_into().map_err(|_| CryptoError::KeyLength { length: key.len(), minimum: N, maximum: N }.to_status())
    }

    /// A nonce, an initialization vector or a tweak of `N` bytes; fails with NonceLength otherwise.
    pub fn nonce<const N: usize>(nonce: &[u8]) -> Result<&[u8; N], &'static Status> {
        nonce
            .try_into()
            .map_err(|_| CryptoError::NonceLength { length: nonce.len(), minimum: N, maximum: N }.to_status())
    }

    /// A place for a tag of `N` bytes; fails with TagLength otherwise.
    pub fn tag_mut<const N: usize>(tag: &mut [u8]) -> Result<&mut [u8; N], &'static Status> {
        let length = tag.len();
        tag.try_into().map_err(|_| CryptoError::TagLength { length, minimum: N, maximum: N }.to_status())
    }

    /// A place for an output of `N` bytes; fails with InvalidArgument otherwise.
    pub fn output_mut<const N: usize>(out: &mut [u8]) -> Result<&mut [u8; N], &'static Status> {
        out.try_into().map_err(|_| &Status::INVALID_ARGUMENT)
    }
}
