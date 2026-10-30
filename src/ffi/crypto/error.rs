use crate::crypto::CryptoError;
use crate::ffi::{Status, ToStatus};

/// The statuses of [`CryptoError`], one per variant.
pub struct CryptoStatus;

impl CryptoStatus {
    pub const KEY_LENGTH: Status = Status::new(c"crypto", c"KeyLength", c"the key length is not accepted");
    pub const NONCE_LENGTH: Status = Status::new(c"crypto", c"NonceLength", c"the nonce length is not accepted");
    pub const TAG_LENGTH: Status = Status::new(c"crypto", c"TagLength", c"the tag length is not accepted");
    pub const INPUT_LENGTH: Status = Status::new(c"crypto", c"InputLength", c"the input length is not accepted");
    pub const INVALID_PARAMETER: Status =
        Status::new(c"crypto", c"InvalidParameter", c"a parameter is outside the range the algorithm allows");
    pub const AUTHENTICATION_FAILED: Status =
        Status::new(c"crypto", c"AuthenticationFailed", c"the tag does not authenticate the data");
    pub const LIMIT_EXCEEDED: Status = Status::new(c"crypto", c"LimitExceeded", c"the limit of the key is exceeded");
    pub const ALLOCATION: Status =
        Status::new(c"crypto", c"Allocation", c"the memory of the operation could not be allocated");
    pub const INVALID_KEY: Status = Status::new(c"crypto", c"InvalidKey", c"the key is not accepted");
    pub const INVALID_SIGNATURE: Status = Status::new(c"crypto", c"InvalidSignature", c"the signature is not valid");
    pub const RANDOM_FAILED: Status = Status::new(c"crypto", c"RandomFailed", c"the source of random bytes failed");
    pub const DECRYPTION_FAILED: Status = Status::new(c"crypto", c"DecryptionFailed", c"decryption failed");
}

impl ToStatus for CryptoError {
    fn to_status(&self) -> &'static Status {
        match self {
            CryptoError::KeyLength { .. } => &CryptoStatus::KEY_LENGTH,
            CryptoError::NonceLength { .. } => &CryptoStatus::NONCE_LENGTH,
            CryptoError::TagLength { .. } => &CryptoStatus::TAG_LENGTH,
            CryptoError::InputLength { .. } => &CryptoStatus::INPUT_LENGTH,
            CryptoError::InvalidParameter => &CryptoStatus::INVALID_PARAMETER,
            CryptoError::AuthenticationFailed => &CryptoStatus::AUTHENTICATION_FAILED,
            CryptoError::LimitExceeded => &CryptoStatus::LIMIT_EXCEEDED,
            CryptoError::Allocation => &CryptoStatus::ALLOCATION,
            CryptoError::InvalidKey => &CryptoStatus::INVALID_KEY,
            CryptoError::InvalidSignature => &CryptoStatus::INVALID_SIGNATURE,
            CryptoError::RandomFailed => &CryptoStatus::RANDOM_FAILED,
            CryptoError::DecryptionFailed => &CryptoStatus::DECRYPTION_FAILED,
        }
    }
}
