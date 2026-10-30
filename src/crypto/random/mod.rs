//! Random bit generation: the [`Random`] interface and the deterministic
//! random bit generators of NIST SP 800-90A Revision 1, which expand the
//! entropy supplied by their user (from the operating system through
//! `platform`, or from a hardware source).

mod ctr_drbg;
mod drbg;
mod error;
mod hash_drbg;
mod hmac_drbg;
mod source;

pub use ctr_drbg::CTRDRBG;
pub use drbg::{DRBG, DRBGConfig};
pub use error::RandomError;
pub use hash_drbg::HashDRBG;
pub use hmac_drbg::HMACDRBG;
pub use source::Random;
