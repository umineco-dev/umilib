//! The Ascon permutation and the hash functions of NIST SP 800-232:
//! Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128. The authenticated
//! encryption Ascon-AEAD128 is `crypto::ascon`.

mod hash256;
mod permutation;
mod sponge;
mod xof;

pub use hash256::AsconHash256;
pub use permutation::AsconPermutation;
pub use sponge::{AsconReader, AsconSponge};
pub use xof::{AsconCXOF128, AsconXOF128};
