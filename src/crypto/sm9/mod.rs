//! SM9, the identity-based cryptographic algorithms of GM/T 0044-2016 on a
//! pairing-friendly curve: key exchange (part 3, [`SM9KEP`]), key
//! encapsulation (part 4, [`SM9KEM`]) and public key encryption (part 4,
//! [`SM9PKE`]), with the functions every part shares (H1 and H2,
//! [`SM9Hash`]; the KDF, [`SM9KDF`]; the conversions of part 1 clause 7,
//! [`SM9Encoding`]). The digital signature algorithm (part 2) is
//! [`crypto::ibs::sm9`](crate::crypto::ibs) with the identity-based
//! signatures.
//!
//! Every scheme is generic over a pairing-friendly curve `C` and a hash
//! function `H`; GM/T 0044.5 specifies
//! [`SM9BN256`](crate::math::pairing::SM9BN256) with SM3. The KGC's
//! encryption master key is ke with Ppub-e = \[ke\]P1 in G_1
//! ([`SM9EncryptMasterKey`]); the encryption key of an identity is de =
//! \[ke / (H1(ID || hid, N) + ke)\]P2 in G_2 ([`SM9EncryptUserKey`]), with
//! the identifier hid of the key generating function, which the parties
//! of an exchange and the sender of a message must use as well.

mod encoding;
mod hash;
mod kdf;
mod kem;
mod kep;
mod keys;
mod pke;

pub use encoding::SM9Encoding;
pub use hash::SM9Hash;
pub use kdf::SM9KDF;
pub use kem::SM9KEM;
pub use kep::{SM9KEP, SM9KeyConfirmation, SM9Role};
pub use keys::{SM9EncryptMasterKey, SM9EncryptUserKey};
#[cfg(umilib_feature = "crypto-mode-cbc")]
pub use pke::SM9BlockCipher;
pub use pke::{SM9Cipher, SM9PKE, SM9StreamCipher};
