//! The modes of operation of block ciphers (SP 800-38A to 38G, RFC 3394,
//! RFC 5297, RFC 5649, RFC 8452), generic over [`BlockCipher`](crate::crypto::BlockCipher), and
//! the padding of the modes that need whole blocks.

mod blocks;
mod padding;

pub use blocks::Blocks;
pub use padding::PKCS7;

#[cfg(umilib_feature = "crypto-mode-cbc")]
pub mod cbc;
#[cfg(umilib_feature = "crypto-mode-ccm")]
pub mod ccm;
#[cfg(umilib_feature = "crypto-mode-cfb")]
pub mod cfb;
#[cfg(umilib_feature = "crypto-mode-ctr")]
pub mod ctr;
#[cfg(umilib_feature = "crypto-mode-ecb")]
pub mod ecb;
#[cfg(umilib_feature = "crypto-mode-gcm")]
pub mod gcm;
#[cfg(umilib_feature = "crypto-mode-gcmsiv")]
pub mod gcmsiv;
#[cfg(umilib_feature = "crypto-mode-kw")]
pub mod kw;
#[cfg(umilib_feature = "crypto-mode-ofb")]
pub mod ofb;
#[cfg(umilib_feature = "crypto-mode-siv")]
pub mod siv;
#[cfg(umilib_feature = "crypto-mode-xts")]
pub mod xts;
