//! The synthetic initialization vector mode (RFC 5297): [`SIV`] and its
//! pseudo-random function of string vectors [`S2V`].

mod aead;
mod s2v;

pub use aead::SIV;
pub use s2v::S2V;
