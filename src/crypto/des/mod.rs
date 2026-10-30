//! DES and Triple DES (NIST SP 800-67r2, formerly FIPS 46-3): the Data
//! Encryption Algorithm on 64-bit blocks and its triple application.
//!
//! DES with one 56-bit key is broken by exhaustive search; it is here for
//! the protocols and files that still use it, and as the engine of TDES.
//! SP 800-131A allows two-key TDES and data encrypted with it only for
//! legacy use, and limits a three-key bundle to 2^20 blocks.

mod dea;
mod tdea;

pub use dea::DES;
pub use tdea::TDES;
