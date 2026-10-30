use core::fmt;

use super::AsconSponge;
use crate::hash::{CryptographicDigest, Digest, XOFReader};
use crate::secret::Zeroize;

/// Ascon-Hash256 (SP 800-232 section 5.1): a 256-bit digest with a security
/// strength of 128 bits. Its use within HMAC is not approved (section 6).
#[derive(Clone)]
pub struct AsconHash256 {
    sponge: AsconSponge,
}

impl AsconHash256 {
    /// The initial value (table 14).
    pub const IV: u64 = 0x0000_0801_00cc_0002;

    pub fn new() -> AsconHash256 {
        AsconHash256 { sponge: AsconSponge::new(AsconHash256::IV) }
    }
}

impl Default for AsconHash256 {
    fn default() -> AsconHash256 {
        AsconHash256::new()
    }
}

impl Digest for AsconHash256 {
    const OUTPUT_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 8;
    type Output = [u8; 32];

    fn update(&mut self, data: &[u8]) {
        self.sponge.absorb(data);
    }

    fn finalize(self) -> [u8; 32] {
        let mut digest = [0u8; 32];
        let mut reader = self.sponge.clone().finalize();
        reader.read(&mut digest);
        reader.zeroize();
        digest
    }

    fn reset(&mut self) {
        self.sponge = AsconSponge::new(AsconHash256::IV);
    }
}

impl CryptographicDigest for AsconHash256 {}

impl Zeroize for AsconHash256 {
    fn zeroize(&mut self) {
        self.sponge.zeroize();
    }
}

impl fmt::Debug for AsconHash256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AsconHash256(..)")
    }
}
