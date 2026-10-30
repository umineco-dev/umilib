use core::fmt;

use super::{AsconReader, AsconSponge};
use crate::hash::{ExtendableOutput, HashError};
use crate::secret::Zeroize;

/// Ascon-XOF128 (SP 800-232 section 5.2): any number of output bytes with a
/// security strength of up to 128 bits; a shorter output is a prefix of a
/// longer one.
#[derive(Clone)]
pub struct AsconXOF128 {
    sponge: AsconSponge,
}

impl AsconXOF128 {
    /// The initial value (table 14).
    pub const IV: u64 = 0x0000_0800_00cc_0003;

    pub fn new() -> AsconXOF128 {
        AsconXOF128 { sponge: AsconSponge::new(AsconXOF128::IV) }
    }
}

impl Default for AsconXOF128 {
    fn default() -> AsconXOF128 {
        AsconXOF128::new()
    }
}

impl ExtendableOutput for AsconXOF128 {
    const BLOCK_SIZE: usize = 8;
    type Reader = AsconReader;

    fn update(&mut self, data: &[u8]) {
        self.sponge.absorb(data);
    }

    fn finalize_xof(self) -> AsconReader {
        self.sponge.clone().finalize()
    }

    fn reset(&mut self) {
        self.sponge = AsconSponge::new(AsconXOF128::IV);
    }
}

impl Zeroize for AsconXOF128 {
    fn zeroize(&mut self) {
        self.sponge.zeroize();
    }
}

impl fmt::Debug for AsconXOF128 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AsconXOF128(..)")
    }
}

/// Ascon-CXOF128 (SP 800-232 section 5.3): Ascon-XOF128 with a
/// customization string of at most 256 bytes for domain separation, absorbed
/// as its bit length and the padded string before the message.
#[derive(Clone)]
pub struct AsconCXOF128 {
    /// The state after the customization, which `reset` returns to.
    customized: AsconSponge,
    sponge: AsconSponge,
}

impl AsconCXOF128 {
    /// The initial value (table 14).
    pub const IV: u64 = 0x0000_0800_00cc_0004;
    /// The longest customization string: 2048 bits.
    pub const MAXIMUM_CUSTOMIZATION: usize = 256;

    pub fn new(customization: &[u8]) -> Result<AsconCXOF128, HashError> {
        if customization.len() > AsconCXOF128::MAXIMUM_CUSTOMIZATION {
            return Err(HashError::InvalidParameter);
        }
        let mut sponge = AsconSponge::new(AsconCXOF128::IV);
        // Z0 = int64(|Z|), then Z padded (algorithm 7).
        sponge.absorb(&(8 * customization.len() as u64).to_le_bytes());
        sponge.absorb(customization);
        sponge.pad();
        Ok(AsconCXOF128 { customized: sponge.clone(), sponge })
    }
}

impl ExtendableOutput for AsconCXOF128 {
    const BLOCK_SIZE: usize = 8;
    type Reader = AsconReader;

    fn update(&mut self, data: &[u8]) {
        self.sponge.absorb(data);
    }

    fn finalize_xof(self) -> AsconReader {
        self.sponge.clone().finalize()
    }

    fn reset(&mut self) {
        self.sponge = self.customized.clone();
    }
}

impl Zeroize for AsconCXOF128 {
    fn zeroize(&mut self) {
        self.customized.zeroize();
        self.sponge.zeroize();
    }
}

impl fmt::Debug for AsconCXOF128 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AsconCXOF128(..)")
    }
}
