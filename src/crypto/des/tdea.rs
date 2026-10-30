use core::fmt;

use super::DES;
use crate::crypto::{BlockCipher, CryptoError, KeyInit};
use crate::secret::{Choice, ConstantTimeEq, Zeroize};

/// The Triple Data Encryption Algorithm (SP 800-67r2 section 3): the forward
/// cipher is E_Key3(D_Key2(E_Key1(d))) and the inverse D_Key1(E_Key2(D_Key3(d))).
///
/// The key bundle is Key1 || Key2 || Key3 (24 bytes) or, for two-key TDES,
/// Key1 || Key2 with Key3 = Key1 (16 bytes). Section 3.1 requires
/// Key1 ≠ Key2 and Key2 ≠ Key3, so that the bundle is not single DES; a
/// bundle that breaks this is refused.
#[derive(Clone)]
pub struct TDES {
    keys: [DES; 3],
}

impl TDES {
    /// The bundle of three keys.
    pub fn new(key1: &[u8; 8], key2: &[u8; 8], key3: &[u8; 8]) -> Result<TDES, CryptoError> {
        if TDES::degenerate(key1, key2).into_bool() || TDES::degenerate(key2, key3).into_bool() {
            return Err(CryptoError::InvalidParameter);
        }
        Ok(TDES { keys: [DES::new(key1), DES::new(key2), DES::new(key3)] })
    }

    /// Whether two keys are equal in the 56 bits that DES uses.
    pub fn degenerate(a: &[u8; 8], b: &[u8; 8]) -> Choice {
        const PARITY: u64 = 0x0101_0101_0101_0101;
        (u64::from_be_bytes(*a) & !PARITY).ct_eq(&(u64::from_be_bytes(*b) & !PARITY))
    }

    /// The DES engines of Key1, Key2 and Key3.
    pub fn keys(&self) -> &[DES; 3] {
        &self.keys
    }
}

impl BlockCipher for TDES {
    const BLOCK_SIZE: usize = 8;
    type Block = [u8; 8];

    fn encrypt_block(&self, block: &mut [u8; 8]) {
        self.keys[0].encrypt_block(block);
        self.keys[1].decrypt_block(block);
        self.keys[2].encrypt_block(block);
    }

    fn decrypt_block(&self, block: &mut [u8; 8]) {
        self.keys[2].decrypt_block(block);
        self.keys[1].encrypt_block(block);
        self.keys[0].decrypt_block(block);
    }
}

impl KeyInit for TDES {
    const MINIMUM_KEY_SIZE: usize = 16;
    const MAXIMUM_KEY_SIZE: usize = 24;

    fn new_from_slice(key: &[u8]) -> Result<TDES, CryptoError> {
        let part = |index: usize| -> &[u8; 8] { key[8 * index..8 * index + 8].try_into().expect("eight bytes") };
        match key.len() {
            16 => TDES::new(part(0), part(1), part(0)),
            24 => TDES::new(part(0), part(1), part(2)),
            length => Err(CryptoError::KeyLength { length, minimum: 16, maximum: 24 }),
        }
    }
}

impl Zeroize for TDES {
    fn zeroize(&mut self) {
        self.keys.iter_mut().for_each(Zeroize::zeroize);
    }
}

impl fmt::Debug for TDES {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TDES(..)")
    }
}
