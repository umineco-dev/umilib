//! AEGIS (draft-irtf-cfrg-aegis-aead-18): authenticated encryption, a MAC
//! and a stream cipher from the AES round function. AEGIS-128L and AEGIS-256 are the parallel modes
//! AEGIS-128X and AEGIS-256X with one lane, as section 5.6 notes.

mod aegis128x;
mod aegis256x;
mod mac;

pub use aegis128x::{AEGIS128L, AEGIS128X, AEGIS128XState};
pub use aegis256x::{AEGIS256, AEGIS256X, AEGIS256XState};
pub use mac::{AEGISMAC128L, AEGISMAC128X, AEGISMAC256, AEGISMAC256X};

use crate::crypto::CryptoError;

/// The constants and the checks shared by the AEGIS variants (section 2).
pub struct AEGISComponents;

impl AEGISComponents {
    /// C0: the Fibonacci sequence modulo 256.
    pub const C0: [u8; 16] =
        [0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62];
    pub const C1: [u8; 16] =
        [0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd];
    /// P_MAX and A_MAX: 2^61 - 1 bytes.
    pub const MAXIMUM_INPUT: u64 = (1 << 61) - 1;

    pub fn xor(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
        let mut out = *a;
        for (byte, other) in out.iter_mut().zip(b) {
            *byte ^= other;
        }
        out
    }

    pub fn and(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
        let mut out = *a;
        for (byte, other) in out.iter_mut().zip(b) {
            *byte &= other;
        }
        out
    }

    /// ctx\[i\] of section 5.1: the index of the lane and the highest index, then zeros.
    pub fn context(lane: usize, degree: usize) -> [u8; 16] {
        let mut context = [0u8; 16];
        context[0] = lane as u8;
        context[1] = (degree - 1) as u8;
        context
    }

    /// Checks the lengths of a message against P_MAX and A_MAX.
    pub fn check(associated: &[u8], data: &[u8]) -> Result<(), CryptoError> {
        for input in [associated, data] {
            if input.len() as u64 > AEGISComponents::MAXIMUM_INPUT {
                return Err(CryptoError::InputLength { length: input.len() });
            }
        }
        Ok(())
    }
}
