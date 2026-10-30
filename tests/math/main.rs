//! Tests of `umilib::math`: integer arithmetic against `u128` and Python
//! (in `port/python/tests`), and modular arithmetic against number theory and
//! the constants of the specifications that use it.

#![allow(clippy::upper_case_acronyms)]

#[cfg(umilib_feature = "math-bigint")]
mod bigint;
#[cfg(umilib_feature = "math-ec")]
mod ec;
#[cfg(umilib_feature = "math-lattice")]
mod lattice;
#[cfg(umilib_feature = "math-modular")]
mod modular;
#[cfg(umilib_feature = "math-pairing")]
mod pairing;
#[cfg(umilib_feature = "math-modular")]
mod vectors;

#[path = "../common/vectors.rs"]
#[allow(dead_code)]
mod common_vectors;
#[cfg(umilib_feature = "math-ec")]
#[path = "../common/ec.rs"]
mod ec_checks;

pub use common_vectors::{RFC, Vectors};

/// A deterministic source of test values (SplitMix64).
pub struct Values {
    state: u64,
}

impl Values {
    pub fn new(seed: u64) -> Values {
        Values { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    /// A value with a random number of significant bits, so that small,
    /// large and boundary values all occur.
    pub fn next_u128(&mut self) -> u128 {
        let value = ((self.next_u64() as u128) << 64) | self.next_u64() as u128;
        match self.next_u64() % 8 {
            0 => 0,
            1 => u128::MAX,
            2 => u128::MAX - (self.next_u64() % 4) as u128,
            3 => (self.next_u64() % 4) as u128,
            _ => value >> (self.next_u64() % 128),
        }
    }
}

/// Hexadecimal text to bytes.
pub struct Hex;

impl Hex {
    pub fn decode(text: &str) -> Vec<u8> {
        let text: String = text.chars().filter(|character| !character.is_whitespace()).collect();
        (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap()).collect()
    }
}
