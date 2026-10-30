use super::AsconPermutation;
use crate::hash::XOFReader;
use crate::secret::Zeroize;

/// The sponge of Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 (SP 800-232
/// section 5): a rate of 64 bits (S0) and Ascon-p\[12\] between blocks.
#[derive(Clone, Debug)]
pub struct AsconSponge {
    permutation: AsconPermutation,
    /// The bytes of the current block already added to S0.
    position: usize,
}

impl AsconSponge {
    /// The rate in bytes.
    pub const RATE: usize = 8;
    pub const ROUNDS: usize = 12;

    /// S = Ascon-p\[12\](IV || 0^256).
    pub fn new(iv: u64) -> AsconSponge {
        let mut permutation = AsconPermutation::from_words([iv, 0, 0, 0, 0]);
        permutation.permute(AsconSponge::ROUNDS);
        AsconSponge { permutation, position: 0 }
    }

    /// The sponge with the state `words` after the initialization (as table 12 lists them).
    pub fn from_words(words: [u64; 5]) -> AsconSponge {
        AsconSponge { permutation: AsconPermutation::from_words(words), position: 0 }
    }

    pub fn permutation(&self) -> &AsconPermutation {
        &self.permutation
    }

    /// Adds `data` to the input: each full block of 8 bytes is followed by Ascon-p\[12\].
    pub fn absorb(&mut self, data: &[u8]) {
        for &byte in data {
            self.permutation.xor_bytes(self.position, &[byte]);
            self.position += 1;
            if self.position == AsconSponge::RATE {
                self.permutation.permute(AsconSponge::ROUNDS);
                self.position = 0;
            }
        }
    }

    /// Adds the padding 1 || 0* to the last (possibly empty) block, then Ascon-p\[12\] (algorithm 2).
    pub fn pad(&mut self) {
        self.permutation.xor_bytes(self.position, &[0x01]);
        self.permutation.permute(AsconSponge::ROUNDS);
        self.position = 0;
    }

    /// Ends the input and returns the reader of the output.
    pub fn finalize(mut self) -> AsconReader {
        self.pad();
        AsconReader { permutation: self.permutation.clone(), position: 0 }
    }
}

impl Zeroize for AsconSponge {
    fn zeroize(&mut self) {
        self.permutation.zeroize();
        self.position = 0;
    }
}

/// Reads the output of the sponge: S0 block by block, with Ascon-p\[12\]
/// between blocks (algorithms 5 to 7).
#[derive(Clone, Debug)]
pub struct AsconReader {
    permutation: AsconPermutation,
    /// The bytes of S0 already read.
    position: usize,
}

impl XOFReader for AsconReader {
    fn read(&mut self, out: &mut [u8]) {
        for byte in out {
            if self.position == AsconSponge::RATE {
                self.permutation.permute(AsconSponge::ROUNDS);
                self.position = 0;
            }
            *byte = self.permutation.byte(self.position);
            self.position += 1;
        }
    }
}

impl Zeroize for AsconReader {
    fn zeroize(&mut self) {
        self.permutation.zeroize();
        self.position = 0;
    }
}
