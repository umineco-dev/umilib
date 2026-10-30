//! scrypt (RFC 7914): the memory-hard password-based key derivation function.

use alloc::vec::Vec;
use core::fmt;

use crate::crypto::CryptoError;
use crate::crypto::pbkdf2::PBKDF2;
use crate::hash::sha::v2::SHA256;
use crate::secret::Zeroize;

/// The parameters of scrypt (section 6): the CPU/memory cost N, the block
/// size r and the parallelization p.
///
/// scrypt needs 128 × r × N bytes of memory ([`Scrypt::memory`]), which a
/// caller should bound before deriving with parameters it did not choose.
/// ROMix reads its memory at indices derived from the password, so scrypt is
/// not resistant to cache-timing attacks by design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scrypt {
    n: u64,
    r: u32,
    p: u32,
}

impl Scrypt {
    /// Checks the parameters of section 6: N > 1 a power of two below
    /// 2^(128 × r / 8), r × p < 2^30, and p ≤ ((2^32 - 1) × 32) / (128 × r).
    pub fn new(n: u64, r: u32, p: u32) -> Result<Scrypt, CryptoError> {
        let valid_n = n > 1 && n.is_power_of_two() && ((16 * r as u64) >= 64 || n < 1u64 << (16 * r as u64));
        let valid_rp = r > 0 && p > 0 && (r as u64 * p as u64) < (1 << 30);
        let valid_p = valid_rp && (p as u64) <= (((1u64 << 32) - 1) * 32) / (128 * r as u64);
        if !valid_n || !valid_p {
            return Err(CryptoError::InvalidParameter);
        }
        Ok(Scrypt { n, r, p })
    }

    pub fn n(&self) -> u64 {
        self.n
    }

    pub fn r(&self) -> u32 {
        self.r
    }

    pub fn p(&self) -> u32 {
        self.p
    }

    /// The bytes of memory a derivation allocates: V (128 × r × N) and B (128 × r × p).
    pub fn memory(&self) -> u128 {
        128 * self.r as u128 * (self.n as u128 + self.p as u128)
    }

    /// The Salsa20/8 core (section 3) on 16 little-endian words.
    pub fn salsa20_8(block: &mut [u32; 16]) {
        let mut input = *block;
        let x = block;
        let quarter = |x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize| {
            x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
            x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
            x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
            x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
        };
        for _ in 0..4 {
            quarter(x, 0, 4, 8, 12);
            quarter(x, 5, 9, 13, 1);
            quarter(x, 10, 14, 2, 6);
            quarter(x, 15, 3, 7, 11);
            quarter(x, 0, 1, 2, 3);
            quarter(x, 5, 6, 7, 4);
            quarter(x, 10, 11, 8, 9);
            quarter(x, 15, 12, 13, 14);
        }
        for (word, input) in x.iter_mut().zip(&input) {
            *word = word.wrapping_add(*input);
        }
        input.zeroize();
    }

    /// scryptBlockMix (section 4) of the 2 × r blocks of `input` into `output`.
    pub fn block_mix(input: &[[u32; 16]], output: &mut [[u32; 16]]) {
        let r = input.len() / 2;
        let mut x = input[2 * r - 1];
        for (index, block) in input.iter().enumerate() {
            for (word, value) in x.iter_mut().zip(block) {
                *word ^= value;
            }
            Scrypt::salsa20_8(&mut x);
            // Y[0], Y[2], ... first, then Y[1], Y[3], ...
            output[index / 2 + (index % 2) * r] = x;
        }
        x.zeroize();
    }

    /// scryptROMix (section 5) of `block` (2 × r blocks) with `memory` of N × 2 × r blocks.
    pub fn ro_mix(block: &mut [[u32; 16]], memory: &mut [[u32; 16]], scratch: &mut [[u32; 16]]) {
        let width = block.len();
        let n = memory.len() / width;
        for chunk in memory.chunks_exact_mut(width) {
            chunk.copy_from_slice(block);
            Scrypt::block_mix(chunk, block);
        }
        for _ in 0..n {
            // Integerify: the first 64 bits of the last block, little-endian, modulo N (a power of two).
            let last = &block[width - 1];
            let j = ((last[0] as u64 | (last[1] as u64) << 32) & (n as u64 - 1)) as usize;
            for (x, v) in block.iter_mut().zip(&memory[j * width..(j + 1) * width]) {
                for (word, value) in x.iter_mut().zip(v) {
                    *word ^= value;
                }
            }
            scratch.copy_from_slice(block);
            Scrypt::block_mix(scratch, block);
        }
    }

    /// DK of `out.len()` bytes from the passphrase `password` and the salt `salt` (section 6).
    pub fn derive(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.is_empty() || out.len() as u64 > PBKDF2::<SHA256>::MAXIMUM_OUTPUT {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        let width = 2 * self.r as usize;
        // The sizes in units of 64 bytes, which may not fit in a usize (or in a u64 for V).
        let units = |count: u64, size: u64| {
            count.checked_mul(size).and_then(|total| usize::try_from(total).ok()).ok_or(CryptoError::Allocation)
        };
        let byte_length = units(64 * width as u64, self.p as u64)?;
        let memory_blocks = units(self.n, width as u64)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(byte_length).map_err(|_| CryptoError::Allocation)?;
        bytes.resize(byte_length, 0);
        let mut memory = Vec::new();
        memory.try_reserve_exact(memory_blocks).map_err(|_| CryptoError::Allocation)?;
        memory.resize(memory_blocks, [0u32; 16]);
        let mut block = Vec::new();
        block.try_reserve_exact(2 * width).map_err(|_| CryptoError::Allocation)?;
        block.resize(2 * width, [0u32; 16]);
        let (block, scratch) = block.split_at_mut(width);
        // B = PBKDF2-HMAC-SHA256(P, S, 1, p × 128 × r).
        PBKDF2::<SHA256>::derive(password, salt, 1, &mut bytes)?;
        for chunk in bytes.chunks_exact_mut(64 * width) {
            for (words, piece) in block.iter_mut().zip(chunk.as_chunks::<64>().0) {
                for (word, bytes) in words.iter_mut().zip(piece.as_chunks::<4>().0) {
                    *word = u32::from_le_bytes(*bytes);
                }
            }
            Scrypt::ro_mix(block, &mut memory, scratch);
            for (words, piece) in block.iter().zip(chunk.as_chunks_mut::<64>().0) {
                for (word, bytes) in words.iter().zip(piece.as_chunks_mut::<4>().0) {
                    *bytes = word.to_le_bytes();
                }
            }
        }
        let result = PBKDF2::<SHA256>::derive(password, &bytes, 1, out);
        bytes.zeroize();
        memory.iter_mut().for_each(|block| block.zeroize());
        block.iter_mut().chain(scratch.iter_mut()).for_each(|block| block.zeroize());
        result
    }
}

impl fmt::Display for Scrypt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "scrypt(N = {}, r = {}, p = {})", self.n, self.r, self.p)
    }
}
