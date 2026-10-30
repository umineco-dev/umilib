//! Streebog, GOST R 34.11-2012 (RFC 6986), the Russian hash function with
//! 256-bit and 512-bit hash codes.
//!
//! The standard writes vectors as numbers, most significant digit first;
//! here messages and hash codes are byte strings whose first byte is the
//! least significant, as implementations exchange them (the examples of RFC
//! 6986 section 10 read in reverse).
//!
//! The nonlinear bijection is applied by scanning all of its 256 entries for
//! every byte, so that no memory access depends on the hashed data: slower
//! than a table lookup, but free of cache timing.

use core::fmt;

use crate::hash::{BlockBuffer, CryptographicDigest, Digest};
use crate::secret::Zeroize;

/// The parameters and transformations of GOST R 34.11-2012 on 512-bit
/// vectors held as eight 64-bit lanes, least significant first.
pub struct StreebogConstants;

impl StreebogConstants {
    /// The nonlinear bijection Pi of section 6.2.
    pub const PI: [u8; 256] = [
        252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46, 153, 186,
        23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5,
        132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242,
        42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21,
        161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126,
        109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
        224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26,
        184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88,
        179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83,
        170, 144, 202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
        116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
    ];
    /// The byte permutation Tau of section 6.3: byte i of P(a) is byte Tau(i) of a.
    pub const TAU: [usize; 64] = [
        0, 8, 16, 24, 32, 40, 48, 56, 1, 9, 17, 25, 33, 41, 49, 57, 2, 10, 18, 26, 34, 42, 50, 58, 3, 11, 19, 27, 35,
        43, 51, 59, 4, 12, 20, 28, 36, 44, 52, 60, 5, 13, 21, 29, 37, 45, 53, 61, 6, 14, 22, 30, 38, 46, 54, 62, 7, 15,
        23, 31, 39, 47, 55, 63,
    ];
    /// The rows of the matrix A of section 6.4, row 0 first.
    pub const A: [u64; 64] = [
        0x8e20faa72ba0b470,
        0x47107ddd9b505a38,
        0xad08b0e0c3282d1c,
        0xd8045870ef14980e,
        0x6c022c38f90a4c07,
        0x3601161cf205268d,
        0x1b8e0b0e798c13c8,
        0x83478b07b2468764,
        0xa011d380818e8f40,
        0x5086e740ce47c920,
        0x2843fd2067adea10,
        0x14aff010bdd87508,
        0x0ad97808d06cb404,
        0x05e23c0468365a02,
        0x8c711e02341b2d01,
        0x46b60f011a83988e,
        0x90dab52a387ae76f,
        0x486dd4151c3dfdb9,
        0x24b86a840e90f0d2,
        0x125c354207487869,
        0x092e94218d243cba,
        0x8a174a9ec8121e5d,
        0x4585254f64090fa0,
        0xaccc9ca9328a8950,
        0x9d4df05d5f661451,
        0xc0a878a0a1330aa6,
        0x60543c50de970553,
        0x302a1e286fc58ca7,
        0x18150f14b9ec46dd,
        0x0c84890ad27623e0,
        0x0642ca05693b9f70,
        0x0321658cba93c138,
        0x86275df09ce8aaa8,
        0x439da0784e745554,
        0xafc0503c273aa42a,
        0xd960281e9d1d5215,
        0xe230140fc0802984,
        0x71180a8960409a42,
        0xb60c05ca30204d21,
        0x5b068c651810a89e,
        0x456c34887a3805b9,
        0xac361a443d1c8cd2,
        0x561b0d22900e4669,
        0x2b838811480723ba,
        0x9bcf4486248d9f5d,
        0xc3e9224312c8c1a0,
        0xeffa11af0964ee50,
        0xf97d86d98a327728,
        0xe4fa2054a80b329c,
        0x727d102a548b194e,
        0x39b008152acb8227,
        0x9258048415eb419d,
        0x492c024284fbaec0,
        0xaa16012142f35760,
        0x550b8e9e21f7a530,
        0xa48b474f9ef5dc18,
        0x70a6a56e2440598e,
        0x3853dc371220a247,
        0x1ca76e95091051ad,
        0x0edd37c48a08a6d8,
        0x07e095624504536c,
        0x8d70c431ac02a736,
        0xc83862965601dd1b,
        0x641c314b2b8ee083,
    ];
    /// The iteration constants C\[1\] to C\[12\] of section 6.5, as 64-bit lanes, least significant first.
    pub const C: [[u64; 8]; 12] = [
        [
            0xdd806559f2a64507,
            0x05767436cc744d23,
            0xa2422a08a460d315,
            0x4b7ce09192676901,
            0x714eb88d7585c4fc,
            0x2f6a76432e45d016,
            0xebcb2f81c0657c1f,
            0xb1085bda1ecadae9,
        ],
        [
            0xe679047021b19bb7,
            0x55dda21bd7cbcd56,
            0x5cb561c2db0aa7ca,
            0x9ab5176b12d69958,
            0x61d55e0f16b50131,
            0xf3feea720a232b98,
            0x4fe39d460f70b5d7,
            0x6fa3b58aa99d2f1a,
        ],
        [
            0x991e96f50aba0ab2,
            0xc2b6f443867adb31,
            0xc1c93a376062db09,
            0xd3e20fe490359eb1,
            0xf2ea7514b1297b7b,
            0x06f15e5f529c1f8b,
            0x0a39fc286a3d8435,
            0xf574dcac2bce2fc7,
        ],
        [
            0x220cbebc84e3d12e,
            0x3453eaa193e837f1,
            0xd8b71333935203be,
            0xa9d72c82ed03d675,
            0x9d721cad685e353f,
            0x488e857e335c3c7d,
            0xf948e1a05d71e4dd,
            0xef1fdfb3e81566d2,
        ],
        [
            0x601758fd7c6cfe57,
            0x7a56a27ea9ea63f5,
            0xdfff00b723271a16,
            0xbfcd1747253af5a3,
            0x359e35d7800fffbd,
            0x7f151c1f1686104a,
            0x9a3f410c6ca92363,
            0x4bea6bacad474799,
        ],
        [
            0xfa68407a46647d6e,
            0xbf71c57236904f35,
            0x0af21f66c2bec6b6,
            0xcffaa6b71c9ab7b4,
            0x187f9ab49af08ec6,
            0x2d66c4f95142a46c,
            0x6fa4c33b7a3039c0,
            0xae4faeae1d3ad3d9,
        ],
        [
            0x8886564d3a14d493,
            0x3517454ca23c4af3,
            0x06476983284a0504,
            0x0992abc52d822c37,
            0xd3473e33197a93c9,
            0x399ec6c7e6bf87c9,
            0x51ac86febf240954,
            0xf4c70e16eeaac5ec,
        ],
        [
            0xa47f0dd4bf02e71e,
            0x36acc2355951a8d9,
            0x69d18d2bd1a5c42f,
            0xf4892bcb929b0690,
            0x89b4443b4ddbc49a,
            0x4eb7f8719c36de1e,
            0x03e7aa020c6e4141,
            0x9b1f5b424d93c9a7,
        ],
        [
            0x7261445183235adb,
            0x0e38dc92cb1f2a60,
            0x7b2b8a9aa6079c54,
            0x800a440bdbb2ceb1,
            0x3cd955b7e00d0984,
            0x3a7d3a1b25894224,
            0x944c9ad8ec165fde,
            0x378f5a541631229b,
        ],
        [
            0x74b4c7fb98459ced,
            0x3698fad1153bb6c3,
            0x7a1e6c303b7652f4,
            0x9fe76702af69334b,
            0x1fffe18a1b336103,
            0x8941e71cff8a78db,
            0x382ae548b2e4f3f3,
            0xabbedea680056f52,
        ],
        [
            0x6bcaa4cd81f32d1b,
            0xdea2594ac06fd85d,
            0xefbacd1d7d476e98,
            0x8a1d71efea48b9ca,
            0x2001802114846679,
            0xd8fa6bbbebab0761,
            0x3002c6cd635afe94,
            0x7bcd9ed0efc889fb,
        ],
        [
            0x48bc924af11bd720,
            0xfaf417d5d9b21b99,
            0xe71da4aa88e12852,
            0x5d80ef9d1891cc86,
            0xf82012d430219f9b,
            0xcda43c32bcdf1d77,
            0xd21380b00449b17a,
            0x378ee767f11631ba,
        ],
    ];

    /// S (section 7): Pi on every byte, scanning the whole table for each of
    /// eight bytes at once, so that the time and the memory accesses do not
    /// depend on the bytes.
    pub fn s(a: &mut [u64; 8]) {
        const LOW: u64 = 0x7F7F_7F7F_7F7F_7F7F;
        const HIGH: u64 = 0x8080_8080_8080_8080;
        const ONES: u64 = 0x0101_0101_0101_0101;
        let mut result = [0u64; 8];
        for (value, &image) in StreebogConstants::PI.iter().enumerate() {
            let candidate = ONES * value as u64;
            let image = ONES * image as u64;
            for (lane, output) in a.iter().zip(result.iter_mut()) {
                // The high bit of each byte of `zero` is set where the byte equals `value`.
                let difference = lane ^ candidate;
                let zero = !(((difference & LOW) + LOW) | difference | LOW) & HIGH;
                *output |= ((zero >> 7) * 0xFF) & image;
            }
        }
        *a = result;
        result.zeroize();
    }

    /// P (section 7): byte i becomes byte Tau(i).
    pub fn p(a: &mut [u64; 8]) {
        let mut bytes = [0u8; 64];
        for (chunk, lane) in bytes.chunks_mut(8).zip(a.iter()) {
            chunk.copy_from_slice(&lane.to_le_bytes());
        }
        for (index, lane) in a.iter_mut().enumerate() {
            let mut value = [0u8; 8];
            for (offset, byte) in value.iter_mut().enumerate() {
                *byte = bytes[StreebogConstants::TAU[8 * index + offset]];
            }
            *lane = u64::from_le_bytes(value);
        }
        bytes.zeroize();
    }

    /// l (section 6.4): the product of a 64-bit vector and the matrix A; bit i
    /// of the vector selects row 63 - i.
    pub fn l(b: u64) -> u64 {
        let mut c = 0;
        for (row, &value) in StreebogConstants::A.iter().enumerate() {
            let bit = (b >> (63 - row)) & 1;
            c ^= value & 0u64.wrapping_sub(bit);
        }
        c
    }

    /// The composition L(P(S(a))) of section 7.
    pub fn lps(a: &mut [u64; 8]) {
        StreebogConstants::s(a);
        StreebogConstants::p(a);
        for lane in a.iter_mut() {
            *lane = StreebogConstants::l(*lane);
        }
    }

    pub fn xor(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
        core::array::from_fn(|index| a[index] ^ b[index])
    }

    /// `a + b` modulo 2^512.
    pub fn add(a: &mut [u64; 8], b: &[u64; 8]) {
        let mut carry = 0u64;
        for (x, &y) in a.iter_mut().zip(b) {
            let (sum, overflow) = x.overflowing_add(y);
            let (sum, overflow_carry) = sum.overflowing_add(carry);
            *x = sum;
            carry = (overflow as u64) + (overflow_carry as u64);
        }
    }

    /// The round function g_N(h, m) of section 8.
    pub fn g(n: &[u64; 8], h: &mut [u64; 8], m: &[u64; 8]) {
        let mut key = StreebogConstants::xor(h, n);
        StreebogConstants::lps(&mut key);
        // E(K, m): twelve rounds of X[K[i]] then LPS, then X[K[13]].
        let mut state = *m;
        for constant in &StreebogConstants::C {
            state = StreebogConstants::xor(&state, &key);
            StreebogConstants::lps(&mut state);
            key = StreebogConstants::xor(&key, constant);
            StreebogConstants::lps(&mut key);
        }
        for ((word, s), (k, x)) in h.iter_mut().zip(state).zip(key.iter().zip(m)) {
            *word ^= s ^ k ^ x;
        }
        key.zeroize();
        state.zeroize();
    }

    /// The 64-byte block as lanes.
    pub fn lanes(block: &[u8; 64]) -> [u64; 8] {
        let mut lanes = [0u64; 8];
        for (lane, bytes) in lanes.iter_mut().zip(block.as_chunks::<8>().0) {
            *lane = u64::from_le_bytes(*bytes);
        }
        lanes
    }
}

/// The hash procedure of section 9 with an initializing value; [`Streebog512`]
/// and [`Streebog256`] differ in it and in the length of the result.
#[derive(Clone)]
pub struct Streebog {
    h: [u64; 8],
    n: [u64; 8],
    sigma: [u64; 8],
    buffer: BlockBuffer<64>,
    initial: [u64; 8],
}

impl Streebog {
    pub const fn new(initial: [u64; 8]) -> Streebog {
        Streebog { h: initial, n: [0; 8], sigma: [0; 8], buffer: BlockBuffer::new(), initial }
    }

    /// Step 2 on one block.
    pub fn process(h: &mut [u64; 8], n: &mut [u64; 8], sigma: &mut [u64; 8], block: &[u8; 64]) {
        let mut m = StreebogConstants::lanes(block);
        StreebogConstants::g(n, h, &m);
        StreebogConstants::add(n, &[512, 0, 0, 0, 0, 0, 0, 0]);
        StreebogConstants::add(sigma, &m);
        m.zeroize();
    }

    pub fn update(&mut self, data: &[u8]) {
        let (h, n, sigma) = (&mut self.h, &mut self.n, &mut self.sigma);
        self.buffer.update(data, |block| Streebog::process(h, n, sigma, block));
    }

    /// Step 3: the last, padded block, then N and Σ; returns h.
    pub fn finalize_state(mut self) -> [u64; 8] {
        let remaining = self.buffer.len();
        let mut block = [0u8; 64];
        block[..remaining].copy_from_slice(self.buffer.pending());
        block[remaining] = 0x01;
        let mut m = StreebogConstants::lanes(&block);
        StreebogConstants::g(&self.n, &mut self.h, &m);
        StreebogConstants::add(&mut self.n, &[8 * remaining as u64, 0, 0, 0, 0, 0, 0, 0]);
        StreebogConstants::add(&mut self.sigma, &m);
        let zero = [0u64; 8];
        StreebogConstants::g(&zero, &mut self.h, &self.n);
        StreebogConstants::g(&zero, &mut self.h, &self.sigma);
        block.zeroize();
        m.zeroize();
        self.h
    }

    pub fn reset(&mut self) {
        self.zeroize();
        self.h = self.initial;
    }
}

impl Zeroize for Streebog {
    fn zeroize(&mut self) {
        self.h.zeroize();
        self.n.zeroize();
        self.sigma.zeroize();
        self.buffer.zeroize();
    }
}

impl Drop for Streebog {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for Streebog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Streebog(..)")
    }
}

/// Streebog with a 512-bit hash code (initializing value 0^512).
#[derive(Clone, Debug)]
pub struct Streebog512 {
    inner: Streebog,
}

impl Streebog512 {
    pub const fn new() -> Streebog512 {
        Streebog512 { inner: Streebog::new([0; 8]) }
    }
}

impl Digest for Streebog512 {
    const OUTPUT_SIZE: usize = 64;
    const BLOCK_SIZE: usize = 64;
    type Output = [u8; 64];

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> [u8; 64] {
        let h = self.inner.finalize_state();
        let mut output = [0u8; 64];
        for (bytes, lane) in output.chunks_mut(8).zip(h) {
            bytes.copy_from_slice(&lane.to_le_bytes());
        }
        output
    }

    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl Default for Streebog512 {
    fn default() -> Streebog512 {
        Streebog512::new()
    }
}

impl CryptographicDigest for Streebog512 {}

impl Zeroize for Streebog512 {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

/// Streebog with a 256-bit hash code (initializing value (00000001)^64, the
/// most significant half of the result).
#[derive(Clone, Debug)]
pub struct Streebog256 {
    inner: Streebog,
}

impl Streebog256 {
    pub const fn new() -> Streebog256 {
        Streebog256 { inner: Streebog::new([0x0101_0101_0101_0101; 8]) }
    }
}

impl Digest for Streebog256 {
    const OUTPUT_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 64;
    type Output = [u8; 32];

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> [u8; 32] {
        let h = self.inner.finalize_state();
        let mut output = [0u8; 32];
        for (bytes, lane) in output.chunks_mut(8).zip(&h[4..]) {
            bytes.copy_from_slice(&lane.to_le_bytes());
        }
        output
    }

    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl Default for Streebog256 {
    fn default() -> Streebog256 {
        Streebog256::new()
    }
}

impl CryptographicDigest for Streebog256 {}

impl Zeroize for Streebog256 {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}
