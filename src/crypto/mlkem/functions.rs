use crate::hash::sha::v3::{SHA3_256, SHA3_512, SHAKE128, SHAKE256};
use crate::hash::{Digest, ExtendableOutput, XOFReader};
use crate::math::lattice::{LatticeRing, MLKEMRing, Polynomial};
use crate::secret::Zeroize;

/// The functions of FIPS 203 section 4.1 and the sampling of section 4.2.2:
/// G = SHA3-512, H = SHA3-256, J = SHAKE256 to 32 bytes, PRF_η = SHAKE256
/// to 64 η bytes and the XOF SHAKE128.
pub struct MLKEMFunctions;

impl MLKEMFunctions {
    /// The bytes of the largest ciphertext of the parameter sets (ML-KEM-1024).
    pub const LARGEST_CIPHERTEXT: usize = 1568;

    /// G(`parts` concatenated) as its two halves of 32 bytes.
    pub fn g(parts: &[&[u8]]) -> ([u8; 32], [u8; 32]) {
        let mut hash = SHA3_512::default();
        for part in parts {
            hash.update(part);
        }
        let mut output = hash.finalize();
        let (mut first, mut second) = ([0u8; 32], [0u8; 32]);
        first.copy_from_slice(&output[..32]);
        second.copy_from_slice(&output[32..]);
        output.zeroize();
        (first, second)
    }

    pub fn h(data: &[u8]) -> [u8; 32] {
        SHA3_256::digest(data)
    }

    /// J(`parts` concatenated).
    pub fn j(parts: &[&[u8]]) -> [u8; 32] {
        let mut function = SHAKE256::default();
        for part in parts {
            function.update(part);
        }
        let mut out = [0u8; 32];
        function.finalize_xof().read(&mut out);
        out
    }

    /// SamplePolyCBD_η(PRF_η(`seed`, `counter`)) (algorithm 8 of the
    /// output of the PRF): each coefficient is the difference of the sums of
    /// two runs of η bits, computed without branches.
    pub fn sample_cbd(eta: usize, seed: &[u8; 32], counter: u8) -> Polynomial<MLKEMRing> {
        let mut function = SHAKE256::default();
        function.update(seed);
        function.update(&[counter]);
        let mut bytes = [0u8; 64 * 3];
        let bytes = &mut bytes[..64 * eta];
        function.finalize_xof().read(bytes);
        let mut polynomial = Polynomial::zero();
        for index in 0..MLKEMRing::N {
            let (mut x, mut y) = (0u32, 0u32);
            for bit in 0..eta {
                let (first, second) = (2 * index * eta + bit, 2 * index * eta + eta + bit);
                x += ((bytes[first / 8] >> (first % 8)) & 1) as u32;
                y += ((bytes[second / 8] >> (second % 8)) & 1) as u32;
            }
            polynomial.set(index, MLKEMRing::sub(x, y));
        }
        bytes.zeroize();
        polynomial
    }

    /// SampleNTT(ρ || j || i) (algorithm 7): the entry (i, j) of Â, by
    /// rejection of 12-bit values of SHAKE128 not below q. The time
    /// depends on ρ, which is public.
    pub fn sample_ntt(rho: &[u8; 32], j: u8, i: u8) -> Polynomial<MLKEMRing> {
        let mut function = SHAKE128::default();
        function.update(rho);
        function.update(&[j, i]);
        let mut reader = function.finalize_xof();
        let mut polynomial = Polynomial::zero();
        let mut block = [0u8; 168];
        let mut count = 0;
        while count < MLKEMRing::N {
            reader.read(&mut block);
            for chunk in block.as_chunks::<3>().0 {
                let first = chunk[0] as u32 | ((chunk[1] as u32 & 0x0F) << 8);
                let second = (chunk[1] as u32 >> 4) | ((chunk[2] as u32) << 4);
                for value in [first, second] {
                    if value < MLKEMRing::Q && count < MLKEMRing::N {
                        polynomial.set(count, value);
                        count += 1;
                    }
                }
            }
        }
        polynomial
    }
}
