use core::marker::PhantomData;

use super::MLDSAParameters;
use crate::hash::sha::v3::{SHAKE128, SHAKE256};
use crate::hash::{ExtendableOutput, XOFReader};
use crate::math::lattice::{LatticePacking, LatticeRing, MLDSARing, Polynomial, PolynomialVector};
use crate::secret::Zeroize;

/// The auxiliary functions of FIPS 204 section 7 for the parameters `P`:
/// the XOFs H = SHAKE256 and G = SHAKE128, the pseudorandom sampling of
/// section 7.3, the rounding and hints of section 7.4 and the bit packing
/// of section 7.1. Coefficients are kept modulo q; a signed value v is the
/// element v mod q, and [`MLDSAFunctions::centered`] gives it back.
pub struct MLDSAFunctions<P: MLDSAParameters> {
    parameters: PhantomData<P>,
}

impl<P: MLDSAParameters> MLDSAFunctions<P> {
    /// H(`parts` concatenated, `out.len()`).
    pub fn h(parts: &[&[u8]], out: &mut [u8]) {
        let mut function = SHAKE256::default();
        for part in parts {
            function.update(part);
        }
        function.finalize_xof().read(out);
    }

    /// x mod± q: the representative in \[-(q - 1)/2, (q - 1)/2\], in constant time.
    pub fn centered(value: u32) -> i32 {
        let above = ((MLDSARing::Q - 1) / 2).wrapping_sub(value) >> 31;
        value as i32 - (MLDSARing::Q & 0u32.wrapping_sub(above)) as i32
    }

    /// The element of Z_q of a signed value of magnitude below q.
    pub fn element(value: i32) -> u32 {
        let negative = (value as u32) >> 31;
        (value as u32).wrapping_add(MLDSARing::Q & 0u32.wrapping_sub(negative))
    }

    /// ||`vector`||∞ < `bound`, of the centered coefficients, computed over
    /// every coefficient; the result alone may be revealed.
    pub fn norm_below<V: PolynomialVector<MLDSARing>>(vector: &V, bound: u32) -> bool {
        let mut exceeds = 0u32;
        for polynomial in vector.as_ref() {
            for coefficient in polynomial.coefficients() {
                let magnitude = MLDSAFunctions::<P>::centered(*coefficient).unsigned_abs();
                exceeds |= bound.wrapping_sub(1).wrapping_sub(magnitude) >> 31;
            }
        }
        exceeds == 0
    }

    /// floor(`value` / `divisor`) for `value` below 2^24, by a multiplication
    /// with ceil(2^48 / divisor), exact in that range, in constant time.
    pub fn divide(value: u32, divisor: u32) -> u32 {
        let reciprocal = (1u64 << 48).div_ceil(divisor as u64);
        ((value as u64 * reciprocal) >> 48) as u32
    }

    /// Power2Round (algorithm 35): (r1, r0) with r = r1 2^d + r0, r0 in
    /// (-2^(d-1), 2^(d-1)], r0 given modulo q.
    pub fn power2round(value: u32) -> (u32, u32) {
        let half = 1u32 << (P::D - 1);
        let low = value & ((1 << P::D) - 1);
        // r0 = low - 2^d if low > 2^(d-1).
        let above = half.wrapping_sub(low) >> 31;
        let r0 = low as i32 - ((1i32 << P::D) & (0i32.wrapping_sub(above as i32)));
        let r1 = ((value as i32 - r0) >> P::D) as u32;
        (r1, MLDSAFunctions::<P>::element(r0))
    }

    /// Decompose (algorithm 36) with α = 2 γ2: (r1, r0) with r ≡ r1 α + r0,
    /// r0 in (-α/2, α/2], except r1 = 0 and r0 - 1 where r - r0 = q - 1;
    /// in constant time.
    pub fn decompose(value: u32) -> (u32, i32) {
        let alpha = 2 * P::GAMMA2;
        let mut r1 = MLDSAFunctions::<P>::divide(value + alpha / 2 - 1, alpha);
        let mut r0 = value as i32 - (r1 * alpha) as i32;
        // r1 = (q - 1) / α only where r - r0 = q - 1.
        let last = (MLDSARing::Q - 1) / alpha;
        let wraps = ((r1 ^ last).wrapping_sub(1) >> 31) as i32;
        r1 &= !(0u32.wrapping_sub(wraps as u32));
        r0 -= wraps;
        (r1, r0)
    }

    /// HighBits (algorithm 37).
    pub fn high_bits(value: u32) -> u32 {
        MLDSAFunctions::<P>::decompose(value).0
    }

    /// LowBits (algorithm 38), modulo q.
    pub fn low_bits(value: u32) -> u32 {
        MLDSAFunctions::<P>::element(MLDSAFunctions::<P>::decompose(value).1)
    }

    /// MakeHint (algorithm 39): 1 if adding z to r changes its high bits, in constant time.
    pub fn make_hint(z: u32, r: u32) -> u32 {
        let difference = MLDSAFunctions::<P>::high_bits(r) ^ MLDSAFunctions::<P>::high_bits(MLDSARing::add(r, z));
        (difference | difference.wrapping_neg()) >> 31
    }

    /// UseHint (algorithm 40), on public values.
    pub fn use_hint(hint: u32, value: u32) -> u32 {
        let m = (MLDSARing::Q - 1) / (2 * P::GAMMA2);
        let (r1, r0) = MLDSAFunctions::<P>::decompose(value);
        match (hint, r0 > 0) {
            (0, _) => r1,
            (_, true) => (r1 + 1) % m,
            (_, false) => (r1 + m - 1) % m,
        }
    }

    /// RejNTTPoly(ρ || s || r) (algorithm 30, with ExpandA's seed of
    /// algorithm 32): the entry (r, s) of Â. Its time depends on the public ρ.
    pub fn rej_ntt_poly(rho: &[u8; 32], s: u8, r: u8) -> Polynomial<MLDSARing> {
        let mut function = SHAKE128::default();
        function.update(rho);
        function.update(&[s, r]);
        let mut reader = function.finalize_xof();
        let mut polynomial = Polynomial::zero();
        let (mut block, mut count) = ([0u8; 168], 0);
        while count < MLDSARing::N {
            reader.read(&mut block);
            for bytes in block.as_chunks::<3>().0 {
                let value = bytes[0] as u32 | (bytes[1] as u32) << 8 | ((bytes[2] & 0x7F) as u32) << 16;
                if value < MLDSARing::Q && count < MLDSARing::N {
                    polynomial.set(count, value);
                    count += 1;
                }
            }
        }
        polynomial
    }

    /// ExpandA (algorithm 32).
    pub fn expand_a(rho: &[u8; 32]) -> P::Matrix {
        let mut matrix = P::Matrix::default();
        for (r, row) in matrix.as_mut().iter_mut().enumerate() {
            for (s, entry) in row.as_mut().iter_mut().enumerate() {
                *entry = MLDSAFunctions::<P>::rej_ntt_poly(rho, s as u8, r as u8);
            }
        }
        matrix
    }

    /// RejBoundedPoly(ρ' || r) (algorithm 31) with CoeffFromHalfByte
    /// (algorithm 15): coefficients in \[-η, η\]. Its time reveals how many
    /// half-bytes were rejected, not the coefficients kept.
    pub fn rej_bounded_poly(seed: &[u8; 64], index: u16) -> Polynomial<MLDSARing> {
        let mut function = SHAKE256::default();
        function.update(seed);
        function.update(&index.to_le_bytes());
        let mut reader = function.finalize_xof();
        let mut polynomial = Polynomial::zero();
        let (mut block, mut count) = ([0u8; 136], 0);
        while count < MLDSARing::N {
            reader.read(&mut block);
            for byte in block {
                for half in [byte & 0x0F, byte >> 4] {
                    let accepted = match P::ETA {
                        2 => half < 15,
                        _ => half < 9,
                    };
                    if accepted && count < MLDSARing::N {
                        let value = match P::ETA {
                            2 => 2 - (half % 5) as i32,
                            _ => 4 - half as i32,
                        };
                        polynomial.set(count, MLDSAFunctions::<P>::element(value));
                        count += 1;
                    }
                }
            }
        }
        block.zeroize();
        polynomial
    }

    /// ExpandS (algorithm 33): s1 of ℓ and s2 of k polynomials.
    pub fn expand_s(seed: &[u8; 64]) -> (P::VectorL, P::VectorK) {
        let (mut s1, mut s2) = (P::VectorL::default(), P::VectorK::default());
        for (index, element) in s1.as_mut().iter_mut().enumerate() {
            *element = MLDSAFunctions::<P>::rej_bounded_poly(seed, index as u16);
        }
        for (index, element) in s2.as_mut().iter_mut().enumerate() {
            *element = MLDSAFunctions::<P>::rej_bounded_poly(seed, (P::L + index) as u16);
        }
        (s1, s2)
    }

    /// ExpandMask(ρ'', κ) (algorithm 34): coefficients in \[-γ1 + 1, γ1\].
    pub fn expand_mask(seed: &[u8; 64], kappa: u16) -> P::VectorL {
        let mut y = P::VectorL::default();
        let mut bytes = [0u8; 32 * 20];
        let bytes = &mut bytes[..32 * P::GAMMA1_BITS as usize];
        for (offset, element) in y.as_mut().iter_mut().enumerate() {
            MLDSAFunctions::<P>::h(&[seed, &kappa.wrapping_add(offset as u16).to_le_bytes()], bytes);
            *element = MLDSAFunctions::<P>::bit_unpack(bytes, P::GAMMA1 - 1, P::GAMMA1);
        }
        bytes.zeroize();
        y
    }

    /// SampleInBall(c̃) (algorithm 29): τ coefficients ±1, the others 0. Its
    /// time depends on c̃, which the signature reveals.
    pub fn sample_in_ball(seed: &[u8]) -> Polynomial<MLDSARing> {
        let mut function = SHAKE256::default();
        function.update(seed);
        let mut reader = function.finalize_xof();
        let mut signs = [0u8; 8];
        reader.read(&mut signs);
        let signs = u64::from_le_bytes(signs);
        let mut c = Polynomial::zero();
        let mut byte = [0u8; 1];
        for (sign, i) in (MLDSARing::N - P::TAU..MLDSARing::N).enumerate() {
            reader.read(&mut byte);
            while byte[0] as usize > i {
                reader.read(&mut byte);
            }
            let j = byte[0] as usize;
            c.set(i, c.get(j));
            c.set(j, if (signs >> sign) & 1 == 1 { MLDSARing::Q - 1 } else { 1 });
        }
        c
    }

    /// BitPack(w, a, b) (algorithm 17): b - w_i in bitlen(a + b) bits each,
    /// written into `out` of 32 bitlen(a + b) bytes.
    pub fn bit_pack(polynomial: &Polynomial<MLDSARing>, a: u32, b: u32, out: &mut [u8]) {
        let bits = u32::BITS - (a + b).leading_zeros();
        let mut value = [0u32];
        // bitlen(a + b) is 1 to 32 for the ranges of ML-DSA, which the packing accepts.
        if let Ok(mut packing) = LatticePacking::new(bits) {
            for coefficient in polynomial.coefficients() {
                value[0] = MLDSARing::sub(b, *coefficient);
                packing.write(&value, out);
            }
        }
        value.zeroize();
    }

    /// BitUnpack(v, a, b) (algorithm 19): w_i = b - the integer of each run
    /// of bitlen(a + b) bits of `bytes`, in \[b - 2^c + 1, b\].
    pub fn bit_unpack(bytes: &[u8], a: u32, b: u32) -> Polynomial<MLDSARing> {
        let bits = u32::BITS - (a + b).leading_zeros();
        let mut polynomial = Polynomial::zero();
        let mut value = [0u32];
        // bitlen(a + b) is 1 to 32 for the ranges of ML-DSA, which the packing accepts.
        if let Ok(mut packing) = LatticePacking::new(bits) {
            for index in 0..MLDSARing::N {
                packing.read(bytes, &mut value);
                polynomial.set(index, MLDSAFunctions::<P>::element(b as i32 - value[0] as i32));
            }
        }
        value.zeroize();
        polynomial
    }

    /// Whether the coefficients of `polynomial`, BitUnpack of an encoding,
    /// are in \[-a, b\]; the result alone may be revealed.
    pub fn in_range(polynomial: &Polynomial<MLDSARing>, a: u32, b: u32) -> bool {
        let mut outside = 0u32;
        for coefficient in polynomial.coefficients() {
            // b - w in [0, a + b] exactly when w in [-a, b].
            outside |= (a + b).wrapping_sub(MLDSARing::sub(b, *coefficient)) >> 31;
        }
        outside == 0
    }

    /// SimpleBitPack(w, b) (algorithm 16) of a vector, `bits` = bitlen b
    /// bits each, into `out`.
    pub fn simple_bit_pack<V: PolynomialVector<MLDSARing>>(vector: &V, bits: u32, out: &mut [u8]) {
        for (polynomial, chunk) in vector.as_ref().iter().zip(out.chunks_exact_mut(32 * bits as usize)) {
            // Each chunk has the bytes of 256 integers of `bits` bits.
            let _ = polynomial.write_bits(bits, chunk);
        }
    }

    /// HintBitPack (algorithm 20) of a hint with at most ω ones into `out` of ω + k bytes.
    pub fn hint_bit_pack(hint: &P::VectorK, out: &mut [u8]) {
        out.fill(0);
        let mut index = 0;
        for (i, polynomial) in hint.as_ref().iter().enumerate() {
            for (j, coefficient) in polynomial.coefficients().iter().enumerate() {
                if *coefficient != 0 {
                    out[index] = j as u8;
                    index += 1;
                }
            }
            out[P::OMEGA + i] = index as u8;
        }
    }

    /// HintBitUnpack (algorithm 21) of ω + k bytes; `None` for a malformed
    /// encoding (indices out of order, counts decreasing or above ω, or
    /// nonzero padding).
    pub fn hint_bit_unpack(bytes: &[u8]) -> Option<P::VectorK> {
        let mut hint = P::VectorK::default();
        let mut index = 0;
        for (i, polynomial) in hint.as_mut().iter_mut().enumerate() {
            let end = bytes[P::OMEGA + i] as usize;
            if end < index || end > P::OMEGA {
                return None;
            }
            let first = index;
            while index < end {
                if index > first && bytes[index - 1] >= bytes[index] {
                    return None;
                }
                polynomial.set(bytes[index] as usize, 1);
                index += 1;
            }
        }
        if bytes[index..P::OMEGA].iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(hint)
    }
}
