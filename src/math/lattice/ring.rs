use super::{CoefficientArray, LatticeCoefficient};

/// The ring R_q = Z_q\[X\]/(X^n + 1) of a module lattice, with the
/// number-theoretic transform (NTT) that maps it to T_q, the product of
/// 2^LAYERS rings Z_q\[X\]/(X^d - γ_i) of degree d = n / 2^LAYERS: d = 2 for
/// ML-KEM (FIPS 203 section 4.3), d = 1 for ML-DSA (FIPS 204 section 7.5).
///
/// A ring is a type of no value; its constants define it, and its functions
/// compute in Z_q in constant time: every value is reduced into \[0, q) by
/// a Barrett reduction and conditional subtractions without branches.
pub trait LatticeRing: Sized + 'static {
    /// The type of the coefficients, large enough for q - 1.
    type Coefficient: LatticeCoefficient;
    /// `[Self::Coefficient; N]`.
    type Coefficients: CoefficientArray<Self::Coefficient>;
    /// The prime q, below 2^31.
    const Q: u32;
    /// The degree n, a power of two.
    const N: usize;
    /// ζ, a primitive 2^(LAYERS + 1)-th root of unity modulo q.
    const ROOT: u32;
    /// The number of layers of the NTT.
    const LAYERS: u32;
    /// ζ^BitRev(i) mod q for i < 2^LAYERS, the bits reversed over LAYERS
    /// bits ([`LatticeTables::zetas`]).
    const ZETAS: &'static [u32];
    /// γ_i = ζ^(2 BitRev(i) + 1) mod q for i < 2^LAYERS, the moduli of the
    /// factors of T_q ([`LatticeTables::gammas`]).
    const GAMMAS: &'static [u32];

    /// floor(2^64 / q), the constant of the Barrett reduction.
    const BARRETT: u64 = LatticeTables::barrett(Self::Q);
    /// (2^LAYERS)^-1 mod q, the factor of the inverse NTT.
    const INVERSE_SCALE: u32 = LatticeTables::inverse(1 << Self::LAYERS, Self::Q);
    /// The degree d of the factors of T_q.
    const FACTOR_DEGREE: usize = Self::N >> Self::LAYERS;

    /// `value` mod q, for any `value`.
    fn reduce(value: u64) -> u32 {
        let quotient = ((value as u128 * Self::BARRETT as u128) >> 64) as u64;
        // The quotient is floor(value / q) or one less: the remainder is below 2q.
        let remainder = (value - quotient * Self::Q as u64) as u32;
        Self::reduce_once(remainder)
    }

    /// `value` - q if `value` ≥ q, for `value` below 2q.
    fn reduce_once(value: u32) -> u32 {
        let difference = value.wrapping_sub(Self::Q);
        // The top bit of the difference is set exactly when value < q (q < 2^31).
        let mask = 0u32.wrapping_sub(difference >> 31);
        difference.wrapping_add(Self::Q & mask)
    }

    /// a + b mod q, for a and b below q.
    fn add(a: u32, b: u32) -> u32 {
        Self::reduce_once(a + b)
    }

    /// a - b mod q, for a and b below q.
    fn sub(a: u32, b: u32) -> u32 {
        Self::reduce_once(a + Self::Q - b)
    }

    /// a b mod q, for a and b below q.
    fn mul(a: u32, b: u32) -> u32 {
        Self::reduce(a as u64 * b as u64)
    }

    /// -a mod q, for a below q.
    fn neg(a: u32) -> u32 {
        Self::sub(0, a)
    }

    /// floor(value / q), in constant time, for `value` below 2^63.
    fn quotient(value: u64) -> u64 {
        let estimate = ((value as u128 * Self::BARRETT as u128) >> 64) as u64;
        // The estimate is the quotient or one less: add one if q fits again.
        let remainder = value - estimate * Self::Q as u64;
        estimate + ((remainder.wrapping_sub(Self::Q as u64) >> 63) ^ 1)
    }

    /// Compress_d(x) = round(2^d x / q) mod 2^d for x below q and d < log2 q
    /// (FIPS 203 equation 4.7), in constant time: the remainder of 2^d x is
    /// rounded up from (q + 1) / 2, as q is odd.
    fn compress(value: u32, bits: u32) -> u32 {
        let rounded = Self::quotient(((value as u64) << bits) + (Self::Q as u64 - 1) / 2);
        (rounded as u32) & ((1 << bits) - 1)
    }

    /// Decompress_d(y) = round(q y / 2^d) for y below 2^d (FIPS 203 equation
    /// 4.8), ties rounded up.
    fn decompress(value: u32, bits: u32) -> u32 {
        ((value as u64 * Self::Q as u64 + (1 << (bits - 1))) >> bits) as u32
    }
}

/// The constants of a [`LatticeRing`], computed at compile time from q, ζ
/// and the number of layers.
pub struct LatticeTables;

impl LatticeTables {
    /// floor(2^64 / q).
    pub const fn barrett(q: u32) -> u64 {
        (u64::MAX / q as u64) + ((u64::MAX % q as u64 + 1) / q as u64)
    }

    /// base^exponent mod q.
    pub const fn pow(base: u32, mut exponent: u64, q: u32) -> u32 {
        let (mut result, mut square) = (1u64, base as u64 % q as u64);
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = result * square % q as u64;
            }
            square = square * square % q as u64;
            exponent >>= 1;
        }
        result as u32
    }

    /// value^-1 mod q for the prime q (Fermat).
    pub const fn inverse(value: u32, q: u32) -> u32 {
        LatticeTables::pow(value, q as u64 - 2, q)
    }

    /// `value` with its lowest `bits` bits reversed.
    pub const fn bit_reverse(value: usize, bits: u32) -> usize {
        let (mut result, mut index) = (0usize, 0u32);
        while index < bits {
            result |= ((value >> index) & 1) << (bits - 1 - index);
            index += 1;
        }
        result
    }

    /// ζ^BitRev(i) mod q for i < COUNT = 2^layers.
    pub const fn zetas<const COUNT: usize>(q: u32, root: u32, layers: u32) -> [u32; COUNT] {
        let mut table = [0u32; COUNT];
        let mut index = 0;
        while index < COUNT {
            table[index] = LatticeTables::pow(root, LatticeTables::bit_reverse(index, layers) as u64, q);
            index += 1;
        }
        table
    }

    /// ζ^(2 BitRev(i) + 1) mod q for i < COUNT = 2^layers.
    pub const fn gammas<const COUNT: usize>(q: u32, root: u32, layers: u32) -> [u32; COUNT] {
        let mut table = [0u32; COUNT];
        let mut index = 0;
        while index < COUNT {
            let exponent = 2 * LatticeTables::bit_reverse(index, layers) as u64 + 1;
            table[index] = LatticeTables::pow(root, exponent, q);
            index += 1;
        }
        table
    }
}
