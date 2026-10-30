use core::fmt;

use super::{CoefficientArray, LatticeCoefficient, LatticeError, LatticePacking, LatticeRing};
use crate::secret::{Choice, ConstantTimeEq, Zeroize};

/// An element of the ring `R` (R_q or, after [`Polynomial::ntt`], T_q): its
/// n coefficients, each in \[0, q). Arithmetic and the transforms are
/// constant time; it prints without its coefficients, which may be secret.
pub struct Polynomial<R: LatticeRing> {
    coefficients: R::Coefficients,
}

impl<R: LatticeRing> Polynomial<R> {
    pub fn zero() -> Polynomial<R> {
        Polynomial { coefficients: R::Coefficients::zero() }
    }

    /// The polynomial of the coefficients `values` (n of them), each reduced modulo q.
    pub fn from_values(values: &[u32]) -> Result<Polynomial<R>, LatticeError> {
        if values.len() != R::N {
            return Err(LatticeError::InvalidLength { length: values.len(), expected: R::N });
        }
        let mut polynomial = Polynomial::<R>::zero();
        for (coefficient, value) in polynomial.coefficients.as_mut_slice().iter_mut().zip(values) {
            *coefficient = R::Coefficient::from_u32(R::reduce(*value as u64));
        }
        Ok(polynomial)
    }

    pub fn coefficients(&self) -> &[R::Coefficient] {
        self.coefficients.as_slice()
    }

    /// The coefficient of X^index (or the entry `index` of an element of T_q).
    pub fn get(&self, index: usize) -> u32 {
        self.coefficients.as_slice()[index].to_u32()
    }

    /// Sets the coefficient of X^index to `value` mod q.
    pub fn set(&mut self, index: usize, value: u32) {
        self.coefficients.as_mut_slice()[index] = R::Coefficient::from_u32(R::reduce(value as u64));
    }

    /// The polynomial whose coefficients are `function` of those of `self`
    /// (and their index), reduced modulo q.
    pub fn map(&self, mut function: impl FnMut(usize, u32) -> u32) -> Polynomial<R> {
        let mut out = Polynomial::<R>::zero();
        for (index, (target, source)) in
            out.coefficients.as_mut_slice().iter_mut().zip(self.coefficients.as_slice()).enumerate()
        {
            *target = R::Coefficient::from_u32(R::reduce(function(index, source.to_u32()) as u64));
        }
        out
    }

    /// The polynomial of `function` of the coefficients of `self` and `other`
    /// at each index, which must give values below q.
    pub fn combine(&self, other: &Polynomial<R>, function: impl Fn(u32, u32) -> u32) -> Polynomial<R> {
        let mut out = Polynomial::<R>::zero();
        let pairs = self.coefficients.as_slice().iter().zip(other.coefficients.as_slice());
        for (target, (a, b)) in out.coefficients.as_mut_slice().iter_mut().zip(pairs) {
            *target = R::Coefficient::from_u32(function(a.to_u32(), b.to_u32()));
        }
        out
    }

    pub fn add(&self, other: &Polynomial<R>) -> Polynomial<R> {
        self.combine(other, R::add)
    }

    pub fn sub(&self, other: &Polynomial<R>) -> Polynomial<R> {
        self.combine(other, R::sub)
    }

    pub fn neg(&self) -> Polynomial<R> {
        Polynomial::zero().sub(self)
    }

    /// Every coefficient multiplied by `scalar` (below q).
    pub fn scale(&self, scalar: u32) -> Polynomial<R> {
        self.map(|_, value| R::mul(value, scalar))
    }

    /// Every coefficient compressed to `bits` bits ([`LatticeRing::compress`]).
    pub fn compress(&self, bits: u32) -> Polynomial<R> {
        self.map(|_, value| R::compress(value, bits))
    }

    /// Every coefficient, of `bits` bits, decompressed ([`LatticeRing::decompress`]).
    pub fn decompress(&self, bits: u32) -> Polynomial<R> {
        self.map(|_, value| R::decompress(value, bits))
    }

    /// The NTT of `self` (FIPS 203 algorithm 9, FIPS 204 algorithm 41): the
    /// residues modulo X^d - γ_i in the order of the bit-reversed i.
    pub fn ntt(&self) -> Polynomial<R> {
        let mut out = *self;
        let values = out.coefficients.as_mut_slice();
        let (mut index, mut length) = (1, R::N / 2);
        while length >= R::FACTOR_DEGREE {
            for start in (0..R::N).step_by(2 * length) {
                let zeta = R::ZETAS[index];
                index += 1;
                for position in start..start + length {
                    let (low, high) = (values[position].to_u32(), values[position + length].to_u32());
                    let product = R::mul(zeta, high);
                    values[position + length] = R::Coefficient::from_u32(R::sub(low, product));
                    values[position] = R::Coefficient::from_u32(R::add(low, product));
                }
            }
            length /= 2;
        }
        out
    }

    /// The inverse NTT of `self` (FIPS 203 algorithm 10, FIPS 204 algorithm 42).
    pub fn inverse_ntt(&self) -> Polynomial<R> {
        let mut out = *self;
        let values = out.coefficients.as_mut_slice();
        let (mut index, mut length) = ((1usize << R::LAYERS) - 1, R::FACTOR_DEGREE);
        while length <= R::N / 2 {
            for start in (0..R::N).step_by(2 * length) {
                let zeta = R::ZETAS[index];
                index -= 1;
                for position in start..start + length {
                    let (low, high) = (values[position].to_u32(), values[position + length].to_u32());
                    values[position] = R::Coefficient::from_u32(R::add(low, high));
                    values[position + length] = R::Coefficient::from_u32(R::mul(zeta, R::sub(high, low)));
                }
            }
            length *= 2;
        }
        for value in values.iter_mut() {
            *value = R::Coefficient::from_u32(R::mul(value.to_u32(), R::INVERSE_SCALE));
        }
        out
    }

    /// The product in T_q of `self` and `other`, both NTT representations
    /// (FIPS 203 algorithms 11 and 12; the product of the entries for d =
    /// 1): in each factor, the product of the residues modulo X^d - γ_i.
    pub fn multiply_ntt(&self, other: &Polynomial<R>) -> Polynomial<R> {
        let degree = R::FACTOR_DEGREE;
        let (f, g) = (self.coefficients.as_slice(), other.coefficients.as_slice());
        let mut out = Polynomial::<R>::zero();
        let h = out.coefficients.as_mut_slice();
        for (factor, gamma) in R::GAMMAS.iter().enumerate() {
            let base = factor * degree;
            for a in 0..degree {
                for b in 0..degree {
                    let mut product = R::mul(f[base + a].to_u32(), g[base + b].to_u32());
                    let mut target = a + b;
                    if target >= degree {
                        // X^d = γ in this factor; the branch depends on the indices alone.
                        target -= degree;
                        product = R::mul(product, *gamma);
                    }
                    let sum = R::add(h[base + target].to_u32(), product);
                    h[base + target] = R::Coefficient::from_u32(sum);
                }
            }
        }
        out
    }

    /// Writes the low `bits` bits of every coefficient into `out` of n ×
    /// `bits` / 8 bytes, least significant bits first (ByteEncode
    /// of FIPS 203 algorithm 5, SimpleBitPack of FIPS 204 algorithm 16).
    pub fn write_bits(&self, bits: u32, out: &mut [u8]) -> Result<(), LatticeError> {
        let mut packing = LatticePacking::new(bits)?;
        let expected = LatticePacking::length(bits, R::N);
        if out.len() != expected {
            return Err(LatticeError::InvalidLength { length: out.len(), expected });
        }
        let mut values = [0u32; 1];
        for coefficient in self.coefficients.as_slice() {
            values[0] = coefficient.to_u32();
            packing.write(&values, out);
        }
        values.zeroize();
        Ok(())
    }

    /// The polynomial of `bytes` of n × `bits` / 8 bytes, each
    /// coefficient reduced modulo q, and whether no coefficient was q or
    /// more (the encoding is then the one [`Polynomial::write_bits`]
    /// writes); constant time (ByteDecode of FIPS 203 algorithm 6).
    pub fn read_bits(bits: u32, bytes: &[u8]) -> Result<(Polynomial<R>, Choice), LatticeError> {
        let mut packing = LatticePacking::new(bits)?;
        let expected = LatticePacking::length(bits, R::N);
        if bytes.len() != expected {
            return Err(LatticeError::InvalidLength { length: bytes.len(), expected });
        }
        let mut polynomial = Polynomial::<R>::zero();
        let mut canonical = Choice::TRUE;
        let mut value = [0u32; 1];
        for coefficient in polynomial.coefficients.as_mut_slice() {
            packing.read(bytes, &mut value);
            // value < q exactly when value - q borrows.
            canonical &= Choice::from_bit((value[0] as u64).wrapping_sub(R::Q as u64).wrapping_shr(63) as u8);
            *coefficient = R::Coefficient::from_u32(R::reduce(value[0] as u64));
        }
        value.zeroize();
        Ok((polynomial, canonical))
    }
}

impl<R: LatticeRing> Clone for Polynomial<R> {
    fn clone(&self) -> Polynomial<R> {
        *self
    }
}

impl<R: LatticeRing> Copy for Polynomial<R> {}

impl<R: LatticeRing> Default for Polynomial<R> {
    fn default() -> Polynomial<R> {
        Polynomial::zero()
    }
}

impl<R: LatticeRing> ConstantTimeEq for Polynomial<R> {
    fn ct_eq(&self, other: &Polynomial<R>) -> Choice {
        self.coefficients.as_slice().ct_eq(other.coefficients.as_slice())
    }
}

impl<R: LatticeRing> PartialEq for Polynomial<R> {
    fn eq(&self, other: &Polynomial<R>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<R: LatticeRing> Eq for Polynomial<R> {}

impl<R: LatticeRing> Zeroize for Polynomial<R> {
    fn zeroize(&mut self) {
        self.coefficients.as_mut_slice().zeroize();
    }
}

impl<R: LatticeRing> fmt::Debug for Polynomial<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Polynomial(..)")
    }
}
