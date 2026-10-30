use super::{LatticeRing, Polynomial};
use crate::secret::Zeroize;

/// A vector of polynomials of the ring `R`: `[Polynomial<R>; K]`, of the
/// length a parameter set fixes, with its arithmetic element by element.
pub trait PolynomialVector<R: LatticeRing>:
    AsRef<[Polynomial<R>]> + AsMut<[Polynomial<R>]> + Copy + Default + Zeroize
{
    /// The NTT of every element.
    fn ntt(&self) -> Self {
        let mut out = *self;
        out.as_mut().iter_mut().for_each(|element| *element = element.ntt());
        out
    }

    /// The inverse NTT of every element.
    fn inverse_ntt(&self) -> Self {
        let mut out = *self;
        out.as_mut().iter_mut().for_each(|element| *element = element.inverse_ntt());
        out
    }

    fn add(&self, other: &Self) -> Self {
        let mut out = *self;
        out.as_mut().iter_mut().zip(other.as_ref()).for_each(|(element, other)| *element = element.add(other));
        out
    }

    fn sub(&self, other: &Self) -> Self {
        let mut out = *self;
        out.as_mut().iter_mut().zip(other.as_ref()).for_each(|(element, other)| *element = element.sub(other));
        out
    }

    /// The inner product of two vectors of NTT representations: Σ self\[i\] × other\[i\] in T_q.
    fn dot_ntt(&self, other: &Self) -> Polynomial<R> {
        let mut sum = Polynomial::zero();
        for (a, b) in self.as_ref().iter().zip(other.as_ref()) {
            sum = sum.add(&a.multiply_ntt(b));
        }
        sum
    }
}

impl<R: LatticeRing, const K: usize> PolynomialVector<R> for [Polynomial<R>; K] where [Polynomial<R>; K]: Default {}

/// A matrix of polynomials of the ring `R`, by rows: `[V; K]` for rows `V`.
pub trait PolynomialMatrix<R: LatticeRing>: AsRef<[Self::Row]> + AsMut<[Self::Row]> + Copy + Default {
    type Row: PolynomialVector<R>;

    /// The product of the matrix and the vector `vector` of NTT
    /// representations, in T_q: an element per row (`O` has as many).
    fn multiply_ntt<O: PolynomialVector<R>>(&self, vector: &Self::Row) -> O {
        let mut out = O::default();
        for (element, row) in out.as_mut().iter_mut().zip(self.as_ref()) {
            *element = row.dot_ntt(vector);
        }
        out
    }

    /// The product of the transposed matrix and `vector` (an element per
    /// row of the matrix), in T_q: an element per column.
    fn multiply_transposed_ntt<V: PolynomialVector<R>>(&self, vector: &V) -> Self::Row {
        let mut out = Self::Row::default();
        for (row, factor) in self.as_ref().iter().zip(vector.as_ref()) {
            for (element, entry) in out.as_mut().iter_mut().zip(row.as_ref()) {
                *element = element.add(&entry.multiply_ntt(factor));
            }
        }
        out
    }
}

impl<R: LatticeRing, V: PolynomialVector<R>, const K: usize> PolynomialMatrix<R> for [V; K]
where
    [V; K]: Default,
{
    type Row = V;
}
