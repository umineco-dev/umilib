# `umilib::math::lattice`

Polynomial rings of module lattices, R_q = Z_q[X]/(X^n + 1), with their
number-theoretic transform (NTT): the arithmetic of ML-KEM (FIPS 203) and
ML-DSA (FIPS 204). Feature: `math-lattice`.

```rust
use umilib::math::lattice::{MLKEMRing, Polynomial};

let f = Polynomial::<MLKEMRing>::from_values(&coefficients)?;   // 256 values, reduced modulo q
let g = Polynomial::<MLKEMRing>::from_values(&others)?;
let product = f.ntt().multiply_ntt(&g.ntt()).inverse_ntt();     // f g in R_q
```

## Rings

| Type | q | n | ζ | NTT layers | Factors of T_q | Coefficient |
| --- | --- | --- | --- | --- | --- | --- |
| `MLKEMRing` | 3329 | 256 | 17 | 7 | 128 of degree 1 (X^2 - γ_i) | `u16` |
| `MLDSARing` | 8380417 | 256 | 1753 | 8 | 256 of degree 0 | `u32` |

`LatticeRing` describes a ring by its constants: q, n, the root ζ, the
number of layers and the coefficient type. `LatticeTables` computes from
them, at compile time, the tables ζ^BitRev(i) (`ZETAS`) and
ζ^(2 BitRev(i) + 1) (`GAMMAS`), the Barrett constant and (2^layers)^-1;
a new ring is a type with those constants.

## Types

- `Polynomial<R>`: `from_values`, `get`, `set`, `map`, `add`, `sub`, `neg`,
  `scale`, `ntt`, `inverse_ntt`, `multiply_ntt` (the product in T_q),
  `compress` and `decompress` (FIPS 203 equations 4.7 and 4.8),
  `write_bits` and `read_bits` (ByteEncode and ByteDecode: `read_bits`
  reduces the values modulo q and returns whether they were all below q).
- `PolynomialVector<R>` and `PolynomialMatrix<R>`: the arrays
  `[Polynomial<R>; K]` and `[V; K]` with their arithmetic (`ntt`,
  `dot_ntt`, `multiply_ntt`, `multiply_transposed_ntt`).
- `LatticePacking`: integers of 1 to 32 bits written into bytes and read
  back, least significant bits first, as FIPS 203 and 204 order them.

## Behavior

- Arithmetic is constant time: values are reduced by a Barrett reduction
  and conditional subtractions without branches, and the transforms follow
  fixed loops. The bytes `LatticePacking` touches depend on the position
  alone.
- Every coefficient is kept in [0, q); signed values v are kept as v mod q.

## C and Python

The C ABI computes the transforms on arrays of the n coefficients as
`uint32_t`, the ring named by the C type name of its type:
`umilib_math_lattice_polynomial_ntt`, `_inverse_ntt` and `_multiply_ntt`
with `umilib_math_lattice_MLKEMRing` or `umilib_math_lattice_MLDSARing`.
In Python, `Polynomial[MLKEMRing]([...])` has the same methods.
