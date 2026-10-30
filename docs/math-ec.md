# `umilib::math::ec`

Elliptic curves over prime fields, generic over the curve. Feature: `math-ec`
(uses `math-modular`). The curves of the specifications are defined in
[`crypto::curve`](crypto-public-key.md#curves); this module holds the
arithmetic they share.

```rust
use umilib::crypto::curve::p256::{P256, P256Scalar};
use umilib::math::ec::{AffinePoint, FieldElement, ProjectivePoint};

let k = FieldElement::<P256Scalar>::from_be_bytes(&scalar_bytes)?;
let point = ProjectivePoint::<P256>::generator().mul(&k).to_affine();
let mut encoded = [0u8; 33];
point.write_encoded(&mut encoded, true)?;          // SEC 1, compressed
assert_eq!(AffinePoint::<P256>::from_encoded(&encoded)?, point);
```

## Fields

- `PrimeField` describes a prime field: `MODULUS` (a `ModularArithmetic`
  value such as `Modulus<N>`, so the precision is the curve's choice) and
  `BYTES`, the bytes of an encoded element. A curve has two: the field of the
  coordinates and that of the scalars (the integers modulo the order of the
  generator).
- `FieldElement<F>` computes in it, in the Montgomery form: `add`, `sub`,
  `neg`, `double`, `mul`, `square`, `pow`, `pow_vartime`, `invert`, `sqrt`
  (returns the root and whether the element is a square), `is_zero`,
  `is_odd`, and the encodings `from_be_bytes`/`from_le_bytes` (exactly
  `BYTES`, below the prime) and `write_be_bytes`/`write_le_bytes`.
- `from_be_bytes_reduced`/`from_le_bytes_reduced` reduce an integer of any
  length (a hash mapped to a scalar); `random_nonzero` draws a uniform
  nonzero element by rejection sampling (FIPS 186-5 appendix A.2.2) from
  any source of bytes.
- `sqrt` uses `x^((p+1)/4)` for p ≡ 3 (mod 4), Atkin's method for
  p ≡ 5 (mod 8), and the constant-time Tonelli–Shanks method of RFC 9380
  appendix I.4 for the other primes.

## Curves and points

| Trait | Points | Formulas |
| --- | --- | --- |
| `WeierstrassCurve` (y² = x³ + ax + b) | `AffinePoint<C>`, `ProjectivePoint<C>` | The complete formulas of Renes, Costello and Batina (2016), chosen by `SHAPE`: a = -3, a = 0 or any a |
| `MontgomeryCurve` (By² = x³ + Ax² + x) | `MontgomeryPoint<C>` (u alone) | The ladder of RFC 7748 section 5 |
| `EdwardsCurve` (ax² + y² = 1 + dx²y²) | `EdwardsPoint<C>` (extended coordinates) | The unified addition add-2008-hwcd of Hisil, Wong, Carter and Dawson |

- Weierstrass points encode as SEC 1 section 2.3.3 (the identity as `00`,
  compressed `02`/`03` || x, uncompressed `04` || x || y); `from_encoded`
  checks that the coordinates are below the prime and on the curve.
  `is_in_subgroup` multiplies by the order when the cofactor is not 1.
- Edwards points encode as RFC 8032 sections 5.1.2 and 5.2.2 (y
  little-endian with the sign of x in the last bit); `from_encoded` refuses y
  not below the prime and x = 0 with the sign 1.
- Montgomery coordinates encode little-endian; `from_bytes` ignores the
  bits above the prime's length and reduces values not below it, as
  decodeUCoordinate does.
- The complete Weierstrass formulas are exact on curves of odd order and,
  on curves of even order, for the points of the subgroup of odd order:
  check the subgroup of points that come from outside.

## Scalar multiplication

| Method | Time |
| --- | --- |
| `mul(&scalar)`, `mul_value(&value)` | Constant: fixed windows of `Window::BITS` (4) bits over every bit of the precision of the scalars, each adding an entry of a table of 16 multiples read in full |
| `mul_vartime`, `mul_value_vartime` | Depends on the scalar, which must be public |
| `mul_add_vartime(a, other, b)` | a·self + b·other with one chain of doublings (Shamir's trick), for verification |
| `MontgomeryPoint::mul_value` | Constant: the ladder over `SCALAR_BITS` bits with conditional swaps |

Every point type is `Copy`, `ConstantTimeEq`, `ConditionallySelectable` and
`Zeroize`; `==` compares the points, whatever their coordinates. `Debug`
prints the coordinates: keep secret points out of formatted output.

## Errors

`ECError`: `InvalidEncoding`, `NotOnCurve`, `NotInSubgroup`, `Identity`.
