# `umilib::math::pairing`

Pairings on curves of embedding degree 12. Feature: `math-pairing` (uses
`math-ec`).

```rust
use umilib::math::ec::{AffinePoint, ProjectivePoint};
use umilib::math::pairing::{BLS12381, BLS12381G1, G2Affine, G2Projective, Pairing};

let p = ProjectivePoint::<BLS12381G1>::generator().mul(&a).to_affine();
let q = G2Projective::<BLS12381>::generator().mul(&b).to_affine();
let value = Pairing::<BLS12381>::pairing(&p, &q)?;      // in G_T
let base = Pairing::<BLS12381>::pairing(&AffinePoint::generator(), &G2Affine::generator())?;
assert_eq!(value, base.pow(&a.mul(&b)));                 // bilinear
```

## Curves

| Type | Family | Parameter | Twist | Source |
| --- | --- | --- | --- | --- |
| `BLS12381` | BLS12 | t = -2^63 - 2^62 - 2^60 - 2^57 - 2^48 - 2^16 | M-type, ξ = u + 1 | draft-irtf-cfrg-pairing-friendly-curves section 4.2.1 |
| `BN462` | BN | t = 2^114 + 2^101 - 2^14 - 1 | D-type, ξ = u + 2 | the same draft, section 4.2.2 |
| `BN254` | BN | t = 4965661367192848881 | D-type, ξ = u + 9 | alt_bn128 of Ethereum (EIP-196, EIP-197); about 100 bits of security |
| `SM9BN256` | BN | t = 0x600000000058F98A | M-type, ξ = u, with u² = -2 | GM/T 0044.5-2016 section 3.1 (SM9); its R-ate pairing is this optimal ate pairing |

Each curve `C` defines the fields `CField` (GF(p)) and `CScalar` (the
integers modulo r) and the curve `CG1`, a `WeierstrassCurve` with a = 0
whose generator spans G_1 (BLS12-381's `COFACTOR` is h, the others' 1).

## Types

- `PairingCurve`: the family (`PairingFamily::BN` or `BLS12`), the twist
  (`TwistType::D` or `M`), the parameter t, ξ, the coefficient b' of the
  twist E' and the generator of G_2.
- `Fp2`, `Fp6`, `Fp12`: the tower GF(p^2) = GF(p)[u]/(u² - β), GF(p^6) =
  GF(p^2)[v]/(v³ - ξ), GF(p^12) = GF(p^6)[w]/(w² - v), in constant time;
  the non-square β is that of the field's `PairingField` (-1 for the curves
  with p ≡ 3 mod 4, -2 for SM9, whose p ≡ 1 mod 4 makes -1 a square). The
  tower of SM9 (GF(p^4) = GF(p^2)[v]/(v² - u), GF(p^12) = GF(p^4)[w]/(w³ -
  v)) has the same w (w⁶ = u), so its elements are those of this tower with
  their coefficients in another order (`SM9Encoding::gt` of `crypto::sm9`).
  `Fp12::coefficients` lists the twelve coefficients over GF(p) in the order
  of the basis 1, u, v, uv, v², uv², w, uw, vw, uvw, v²w, uv²w, which is the
  order of the draft's test vectors.
- `G2Affine`, `G2Projective`: points of E'(GF(p^2)), with the complete
  formulas for a = 0, constant-time `mul` and the encoding x0 || x1 || y0 ||
  y1 (each coordinate big-endian of the bytes of p).
- `Pairing<C>`: `pairing(&P, &Q)`, and its parts `miller_loop` and
  `final_exponentiation`, as appendix A of the draft defines them.
- `GT<C>`: the values of the pairing: `mul`, `invert` (the conjugate),
  `pow` (constant time), `is_one` and the encoding of the twelve coefficients.

## Behavior

- The Miller loop computes the lines in affine coordinates. Its inversions
  are those of the fields, constant time like the rest of their arithmetic,
  and its branches depend only on the loop parameter and on cases that
  points of the subgroups never reach (the identity, a vertical line): a
  pairing of points of G_1 and G_2 takes time that does not depend on them,
  so either may be secret (the encryption key de of SM9 is). Arithmetic in
  G_2 (`mul`) and in G_T (`pow`) is constant time.
- The pairing of the identity with anything is 1.
- `G2Affine::is_in_subgroup` multiplies by r; points from outside must be
  checked before they are paired.

## C and Python

The C ABI exports the pairing on encoded points (`umilib_math_pairing_pairing_pairing`),
the curve chosen by the C type name of its type (`umilib_math_pairing_BLS12381`,
`umilib_math_pairing_BN254`, `umilib_math_pairing_BN462`): a point of G_1 in
SEC 1, a point of G_2 as `G2Affine::write_encoded` gives it and the result as
`GT::write_bytes` gives it. Points that are not on the curve or not in their
subgroups of order r are refused (`InvalidArgument`). In Python:

```python
from umilib.math.pairing import BLS12381, Pairing

value = Pairing[BLS12381].pairing(p, q)
```
