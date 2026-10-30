# `umilib::math::modular`

Arithmetic modulo an odd number, in constant time, by Montgomery
multiplication. Feature: `math-modular` (uses `math-bigint`).

```rust
use umilib::math::bigint::U256;
use umilib::math::modular::Modulus;

let p = U256::from_hex_vartime_or_panic("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
let field = Modulus::new(p)?;
let a = field.residue(&U256::from_u64(121665)?);
let b = field.residue(&U256::from_u64(121666)?);
let d = field.mul(&field.neg(&a), &field.invert(&b)?); // -121665/121666 (RFC 8032)
let value: U256 = field.retrieve(&d);
let power = field.pow(&a, &p.wrapping_sub(&U256::ONE));  // a^(p-1) = 1
```

## Types

- `Modulus<N>` (for `Uint<N>`) and `BoxedModulus` (for `BoxedUint`) hold an
  odd modulus of at least 3 with its Montgomery constants and perform every
  operation: `residue`, `retrieve`, `zero`, `one`, `add`, `sub`, `neg`, `mul`,
  `square`, `pow`, `pow_vartime`, `invert`, `from_montgomery`.
- `Residue<N>` and `BoxedResidue` are values modulo a modulus in the
  Montgomery form `x * R mod m`, where `R = 2^precision`. A residue does not
  remember its modulus: pass it only to the modulus that made it. With
  another modulus of the same precision the results are meaningless (never
  undefined behavior); `BoxedModulus` methods fail with `SizeMismatch` for a
  residue of another precision.
- `ModularLimbs` holds the algorithms on slices of limbs.
- `ModularArithmetic` is the interface of `Modulus<N>` for code generic over
  the precision (`math::ec`), with associated `Value` and `Residue` types.
- `Modulus::new_vartime` (and `new_vartime_or_panic`) and
  `residue_vartime` are `const fn`s for constants: a curve's prime and
  coefficients are computed at compile time.
- `BoxedModulus::miller_rabin(base)` is one round of the Miller–Rabin test
  of FIPS 186-5 appendix B.3.1, constant time except in the number of
  trailing zero bits of modulus - 1.

## Behavior

- **Constant time.** `Modulus::new` takes time that depends only on the
  precision, so the modulus itself may be secret (an RSA prime). It reveals
  only whether the modulus is valid (`InvalidModulus` if it is even or below
  3). `pow` uses a fixed window of 4 bits over every bit of the exponent's
  precision and reads every table entry at each step; `pow_vartime` uses
  square-and-multiply and is for public exponents such as an RSA public
  exponent. `invert` is a binary extended GCD with a fixed number of
  iterations (twice the precision in bits) and reveals only whether the value
  is invertible (`NotInvertible`, including for zero). Exponentiation and
  inversion set the data-independent timing mode of the processor themselves
  (see [secret.md](secret.md)); hold a `DataIndependentTiming` guard around
  computations made of the short operations (`add`, `mul`, ...).
- `Residue` is `ConditionallySelectable`; `BoxedResidue` has
  `conditional_assign` and `conditional_swap`, which require the same precision.
- `residue` accepts any value of the precision (a `BoxedModulus` accepts any
  precision) and reduces it.
- `from_montgomery` checks that a Montgomery form is below the modulus
  (`Overflow` otherwise); `Residue::from_montgomery_unchecked` does not.
- `pow` with the exponent zero gives one, including for the base zero.
- **Zeroization.** `BoxedModulus` and `BoxedResidue` are zeroed when dropped.
  `Modulus` and `Residue` are `Copy` and cannot zeroize themselves: call
  `zeroize()` on secret ones, or keep them in a `Secret`.

## C and Python

Only `BoxedModulus` and `BoxedResidue` are exported
(`umilib_math_modular_boxed_modulus_*`, `umilib_math_modular_boxed_residue_*`,
`umilib.math.modular`), for the reasons given in
[math-bigint.md](math-bigint.md). Errors have the domain `math.bigint`
(`umilib.math.bigint.MathError` in Python).
