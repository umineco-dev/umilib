# `umilib::math::bigint`

Unsigned big integers of fixed precision, in constant time. Feature:
`math-bigint` (uses `secret`).

```rust
use umilib::math::bigint::{BoxedUint, U256};

// Fixed precision, on the stack: for elliptic curve fields.
const P: U256 = U256::from_hex_vartime_or_panic("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
let x = U256::from_be_bytes(&bytes)?;
let (sum, carry) = x.overflowing_add(&P);
let (low, high) = x.widening_mul(&x);
let remainder = U256::rem_wide(&low, &high, &P)?;

// Precision chosen at run time, on the heap: for RSA and Diffie-Hellman.
let n = BoxedUint::from_be_bytes(&modulus_bytes, 2048)?;
let (quotient, remainder) = n.div_rem(&BoxedUint::from_u64(65537, 64)?)?;
```

## Types

- `Uint<N>` holds `N` limbs. A limb is the native word (64 bits on 64-bit
  targets, 32 bits elsewhere), so name precisions in bits: `U64`, `U128`,
  `U192`, `U256`, `U320`, `U384`, `U448`, `U512`, `U576` (P-521), `U640`,
  `U768`, `U896`, `U1024`, `U1536`, `U2048`, `U3072`, `U4096`, `U6144`,
  `U8192`, or `Uint<{ Limbs::count(bits) }>`. Every alias has the same
  precision on every platform.
- `BoxedUint` has a precision chosen when it is created, rounded up to a
  multiple of 64 bits (at least 64) so that it is the same on every platform,
  and at most `BoxedUint::MAXIMUM_PRECISION` (2^30) bits. Constructors that
  take a precision fail with `InvalidPrecision` above it and with
  `AllocationFailed` when memory runs out. Operands of different precisions
  are zero-extended to the larger one, which is the precision of the result;
  `div_rem` returns the quotient in the precision of the dividend and the
  remainder in that of the divisor. Its limbs are zeroed when it is dropped.
- `Limbs` holds the algorithms, written once on slices of limbs, which both
  types use. It can be used directly for other representations.
- `UnsignedInteger` is the interface of `Uint<N>` for code generic over the
  precision (the fields of elliptic curves): the same operations with the
  same timing, and `from_byte_source`, an integer of every bit of the
  precision from any source of bytes (a random integer from a `Random`).
- `BoxedUint` adds `mul_wide` (the full product, in the sum of the
  precisions), `gcd_vartime` (the binary GCD) and `rem_limb_vartime` (the
  remainder by one limb, to sieve candidate primes); their time depends on
  the values.

## Behavior

- **Constant time.** Unless a method name ends in `_vartime`, the time and
  the memory accesses depend only on the precision and on public arguments
  (shift amounts, bit indices), never on the values. Comparisons return a
  `Choice` (`ct_lt`, `ct_gt`, `ct_eq`, `is_zero`, `is_odd`, `bit`);
  `compare_vartime` returns an `Ordering`. `==` compares in constant time and
  reveals only the result. Division is restoring shift-and-subtract division,
  one step per bit of the dividend; it reveals only whether the divisor is
  zero (`DivisionByZero`). `bit_length` avoids `leading_zeros`, which may
  branch on targets without such an instruction. Division sets the
  data-independent timing mode of the processor itself (see
  [secret.md](secret.md)); hold a `DataIndependentTiming` guard around
  computations made of the short operations.
- **Formatting reveals values.** `Debug` and `{:x}` print the value, as they
  do for the integer types of Rust; keep secret values in `Secret` or in types
  that do not print them.
- **No hidden overflow.** There are no `+`, `-` or `*` operators: arithmetic
  is `wrapping_*`, `overflowing_*` (with the carry as a `Choice`) or
  `widening_mul` (the full product as low and high halves). The bitwise
  operators `&`, `|`, `^` and `!` are implemented (on references for
  `BoxedUint`). Shifting by the precision or more gives zero.
- **Bytes.** `from_be_bytes` and `from_le_bytes` accept leading (big-endian)
  or trailing (little-endian) zero bytes beyond the precision and fail with
  `Overflow` for any other byte beyond it. `to_be_bytes`/`to_le_bytes` write
  every byte of the precision; `write_be_bytes`/`write_le_bytes` fill a given
  slice, padding with zeros, and fail (zeroing it) if the value does not fit.
- **Hexadecimal** (`from_hex_vartime`, `{:x}`, `{:X}`) is for public values
  such as constants: parsing takes time that depends on the digits. The text
  is one digit or more with no prefix or separators. `from_hex_vartime_or_panic` is a
  `const fn` for constants, which then fail at compile time. Formatting writes
  every digit of the precision.

## Errors

`MathError`: `Overflow`, `SizeMismatch`, `DivisionByZero`, `NotInvertible`,
`InvalidModulus`, `InvalidDigit { position }`, `InvalidPrecision { precision,
maximum }` and `AllocationFailed`. `NotInvertible` and `InvalidModulus` come
from [`math-modular`](math-modular.md), which shares this error type;
`SizeMismatch` comes from the `BoxedUint` methods that need equal precisions
(`conditional_assign`, `conditional_swap`) and from `BoxedModulus`.

## C and Python

Only `BoxedUint` is exported (`umilib_math_bigint_boxed_uint_*`,
`umilib.math.bigint.BoxedUint`): `Uint<N>` has its precision in a const
generic parameter, which C cannot name, and `Limbs` works on native words.
A `BoxedUint` of the same precision computes the same results. Choices are
`uint8_t` 0 or 1 in C and `umilib.secret.Choice` in Python. Python adds
`BoxedUint.from_int(value, precision)` and `int(value)` to convert from and to
Python integers; they are not constant-time.
