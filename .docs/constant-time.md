# Secret data

## Constant time

Code that handles secrets must not branch on them or use them as memory
indices, because timing reveals both. `umilib::secret` provides the building
blocks:

- `Choice` holds `0` or `1`; logic is done with bit operations.
- Equality of integers uses `(x | -x) >> (BITS - 1)`, which is `1` exactly when
  `x != 0`, so no comparison instruction depends on the value.
- Selection uses a mask `0 - choice` (all ones or all zeros).

Rust and LLVM make no promise that this stays branch-free: the optimizer may
recognize a mask and emit a branch. Every `Choice` passes through
`core::hint::black_box`, which hides its value from the optimizer and has been
effective in practice (it is what other Rust constant-time libraries rely on),
but it is documented as best effort. When a new primitive is added, inspect its
assembly on x86_64 and aarch64 for branches on secret data, and prefer
algorithms that are constant-time by construction (bitsliced AES rather than
table lookups, complete addition formulas for elliptic curves).

Big integers (`math-bigint`, `math-modular`) follow the same rules: loops run
over every limb of the precision, carries and borrows are computed with
double-width arithmetic instead of comparisons, and conditional subtraction
masks the subtrahend. Division is bitwise restoring division, modular
exponentiation reads every entry of its window table, and inversion is a
binary GCD with a fixed number of iterations. The precision, shift amounts and
bit indices are public. `leading_zeros` is avoided because targets without a
count-leading-zeros instruction may implement it with branches. Functions that
reveal values end in `_vartime` (hexadecimal parsing, ordering, exponentiation
by public exponents).

Lengths are treated as public: `ct_eq` on slices of different lengths returns
`false` immediately.

Processors can also take data-dependent time without any branch. Arm
processors with FEAT_DIT do so until `PSTATE.DIT` is set; on Apple silicon a
256-bit restoring division, compiled without data-dependent branches, took
from 218 to 673 µs per 200 calls depending on the operands without DIT and
757 µs for every operand with it. `secret::DataIndependentTiming` sets the
flag (with `msr DIT, #1`, only where the `dit` target feature guarantees the
instruction) and restores it on drop. Writing the flag costs about 40 ns,
three times a 256-bit Montgomery multiplication, so the guard is taken by the
long operations (`Limbs::div_rem`, `ModularLimbs::pow`, `invert_odd`) and by
the callers of short ones around whole computations. Intel's DOITM is a model
specific register that only the operating system can set. Linux on arm64
without the compile-time feature needs run-time detection, which belongs to
`platform`.

### Multiplication

Poly1305 (`u64 × u64 → u128`), GHASH and POLYVAL (carry-less products from
masked 64-bit multiplications) and IDEA multiply secret values. They assume
that the processor multiplies in constant time, which holds for current
64-bit processors. Some 32-bit cores do not: the Cortex-M3 ends `UMULL`
early for small operands, and on 32-bit targets a 64-bit product becomes a
sequence of 32-bit ones or a library call. Code for such cores needs
multiplications written for them; until then, these primitives are not
constant time there.

### Ciphers defined by tables

AES is computed by a bitsliced circuit (`AESBitslice`), with no table at all.
The other ciphers whose specifications define S-boxes or lookup tables
(ARIA, Camellia, SEED, SM4, Kuznyechik, Magma, DES, RC2, and the state of
RC4) keep them in `secret::ConstantTimeTable<WORDS, BITS>`: entries of 1 to
32 bits packed into 64-bit words, where every `get` and `set` reads (and
writes) every word and selects with masks made from `mask(a, b)`, whose
difference passes through `black_box`. A lookup in a table of 256 bytes
therefore costs 32 word operations and 8 entry selections, which is why
these ciphers run at about 3 to 11 MiB/s. Two techniques keep tables small:

- Kuznyechik's linear layer L is a 128 × 128 bit matrix computed at compile
  time from its definition, applied with masks, instead of the usual 16
  tables of 256 entries of 128 bits.
- DES and Magma use 4-bit tables (`BITS = 4`).

IDEA has no table: its multiplication modulo 2^16 + 1 selects the case of a
zero operand with a mask, and inversion is the fixed chain x^65535. Anyone
adding a cipher with tables must use `ConstantTimeTable` (or a circuit) and
check its tables against the specification in tests, since a transcription
error in a table only shows on some inputs.

### Decryption failures

An AEAD that fails to authenticate leaves no plaintext, which callers of
`decrypt_in_place` may otherwise read by mistake. The constructions that
can check the tag before decrypting (GCM, ChaCha20-Poly1305) do so; those
whose tag depends on the plaintext (CCM, SIV, GCM-SIV, Ascon-AEAD128)
decrypt, compare, and encrypt again on failure, which restores the
ciphertext; AEGIS zeroes the buffer, as its specification requires. The
comparison is always `ConstantTimeEq`, and the computed tag is zeroized.

### Public-key cryptography

- Scalar multiplications of secret scalars use fixed windows over every
  bit of the precision of the scalars and read every entry of the table
  (`math::ec::Window`); the Montgomery ladder swaps conditionally. Points
  use complete formulas, so no input takes another path. Verification uses
  `mul_add_vartime`, whose time depends on the public scalars.
- Nonces of ECDSA, DSA, SM2 and GOST R 34.10 come from HMAC_DRBG seeded with
  the key and the digest (RFC 6979 section 3.2), through
  `HMACDRBG::with_seed`, which skips the length checks of SP 800-90A that
  these seeds need not meet. The candidates rejected by the nonce loop
  reveal nothing of the kept one.
- Rejection sampling (`FieldElement::random_nonzero`, RSA primes, DH
  exponents) reveals the number of rejected candidates, not the kept value.
  RSA key generation sieves candidates with `rem_limb_vartime` and computes
  `gcd_vartime`: the time depends on the candidates, which are secret; this
  is accepted for key generation, as in common practice, and documented.
- RSA's private operation blinds its input by r^e and unblinds by r^-1 (r
  from the caller's `Random`), uses constant-time exponentiation, and checks
  its result with the public operation before returning it.
- OAEP decryption finds the separator with a scan over every byte and one
  error for every failure (`DecryptionFailed`), as RFC 8017 section 7.1.2
  note 2 requires.
- The Miller loop of `math::pairing` uses affine lines. Their inversions are
  those of the fields (`ModularLimbs::invert_odd`: a fixed number of
  iterations with conditional operations), and the loop branches only on its
  parameter and on cases that points of the subgroups never reach (the
  identity, vertical lines), so a pairing takes the same time for all points
  of G_1 and G_2: SM9 pairs its secret keys de (decryption, decapsulation and
  key exchange). The final exponentiation raises a secret value to public
  exponents with `pow_vartime`, whose time depends on the exponent alone.
  `GT::pow` and `G2Projective::mul` are constant time. The points of
  identities, Q = [H1(ID || hid)]P1 + Ppub-e in SM9, are computed with
  `mul_vartime` of the public hash.

### Post-quantum cryptography

- `math::lattice` reduces with a Barrett reduction (a 128-bit product) and
  conditional subtractions by masks; Compress divides by q with the same
  multiplication. The NTT and its inverse run fixed loops.
- ML-KEM selects K or J(z || c) by `ConditionallySelectable` after a
  constant-time comparison of the ciphertexts; the CBD sampling counts bits
  without branches. SampleNTT rejects values of a public seed.
- ML-DSA keeps signed values modulo q and computes `centered`, Power2Round,
  Decompose (division by 2γ2 through a multiplication by ceil(2^48 / 2γ2),
  exact below 2^24) and MakeHint with masks. The rejection of the signing
  loop and of RejBoundedPoly reveals the number of iterations, which FIPS
  204 allows (appendix C); the norm checks scan every coefficient.
- SLH-DSA hashes; the indices into its trees come from the public digest.

## Zeroization

`Zeroize` writes zeros with `core::ptr::write_volatile` followed by
`compiler_fence(SeqCst)`, which the compiler may not remove. `Vec<u8>` and
`String` also zero their spare capacity. `Secret<T>` zeroizes on drop.
Zeroization cannot reach copies made earlier (moves, reallocations, registers,
swap), so secrets should be created in their final location and not moved or
grown.

The states of hash functions, HMAC and the DRBGs zeroize themselves on drop,
and their temporaries (message schedules, intermediate chaining values, the
tag compared by `HMAC::verify`) are zeroized before they go out of scope.
Constructors return their state by value, so a stale copy may remain on the
stack of the constructor; that is the limit above, not a bug to fix in each
type. The C ABI keeps each state in the heap block it was created in: a
function that consumes a state (`finalize`) computes through a reference and
then drops the block, so `Drop` zeroizes it in place instead of in a moved
copy that would leave the original block unzeroized when freed.

A zeroized object is not a fresh one. After `zeroize()` a keyed hash or HMAC
is unusable except to be dropped, and a DRBG is uninstantiated: every
function fails with `Uninstantiated` (SP 800-90A section 9.4).
