# One-time passwords: `umilib::auth::totp`

`auth-totp` (no `std`) generates and checks one-time passwords:

- **HOTP** (RFC 4226) counts events: each password belongs to a counter.
- **TOTP** (RFC 6238) counts time steps: each password belongs to a time
  step since an origin.

Both are HMAC over any cryptographic hash function. RFC 6238 names SHA-1,
SHA-256 and SHA-512; SHA-1 is what authenticator apps use by default.

```rust
use umilib::auth::totp::{TOTP, TOTPConfig};
use umilib::hash::sha::v1::SHA1;

let totp = TOTP::<SHA1>::new(&key, &TOTPConfig::default())?;   // 6 digits, 30-second steps from the epoch
let password = totp.generate(now)?;                              // `now`: seconds of the Unix epoch
println!("{password}");                                          // leading zeros kept, e.g. "081804"
if let Some(step) = totp.verify(entered.as_bytes(), now, 1, 1)? {
    // Accept only if `step` is after the last step accepted for this key, then remember it.
}
```

## HOTP

`HOTP::<H>::new(key, digits)` builds a generator.

- The key must have at least 16 bytes (128 bits, RFC 4226 R6; 20 are
  recommended); a shorter one fails with `OTPError::KeyTooShort`.
- A password has 6 to 10 digits (`OTPError::Digits` otherwise).
- The hash function's output must have at least 19 bytes, as the dynamic
  truncation reads 4 bytes at an offset up to 15. MD5, for example, fails
  with `OTPError::Hash`.

The generator works as follows:

- `generate(counter)` gives the `OTPCode` of a counter: HMAC of the key
  over the counter (8 bytes, big-endian), dynamically truncated to 31 bits
  (`HOTP::truncate`), reduced to its last `digits` digits.
- `verify(code, counter, look_ahead)` returns the first counter from
  `counter` to `counter + look_ahead` whose password is `code` (ASCII
  digits), or `None`. It tries every counter of the window and compares
  in constant time.

An `OTPCode` has `value`, `digits` and `to_ascii`, and `Display` writes it
with leading zeros. Its `Debug` output does not print the password.

## TOTP

`TOTP::<H>::new(key, &TOTPConfig { digits, period, origin })` builds a
generator; the defaults are 6 digits and 30-second steps from 0, the Unix
epoch.

- `counter(time)` is the step `(time - origin) / period`. Times are
  seconds of the Unix epoch, given by the caller, so the module needs no
  clock; a time before the origin fails with `OTPError::Time`, and a zero
  period with `OTPError::Period`.
- `generate(time)` gives the password of the step of `time`.
- `verify(code, time, behind, ahead)` tries the steps from `behind`
  before to `ahead` after that of `time`, for clocks out of step and for
  the time the password took to arrive (RFC 6238 §5.2 recommends at most
  one step behind). It returns the step that matched.

## Replay

A password must be accepted at most once. RFC 4226 §7.2 and RFC 6238 §5.2
require the verifier to remember the counter (or step) of the last
password it accepted, and to accept no password of that counter or an
earlier one again. `verify` returns the counter for that purpose.
Limiting the number of failed attempts (RFC 4226 §7.3) is also the
verifier's job.

## Not provided

The `otpauth://` URIs of authenticator apps are a de facto format, not a
standard. They need percent-encoding, which comes with the URL support of
the HTTP phase.

## C and Python

The C ABI (`include/umilib/auth/totp.h`) and the Python package
`umilib.auth.totp` provide:

- `HOTP` and `TOTP`, with the hash function chosen by its C type name
  (`umilib_hash_sha_v1_SHA1`), as HMAC does. In Python that is
  `HOTP[SHA1](key, digits)` and `TOTP[SHA256](key, TOTPConfig(...))`.
- Passwords written as ASCII digits.
- The errors `KeyTooShort`, `Digits`, `Period`, `Time` and `Hash`.
