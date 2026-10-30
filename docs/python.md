# Python

`port/python` is the `umilib` Python package. It mirrors the Rust crate: the
module `umilib.bytes` is `umilib::bytes`, with the same types and method names,
and calls the umilib shared library through `ctypes` (see [ffi.md](ffi.md)).

## Installing

Wheels from PyPI bundle the shared library for their platform:

```bash
pip install umilib
```

The source distribution contains no library; it uses `UMILIB_LIBRARY_PATH` or
a system installation.

## Finding the library

1. `UMILIB_LIBRARY_PATH`: a library file, or a directory that contains it;
2. the library bundled in the package (`umilib/ffi/`);
3. the system (`ctypes.util.find_library("umilib")`).

`umilib.VERSION` is the version of the loaded library.

## Differences dictated by the language

- Rust type parameters become leading arguments: `reader.read_be::<u32>()` is
  `reader.read_be(Integer.U32)`.
- Slices that Rust borrows are returned as `bytes` copies; memory that Rust
  writes into (`SliceWriter`, `Zeroize`) is a `bytearray`.
- `Duration` is `datetime.timedelta` (microsecond resolution).
- Errors are exceptions: `BytesError` for `bytes`, `FFIError` with `domain`,
  `name` and `message` in general. Error fields of Rust variants (such as the
  number of bytes needed) are not available.
- Integer arguments outside the range of their C type raise `OverflowError`
  (ctypes would otherwise wrap `-1` to the largest value), and negative
  durations raise `ValueError`.
- Exceptions raised by Python callbacks (a benchmark routine, a fuzz target)
  never cross into C: a failing benchmark routine is not called again and its
  exception is raised when measuring ends; a failing fuzz target is a failure;
  `KeyboardInterrupt` and `SystemExit` stop the run and are raised again.
- Objects created by umilib are released when garbage collected, by `close()`
  or at the end of a `with` block.
- Objects can be shared between threads: every call locks the objects it is
  given, and methods that copy memory an object owns, or consume it, hold the
  lock until they are done (the C ABI itself does not synchronize, see
  [ffi.md](ffi.md)). Using an object from a callback that runs inside a call
  on the same object raises `FFIError` (`Reentrant`) instead of deadlocking; a
  callback must not wait for another thread that uses such an object either.
- `umilib.secret.DataIndependentTiming` is a context manager only, because
  the mode it sets belongs to the thread that leaves the block.
- Generic Rust types whose parameter is a constant, such as
  `umilib::math::bigint::Uint<N>`, are not available; a type with a run-time
  parameter computes the same results (`BoxedUint`). The modules that are
  concerned say so. Where the Rust aliases name instances (`SipHash24` for
  `SipHash<2, 4>`), those are the classes.
- A Rust type generic over a hash function, a block cipher or a size is
  subscripted with the class or the size: `HMAC::<SHA256>::new(key)` is
  `HMAC[SHA256](key)`, `GCM::<AES128, 12>` is `GCM[AES128, 12]`,
  `AEGIS128X::<2, 16>` is `AEGIS128X[2, 16]` and `KBKDF<HMAC<SHA256>>` is
  `KBKDF[HMAC[SHA256]]`. The classes must satisfy the Rust bounds (a
  `CryptographicDigest`, a `BlockCipher` with the required block size),
  checked when subscripting (`TypeError`). Where Rust passes cipher objects
  (`CBC::new(AES128::new(key), iv)`), Python passes the key:
  `CBC[AES128](key, iv)`.
- Operations in place (`encrypt_blocks`, the modes, `apply_keystream`,
  `encrypt_in_place`) take a `bytearray`.
- Types of no value that choose parameters, such as the curves
  (`umilib.crypto.curve.p256.P256`) and the groups of DH and SRP, are classes
  whose `C_TYPE` is their C type name. The schemes of the traits
  `KeyAgreement` and `SignatureScheme` are classes of no instances, as in
  Rust (`ECDSA[P256, SHA256].sign(key, message)`); their keys are objects
  that hold the encodings, secret ones in a `Secret`. Rust functions that
  write a secret into a slice (`agree`, `write_private_key`, `export`) take a
  `bytearray`; those that return one (a decrypted message, a premaster
  secret) return a `bytearray`. Functions that draw random values take a
  generator of `umilib.crypto.random`, whose handle the C ABI uses.
- Fields of structures (`BLAKE2bParameters`, `CRCParameters`, `DRBGConfig`)
  are checked against their C types like arguments (`OverflowError`).
- The traits of `umilib::hash` (`Digest`, `CryptographicDigest`,
  `ExtendableOutput`, `XOFReader`) are base classes; a few more bases share the methods that families of Rust
  types share (`BLAKE2Variable`, `BLAKE2Fixed`). Methods that consume the
  Rust value, such as `Digest.finalize`, release the Python object: call
  `clone()` first to keep it.
- Python keeps copies of `bytes` and `str` that cannot be erased. Keep secrets
  in `umilib.secret.Secret` or in a `bytearray`, and erase them with
  `Zeroize.zeroize`. A `bytearray` passed to `Secret` is erased, and the
  functions of `umilib.secret` read `bytearray`s in place without copying.
  `Secret.expose_mut()` returns a view into the secret that keeps it alive;
  `close()` refuses (`Borrowed`) while such a view is in use.

Wheels exist for Linux (manylinux), Android, macOS and Windows. iOS archives
contain the libraries, but no iOS wheels are published, because PEP 730
requires binaries packaged as frameworks.

## Example

```python
from umilib.bytes import Buffer, Integer, Reader

buffer = Buffer.with_limit(1024)
buffer.write_be_sized(Integer.U32, 3, 3)
buffer.write(b"abc")
reader = Reader(buffer.as_slice())
length = reader.read_be_sized(Integer.U32, 3)
assert reader.read_slice(length) == b"abc"
```

## Building and testing

```bash
cargo rustc --lib --all-features --crate-type cdylib
UMILIB_LIBRARY_PATH=target/debug uv run --directory port/python --group dev pytest
```

`python3 tools/check_ffi.py` does both and also runs the C tests. The build
backend (`port/python/backend.py`) uses only the standard library; set the
`library` config setting (or `UMILIB_WHEEL_LIBRARY`) to bundle a library in a
wheel.
