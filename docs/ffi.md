# The C ABI

The `ffi` feature exports a C ABI for every other enabled module. Headers are in
`include/`: include `umilib.h` for everything or `umilib/<module path>.h` for one module.

Build the libraries with:

```bash
cargo rustc --release --lib --features ffi,bytes,secret --crate-type staticlib,cdylib
```

Release archives contain `lib/` (static and shared libraries, `pkgconfig/umilib.pc`)
and `include/`.

## Conventions

- **Names.** Functions are `umilib_<module path>_<type>_<method>` in `snake_case`
  (`umilib_bytes_reader_read_be_u32`). Types keep their Rust name after the module
  prefix (`umilib_bytes_Reader`, `umilib_ffi_Status`). Generic methods are
  exported once per type, with the type as a suffix (`_u32`, `_i128`).
- **Errors.** A fallible function returns `const umilib_ffi_Status*`: `NULL` on
  success, otherwise a static description with `domain` (the module, such as
  `bytes` or `platform.fuzz`), `name` (the Rust error variant, such as
  `UnexpectedEnd`) and `message`. Never free a status. Results are written to
  `out` parameters only on success.
- **Objects.** Opaque handles are created by `*_new` (or another constructor)
  through an `out` parameter and released with `*_free`, which accepts `NULL`.
  A function that consumes the Rust value (`finalize` of a hash function,
  `verify` of HMAC) releases the handle when it succeeds; when it fails, the
  handle is not released.
- **Generic types.** A Rust type generic over a hash function, such as
  `HMAC<H>`, is one C type whose constructor takes the C type name of the hash
  type as UTF-8 text (`"umilib_hash_sha_v2_SHA256"`). A Rust type generic over
  a constant is exported for the constants the Rust aliases name
  (`SipHash24` for `SipHash<2, 4>`, `Sponge168` for `Sponge<168>`).
- **Bytes in.** `const uint8_t* data, size_t length`; `data` may be `NULL` when
  `length` is 0. Text is UTF-8 in the same form.
- **Bytes out.** `umilib_ffi_Buffer` (do not modify its fields), released with
  `umilib_ffi_buffer_free`, which overwrites the bytes with zeros (they may be
  secret) and resets the buffer to empty. Initialize every
  buffer to zero (`umilib_ffi_Buffer buffer = {0};`) so that freeing one that
  was never filled is safe. A buffer passed as an `out` parameter is
  overwritten without being freed, so free it before reuse.
- **Aliasing.** Where a function takes several pointers to memory it writes,
  they must be identical or disjoint; partially overlapping ranges are
  rejected with `InvalidArgument`. An output written in place (an integer, a
  `bool`, a structure, a status pointer or an array of them) must not share
  any byte with a range the function reads or with another such output, not
  even as the same pointer: the function fails with `InvalidArgument` before
  it writes anything. A null pointer shares nothing and fails with
  `NullPointer`. Two outputs that receive handles must be
  different pointers (one would overwrite, and leak, the other). Appending a
  `umilib_bytes_Buffer` to itself works; the `der_writer_write_*` functions
  reject input that points into the writer's own bytes, which appending may
  move. Passing one object as both operands of a mutation
  (`conditional_assign`, `conditional_swap`) does nothing.
- **Choices.** A secret boolean is a `uint8_t` holding 0 or 1; functions that
  return a status reject other values with `InvalidArgument`.
- **Allocation.** A request that cannot be allocated fails with a status
  (such as `CapacityExceeded`); no function aborts the process.
- **Borrowed memory.** A reader or writer created over your memory keeps
  pointing to it; keep it valid and unchanged until the object is released.
- **128-bit integers.** `umilib_ffi_U128` and `umilib_ffi_I128` hold
  `(high << 64) | low`, because C has no portable 128-bit integer.
- **Callbacks.** Function pointer types such as `umilib_platform_bench_Routine`
  receive the `void* context` you pass alongside them.
- **Threads.** Functions do not synchronize; do not use one object from two
  threads at once.

## Example

```c
#include <umilib.h>

const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
umilib_bytes_Reader* reader = NULL;
if (umilib_bytes_reader_new(data, sizeof data, &reader) == NULL) {
    uint32_t value;
    const umilib_ffi_Status* status = umilib_bytes_reader_read_be_u32(reader, &value);
    if (status) fprintf(stderr, "%s: %s\n", status->name, status->message);
    umilib_bytes_reader_free(reader);
}
```

## The manifest

`umilib_ffi_manifest` writes a JSON description of every exported type and
function of the build (the same information as the headers, generated from the
Rust source). Bindings for other languages, such as the Python bindings, read
it instead of repeating every signature.
