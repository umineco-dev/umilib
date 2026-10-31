# Design rules

These rules apply to every module. They come from the project's CLAUDE.md and
from decisions made while building umilib.

## Dependencies

- No crate other than `core`, `alloc` and `std` is used, including in tests,
  benchmarks and tools. Tools are Python scripts that use only the standard
  library.
- Only `src/platform` uses `std`. Everything else is `no_std`, independent of
  the CPU architecture and the operating system, and must build for
  `thumbv7em-none-eabihf` and `riscv32imac-unknown-none-elf`.
- The platform part declares the operating system functions it needs itself
  (`unsafe extern "C"` blocks) instead of using crates such as `libc`.

## Structure

- One feature per module, and one module per directory (see
  [feature-system.md](feature-system.md)).
- Nothing is private in intent: every type is a complete, reusable component.
  A Huffman coder written for HPACK is a general Huffman module that HPACK uses.
- Files contain types (and their `impl` blocks); functions that act on a type
  are its methods or associated functions. Constants live in the type they
  belong to.
- Modules do not contain code specific to other modules. Integration code lives
  in the module that depends on the other.

## Naming

- Types use `CamelCase` with acronyms in capitals: `HTTPRequest`, `TLSClient`,
  `SHA256`, `IPv4Address`, `BytesError`. Crate-wide
  `clippy::upper_case_acronyms` is allowed for this.
- Each error type is named after its module (`BytesError`), so that imports
  from several modules never clash.
- Symmetric operations use symmetric names: `encode`/`decode`,
  `encrypt`/`decrypt`, `sign`/`verify`, `read_*`/`write_*`.

## Versions and extensibility

- Every protocol version is its own module implementing a shared trait, so
  that versions stay compatible except where they truly differ.
- Code never assumes that something is a known version because it looks like
  one: a QUIC connection is HTTP/3 only if ALPN says `h3`. Unknown versions are
  rejected.
- Every limit and timeout is a field of a configuration type with a `Default`.

## Efficiency

- Parse without copying (types borrow their input), allocate only when needed,
  and box large enum variants so that small variants stay small.
- Prefer generic code over converting to the widest type.
- Safety, stability and reliability come before speed.

## `unsafe`

The crate denies `unsafe_code`; only `ffi`, `platform`, `runtime` and `secret` allow it.
Every `unsafe` block has a `SAFETY:` comment, and Miri runs the tests of these
modules in CI. Undocumented behaviour of a platform or compiler is never relied
on (for example, Windows' undocumented `AFD_POLL` is not used).
