# The feature system

## Rules

1. A canonical feature `a-b-c` is the directory `src/a/b/c` with a `mod.rs`,
   which is the module `umilib::a::b::c`. Every directory of `src` (outside
   `src/ffi`) is a canonical feature. Segments are Rust and Python identifiers:
   versions are `v4`, `v1_3`; other variants are names (`base64`).
2. A parent feature lists all of its direct children, so enabling `a` enables
   `a-b` and `a-b-c`.
3. An alias (such as `protocol-ipv4`) lists exactly one canonical feature and
   has no directory.
4. Dependencies between modules are feature dependencies in `Cargo.toml`.
5. Features are written one per line in `Cargo.toml`, because `build.rs` and
   `tests/features` read the table line by line.

## Compiling parents

A parent module must be compiled when any descendant is enabled, even if the
parent feature itself is not. Listing every descendant in a `cfg(any(...))`
would be error-prone, so `build.rs` reads the enabled features from
`CARGO_CFG_FEATURE` (set by Cargo 1.85 and later; the minimum supported Rust
is 1.88) and sets `umilib_feature = "<prefix>"` for every prefix of every
enabled feature. Modules are declared with:

```rust
#[cfg(umilib_feature = "platform")]
pub mod platform;
```

Because of this rule, `cfg(umilib_feature = "<parent>")` holds when only one
child is enabled: `codec-deflate` enables `codec-huffman-canonical`, which
sets `umilib_feature = "codec-huffman"` without `codec-huffman-adaptive`.
Code that uses the items of particular children (a test, a benchmark or a
fuzz target over several of them) is gated on those children, as
`cfg(all(umilib_feature = "codec-huffman-adaptive", umilib_feature =
"codec-huffman-canonical"))`, not on the parent.

A module that another module needs without its features is compiled for both:
the root of `hash` holds the `Digest` interfaces that `crypto-hmac` is generic
over, so it is declared with
`#[cfg(any(umilib_feature = "hash", umilib_feature = "crypto-hmac"))]`, in
`src/lib.rs` and in `src/ffi/mod.rs`. Every hash feature depends on `secret`,
because that root zeroizes its buffers.

`build.rs` also declares every possible value with `rustc-check-cfg`, so a
misspelled feature in a `cfg` is a compile-time warning (an error in CI). The
cfgs apply to tests, benchmarks and fuzz targets too. `umilib_all_features` is
set when every feature is enabled.

## Checks

- `tests/features` checks rules 1 to 3, that `src/ffi` and
  `port/python/umilib` mirror the modules exactly, and that every
  `umilib_feature` string names a feature.
- `tools/check_features.py` compiles every feature alone, which finds missing
  feature dependencies. CI runs it in four parts.

## Adding a module

1. Create `src/<path>/mod.rs` and declare it in its parent with
   `#[cfg(umilib_feature = "<feature>")]`.
2. Add the feature to `Cargo.toml` with its dependencies, and add it to its
   parent's list.
3. Add the C ABI in `src/ffi/<path>/mod.rs` with a `MODULE` manifest node,
   listed in the parent's `MODULE`, then run
   `UMILIB_BLESS=1 cargo test --all-features --test ffi` to generate the header.
4. Add the Python mirror in `port/python/umilib/<path>/__init__.py`.
5. Add tests (`tests/`, `port/python/tests/`), benchmarks (`benches/`), fuzz
   targets (`fuzz/`) and documentation (`docs/`).
