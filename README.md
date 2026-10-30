# umilib

The Umineco Library: types and implementations of codecs, hashes, cryptography,
protocols and authentication, used by the official ukmods of uKernel and by other
projects.

- **Zero dependencies.** Everything except the Rust standard library is implemented in this crate.
- **`no_std` types.** Everything outside `umilib::platform` depends only on `core` and `alloc`,
  is independent of CPU architecture and platform, and runs in a ukmod or on bare metal.
- **Platforms.** `umilib::platform` supports Linux, Darwin (macOS, iOS, iPadOS), Android and Windows.
- **Bindings.** A C ABI (`ffi` feature, headers in `include/`) and Python bindings (`port/python`)
  that mirror the Rust modules one to one.
- **Features select modules.** The feature `a-b-c` enables the module `umilib::a::b::c`
  (directory `src/a/b/c`); enabling a parent enables all of its children.

## Usage

```toml
[dependencies]
umilib = { version = "0", features = ["bytes", "secret"] }
```

```rust
use umilib::bytes::{Buffer, Reader, Writer};

let mut buffer = Buffer::new();
buffer.write_be_sized(0x01_0000u32, 3)?; // a TLS uint24
let mut reader = Reader::new(buffer.as_slice());
assert_eq!(reader.read_be_sized::<u32>(3)?, 0x01_0000);
# Ok::<(), umilib::bytes::BytesError>(())
```

## Documentation

- [`docs/`](docs/README.md): how to use umilib (features, modules, the C ABI, Python, benchmarks, fuzzing, CI).
- [`.docs/`](.docs/README.md): how umilib is built (design rules, the feature system, testing).

## License

MIT; see [LICENSE](LICENSE).
