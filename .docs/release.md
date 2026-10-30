# Releases

`release.yml` drives the release; the logic is in scripts that also run locally.

- `tools/release.py version <tag>` sets both versions (SemVer for Cargo, PEP 440
  for Python; only `alpha.N`, `beta.N` and `rc.N` pre-releases have a PEP 440
  form, others are rejected) and updates `Cargo.lock`. A tag with build metadata
  (`v1.0.0+build.5`) is rejected too: PyPI refuses local versions, and crates.io
  does not tell `1.0.0+a` from `1.0.0+b`, so the release would be taken by
  crates.io and then fail at PyPI, half published.
- `tools/release.py build --tag ... --arch ... --platform ... --targets "<rust target>:<lib dir> ..." --output dist`
  builds every target with `cargo rustc --release --lib --all-features
  --crate-type staticlib,cdylib` (static only for targets that cannot link a
  shared library; nightly with `-Zbuild-std` for Tier 3), sets the install name
  (`@rpath/libumilib.dylib`) or soname (`libumilib.so`) so that the shared
  library is found by name, records the system libraries rustc reports for
  static linking (`--print=native-static-libs`) as `Libs.private` in
  `umilib.pc`, writes the archive and builds the wheels.
- `port/python/backend.py` writes archives with fixed timestamps and
  permissions, so the same inputs always produce the same wheel. It derives a
  platform tag only for glibc-linked ELF libraries and otherwise requires an
  explicit one, so a library is never labelled for the wrong platform.
- `tools/target.py` knows, for every Rust target, the Debian packages, linker,
  rustflags, qemu runner and wheel tag. The test workflow uses it as well, so
  test and release builds are configured identically.
- Wheels are `py3-none-<platform>` because the bindings use ctypes and do not
  depend on the Python ABI. Linux wheels get the manylinux tag of the newest
  glibc symbol version the library needs, read from its ELF `.gnu.version_r`
  section by `port/python/backend.py`.

To check a build locally (on macOS):

```bash
python3 tools/release.py build --tag v0.0.0 --arch aarch64 --platform darwin \
    --targets "aarch64-apple-darwin:lib aarch64-apple-ios:lib/ios aarch64-apple-ios-sim:lib/ios-simulator" \
    --output /tmp/umilib-dist
```
