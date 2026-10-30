# Fuzzing

`umilib::platform::fuzz` (feature `platform-fuzz`) runs code on generated
inputs to find inputs that make it panic. It is a general library: use it for
your own code too.

- `FuzzTarget` (or `FuzzFunction::new(name, function)`) is the code under test;
  it fails by panicking.
- `Fuzzer` mutates inputs with a deterministic built-in engine that needs only
  `std`, saves failing inputs, and replays a `Corpus` (a directory of inputs;
  files starting with `.` are ignored, and files written by umilib are named
  by the FNV-1a hash of their contents). `FuzzConfig` stops at whichever of
  `iterations` and `duration` comes first; set `iterations` to `None` to fuzz
  for a duration only. A target name must be a valid directory name (letters,
  digits, `-`, `_`, `.`, not starting with `.`). `FuzzReport::saved` lists the
  files failing inputs were saved to; a failure that could not be saved is
  still in `FuzzReport::failures`.
- `LibFuzzer` runs a target under LLVM libFuzzer, which uses code coverage to
  find new inputs. It is compiled only with the `umilib_libfuzzer` cfg.

## umilib's fuzz targets

`fuzz/` holds one module per tested module, and `fuzz/corpus/<target>/` the
stored inputs. Targets check properties as well as the absence of panics, such
as round trips and agreement between equivalent APIs.

```bash
cargo test --all-features --test fuzz                     # replay corpora + a short deterministic pass
cargo test --all-features --test fuzz -- --list           # list the targets (`--skip TEXT` excludes some)
cargo test --all-features --test fuzz -- --fuzz bytes-reader --time 60
python3 tools/fuzz.py bytes-reader --time 600             # libFuzzer
python3 tools/fuzz.py bytes-reader --time 600 --sanitizer address
python3 tools/fuzz.py bytes-reader -- -merge=1 /tmp/minimized    # minimize the corpus into /tmp/minimized
```

libFuzzer re-executes the program for `-merge`, `-fork` and `-jobs`. The
harness supports this by starting libFuzzer in a child process with
`UMILIB_FUZZ_TARGET` set to the target name (`LibFuzzer::TARGET_VARIABLE`);
a process started with that variable runs the named target with its arguments
passed to libFuzzer unchanged.

`tools/fuzz.py` needs the nightly toolchain and clang with its libFuzzer
runtime (`libclang_rt.fuzzer_no_main`; on macOS, Homebrew's `llvm`; on Debian
and Ubuntu, `libclang-rt-<version>-dev`). libFuzzer adds new interesting inputs
to the corpus directory and writes crashes to `fuzz/artifacts/<target>/`. When
fixing a crash, add the crashing input to the corpus so that `cargo test`
replays it from then on.

The `Fuzz` workflow fuzzes every target weekly with AddressSanitizer.
