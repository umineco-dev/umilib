# umilib for Python

Python bindings of [umilib](https://github.com/umineco-dev/umilib), the Umineco Library.
Every module mirrors the Rust module of the same path (`umilib.bytes` is `umilib::bytes`)
and calls the umilib shared library through `ctypes`.

The shared library is searched for in this order:

1. `UMILIB_LIBRARY_PATH` (a file, or a directory containing the library);
2. the library bundled in the wheel;
3. the shared libraries of the system.

See `docs/python.md` in the repository for details.
