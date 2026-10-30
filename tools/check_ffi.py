#!/usr/bin/env python3
"""Builds the umilib shared library and checks its C ABI and Python bindings.

1. builds the shared library with every feature (``cargo rustc --crate-type cdylib``);
2. checks that the functions the library exports are exactly those of its
   manifest (where ``nm`` can list them), so that no function is missing from
   the headers and the bindings;
3. compiles every C program in ``tests/ffi/c`` with clang against ``include/``
   and the library, and runs it;
4. runs the Python tests in ``port/python`` with ``UMILIB_LIBRARY_PATH`` set.

Uses only the Python standard library. Run from anywhere: ``python3 tools/check_ffi.py``.
"""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


class Buffer(ctypes.Structure):
    """``umilib_ffi_Buffer``."""

    _fields_ = [("data", ctypes.c_void_p), ("length", ctypes.c_size_t), ("capacity", ctypes.c_size_t)]


class CheckFFI:
    ROOT = Path(__file__).resolve().parent.parent

    @staticmethod
    def run(command: list[str], **options: object) -> None:
        print("+", " ".join(command), flush=True)
        subprocess.run(command, check=True, **options)

    @staticmethod
    def library() -> Path:
        CheckFFI.run(["cargo", "rustc", "--lib", "--all-features", "--crate-type", "cdylib"], cwd=CheckFFI.ROOT)
        directory = CheckFFI.ROOT / "target" / "debug"
        for name in ("libumilib.so", "libumilib.dylib", "umilib.dll"):
            if (directory / name).is_file():
                return directory / name
        raise SystemExit("the shared library was not built")

    @staticmethod
    def manifest_functions(library: Path) -> set[str]:
        """The names of the functions in the manifest of ``library``."""
        handle = ctypes.CDLL(str(library))
        manifest, free = handle.umilib_ffi_manifest, handle.umilib_ffi_buffer_free
        manifest.argtypes, manifest.restype = [ctypes.c_void_p], ctypes.c_void_p
        free.argtypes, free.restype = [ctypes.c_void_p], None
        buffer = Buffer()
        if manifest(ctypes.byref(buffer)) is not None:
            raise SystemExit("umilib_ffi_manifest failed")
        try:
            document = json.loads(ctypes.string_at(buffer.data, buffer.length).decode("utf-8"))
        finally:
            free(ctypes.byref(buffer))
        names: set[str] = set()
        modules = [document]
        while modules:
            module = modules.pop()
            names.update(function["name"] for function in module.get("functions", []))
            modules.extend(module.get("modules", []))
        return names

    @staticmethod
    def exports(library: Path) -> None:
        """Checks that the ``umilib_`` functions exported by ``library`` are those of its manifest."""
        nm = shutil.which("llvm-nm") or shutil.which("nm")
        if sys.platform == "win32" or nm is None:
            print("skipping the check of the exported symbols: no nm", flush=True)
            return
        output = subprocess.run([nm, "-g", "--defined-only", str(library)], check=True, capture_output=True, text=True).stdout
        exported = set()
        for line in output.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] == "T":
                name = parts[2].removeprefix("_") if sys.platform == "darwin" else parts[2]
                if name.startswith("umilib_"):
                    exported.add(name)
        declared = CheckFFI.manifest_functions(library)
        if exported != declared:
            raise SystemExit(
                f"exported but not in the manifest: {sorted(exported - declared)}\n"
                f"in the manifest but not exported: {sorted(declared - exported)}"
            )
        print(f"the {len(exported)} exported functions are those of the manifest", flush=True)

    @staticmethod
    def c_programs(library: Path, output: Path) -> None:
        output.mkdir(parents=True, exist_ok=True)
        for source in sorted((CheckFFI.ROOT / "tests" / "ffi" / "c").glob("*.c")):
            program = output / (source.stem + (".exe" if sys.platform == "win32" else ""))
            command = ["clang", "-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic", f"-I{CheckFFI.ROOT / 'include'}", str(source), "-o", str(program)]
            if sys.platform == "win32":
                command.append(str(library.with_suffix(".dll.lib")))
            else:
                command += [f"-L{library.parent}", "-lumilib", f"-Wl,-rpath,{library.parent}"]
            CheckFFI.run(command)
            environment = dict(os.environ)
            if sys.platform == "win32":
                environment["PATH"] = f"{library.parent}{os.pathsep}{environment.get('PATH', '')}"
            CheckFFI.run([str(program)], env=environment)

    @staticmethod
    def python(library: Path) -> None:
        environment = dict(os.environ, UMILIB_LIBRARY_PATH=str(library))
        CheckFFI.run(["uv", "run", "--group", "dev", "pytest", "-q"], cwd=CheckFFI.ROOT / "port" / "python", env=environment)

    @staticmethod
    def main() -> None:
        library = CheckFFI.library()
        CheckFFI.exports(library)
        CheckFFI.c_programs(library, CheckFFI.ROOT / "target" / "ffi")
        if "--no-python" not in sys.argv:
            CheckFFI.python(library)


if __name__ == "__main__":
    CheckFFI.main()
