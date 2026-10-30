#!/usr/bin/env python3
"""Runs a umilib fuzz target under LLVM libFuzzer.

    python3 tools/fuzz.py <target> [--time SECONDS] [--sanitizer address] [--features FEATURES] [-- LIBFUZZER-ARGUMENTS]

The features default to ``bytes,secret,platform-fuzz``; the targets of
other modules need theirs (``--features crypto,hash,codec,platform-fuzz``).

Builds ``fuzz/main.rs`` with the nightly toolchain, SanitizerCoverage
instrumentation (the options libFuzzer documents for coverage feedback:
``inline-8bit-counters``, ``pc-table`` and ``trace-compares``) and the
``umilib_libfuzzer`` cfg, links ``libclang_rt.fuzzer_no_main`` from the clang
installation, and runs the target with ``--engine libfuzzer``.

Crashes are written to ``fuzz/artifacts/<target>/``. Uses only the standard library.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


class Fuzz:
    ROOT = Path(__file__).resolve().parent.parent
    COVERAGE = [
        "-Cpasses=sancov-module",
        "-Cllvm-args=-sanitizer-coverage-level=4",
        "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters",
        "-Cllvm-args=-sanitizer-coverage-pc-table",
        "-Cllvm-args=-sanitizer-coverage-trace-compares",
    ]

    @staticmethod
    def runtime() -> Path:
        """The path of libFuzzer without ``main`` in the clang installation."""
        clang = os.environ.get("CLANG", "clang")
        if sys.platform == "darwin":
            names = ["libclang_rt.fuzzer_no_main_osx.a"]
        else:
            machine = os.uname().machine
            names = [f"libclang_rt.fuzzer_no_main-{machine}.a", "libclang_rt.fuzzer_no_main.a"]
        for name in names:
            path = Path(subprocess.run([clang, f"--print-file-name={name}"], capture_output=True, text=True, check=True).stdout.strip())
            if path.is_file():
                return path
        directory = subprocess.run([clang, "--print-runtime-dir"], capture_output=True, text=True, check=True).stdout.strip()
        for name in names:
            if (Path(directory) / name).is_file():
                return Path(directory) / name
        raise SystemExit("libclang_rt.fuzzer_no_main was not found; install LLVM's compiler-rt and set CLANG")

    @staticmethod
    def parse(arguments: list[str]) -> dict:
        options = {"target": None, "time": None, "sanitizer": None, "features": None, "engine": []}
        if "--" in arguments:
            index = arguments.index("--")
            arguments, options["engine"] = arguments[:index], arguments[index + 1:]
        iterator = iter(arguments)
        for argument in iterator:
            if argument in ("-h", "--help"):
                print(__doc__)
                raise SystemExit(0)
            if argument in ("--time", "--sanitizer", "--features"):
                value = next(iterator, None)
                if value is None:
                    raise SystemExit(f"{argument} needs a value")
                options[argument[2:]] = value
            elif argument.startswith("-"):
                raise SystemExit(f"unknown option: {argument}")
            elif options["target"] is None:
                options["target"] = argument
            else:
                raise SystemExit(f"unexpected argument: {argument}")
        if options["target"] is None:
            raise SystemExit(__doc__)
        return options

    @staticmethod
    def main() -> None:
        options = Fuzz.parse(sys.argv[1:])
        runtime = Fuzz.runtime()
        flags = ["--cfg", "umilib_libfuzzer", "-Cdebug-assertions", "-Coverflow-checks", *Fuzz.COVERAGE, f"-Clink-arg={runtime}"]
        if sys.platform == "darwin":
            flags.append("-Clink-arg=-lc++")
        else:
            flags.append("-Clink-arg=-lstdc++")
        if options["sanitizer"]:
            flags.append(f"-Zsanitizer={options['sanitizer']}")
        features = options["features"] or "bytes,secret,platform-fuzz"
        environment = dict(os.environ, RUSTFLAGS=" ".join(flags))
        target_directory = Fuzz.ROOT / "target" / "libfuzzer"
        command = ["cargo", "+nightly", "test", "--no-run", "--release", "--test", "fuzz", "--features", features,
                   "--target-dir", str(target_directory), "--message-format=json"]
        if options["sanitizer"]:
            host = subprocess.run(["rustc", "+nightly", "-vV"], capture_output=True, text=True, check=True).stdout
            triple = next(line.split(": ")[1] for line in host.splitlines() if line.startswith("host: "))
            command += ["--target", triple]
        print("+ RUSTFLAGS=" + repr(environment["RUSTFLAGS"]), " ".join(command), flush=True)
        build = subprocess.run(command, cwd=Fuzz.ROOT, env=environment, capture_output=True, text=True)
        if build.returncode != 0:
            sys.stderr.write(build.stderr)
            raise SystemExit("the fuzz target could not be built")
        executable = None
        for line in build.stdout.splitlines():
            message = json.loads(line)
            if message.get("reason") == "compiler-artifact" and message.get("target", {}).get("name") == "fuzz" and message.get("executable"):
                executable = message["executable"]
        if executable is None:
            raise SystemExit("the fuzz executable was not found")
        artifacts = Fuzz.ROOT / "fuzz" / "artifacts" / options["target"]
        artifacts.mkdir(parents=True, exist_ok=True)
        run = [executable, "--fuzz", options["target"], "--engine", "libfuzzer"]
        if options["time"]:
            run += ["--time", options["time"]]
        run += ["--", f"-artifact_prefix={artifacts}/", *options["engine"]]
        print("+", " ".join(run), flush=True)
        raise SystemExit(subprocess.run(run, cwd=Fuzz.ROOT).returncode)


if __name__ == "__main__":
    Fuzz.main()
