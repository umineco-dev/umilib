#!/usr/bin/env python3
"""Checks that every feature of umilib compiles on its own, without warnings.

Runs ``cargo check --no-default-features --features <feature> --all-targets``,
with ``-D warnings`` added to ``RUSTFLAGS``, for every feature in
``Cargo.toml`` (tests and benchmarks whose required features are missing are
skipped by Cargo), and again with ``ffi``, whose modules follow the features. ``--part N/M`` checks only the N-th of M slices, so CI can
split the work. Uses only the standard library.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path


class CheckFeatures:
    ROOT = Path(__file__).resolve().parent.parent

    @staticmethod
    def features() -> list[str]:
        with open(CheckFeatures.ROOT / "Cargo.toml", "rb") as file:
            return sorted(name for name in tomllib.load(file)["features"] if name != "default")

    @staticmethod
    def part(features: list[str], argument: str | None) -> list[str]:
        if argument is None:
            return features
        index, count = (int(value) for value in argument.split("/"))
        return [feature for position, feature in enumerate(features) if position % count == index - 1]

    @staticmethod
    def main() -> None:
        argument = None
        if "--part" in sys.argv:
            argument = sys.argv[sys.argv.index("--part") + 1]
        failed = []
        # Code that only some features compile must not leave warnings behind either.
        environment = dict(os.environ, RUSTFLAGS=f"{os.environ.get('RUSTFLAGS', '')} -D warnings".strip())
        for feature in CheckFeatures.part(CheckFeatures.features(), argument):
            for selection in (feature, f"ffi,{feature}") if feature != "ffi" else (feature,):
                command = ["cargo", "check", "--quiet", "--no-default-features", "--features", selection, "--all-targets"]
                print(f"+ {' '.join(command)}", flush=True)
                if subprocess.run(command, cwd=CheckFeatures.ROOT, env=environment).returncode != 0:
                    failed.append(selection)
        if failed:
            raise SystemExit(f"features that do not compile alone: {', '.join(failed)}")
        print("every feature compiles alone without warnings")


if __name__ == "__main__":
    CheckFeatures.main()
