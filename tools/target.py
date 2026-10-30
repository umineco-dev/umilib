#!/usr/bin/env python3
"""How to build for, link for and run on every Rust target used by CI and releases.

    python3 tools/target.py packages <target>...      # Debian packages needed on Linux runners
    python3 tools/target.py environment <target>...   # KEY=VALUE lines for $GITHUB_ENV

Linux cross targets link with clang and lld against the Debian cross sysroots
(clang finds the cross GCC runtime files in /usr/lib/gcc-cross) and run under
qemu-user. Android targets link with the clang of the Android NDK. Apple and
Windows targets use the native toolchains of their runners. Tier 3 targets are
built with the nightly toolchain and ``-Zbuild-std``.

Uses only the standard library.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Target:
    rust: str
    #: The GNU triple of a Debian cross toolchain, for Linux cross targets.
    gnu: str | None = None
    #: The Debian architecture of the cross sysroot.
    debian: str | None = None
    #: The qemu-user program that runs binaries of the target.
    qemu: str | None = None
    #: The clang triple prefix and API level of an Android target.
    android: tuple[str, int] | None = None
    #: Whether the target is Tier 3 and needs nightly with -Zbuild-std.
    tier3: bool = False
    #: Whether a shared library can be linked for the target in CI.
    shared: bool = True
    #: The wheel platform tag of the shared library, if wheels are published for the target.
    #: iOS has none: PEP 730 requires binaries in frameworks, which the wheels do not provide yet.
    wheel: str | None = None
    #: Extra rustflags for the target.
    rustflags: list[str] = field(default_factory=list)

    @property
    def variable(self) -> str:
        return self.rust.upper().replace("-", "_").replace(".", "_")

    def packages(self) -> list[str]:
        if self.gnu is None:
            return []
        packages = [f"gcc-{self.gnu}", f"libc6-dev-{self.debian}-cross", "clang", "lld"]
        if self.qemu:
            # binfmt_misc runs the processes that tests start from the target's binaries under qemu too.
            packages += ["qemu-user", "qemu-user-binfmt"]
        return packages

    def environment(self) -> dict[str, str]:
        variables: dict[str, str] = {}
        rustflags = list(self.rustflags)
        if self.gnu is not None:
            variables[f"CARGO_TARGET_{self.variable}_LINKER"] = "clang"
            rustflags += [f"-Clink-arg=--target={self.gnu}", "-Clink-arg=-fuse-ld=lld"]
            if self.qemu:
                variables[f"CARGO_TARGET_{self.variable}_RUNNER"] = self.qemu
                # The sysroot as an environment variable rather than `-L`: the processes a test starts
                # inherit it, and the qemu that binfmt_misc runs for them reads it too.
                variables["QEMU_LD_PREFIX"] = f"/usr/{self.gnu}"
        if self.android is not None:
            ndk = os.environ.get("ANDROID_NDK_LATEST_HOME") or os.environ.get("ANDROID_NDK_HOME", "")
            host = "darwin-x86_64" if sys.platform == "darwin" else "linux-x86_64"
            binaries = f"{ndk}/toolchains/llvm/prebuilt/{host}/bin"
            triple, api = self.android
            variables[f"CARGO_TARGET_{self.variable}_LINKER"] = f"{binaries}/{triple}{api}-clang"
            variables[f"AR_{self.rust.replace('-', '_')}"] = f"{binaries}/llvm-ar"
        if rustflags:
            variables[f"CARGO_TARGET_{self.variable}_RUSTFLAGS"] = " ".join(rustflags)
        return variables


class Targets:
    """Every target, keyed by Rust triple."""

    ALL: dict[str, Target] = {
        target.rust: target
        for target in [
            Target("x86_64-unknown-linux-gnu", wheel="auto"),
            Target("i686-unknown-linux-gnu", gnu="i686-linux-gnu", debian="i386", qemu="qemu-i386", wheel="auto"),
            Target("armv7-unknown-linux-gnueabihf", gnu="arm-linux-gnueabihf", debian="armhf", qemu="qemu-arm", wheel="auto"),
            Target("aarch64-unknown-linux-gnu", gnu="aarch64-linux-gnu", debian="arm64", qemu="qemu-aarch64", wheel="auto"),
            Target("riscv64gc-unknown-linux-gnu", gnu="riscv64-linux-gnu", debian="riscv64", qemu="qemu-riscv64", wheel="auto"),
            Target("riscv32gc-unknown-linux-gnu", tier3=True, shared=False),
            Target("s390x-unknown-linux-gnu", gnu="s390x-linux-gnu", debian="s390x", qemu="qemu-s390x"),
            Target("x86_64-linux-android", android=("x86_64-linux-android", 24), wheel="android_24_x86_64"),
            Target("i686-linux-android", android=("i686-linux-android", 24), wheel="android_24_x86"),
            Target("armv7-linux-androideabi", android=("armv7a-linux-androideabi", 24), wheel="android_24_armeabi_v7a"),
            Target("aarch64-linux-android", android=("aarch64-linux-android", 24), wheel="android_24_arm64_v8a"),
            Target("riscv64-linux-android", android=("riscv64-linux-android", 35), tier3=True),
            Target("x86_64-apple-darwin", wheel="macosx_10_12_x86_64"),
            Target("aarch64-apple-darwin", wheel="macosx_11_0_arm64"),
            Target("x86_64-apple-ios"),
            Target("aarch64-apple-ios"),
            Target("aarch64-apple-ios-sim"),
            Target("i686-pc-windows-msvc", wheel="win32"),
            Target("x86_64-pc-windows-msvc", wheel="win_amd64"),
            Target("aarch64-pc-windows-msvc", wheel="win_arm64"),
            Target("thumbv7a-pc-windows-msvc", tier3=True, shared=False),
        ]
    }

    @staticmethod
    def get(name: str) -> Target:
        try:
            return Targets.ALL[name]
        except KeyError:
            raise SystemExit(f"unknown target: {name}") from None

    @staticmethod
    def main() -> None:
        if len(sys.argv) < 3 or sys.argv[1] not in ("packages", "environment"):
            raise SystemExit(__doc__)
        targets = [Targets.get(name) for name in sys.argv[2:]]
        if sys.argv[1] == "packages":
            print(" ".join(sorted({package for target in targets for package in target.packages()})))
        else:
            variables: dict[str, str] = {}
            for target in targets:
                for key, value in target.environment().items():
                    if variables.setdefault(key, value) != value:
                        raise SystemExit(f"{key} differs between the targets; set up one at a time")
            for key, value in variables.items():
                print(f"{key}={value}")


if __name__ == "__main__":
    Targets.main()
