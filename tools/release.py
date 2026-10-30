#!/usr/bin/env python3
"""Release steps of umilib, run by .github/workflows/release.yml and usable locally.

    python3 tools/release.py version <tag>
        Sets the version in Cargo.toml and port/python/pyproject.toml to the tag
        without its leading "v", updates Cargo.lock, and prints `version=...`
        and `python_version=...`.
    python3 tools/release.py build --tag <tag> --arch <arch> --platform <platform> \\
            --targets "<rust target>:<lib directory> ..." --output <directory>
        Builds the static and (where possible) shared libraries of every target with
        every feature, writes umilib-<tag>-<arch>-<platform>.tar.xz and the Python
        wheels of the targets that have a wheel platform tag.
    python3 tools/release.py checksums <directory>
        Writes SHA256SUMS for the files in the directory.

Uses only the standard library.
"""

from __future__ import annotations

import hashlib
import os
import importlib.util
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from target import Target, Targets  # noqa: E402


class Version:
    """Release versions: SemVer for Cargo, PEP 440 for Python."""

    SEMVER = re.compile(
        r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
        r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
        r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
    )
    PYTHON_PRERELEASES = {"alpha": "a", "a": "a", "beta": "b", "b": "b", "rc": "rc"}

    @staticmethod
    def from_tag(tag: str) -> str:
        if not tag.startswith("v"):
            raise SystemExit(f"release tags start with 'v': {tag}")
        version = tag[1:]
        match = Version.SEMVER.match(version)
        if not match:
            raise SystemExit(f"not a semantic version: {version}")
        # Build metadata publishes nowhere: PyPI refuses local versions (PEP 440 "+..."), and
        # crates.io takes 1.0.0+a and 1.0.0+b for the same version. Refused here, before
        # anything is published, rather than after crates.io took the release and PyPI did not.
        if match.group(5):
            raise SystemExit(f"release tags carry no build metadata: {version}")
        return version

    @staticmethod
    def python(version: str) -> str:
        """The PEP 440 form of a SemVer version: ``1.0.0-rc.1`` is ``1.0.0rc1``."""
        match = Version.SEMVER.match(version)
        release = ".".join(match.group(index) for index in (1, 2, 3))
        prerelease, build = match.group(4), match.group(5)
        if prerelease:
            parts = prerelease.split(".")
            kind = Version.PYTHON_PRERELEASES.get(parts[0].lower())
            number = parts[1] if len(parts) > 1 else "0"
            if kind is None or len(parts) > 2 or not number.isdigit():
                raise SystemExit(f"pre-release {prerelease} has no PEP 440 form; use alpha.N, beta.N or rc.N")
            release += f"{kind}{number}"
        if build:
            raise SystemExit(f"a version with build metadata has no published PEP 440 form: {version}")
        return release

    @staticmethod
    def replace(path: Path, section: str, version: str) -> None:
        """Replaces the first `version = "..."` line of `section` in a TOML file."""
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        current = None
        for index, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("["):
                current = stripped
            elif current == section and re.match(r'^version\s*=\s*"[^"]*"\s*$', stripped):
                lines[index] = f'version = "{version}"\n'
                path.write_text("".join(lines), encoding="utf-8")
                return
        raise SystemExit(f"no version in {section} of {path}")

    @staticmethod
    def set(tag: str) -> None:
        root = Release.ROOT
        version = Version.from_tag(tag)
        python = Version.python(version)
        Version.replace(root / "Cargo.toml", "[package]", version)
        Version.replace(root / "port" / "python" / "pyproject.toml", "[project]", python)
        # Keep Cargo.lock in step, so that `build --locked` works afterwards.
        subprocess.run(["cargo", "update", "--workspace", "--offline", "--quiet"], cwd=root, check=True)
        print(f"version={version}")
        print(f"python_version={python}")


class Release:
    ROOT = Path(__file__).resolve().parent.parent
    #: The native libraries printed by rustc for each built target.
    native_libraries: dict[str, str] = {}

    @staticmethod
    def run(command: list[str], environment: dict[str, str] | None = None) -> None:
        print("+", " ".join(command), flush=True)
        subprocess.run(command, cwd=Release.ROOT, check=True, env=environment)

    @staticmethod
    def build_target(target: Target) -> Path:
        """Builds the libraries of `target` and returns the directory containing them."""
        environment = dict(os.environ)
        environment.update(target.environment())
        crate_types = "staticlib,cdylib" if target.shared else "staticlib"
        command = ["cargo"]
        if target.tier3:
            command.append("+nightly")
        command += ["rustc", "--release", "--lib", "--all-features", "--locked", "--target", target.rust, "--crate-type", crate_types]
        if target.tier3:
            command.append("-Zbuild-std")
        command += ["--", "--print=native-static-libs"]
        if target.shared:
            # Shared libraries are found by name at run time, not by the path they were built at.
            if "-apple-" in target.rust:
                command.append("-Clink-arg=-Wl,-install_name,@rpath/libumilib.dylib")
            elif "-linux-" in target.rust:
                command.append("-Clink-arg=-Wl,-soname,libumilib.so")
        print("+", " ".join(command), flush=True)
        result = subprocess.run(command, cwd=Release.ROOT, env=environment, stderr=subprocess.PIPE, text=True)
        sys.stderr.write(result.stderr)
        if result.returncode != 0:
            raise SystemExit(f"the build for {target.rust} failed")
        # The system libraries a program linking the static library also needs.
        Release.native_libraries[target.rust] = next(
            (line.split("native-static-libs:", 1)[1].strip() for line in result.stderr.splitlines() if "native-static-libs:" in line), ""
        )
        return Release.ROOT / "target" / target.rust / "release"

    @staticmethod
    def libraries(directory: Path, target: Target) -> list[Path]:
        names = ["libumilib.a", "umilib.lib", "libumilib.so", "libumilib.dylib", "umilib.dll", "umilib.dll.lib"]
        found = [directory / name for name in names if (directory / name).is_file()]
        if not found:
            raise SystemExit(f"no library was built for {target.rust}")
        return found

    @staticmethod
    def shared_library(libraries: list[Path]) -> Path | None:
        for library in libraries:
            if library.suffix in (".so", ".dylib", ".dll"):
                return library
        return None

    @staticmethod
    def pkg_config(version: str, private: str) -> str:
        return (
            "prefix=${pcfiledir}/../..\n"
            "libdir=${prefix}/lib\n"
            "includedir=${prefix}/include\n\n"
            "Name: umilib\n"
            "Description: Umineco Library\n"
            f"Version: {version}\n"
            "Libs: -L${libdir} -lumilib\n"
            f"Libs.private: {private}\n"
            "Cflags: -I${includedir}\n"
        )

    @staticmethod
    def wheel(library: Path, target: Target, output: Path) -> None:
        specification = importlib.util.spec_from_file_location("backend", Release.ROOT / "port" / "python" / "backend.py")
        backend = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(backend)
        settings = {"library": str(library)}
        if target.wheel != "auto":
            settings["platform"] = target.wheel
        name = backend.Backend.build_wheel(str(output), settings)
        print(f"wheel: {name}")

    @staticmethod
    def build(arguments: list[str]) -> None:
        options = dict(zip(arguments[::2], arguments[1::2]))
        tag, arch, platform = options["--tag"], options["--arch"], options["--platform"]
        output = Path(options["--output"]).resolve()
        output.mkdir(parents=True, exist_ok=True)
        version = Version.from_tag(tag)
        name = f"umilib-{tag}-{arch}-{platform}"
        staging = Release.ROOT / "target" / "release-staging" / name
        shutil.rmtree(staging, ignore_errors=True)
        (staging / "lib" / "pkgconfig").mkdir(parents=True)
        for entry in options["--targets"].split():
            rust, subdirectory = entry.split(":")
            target = Targets.get(rust)
            libraries = Release.libraries(Release.build_target(target), target)
            destination = staging / subdirectory
            destination.mkdir(parents=True, exist_ok=True)
            for library in libraries:
                shutil.copy2(library, destination / library.name)
            shared = Release.shared_library(libraries)
            if target.wheel and shared is not None:
                Release.wheel(shared, target, output)
        shutil.copy2(Release.ROOT / "LICENSE", staging / "LICENSE")
        shutil.copy2(Release.ROOT / "README.md", staging / "README.md")
        shutil.copytree(Release.ROOT / "include", staging / "include")
        first = options["--targets"].split()[0].split(":")[0]
        private = Release.native_libraries.get(first, "")
        (staging / "lib" / "pkgconfig" / "umilib.pc").write_text(Release.pkg_config(version, private), encoding="utf-8")
        archive = output / f"{name}.tar.xz"
        with tarfile.open(archive, "w:xz") as file:
            file.add(staging, arcname=name)
        print(f"archive: {archive}")

    @staticmethod
    def checksums(directory: Path) -> None:
        lines = []
        for path in sorted(directory.iterdir()):
            if path.is_file() and path.name != "SHA256SUMS":
                lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
        (directory / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")
        print("".join(lines), end="")

    @staticmethod
    def main() -> None:
        if len(sys.argv) < 3:
            raise SystemExit(__doc__)
        command = sys.argv[1]
        if command == "version":
            Version.set(sys.argv[2])
        elif command == "build":
            Release.build(sys.argv[2:])
        elif command == "checksums":
            Release.checksums(Path(sys.argv[2]))
        else:
            raise SystemExit(__doc__)


if __name__ == "__main__":
    Release.main()
