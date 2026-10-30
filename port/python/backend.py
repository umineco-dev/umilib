"""The PEP 517 build backend of the umilib Python package, using only the standard library.

A wheel bundles the shared library given by the ``library`` config setting or
the ``UMILIB_WHEEL_LIBRARY`` environment variable; without one, the wheel is
pure Python and loads the library from ``UMILIB_LIBRARY_PATH`` or the system.
The platform tag is the ``platform`` config setting or ``UMILIB_WHEEL_PLATFORM``;
without one, it is derived only for glibc-linked Linux libraries, which get the
manylinux tag of the newest glibc symbol version they need. Archives use fixed
timestamps and permissions so that builds are reproducible.

PEP 517 requires the hooks to be module attributes; they are the methods of
:class:`Backend`.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import struct
import tarfile
import tomllib
import zipfile
from pathlib import Path
from typing import Any


class Backend:
    ROOT = Path(__file__).resolve().parent
    PACKAGE = "umilib"
    LIBRARY_NAMES = {".so": "libumilib.so", ".dylib": "libumilib.dylib", ".dll": "umilib.dll"}
    ELF_MACHINES = {3: "i686", 62: "x86_64", 40: "armv7l", 183: "aarch64", 243: "riscv64", 22: "s390x", 21: "ppc64le"}
    MINIMUM_GLIBC = (2, 17)
    #: The timestamp of every archive member, so that builds are reproducible.
    TIMESTAMP = (1980, 1, 1, 0, 0, 0)

    @staticmethod
    def license_file() -> Path:
        """LICENSE next to this file (in an sdist) or at the repository root."""
        for path in (Backend.ROOT / "LICENSE", Backend.ROOT.parent.parent / "LICENSE"):
            if path.is_file():
                return path
        raise FileNotFoundError("LICENSE was not found")

    @staticmethod
    def project() -> dict[str, Any]:
        with open(Backend.ROOT / "pyproject.toml", "rb") as file:
            return tomllib.load(file)["project"]

    @staticmethod
    def metadata() -> str:
        project = Backend.project()
        readme = (Backend.ROOT / project["readme"]).read_text(encoding="utf-8")
        lines = [
            "Metadata-Version: 2.4",
            f"Name: {project['name']}",
            f"Version: {project['version']}",
            f"Summary: {project['description']}",
            f"License-Expression: {project['license']}",
            "License-File: LICENSE",
            f"Requires-Python: {project['requires-python']}",
            "Description-Content-Type: text/markdown",
            "",
            readme,
        ]
        return "\n".join(lines)

    @staticmethod
    def setting(config_settings: dict[str, Any] | None, name: str, environment: str) -> str | None:
        value = (config_settings or {}).get(name) or os.environ.get(environment)
        return str(value) if value else None

    @staticmethod
    def sources() -> list[Path]:
        package = Backend.ROOT / Backend.PACKAGE
        return sorted(path for path in package.rglob("*.py") if "__pycache__" not in path.parts)

    @staticmethod
    def glibc_tag(library: Path) -> str | None:
        """The manylinux tag of an ELF shared library, or ``None`` if it is not ELF."""
        data = library.read_bytes()
        if data[:4] != b"\x7fELF":
            return None
        is_64 = data[4] == 2
        order = "<" if data[5] == 1 else ">"
        machine = struct.unpack_from(order + "H", data, 18)[0]
        architecture = "ppc64" if machine == 21 and order == ">" else Backend.ELF_MACHINES.get(machine)
        if architecture is None:
            raise ValueError(f"unsupported ELF machine {machine}")
        if is_64:
            section_offset, = struct.unpack_from(order + "Q", data, 40)
            section_size, section_count = struct.unpack_from(order + "HH", data, 58)
        else:
            section_offset, = struct.unpack_from(order + "I", data, 32)
            section_size, section_count = struct.unpack_from(order + "HH", data, 46)
        sections = []
        for index in range(section_count):
            base = section_offset + index * section_size
            if is_64:
                kind, = struct.unpack_from(order + "I", data, base + 4)
                offset, size = struct.unpack_from(order + "QQ", data, base + 24)
                link, info = struct.unpack_from(order + "II", data, base + 40)
            else:
                kind, = struct.unpack_from(order + "I", data, base + 4)
                offset, size, link, info = struct.unpack_from(order + "IIII", data, base + 16)
            sections.append((kind, offset, size, link, info))
        newest = None
        for kind, offset, size, link, info in sections:
            if kind != 0x6FFFFFFE:  # SHT_GNU_verneed
                continue
            strings = sections[link][1]
            entry = offset
            for _ in range(info):
                _, count, _, auxiliary, following = struct.unpack_from(order + "HHIII", data, entry)
                position = entry + auxiliary
                for _ in range(count):
                    _, _, _, name, next_auxiliary = struct.unpack_from(order + "IHHII", data, position)
                    end = data.index(b"\0", strings + name)
                    version = data[strings + name:end].decode("ascii")
                    numbers = version[6:].split(".")[:2] if version.startswith("GLIBC_") else []
                    # GLIBC_PRIVATE and other names without a version number are skipped.
                    if len(numbers) == 2 and all(number.isdigit() for number in numbers):
                        parts = (int(numbers[0]), int(numbers[1]))
                        newest = parts if newest is None else max(newest, parts)
                    position += next_auxiliary
                entry += following
        if newest is None:
            # Not linked against glibc (for example musl): manylinux does not apply.
            raise ValueError(f"{library} requires no glibc version; pass the platform tag explicitly")
        newest = max(newest, Backend.MINIMUM_GLIBC)
        return f"manylinux_{newest[0]}_{newest[1]}_{architecture}"

    @staticmethod
    def platform_tag(library: Path | None, config_settings: dict[str, Any] | None) -> str:
        configured = Backend.setting(config_settings, "platform", "UMILIB_WHEEL_PLATFORM")
        if configured:
            return configured
        if library is None:
            return "any"
        tag = Backend.glibc_tag(library)
        if tag is None:
            raise ValueError(f"the platform of {library} cannot be derived; pass the platform tag explicitly")
        return tag

    @staticmethod
    def record_line(path: str, data: bytes) -> str:
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        return f"{path},sha256={digest},{len(data)}"

    @staticmethod
    def write_wheel(directory: str, files: dict[str, bytes], tag: str, pure: bool) -> str:
        project = Backend.project()
        version = project["version"]
        name = f"{Backend.PACKAGE}-{version}-{tag}.whl"
        dist_info = f"{Backend.PACKAGE}-{version}.dist-info"
        files = dict(files)
        files[f"{dist_info}/METADATA"] = Backend.metadata().encode("utf-8")
        files[f"{dist_info}/WHEEL"] = (
            "Wheel-Version: 1.0\nGenerator: umilib-backend\n"
            f"Root-Is-Purelib: {'true' if pure else 'false'}\nTag: {tag}\n"
        ).encode("utf-8")
        files[f"{dist_info}/licenses/LICENSE"] = Backend.license_file().read_bytes()
        record = [Backend.record_line(path, data) for path, data in files.items()]
        record.append(f"{dist_info}/RECORD,,")
        files[f"{dist_info}/RECORD"] = ("\n".join(record) + "\n").encode("utf-8")
        with zipfile.ZipFile(Path(directory) / name, "w", zipfile.ZIP_DEFLATED) as wheel:
            for path, data in files.items():
                member = zipfile.ZipInfo(path, date_time=Backend.TIMESTAMP)
                member.external_attr = 0o644 << 16
                member.compress_type = zipfile.ZIP_DEFLATED
                wheel.writestr(member, data)
        return name

    @staticmethod
    def build_wheel(wheel_directory: str, config_settings: dict[str, Any] | None = None, metadata_directory: str | None = None) -> str:
        files = {path.relative_to(Backend.ROOT).as_posix(): path.read_bytes() for path in Backend.sources()}
        configured = Backend.setting(config_settings, "library", "UMILIB_WHEEL_LIBRARY")
        library = Path(configured) if configured else None
        if library is not None:
            bundled = Backend.LIBRARY_NAMES.get(library.suffix)
            if bundled is None:
                raise ValueError(f"unknown shared library type: {library}")
            files[f"{Backend.PACKAGE}/ffi/{bundled}"] = library.read_bytes()
        platform = Backend.platform_tag(library, config_settings)
        return Backend.write_wheel(wheel_directory, files, f"py3-none-{platform}", library is None)

    @staticmethod
    def build_editable(wheel_directory: str, config_settings: dict[str, Any] | None = None, metadata_directory: str | None = None) -> str:
        files = {f"{Backend.PACKAGE}.pth": (str(Backend.ROOT) + "\n").encode("utf-8")}
        return Backend.write_wheel(wheel_directory, files, "py3-none-any", True)

    @staticmethod
    def build_sdist(sdist_directory: str, config_settings: dict[str, Any] | None = None) -> str:
        project = Backend.project()
        base = f"{Backend.PACKAGE}-{project['version']}"
        name = f"{base}.tar.gz"
        members = {"pyproject.toml": Backend.ROOT / "pyproject.toml", "backend.py": Backend.ROOT / "backend.py",
                   "README.md": Backend.ROOT / "README.md", "LICENSE": Backend.license_file()}
        for path in Backend.sources():
            members[path.relative_to(Backend.ROOT).as_posix()] = path
        with tarfile.open(Path(sdist_directory) / name, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            contents = {member: path.read_bytes() for member, path in members.items()}
            contents["PKG-INFO"] = Backend.metadata().encode("utf-8")
            for member, data in sorted(contents.items()):
                information = tarfile.TarInfo(f"{base}/{member}")
                information.size = len(data)
                information.mode = 0o644
                information.mtime = 315532800  # 1980-01-01, as in wheels
                archive.addfile(information, io.BytesIO(data))
        return name

    @staticmethod
    def get_requires_for_build_wheel(config_settings: dict[str, Any] | None = None) -> list[str]:
        return []

    @staticmethod
    def get_requires_for_build_editable(config_settings: dict[str, Any] | None = None) -> list[str]:
        return []

    @staticmethod
    def get_requires_for_build_sdist(config_settings: dict[str, Any] | None = None) -> list[str]:
        return []


build_wheel = Backend.build_wheel
build_editable = Backend.build_editable
build_sdist = Backend.build_sdist
get_requires_for_build_wheel = Backend.get_requires_for_build_wheel
get_requires_for_build_editable = Backend.get_requires_for_build_editable
get_requires_for_build_sdist = Backend.get_requires_for_build_sdist
