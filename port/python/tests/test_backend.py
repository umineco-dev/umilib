"""Tests of the build backend: wheels follow the binary distribution format
(PEP 427 / the wheel specification) and sdists contain the sources."""

import base64
import hashlib
import sys
import tarfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import backend  # noqa: E402


def test_pure_wheel_has_a_valid_record(tmp_path):
    name = backend.build_wheel(str(tmp_path))
    assert name.endswith("-py3-none-any.whl")
    with zipfile.ZipFile(tmp_path / name) as wheel:
        files = set(wheel.namelist())
        version = backend.Backend.project()["version"]
        dist_info = f"umilib-{version}.dist-info"
        assert {f"{dist_info}/METADATA", f"{dist_info}/WHEEL", f"{dist_info}/RECORD", "umilib/__init__.py", "umilib/ffi/__init__.py"} <= files
        assert "Root-Is-Purelib: true" in wheel.read(f"{dist_info}/WHEEL").decode()
        for line in wheel.read(f"{dist_info}/RECORD").decode().splitlines():
            path, digest, size = line.split(",")
            if path.endswith("RECORD"):
                assert digest == "" and size == ""
                continue
            data = wheel.read(path)
            expected = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            assert digest == f"sha256={expected}" and int(size) == len(data)


def test_wheel_bundles_the_library(tmp_path):
    library = tmp_path / "libumilib.so"
    library.write_bytes(b"not really a library")
    name = backend.build_wheel(str(tmp_path), {"library": str(library), "platform": "linux_x86_64"})
    assert name.endswith("-py3-none-linux_x86_64.whl")
    with zipfile.ZipFile(tmp_path / name) as wheel:
        assert wheel.read("umilib/ffi/libumilib.so") == b"not really a library"


def test_sdist_contains_the_sources(tmp_path):
    name = backend.build_sdist(str(tmp_path))
    with tarfile.open(tmp_path / name) as archive:
        names = archive.getnames()
    base = name.removesuffix(".tar.gz")
    assert {f"{base}/pyproject.toml", f"{base}/backend.py", f"{base}/PKG-INFO", f"{base}/umilib/__init__.py", f"{base}/LICENSE"} <= set(names)


def test_glibc_tag_reads_version_requirements():
    import os

    library = Path(os.environ.get("UMILIB_LIBRARY_PATH", ""))
    if library.suffix == ".so" and library.is_file():
        tag = backend.Backend.glibc_tag(library)
        assert tag.startswith("manylinux_2_")
    assert backend.Backend.glibc_tag(Path(__file__)) is None
