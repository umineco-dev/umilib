"""Access to the test vectors in ``tests/vectors`` of the repository, shared by the tests: the records of
the NIST CAVP response files (and of the files extracted from specifications in the same format), the
tests of Project Wycheproof and the examples of the GM/T standards."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[3] / "tests" / "vectors"


@dataclass
class Record:
    """One record of a response file: its fields in order and the bracketed headers in force for it."""

    header: dict[str, str] = field(default_factory=dict)
    fields: list[tuple[str, str]] = field(default_factory=list)

    @staticmethod
    def all(path: str) -> list[Record]:
        """The records of ``path``: ``Key = Value`` lines separated by blank lines, under ``[Key = Value]``
        or ``[Name]`` headers."""
        records: list[Record] = []
        header: dict[str, str] = {}
        fresh = False
        current = Record()
        for line in (ROOT / path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("#"):
                continue
            if not line:
                if current.fields:
                    records.append(current)
                    current = Record()
                continue
            if line.startswith("[") and line.endswith("]"):
                if not fresh:
                    header, fresh = {}, True
                key, _, value = line[1:-1].partition("=")
                header[key.strip()] = value.strip()
                continue
            fresh = False
            key, _, value = line.partition("=")
            current.header = dict(header)
            current.fields.append((key.strip(), value.strip()))
        if current.fields:
            records.append(current)
        return records

    def get(self, key: str) -> str | None:
        return next((value for name, value in self.fields if name == key), None)

    def field(self, key: str) -> str:
        value = self.get(key)
        if value is None:
            raise KeyError(f"no field {key} in {self.fields}")
        return value

    def values(self, key: str) -> list[str]:
        return [value for name, value in self.fields if name == key]

    def bytes(self, key: str) -> bytes:
        return bytes.fromhex(self.field(key))


class Wycheproof:
    """The tests of a Project Wycheproof file, each with its group."""

    @staticmethod
    def tests(path: str) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
        document = json.loads((ROOT / path).read_text(encoding="utf-8"))
        for group in document["testGroups"]:
            for test in group["tests"]:
                yield group, test

    @staticmethod
    def bytes(test: dict[str, Any], key: str) -> bytes:
        return bytes.fromhex(test[key])

    @staticmethod
    def valid(test: dict[str, Any]) -> bool:
        return test["result"] == "valid"


class GMT:
    """The examples of the GM/T standards, whose values are located by the English text before them,
    since the text layer of the documents loses the symbols ("?" in the extractions)."""

    def __init__(self, text: str) -> None:
        self.text = text

    @staticmethod
    def read(path: str) -> GMT:
        """The text of ``path`` without its page breaks: the "=== page" marker of the extraction and the
        page number on the line after it."""
        kept, skip = [], False
        for line in (ROOT / path).read_text(encoding="utf-8").splitlines():
            if line.startswith("=== page"):
                skip = True
                continue
            if skip:
                skip = False
                continue
            kept.append(line)
        return GMT("\n".join(kept))

    def section(self, start: str, end: str) -> GMT:
        """The part of the text from ``start`` to ``end``, both texts that occur in it."""
        begin = self.text.index(start)
        return GMT(self.text[begin : self.text.index(end, begin)])

    def after(self, start: str) -> GMT:
        """The part of the text from ``start`` to its end."""
        return GMT(self.text[self.text.index(start) :])

    def values(self, label: str, count: int) -> list[bytes]:
        """The ``count`` values after the first ``label``: runs of hexadecimal words, a value ending at a
        comma, a closing parenthesis, a word that is not hexadecimal or the end of the text."""
        start = self.text.index(label) + len(label)
        values: list[bytes] = []
        current = ""
        # "." after the last word ends the value the text ends with.
        for token in [*self.text[start:].split(), "."]:
            word = token.lstrip("(").rstrip(",)")
            hexadecimal = bool(word) and all(c in "0123456789abcdefABCDEF" for c in word)
            if hexadecimal:
                current += word
            if (not hexadecimal or token.endswith((",", ")"))) and current:
                values.append(bytes.fromhex(current if len(current) % 2 == 0 else "0" + current))
                current = ""
                if len(values) == count:
                    return values
        raise AssertionError(f"{label}: {len(values)} of {count} values")

    def value(self, label: str) -> bytes:
        return self.values(label, 1)[0]

    def padded(self, label: str, length: int) -> bytes:
        """The value after ``label`` with zeros before it up to ``length`` bytes, as the examples print
        integers without their leading zeros."""
        value = self.value(label)
        assert len(value) <= length, f"{label}: {len(value)} bytes"
        return value.rjust(length, b"\0")
