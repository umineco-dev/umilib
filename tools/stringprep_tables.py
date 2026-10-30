#!/usr/bin/env python3
"""Writes ``src/codec/stringprep/tables.rs`` from the files of ``tests/vectors/codec/stringprep``:

- the tables of RFC 3454 appendices A to D (``rfc3454.txt``): sets of code
  points as sorted ranges, and the mappings of B.1, B.2 and B.3;
- the data of Unicode 3.2 (``UnicodeData-3.2.0.txt``,
  ``CompositionExclusions-3.2.0.txt``) that normalization needs: canonical
  combining classes as ranges, one level of decomposition of each code point
  (canonical or compatibility), and the primary composites;
- the combining marks of Unicode 3.2 (general categories Mn, Mc and Me) as
  ranges, which tell a space from a space followed by a combining mark
  (RFC 4518 section 2.6).

Uses only the standard library. Run from anywhere: ``python3 tools/stringprep_tables.py``.
"""

from __future__ import annotations

import re
from pathlib import Path


class StringPrepTables:
    ROOT = Path(__file__).resolve().parent.parent
    SOURCE = ROOT / "tests" / "vectors" / "codec" / "stringprep"
    OUTPUT = ROOT / "src" / "codec" / "stringprep" / "tables.rs"
    # The tables of RFC 3454 and their names in Rust.
    SETS = ["A.1", "C.1.1", "C.1.2", "C.2.1", "C.2.2", "C.3", "C.4", "C.5", "C.6", "C.7", "C.8", "C.9", "D.1", "D.2"]
    MAPPINGS = ["B.1", "B.2", "B.3"]

    @staticmethod
    def rfc_tables() -> dict[str, list[str]]:
        """The lines of each table of RFC 3454, without page breaks."""
        tables: dict[str, list[str]] = {}
        current = None
        for line in (StringPrepTables.SOURCE / "rfc3454.txt").read_text(encoding="ascii").splitlines():
            start = re.match(r"\s*----- Start Table (\S+) -----", line)
            if start:
                current = start.group(1)
                tables[current] = []
                continue
            if re.match(r"\s*----- End Table", line):
                current = None
                continue
            stripped = line.strip().lstrip("\f")
            if current is None or not stripped or stripped.startswith("RFC 3454") or stripped.startswith("Hoffman & Blanchet"):
                continue
            tables[current].append(stripped)
        return tables

    @staticmethod
    def ranges(lines: list[str]) -> list[tuple[int, int]]:
        """The merged, sorted ranges of the code points or ranges at the start of `lines`."""
        ranges = []
        for line in lines:
            field = line.split(";")[0].strip()
            low, _, high = field.partition("-")
            ranges.append((int(low, 16), int(high or low, 16)))
        ranges.sort()
        merged: list[tuple[int, int]] = []
        for low, high in ranges:
            if merged and low <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], high))
            else:
                merged.append((low, high))
        return merged

    @staticmethod
    def mapping(lines: list[str]) -> list[tuple[int, list[int]]]:
        entries = []
        for line in lines:
            source, target = line.split(";")[0:2]
            entries.append((int(source, 16), [int(point, 16) for point in target.split()]))
        entries.sort()
        return entries

    @staticmethod
    def unicode_data() -> tuple[list[tuple[int, int, int]], list[tuple[int, bool, list[int]]], dict[int, list[int]]]:
        """The combining classes as ranges, the decompositions, and the canonical ones by code point."""
        classes: dict[int, int] = {}
        decompositions = []
        canonical: dict[int, list[int]] = {}
        for line in (StringPrepTables.SOURCE / "UnicodeData-3.2.0.txt").read_text(encoding="ascii").splitlines():
            fields = line.split(";")
            point = int(fields[0], 16)
            if int(fields[3]):
                classes[point] = int(fields[3])
            if fields[5]:
                parts = fields[5].split()
                compatibility = parts[0].startswith("<")
                targets = [int(part, 16) for part in (parts[1:] if compatibility else parts)]
                decompositions.append((point, compatibility, targets))
                if not compatibility:
                    canonical[point] = targets
        ranges: list[tuple[int, int, int]] = []
        for point in sorted(classes):
            if ranges and ranges[-1][1] + 1 == point and ranges[-1][2] == classes[point]:
                ranges[-1] = (ranges[-1][0], point, classes[point])
            else:
                ranges.append((point, point, classes[point]))
        return ranges, decompositions, canonical

    @staticmethod
    def combining_marks() -> list[tuple[int, int]]:
        marks = []
        lines = (StringPrepTables.SOURCE / "UnicodeData-3.2.0.txt").read_text(encoding="ascii").splitlines()
        for line in lines:
            fields = line.split(";")
            if fields[2].startswith("M"):
                marks.append(f"{fields[0]}")
        return StringPrepTables.ranges(marks)

    @staticmethod
    def compositions(canonical: dict[int, list[int]], classes: list[tuple[int, int, int]]) -> list[tuple[int, int, int]]:
        """The primary composites: canonical decompositions of two code points, the first a starter,
        less the composition exclusions (UAX #15 version 3.2, section 5)."""
        exclusions = set()
        for line in (StringPrepTables.SOURCE / "CompositionExclusions-3.2.0.txt").read_text(encoding="utf-8").splitlines():
            field = line.split("#")[0].strip()
            if field:
                exclusions.add(int(field, 16))
        nonstarters = {point for low, high, _ in classes for point in range(low, high + 1)}
        pairs = []
        for point, targets in canonical.items():
            if len(targets) == 2 and point not in exclusions and point not in nonstarters and targets[0] not in nonstarters:
                pairs.append((targets[0], targets[1], point))
        pairs.sort()
        return pairs

    @staticmethod
    def text(points: list[int]) -> str:
        return '"' + "".join(f"\\u{{{point:X}}}" for point in points) + '"'

    @staticmethod
    def write() -> None:
        tables = StringPrepTables.rfc_tables()
        classes, decompositions, canonical = StringPrepTables.unicode_data()
        compositions = StringPrepTables.compositions(canonical, classes)
        out = [
            "// Generated by tools/stringprep_tables.py from tests/vectors/codec/stringprep; do not edit.",
            "//",
            "// The tables of RFC 3454 (IETF Trust Legal Provisions) and data derived from the Unicode",
            "// Character Database 3.2.0, Copyright (c) 1991-2026 Unicode, Inc., distributed under the",
            "// Unicode License v3 (tests/vectors/codec/stringprep/LICENSE-UNICODE.txt).",
            "",
            "use super::{LDAPPrep, NormalizationForm, StringPrepTable};",
            "",
            "impl StringPrepTable {",
        ]
        for name in StringPrepTables.SETS:
            ranges = StringPrepTables.ranges(tables[name])
            constant = name.replace(".", "")
            out.append(f"    /// The ranges of table {name} of RFC 3454.")
            out.append(f"    pub const {constant}_RANGES: &'static [(u32, u32)] = &[")
            out.extend(f"        (0x{low:04X}, 0x{high:04X})," for low, high in ranges)
            out.append("    ];")
        for name in StringPrepTables.MAPPINGS:
            entries = StringPrepTables.mapping(tables[name])
            constant = name.replace(".", "")
            out.append(f"    /// The mappings of table {name} of RFC 3454, by code point.")
            out.append(f"    pub const {constant}_MAPPINGS: &'static [(u32, &'static str)] = &[")
            out.extend(f"        (0x{point:04X}, {StringPrepTables.text(target)})," for point, target in entries)
            out.append("    ];")
        out.append("}")
        out.append("")
        out.append("impl NormalizationForm {")
        out.append("    /// The canonical combining classes other than 0 of Unicode 3.2, as ranges of one class.")
        out.append("    pub const COMBINING_CLASSES: &'static [(u32, u32, u8)] = &[")
        out.extend(f"        (0x{low:04X}, 0x{high:04X}, {value})," for low, high, value in classes)
        out.append("    ];")
        out.append("    /// The decomposition mappings of Unicode 3.2 (one level), by code point, with whether each is a")
        out.append("    /// compatibility one. Hangul syllables are decomposed by algorithm.")
        out.append("    pub const DECOMPOSITIONS: &'static [(u32, bool, &'static str)] = &[")
        out.extend(
            f"        (0x{point:04X}, {'true' if compatibility else 'false'}, {StringPrepTables.text(targets)}),"
            for point, compatibility, targets in sorted(decompositions)
        )
        out.append("    ];")
        out.append("    /// The primary composites of Unicode 3.2: the starter, the code point that follows it and the")
        out.append("    /// composite, sorted by the pair. Hangul syllables are composed by algorithm.")
        out.append("    pub const COMPOSITIONS: &'static [(u32, u32, u32)] = &[")
        out.extend(f"        (0x{first:04X}, 0x{second:04X}, 0x{composite:04X})," for first, second, composite in compositions)
        out.append("    ];")
        out.append("}")
        out.append("")
        out.append("impl LDAPPrep {")
        out.append("    /// The combining marks of Unicode 3.2 (general categories Mn, Mc and Me), as ranges.")
        out.append("    pub const COMBINING_MARKS: &'static [(u32, u32)] = &[")
        out.extend(f"        (0x{low:04X}, 0x{high:04X})," for low, high in StringPrepTables.combining_marks())
        out.append("    ];")
        out.append("}")
        StringPrepTables.OUTPUT.write_text("\n".join(out) + "\n", encoding="utf-8")
        print(f"wrote {StringPrepTables.OUTPUT} ({len(compositions)} compositions, {len(decompositions)} decompositions)")


if __name__ == "__main__":
    StringPrepTables.write()
