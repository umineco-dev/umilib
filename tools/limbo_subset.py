#!/usr/bin/env python3
"""Writes ``tests/vectors/auth/cert/path/limbo/limbo.json``, the subset of
x509-limbo (https://github.com/C2SP/x509-limbo, Apache License 2.0) the
tests of ``auth-cert-path`` run: every test case that is not from the
BetterTLS name constraints suite, and every 16th of that suite (its cases
differ in the names they combine). Run with the full ``limbo.json`` of
x509-limbo: ``python3 tools/limbo_subset.py path/to/limbo.json``. Uses only
the standard library. The tests run the full file instead when
``UMILIB_LIMBO`` names it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


class LimboSubset:
    OUTPUT = Path(__file__).resolve().parent.parent / "tests" / "vectors" / "auth" / "cert" / "path" / "limbo" / "limbo.json"
    SAMPLE = 16

    @staticmethod
    def keep(case: dict) -> bool:
        identifier = case["id"]
        if not identifier.startswith("bettertls::nameconstraints::"):
            return True
        return int(identifier.rsplit("tc", 1)[1]) % LimboSubset.SAMPLE == 0

    @staticmethod
    def write(source: Path) -> None:
        document = json.loads(source.read_text(encoding="utf-8"))
        cases = [case for case in document["testcases"] if LimboSubset.keep(case)]
        subset = {"version": document["version"], "testcases": cases}
        LimboSubset.OUTPUT.write_text(json.dumps(subset, indent=1) + "\n", encoding="utf-8")
        print(f"wrote {len(cases)} of {len(document['testcases'])} test cases to {LimboSubset.OUTPUT}")


if __name__ == "__main__":
    LimboSubset.write(Path(sys.argv[1]))
