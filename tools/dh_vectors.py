#!/usr/bin/env python3
"""Writes ``tests/vectors/crypto/dh/python.txt``: Diffie-Hellman exchanges in
the groups of RFC 7919 and RFC 3526 computed with Python's integers, which
serve the Rust tests of ``umilib::crypto::dh`` as an oracle independent of the
code under test.

The primes are read from the RFC texts in ``tests/vectors``. Every line is
``group x_a x_b y_a y_b z`` in hexadecimal, the public keys and the shared
secret written in the bytes of p. The exponents are drawn from a fixed seed,
so running the script again writes the same file. Uses only the standard
library.
"""

from __future__ import annotations

import random
import re
from pathlib import Path


class DHVectors:
    ROOT = Path(__file__).resolve().parent.parent
    OUTPUT = ROOT / "tests" / "vectors" / "crypto" / "dh" / "python.txt"
    RFC7919 = ROOT / "tests" / "vectors" / "crypto" / "dh" / "rfc7919.txt"
    RFC3526 = ROOT / "tests" / "vectors" / "math" / "modular" / "rfc3526.txt"
    EXCHANGES = 3

    def __init__(self) -> None:
        self.random = random.Random(20261024)

    @staticmethod
    def hexadecimal(text: str) -> int:
        """The integer of the groups of eight hexadecimal digits of ``text``, page breaks removed."""
        lines = [line for line in text.splitlines() if not re.match(r"^(RFC \d+|\S.*\[Page \d+\])", line)]
        return int("".join(re.findall(r"\b[0-9A-F]{8}\b", "\n".join(lines))), 16)

    def groups(self) -> list[tuple[str, int]]:
        groups = []
        text = self.RFC7919.read_text(encoding="utf-8")
        for index, bits in enumerate([2048, 3072, 4096, 6144, 8192]):
            section = text[text.index(f"\nA.{index + 1}.  ffdhe{bits}\n") :]
            start = section.index("The hexadecimal representation of p is:")
            end = section.index("The generator is: g = 2", start)
            groups.append((f"ffdhe{bits}", self.hexadecimal(section[start:end])))
        text = self.RFC3526.read_text(encoding="utf-8")
        for bits in [1536, 2048, 3072, 4096, 6144, 8192]:
            section = text[text.index(f"{bits}-bit MODP Group\n") :]
            start = section.index("Its hexadecimal value is:")
            end = section.index("The generator is: 2", start)
            groups.append((f"modp{bits}", self.hexadecimal(section[start:end])))
        for name, prime in groups:
            assert prime.bit_length() == int(name[-4:]), name
        return groups

    def write(self) -> None:
        lines = []
        for name, prime in self.groups():
            size = (prime.bit_length() + 7) // 8
            order = (prime - 1) // 2
            for _ in range(self.EXCHANGES):
                a, b = self.random.randrange(1, order), self.random.randrange(1, order)
                y_a, y_b = pow(2, a, prime), pow(2, b, prime)
                z = pow(y_b, a, prime)
                assert z == pow(y_a, b, prime)
                values = [a.to_bytes(size, "big"), b.to_bytes(size, "big")]
                values += [value.to_bytes(size, "big") for value in (y_a, y_b, z)]
                lines.append(" ".join([name] + [value.hex() for value in values]))
        self.OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    DHVectors().write()
