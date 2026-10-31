"""Finite State Entropy (tANS, RFC 8878 section 4.1): normalized distributions, their table descriptions, and
their decoding and encoding tables. Mirrors ``umilib::codec::fse``."""

from __future__ import annotations

import ctypes

from umilib.ffi import Bytes, Handle, Library


class FSEDistribution(Handle):
    """A normalized distribution: the probabilities of the symbols 0 to the last present one on a scale of
    2^accuracy_log, -1 meaning "less than 1" (counted as 1)."""

    PREFIX = "umilib_codec_fse_fse_distribution"
    FREE = f"{PREFIX}_free"
    MINIMUM_LOG = 5
    MAXIMUM_LOG = 15
    MAXIMUM_SYMBOLS = 256

    @classmethod
    def from_pointer(cls, pointer: int) -> FSEDistribution:
        distribution = cls.__new__(cls)
        Handle.__init__(distribution, pointer)
        return distribution

    def __init__(self, accuracy_log: int, probabilities: list[int]) -> None:
        """Raises ``InvalidParameter`` unless the probabilities add up to the scale."""
        array = (ctypes.c_int16 * len(probabilities))(*probabilities)
        super().__init__(Handle.create(f"{self.PREFIX}_new", accuracy_log, array, len(probabilities)))

    @classmethod
    def read(cls, data: bytes, maximum_log: int, maximum_symbols: int) -> tuple[FSEDistribution, int]:
        """Reads a table description from the start of ``data``: the distribution and the bytes it took."""
        pointer, length = Bytes.readable(data)
        out, used = ctypes.c_void_p(), ctypes.c_size_t()
        Library.default().call(
            f"{cls.PREFIX}_read", pointer, length, maximum_log, maximum_symbols, ctypes.byref(out), ctypes.byref(used),
        )
        return cls.from_pointer(out.value), used.value

    @classmethod
    def normalize(cls, counts: list[int], accuracy_log: int) -> FSEDistribution:
        """The distribution of ``counts`` (2 or more present symbols) on a scale of 2^accuracy_log."""
        array = (ctypes.c_uint32 * len(counts))(*counts)
        return cls.from_pointer(Handle.create(f"{cls.PREFIX}_normalize", array, len(counts), accuracy_log))

    @property
    def accuracy_log(self) -> int:
        return self.library.value(f"{self.PREFIX}_accuracy_log", ctypes.c_uint32, self.handle)

    @property
    def probabilities(self) -> list[int]:
        count = self.library.value(f"{self.PREFIX}_symbols", ctypes.c_size_t, self.handle)
        return [self.library.value(f"{self.PREFIX}_probability", ctypes.c_int16, self.handle, symbol) for symbol in range(count)]

    def write(self) -> bytes:
        """The table description."""
        return self.library.output(f"{self.PREFIX}_write", self.handle)

    def spread(self) -> bytes:
        """The symbol of each table position."""
        return self.library.output(f"{self.PREFIX}_spread", self.handle)


class FSEDecodingTable(Handle):
    """The decoding table of a distribution: per state, its symbol, and the bits to read and the baseline to add
    for the next state."""

    PREFIX = "umilib_codec_fse_fse_decoding_table"
    FREE = f"{PREFIX}_free"

    def __init__(self, distribution: FSEDistribution) -> None:
        super().__init__(Handle.create(f"{self.PREFIX}_new", distribution))

    @classmethod
    def single(cls, symbol: int) -> FSEDecodingTable:
        """The table of a single symbol: one state, no bits."""
        table = cls.__new__(cls)
        Handle.__init__(table, Handle.create(f"{cls.PREFIX}_single", symbol))
        return table

    @property
    def accuracy_log(self) -> int:
        return self.library.value(f"{self.PREFIX}_accuracy_log", ctypes.c_uint32, self.handle)

    def entry(self, state: int) -> tuple[int, int, int]:
        """The symbol, the bits and the baseline of ``state``."""
        symbol, bits, baseline = ctypes.c_uint8(), ctypes.c_uint8(), ctypes.c_uint16()
        self.library.call(f"{self.PREFIX}_entry", self.handle, state, ctypes.byref(symbol), ctypes.byref(bits), ctypes.byref(baseline))
        return symbol.value, bits.value, baseline.value


class FSEEncodingTable(Handle):
    """The encoding table of a distribution: encoder states are decoder states plus 2^accuracy_log, and symbols
    are encoded from the last decoded to the first."""

    PREFIX = "umilib_codec_fse_fse_encoding_table"
    FREE = f"{PREFIX}_free"

    def __init__(self, distribution: FSEDistribution) -> None:
        super().__init__(Handle.create(f"{self.PREFIX}_new", distribution))

    @property
    def accuracy_log(self) -> int:
        return self.library.value(f"{self.PREFIX}_accuracy_log", ctypes.c_uint32, self.handle)

    def initial_state(self, symbol: int) -> int:
        """The first state, for the symbol decoded last."""
        return self.library.value(f"{self.PREFIX}_initial_state", ctypes.c_uint32, self.handle, symbol)

    def transition(self, state: int, symbol: int) -> tuple[int, int]:
        """The number of low bits of ``state`` to write for ``symbol``, and the state before it."""
        bits, previous = ctypes.c_uint32(), ctypes.c_uint32()
        self.library.call(f"{self.PREFIX}_transition", self.handle, state, symbol, ctypes.byref(bits), ctypes.byref(previous))
        return bits.value, previous.value


__all__ = ["FSEDecodingTable", "FSEDistribution", "FSEEncodingTable"]
