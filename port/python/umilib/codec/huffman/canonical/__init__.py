"""Canonical prefix codes (RFC 1951 section 3.2.2), their decoding tables, and a block format of umilib
that compresses with them. Mirrors ``umilib::codec::huffman::canonical``."""

from __future__ import annotations

import ctypes

from umilib.bytes import BitOrder
from umilib.codec import Compressor, Decompressor
from umilib.codec.huffman import HuffmanError
from umilib.ffi import Handle, Library



class HuffmanCode(Handle):
    """A canonical prefix code, defined by the lengths of the codes of the symbols 0, 1, ..."""

    PREFIX = "umilib_codec_huffman_canonical_huffman_code"
    FREE = f"{PREFIX}_free"
    MAXIMUM_LENGTH = 15
    MAXIMUM_SYMBOLS = 1 << 15

    @classmethod
    def from_pointer(cls, pointer: int) -> HuffmanCode:
        code = cls.__new__(cls)
        Handle.__init__(code, pointer)
        return code

    @classmethod
    def from_lengths(cls, lengths: bytes | list[int]) -> HuffmanCode:
        """The code of ``lengths``; raises ``InvalidLengths`` if they are over-subscribed."""
        data = bytes(lengths)
        return cls.from_pointer(Handle.create(f"{cls.PREFIX}_from_lengths", data, len(data)))

    @classmethod
    def from_frequencies(cls, frequencies: list[int], maximum_length: int) -> HuffmanCode:
        """An optimal code of ``frequencies`` with lengths at most ``maximum_length``."""
        array = (ctypes.c_uint32 * len(frequencies))(*frequencies)
        return cls.from_pointer(Handle.create(f"{cls.PREFIX}_from_frequencies", array, len(frequencies), maximum_length))

    @staticmethod
    def lengths_from_frequencies(frequencies: list[int], maximum_length: int) -> bytes:
        """The lengths :meth:`from_frequencies` assigns."""
        array = (ctypes.c_uint32 * len(frequencies))(*frequencies)
        return Library.default().output(f"{HuffmanCode.PREFIX}_lengths_from_frequencies", array, len(frequencies), maximum_length)

    def symbols(self) -> int:
        return self.library.value(f"{self.PREFIX}_symbols", ctypes.c_size_t, self.handle)

    def lengths(self) -> bytes:
        return self.library.output(f"{self.PREFIX}_lengths", self.handle)

    def length(self, symbol: int) -> int:
        """The length of the code of ``symbol``; 0 if it has none."""
        return self.library.value(f"{self.PREFIX}_length", ctypes.c_uint32, self.handle, symbol)

    def code(self, symbol: int) -> int:
        """The code of ``symbol``, its first bit the most significant of its length."""
        return self.library.value(f"{self.PREFIX}_code", ctypes.c_uint32, self.handle, symbol)

    def reversed_code(self, symbol: int) -> int:
        """The code of ``symbol`` with its bits reversed, its first bit the least significant."""
        return self.library.value(f"{self.PREFIX}_reversed_code", ctypes.c_uint32, self.handle, symbol)

    def maximum_length(self) -> int:
        return self.library.value(f"{self.PREFIX}_maximum_length", ctypes.c_uint32, self.handle)

    def is_complete(self) -> bool:
        """Whether the codes use every sequence of bits."""
        return self.library.value(f"{self.PREFIX}_is_complete", ctypes.c_bool, self.handle)


class HuffmanTable(Handle):
    """A table that decodes the codes of a :class:`HuffmanCode` from streams of a bit order."""

    PREFIX = "umilib_codec_huffman_canonical_huffman_table"
    FREE = f"{PREFIX}_free"

    def __init__(self, code: HuffmanCode, order: BitOrder) -> None:
        super().__init__(Handle.create(f"{self.PREFIX}_new", code, int(order)))

    def peek_bits(self) -> int:
        """The bits to peek before :meth:`decode`: the longest code."""
        return self.library.value(f"{self.PREFIX}_peek_bits", ctypes.c_uint32, self.handle)

    def decode(self, bits: int) -> tuple[int, int]:
        """The symbol and the length of the code at the start of ``bits``; raises ``InvalidCode`` if none."""
        symbol, length = ctypes.c_uint16(), ctypes.c_uint32()
        self.library.call(f"{self.PREFIX}_decode", self.handle, bits, ctypes.byref(symbol), ctypes.byref(length))
        return symbol.value, length.value


class CanonicalHuffmanConfig:
    """The parameters of a :class:`CanonicalHuffmanCompressor`."""

    def __init__(self, block_size: int | None = None) -> None:
        if block_size is None:
            block_size = Library.default().value("umilib_codec_huffman_canonical_canonical_huffman_config_default_block_size", ctypes.c_size_t)
        #: The most input bytes of a block, at least 1.
        self.block_size = block_size


class CanonicalHuffmanCompressor(Compressor):
    """Compresses into the block format of canonical Huffman codes of umilib."""

    PREFIX = "umilib_codec_huffman_canonical_canonical_huffman_compressor"

    def __init__(self, config: CanonicalHuffmanConfig | None = None) -> None:
        config = config or CanonicalHuffmanConfig()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.block_size))


class CanonicalHuffmanDecompressor(Decompressor):
    """Decompresses the block format of canonical Huffman codes of umilib."""

    PREFIX = "umilib_codec_huffman_canonical_canonical_huffman_decompressor"

    def __init__(self) -> None:
        super().__init__(Handle.create(f"{self.PREFIX}_new"))


__all__ = [
    "CanonicalHuffmanCompressor",
    "CanonicalHuffmanConfig",
    "CanonicalHuffmanDecompressor",
    "HuffmanCode",
    "HuffmanError",
    "HuffmanTable",
]
