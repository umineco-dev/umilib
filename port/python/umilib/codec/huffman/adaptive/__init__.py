"""Adaptive Huffman coding by Vitter's algorithm, and a stream format of umilib that compresses with it.
Mirrors ``umilib::codec::huffman::adaptive``."""

from __future__ import annotations

import ctypes

from umilib.codec import Compressor, Decompressor
from umilib.ffi import U128, Handle

class AdaptiveHuffmanTree(Handle):
    """The code tree of Vitter's algorithm over an alphabet of ``symbols`` symbols."""

    PREFIX = "umilib_codec_huffman_adaptive_adaptive_huffman_tree"
    FREE = f"{PREFIX}_free"
    MAXIMUM_SYMBOLS = 1 << 15

    def __init__(self, symbols: int) -> None:
        super().__init__(Handle.create(f"{self.PREFIX}_new", symbols))

    def clone(self) -> AdaptiveHuffmanTree:
        tree = AdaptiveHuffmanTree.__new__(AdaptiveHuffmanTree)
        Handle.__init__(tree, Handle.create(f"{self.PREFIX}_clone", self.handle))
        return tree

    def symbols(self) -> int:
        return self.library.value(f"{self.PREFIX}_symbols", ctypes.c_size_t, self.handle)

    def code(self, symbol: int) -> tuple[int, int]:
        """The code of ``symbol`` in the current tree: its bits, the first the least significant, and their number."""
        bits, length = U128(), ctypes.c_uint32()
        self.library.call(f"{self.PREFIX}_code", self.handle, symbol, ctypes.byref(bits), ctypes.byref(length))
        return bits.to_int(), length.value

    def update(self, symbol: int) -> None:
        """Counts an occurrence of ``symbol`` and updates the tree."""
        self.library.call(f"{self.PREFIX}_update", self.handle, symbol)


class AdaptiveHuffmanCompressor(Compressor):
    """Compresses into the adaptive Huffman format of umilib."""

    PREFIX = "umilib_codec_huffman_adaptive_adaptive_huffman_compressor"

    def __init__(self) -> None:
        super().__init__(Handle.create(f"{self.PREFIX}_new"))


class AdaptiveHuffmanDecompressor(Decompressor):
    """Decompresses the adaptive Huffman format of umilib."""

    PREFIX = "umilib_codec_huffman_adaptive_adaptive_huffman_decompressor"

    def __init__(self) -> None:
        super().__init__(Handle.create(f"{self.PREFIX}_new"))


__all__ = ["AdaptiveHuffmanCompressor", "AdaptiveHuffmanDecompressor", "AdaptiveHuffmanTree"]
