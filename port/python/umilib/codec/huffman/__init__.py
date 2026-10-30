"""Huffman coding: canonical prefix codes and adaptive Huffman coding. Mirrors ``umilib::codec::huffman``."""

from __future__ import annotations

from umilib.ffi import FFIError, Library


class HuffmanError(FFIError):
    """An error of a Huffman code; ``name`` is the variant, such as ``InvalidLengths``."""


Library.register_error("codec.huffman", HuffmanError)
