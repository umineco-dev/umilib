"""Binary-to-text encodings. Mirrors ``umilib::codec::base``.

Presets are class attributes (``Base64.STANDARD``) created on first use.
Alphabets are static objects of the library; custom alphabets can only be
built in Rust, because they borrow ``'static`` data.
"""

from __future__ import annotations

import contextlib
import ctypes
import enum
from dataclasses import dataclass

from umilib.ffi import Bytes, FFIError, Handle, Library, Preset


class BaseError(FFIError):
    """An error of a binary-to-text encoding; ``name`` is the variant, such as ``NonCanonical``."""


Library.register_error("codec.base", BaseError)


class Padding(enum.IntEnum):
    """How an encoding treats the padding that completes its last group."""

    Required = 0
    Forbidden = 1
    Indifferent = 2


@dataclass(frozen=True)
class AlphabetRange:
    """A run of ``count`` consecutive characters from ``first``, encoding values from ``value``."""

    first: int
    count: int
    value: int
    canonical: bool = True

    @classmethod
    def new(cls, first: int, count: int, value: int) -> AlphabetRange:
        return cls(first, count, value, True)

    @classmethod
    def decode_only(cls, first: int, count: int, value: int) -> AlphabetRange:
        return cls(first, count, value, False)


class Alphabet:
    """The characters of an encoding: a static object of the library, or the
    copy inside a :class:`BitEncoding`, which ``owner`` keeps alive. Every use
    of such a copy holds the lock of its encoding and fails once the encoding
    is closed."""

    def __init__(self, pointer: int, owner: Handle | None = None) -> None:
        if not pointer:
            raise FFIError("ffi", "NullPointer", "the library returned a null alphabet")
        self.pointer = pointer
        self.owner = owner

    @classmethod
    def static(cls, function: str) -> Alphabet:
        return cls(Library.default().function(function)())

    def holding(self) -> contextlib.AbstractContextManager[object]:
        """The lock of the encoding that owns the alphabet, if any, for one use of the pointer."""
        return self.owner.locked() if self.owner is not None else contextlib.nullcontext()

    def size(self) -> int:
        with self.holding():
            return Library.default().value("umilib_codec_base_alphabet_size", ctypes.c_size_t, self.pointer)

    def encode(self, value: int) -> int:
        with self.holding():
            return Library.default().value("umilib_codec_base_alphabet_encode", ctypes.c_uint8, self.pointer, value)

    def decode(self, character: int) -> int | None:
        valid, value = ctypes.c_bool(), ctypes.c_uint8()
        with self.holding():
            Library.default().call("umilib_codec_base_alphabet_decode", self.pointer, character, ctypes.byref(valid), ctypes.byref(value))
        return value.value if valid.value else None

    @property
    def ranges(self) -> list[AlphabetRange]:
        library = Library.default()
        ranges = []
        with self.holding():
            count = library.value("umilib_codec_base_alphabet_range_count", ctypes.c_size_t, self.pointer)
            for index in range(count):
                out = library.type("umilib_codec_base_AlphabetRange")()
                library.call("umilib_codec_base_alphabet_ranges", self.pointer, index, ctypes.byref(out))
                ranges.append(AlphabetRange(out.first, out.count, out.value, out.canonical))
        return ranges

    @staticmethod
    def mask_in(value: int, start: int, count: int) -> int:
        return Library.default().function("umilib_codec_base_alphabet_mask_in")(value, start, count)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Alphabet) and self.ranges == other.ranges


class Encoding(Handle):
    """A binary-to-text encoding. ``PREFIX`` names its C functions."""

    PREFIX = ""

    def maximum_encoded_length(self, length: int) -> int | None:
        has_length, out = ctypes.c_bool(), ctypes.c_size_t()
        self.library.call(f"{self.PREFIX}_maximum_encoded_length", self.handle, length, ctypes.byref(has_length), ctypes.byref(out))
        return out.value if has_length.value else None

    def maximum_decoded_length(self, length: int) -> int:
        return self.library.value(f"{self.PREFIX}_maximum_decoded_length", ctypes.c_size_t, self.handle, length)

    def encode_to_slice(self, data: bytes, output: bytearray) -> int:
        """Encodes ``data`` into the start of ``output`` and returns the number of characters."""
        data, length = Bytes.readable(data)
        return self.library.value(f"{self.PREFIX}_encode_to_slice", ctypes.c_size_t, self.handle, data, length, Bytes.mutable(output), len(output))

    def decode_to_slice(self, data: bytes, output: bytearray) -> int:
        """Decodes ``data`` into the start of ``output`` and returns the number of bytes."""
        data, length = Bytes.readable(data)
        return self.library.value(f"{self.PREFIX}_decode_to_slice", ctypes.c_size_t, self.handle, data, length, Bytes.mutable(output), len(output))

    def try_encode(self, data: bytes) -> str:
        data, length = Bytes.readable(data)
        return self.library.output(f"{self.PREFIX}_try_encode", self.handle, data, length).decode("ascii")

    def encode(self, data: bytes) -> str:
        data, length = Bytes.readable(data)
        return self.library.output(f"{self.PREFIX}_encode", self.handle, data, length).decode("ascii")

    def decode(self, text: str | bytes) -> bytes:
        data = text.encode("ascii") if isinstance(text, str) else text
        data, length = Bytes.readable(data)
        return self.library.output(f"{self.PREFIX}_decode", self.handle, data, length)


class BitEncoding(Encoding):
    """An encoding of ``bits`` bits per character (RFC 4648): the engine of Base16, Base32 and Base64."""

    FREE = "umilib_codec_base_bit_encoding_free"
    PREFIX = "umilib_codec_base_bit_encoding"

    def __init__(self, alphabet: Alphabet | None = None, bits: int = 0, padding: Padding = Padding.Required,
                 padding_character: int = ord("="), pointer: int | None = None) -> None:
        if pointer is None:
            if alphabet is None:
                raise TypeError("BitEncoding needs an alphabet")
            with alphabet.holding():
                pointer = Handle.create("umilib_codec_base_bit_encoding_new", alphabet.pointer, bits, int(padding), padding_character)
        super().__init__(pointer)

    def parameters(self) -> tuple[int, Padding, int]:
        bits, padding, character = ctypes.c_uint32(), ctypes.c_uint8(), ctypes.c_uint8()
        self.library.call(f"{self.PREFIX}_parameters", self.handle, ctypes.byref(bits), ctypes.byref(padding), ctypes.byref(character))
        return bits.value, Padding(padding.value), character.value

    @property
    def alphabet(self) -> Alphabet:
        return Alphabet(self.library.value(f"{self.PREFIX}_alphabet", ctypes.c_void_p, self.handle), owner=self)

    @property
    def bits(self) -> int:
        return self.parameters()[0]

    @property
    def padding(self) -> Padding:
        return self.parameters()[1]

    @property
    def padding_character(self) -> int:
        return self.parameters()[2]

    def is_valid(self) -> bool:
        """Whether the fields form an encoding: 1 to 7 bits, an alphabet of ``2^bits``
        characters and a padding character outside it."""
        return self.library.value(f"{self.PREFIX}_is_valid", ctypes.c_bool, self.handle)

    def group_characters(self) -> int:
        return self.library.value(f"{self.PREFIX}_group_characters", ctypes.c_size_t, self.handle)

    def group_bytes(self) -> int:
        return self.library.value(f"{self.PREFIX}_group_bytes", ctypes.c_size_t, self.handle)

    def is_valid_remainder(self, remainder: int) -> bool:
        return self.library.value(f"{self.PREFIX}_is_valid_remainder", ctypes.c_bool, self.handle, remainder)


__all__ = ["Alphabet", "AlphabetRange", "BaseError", "BitEncoding", "Encoding", "Padding", "Preset"]
