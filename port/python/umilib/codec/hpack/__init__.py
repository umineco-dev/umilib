"""HPACK (RFC 7541): the field compression of HTTP/2. Mirrors ``umilib::codec::hpack``.

An :class:`HPACKEncoder` writes field blocks of lists of :class:`HPACKField`, an
:class:`HPACKDecoder` reads them; each keeps its dynamic table in step with the other end's.
Errors are :class:`HPACKError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
from typing import ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Handle, Library, Structures


__all__ = ["HPACKDecoder", "HPACKDecoderConfig", "HPACKEncoder", "HPACKEncoderConfig", "HPACKError", "HPACKField", "HPACKFields"]


class HPACKError(FFIError):
    """An error of HPACK: ``Truncated``, ``IntegerOverflow``, ``InvalidIndex``, ``InvalidHuffman``,
    ``InvalidTableSizeUpdate``, ``StringTooLong``, ``FieldListTooLarge`` (the table is still in step)
    or ``NoSuchField``."""


Library.register_error("codec.hpack", HPACKError)


@dataclasses.dataclass(frozen=True)
class HPACKField:
    """A field: its name, its value, and whether it is never indexed (RFC 7541 §7.1.3)."""

    name: bytes
    value: bytes
    sensitive: bool = False


@dataclasses.dataclass
class HPACKEncoderConfig:
    """The configuration of an :class:`HPACKEncoder`."""

    C_TYPE: ClassVar[str] = "umilib_codec_hpack_HPACKEncoderConfig"

    maximum_table_size: int = 4096
    huffman: bool = True
    maximum_indexed_size: int = 1024


@dataclasses.dataclass
class HPACKDecoderConfig:
    """The configuration of an :class:`HPACKDecoder`."""

    C_TYPE: ClassVar[str] = "umilib_codec_hpack_HPACKDecoderConfig"

    maximum_table_size: int = 4096
    maximum_string_length: int = 1 << 16
    maximum_field_list_size: int = 1 << 16


class HPACKFields(Handle):
    """A list of fields as the C ABI holds it, made of and turned into lists of :class:`HPACKField`."""

    FREE = "umilib_codec_hpack_hpack_fields_free"

    @classmethod
    def of(cls, fields: list[HPACKField]) -> HPACKFields:
        out = cls(Handle.create("umilib_codec_hpack_hpack_fields_new"))
        for field in fields:
            out.library.call("umilib_codec_hpack_hpack_fields_push", out.handle, *Bytes.readable(field.name), *Bytes.readable(field.value), field.sensitive)
        return out

    def to_list(self) -> list[HPACKField]:
        count = self.library.value("umilib_codec_hpack_hpack_fields_count", ctypes.c_size_t, self.handle)
        fields = []
        for index in range(count):
            name, value, sensitive = Buffer(), Buffer(), ctypes.c_bool()
            self.library.call("umilib_codec_hpack_hpack_fields_get", self.handle, index, ctypes.byref(name), ctypes.byref(value), ctypes.byref(sensitive))
            fields.append(HPACKField(self.library.take(name), self.library.take(value), sensitive.value))
        return fields


class HPACKEncoder(Handle):
    """An encoder of field blocks (RFC 7541 §2.3, §6) for a decoder whose table is limited to ``limit`` bytes."""

    FREE = "umilib_codec_hpack_hpack_encoder_free"

    def __init__(self, config: HPACKEncoderConfig | None = None, limit: int = 4096) -> None:
        structure = Structures.to_structure(config or HPACKEncoderConfig(), HPACKEncoderConfig.C_TYPE)
        super().__init__(Handle.create("umilib_codec_hpack_hpack_encoder_new", structure, limit))

    def set_limit(self, limit: int) -> None:
        """Takes the decoder's new limit (SETTINGS_HEADER_TABLE_SIZE)."""
        self.library.call("umilib_codec_hpack_hpack_encoder_set_limit", self.handle, limit)

    def resize(self, size: int) -> None:
        self.library.call("umilib_codec_hpack_hpack_encoder_resize", self.handle, size)

    def encode(self, fields: list[HPACKField]) -> bytes:
        with HPACKFields.of(fields) as handle:
            return self.library.output("umilib_codec_hpack_hpack_encoder_encode", self.handle, handle)


class HPACKDecoder(Handle):
    """A decoder of field blocks."""

    FREE = "umilib_codec_hpack_hpack_decoder_free"

    def __init__(self, config: HPACKDecoderConfig | None = None) -> None:
        structure = Structures.to_structure(config or HPACKDecoderConfig(), HPACKDecoderConfig.C_TYPE)
        super().__init__(Handle.create("umilib_codec_hpack_hpack_decoder_new", structure))

    def set_limit(self, limit: int) -> None:
        """Sets the limit this end advertised; a lower one must be confirmed by the next block."""
        self.library.call("umilib_codec_hpack_hpack_decoder_set_limit", self.handle, limit)

    def decode(self, block: bytes) -> list[HPACKField]:
        with HPACKFields(Handle.create("umilib_codec_hpack_hpack_decoder_decode", self.handle, *Bytes.readable(block))) as fields:
            return fields.to_list()
