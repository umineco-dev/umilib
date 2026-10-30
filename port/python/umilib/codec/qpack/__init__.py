"""QPACK (RFC 9204): the field compression of HTTP/3. Mirrors ``umilib::codec::qpack``.

A :class:`QPACKEncoder` writes field sections and the instructions of its encoder stream; a
:class:`QPACKDecoder` reads them and writes the instructions of its decoder stream. The caller moves
the bytes of both streams (``take_instructions`` and ``receive_*_stream``). Fields are
:class:`~umilib.codec.hpack.HPACKField`. Errors are :class:`QPACKError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
from typing import ClassVar

from umilib.codec.hpack import HPACKField, HPACKFields
from umilib.ffi import Bytes, FFIError, Handle, Library, Structures

P = "umilib_codec_qpack"

__all__ = ["QPACKDecoded", "QPACKDecoder", "QPACKDecoderConfig", "QPACKEncoder", "QPACKEncoderConfig", "QPACKError"]


class QPACKError(FFIError):
    """An error of QPACK: ``DecompressionFailed``, ``EncoderStream``, ``DecoderStream`` (each a
    connection error of HTTP/3) or ``FieldListTooLarge`` (of the stream alone)."""


Library.register_error("codec.qpack", QPACKError)


@dataclasses.dataclass
class QPACKEncoderConfig:
    C_TYPE: ClassVar[str] = f"{P}_QPACKEncoderConfig"

    maximum_table_capacity: int = 4096
    huffman: bool = True
    maximum_indexed_size: int = 1024
    blocking: bool = True


@dataclasses.dataclass
class QPACKDecoderConfig:
    C_TYPE: ClassVar[str] = f"{P}_QPACKDecoderConfig"

    maximum_table_capacity: int = 4096
    blocked_streams: int = 16
    maximum_string_length: int = 1 << 16
    maximum_field_list_size: int = 1 << 16


@dataclasses.dataclass(frozen=True)
class QPACKDecoded:
    """What decoding a field section gave: its fields, or ``blocked`` until inserts arrive (RFC 9204 §2.1.2)."""

    fields: list[HPACKField] | None
    blocked: bool


class QPACKEncoder(Handle):
    """An encoder of field sections; it uses no dynamic table until :meth:`set_peer_settings`."""

    FREE = f"{P}_qpack_encoder_free"

    def __init__(self, config: QPACKEncoderConfig | None = None) -> None:
        structure = Structures.to_structure(config or QPACKEncoderConfig(), QPACKEncoderConfig.C_TYPE)
        super().__init__(Handle.create(f"{P}_qpack_encoder_new", structure))

    def set_peer_settings(self, maximum_table_capacity: int, blocked_streams: int) -> None:
        self.library.call(f"{P}_qpack_encoder_set_peer_settings", self.handle, maximum_table_capacity, blocked_streams)

    def encode(self, stream: int, fields: list[HPACKField]) -> bytes:
        with HPACKFields.of(fields) as handle:
            return self.library.output(f"{P}_qpack_encoder_encode", self.handle, stream, handle)

    def receive_decoder_stream(self, data: bytes) -> None:
        self.library.call(f"{P}_qpack_encoder_receive_decoder_stream", self.handle, *Bytes.readable(data))

    def take_instructions(self) -> bytes:
        """The encoder stream's instructions to send."""
        return self.library.output(f"{P}_qpack_encoder_take_instructions", self.handle)


class QPACKDecoder(Handle):
    FREE = f"{P}_qpack_decoder_free"

    def __init__(self, config: QPACKDecoderConfig | None = None) -> None:
        structure = Structures.to_structure(config or QPACKDecoderConfig(), QPACKDecoderConfig.C_TYPE)
        super().__init__(Handle.create(f"{P}_qpack_decoder_new", structure))

    def receive_encoder_stream(self, data: bytes) -> None:
        self.library.call(f"{P}_qpack_decoder_receive_encoder_stream", self.handle, *Bytes.readable(data))

    def decode(self, stream: int, section: bytes) -> QPACKDecoded:
        """Decodes the field section of ``stream``; decode it again once a blocked one's inserts arrive."""
        blocked, out = ctypes.c_bool(), ctypes.c_void_p()
        self.library.call(f"{P}_qpack_decoder_decode", self.handle, stream, *Bytes.readable(section), ctypes.byref(blocked), ctypes.byref(out))
        if blocked.value:
            return QPACKDecoded(None, True)
        with HPACKFields(out.value) as fields:
            return QPACKDecoded(fields.to_list(), False)

    def cancel_stream(self, stream: int) -> None:
        self.library.call(f"{P}_qpack_decoder_cancel_stream", self.handle, stream)

    def take_instructions(self) -> bytes:
        """The decoder stream's instructions to send."""
        return self.library.output(f"{P}_qpack_decoder_take_instructions", self.handle)
