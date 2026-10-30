"""PEM, RFC 7468. Mirrors ``umilib::codec::pem``."""

from __future__ import annotations

import ctypes
import enum

from umilib.ffi import Bytes, FFIError, Handle, Library, Text


class PEMError(FFIError):
    """An error of PEM parsing; ``name`` is the variant, such as ``LabelMismatch``.
    Invalid base64 text raises :class:`umilib.codec.base.BaseError` instead."""


Library.register_error("codec.pem", PEMError)


class PEMStrictness(enum.IntEnum):
    """The grammar of RFC 7468 section 3 used to parse base64 text."""

    Strict = 0
    Standard = 1
    Lax = 2


class PEMLineEnding(enum.IntEnum):
    LF = 0
    CRLF = 1

    def as_str(self) -> str:
        return "\n" if self is PEMLineEnding.LF else "\r\n"


class PEMLabel:
    """The labels of RFC 7468 sections 5 to 13."""

    CERTIFICATE = "CERTIFICATE"
    X509_CRL = "X509 CRL"
    CERTIFICATE_REQUEST = "CERTIFICATE REQUEST"
    PKCS7 = "PKCS7"
    CMS = "CMS"
    PRIVATE_KEY = "PRIVATE KEY"
    ENCRYPTED_PRIVATE_KEY = "ENCRYPTED PRIVATE KEY"
    ATTRIBUTE_CERTIFICATE = "ATTRIBUTE CERTIFICATE"
    PUBLIC_KEY = "PUBLIC KEY"

    @staticmethod
    def is_valid(label: str) -> bool:
        data = label.encode("utf-8")
        return Library.default().value("umilib_codec_pem_pem_label_is_valid", ctypes.c_bool, data, len(data))


class PEMConfig(Handle):
    """Options of PEM parsing."""

    FREE = "umilib_codec_pem_pem_config_free"

    def __init__(self, strictness: PEMStrictness | None = None, require_matching_label: bool | None = None,
                 maximum_length: int | None = None) -> None:
        super().__init__(Handle.create("umilib_codec_pem_pem_config_new"))
        current = self.settings()
        self.update(
            current[0] if strictness is None else strictness,
            current[1] if require_matching_label is None else require_matching_label,
            current[2] if maximum_length is None else maximum_length,
        )

    def settings(self) -> tuple[PEMStrictness, bool, int]:
        strictness, matching, maximum = ctypes.c_uint8(), ctypes.c_bool(), ctypes.c_size_t()
        self.library.call("umilib_codec_pem_pem_config_settings", self.handle, ctypes.byref(strictness), ctypes.byref(matching), ctypes.byref(maximum))
        return PEMStrictness(strictness.value), matching.value, maximum.value

    def update(self, strictness: PEMStrictness, require_matching_label: bool, maximum_length: int) -> None:
        self.library.call("umilib_codec_pem_pem_config_set", self.handle, int(strictness), require_matching_label, maximum_length)

    strictness = property(lambda self: self.settings()[0], lambda self, value: self.update(value, self.settings()[1], self.settings()[2]))
    require_matching_label = property(lambda self: self.settings()[1], lambda self, value: self.update(self.settings()[0], value, self.settings()[2]))
    maximum_length = property(lambda self: self.settings()[2], lambda self, value: self.update(self.settings()[0], self.settings()[1], value))


class PEMDocument(Handle):
    """A label and its data; the data is zeroized when the document is released."""

    FREE = "umilib_codec_pem_pem_document_free"

    def __init__(self, label: str | None = None, data: bytes | bytearray = b"", pointer: int | None = None) -> None:
        if pointer is None:
            label_data, label_length = Text.encode(label or "")
            data, length = Bytes.readable(data)
            pointer = Handle.create("umilib_codec_pem_pem_document_new", label_data, label_length, data, length)
        super().__init__(pointer)

    @classmethod
    def new(cls, label: str, data: bytes | bytearray) -> PEMDocument:
        return cls(label, data)

    def label(self) -> str:
        return self.library.output("umilib_codec_pem_pem_document_label", self.handle).decode("utf-8")

    def data(self) -> bytes:
        """A copy of the data; prefer :meth:`into_data` into a ``bytearray`` for secrets."""
        pointer, length = ctypes.c_void_p(), ctypes.c_size_t()
        with self.locked():
            self.library.call("umilib_codec_pem_pem_document_data", self.handle, ctypes.byref(pointer), ctypes.byref(length))
            return ctypes.string_at(pointer.value, length.value) if length.value else b""

    def into_data(self) -> bytearray:
        """Takes the data out and releases the document; zeroize the result when done."""
        pointer, length = ctypes.c_void_p(), ctypes.c_size_t()
        with self.locked():
            self.library.call("umilib_codec_pem_pem_document_data", self.handle, ctypes.byref(pointer), ctypes.byref(length))
            data = bytearray(length.value)
            if length.value:
                ctypes.memmove((ctypes.c_uint8 * length.value).from_buffer(data), pointer.value, length.value)
            self.close()
        return data

    @classmethod
    def decode(cls, text: str | bytes, config: PEMConfig | None = None) -> PEMDocument:
        data = text.encode("utf-8") if isinstance(text, str) else text
        data, length = Bytes.readable(data)
        return cls(pointer=Handle.create("umilib_codec_pem_pem_document_decode", data, length, config.handle if config else None))

    @classmethod
    def decode_next(cls, text: str | bytes, start: int, config: PEMConfig | None = None) -> tuple[PEMDocument, int] | None:
        data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        found, out, following = ctypes.c_bool(), ctypes.c_void_p(), ctypes.c_size_t()
        Library.default().call(
            "umilib_codec_pem_pem_document_decode_next", data, len(data), start, config.handle if config else None,
            ctypes.byref(found), ctypes.byref(out), ctypes.byref(following),
        )
        return (cls(pointer=out.value), following.value) if found.value else None

    @classmethod
    def decode_all(cls, text: str | bytes, config: PEMConfig | None = None) -> list[PEMDocument]:
        data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        documents, position = [], 0
        while (result := cls.decode_next(data, position, config)) is not None:
            document, position = result
            documents.append(document)
        return documents

    def encode(self) -> str:
        return self.library.output("umilib_codec_pem_pem_document_encode", self.handle).decode("ascii")

    def encode_with(self, line_ending: PEMLineEnding) -> str:
        return self.library.output("umilib_codec_pem_pem_document_encode_with", self.handle, int(line_ending)).decode("ascii")

    def __repr__(self) -> str:
        return f"PEMDocument(label={self.label()!r}, length={len(self.data())})"


__all__ = ["PEMConfig", "PEMDocument", "PEMError", "PEMLabel", "PEMLineEnding", "PEMStrictness"]
