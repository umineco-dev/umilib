"""The modes of operation of block ciphers and the padding of PKCS #7. Mirrors ``umilib::crypto::mode``.

Each mode is selected by the class of its cipher, as ``CBC[AES128](key, iv)``,
which is ``CBC::new(AES128::new(key), iv)``; the cipher of a mode of
SP 800-38A may have blocks of 8 or 16 bytes.
"""

from __future__ import annotations

import ctypes

from umilib.ffi import Buffer, Bytes, Library


class PKCS7:
    """The padding of PKCS #7 (RFC 5652 section 6.3): k - (l mod k) bytes of that value."""

    @staticmethod
    def pad(data: bytearray, block_size: int) -> None:
        """Appends to ``data`` its padding for blocks of ``block_size`` bytes (1 to 255)."""
        # ``data`` is read in place; the export must end before it grows.
        source, length = Bytes.readable(data)
        buffer = Buffer()
        library = Library.default()
        library.call("umilib_crypto_mode_pkcs7_pad", source, length, block_size, ctypes.byref(buffer))
        del source
        data[:] = library.take(buffer)

    @staticmethod
    def unpad_length(data: bytes | bytearray | memoryview, block_size: int) -> int:
        """The length of ``data`` without its padding, checked in constant time; raises ``InputLength``
        unless ``data`` is a whole number of blocks and ``InvalidParameter`` if the padding is wrong."""
        source, length = Bytes.readable(data)
        return Library.default().value("umilib_crypto_mode_pkcs7_unpad_length", ctypes.c_size_t, source, length, block_size)

    @staticmethod
    def unpad(data: bytearray, block_size: int) -> None:
        """Removes the padding of ``data``."""
        del data[PKCS7.unpad_length(data, block_size) :]


__all__ = ["PKCS7"]
