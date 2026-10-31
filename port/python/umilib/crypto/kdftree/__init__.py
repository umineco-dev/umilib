"""KDF_TREE (RFC 7836 section 4.4, R 50.1.113-2016): the key derivation function of the GOST cipher
suites. Mirrors ``umilib::crypto::kdftree``.

``KDFTree[HMAC[Streebog256]](key, 1)`` is
``KDFTree::new(HMAC::<Streebog256>::new(key), 1)``.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import Primitive, Specialization
from umilib.crypto.kbkdf import KBKDF
from umilib.ffi import Bytes, Handle, Text


class KDFTree(Primitive):
    """KDF_TREE over the PRF ``KDFTree[P]``, keyed with K_in, with a counter of 1 to 4 bytes."""

    PREFIX = "umilib_crypto_kdftree_kdftree"
    PRF: ClassVar[Any] = None

    def __class_getitem__(cls, prf: Any) -> Any:
        KBKDF.names(prf, "KDFTree")
        return Specialization.of(cls, (prf,), {"PRF": prf})

    def __init__(self, key: bytes | bytearray | memoryview, counter_bytes: int) -> None:
        function, primitive = KBKDF.names(Specialization.require(self.PRF, "KDFTree"), "KDFTree")
        function_name, function_length = Text.encode(function)
        primitive_name, primitive_length = Text.encode(primitive)
        data, length = Bytes.readable(key)
        super().__init__(
            Handle.create("umilib_crypto_kdftree_kdftree_new", function_name, function_length, primitive_name, primitive_length, data, length, counter_bytes)
        )

    def derive(self, label: bytes | bytearray | memoryview, seed: bytes | bytearray | memoryview, length: int) -> bytes:
        """K(i) = PRF(K_in, [i]_b || label || 0x00 || seed || [L]_b): ``length`` bytes of keying material."""
        label_data, label_length = Bytes.readable(label)
        seed_data, seed_length = Bytes.readable(seed)
        out = (ctypes.c_uint8 * length)()
        self.library.call("umilib_crypto_kdftree_kdftree_derive", self.handle, label_data, label_length, seed_data, seed_length, out, length)
        return bytes(out)


__all__ = ["KDFTree"]
