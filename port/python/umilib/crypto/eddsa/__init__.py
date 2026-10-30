"""EdDSA: Ed25519 and Ed448 (RFC 8032). Mirrors ``umilib::crypto::eddsa``.

``EdDSA[Edwards25519]`` (:data:`Ed25519`) and ``EdDSA[Edwards448]``
(:data:`Ed448`) sign with the pure variants of :class:`SignatureScheme`;
:meth:`EdDSA.sign_with_context` gives Ed25519ctx and Ed448 with a context,
and :meth:`EdDSA.sign_prehashed` Ed25519ph and Ed448ph. Signing keys are the
secret seeds of section 5.1.5 (5.2.5), verifying keys the encoded points.
"""

from __future__ import annotations

import ctypes
from typing import Any

from umilib.crypto import EncodedKey, Names, SignatureScheme, SigningKey, VerifyingKey
from umilib.ffi import Bytes
from umilib.math.ec import EdwardsCurve


class EdDSA(SignatureScheme):
    """EdDSA on the curve of ``EdDSA[C]``."""

    PREFIX = "umilib_crypto_eddsa_eddsa"

    def __class_getitem__(cls, curve: Any) -> Any:
        curve = Names.require(curve, EdwardsCurve, "EdDSA")
        return cls.specialize((curve,), cls.SIZES, {"__doc__": f"EdDSA on {curve.__name__}."})

    @classmethod
    def sign_with_context(
        cls,
        key: SigningKey,
        context: bytes | bytearray | memoryview,
        message: bytes | bytearray | memoryview,
    ) -> bytes:
        """The signature of Ed25519ctx or of Ed448 with ``context`` (of at most 255 bytes; Ed25519ctx
        refuses an empty one)."""
        return cls.sign_variant("sign_with_context", key, context, message)

    @classmethod
    def verify_with_context(
        cls,
        key: VerifyingKey,
        context: bytes | bytearray | memoryview,
        message: bytes | bytearray | memoryview,
        signature: bytes | bytearray | memoryview,
    ) -> None:
        cls.verify_variant("verify_with_context", key, context, message, signature)

    @classmethod
    def sign_prehashed(
        cls,
        key: SigningKey,
        context: bytes | bytearray | memoryview,
        message: bytes | bytearray | memoryview,
    ) -> bytes:
        """The signature of Ed25519ph or Ed448ph of the message itself, which the function hashes."""
        return cls.sign_variant("sign_prehashed", key, context, message)

    @classmethod
    def verify_prehashed(
        cls,
        key: VerifyingKey,
        context: bytes | bytearray | memoryview,
        message: bytes | bytearray | memoryview,
        signature: bytes | bytearray | memoryview,
    ) -> None:
        cls.verify_variant("verify_prehashed", key, context, message, signature)

    @classmethod
    def sign_variant(cls, function: str, key: SigningKey, context: Any, message: Any) -> bytes:
        key.check(cls)
        out = (ctypes.c_uint8 * cls.SIGNATURE_SIZE)()
        context_data, context_length = Bytes.readable(context)
        message_data, message_length = Bytes.readable(message)
        with EncodedKey.encodings(key) as [(data, length)]:
            cls.call(function, data, length, context_data, context_length, message_data, message_length, out, len(out))
        return bytes(out)

    @classmethod
    def verify_variant(cls, function: str, key: VerifyingKey, context: Any, message: Any, signature: Any) -> None:
        key.check(cls)
        context_data, context_length = Bytes.readable(context)
        message_data, message_length = Bytes.readable(message)
        signature_data, signature_length = Bytes.readable(signature)
        with EncodedKey.encodings(key) as [(data, length)]:
            cls.call(function, data, length, context_data, context_length, message_data, message_length, signature_data, signature_length)


class EdDSACurves:
    """The curves of the aliases of RFC 8032."""

    @staticmethod
    def ed25519() -> Any:
        from umilib.crypto.curve.curve25519 import Edwards25519

        return EdDSA[Edwards25519]

    @staticmethod
    def ed448() -> Any:
        from umilib.crypto.curve.curve448 import Edwards448

        return EdDSA[Edwards448]


#: Ed25519 of RFC 8032 section 5.1.
Ed25519 = EdDSACurves.ed25519()
#: Ed448 of RFC 8032 section 5.2.
Ed448 = EdDSACurves.ed448()

__all__ = ["Ed25519", "Ed448", "EdDSA", "EdDSACurves"]
