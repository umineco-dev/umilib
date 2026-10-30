"""ML-KEM, the module-lattice-based key-encapsulation mechanism of FIPS 203. Mirrors
``umilib::crypto::mlkem``.

``MLKEM[MLKEM768]`` is a :class:`~umilib.crypto.KeyEncapsulation`: keys are the encodings of FIPS 203
(an encapsulation key passes the checks of section 7.2 when it is read, a decapsulation key those of
section 7.3), and decapsulation rejects implicitly. :meth:`MLKEM.decapsulation_key_from_seed` expands
the seed d || z of 64 bytes; :meth:`MLKEM.encapsulate_internal` encapsulates with a given m, for testing.
"""

from __future__ import annotations

import ctypes
from typing import Any

from umilib.crypto import DecapsulationKey, EncapsulationKey, EncodedKey, KeyEncapsulation, Names
from umilib.ffi import Bytes, Marker
from umilib.secret import Secret


class MLKEMParameters(Marker, abstract=True):
    """A parameter set of ML-KEM (FIPS 203 table 2), named by its C type name."""


class MLKEM512(MLKEMParameters):
    """ML-KEM-512, of security category 1."""


class MLKEM768(MLKEMParameters):
    """ML-KEM-768, of security category 3."""


class MLKEM1024(MLKEMParameters):
    """ML-KEM-1024, of security category 5."""


class MLKEM(KeyEncapsulation):
    """ML-KEM with the parameter set of ``MLKEM[P]``."""

    PREFIX = "umilib_crypto_mlkem_mlkem"

    def __class_getitem__(cls, parameters: Any) -> Any:
        parameters = Names.require(parameters, MLKEMParameters, "MLKEM")
        return cls.specialize((parameters,), cls.SIZES, {"__doc__": f"ML-KEM with {parameters.__name__}."})

    @classmethod
    def decapsulation_key_from_seed(cls, seed: bytes | bytearray) -> DecapsulationKey:
        """The decapsulation key of the seed d || z of 64 bytes (FIPS 203 section 3.3); raises
        ``InvalidKey`` for another length. A ``bytearray`` is zeroized afterwards."""
        key = DecapsulationKey.allocate(cls, cls.DECAPSULATION_KEY_SIZE)
        source = Secret(seed if isinstance(seed, bytearray) else bytearray(seed))
        with source:
            with source.locked():
                data, length = source.location()
                with key.writable() as (out, size):
                    cls.call("decapsulation_key_from_seed", data, length, out, size)
        return key

    @classmethod
    def encapsulate_internal(cls, key: EncapsulationKey, message: bytes | bytearray, shared: bytearray) -> bytes:
        """ML-KEM.Encaps_internal (FIPS 203 algorithm 17) with the 32 bytes of m, for testing: returns the
        ciphertext and writes the shared secret into ``shared`` of 32 bytes."""
        key.check(cls)
        ciphertext = (ctypes.c_uint8 * cls.CIPHERTEXT_SIZE)()
        message_data, message_length = Bytes.readable(message)
        with EncodedKey.encodings(key) as [(data, length)]:
            cls.call(
                "encapsulate_internal", data, length, message_data, message_length, ciphertext, len(ciphertext), Bytes.mutable(shared), len(shared)
            )
        return bytes(ciphertext)


__all__ = ["MLKEM", "MLKEM512", "MLKEM768", "MLKEM1024", "MLKEMParameters"]
