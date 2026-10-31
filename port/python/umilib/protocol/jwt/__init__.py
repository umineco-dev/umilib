"""JSON Object Signing and Encryption and JSON Web Tokens: JWK (RFC 7517), JWS (RFC 7515), JWE (RFC 7516)
and JWT (RFC 7519) with the validation of RFC 8725. Mirrors ``umilib::protocol::jwt``.

Algorithms are the enums :class:`JWSAlgorithm`, :class:`JWEAlgorithm` and :class:`JWEEncryption`, in the
order of the Rust constants ``ALL``; generators are those of :mod:`umilib.crypto.random`. Errors are
:class:`JWTError` (``name`` is the variant of the Rust ``JWTError``), :class:`~umilib.codec.json.JSONError`,
:class:`~umilib.auth.cert.key.KeyStatusError` and :class:`~umilib.crypto.CryptoError`.
"""

from __future__ import annotations

import ctypes
import enum
from collections.abc import Iterable, Sequence
from typing import Any, ClassVar

from umilib.auth.cert.key import HashAlgorithm, PrivateKey, PublicKey
from umilib.codec.json import JSONValue
from umilib.ffi import Buffer, Bytes, FFIError, Handle, Library, Text


class JWTError(FFIError):
    """An error of JOSE or of a JWT: ``Base64``, ``Format``, ``Header``, ``UnknownAlgorithm``,
    ``UnknownKeyType``, ``AlgorithmNotAllowed``, ``KeyMismatch``, ``Critical``, ``Signature``, ``Decryption``,
    ``Compression``, ``Limit``, ``Expired``, ``NotYetValid``, ``Issuer``, ``Audience``, ``Subject``, ``Type``,
    ``MissingClaim`` or ``InvalidClaim``."""


Library.register_error("protocol.jwt", JWTError)


class Algorithm(enum.IntEnum):
    """The base of the algorithm enums: each value has its name in the IANA registry (``REGISTERED``)."""

    def registered_name(self) -> str:
        """The name of the algorithm in the IANA registry, the value of ``alg`` or ``enc``."""
        return type(self).REGISTERED[self.value]

    @classmethod
    def from_name(cls, name: str) -> Any:
        """The algorithm of the registered ``name``, or ``None``."""
        return cls(cls.REGISTERED.index(name)) if name in cls.REGISTERED else None


class JWSAlgorithm(Algorithm):
    """The algorithms of JWS (RFC 7518 §3, RFC 8812, RFC 9864, RFC 9964); ``None_`` is ``none``."""

    HS256 = 0
    HS384 = 1
    HS512 = 2
    RS256 = 3
    RS384 = 4
    RS512 = 5
    PS256 = 6
    PS384 = 7
    PS512 = 8
    ES256 = 9
    ES384 = 10
    ES512 = 11
    ES256K = 12
    EdDSA = 13
    Ed25519 = 14
    Ed448 = 15
    MLDSA44 = 16
    MLDSA65 = 17
    MLDSA87 = 18
    None_ = 19

    REGISTERED = enum.nonmember(
        (
            "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384",
            "ES512", "ES256K", "EdDSA", "Ed25519", "Ed448", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "none",
        )
    )  # fmt: skip


class JWEAlgorithm(Algorithm):
    """The key management algorithms of JWE (RFC 7518 §4, RFC 8037)."""

    RSAOAEP = 0
    RSAOAEP256 = 1
    RSAOAEP384 = 2
    RSAOAEP512 = 3
    A128KW = 4
    A192KW = 5
    A256KW = 6
    Dir = 7
    ECDHES = 8
    ECDHESA128KW = 9
    ECDHESA192KW = 10
    ECDHESA256KW = 11
    A128GCMKW = 12
    A192GCMKW = 13
    A256GCMKW = 14
    PBES2HS256A128KW = 15
    PBES2HS384A192KW = 16
    PBES2HS512A256KW = 17

    REGISTERED = enum.nonmember(
        (
            "RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512", "A128KW", "A192KW", "A256KW", "dir",
            "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW",
            "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW",
        )
    )  # fmt: skip


class JWEEncryption(Algorithm):
    """The content encryption algorithms of JWE (RFC 7518 §5)."""

    A128CBCHS256 = 0
    A192CBCHS384 = 1
    A256CBCHS512 = 2
    A128GCM = 3
    A192GCM = 4
    A256GCM = 5

    REGISTERED = enum.nonmember(
        ("A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM")
    )


class Names:
    """The arguments of the C ABI for lists of algorithms."""

    @staticmethod
    def indices(values: Iterable[enum.IntEnum]) -> tuple[Any, int]:
        """The bytes of the indices of ``values`` and their count."""
        data = bytes(int(value) for value in values)
        return Bytes.readable(data)[0], len(data)


class JOSEHeader(Handle):
    """A JOSE Header (RFC 7515 §4, RFC 7516 §4): a JSON object of header parameters, kept in order."""

    FREE = "umilib_protocol_jwt_jose_header_free"

    def __init__(self, pointer: int | None = None) -> None:
        """An empty header, or the header of ``pointer``."""
        super().__init__(pointer if pointer is not None else Handle.create("umilib_protocol_jwt_jose_header_new"))

    @staticmethod
    def new() -> JOSEHeader:
        return JOSEHeader()

    @staticmethod
    def decode(data: bytes | bytearray | memoryview | str) -> JOSEHeader:
        """The header of the JSON text ``data``, an object without duplicate parameters."""
        if isinstance(data, str):
            data = data.encode()
        return JOSEHeader(Handle.create("umilib_protocol_jwt_jose_header_decode", *Bytes.readable(data)))

    def encode(self) -> str:
        return self.library.output("umilib_protocol_jwt_jose_header_encode", self.handle).decode()

    def get(self, name: str) -> JSONValue | None:
        pointer = Library.default().optional("umilib_protocol_jwt_jose_header_get", ctypes.c_void_p, self.handle, *Text.encode(name))
        return None if pointer is None else JSONValue(pointer)

    def set(self, name: str, value: JSONValue) -> None:
        self.library.call("umilib_protocol_jwt_jose_header_set", self.handle, *Text.encode(name), value)

    def set_string(self, name: str, value: str) -> None:
        self.library.call("umilib_protocol_jwt_jose_header_set_string", self.handle, *Text.encode(name), *Text.encode(value))

    def remove(self, name: str) -> bool:
        """Removes the parameter ``name``; whether it was present."""
        return self.library.value("umilib_protocol_jwt_jose_header_remove", ctypes.c_bool, self.handle, *Text.encode(name))

    def string(self, name: str) -> str | None:
        """The string parameter ``name``, if present."""
        value = self.get(name)
        return None if value is None else value.as_str()

    def clone(self) -> JOSEHeader:
        return JOSEHeader(Handle.create("umilib_protocol_jwt_jose_header_clone", self.handle))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, JOSEHeader) and JSONValue.parse(self.encode()) == JSONValue.parse(other.encode())


class JWK(Handle):
    """A JSON Web Key (RFC 7517): ``EC``, ``RSA``, ``oct``, ``OKP`` (RFC 8037) or ``AKP`` (RFC 9964)."""

    FREE = "umilib_protocol_jwt_jwk_free"

    @staticmethod
    def from_json(text: bytes | bytearray | memoryview | str) -> JWK:
        """The JWK of the JSON text ``text``, with the checks of RFC 7517 and RFC 7518 §6."""
        if isinstance(text, str):
            text = text.encode()
        return JWK(Handle.create("umilib_protocol_jwt_jwk_from_json", *Bytes.readable(text)))

    def to_json(self) -> str:
        return self.library.output("umilib_protocol_jwt_jwk_to_json", self.handle).decode()

    @staticmethod
    def symmetric(k: bytes | bytearray | memoryview) -> JWK:
        """The ``oct`` JWK of the key ``k``."""
        return JWK(Handle.create("umilib_protocol_jwt_jwk_symmetric", *Bytes.readable(k)))

    def to_public(self) -> JWK:
        """The JWK without its private parameters."""
        return JWK(Handle.create("umilib_protocol_jwt_jwk_to_public", self.handle))

    @property
    def is_secret(self) -> bool:
        """Whether the JWK holds secret material: a symmetric key or private parameters."""
        return self.library.value("umilib_protocol_jwt_jwk_is_secret", ctypes.c_bool, self.handle)

    @property
    def key_type(self) -> str:
        """``kty``."""
        return self.library.output("umilib_protocol_jwt_jwk_key_type", self.handle).decode()

    def text(self, member: str) -> str | None:
        data = self.library.optional(f"umilib_protocol_jwt_jwk_{member}", Buffer, self.handle)
        return None if data is None else data.decode()

    @property
    def key_id(self) -> str | None:
        """``kid``."""
        return self.text("key_id")

    @key_id.setter
    def key_id(self, value: str | None) -> None:
        self.library.call("umilib_protocol_jwt_jwk_set_key_id", self.handle, *Text.encode(value))

    @property
    def algorithm(self) -> str | None:
        """``alg``."""
        return self.text("algorithm")

    @algorithm.setter
    def algorithm(self, value: str | None) -> None:
        self.library.call("umilib_protocol_jwt_jwk_set_algorithm", self.handle, *Text.encode(value))

    @property
    def key_use(self) -> str | None:
        """``use``."""
        return self.text("key_use")

    @key_use.setter
    def key_use(self, value: str | None) -> None:
        self.library.call("umilib_protocol_jwt_jwk_set_key_use", self.handle, *Text.encode(value))

    def check(self) -> None:
        """Checks the rules of RFC 7517 the JWK must follow."""
        self.library.call("umilib_protocol_jwt_jwk_check", self.handle)

    def thumbprint(self, hash: HashAlgorithm) -> bytes:
        """The thumbprint of RFC 7638."""
        return self.library.output("umilib_protocol_jwt_jwk_thumbprint", self.handle, int(hash))

    def thumbprint_uri(self, hash: HashAlgorithm) -> str:
        """The thumbprint URI of RFC 9278."""
        return self.library.output("umilib_protocol_jwt_jwk_thumbprint_uri", self.handle, int(hash)).decode()

    def public_key(self) -> PublicKey:
        return PublicKey(Handle.create("umilib_protocol_jwt_jwk_public_key", self.handle))

    def private_key(self) -> PrivateKey:
        return PrivateKey(Handle.create("umilib_protocol_jwt_jwk_private_key", self.handle))

    @staticmethod
    def from_public_key(key: PublicKey) -> JWK:
        return JWK(Handle.create("umilib_protocol_jwt_jwk_from_public_key", key))

    @staticmethod
    def from_private_key(key: PrivateKey) -> JWK:
        return JWK(Handle.create("umilib_protocol_jwt_jwk_from_private_key", key))

    def clone(self) -> JWK:
        return JWK(Handle.create("umilib_protocol_jwt_jwk_clone", self.handle))


class JWKSet(Handle):
    """A JWK Set (RFC 7517 §5)."""

    FREE = "umilib_protocol_jwt_jwk_set_free"

    def __init__(self, pointer: int | None = None) -> None:
        super().__init__(pointer if pointer is not None else Handle.create("umilib_protocol_jwt_jwk_set_new"))

    @staticmethod
    def from_json(text: bytes | bytearray | memoryview | str) -> JWKSet:
        """The set of the JSON text ``text``; keys of unknown types are skipped (RFC 7517 §5)."""
        if isinstance(text, str):
            text = text.encode()
        return JWKSet(Handle.create("umilib_protocol_jwt_jwk_set_from_json", *Bytes.readable(text)))

    def to_json(self) -> str:
        return self.library.output("umilib_protocol_jwt_jwk_set_to_json", self.handle).decode()

    def __len__(self) -> int:
        return self.library.value("umilib_protocol_jwt_jwk_set_len", ctypes.c_size_t, self.handle)

    @property
    def keys(self) -> list[JWK]:
        """Copies of the keys."""
        return [JWK(Handle.create("umilib_protocol_jwt_jwk_set_key", self.handle, index)) for index in range(len(self))]

    def push(self, key: JWK) -> None:
        self.library.call("umilib_protocol_jwt_jwk_set_push", self.handle, key)

    def find(self, key_id: str) -> list[JWK]:
        """The keys whose ``kid`` is ``key_id``."""
        return [key for key in self.keys if key.key_id == key_id]


class JWSConfig(Handle):
    """What verifying a JWS accepts (RFC 8725 §3.1): the algorithms, and the critical header parameters
    understood beyond ``b64``."""

    FREE = "umilib_protocol_jwt_jws_config_free"

    MAXIMUM_SIGNATURES: ClassVar[int] = 16

    def __init__(self, algorithms: Sequence[JWSAlgorithm], critical: Sequence[str] = ()) -> None:
        super().__init__(Handle.create("umilib_protocol_jwt_jws_config_new", *Names.indices(algorithms)))
        for name in critical:
            self.understand(name)

    def set_maximum_signatures(self, maximum: int) -> None:
        """Sets the most signatures a JWS may have (the work of one verification)."""
        self.library.call("umilib_protocol_jwt_jws_config_set_maximum_signatures", self.handle, maximum)

    def understand(self, name: str) -> None:
        self.library.call("umilib_protocol_jwt_jws_config_understand", self.handle, *Text.encode(name))


class JWS(Handle):
    """A JWS (RFC 7515): a payload and its signatures."""

    FREE = "umilib_protocol_jwt_jws_free"

    @staticmethod
    def new(payload: bytes | bytearray | memoryview) -> JWS:
        """A JWS of ``payload``, without signatures yet."""
        return JWS(Handle.create("umilib_protocol_jwt_jws_new", *Bytes.readable(payload)))

    @property
    def payload(self) -> bytes:
        return self.library.output("umilib_protocol_jwt_jws_payload", self.handle)

    def __len__(self) -> int:
        """The number of signatures."""
        return self.library.value("umilib_protocol_jwt_jws_signature_count", ctypes.c_size_t, self.handle)

    def signature_header(self, index: int) -> JOSEHeader:
        """The JOSE Header of the signature at ``index``."""
        return JOSEHeader(Handle.create("umilib_protocol_jwt_jws_signature_header", self.handle, index))

    def sign(self, protected: JOSEHeader, header: JOSEHeader | None, key: JWK, random: Any) -> None:
        """Adds the signature of the payload with the headers ``protected`` and ``header`` under ``key``."""
        self.library.call("umilib_protocol_jwt_jws_sign", self.handle, protected, header, key, *random.source())

    def verify(self, key: JWK, config: JWSConfig) -> int:
        """Verifies the JWS under ``key`` (RFC 7515 §5.2): the index of the signature that verifies."""
        return self.library.value("umilib_protocol_jwt_jws_verify", ctypes.c_size_t, self.handle, key, config)

    def verify_unsecured(self) -> None:
        """Accepts an Unsecured JWS (RFC 7518 §3.6), as an explicit decision of the application."""
        self.library.call("umilib_protocol_jwt_jws_verify_unsecured", self.handle)

    @staticmethod
    def from_compact(text: str) -> JWS:
        return JWS(Handle.create("umilib_protocol_jwt_jws_from_compact", *Text.encode(text), None, 0, False))

    @staticmethod
    def from_compact_detached(text: str, payload: bytes | bytearray | memoryview) -> JWS:
        return JWS(Handle.create("umilib_protocol_jwt_jws_from_compact", *Text.encode(text), *Bytes.readable(payload), True))

    def to_compact(self) -> str:
        return self.library.output("umilib_protocol_jwt_jws_to_compact", self.handle, False).decode()

    def to_compact_detached(self) -> str:
        return self.library.output("umilib_protocol_jwt_jws_to_compact", self.handle, True).decode()

    @staticmethod
    def from_json(text: bytes | bytearray | memoryview | str) -> JWS:
        if isinstance(text, str):
            text = text.encode()
        return JWS(Handle.create("umilib_protocol_jwt_jws_from_json", *Bytes.readable(text), None, 0, False))

    @staticmethod
    def from_json_detached(text: bytes | bytearray | memoryview | str, payload: bytes | bytearray | memoryview) -> JWS:
        if isinstance(text, str):
            text = text.encode()
        return JWS(Handle.create("umilib_protocol_jwt_jws_from_json", *Bytes.readable(text), *Bytes.readable(payload), True))

    def json(self, flattened: bool, detached: bool) -> str:
        return self.library.output("umilib_protocol_jwt_jws_to_json", self.handle, flattened, detached).decode()

    def to_json(self) -> str:
        return self.json(False, False)

    def to_flattened_json(self) -> str:
        return self.json(True, False)

    def to_json_detached(self) -> str:
        return self.json(False, True)

    def to_flattened_json_detached(self) -> str:
        return self.json(True, True)

    def clone(self) -> JWS:
        return JWS(Handle.create("umilib_protocol_jwt_jws_clone", self.handle))


class JWEConfig(Handle):
    """What decrypting a JWE accepts (RFC 8725 §3.1): the algorithms, the critical header parameters
    understood, the largest PBES2 iteration count, and whether compressed plaintexts are accepted."""

    FREE = "umilib_protocol_jwt_jwe_config_free"
    MAXIMUM_PBES2_COUNT: ClassVar[int] = 1_000_000
    MAXIMUM_RECIPIENTS: ClassVar[int] = 16
    MAXIMUM_DECOMPRESSED: ClassVar[int] = 1 << 20

    def __init__(self, algorithms: Sequence[JWEAlgorithm], encryptions: Sequence[JWEEncryption], critical: Sequence[str] = ()) -> None:
        super().__init__(Handle.create("umilib_protocol_jwt_jwe_config_new", *Names.indices(algorithms), *Names.indices(encryptions)))
        for name in critical:
            self.understand(name)

    def understand(self, name: str) -> None:
        self.library.call("umilib_protocol_jwt_jwe_config_understand", self.handle, *Text.encode(name))

    def set_maximum_pbes2_count(self, count: int) -> None:
        self.library.call("umilib_protocol_jwt_jwe_config_set_maximum_pbes2_count", self.handle, count)

    def set_maximum_recipients(self, maximum: int) -> None:
        """Sets the most recipients a JWE may have (the work of one decryption)."""
        self.library.call("umilib_protocol_jwt_jwe_config_set_maximum_recipients", self.handle, maximum)

    def set_compression(self, compression: bool, maximum_decompressed: int = MAXIMUM_DECOMPRESSED) -> None:
        self.library.call("umilib_protocol_jwt_jwe_config_set_compression", self.handle, compression, maximum_decompressed)


class JWE(Handle):
    """A JWE (RFC 7516): its headers, recipients, JWE AAD and encrypted content."""

    FREE = "umilib_protocol_jwt_jwe_free"

    @staticmethod
    def encrypt(
        plaintext: bytes | bytearray | memoryview,
        protected: JOSEHeader,
        unprotected: JOSEHeader | None,
        recipients: Sequence[tuple[JWK, JOSEHeader | None]],
        aad: bytes | bytearray | memoryview | None,
        random: Any,
    ) -> JWE:
        """The JWE of ``plaintext`` for ``recipients``, each a key and its per-recipient header (RFC 7516 §5.1)."""
        keys = [key for key, _ in recipients]
        headers = [header for _, header in recipients]
        random_handle, random_name, random_length = random.source()
        # Every handle of the call is locked here, in the order of Handle.locked_all.
        handles = [*keys, *(header for header in [*headers, protected, unprotected] if header is not None), random_handle]
        with Handle.locked_all(*handles):
            key_array = (ctypes.c_void_p * len(keys))(*[key.pointer for key in keys])
            header_array = (ctypes.c_void_p * len(headers))(*[None if header is None else header.pointer for header in headers])
            aad_data, aad_length = Bytes.readable(aad if aad is not None else b"")
            pointer = Handle.create(
                "umilib_protocol_jwt_jwe_encrypt",
                *Bytes.readable(plaintext),
                protected,
                unprotected,
                ctypes.cast(key_array, ctypes.c_void_p),
                ctypes.cast(header_array, ctypes.c_void_p),
                len(keys),
                aad_data,
                aad_length,
                aad is not None,
                random_handle,
                random_name,
                random_length,
            )
        return JWE(pointer)

    def decrypt(self, key: JWK, config: JWEConfig, random: Any) -> tuple[bytes, int]:
        """Decrypts the JWE with ``key`` (RFC 7516 §5.2): the plaintext and the index of the recipient."""
        buffer = Buffer()
        recipient = ctypes.c_size_t()
        self.library.call("umilib_protocol_jwt_jwe_decrypt", self.handle, key, config, *random.source(), ctypes.byref(buffer), ctypes.byref(recipient))
        return self.library.take(buffer), recipient.value

    def __len__(self) -> int:
        """The number of recipients."""
        return self.library.value("umilib_protocol_jwt_jwe_recipient_count", ctypes.c_size_t, self.handle)

    def joined_header(self, index: int) -> JOSEHeader:
        """The JOSE Header of the recipient at ``index``: the union of its headers."""
        return JOSEHeader(Handle.create("umilib_protocol_jwt_jwe_recipient_header", self.handle, index))

    @staticmethod
    def from_compact(text: str) -> JWE:
        return JWE(Handle.create("umilib_protocol_jwt_jwe_from_compact", *Text.encode(text)))

    def to_compact(self) -> str:
        return self.library.output("umilib_protocol_jwt_jwe_to_compact", self.handle).decode()

    @staticmethod
    def from_json(text: bytes | bytearray | memoryview | str) -> JWE:
        if isinstance(text, str):
            text = text.encode()
        return JWE(Handle.create("umilib_protocol_jwt_jwe_from_json", *Bytes.readable(text)))

    def to_json(self) -> str:
        return self.library.output("umilib_protocol_jwt_jwe_to_json", self.handle, False).decode()

    def to_flattened_json(self) -> str:
        return self.library.output("umilib_protocol_jwt_jwe_to_json", self.handle, True).decode()

    def clone(self) -> JWE:
        return JWE(Handle.create("umilib_protocol_jwt_jwe_clone", self.handle))


class JWTClaims(Handle):
    """A JWT Claims Set (RFC 7519 §4): a JSON object of claims, kept in order."""

    FREE = "umilib_protocol_jwt_jwt_claims_free"

    def __init__(self, pointer: int | None = None) -> None:
        super().__init__(pointer if pointer is not None else Handle.create("umilib_protocol_jwt_jwt_claims_new"))

    @staticmethod
    def new() -> JWTClaims:
        return JWTClaims()

    @staticmethod
    def decode(data: bytes | bytearray | memoryview | str) -> JWTClaims:
        """The claims of the JSON text ``data``, an object without duplicate names."""
        if isinstance(data, str):
            data = data.encode()
        return JWTClaims(Handle.create("umilib_protocol_jwt_jwt_claims_decode", *Bytes.readable(data)))

    def encode(self) -> str:
        return self.library.output("umilib_protocol_jwt_jwt_claims_encode", self.handle).decode()

    def get(self, name: str) -> JSONValue | None:
        pointer = Library.default().optional("umilib_protocol_jwt_jwt_claims_get", ctypes.c_void_p, self.handle, *Text.encode(name))
        return None if pointer is None else JSONValue(pointer)

    def set(self, name: str, value: JSONValue) -> None:
        self.library.call("umilib_protocol_jwt_jwt_claims_set", self.handle, *Text.encode(name), value)

    def set_string(self, name: str, value: str) -> None:
        self.library.call("umilib_protocol_jwt_jwt_claims_set_string", self.handle, *Text.encode(name), *Text.encode(value))

    def set_numeric_date(self, name: str, seconds: int) -> None:
        """Sets ``name`` to the NumericDate ``seconds`` (RFC 7519 §2)."""
        self.library.call("umilib_protocol_jwt_jwt_claims_set_numeric_date", self.handle, *Text.encode(name), seconds)

    def remove(self, name: str) -> bool:
        return self.library.value("umilib_protocol_jwt_jwt_claims_remove", ctypes.c_bool, self.handle, *Text.encode(name))

    def value(self, name: str) -> Any:
        """The claim ``name`` as Python objects, or ``None``."""
        claim = self.get(name)
        return None if claim is None else claim.to_python()

    def issuer(self) -> str | None:
        return self.value("iss")

    def subject(self) -> str | None:
        return self.value("sub")

    def audience(self) -> list[str]:
        """``aud``: a string or strings; empty when absent."""
        audience = self.value("aud")
        return [] if audience is None else [audience] if isinstance(audience, str) else list(audience)

    def expiration(self) -> float | None:
        return self.value("exp")

    def not_before(self) -> float | None:
        return self.value("nbf")

    def issued_at(self) -> float | None:
        return self.value("iat")

    def jwt_id(self) -> str | None:
        return self.value("jti")

    def clone(self) -> JWTClaims:
        return JWTClaims(Handle.create("umilib_protocol_jwt_jwt_claims_clone", self.handle))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, JWTClaims) and JSONValue.parse(self.encode()) == JSONValue.parse(other.encode())


class JWTValidation(Handle):
    """What a JWT must satisfy (RFC 7519 §7.2, RFC 8725 §3): the time ``now`` in seconds since the epoch, with
    ``leeway`` seconds for ``exp`` and ``nbf``; the issuer, audience and subject expected; the expected
    ``typ``; and the claims required."""

    FREE = "umilib_protocol_jwt_jwt_validation_free"

    def __init__(
        self,
        now: int,
        leeway: int = 0,
        issuer: str | None = None,
        audience: str | None = None,
        subject: str | None = None,
        token_type: str | None = None,
        required: Sequence[str] = (),
    ) -> None:
        super().__init__(Handle.create("umilib_protocol_jwt_jwt_validation_new", now))
        self.library.call("umilib_protocol_jwt_jwt_validation_set_leeway", self.handle, leeway)
        for member, value in (("issuer", issuer), ("audience", audience), ("subject", subject), ("token_type", token_type)):
            self.library.call(f"umilib_protocol_jwt_jwt_validation_set_{member}", self.handle, *Text.encode(value))
        for name in required:
            self.library.call("umilib_protocol_jwt_jwt_validation_require", self.handle, *Text.encode(name))

    def validate(self, header: JOSEHeader, claims: JWTClaims) -> None:
        """Checks ``claims``, held by ``header``."""
        self.library.call("umilib_protocol_jwt_jwt_validation_validate", self.handle, header, claims)


class JWT(Handle):
    """A JWT that verified or decrypted: the header that holds its claims, and the claims. Each form of JWT
    (JWS, JWE, JWS inside a JWE) has its pair of functions (RFC 8725 §3.12)."""

    FREE = "umilib_protocol_jwt_jwt_free"

    @property
    def header(self) -> JOSEHeader:
        return JOSEHeader(Handle.create("umilib_protocol_jwt_jwt_header", self.handle))

    @property
    def claims(self) -> JWTClaims:
        return JWTClaims(Handle.create("umilib_protocol_jwt_jwt_claims", self.handle))

    @staticmethod
    def sign(claims: JWTClaims, header: JOSEHeader, key: JWK, random: Any) -> str:
        """The compact JWS of ``claims`` with the protected header ``header`` under ``key``."""
        return Library.default().output("umilib_protocol_jwt_jwt_sign", claims, header, key, *random.source()).decode()

    @staticmethod
    def verify(text: str, key: JWK, config: JWSConfig, validation: JWTValidation) -> JWT:
        """The JWT of the compact JWS ``text``, verified and validated (RFC 7519 §7.2)."""
        return JWT(Handle.create("umilib_protocol_jwt_jwt_verify", *Text.encode(text), key, config, validation))

    @staticmethod
    def verify_unsecured(text: str, validation: JWTValidation) -> JWT:
        """The JWT of an Unsecured JWS (RFC 7519 §6), as an explicit decision of the application."""
        return JWT(Handle.create("umilib_protocol_jwt_jwt_verify_unsecured", *Text.encode(text), validation))

    @staticmethod
    def encrypt(claims: JWTClaims, header: JOSEHeader, key: JWK, random: Any) -> str:
        """The compact JWE of ``claims`` with the protected header ``header`` for ``key``."""
        return Library.default().output("umilib_protocol_jwt_jwt_encrypt", claims, header, key, *random.source()).decode()

    @staticmethod
    def decrypt(text: str, key: JWK, config: JWEConfig, validation: JWTValidation, random: Any) -> JWT:
        """The JWT of the compact JWE ``text``, decrypted and validated."""
        return JWT(Handle.create("umilib_protocol_jwt_jwt_decrypt", *Text.encode(text), key, config, validation, *random.source()))

    @staticmethod
    def sign_and_encrypt(
        claims: JWTClaims, signing_header: JOSEHeader, signing_key: JWK, encryption_header: JOSEHeader, encryption_key: JWK, random: Any
    ) -> str:
        """A Nested JWT (RFC 7519 §5.2): the JWS of ``claims`` in a JWE with the ``cty`` of "JWT"."""
        return (
            Library.default()
            .output("umilib_protocol_jwt_jwt_sign_and_encrypt", claims, signing_header, signing_key, encryption_header, encryption_key, *random.source())
            .decode()
        )

    @staticmethod
    def decrypt_and_verify(
        text: str,
        decryption_key: JWK,
        decryption: JWEConfig,
        verification_key: JWK,
        verification: JWSConfig,
        validation: JWTValidation,
        random: Any,
    ) -> JWT:
        """The JWT of the Nested JWT ``text``: decrypted, verified and validated."""
        return JWT(
            Handle.create(
                "umilib_protocol_jwt_jwt_decrypt_and_verify", *Text.encode(text), decryption_key, decryption, verification_key, verification, validation, *random.source()
            )
        )


__all__ = [
    "JOSEHeader",
    "JWE",
    "JWEAlgorithm",
    "JWEConfig",
    "JWEEncryption",
    "JWK",
    "JWKSet",
    "JWS",
    "JWSAlgorithm",
    "JWSConfig",
    "JWT",
    "JWTClaims",
    "JWTError",
    "JWTValidation",
]
