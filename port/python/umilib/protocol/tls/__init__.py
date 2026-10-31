"""Transport Layer Security: TLS 1.3 (RFC 9846) and TLS 1.2 (RFC 5246), with resumption and early
data, post-handshake authentication, OCSP stapling, record size limits (RFC 8449) and Encrypted
ClientHello (RFC 9849). Mirrors ``umilib::protocol::tls``.

A :class:`TLSConnection` does no I/O: give it the bytes that arrive with :meth:`TLSConnection.receive`
and send what :meth:`TLSConnection.transmit` returns after each call. Versions, cipher suites, groups,
signature schemes and alerts are their IANA numbers (:class:`TLSVersion` and the like name some).
Times are seconds since 1970. Errors are :class:`TLSError`; :meth:`TLSConnection.error` tells the alert.
"""

from __future__ import annotations

import ctypes
import dataclasses
import enum
import os
from typing import Any, ClassVar

from umilib.auth.cert.key import PrivateKey
from umilib.auth.cert.path import TrustAnchor
from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Text, Words


__all__ = [
    "TLSAlertDescription",
    "TLSCertifiedKey",
    "TLSCipherSuite",
    "TLSClientAuthentication",
    "TLSClientConfig",
    "TLSClientOptions",
    "TLSConfig",
    "TLSConnection",
    "TLSECHCipherSuite",
    "TLSECHKey",
    "TLSECHStatus",
    "TLSEarlyData",
    "TLSError",
    "TLSErrorKind",
    "TLSEvent",
    "TLSFailure",
    "TLSLimits",
    "TLSNamedGroup",
    "TLSPathVerifier",
    "TLSRule",
    "TLSServerConfig",
    "TLSServerOptions",
    "TLSSession",
    "TLSSignatureScheme",
    "TLSStructures",
    "TLSVersion",
]


class TLSError(FFIError):
    """An error of TLS: ``Protocol`` (the peer broke the protocol), ``Alert`` (the peer sent a fatal
    alert), ``State`` or ``Config``. :meth:`TLSConnection.error` tells the alert."""


Library.register_error("protocol.tls", TLSError)


class TLSVersion(int):
    """A protocol version (RFC 9846 §4.2.2)."""

    TLS1_2: ClassVar[TLSVersion]
    TLS1_3: ClassVar[TLSVersion]


TLSVersion.TLS1_2, TLSVersion.TLS1_3 = TLSVersion(0x0303), TLSVersion(0x0304)


class TLSCipherSuite(int):
    """A cipher suite (the IANA registry)."""

    TLS_AES_128_GCM_SHA256: ClassVar[TLSCipherSuite]
    TLS_AES_256_GCM_SHA384: ClassVar[TLSCipherSuite]
    TLS_CHACHA20_POLY1305_SHA256: ClassVar[TLSCipherSuite]
    TLS_AES_128_CCM_SHA256: ClassVar[TLSCipherSuite]
    TLS_AES_128_CCM_8_SHA256: ClassVar[TLSCipherSuite]
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: ClassVar[TLSCipherSuite]
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: ClassVar[TLSCipherSuite]
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: ClassVar[TLSCipherSuite]
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: ClassVar[TLSCipherSuite]
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: ClassVar[TLSCipherSuite]
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: ClassVar[TLSCipherSuite]


for _name, _value in [
    ("TLS_AES_128_GCM_SHA256", 0x1301), ("TLS_AES_256_GCM_SHA384", 0x1302), ("TLS_CHACHA20_POLY1305_SHA256", 0x1303),
    ("TLS_AES_128_CCM_SHA256", 0x1304), ("TLS_AES_128_CCM_8_SHA256", 0x1305),
    ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02B), ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0xC02C),
    ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC02F), ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xC030),
    ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA8), ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA9),
]:  # fmt: skip
    setattr(TLSCipherSuite, _name, TLSCipherSuite(_value))


class TLSNamedGroup(int):
    """A group of key exchange (RFC 9846 §4.3.7, RFC 7919, RFC 10024)."""

    SECP256R1: ClassVar[TLSNamedGroup]
    SECP384R1: ClassVar[TLSNamedGroup]
    SECP521R1: ClassVar[TLSNamedGroup]
    X25519: ClassVar[TLSNamedGroup]
    X448: ClassVar[TLSNamedGroup]
    FFDHE2048: ClassVar[TLSNamedGroup]
    SECP256R1_MLKEM768: ClassVar[TLSNamedGroup]
    X25519_MLKEM768: ClassVar[TLSNamedGroup]
    SECP384R1_MLKEM1024: ClassVar[TLSNamedGroup]


for _name, _value in [
    ("SECP256R1", 0x0017), ("SECP384R1", 0x0018), ("SECP521R1", 0x0019), ("X25519", 0x001D), ("X448", 0x001E),
    ("FFDHE2048", 0x0100), ("SECP256R1_MLKEM768", 0x11EB), ("X25519_MLKEM768", 0x11EC), ("SECP384R1_MLKEM1024", 0x11ED),
]:  # fmt: skip
    setattr(TLSNamedGroup, _name, TLSNamedGroup(_value))


class TLSSignatureScheme(int):
    """A signature scheme (RFC 9846 §4.3.3)."""

    RSA_PKCS1_SHA256: ClassVar[TLSSignatureScheme]
    ECDSA_SECP256R1_SHA256: ClassVar[TLSSignatureScheme]
    ECDSA_SECP384R1_SHA384: ClassVar[TLSSignatureScheme]
    RSA_PSS_RSAE_SHA256: ClassVar[TLSSignatureScheme]
    ED25519: ClassVar[TLSSignatureScheme]
    ED448: ClassVar[TLSSignatureScheme]


for _name, _value in [
    ("RSA_PKCS1_SHA256", 0x0401), ("ECDSA_SECP256R1_SHA256", 0x0403), ("ECDSA_SECP384R1_SHA384", 0x0503),
    ("RSA_PSS_RSAE_SHA256", 0x0804), ("ED25519", 0x0807), ("ED448", 0x0808),
]:  # fmt: skip
    setattr(TLSSignatureScheme, _name, TLSSignatureScheme(_value))


class TLSAlertDescription(int):
    """The description of an alert (RFC 9846 §6)."""

    CLOSE_NOTIFY: ClassVar[TLSAlertDescription]
    UNEXPECTED_MESSAGE: ClassVar[TLSAlertDescription]
    BAD_RECORD_MAC: ClassVar[TLSAlertDescription]
    HANDSHAKE_FAILURE: ClassVar[TLSAlertDescription]
    BAD_CERTIFICATE: ClassVar[TLSAlertDescription]
    CERTIFICATE_EXPIRED: ClassVar[TLSAlertDescription]
    ILLEGAL_PARAMETER: ClassVar[TLSAlertDescription]
    UNKNOWN_CA: ClassVar[TLSAlertDescription]
    DECODE_ERROR: ClassVar[TLSAlertDescription]
    DECRYPT_ERROR: ClassVar[TLSAlertDescription]
    PROTOCOL_VERSION: ClassVar[TLSAlertDescription]
    INTERNAL_ERROR: ClassVar[TLSAlertDescription]
    MISSING_EXTENSION: ClassVar[TLSAlertDescription]
    CERTIFICATE_REQUIRED: ClassVar[TLSAlertDescription]
    NO_APPLICATION_PROTOCOL: ClassVar[TLSAlertDescription]
    ECH_REQUIRED: ClassVar[TLSAlertDescription]


for _name, _value in [
    ("CLOSE_NOTIFY", 0), ("UNEXPECTED_MESSAGE", 10), ("BAD_RECORD_MAC", 20), ("HANDSHAKE_FAILURE", 40),
    ("BAD_CERTIFICATE", 42), ("CERTIFICATE_EXPIRED", 45), ("ILLEGAL_PARAMETER", 47), ("UNKNOWN_CA", 48),
    ("DECODE_ERROR", 50), ("DECRYPT_ERROR", 51), ("PROTOCOL_VERSION", 70), ("INTERNAL_ERROR", 80),
    ("MISSING_EXTENSION", 109), ("CERTIFICATE_REQUIRED", 116), ("NO_APPLICATION_PROTOCOL", 120), ("ECH_REQUIRED", 121),
]:  # fmt: skip
    setattr(TLSAlertDescription, _name, TLSAlertDescription(_value))
del _name, _value


class TLSEvent(enum.IntEnum):
    """What happened on a connection that the application may act on."""

    CONNECTED = 0
    READABLE = 1
    PEER_CLOSED = 2
    AUTHENTICATED = 3


class TLSEarlyData(enum.IntEnum):
    """What became of early data (RFC 9846 §4.2.10)."""

    NOT_OFFERED = 0
    OFFERED = 1
    ACCEPTED = 2
    REJECTED = 3


class TLSECHStatus(enum.IntEnum):
    """Whether the ClientHello was encrypted (RFC 9849)."""

    NOT_OFFERED = 0
    GREASE = 1
    OFFERED = 2
    ACCEPTED = 3
    REJECTED = 4


class TLSClientAuthentication(enum.IntEnum):
    """Whether a server asks clients for a certificate."""

    OFF = 0
    OPTIONAL = 1
    REQUIRED = 2


class TLSErrorKind(enum.IntEnum):
    """The variant of the error that ended a connection."""

    PROTOCOL = 0
    ALERT = 1
    STATE = 2
    CONFIG = 3
    WRITE = 4
    TRANSPORT = 5


@dataclasses.dataclass(frozen=True)
class TLSFailure:
    """Why a connection failed: the kind of error and, for ``PROTOCOL`` the alert sent, for ``ALERT``
    the alert received."""

    kind: TLSErrorKind
    alert: TLSAlertDescription


@dataclasses.dataclass
class TLSLimits:
    """The limits of a :class:`TLSConfig`."""

    FIELDS: ClassVar[tuple[str, ...]] = (
        "maximum_handshake_message", "record_size_limit", "maximum_buffered_data", "maximum_key_updates",
        "require_extended_main_secret", "maximum_ignored_records",
    )  # fmt: skip

    maximum_handshake_message: int = 1 << 16
    record_size_limit: int = 1 << 14
    maximum_buffered_data: int = 1 << 20
    maximum_key_updates: int = 32
    require_extended_main_secret: bool = True
    maximum_ignored_records: int = 32


@dataclasses.dataclass
class TLSClientOptions:
    """The flags of a :class:`TLSClientConfig`."""

    FIELDS: ClassVar[tuple[str, ...]] = (
        "middlebox_compatibility", "send_server_name", "request_certificate_status", "post_handshake_authentication",
        "early_data", "ech_grease",
    )  # fmt: skip

    middlebox_compatibility: bool = True
    send_server_name: bool = True
    request_certificate_status: bool = False
    post_handshake_authentication: bool = False
    early_data: bool = False
    ech_grease: bool = False


@dataclasses.dataclass
class TLSServerOptions:
    """The numbers and flags of a :class:`TLSServerConfig`."""

    FIELDS: ClassVar[tuple[str, ...]] = (
        "prefer_own_cipher_suites", "client_authentication", "ticket_count", "ticket_lifetime", "maximum_early_data",
        "freshness_window",
    )  # fmt: skip

    prefer_own_cipher_suites: bool = True
    client_authentication: TLSClientAuthentication = TLSClientAuthentication.OFF
    ticket_count: int = 2
    ticket_lifetime: int = 7200
    maximum_early_data: int = 0
    freshness_window: int = 10


class TLSStructures:
    """Conversions of the dataclasses of this module and of number lists to the C ABI."""

    @staticmethod
    def structure(name: str, value: Any) -> Any:
        """The structure ``name`` of the fields of ``value``."""
        structure = Library.default().type(f"umilib_protocol_tls_{name}")()
        for field in value.FIELDS:
            item = getattr(value, field)
            Fields.assign(structure, field, int(item) if isinstance(item, enum.Enum) else item)
        return structure

    @staticmethod
    def numbers(values: list[int]) -> tuple[Any, int]:
        """An array of 16-bit numbers and its count."""
        if not values:
            return None, 0
        return Words.array(ctypes.c_uint16, [int(value) for value in values], len(values)), len(values)


class TLSConfig(Handle):
    """What both ends configure: versions, cipher suites, groups, signature schemes, application
    protocols and limits, most preferred first; every one compiled in by default."""

    FREE = "umilib_protocol_tls_tls_config_free"

    def __init__(self, pointer: int | None = None) -> None:
        super().__init__(pointer or Handle.create("umilib_protocol_tls_tls_config_new"))

    def set_versions(self, versions: list[int]) -> None:
        self.library.call("umilib_protocol_tls_tls_config_set_versions", self.handle, *TLSStructures.numbers(versions))

    def set_cipher_suites(self, suites: list[int]) -> None:
        self.library.call("umilib_protocol_tls_tls_config_set_cipher_suites", self.handle, *TLSStructures.numbers(suites))

    def set_groups(self, groups: list[int]) -> None:
        self.library.call("umilib_protocol_tls_tls_config_set_groups", self.handle, *TLSStructures.numbers(groups))

    def set_signature_schemes(self, schemes: list[int]) -> None:
        self.library.call("umilib_protocol_tls_tls_config_set_signature_schemes", self.handle, *TLSStructures.numbers(schemes))

    def set_protocols(self, protocols: list[bytes]) -> None:
        pointers, lengths, count, _kept = Bytes.array(protocols)
        self.library.call("umilib_protocol_tls_tls_config_set_protocols", self.handle, pointers, lengths, count)

    @property
    def limits(self) -> TLSLimits:
        structure = Library.default().type("umilib_protocol_tls_TLSLimits")()
        self.library.call("umilib_protocol_tls_tls_config_limits", self.handle, ctypes.byref(structure))
        return TLSLimits(**{field: getattr(structure, field) for field in TLSLimits.FIELDS})

    @limits.setter
    def limits(self, limits: TLSLimits) -> None:
        self.library.call("umilib_protocol_tls_tls_config_set_limits", self.handle, ctypes.byref(TLSStructures.structure("TLSLimits", limits)))


class TLSPathVerifier(Handle):
    """Path validation of peers' certificates to trust anchors (RFC 5280, RFC 9525)."""

    FREE = "umilib_protocol_tls_tls_path_verifier_free"

    @staticmethod
    def anchors(anchors: list[TrustAnchor]) -> Any:
        library = Library.default()
        handle = ctypes.c_void_p(Handle.create("umilib_auth_cert_path_trust_anchors_new"))
        for anchor in anchors:
            library.call("umilib_auth_cert_path_trust_anchors_push", handle, anchor)
        return handle

    @classmethod
    def servers(cls, anchors: list[TrustAnchor]) -> TLSPathVerifier:
        """The verification of servers: the Web PKI profile, ``id-kp-serverAuth``."""
        return cls.of("umilib_protocol_tls_tls_path_verifier_servers", anchors)

    @classmethod
    def clients(cls, anchors: list[TrustAnchor]) -> TLSPathVerifier:
        """The verification of clients: the profile of RFC 5280, ``id-kp-clientAuth``."""
        return cls.of("umilib_protocol_tls_tls_path_verifier_clients", anchors)

    @classmethod
    def of(cls, name: str, anchors: list[TrustAnchor]) -> TLSPathVerifier:
        handle = TLSPathVerifier.anchors(anchors)
        try:
            return cls(Handle.create(name, handle))
        finally:
            Library.default().function("umilib_auth_cert_path_trust_anchors_free")(handle)


class TLSCertifiedKey(Handle):
    """A certificate chain (DER, the end-entity certificate first) and the private key of its first
    certificate, with an OCSP response to staple."""

    FREE = "umilib_protocol_tls_tls_certified_key_free"

    @classmethod
    def new(cls, chain: list[bytes], key: PrivateKey, ocsp: bytes | None = None) -> TLSCertifiedKey:
        """The certified key of ``chain`` and ``key``, which it takes: ``key`` is released."""
        pointers, lengths, count, _kept = Bytes.array(chain)
        with key.locked():
            out = ctypes.c_void_p()
            Library.default().call("umilib_protocol_tls_tls_certified_key_new", pointers, lengths, count, key.pointer, *Bytes.readable(ocsp or b""), ctypes.byref(out))
            key.consumed()
        return cls(out.value)


@dataclasses.dataclass(frozen=True)
class TLSECHCipherSuite:
    """A pair of an HPKE KDF and AEAD (RFC 9849 §4)."""

    MANDATORY: ClassVar[TLSECHCipherSuite]

    kdf_id: int
    aead_id: int


TLSECHCipherSuite.MANDATORY = TLSECHCipherSuite(0x0001, 0x0001)


class TLSECHKey(Handle):
    """An ECH configuration and its private key, which a client-facing server holds (RFC 9849 §7)."""

    FREE = "umilib_protocol_tls_tls_ech_key_free"
    DHKEM_P256: ClassVar[int] = 0x0010
    DHKEM_X25519: ClassVar[int] = 0x0020

    @classmethod
    def generate(
        cls,
        config_id: int,
        public_name: str,
        kem_id: int = 0x0020,
        cipher_suites: list[TLSECHCipherSuite] | None = None,
        maximum_name_length: int = 0,
        retry: bool = True,
        seed: bytes | None = None,
    ) -> TLSECHKey:
        """A new key of the KEM ``kem_id`` for the configuration ``config_id`` of ``public_name``."""
        suites = cipher_suites or [TLSECHCipherSuite(0x0001, 0x0001)]
        numbers = [number for suite in suites for number in (suite.kdf_id, suite.aead_id)]
        pairs = Words.array(ctypes.c_uint16, numbers, len(numbers))
        return cls(Handle.create(
            "umilib_protocol_tls_tls_ech_key_generate", config_id, kem_id, pairs, len(suites), maximum_name_length, *Text.encode(public_name),
            retry, *Bytes.readable(seed or os.urandom(48)),
        ))  # fmt: skip

    @classmethod
    def new(cls, config_list: bytes, private_key: bytes, retry: bool = True) -> TLSECHKey:
        """The key of the first configuration of ``config_list`` and the KEM's serialized ``private_key``."""
        return cls(Handle.create("umilib_protocol_tls_tls_ech_key_new", *Bytes.readable(config_list), *Bytes.readable(private_key), retry))

    @property
    def config_list(self) -> bytes:
        """The ``ECHConfigList`` of the configuration, which clients are given."""
        return self.library.output("umilib_protocol_tls_tls_ech_key_config_list", self.handle)

    @property
    def private_key(self) -> bytearray:
        return self.library.output_secret("umilib_protocol_tls_tls_ech_key_private_key", self.handle)


class TLSClientConfig(Handle):
    """The configuration of clients: a :class:`TLSConfig` and what checks servers."""

    FREE = "umilib_protocol_tls_tls_client_config_free"

    @classmethod
    def new(cls, config: TLSConfig, verifier: TLSPathVerifier) -> TLSClientConfig:
        return cls(Handle.create("umilib_protocol_tls_tls_client_config_new", config, verifier))

    def set_options(self, options: TLSClientOptions) -> None:
        self.library.call("umilib_protocol_tls_tls_client_config_set_options", self.handle, ctypes.byref(TLSStructures.structure("TLSClientOptions", options)))

    def set_key_share_groups(self, groups: list[int]) -> None:
        self.library.call("umilib_protocol_tls_tls_client_config_set_key_share_groups", self.handle, *TLSStructures.numbers(groups))

    def set_certificate(self, key: TLSCertifiedKey | None) -> None:
        self.library.call("umilib_protocol_tls_tls_client_config_set_certificate", self.handle, key)

    def set_session_cache(self, capacity: int) -> None:
        """Keeps up to ``capacity`` tickets of servers to resume their sessions; none for 0."""
        self.library.call("umilib_protocol_tls_tls_client_config_set_session_cache", self.handle, capacity)

    def set_ech_configs(self, config_list: bytes) -> None:
        """Encrypts the ClientHello with the first usable configuration of the ``ECHConfigList``."""
        self.library.call("umilib_protocol_tls_tls_client_config_set_ech_configs", self.handle, *Bytes.readable(config_list))


class TLSServerConfig(Handle):
    """The configuration of servers: a :class:`TLSConfig`, the certificates to present, and what
    makes tickets, refuses replays and decrypts ClientHellos."""

    FREE = "umilib_protocol_tls_tls_server_config_free"

    @classmethod
    def new(cls, config: TLSConfig, certificates: list[TLSCertifiedKey]) -> TLSServerConfig:
        server = cls(Handle.create("umilib_protocol_tls_tls_server_config_new", config))
        for certificate in certificates:
            server.add_certificate(certificate)
        return server

    def add_certificate(self, key: TLSCertifiedKey) -> None:
        self.library.call("umilib_protocol_tls_tls_server_config_add_certificate", self.handle, key)

    def set_options(self, options: TLSServerOptions) -> None:
        self.library.call("umilib_protocol_tls_tls_server_config_set_options", self.handle, ctypes.byref(TLSStructures.structure("TLSServerOptions", options)))

    def set_client_verifier(self, verifier: TLSPathVerifier | None) -> None:
        self.library.call("umilib_protocol_tls_tls_server_config_set_client_verifier", self.handle, verifier)

    def set_ticket_key(self, name: bytes, key: bytes) -> None:
        """Makes tickets with the AES-256-GCM ``key`` (32 bytes) named ``name`` (16 bytes)."""
        if len(name) != 16 or len(key) != 32:
            raise ValueError("a ticket key is named by 16 bytes and is 32 bytes")
        self.library.call("umilib_protocol_tls_tls_server_config_set_ticket_key", self.handle, bytes(name), bytes(key))

    def set_replay_cache(self, window: int, capacity: int) -> None:
        self.library.call("umilib_protocol_tls_tls_server_config_set_replay_cache", self.handle, window, capacity)

    def add_ech_key(self, key: TLSECHKey) -> None:
        self.library.call("umilib_protocol_tls_tls_server_config_add_ech_key", self.handle, key)


@dataclasses.dataclass(frozen=True)
class TLSSession:
    """What a connection negotiated; ``None`` for what is not negotiated yet."""

    version: TLSVersion | None
    cipher_suite: TLSCipherSuite | None
    group: TLSNamedGroup | None
    peer_signature_scheme: TLSSignatureScheme | None
    resumed: bool
    early_data: TLSEarlyData
    ech: TLSECHStatus
    handshaking: bool


class TLSConnection(Handle):
    """A TLS connection without I/O (RFC 9846, RFC 5246)."""

    FREE = "umilib_protocol_tls_tls_connection_free"

    @classmethod
    def client(cls, config: TLSClientConfig, server_name: str | None, time: int, seed: bytes | None = None) -> TLSConnection:
        """A client connecting to ``server_name`` (a DNS name, or an address its certificate must name) at
        ``time``, its ClientHello written; randomness is seeded from the operating system unless ``seed``."""
        return cls(Handle.create("umilib_protocol_tls_tls_connection_client", config, *Text.encode(server_name or ""), *Bytes.readable(seed or os.urandom(48)), time))

    @classmethod
    def server(cls, config: TLSServerConfig, time: int, seed: bytes | None = None) -> TLSConnection:
        return cls(Handle.create("umilib_protocol_tls_tls_connection_server", config, *Bytes.readable(seed or os.urandom(48)), time))

    def receive(self, data: bytes) -> None:
        """Takes bytes received from the transport; raises :class:`TLSError` when the connection fails."""
        self.library.call("umilib_protocol_tls_tls_connection_receive", self.handle, *Bytes.readable(data))

    def transmit(self) -> bytes:
        """The bytes to send to the transport."""
        return self.library.output("umilib_protocol_tls_tls_connection_transmit", self.handle)

    def send(self, data: bytes) -> None:
        """Sends application data, or early data the handshake allows; raises ``State`` otherwise."""
        self.library.call("umilib_protocol_tls_tls_connection_send", self.handle, *Bytes.readable(data))

    def read(self, size: int) -> bytes:
        out = (ctypes.c_uint8 * max(size, 1))()
        count = self.library.value("umilib_protocol_tls_tls_connection_read", ctypes.c_size_t, self.handle, out, size)
        return bytes(out[:count])

    def poll_event(self) -> TLSEvent | None:
        found, kind = ctypes.c_bool(), ctypes.c_uint8()
        self.library.call("umilib_protocol_tls_tls_connection_poll_event", self.handle, ctypes.byref(found), ctypes.byref(kind))
        return TLSEvent(kind.value) if found.value else None

    def close(self) -> None:
        """Sends close_notify (RFC 9846 §6.1). :meth:`free` releases the object."""
        self.library.call("umilib_protocol_tls_tls_connection_close", self.handle)

    def update_keys(self, request: bool) -> None:
        self.library.call("umilib_protocol_tls_tls_connection_update_keys", self.handle, request)

    def request_certificate(self) -> None:
        self.library.call("umilib_protocol_tls_tls_connection_request_certificate", self.handle)

    def export(self, label: bytes, context: bytes | None, length: int) -> bytearray:
        """Keying material (RFC 9846 §7.5, RFC 5705)."""
        out = bytearray(length)
        self.library.call(
            "umilib_protocol_tls_tls_connection_export", self.handle, *Bytes.readable(label), context is not None, *Bytes.readable(context or b""),
            Bytes.mutable(out), length,
        )  # fmt: skip
        return out

    @property
    def session(self) -> TLSSession:
        structure = Library.default().type("umilib_protocol_tls_TLSSession")()
        self.library.call("umilib_protocol_tls_tls_connection_session", self.handle, ctypes.byref(structure))
        return TLSSession(
            version=TLSVersion(structure.version) if structure.version else None,
            cipher_suite=TLSCipherSuite(structure.cipher_suite) if structure.cipher_suite else None,
            group=TLSNamedGroup(structure.group) if structure.group else None,
            peer_signature_scheme=TLSSignatureScheme(structure.peer_signature_scheme) if structure.peer_signature_scheme else None,
            resumed=structure.resumed,
            early_data=TLSEarlyData(structure.early_data),
            ech=TLSECHStatus(structure.ech),
            handshaking=structure.handshaking,
        )

    @property
    def protocol(self) -> bytes | None:
        return self.library.optional("umilib_protocol_tls_tls_connection_protocol", Buffer, self.handle)

    @property
    def server_name(self) -> str | None:
        name = self.library.optional("umilib_protocol_tls_tls_connection_server_name", Buffer, self.handle)
        return None if name is None else name.decode("utf-8")

    @property
    def peer_certificates(self) -> list[bytes]:
        certificates = []
        while (certificate := self.library.optional("umilib_protocol_tls_tls_connection_peer_certificate", Buffer, self.handle, len(certificates))) is not None:
            certificates.append(certificate)
        return certificates

    @property
    def certificate_status(self) -> bytes | None:
        """The OCSP response the server stapled (RFC 6066 §8)."""
        return self.library.optional("umilib_protocol_tls_tls_connection_certificate_status", Buffer, self.handle)

    @property
    def ech_retry_configs(self) -> bytes | None:
        """The ``ECHConfigList`` of a server that rejected ECH (RFC 9849 §6.1.6)."""
        return self.library.optional("umilib_protocol_tls_tls_connection_ech_retry_configs", Buffer, self.handle)

    def error(self) -> TLSFailure | None:
        """Why the connection failed, if it did."""
        failed, kind, alert = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_uint8()
        self.library.call("umilib_protocol_tls_tls_connection_error", self.handle, ctypes.byref(failed), ctypes.byref(kind), ctypes.byref(alert))
        return TLSFailure(TLSErrorKind(kind.value), TLSAlertDescription(alert.value)) if failed.value else None


class TLSRule(Handle):
    """A rule that routes TLS connections by server name (``*`` any, ``*.domain`` one label of the
    domain, ``""`` no name, otherwise that name) and, if given, application protocol."""

    FREE = "umilib_protocol_tls_tls_rule_free"

    @classmethod
    def new(cls, server_name: str, protocol: bytes | None = None) -> TLSRule:
        return cls(Handle.create("umilib_protocol_tls_tls_rule_new", *Text.encode(server_name), *Bytes.readable(protocol or b"")))

    def matches_session(self, connection: TLSConnection) -> bool:
        return bool(self.library.value("umilib_protocol_tls_tls_rule_matches_session", ctypes.c_bool, self.handle, connection))

    def matches_client_hello(self, body: bytes) -> bool:
        """Whether the rule matches the body of a ClientHello (without its handshake header)."""
        return bool(self.library.value("umilib_protocol_tls_tls_rule_matches_client_hello", ctypes.c_bool, self.handle, *Bytes.readable(body)))
