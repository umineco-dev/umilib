"""The Online Certificate Status Protocol (RFC 6960, with the nonce of RFC 8954). Mirrors ``umilib::auth::cert::ocsp``.

Certificate identifiers, requests, responses and their parts are handles;
certificates, names and extensions are those of :mod:`umilib.auth.cert.x509`,
keys and algorithms those of :mod:`umilib.auth.cert.key`. Times are seconds
since 1970-01-01T00:00:00Z and serial numbers integers. A list of
certificates given as ``None`` is the absent field. Errors are
:class:`OCSPStatusError`, or those of x509 and key for encodings and keys.
"""

from __future__ import annotations

import ctypes
import enum
from dataclasses import dataclass, field
from typing import Any, ClassVar

from umilib.auth.cert.key import HashAlgorithm, KeyLimits, PrivateKey, PublicKey, SignatureAlgorithm
from umilib.auth.cert.x509 import Certificate, Certificates, CRLReason, Extensions, GeneralName, Integer, Name
from umilib.ffi import Buffer, Bytes, FFIError, Handle, Library


class OCSPStatusError(FFIError):
    """An error of a request or a response: ``Version``, ``Status``, ``ResponseType``, ``Algorithm``,
    ``Signer``, ``NotFound``, ``Time``, ``Nonce`` or ``UnknownCriticalExtension``."""


Library.register_error("auth.cert.ocsp", OCSPStatusError)


class OCSPResponseStatus(enum.IntEnum):
    """The status of a response (RFC 6960 §4.2.1)."""

    Successful = 0
    MalformedRequest = 1
    InternalError = 2
    TryLater = 3
    SigRequired = 5
    Unauthorized = 6


class CertID(Handle):
    """The identifier of a certificate: hashes of its issuer's name and key, and its serial number."""

    FREE = "umilib_auth_cert_ocsp_cert_id_free"

    @staticmethod
    def new(certificate: Certificate, issuer_key: PublicKey, hash: HashAlgorithm) -> CertID:
        """The identifier of ``certificate``, issued by the holder of ``issuer_key``, with ``hash``."""
        return CertID(Handle.create("umilib_auth_cert_ocsp_cert_id_new", certificate, issuer_key, int(hash)))

    @staticmethod
    def from_der(data: bytes | bytearray | memoryview) -> CertID:
        return CertID(Handle.create("umilib_auth_cert_ocsp_cert_id_from_der", *Bytes.readable(data)))

    def to_der(self) -> bytes:
        return self.library.output("umilib_auth_cert_ocsp_cert_id_to_der", self.handle)

    @property
    def serial_number(self) -> int:
        return Integer.decode(self.library.output("umilib_auth_cert_ocsp_cert_id_serial_number", self.handle))

    def matches(self, other: CertID) -> bool:
        """Whether both name the same certificate (the same hash function, hashes and serial number)."""
        return bool(self.library.value("umilib_auth_cert_ocsp_cert_id_matches", ctypes.c_bool, self.handle, other))

    def identifies(self, certificate: Certificate, issuer_key: PublicKey) -> bool:
        """Whether the identifier names ``certificate``, issued by the holder of ``issuer_key``."""
        return bool(self.library.value("umilib_auth_cert_ocsp_cert_id_identifies", ctypes.c_bool, self.handle, certificate, issuer_key))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CertID) and self.to_der() == other.to_der()

    def __hash__(self) -> int:
        return hash(self.to_der())


@dataclass(frozen=True)
class CertStatus:
    """The status of a certificate (RFC 6960 §4.2.1): good, revoked (at ``time``, for ``reason`` if any) or unknown."""

    class Kind(enum.IntEnum):
        Good = 0
        Revoked = 1
        Unknown = 2

    NO_REASON: ClassVar[int] = 255

    kind: CertStatus.Kind
    time: int | None = None
    reason: CRLReason | None = None

    @staticmethod
    def good() -> CertStatus:
        return CertStatus(CertStatus.Kind.Good)

    @staticmethod
    def revoked(time: int, reason: CRLReason | None = None) -> CertStatus:
        return CertStatus(CertStatus.Kind.Revoked, time, reason)

    @staticmethod
    def unknown() -> CertStatus:
        return CertStatus(CertStatus.Kind.Unknown)

    def arguments(self) -> tuple[int, int, int]:
        """The kind, revocation time and reason code of the C functions."""
        reason = CertStatus.NO_REASON if self.reason is None else int(self.reason)
        return int(self.kind), self.time or 0, reason


@dataclass
class OCSPConfig:
    """The inputs of the checks of a response (RFC 6960 §3.2): the time, the nonce of the request (if
    it had one), the largest keys of delegated responders, whether SHA-1 signatures are accepted, how
    long (in seconds) a status without ``nextUpdate`` is current, and the most signatures the search
    of the signer verifies."""

    time: int
    nonce: bytes | None = None
    key_limits: KeyLimits = field(default_factory=KeyLimits)
    accept_sha1: bool = False
    lifetime_without_next_update: int = 24 * 60 * 60
    maximum_signatures: int = 9

    def handle(self) -> Any:
        """A C configuration, for the caller to release with ``umilib_auth_cert_ocsp_ocsp_config_free``."""
        library = Library.default()
        handle = ctypes.c_void_p(Handle.create("umilib_auth_cert_ocsp_ocsp_config_new", self.time))
        try:
            library.call("umilib_auth_cert_ocsp_ocsp_config_set_nonce", handle, *Bytes.readable(self.nonce or b""))
            limits = self.key_limits
            library.call("umilib_auth_cert_ocsp_ocsp_config_set_key_limits", handle, limits.maximum_rsa_bits, limits.maximum_rsa_exponent_bits)
            library.call("umilib_auth_cert_ocsp_ocsp_config_set_accept_sha1", handle, self.accept_sha1)
            library.call("umilib_auth_cert_ocsp_ocsp_config_set_limits", handle, self.lifetime_without_next_update, self.maximum_signatures)
        except BaseException:
            library.function("umilib_auth_cert_ocsp_ocsp_config_free")(handle)
            raise
        return handle


class OCSPNonce:
    """The nonce extension (RFC 8954): 1 to 32 octets a response repeats."""

    OID: ClassVar[str] = "1.3.6.1.5.5.7.48.1.2"
    SIZE: ClassVar[range] = range(1, 33)

    @staticmethod
    def random(random: Any) -> bytes:
        """A nonce of 32 octets drawn from ``random``, a generator of :mod:`umilib.crypto.random`."""
        handle, name, length = random.source()
        return Library.default().output("umilib_auth_cert_ocsp_ocsp_nonce_random", handle, name, length)


class TBSRequest(Handle):
    """The fields of a request: the certificates asked about, the requestor's name and the nonce."""

    FREE = "umilib_auth_cert_ocsp_tbs_request_free"

    def __init__(self, cert_ids: list[CertID] | None = None, requestor_name: GeneralName | None = None, nonce: bytes | None = None) -> None:
        super().__init__(Handle.create("umilib_auth_cert_ocsp_tbs_request_new"))
        for cert_id in cert_ids or []:
            self.push(cert_id)
        if requestor_name is not None:
            self.set_requestor_name(requestor_name)
        if nonce is not None:
            self.set_nonce(nonce)

    def push(self, cert_id: CertID) -> None:
        self.library.call("umilib_auth_cert_ocsp_tbs_request_push", self.handle, cert_id)

    def set_requestor_name(self, name: GeneralName) -> None:
        self.library.call("umilib_auth_cert_ocsp_tbs_request_set_requestor_name", self.handle, int(name.kind), *Bytes.readable(name.data))

    def set_nonce(self, nonce: bytes) -> None:
        self.library.call("umilib_auth_cert_ocsp_tbs_request_set_nonce", self.handle, *Bytes.readable(nonce))


class OCSPRequest(Handle):
    """A request (RFC 6960 §4.1.1), signed or not."""

    FREE = "umilib_auth_cert_ocsp_ocsp_request_free"

    @staticmethod
    def new(tbs_request: TBSRequest) -> OCSPRequest:
        """The unsigned request of ``tbs_request``."""
        return OCSPRequest(Handle.create("umilib_auth_cert_ocsp_ocsp_request_new", tbs_request))

    @staticmethod
    def sign(tbs_request: TBSRequest, key: PrivateKey, algorithm: SignatureAlgorithm, certificates: list[Certificate] | None, random: Any) -> OCSPRequest:
        """The request of ``tbs_request`` signed by ``key`` with ``algorithm``, with ``certificates``."""
        handle, name, length = random.source()
        list_handle = Certificates.handle_of(certificates)
        try:
            return OCSPRequest(Handle.create("umilib_auth_cert_ocsp_ocsp_request_sign", tbs_request, key, algorithm, list_handle, handle, name, length))
        finally:
            Certificates.free(list_handle)

    @staticmethod
    def from_der(data: bytes | bytearray | memoryview) -> OCSPRequest:
        return OCSPRequest(Handle.create("umilib_auth_cert_ocsp_ocsp_request_from_der", *Bytes.readable(data)))

    def to_der(self) -> bytes:
        return self.library.output("umilib_auth_cert_ocsp_ocsp_request_to_der", self.handle)

    @property
    def cert_ids(self) -> list[CertID]:
        """The identifiers of the certificates asked about."""
        count = self.library.value("umilib_auth_cert_ocsp_ocsp_request_count", ctypes.c_size_t, self.handle)
        return [CertID(Handle.create("umilib_auth_cert_ocsp_ocsp_request_cert_id", self.handle, index)) for index in range(count)]

    @property
    def requestor_name(self) -> GeneralName | None:
        has, kind, data = ctypes.c_bool(), ctypes.c_uint8(), Buffer()
        self.library.call("umilib_auth_cert_ocsp_ocsp_request_requestor_name", self.handle, ctypes.byref(has), ctypes.byref(kind), ctypes.byref(data))
        name = self.library.take(data)
        return GeneralName(GeneralName.Kind(kind.value), name) if has.value else None

    @property
    def nonce(self) -> bytes | None:
        return self.library.optional("umilib_auth_cert_ocsp_ocsp_request_nonce", Buffer, self.handle)

    @property
    def is_signed(self) -> bool:
        return self.signature_certificates()[0]

    @property
    def certificates(self) -> list[Certificate] | None:
        """The certificates of the signature (``None`` without the field or the signature)."""
        return self.signature_certificates()[1]

    def signature_certificates(self) -> tuple[bool, list[Certificate] | None]:
        """Whether the request is signed, and the certificates of its signature."""
        signed, has, handle = ctypes.c_bool(), ctypes.c_bool(), ctypes.c_void_p()
        self.library.call("umilib_auth_cert_ocsp_ocsp_request_certificates", self.handle, ctypes.byref(signed), ctypes.byref(has), ctypes.byref(handle))
        certificates = Certificates.list_of(handle)
        return signed.value, certificates if has.value else None

    def verify(self, key: PublicKey) -> None:
        """Returns if the request is signed and its signature verifies under ``key``; raises otherwise."""
        self.library.call("umilib_auth_cert_ocsp_ocsp_request_verify", self.handle, key)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, OCSPRequest) and self.to_der() == other.to_der()

    def __hash__(self) -> int:
        return hash(self.to_der())


class SingleResponse(Handle):
    """The status of one certificate, current from ``this_update`` to ``next_update`` (RFC 6960 §4.2.1)."""

    FREE = "umilib_auth_cert_ocsp_single_response_free"

    def __init__(self, cert_id: CertID | int, status: CertStatus | None = None, this_update: int = 0, next_update: int | None = None, extensions: Extensions | None = None) -> None:
        """The status ``status`` of the certificate ``cert_id`` names (or the handle ``cert_id`` of a status)."""
        if isinstance(cert_id, int):
            super().__init__(cert_id)
            return
        library = Library.default()
        kind, time, reason = (status or CertStatus.unknown()).arguments()
        handle = (extensions or Extensions()).handle()
        try:
            pointer = Handle.create("umilib_auth_cert_ocsp_single_response_new", cert_id, kind, time, reason, this_update, next_update is not None, next_update or 0, handle)
        finally:
            library.function("umilib_auth_cert_x509_extensions_free")(handle)
        super().__init__(pointer)

    @property
    def cert_id(self) -> CertID:
        return CertID(Handle.create("umilib_auth_cert_ocsp_single_response_cert_id", self.handle))

    @property
    def status(self) -> CertStatus:
        kind, time, reason = ctypes.c_uint8(), ctypes.c_int64(), ctypes.c_uint8()
        self.library.call("umilib_auth_cert_ocsp_single_response_status", self.handle, ctypes.byref(kind), ctypes.byref(time), ctypes.byref(reason))
        if kind.value != CertStatus.Kind.Revoked:
            return CertStatus(CertStatus.Kind(kind.value))
        return CertStatus.revoked(time.value, None if reason.value == CertStatus.NO_REASON else CRLReason(reason.value))

    def updates(self) -> tuple[int, int | None]:
        this_update, has_next, next_update = ctypes.c_int64(), ctypes.c_bool(), ctypes.c_int64()
        self.library.call("umilib_auth_cert_ocsp_single_response_updates", self.handle, ctypes.byref(this_update), ctypes.byref(has_next), ctypes.byref(next_update))
        return this_update.value, next_update.value if has_next.value else None

    @property
    def this_update(self) -> int:
        return self.updates()[0]

    @property
    def next_update(self) -> int | None:
        return self.updates()[1]

    @property
    def extensions(self) -> Extensions:
        return Extensions.output("umilib_auth_cert_ocsp_single_response_extensions", self.handle)


@dataclass(frozen=True)
class ResponderID:
    """The responder of a response: its name (``by_key`` false, ``data`` the DER of the name) or the SHA-1 hash of its key."""

    by_key: bool
    data: bytes

    def name(self) -> Name | None:
        return None if self.by_key else Name.from_der(self.data)


class ResponseData(Handle):
    """The signed fields of a basic response: the responder, when it was produced, the statuses and the nonce."""

    FREE = "umilib_auth_cert_ocsp_response_data_free"

    @staticmethod
    def by_name(name: Name, produced_at: int) -> ResponseData:
        return ResponseData(Handle.create("umilib_auth_cert_ocsp_response_data_new_by_name", name, produced_at))

    @staticmethod
    def by_key(key: PublicKey, produced_at: int) -> ResponseData:
        """The fields of the responder named by the SHA-1 hash of ``key``."""
        return ResponseData(Handle.create("umilib_auth_cert_ocsp_response_data_new_by_key", key, produced_at))

    def push(self, single: SingleResponse) -> None:
        self.library.call("umilib_auth_cert_ocsp_response_data_push", self.handle, single)

    def set_nonce(self, nonce: bytes) -> None:
        self.library.call("umilib_auth_cert_ocsp_response_data_set_nonce", self.handle, *Bytes.readable(nonce))

    def sign(self, key: PrivateKey, algorithm: SignatureAlgorithm, certificates: list[Certificate] | None, random: Any) -> BasicOCSPResponse:
        """The basic response signed by ``key`` with ``algorithm``, with ``certificates`` (a delegated responder's)."""
        handle, name, length = random.source()
        list_handle = Certificates.handle_of(certificates)
        try:
            return BasicOCSPResponse(Handle.create("umilib_auth_cert_ocsp_response_data_sign", self.handle, key, algorithm, list_handle, handle, name, length))
        finally:
            Certificates.free(list_handle)


class BasicOCSPResponse(Handle):
    """A basic response (RFC 6960 §4.2.1): signed statuses and certificates that help verify them."""

    FREE = "umilib_auth_cert_ocsp_basic_ocsp_response_free"

    @staticmethod
    def from_der(data: bytes | bytearray | memoryview) -> BasicOCSPResponse:
        return BasicOCSPResponse(Handle.create("umilib_auth_cert_ocsp_basic_ocsp_response_from_der", *Bytes.readable(data)))

    def to_der(self) -> bytes:
        return self.library.output("umilib_auth_cert_ocsp_basic_ocsp_response_to_der", self.handle)

    @property
    def responder_id(self) -> ResponderID:
        by_key, data = ctypes.c_bool(), Buffer()
        self.library.call("umilib_auth_cert_ocsp_basic_ocsp_response_responder_id", self.handle, ctypes.byref(by_key), ctypes.byref(data))
        return ResponderID(by_key.value, self.library.take(data))

    @property
    def produced_at(self) -> int:
        return self.library.value("umilib_auth_cert_ocsp_basic_ocsp_response_produced_at", ctypes.c_int64, self.handle)

    @property
    def responses(self) -> list[SingleResponse]:
        """The statuses, unchecked."""
        count = self.library.value("umilib_auth_cert_ocsp_basic_ocsp_response_count", ctypes.c_size_t, self.handle)
        return [SingleResponse(Handle.create("umilib_auth_cert_ocsp_basic_ocsp_response_get", self.handle, index)) for index in range(count)]

    @property
    def extensions(self) -> Extensions:
        return Extensions.output("umilib_auth_cert_ocsp_basic_ocsp_response_extensions", self.handle)

    @property
    def nonce(self) -> bytes | None:
        return self.library.optional("umilib_auth_cert_ocsp_basic_ocsp_response_nonce", Buffer, self.handle)

    @property
    def certificates(self) -> list[Certificate]:
        return Certificates.list_of(ctypes.c_void_p(Handle.create("umilib_auth_cert_ocsp_basic_ocsp_response_certificates", self.handle)))

    @property
    def signature_algorithm(self) -> bytes:
        """The DER ``AlgorithmIdentifier`` of the signature algorithm."""
        return self.library.output("umilib_auth_cert_ocsp_basic_ocsp_response_signature_algorithm", self.handle)

    def signer(self, issuer_name: Name, issuer_key: PublicKey, config: OCSPConfig) -> PublicKey:
        """The key that signed the response, if it may answer for the CA of ``issuer_name`` and ``issuer_key`` (RFC 6960 §4.2.2.2)."""
        handle = config.handle()
        try:
            return PublicKey(Handle.create("umilib_auth_cert_ocsp_basic_ocsp_response_signer", self.handle, issuer_name, issuer_key, handle))
        finally:
            self.library.function("umilib_auth_cert_ocsp_ocsp_config_free")(handle)

    def verify(self, cert_id: CertID, issuer_name: Name, issuer_key: PublicKey, config: OCSPConfig) -> SingleResponse:
        """The status of the certificate ``cert_id`` names, after the checks of RFC 6960 §3.2; raises otherwise."""
        handle = config.handle()
        try:
            return SingleResponse(Handle.create("umilib_auth_cert_ocsp_basic_ocsp_response_verify", self.handle, cert_id, issuer_name, issuer_key, handle))
        finally:
            self.library.function("umilib_auth_cert_ocsp_ocsp_config_free")(handle)

    def add_to(self, sources: Any) -> None:
        """Appends a copy of the response to ``sources``, the C list of revocation sources of :mod:`umilib.auth.cert.path`."""
        self.library.call("umilib_auth_cert_ocsp_basic_ocsp_response_add_to", self.handle, sources)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, BasicOCSPResponse) and self.to_der() == other.to_der()

    def __hash__(self) -> int:
        return hash(self.to_der())


class OCSPResponse(Handle):
    """A response (RFC 6960 §4.2.1): a status, and a basic response when it is successful."""

    FREE = "umilib_auth_cert_ocsp_ocsp_response_free"

    def __init__(self, status: OCSPResponseStatus | int, basic: BasicOCSPResponse | None = None, *, handle: int | None = None) -> None:
        """The response of ``status`` with ``basic`` (only when successful)."""
        if handle is not None:
            super().__init__(handle)
            return
        super().__init__(Handle.create("umilib_auth_cert_ocsp_ocsp_response_new", int(status), basic))

    @staticmethod
    def from_der(data: bytes | bytearray | memoryview) -> OCSPResponse:
        return OCSPResponse(0, handle=Handle.create("umilib_auth_cert_ocsp_ocsp_response_from_der", *Bytes.readable(data)))

    def to_der(self) -> bytes:
        return self.library.output("umilib_auth_cert_ocsp_ocsp_response_to_der", self.handle)

    @property
    def status(self) -> OCSPResponseStatus:
        return OCSPResponseStatus(self.library.value("umilib_auth_cert_ocsp_ocsp_response_status", ctypes.c_uint8, self.handle))

    def basic(self) -> BasicOCSPResponse:
        """The basic response of a successful response; raises ``Status`` otherwise."""
        return BasicOCSPResponse(Handle.create("umilib_auth_cert_ocsp_ocsp_response_basic", self.handle))

    def add_to(self, sources: Any) -> None:
        """Appends a copy of the response to ``sources``, the C list of revocation sources of :mod:`umilib.auth.cert.path`."""
        self.library.call("umilib_auth_cert_ocsp_ocsp_response_add_to", self.handle, sources)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, OCSPResponse) and self.to_der() == other.to_der()

    def __hash__(self) -> int:
        return hash(self.to_der())


__all__ = [
    "BasicOCSPResponse",
    "CertID",
    "CertStatus",
    "OCSPConfig",
    "OCSPNonce",
    "OCSPRequest",
    "OCSPResponse",
    "OCSPResponseStatus",
    "OCSPStatusError",
    "ResponderID",
    "ResponseData",
    "SingleResponse",
    "TBSRequest",
]
