"""Certification path building and validation (RFC 5280 §6, RFC 4158). Mirrors ``umilib::auth::cert::path``.

A :class:`PathValidator` builds a path from a target through intermediate
certificates to a :class:`TrustAnchor` and validates it under a
:class:`PathConfig`, against CRLs and other revocation sources (such as the
responses of :mod:`umilib.auth.cert.ocsp`). Times are seconds since
1970-01-01T00:00:00Z and object identifiers dotted text. A refused path
raises :class:`PathError`, which names the reason, the certificate it
concerns and, for a revoked one, the reason of the revocation.
"""

from __future__ import annotations

import ctypes
import enum
from dataclasses import dataclass, field
from typing import Any, ClassVar

from umilib.auth.cert.key import KeyLimits, PublicKey
from umilib.auth.cert.x509 import Certificate, CertificateList, CertificateLists, Certificates, CRLReason, KeyUsage, Name
from umilib.ffi import Bytes, FFIError, Handle, Library, Status, Text


class PathStatusError(FFIError):
    """An error of path validation; :class:`PathError` when a path is refused."""


Library.register_error("auth.cert.path", PathStatusError)


class PathError(PathStatusError):
    """A refused path: ``name`` is the reason (such as ``Signature`` or ``Revoked``, or an error of x509
    or key), ``index`` the certificate it concerns (0 for the target, the length of the path for the
    trust anchor) and ``revocation_reason`` the reason of a revocation."""

    def __init__(self, domain: str, name: str, message: str, index: int = 0, revocation_reason: CRLReason | None = None) -> None:
        super().__init__(domain, name, message)
        self.index = index
        self.revocation_reason = revocation_reason


class PathProfile(enum.IntEnum):
    """Which requirements a path must meet beyond the algorithm of RFC 5280 §6."""

    Algorithm = 0
    RFC5280 = 1
    WebPKI = 2


@dataclass(frozen=True)
class RevocationConfig:
    """Whether revocation is checked, whether an unknown status fails, whether delta CRLs are applied,
    and how long (in seconds) a CRL or a status without ``nextUpdate`` is current after its ``thisUpdate``."""

    check: bool = False
    require: bool = False
    use_deltas: bool = False
    lifetime_without_next_update: int = 24 * 60 * 60

    NONE: ClassVar[RevocationConfig]
    REQUIRED: ClassVar[RevocationConfig]


RevocationConfig.NONE = RevocationConfig(False, False, False)
RevocationConfig.REQUIRED = RevocationConfig(True, True, True)


@dataclass(frozen=True)
class ServiceIdentity:
    """The identity a target must name (RFC 9525): a DNS name in A-labels, an address of 4 or 16 octets, or a mailbox."""

    class Kind(enum.IntEnum):
        DNS = 1
        IPAddress = 2
        Email = 3

    kind: ServiceIdentity.Kind
    data: bytes

    @staticmethod
    def dns(name: str) -> ServiceIdentity:
        return ServiceIdentity(ServiceIdentity.Kind.DNS, name.encode("utf-8"))

    @staticmethod
    def ip_address(address: bytes) -> ServiceIdentity:
        return ServiceIdentity(ServiceIdentity.Kind.IPAddress, bytes(address))

    @staticmethod
    def email(address: str) -> ServiceIdentity:
        return ServiceIdentity(ServiceIdentity.Kind.Email, address.encode("utf-8"))


@dataclass
class PathConfig:
    """The inputs of path validation (RFC 5280 §6.1.1) and the limits of path building. The defaults
    are those of ``PathConfig::new``: the profile of RFC 5280, any policy, no name constraints, at most
    8 intermediates, 100 signatures, 4 nested CRL issuer paths and 2^20 name comparisons, SHA-1 refused, no revocation checking,
    and no usage, purpose or identity asked for."""

    time: int
    profile: PathProfile = PathProfile.RFC5280
    initial_policy_set: list[str] | None = None
    initial_explicit_policy: bool = False
    initial_policy_mapping_inhibit: bool = False
    initial_any_policy_inhibit: bool = False
    initial_name_constraints: bytes | None = None
    """The DER ``NameConstraints`` value of the initial permitted and excluded subtrees."""
    maximum_intermediates: int = 8
    maximum_signatures: int = 100
    maximum_nested_signers: int = 4
    maximum_name_checks: int = 1 << 20
    key_limits: KeyLimits = field(default_factory=KeyLimits)
    accept_sha1: bool = False
    revocation: RevocationConfig = RevocationConfig.NONE
    key_usage: KeyUsage | None = None
    extended_key_usage: str | None = None
    identity: ServiceIdentity | None = None

    SERVER_AUTH: ClassVar[str] = "1.3.6.1.5.5.7.3.1"

    @staticmethod
    def web_pki_server(time: int, identity: ServiceIdentity) -> PathConfig:
        """The validation of a TLS server named ``identity``: the Web PKI profile and the purpose ``id-kp-serverAuth``."""
        return PathConfig(time, profile=PathProfile.WebPKI, extended_key_usage=PathConfig.SERVER_AUTH, identity=identity)

    def handle(self) -> Any:
        """A C configuration, for the caller to release with ``umilib_auth_cert_path_path_config_free``."""
        library = Library.default()
        handle = ctypes.c_void_p(Handle.create("umilib_auth_cert_path_path_config_new", self.time))
        try:
            call = library.call
            call("umilib_auth_cert_path_path_config_set_profile", handle, int(self.profile))
            policies = ",".join(self.initial_policy_set or [])
            call("umilib_auth_cert_path_path_config_set_initial_policy_set", handle, self.initial_policy_set is None, *Text.encode(policies))
            call(
                "umilib_auth_cert_path_path_config_set_initial_policy_flags",
                handle,
                self.initial_explicit_policy,
                self.initial_policy_mapping_inhibit,
                self.initial_any_policy_inhibit,
            )
            call("umilib_auth_cert_path_path_config_set_initial_name_constraints", handle, *Bytes.readable(self.initial_name_constraints or b""))
            call("umilib_auth_cert_path_path_config_set_limits", handle, self.maximum_intermediates, self.maximum_signatures, self.maximum_nested_signers, self.maximum_name_checks)
            call("umilib_auth_cert_path_path_config_set_key_limits", handle, self.key_limits.maximum_rsa_bits, self.key_limits.maximum_rsa_exponent_bits)
            call("umilib_auth_cert_path_path_config_set_accept_sha1", handle, self.accept_sha1)
            revocation = self.revocation
            call(
                "umilib_auth_cert_path_path_config_set_revocation",
                handle,
                revocation.check,
                revocation.require,
                revocation.use_deltas,
                revocation.lifetime_without_next_update,
            )
            call("umilib_auth_cert_path_path_config_set_key_usage", handle, self.key_usage is not None, int(self.key_usage or 0))
            call("umilib_auth_cert_path_path_config_set_extended_key_usage", handle, *Text.encode(self.extended_key_usage or ""))
            identity = self.identity
            kind, data = (0, b"") if identity is None else (int(identity.kind), identity.data)
            call("umilib_auth_cert_path_path_config_set_identity", handle, kind, *Bytes.readable(data))
        except BaseException:
            library.function("umilib_auth_cert_path_path_config_free")(handle)
            raise
        return handle


class TrustAnchor(Handle):
    """A trust anchor (RFC 5280 §6.1.1 (d)): a trusted name and key, with name constraints, and the certificate it came from."""

    FREE = "umilib_auth_cert_path_trust_anchor_free"

    @staticmethod
    def new(name: Name, public_key: PublicKey, name_constraints: bytes | None = None) -> TrustAnchor:
        """The anchor of ``name`` and ``public_key``, with the DER ``NameConstraints`` value ``name_constraints``."""
        return TrustAnchor(Handle.create("umilib_auth_cert_path_trust_anchor_new", name, public_key, *Bytes.readable(name_constraints or b"")))

    @staticmethod
    def from_certificate(certificate: Certificate, limits: KeyLimits | None = None) -> TrustAnchor:
        """The anchor of ``certificate``: its subject, its key (within ``limits``) and its name constraints."""
        limits = limits or KeyLimits()
        return TrustAnchor(Handle.create("umilib_auth_cert_path_trust_anchor_from_certificate", certificate, limits.maximum_rsa_bits, limits.maximum_rsa_exponent_bits))

    @property
    def name(self) -> Name:
        return Name(Handle.create("umilib_auth_cert_path_trust_anchor_name", self.handle))

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(Handle.create("umilib_auth_cert_path_trust_anchor_public_key", self.handle))


@dataclass
class ValidatedPath:
    """A path that validated: its certificates from the target, its anchor, and the user-constrained
    policy set (RFC 9618 §5.5), which has anyPolicy (``2.5.29.32.0``) when every policy is valid."""

    certificates: list[Certificate]
    anchor: TrustAnchor
    policies: list[str]


@dataclass
class PathValidator:
    """Builds and validates paths from targets through ``intermediates`` to one of ``anchors``, under
    ``config``, with the CRLs ``crls`` and the revocation sources ``sources`` (such as OCSP responses)."""

    config: PathConfig
    anchors: list[TrustAnchor]
    intermediates: list[Certificate] = field(default_factory=list)
    crls: list[CertificateList] = field(default_factory=list)
    sources: list[Any] = field(default_factory=list)

    def with_sources(self, sources: list[Any]) -> PathValidator:
        """The validator with the revocation sources ``sources``, consulted in order after the CRLs."""
        return PathValidator(self.config, self.anchors, self.intermediates, self.crls, list(sources))

    def validate(self, target: Certificate) -> ValidatedPath:
        """The path from ``target`` that validated; raises :class:`PathError` with the error of the longest path tried."""
        library = Library.default()
        handles: list[tuple[str, Any]] = []
        try:
            config = self.config.handle()
            handles.append(("umilib_auth_cert_path_path_config_free", config))
            anchors = ctypes.c_void_p(Handle.create("umilib_auth_cert_path_trust_anchors_new"))
            handles.append(("umilib_auth_cert_path_trust_anchors_free", anchors))
            for anchor in self.anchors:
                library.call("umilib_auth_cert_path_trust_anchors_push", anchors, anchor)
            intermediates = Certificates.handle_of(self.intermediates)
            handles.append(("umilib_auth_cert_x509_certificates_free", intermediates))
            crls = CertificateLists.handle_of(self.crls)
            handles.append(("umilib_auth_cert_x509_certificate_lists_free", crls))
            sources = ctypes.c_void_p(Handle.create("umilib_auth_cert_path_revocation_sources_new"))
            handles.append(("umilib_auth_cert_path_revocation_sources_free", sources))
            for source in self.sources:
                source.add_to(sources)
            outcome = ctypes.c_void_p(Handle.create("umilib_auth_cert_path_path_validator_validate", config, anchors, intermediates, crls, sources, target))
            handles.append(("umilib_auth_cert_path_path_outcome_free", outcome))
            return self.outcome(outcome)
        finally:
            for free, handle in reversed(handles):
                library.function(free)(handle)

    def outcome(self, outcome: Any) -> ValidatedPath:
        """The path of the C outcome ``outcome``, or its error raised."""
        library = Library.default()
        valid, reason, index, revocation = ctypes.c_bool(), ctypes.c_void_p(), ctypes.c_size_t(), ctypes.c_uint8()
        library.call("umilib_auth_cert_path_path_outcome_error", outcome, ctypes.byref(valid), ctypes.byref(reason), ctypes.byref(index), ctypes.byref(revocation))
        if not valid.value:
            status = Status.from_address(reason.value)
            revocation_reason = None if revocation.value == 255 else CRLReason(revocation.value)
            raise PathError(status.domain.decode("utf-8"), status.name.decode("utf-8"), status.message.decode("utf-8"), index.value, revocation_reason)
        certificates = Certificates.list_of(ctypes.c_void_p(Handle.create("umilib_auth_cert_path_path_outcome_certificates", outcome)))
        anchor = library.value("umilib_auth_cert_path_path_outcome_anchor", ctypes.c_size_t, outcome)
        policies = library.output("umilib_auth_cert_path_path_outcome_policies", outcome).decode("ascii")
        return ValidatedPath(certificates, self.anchors[anchor], policies.split(",") if policies else [])


__all__ = [
    "PathConfig",
    "PathError",
    "PathProfile",
    "PathStatusError",
    "PathValidator",
    "RevocationConfig",
    "ServiceIdentity",
    "TrustAnchor",
    "ValidatedPath",
]
