"""X.509 certificates and CRLs (RFC 5280). Mirrors ``umilib::auth::cert::x509``.

Names, certificates, CRLs and their signed fields are handles. Times are
seconds since 1970-01-01T00:00:00Z; serial numbers and CRL numbers are
integers; object identifiers are dotted text. A list of extensions is an
:class:`Extensions` of :class:`Extension` values (an object identifier, the
criticality and the DER of the value), and the classes named after an
extension type convert its value with ``to_der`` and ``from_der``.
Signing takes a generator of :mod:`umilib.crypto.random`. Errors are
:class:`X509StatusError`, or :class:`umilib.auth.cert.key.KeyStatusError`
for keys and signatures.
"""

from __future__ import annotations

import ctypes
import enum
from dataclasses import dataclass, field
from typing import Any, ClassVar, TypeVar

from umilib.auth.cert.key import PrivateKey, PublicKey, SignatureAlgorithm
from umilib.ffi import Buffer, Bytes, FFIError, Handle, Library, Text


class X509StatusError(FFIError):
    """An error of a certificate, a CRL, a name or an extension: ``Encoding``, ``PEM``, ``PEMLabel``,
    ``Version``, ``AlgorithmMismatch``, ``DuplicateExtension``, ``InvalidExtension``, ``InvalidName``,
    ``InvalidTime``, ``InvalidSerialNumber`` or ``InvalidAttribute``."""


Library.register_error("auth.cert.x509", X509StatusError)


class Integer:
    """The contents octets of INTEGERs (big-endian two's complement in the fewest octets) of Python integers."""

    @staticmethod
    def encode(value: int) -> bytes:
        magnitude = value if value >= 0 else ~value
        return value.to_bytes(magnitude.bit_length() // 8 + 1, "big", signed=True)

    @staticmethod
    def decode(content: bytes) -> int:
        return int.from_bytes(content, "big", signed=True)


class Version(enum.IntEnum):
    """The version of a certificate or a CRL; the value is the INTEGER of the ``Version`` syntax."""

    V1 = 0
    V2 = 1
    V3 = 2


class NameAttribute(enum.IntEnum):
    """The attribute types of names this module knows; the value is the number of the C ABI."""

    CommonName = 0
    Surname = 1
    SerialNumber = 2
    Country = 3
    Locality = 4
    StateOrProvince = 5
    Street = 6
    Organization = 7
    OrganizationalUnit = 8
    Title = 9
    BusinessCategory = 10
    PostalCode = 11
    Name = 12
    GivenName = 13
    Initials = 14
    GenerationQualifier = 15
    DNQualifier = 16
    Pseudonym = 17
    OrganizationIdentifier = 18
    DomainComponent = 19
    UserID = 20
    EmailAddress = 21


class Name(Handle):
    """A distinguished name; names are equal when their encodings are."""

    FREE = "umilib_auth_cert_x509_name_free"

    @staticmethod
    def empty() -> Name:
        return Name(Handle.create("umilib_auth_cert_x509_name_empty"))

    @staticmethod
    def from_der(data: bytes | bytearray | memoryview) -> Name:
        return Name(Handle.create("umilib_auth_cert_x509_name_from_der", *Bytes.readable(data)))

    @staticmethod
    def from_attributes(attributes: list[tuple[NameAttribute, str]]) -> Name:
        """The name with one relative name of one attribute for each of ``attributes``, the most significant first."""
        name = Name.empty()
        for attribute, text in attributes:
            name = name.append(attribute, text)
        return name

    def append(self, attribute: NameAttribute, text: str) -> Name:
        """The name followed by a relative name of the attribute ``attribute`` of ``text``."""
        return Name(Handle.create("umilib_auth_cert_x509_name_append", self.handle, attribute, *Text.encode(text)))

    def to_der(self) -> bytes:
        return self.library.output("umilib_auth_cert_x509_name_to_der", self.handle)

    def to_rfc4514(self) -> str:
        """The string representation of RFC 4514."""
        return self.library.output("umilib_auth_cert_x509_name_to_rfc4514", self.handle).decode("utf-8")

    def __str__(self) -> str:
        return self.to_rfc4514()

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Name) and self.to_der() == other.to_der()

    def __hash__(self) -> int:
        return hash(self.to_der())


@dataclass(frozen=True)
class GeneralName:
    """A general name: its kind and its bytes (the text of e-mail addresses, DNS names and URIs, the
    octets of an address, the dotted text of a registered identifier, the DER of a directory name, the
    contents of the element of the other kinds)."""

    class Kind(enum.IntEnum):
        OtherName = 0
        RFC822Name = 1
        DNSName = 2
        X400Address = 3
        DirectoryName = 4
        EDIPartyName = 5
        URI = 6
        IPAddress = 7
        RegisteredID = 8

    kind: GeneralName.Kind
    data: bytes

    @staticmethod
    def dns_name(name: str) -> GeneralName:
        return GeneralName(GeneralName.Kind.DNSName, name.encode("ascii"))

    @staticmethod
    def rfc822_name(address: str) -> GeneralName:
        return GeneralName(GeneralName.Kind.RFC822Name, address.encode("ascii"))

    @staticmethod
    def uri(uri: str) -> GeneralName:
        return GeneralName(GeneralName.Kind.URI, uri.encode("ascii"))

    @staticmethod
    def ip_address(address: bytes) -> GeneralName:
        return GeneralName(GeneralName.Kind.IPAddress, bytes(address))

    @staticmethod
    def directory_name(name: Name) -> GeneralName:
        return GeneralName(GeneralName.Kind.DirectoryName, name.to_der())

    @staticmethod
    def registered_id(oid: str) -> GeneralName:
        return GeneralName(GeneralName.Kind.RegisteredID, oid.encode("ascii"))

    @staticmethod
    def handle_of(names: list[GeneralName]) -> Any:
        """A C list of ``names``, for the caller to release with ``umilib_auth_cert_x509_general_names_free``."""
        library = Library.default()
        handle = ctypes.c_void_p(Handle.create("umilib_auth_cert_x509_general_names_new"))
        try:
            for name in names:
                library.call("umilib_auth_cert_x509_general_names_push", handle, name.kind, *Bytes.readable(name.data))
        except BaseException:
            library.function("umilib_auth_cert_x509_general_names_free")(handle)
            raise
        return handle

    @staticmethod
    def list_of(handle: Any) -> list[GeneralName]:
        """The names of a C list, which is released."""
        library = Library.default()
        try:
            count = library.value("umilib_auth_cert_x509_general_names_count", ctypes.c_size_t, handle)
            names = []
            for index in range(count):
                kind = ctypes.c_uint8()
                data = Buffer()
                library.call("umilib_auth_cert_x509_general_names_get", handle, index, ctypes.byref(kind), ctypes.byref(data))
                names.append(GeneralName(GeneralName.Kind(kind.value), library.take(data)))
            return names
        finally:
            library.function("umilib_auth_cert_x509_general_names_free")(handle)


@dataclass(frozen=True)
class Extension:
    """An extension: its type, whether it is critical, and the DER of its value."""

    oid: str
    critical: bool
    value: bytes

    @staticmethod
    def new(value: Any, critical: bool) -> Extension:
        """The extension holding ``value``, of one of the classes named after an extension type."""
        return Extension(value.OID, critical, value.to_der())

    def typed(self, kind: type[T]) -> T:
        """The value as ``kind``; raises ``InvalidExtension`` if the extension is of another type."""
        if self.oid != kind.OID:  # type: ignore[attr-defined]
            raise X509StatusError("auth.cert.x509", "InvalidExtension", "invalid extension")
        return kind.from_der(self.value)  # type: ignore[attr-defined, no-any-return]


T = TypeVar("T")


@dataclass
class Extensions:
    """A list of extensions, each of a different type; an empty list stands for the absent field."""

    entries: list[Extension] = field(default_factory=list)

    def get(self, oid: str) -> Extension | None:
        return next((extension for extension in self.entries if extension.oid == oid), None)

    def typed(self, kind: type[T]) -> T | None:
        """The extension of the type of ``kind``, decoded, if there is one."""
        extension = self.get(kind.OID)  # type: ignore[attr-defined]
        return None if extension is None else extension.typed(kind)

    def push(self, extension: Extension) -> None:
        """Appends ``extension``; raises ``DuplicateExtension`` if one of its type is already there."""
        if self.get(extension.oid) is not None:
            raise X509StatusError("auth.cert.x509", "DuplicateExtension", "two extensions of the same type")
        self.entries.append(extension)

    def is_empty(self) -> bool:
        return not self.entries

    def handle(self) -> Any:
        """A C list of the extensions, for the caller to release with ``umilib_auth_cert_x509_extensions_free``."""
        library = Library.default()
        handle = ctypes.c_void_p(Handle.create("umilib_auth_cert_x509_extensions_new"))
        try:
            for extension in self.entries:
                library.call("umilib_auth_cert_x509_extensions_push", handle, *Text.encode(extension.oid), extension.critical, *Bytes.readable(extension.value))
        except BaseException:
            library.function("umilib_auth_cert_x509_extensions_free")(handle)
            raise
        return handle

    @staticmethod
    def from_handle(handle: Any) -> Extensions:
        """The extensions of a C list, which is released."""
        library = Library.default()
        try:
            count = library.value("umilib_auth_cert_x509_extensions_count", ctypes.c_size_t, handle)
            entries = []
            for index in range(count):
                oid, value, critical = Buffer(), Buffer(), ctypes.c_bool()
                library.call("umilib_auth_cert_x509_extensions_get", handle, index, ctypes.byref(oid), ctypes.byref(critical), ctypes.byref(value))
                entries.append(Extension(library.take(oid).decode("ascii"), critical.value, library.take(value)))
            return Extensions(entries)
        finally:
            library.function("umilib_auth_cert_x509_extensions_free")(handle)

    @staticmethod
    def output(name: str, *arguments: Any) -> Extensions:
        """The extensions a C function writes into its trailing handle output."""
        return Extensions.from_handle(ctypes.c_void_p(Handle.create(name, *arguments)))


@dataclass(frozen=True)
class BasicConstraints:
    """The ``BasicConstraints`` extension (RFC 5280 §4.2.1.9)."""

    OID: ClassVar[str] = "2.5.29.19"
    ca: bool = False
    path_length: int | None = None

    def to_der(self) -> bytes:
        has_path_length = self.path_length is not None
        return Library.default().output("umilib_auth_cert_x509_basic_constraints_encode", self.ca, has_path_length, self.path_length or 0)

    @staticmethod
    def from_der(data: bytes) -> BasicConstraints:
        ca, has_path_length, path_length = ctypes.c_bool(), ctypes.c_bool(), ctypes.c_uint32()
        Library.default().call(
            "umilib_auth_cert_x509_basic_constraints_decode", *Bytes.readable(data), ctypes.byref(ca), ctypes.byref(has_path_length), ctypes.byref(path_length)
        )
        return BasicConstraints(ca.value, path_length.value if has_path_length.value else None)


class KeyUsage(enum.IntFlag):
    """The ``KeyUsage`` extension (RFC 5280 §4.2.1.3): named bit ``n`` is ``1 << n``."""

    DIGITAL_SIGNATURE = 1 << 0
    CONTENT_COMMITMENT = 1 << 1
    KEY_ENCIPHERMENT = 1 << 2
    DATA_ENCIPHERMENT = 1 << 3
    KEY_AGREEMENT = 1 << 4
    KEY_CERT_SIGN = 1 << 5
    CRL_SIGN = 1 << 6
    ENCIPHER_ONLY = 1 << 7
    DECIPHER_ONLY = 1 << 8

    def to_der(self) -> bytes:
        return Library.default().output("umilib_auth_cert_x509_key_usage_encode", int(self))

    @staticmethod
    def from_der(data: bytes) -> KeyUsage:
        return KeyUsage(Library.default().value("umilib_auth_cert_x509_key_usage_decode", ctypes.c_uint16, *Bytes.readable(data)))


KeyUsage.OID = "2.5.29.15"  # type: ignore[attr-defined]


@dataclass(frozen=True)
class ExtendedKeyUsage:
    """The ``ExtendedKeyUsage`` extension (RFC 5280 §4.2.1.12): at least one purpose."""

    OID: ClassVar[str] = "2.5.29.37"
    ANY: ClassVar[str] = "2.5.29.37.0"
    SERVER_AUTH: ClassVar[str] = "1.3.6.1.5.5.7.3.1"
    CLIENT_AUTH: ClassVar[str] = "1.3.6.1.5.5.7.3.2"
    CODE_SIGNING: ClassVar[str] = "1.3.6.1.5.5.7.3.3"
    EMAIL_PROTECTION: ClassVar[str] = "1.3.6.1.5.5.7.3.4"
    TIME_STAMPING: ClassVar[str] = "1.3.6.1.5.5.7.3.8"
    OCSP_SIGNING: ClassVar[str] = "1.3.6.1.5.5.7.3.9"
    purposes: tuple[str, ...]

    def to_der(self) -> bytes:
        return Library.default().output("umilib_auth_cert_x509_extended_key_usage_encode", *Text.encode(",".join(self.purposes)))

    @staticmethod
    def from_der(data: bytes) -> ExtendedKeyUsage:
        text = Library.default().output("umilib_auth_cert_x509_extended_key_usage_decode", *Bytes.readable(data)).decode("ascii")
        return ExtendedKeyUsage(tuple(text.split(",")))


@dataclass(frozen=True)
class SubjectAlternativeName:
    """The ``SubjectAltName`` extension (RFC 5280 §4.2.1.6): at least one name."""

    OID: ClassVar[str] = "2.5.29.17"
    names: tuple[GeneralName, ...]

    def to_der(self) -> bytes:
        handle = GeneralName.handle_of(list(self.names))
        try:
            return Library.default().output("umilib_auth_cert_x509_general_names_to_der", handle)
        finally:
            Library.default().function("umilib_auth_cert_x509_general_names_free")(handle)

    @classmethod
    def from_der(cls, data: bytes) -> Any:
        handle = ctypes.c_void_p(Handle.create("umilib_auth_cert_x509_general_names_from_der", *Bytes.readable(data)))
        return cls(tuple(GeneralName.list_of(handle)))


@dataclass(frozen=True)
class IssuerAlternativeName(SubjectAlternativeName):
    """The ``IssuerAltName`` extension (RFC 5280 §4.2.1.7)."""

    OID: ClassVar[str] = "2.5.29.18"


@dataclass(frozen=True)
class CertificateIssuer(SubjectAlternativeName):
    """The ``CertificateIssuer`` CRL entry extension (RFC 5280 §5.3.3)."""

    OID: ClassVar[str] = "2.5.29.29"


@dataclass(frozen=True)
class SubjectKeyIdentifier:
    """The ``SubjectKeyIdentifier`` extension (RFC 5280 §4.2.1.2)."""

    OID: ClassVar[str] = "2.5.29.14"
    key_identifier: bytes

    @staticmethod
    def from_public_key(key: PublicKey) -> SubjectKeyIdentifier:
        """The identifier by the first method of RFC 5280 §4.2.1.2: the SHA-1 of the ``subjectPublicKey``."""
        return SubjectKeyIdentifier(Library.default().output("umilib_auth_cert_x509_subject_key_identifier_from_public_key", key))

    def to_der(self) -> bytes:
        return Library.default().output("umilib_auth_cert_x509_subject_key_identifier_encode", *Bytes.readable(self.key_identifier))

    @staticmethod
    def from_der(data: bytes) -> SubjectKeyIdentifier:
        return SubjectKeyIdentifier(Library.default().output("umilib_auth_cert_x509_subject_key_identifier_decode", *Bytes.readable(data)))


@dataclass(frozen=True)
class AuthorityKeyIdentifier:
    """The ``AuthorityKeyIdentifier`` extension (RFC 5280 §4.2.1.1): the key identifier of the issuer, and
    the issuer's name and serial number, both given or both absent."""

    OID: ClassVar[str] = "2.5.29.35"
    key_identifier: bytes | None = None
    authority_cert_issuer: tuple[GeneralName, ...] | None = None
    authority_cert_serial_number: int | None = None

    def to_der(self) -> bytes:
        library = Library.default()
        identifier = self.key_identifier or b""
        serial = b"" if self.authority_cert_serial_number is None else Integer.encode(self.authority_cert_serial_number)
        issuer = None if self.authority_cert_issuer is None else GeneralName.handle_of(list(self.authority_cert_issuer))
        try:
            return library.output(
                "umilib_auth_cert_x509_authority_key_identifier_encode", self.key_identifier is not None, *Bytes.readable(identifier), issuer, *Bytes.readable(serial)
            )
        finally:
            if issuer is not None:
                library.function("umilib_auth_cert_x509_general_names_free")(issuer)

    @staticmethod
    def from_der(data: bytes) -> AuthorityKeyIdentifier:
        library = Library.default()
        has_identifier, identifier, has_issuer, issuer, serial = ctypes.c_bool(), Buffer(), ctypes.c_bool(), ctypes.c_void_p(), Buffer()
        library.call(
            "umilib_auth_cert_x509_authority_key_identifier_decode",
            *Bytes.readable(data),
            ctypes.byref(has_identifier),
            ctypes.byref(identifier),
            ctypes.byref(has_issuer),
            ctypes.byref(issuer),
            ctypes.byref(serial),
        )
        identifier_bytes, serial_bytes = library.take(identifier), library.take(serial)
        if not has_issuer.value:
            return AuthorityKeyIdentifier(identifier_bytes if has_identifier.value else None)
        names = tuple(GeneralName.list_of(issuer))
        return AuthorityKeyIdentifier(identifier_bytes if has_identifier.value else None, names, Integer.decode(serial_bytes))


@dataclass(frozen=True)
class CRLNumber:
    """The ``CRLNumber`` CRL extension (RFC 5280 §5.2.3)."""

    OID: ClassVar[str] = "2.5.29.20"
    number: int

    def to_der(self) -> bytes:
        return Library.default().output("umilib_auth_cert_x509_crl_number_encode", *Bytes.readable(Integer.encode(self.number)))

    @staticmethod
    def from_der(data: bytes) -> CRLNumber:
        return CRLNumber(Integer.decode(Library.default().output("umilib_auth_cert_x509_crl_number_decode", *Bytes.readable(data))))


class CRLReason(enum.IntEnum):
    """The ``CRLReason`` CRL entry extension (RFC 5280 §5.3.1)."""

    Unspecified = 0
    KeyCompromise = 1
    CACompromise = 2
    AffiliationChanged = 3
    Superseded = 4
    CessationOfOperation = 5
    CertificateHold = 6
    RemoveFromCRL = 8
    PrivilegeWithdrawn = 9
    AACompromise = 10

    def to_der(self) -> bytes:
        return Library.default().output("umilib_auth_cert_x509_crl_reason_encode", int(self))

    @staticmethod
    def from_der(data: bytes) -> CRLReason:
        return CRLReason(Library.default().value("umilib_auth_cert_x509_crl_reason_decode", ctypes.c_uint8, *Bytes.readable(data)))


CRLReason.OID = "2.5.29.21"  # type: ignore[attr-defined]


class SerialNumber:
    """Serial numbers (RFC 5280 §4.1.2.2)."""

    @staticmethod
    def random(random: Any) -> int:
        """A positive serial number of 159 random bits from the generator ``random``."""
        handle, name, length = random.source()
        return Integer.decode(Library.default().output("umilib_auth_cert_x509_serial_number_random", handle, name, length))


class Certificate(Handle):
    """A certificate (RFC 5280 §4.1)."""

    FREE = "umilib_auth_cert_x509_certificate_free"

    @staticmethod
    def from_der(data: bytes | bytearray | memoryview) -> Certificate:
        return Certificate(Handle.create("umilib_auth_cert_x509_certificate_from_der", *Bytes.readable(data)))

    @staticmethod
    def from_pem(text: str) -> Certificate:
        """The certificate of the first PEM document (``CERTIFICATE``) of ``text``."""
        return Certificate(Handle.create("umilib_auth_cert_x509_certificate_from_pem", *Text.encode(text)))

    @staticmethod
    def from_pem_all(text: str) -> list[Certificate]:
        """The certificates of every PEM document of ``text``, each ``CERTIFICATE``."""
        return Certificates.list_of(ctypes.c_void_p(Handle.create("umilib_auth_cert_x509_certificates_from_pem", *Text.encode(text))))

    def to_der(self) -> bytes:
        return self.library.output("umilib_auth_cert_x509_certificate_to_der", self.handle)

    def to_pem(self) -> str:
        return self.library.output("umilib_auth_cert_x509_certificate_to_pem", self.handle).decode("ascii")

    @property
    def tbs_encoding(self) -> bytes:
        """The signed bytes: the DER of the ``TBSCertificate`` as read."""
        return self.library.output("umilib_auth_cert_x509_certificate_tbs_der", self.handle)

    @property
    def version(self) -> Version:
        return Version(self.library.value("umilib_auth_cert_x509_certificate_version", ctypes.c_uint8, self.handle))

    @property
    def serial_number(self) -> int:
        return Integer.decode(self.library.output("umilib_auth_cert_x509_certificate_serial_number", self.handle))

    @property
    def signature_algorithm(self) -> bytes:
        """The DER ``AlgorithmIdentifier`` of the signature algorithm (see :meth:`SignatureAlgorithm.from_der`)."""
        return self.library.output("umilib_auth_cert_x509_certificate_signature_algorithm", self.handle)

    @property
    def signature(self) -> bytes:
        return self.library.output("umilib_auth_cert_x509_certificate_signature", self.handle)

    @property
    def issuer(self) -> Name:
        return Name(Handle.create("umilib_auth_cert_x509_certificate_issuer", self.handle))

    @property
    def subject(self) -> Name:
        return Name(Handle.create("umilib_auth_cert_x509_certificate_subject", self.handle))

    @property
    def validity(self) -> tuple[int, int]:
        """The start and the end of the validity, both included, in seconds since the epoch."""
        not_before, not_after = ctypes.c_int64(), ctypes.c_int64()
        self.library.call("umilib_auth_cert_x509_certificate_validity", self.handle, ctypes.byref(not_before), ctypes.byref(not_after))
        return not_before.value, not_after.value

    @property
    def extensions(self) -> Extensions:
        return Extensions.output("umilib_auth_cert_x509_certificate_extensions", self.handle)

    def public_key(self) -> PublicKey:
        """The subject's public key."""
        return PublicKey(Handle.create("umilib_auth_cert_x509_certificate_public_key", self.handle))

    def verify(self, issuer: PublicKey) -> None:
        """Returns if the signature verifies under ``issuer``, the issuer's public key; raises otherwise."""
        self.library.call("umilib_auth_cert_x509_certificate_verify", self.handle, issuer)

    def is_self_issued(self) -> bool:
        return self.library.value("umilib_auth_cert_x509_certificate_is_self_issued", ctypes.c_bool, self.handle)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Certificate) and self.to_der() == other.to_der()

    def __hash__(self) -> int:
        return hash(self.to_der())


class TBSCertificate(Handle):
    """The signed fields of a certificate (RFC 5280 §4.1), without unique identifiers."""

    FREE = "umilib_auth_cert_x509_tbs_certificate_free"

    def __init__(
        self,
        version: Version,
        serial_number: int,
        signature: SignatureAlgorithm,
        issuer: Name,
        not_before: int,
        not_after: int,
        subject: Name,
        public_key: PublicKey,
        extensions: Extensions | None = None,
    ) -> None:
        library = Library.default()
        handle = (extensions or Extensions()).handle()
        try:
            serial = Integer.encode(serial_number)
            super().__init__(
                Handle.create(
                    "umilib_auth_cert_x509_tbs_certificate_new", version, *Bytes.readable(serial), signature, issuer, not_before, not_after, subject, public_key, handle
                )
            )
        finally:
            library.function("umilib_auth_cert_x509_extensions_free")(handle)

    def check(self) -> None:
        """Returns if the fields meet the requirements RFC 5280 places on what CAs issue; raises otherwise."""
        self.library.call("umilib_auth_cert_x509_tbs_certificate_check", self.handle)

    def to_der(self) -> bytes:
        return self.library.output("umilib_auth_cert_x509_tbs_certificate_to_der", self.handle)

    def sign(self, key: PrivateKey, random: Any) -> Certificate:
        """The certificate of the fields signed by ``key`` with the signature algorithm of the fields."""
        handle, name, length = random.source()
        return Certificate(Handle.create("umilib_auth_cert_x509_tbs_certificate_sign", self.handle, key, handle, name, length))


@dataclass(frozen=True)
class Attribute:
    """An attribute (RFC 5280 appendix A.1, RFC 2986 §4.1): its type and its values, each the DER of one element."""

    oid: str
    values: tuple[bytes, ...]


@dataclass(frozen=True)
class RevokedCertificate:
    """An entry of a CRL (RFC 5280 §5.1.2.6)."""

    serial_number: int
    revocation_date: int
    extensions: Extensions = field(default_factory=Extensions)


class TBSCertList(Handle):
    """The signed fields of a CRL (RFC 5280 §5.1)."""

    FREE = "umilib_auth_cert_x509_tbs_cert_list_free"

    def __init__(
        self,
        version: Version,
        signature: SignatureAlgorithm,
        issuer: Name,
        this_update: int,
        next_update: int | None,
        revoked_certificates: list[RevokedCertificate] | None = None,
        extensions: Extensions | None = None,
    ) -> None:
        library = Library.default()
        handle = (extensions or Extensions()).handle()
        try:
            super().__init__(
                Handle.create(
                    "umilib_auth_cert_x509_tbs_cert_list_new", version, signature, issuer, this_update, next_update is not None, next_update or 0, handle
                )
            )
        finally:
            library.function("umilib_auth_cert_x509_extensions_free")(handle)
        for entry in revoked_certificates or []:
            self.push(entry)

    def push(self, entry: RevokedCertificate) -> None:
        """Appends an entry."""
        handle = entry.extensions.handle()
        try:
            serial = Integer.encode(entry.serial_number)
            self.library.call("umilib_auth_cert_x509_tbs_cert_list_push", self.handle, *Bytes.readable(serial), entry.revocation_date, handle)
        finally:
            self.library.function("umilib_auth_cert_x509_extensions_free")(handle)

    def sign(self, key: PrivateKey, random: Any) -> CertificateList:
        """The CRL of the fields signed by ``key`` with the signature algorithm of the fields."""
        handle, name, length = random.source()
        return CertificateList(Handle.create("umilib_auth_cert_x509_tbs_cert_list_sign", self.handle, key, handle, name, length))


class CertificateList(Handle):
    """A CRL (RFC 5280 §5.1)."""

    FREE = "umilib_auth_cert_x509_certificate_list_free"

    @staticmethod
    def from_der(data: bytes | bytearray | memoryview) -> CertificateList:
        return CertificateList(Handle.create("umilib_auth_cert_x509_certificate_list_from_der", *Bytes.readable(data)))

    @staticmethod
    def from_pem(text: str) -> CertificateList:
        """The CRL of the first PEM document (``X509 CRL``) of ``text``."""
        return CertificateList(Handle.create("umilib_auth_cert_x509_certificate_list_from_pem", *Text.encode(text)))

    def to_der(self) -> bytes:
        return self.library.output("umilib_auth_cert_x509_certificate_list_to_der", self.handle)

    def to_pem(self) -> str:
        return self.library.output("umilib_auth_cert_x509_certificate_list_to_pem", self.handle).decode("ascii")

    @property
    def version(self) -> Version:
        return Version(self.library.value("umilib_auth_cert_x509_certificate_list_version", ctypes.c_uint8, self.handle))

    @property
    def issuer(self) -> Name:
        return Name(Handle.create("umilib_auth_cert_x509_certificate_list_issuer", self.handle))

    @property
    def this_update(self) -> int:
        return self.library.value("umilib_auth_cert_x509_certificate_list_this_update", ctypes.c_int64, self.handle)

    @property
    def next_update(self) -> int | None:
        return self.library.optional("umilib_auth_cert_x509_certificate_list_next_update", ctypes.c_int64, self.handle)

    @property
    def extensions(self) -> Extensions:
        return Extensions.output("umilib_auth_cert_x509_certificate_list_extensions", self.handle)

    @property
    def revoked_certificates(self) -> list[RevokedCertificate]:
        count = self.library.value("umilib_auth_cert_x509_certificate_list_count", ctypes.c_size_t, self.handle)
        return [self.entry(index) for index in range(count)]

    def entry(self, index: int) -> RevokedCertificate:
        serial, date, extensions = Buffer(), ctypes.c_int64(), ctypes.c_void_p()
        self.library.call("umilib_auth_cert_x509_certificate_list_get", self.handle, index, ctypes.byref(serial), ctypes.byref(date), ctypes.byref(extensions))
        return RevokedCertificate(Integer.decode(self.library.take(serial)), date.value, Extensions.from_handle(extensions))

    def find(self, serial_number: int) -> RevokedCertificate | None:
        """The entry of ``serial_number``, if the CRL lists it (the issuers of an indirect CRL are not considered)."""
        index = self.library.optional("umilib_auth_cert_x509_certificate_list_find", ctypes.c_size_t, self.handle, *Bytes.readable(Integer.encode(serial_number)))
        return None if index is None else self.entry(index)

    def verify(self, issuer: PublicKey) -> None:
        """Returns if the signature verifies under ``issuer``, the CRL issuer's public key; raises otherwise."""
        self.library.call("umilib_auth_cert_x509_certificate_list_verify", self.handle, issuer)


class Certificates:
    """C lists of certificates (``umilib_auth_cert_x509_Certificates``)."""

    @staticmethod
    def handle_of(certificates: list[Certificate] | None) -> Any:
        """A C list of ``certificates`` (null for ``None``), for the caller to release with :meth:`free`."""
        if certificates is None:
            return None
        library = Library.default()
        handle = ctypes.c_void_p(Handle.create("umilib_auth_cert_x509_certificates_new"))
        try:
            for certificate in certificates:
                library.call("umilib_auth_cert_x509_certificates_push", handle, certificate)
        except BaseException:
            Certificates.free(handle)
            raise
        return handle

    @staticmethod
    def list_of(handle: Any) -> list[Certificate]:
        """The certificates of a C list, which is released."""
        library = Library.default()
        try:
            count = library.value("umilib_auth_cert_x509_certificates_count", ctypes.c_size_t, handle)
            return [Certificate(Handle.create("umilib_auth_cert_x509_certificates_get", handle, index)) for index in range(count)]
        finally:
            Certificates.free(handle)

    @staticmethod
    def free(handle: Any) -> None:
        if handle is not None:
            Library.default().function("umilib_auth_cert_x509_certificates_free")(handle)


class CertificateLists:
    """C lists of CRLs (``umilib_auth_cert_x509_CertificateLists``)."""

    @staticmethod
    def handle_of(lists: list[CertificateList]) -> Any:
        """A C list of ``lists``, for the caller to release with :meth:`free`."""
        library = Library.default()
        handle = ctypes.c_void_p(Handle.create("umilib_auth_cert_x509_certificate_lists_new"))
        try:
            for crl in lists:
                library.call("umilib_auth_cert_x509_certificate_lists_push", handle, crl)
        except BaseException:
            CertificateLists.free(handle)
            raise
        return handle

    @staticmethod
    def list_of(handle: Any) -> list[CertificateList]:
        """The CRLs of a C list, which is released."""
        library = Library.default()
        try:
            count = library.value("umilib_auth_cert_x509_certificate_lists_count", ctypes.c_size_t, handle)
            return [CertificateList(Handle.create("umilib_auth_cert_x509_certificate_lists_get", handle, index)) for index in range(count)]
        finally:
            CertificateLists.free(handle)

    @staticmethod
    def free(handle: Any) -> None:
        if handle is not None:
            Library.default().function("umilib_auth_cert_x509_certificate_lists_free")(handle)


__all__ = [
    "Attribute",
    "AuthorityKeyIdentifier",
    "BasicConstraints",
    "CRLNumber",
    "CRLReason",
    "Certificate",
    "CertificateIssuer",
    "CertificateList",
    "CertificateLists",
    "Certificates",
    "ExtendedKeyUsage",
    "Extension",
    "Extensions",
    "GeneralName",
    "Integer",
    "IssuerAlternativeName",
    "KeyUsage",
    "Name",
    "NameAttribute",
    "RevokedCertificate",
    "SerialNumber",
    "SubjectAlternativeName",
    "SubjectKeyIdentifier",
    "TBSCertList",
    "TBSCertificate",
    "Version",
    "X509StatusError",
]
