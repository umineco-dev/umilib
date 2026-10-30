"""Certification requests (PKCS #10, RFC 2986). Mirrors ``umilib::auth::cert::csr``.

Names, keys and extensions are those of :mod:`umilib.auth.cert.x509` and
:mod:`umilib.auth.cert.key`. Attribute types are dotted text and attribute
values the DER of one element.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.auth.cert.key import PrivateKey, PublicKey, SignatureAlgorithm
from umilib.auth.cert.x509 import Attribute, Extensions, Name
from umilib.ffi import Buffer, Bytes, Handle, Library, Text


class CertificationRequestInfo(Handle):
    """The signed information of a request: the subject, its public key and attributes."""

    FREE = "umilib_auth_cert_csr_certification_request_info_free"
    EXTENSION_REQUEST: ClassVar[str] = "1.2.840.113549.1.9.14"
    CHALLENGE_PASSWORD: ClassVar[str] = "1.2.840.113549.1.9.7"

    def __init__(self, subject: Name, public_key: PublicKey, extensions: Extensions | None = None) -> None:
        """The information with an ``extensionRequest`` attribute of ``extensions`` if they are not empty."""
        library = Library.default()
        handle = (extensions or Extensions()).handle()
        try:
            super().__init__(Handle.create("umilib_auth_cert_csr_certification_request_info_new", subject, public_key, handle))
        finally:
            library.function("umilib_auth_cert_x509_extensions_free")(handle)

    def push(self, oid: str, value: bytes) -> None:
        """Appends an attribute of the type ``oid`` with one value, the DER element ``value``."""
        self.library.call("umilib_auth_cert_csr_certification_request_info_push", self.handle, *Text.encode(oid), *Bytes.readable(value))

    def to_der(self) -> bytes:
        return self.library.output("umilib_auth_cert_csr_certification_request_info_to_der", self.handle)

    def sign(self, key: PrivateKey, algorithm: SignatureAlgorithm, random: Any) -> CertificationRequest:
        """The request signed by ``key``, the subject's private key; raises ``Mismatch`` for another key."""
        handle, name, length = random.source()
        return CertificationRequest(Handle.create("umilib_auth_cert_csr_certification_request_info_sign", self.handle, key, algorithm, handle, name, length))


class CertificationRequest(Handle):
    """A certification request (RFC 2986 §4.2)."""

    FREE = "umilib_auth_cert_csr_certification_request_free"

    @staticmethod
    def from_der(data: bytes | bytearray | memoryview) -> CertificationRequest:
        return CertificationRequest(Handle.create("umilib_auth_cert_csr_certification_request_from_der", *Bytes.readable(data)))

    @staticmethod
    def from_pem(text: str) -> CertificationRequest:
        """The request of the first PEM document (``CERTIFICATE REQUEST`` or ``NEW CERTIFICATE REQUEST``)."""
        return CertificationRequest(Handle.create("umilib_auth_cert_csr_certification_request_from_pem", *Text.encode(text)))

    def to_der(self) -> bytes:
        return self.library.output("umilib_auth_cert_csr_certification_request_to_der", self.handle)

    def to_pem(self) -> str:
        return self.library.output("umilib_auth_cert_csr_certification_request_to_pem", self.handle).decode("ascii")

    @property
    def subject(self) -> Name:
        return Name(Handle.create("umilib_auth_cert_csr_certification_request_subject", self.handle))

    @property
    def extensions(self) -> Extensions:
        """The requested extensions (empty without an ``extensionRequest``)."""
        return Extensions.output("umilib_auth_cert_csr_certification_request_extensions", self.handle)

    @property
    def attributes(self) -> list[Attribute]:
        count = self.library.value("umilib_auth_cert_csr_certification_request_attribute_count", ctypes.c_size_t, self.handle)
        attributes = []
        for index in range(count):
            oid, values = Buffer(), ctypes.c_size_t()
            self.library.call("umilib_auth_cert_csr_certification_request_attribute", self.handle, index, ctypes.byref(oid), ctypes.byref(values))
            data = tuple(
                self.library.output("umilib_auth_cert_csr_certification_request_attribute_value", self.handle, index, value) for value in range(values.value)
            )
            attributes.append(Attribute(self.library.take(oid).decode("ascii"), data))
        return attributes

    @property
    def signature_algorithm(self) -> bytes:
        """The DER ``AlgorithmIdentifier`` of the signature algorithm."""
        return self.library.output("umilib_auth_cert_csr_certification_request_signature_algorithm", self.handle)

    def public_key(self) -> PublicKey:
        return PublicKey(Handle.create("umilib_auth_cert_csr_certification_request_public_key", self.handle))

    def verify(self) -> None:
        """Returns if the signature verifies under the request's own public key; raises otherwise."""
        self.library.call("umilib_auth_cert_csr_certification_request_verify", self.handle)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CertificationRequest) and self.to_der() == other.to_der()

    def __hash__(self) -> int:
        return hash(self.to_der())


__all__ = ["CertificationRequest", "CertificationRequestInfo"]
