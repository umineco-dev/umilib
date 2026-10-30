//! The C ABI of [`crate::auth::cert::x509`].
//!
//! Names, lists of general names, lists of extensions, certificates, CRLs
//! and the signed fields of both are handles. Times are seconds since
//! 1970-01-01T00:00:00Z, written in the form RFC 5280 requires for their
//! year. Serial numbers and CRL numbers are the contents octets of their
//! INTEGER. Object identifiers are dotted text. Extensions are read and
//! written as the DER of their value; the functions named after an
//! extension type convert its value to and from its fields.
//!
//! A general name is a kind, its context tag number (0 `otherName`, 1
//! `rfc822Name`, 2 `dNSName`, 3 `x400Address`, 4 `directoryName`, 5
//! `ediPartyName`, 6 `uniformResourceIdentifier`, 7 `iPAddress`, 8
//! `registeredID`), and bytes: the text of 1, 2 and 6, the octets of 7,
//! the dotted text of 8, the DER of the `Name` of 4, and the contents of
//! the element of 0, 3 and 5.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;

use crate::auth::cert::key::{PrivateKey, PublicKey, SignatureAlgorithm};
use crate::auth::cert::x509::{
    AttributeTypeAndValue, AuthorityKeyIdentifier, BasicConstraints, CRLNumber, CRLReason, Certificate,
    CertificateList, ExtendedKeyUsage, Extension, ExtensionValue, Extensions, GeneralName, KeyUsage, Name,
    NameAttribute, OtherName, RelativeDistinguishedName, RevokedCertificate, SerialNumber, SubjectAlternativeName,
    SubjectKeyIdentifier, TBSCertList, TBSCertificate, Time, Validity, Version, X509Error,
};
use crate::codec::asn1::der::DERReader;
use crate::codec::asn1::{ObjectIdentifier, Tag};
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};

/// The statuses of this module, one per variant of [`X509Error`] (a key error keeps its own).
pub struct X509Status;

impl X509Status {
    pub const ENCODING: Status = Status::new(c"auth.cert.x509", c"Encoding", c"the DER encoding is malformed");
    pub const PEM: Status = Status::new(c"auth.cert.x509", c"PEM", c"the PEM text is malformed");
    pub const PEM_LABEL: Status =
        Status::new(c"auth.cert.x509", c"PEMLabel", c"a PEM document of another label than expected");
    pub const VERSION: Status =
        Status::new(c"auth.cert.x509", c"Version", c"unknown version, or one that does not allow the fields present");
    pub const ALGORITHM_MISMATCH: Status = Status::new(
        c"auth.cert.x509",
        c"AlgorithmMismatch",
        c"the signature algorithm inside the signed data differs from the one outside",
    );
    pub const DUPLICATE_EXTENSION: Status =
        Status::new(c"auth.cert.x509", c"DuplicateExtension", c"two extensions of the same type");
    pub const INVALID_EXTENSION: Status = Status::new(c"auth.cert.x509", c"InvalidExtension", c"invalid extension");
    pub const INVALID_NAME: Status = Status::new(c"auth.cert.x509", c"InvalidName", c"invalid name");
    pub const INVALID_TIME: Status = Status::new(c"auth.cert.x509", c"InvalidTime", c"invalid time");
    pub const INVALID_SERIAL_NUMBER: Status =
        Status::new(c"auth.cert.x509", c"InvalidSerialNumber", c"invalid serial number");
    pub const INVALID_ATTRIBUTE: Status = Status::new(c"auth.cert.x509", c"InvalidAttribute", c"invalid attribute");

    /// The object identifier of dotted `text`.
    pub fn oid(text: &str) -> Result<ObjectIdentifier<'static>, &'static Status> {
        ObjectIdentifier::parse(text).map_err(|_| &Status::INVALID_ARGUMENT)
    }

    /// The version of the number of the `Version` syntax (0 for v1).
    pub fn version(number: u8) -> Result<Version, &'static Status> {
        Version::from_integer(number as i128).map_err(|error| error.to_status())
    }

    /// The time `seconds` after the epoch, in the form RFC 5280 requires.
    pub fn time(seconds: i64) -> Result<Time, &'static Status> {
        Time::from_unix_seconds(seconds).map_err(|error| error.to_status())
    }

    /// The general name of `kind` and `data` (see the module documentation).
    pub fn general_name(kind: u8, data: &[u8]) -> Result<GeneralName<'static>, &'static Status> {
        let text =
            || core::str::from_utf8(data).map(|text| Cow::Owned(String::from(text))).map_err(|_| &Status::INVALID_UTF8);
        let owned = || Cow::Owned(data.to_vec());
        let name = match kind {
            0 => {
                let mut reader = DERReader::new(data);
                let type_id = reader.read_object_identifier().map_err(|_| &X509Status::INVALID_NAME)?;
                let mut explicit = reader.read_explicit(0).map_err(|_| &X509Status::INVALID_NAME)?;
                let value = explicit.read_element().map_err(|_| &X509Status::INVALID_NAME)?.encoding;
                if !explicit.is_empty() || !reader.is_empty() {
                    return Err(&X509Status::INVALID_NAME);
                }
                GeneralName::OtherName(OtherName { type_id: type_id.into_owned(), value: Cow::Owned(value.to_vec()) })
            }
            1 => GeneralName::RFC822Name(text()?),
            2 => GeneralName::DNSName(text()?),
            3 => GeneralName::X400Address(owned()),
            4 => GeneralName::DirectoryName(Name::from_der(data).map_err(|error| error.to_status())?.into_owned()),
            5 => GeneralName::EDIPartyName(owned()),
            6 => GeneralName::URI(text()?),
            7 => GeneralName::IPAddress(owned()),
            8 => GeneralName::RegisteredID(X509Status::oid(
                core::str::from_utf8(data).map_err(|_| &Status::INVALID_UTF8)?,
            )?),
            _ => return Err(&Status::INVALID_ARGUMENT),
        };
        Ok(name)
    }

    /// The bytes of `name` (see the module documentation).
    pub fn general_name_data(name: &GeneralName<'_>) -> Vec<u8> {
        match name {
            GeneralName::OtherName(other) => {
                let mut writer = crate::codec::asn1::der::DERWriter::new();
                writer.write_object_identifier(&other.type_id);
                writer.write_element(Tag::context(0, true), &other.value);
                writer.into_bytes()
            }
            GeneralName::RFC822Name(text) | GeneralName::DNSName(text) | GeneralName::URI(text) => {
                text.as_bytes().to_vec()
            }
            GeneralName::X400Address(bytes) | GeneralName::EDIPartyName(bytes) | GeneralName::IPAddress(bytes) => {
                bytes.to_vec()
            }
            GeneralName::DirectoryName(name) => name.as_der().to_vec(),
            GeneralName::RegisteredID(oid) => alloc::format!("{oid}").into_bytes(),
        }
    }
}

impl ToStatus for X509Error {
    fn to_status(&self) -> &'static Status {
        match *self {
            X509Error::Encoding(_) => &X509Status::ENCODING,
            X509Error::PEM(_) => &X509Status::PEM,
            X509Error::PEMLabel => &X509Status::PEM_LABEL,
            X509Error::Key(error) => error.to_status(),
            X509Error::Version => &X509Status::VERSION,
            X509Error::AlgorithmMismatch => &X509Status::ALGORITHM_MISMATCH,
            X509Error::DuplicateExtension => &X509Status::DUPLICATE_EXTENSION,
            X509Error::InvalidExtension => &X509Status::INVALID_EXTENSION,
            X509Error::InvalidName => &X509Status::INVALID_NAME,
            X509Error::InvalidTime => &X509Status::INVALID_TIME,
            X509Error::InvalidSerialNumber => &X509Status::INVALID_SERIAL_NUMBER,
            X509Error::InvalidAttribute => &X509Status::INVALID_ATTRIBUTE,
        }
    }
}

impl Value for Name<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_x509_Name");
}

impl Value for Vec<GeneralName<'static>> {
    const TYPE: Type = Type::Named("umilib_auth_cert_x509_GeneralNames");
}

impl Value for Extensions<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_x509_Extensions");
}

impl Value for Certificate<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_x509_Certificate");
}

impl Value for Vec<Certificate<'static>> {
    const TYPE: Type = Type::Named("umilib_auth_cert_x509_Certificates");
}

impl Value for TBSCertificate<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_x509_TBSCertificate");
}

impl Value for CertificateList<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_x509_CertificateList");
}

impl Value for Vec<CertificateList<'static>> {
    const TYPE: Type = Type::Named("umilib_auth_cert_x509_CertificateLists");
}

impl Value for TBSCertList<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_x509_TBSCertList");
}

crate::ffi_functions! {
    const FUNCTIONS;

    /// Writes the empty name into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_name_empty(out: *mut *mut Name<'static>) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, Name::empty()) })
    }

    /// Writes the name of the DER `Name` of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_name_from_der(data: *const u8, length: usize, out: *mut *mut Name<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let name = Name::from_der(data).map_err(|error| error.to_status())?.into_owned();
            unsafe { Pointer::write_handle(out, name) }
        })())
    }

    /// Writes the name `name` followed by a relative distinguished name of one attribute, of the
    /// type `attribute` (an index of `NameAttribute::ALL`) and the `length` bytes of text at `text`,
    /// into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_name_append(name: *const Name<'static>, attribute: u8, text: *const u8, length: usize, out: *mut *mut Name<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and a writable pointer.
            let name = unsafe { Pointer::reference(name) }?;
            let text = unsafe { Pointer::text(text, length) }?;
            let attribute = *NameAttribute::ALL.get(attribute as usize).ok_or(&Status::INVALID_ARGUMENT)?;
            let attribute = AttributeTypeAndValue::from_text(attribute, text).map_err(|error| error.to_status())?;
            let mut rdns: Vec<RelativeDistinguishedName<'_>> = name.rdns().collect();
            rdns.push(RelativeDistinguishedName::new(&[attribute]).map_err(|error| error.to_status())?);
            let appended = Name::new(&rdns).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, appended) }
        })())
    }

    /// Writes the DER of the name into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_name_to_der(name: *const Name<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let name = unsafe { Pointer::reference(name) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(name.as_der().to_vec())) }
        })())
    }

    /// Writes the string representation of RFC 4514 of the name into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_name_to_rfc4514(name: *const Name<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let name = unsafe { Pointer::reference(name) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(name.to_rfc4514().into_bytes())) }
        })())
    }

    /// Releases a name. Does nothing if `name` is null.
    pub unsafe extern "C" fn umilib_auth_cert_x509_name_free(name: *mut Name<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(name) }
    }

    /// Writes an empty list of general names into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_general_names_new(out: *mut *mut Vec<GeneralName<'static>>) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, Vec::new()) })
    }

    /// Appends the general name of `kind` and the `length` bytes at `data` to the list.
    pub unsafe extern "C" fn umilib_auth_cert_x509_general_names_push(names: *mut Vec<GeneralName<'static>>, kind: u8, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let names = unsafe { Pointer::reference_mut(names) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            names.push(X509Status::general_name(kind, data)?);
            Ok(())
        })())
    }

    /// Writes the number of names of the list into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_general_names_count(names: *const Vec<GeneralName<'static>>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let names = unsafe { Pointer::reference(names) }?;
            unsafe { Pointer::write(out, names.len()) }
        })())
    }

    /// Writes the kind and the bytes of the name at `index` of the list into `out_kind` and `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_general_names_get(names: *const Vec<GeneralName<'static>>, index: usize, out_kind: *mut u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            if out_kind.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a valid handle and writable pointers.
            let names = unsafe { Pointer::reference(names) }?;
            let name = names.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out_kind, name.tag_number() as u8) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(X509Status::general_name_data(name))) }
        })())
    }

    /// Writes the DER of the list as the value of a `SubjectAltName`, `IssuerAltName` or
    /// `CertificateIssuer` extension (at least one name; addresses of 4 or 16 octets) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_general_names_to_der(names: *const Vec<GeneralName<'static>>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let names = unsafe { Pointer::reference(names) }?;
            let value = SubjectAlternativeName { names: names.clone() }.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(value)) }
        })())
    }

    /// Writes the list of the value of a `SubjectAltName`, `IssuerAltName` or `CertificateIssuer`
    /// extension, the `length` bytes at `data`, into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_general_names_from_der(data: *const u8, length: usize, out: *mut *mut Vec<GeneralName<'static>>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let names = SubjectAlternativeName::from_der(data).map_err(|error| error.to_status())?.into_owned().names;
            unsafe { Pointer::write_handle(out, names) }
        })())
    }

    /// Releases a list of general names. Does nothing if `names` is null.
    pub unsafe extern "C" fn umilib_auth_cert_x509_general_names_free(names: *mut Vec<GeneralName<'static>>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(names) }
    }

    /// Writes an empty list of extensions into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_extensions_new(out: *mut *mut Extensions<'static>) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, Extensions::new()) })
    }

    /// Appends the extension of type `oid` (dotted text of `oid_length` bytes), criticality
    /// `critical` and the DER value of `length` bytes at `value`; fails with DuplicateExtension if
    /// one of its type is already there.
    pub unsafe extern "C" fn umilib_auth_cert_x509_extensions_push(extensions: *mut Extensions<'static>, oid: *const u8, oid_length: usize, critical: bool, value: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let extensions = unsafe { Pointer::reference_mut(extensions) }?;
            let oid = X509Status::oid(unsafe { Pointer::text(oid, oid_length) }?)?;
            let value = unsafe { Pointer::slice(value, length) }?;
            let extension = Extension { oid, critical, value: Cow::Owned(value.to_vec()) };
            extensions.push(extension).map_err(|error| error.to_status())
        })())
    }

    /// Writes the number of extensions of the list into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_extensions_count(extensions: *const Extensions<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let extensions = unsafe { Pointer::reference(extensions) }?;
            unsafe { Pointer::write(out, extensions.entries.len()) }
        })())
    }

    /// Writes the type (dotted text), the criticality and the DER value of the extension at `index`
    /// into `out_oid`, `out_critical` and `out_value`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_extensions_get(extensions: *const Extensions<'static>, index: usize, out_oid: *mut Buffer, out_critical: *mut bool, out_value: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            if out_oid.is_null() || out_critical.is_null() || out_value.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a valid handle and writable pointers.
            let extensions = unsafe { Pointer::reference(extensions) }?;
            let extension = extensions.entries.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out_oid, Buffer::from_vec(alloc::format!("{}", extension.oid).into_bytes())) }?;
            unsafe { Pointer::write(out_critical, extension.critical) }?;
            unsafe { Pointer::write(out_value, Buffer::from_vec(extension.value.to_vec())) }
        })())
    }

    /// Writes whether the list has an extension of type `oid` into `out_found` and, if it has, its
    /// index into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_extensions_find(extensions: *const Extensions<'static>, oid: *const u8, oid_length: usize, out_found: *mut bool, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            if out_found.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a valid handle, readable text and writable pointers.
            let extensions = unsafe { Pointer::reference(extensions) }?;
            let oid = X509Status::oid(unsafe { Pointer::text(oid, oid_length) }?)?;
            let index = extensions.entries.iter().position(|extension| extension.oid == oid);
            unsafe { Pointer::write(out_found, index.is_some()) }?;
            unsafe { Pointer::write(out, index.unwrap_or(0)) }
        })())
    }

    /// Releases a list of extensions. Does nothing if `extensions` is null.
    pub unsafe extern "C" fn umilib_auth_cert_x509_extensions_free(extensions: *mut Extensions<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(extensions) }
    }

    /// Writes the DER value of a `BasicConstraints` extension into `out`; `path_length` is used if `has_path_length`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_basic_constraints_encode(ca: bool, has_path_length: bool, path_length: u32, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let constraints = BasicConstraints { ca, path_length: has_path_length.then_some(path_length) };
            let value = constraints.to_der().map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable buffer.
            unsafe { Pointer::write(out, Buffer::from_vec(value)) }
        })())
    }

    /// Writes the fields of the `BasicConstraints` value of `length` bytes at `data` into `out_ca`,
    /// `out_has_path_length` and `out_path_length`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_basic_constraints_decode(data: *const u8, length: usize, out_ca: *mut bool, out_has_path_length: *mut bool, out_path_length: *mut u32) -> *const Status {
        Status::from_result((|| {
            if out_ca.is_null() || out_has_path_length.is_null() || out_path_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes readable bytes and writable pointers.
            let data = unsafe { Pointer::slice(data, length) }?;
            let constraints = BasicConstraints::from_der(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_ca, constraints.ca) }?;
            unsafe { Pointer::write(out_has_path_length, constraints.path_length.is_some()) }?;
            unsafe { Pointer::write(out_path_length, constraints.path_length.unwrap_or(0)) }
        })())
    }

    /// Writes the DER value of a `KeyUsage` extension of the named bits `bits` (bit `n` is `1 << n`) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_key_usage_encode(bits: u16, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let value = KeyUsage { bits }.to_der().map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable buffer.
            unsafe { Pointer::write(out, Buffer::from_vec(value)) }
        })())
    }

    /// Writes the named bits of the `KeyUsage` value of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_key_usage_decode(data: *const u8, length: usize, out: *mut u16) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let usage = KeyUsage::from_der(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, usage.bits) }
        })())
    }

    /// Writes the DER value of an `ExtendedKeyUsage` extension of the purposes in `purposes`
    /// (dotted identifiers separated by commas) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_extended_key_usage_encode(purposes: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable buffer.
            let purposes = unsafe { Pointer::text(purposes, length) }?;
            let purposes = purposes.split(',').map(X509Status::oid).collect::<Result<Vec<_>, _>>()?;
            let value = ExtendedKeyUsage { purposes }.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(value)) }
        })())
    }

    /// Writes the purposes of the `ExtendedKeyUsage` value of `length` bytes at `data`, dotted
    /// identifiers separated by commas, into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_extended_key_usage_decode(data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let usage = ExtendedKeyUsage::from_der(data).map_err(|error| error.to_status())?;
            let text: Vec<String> = usage.purposes.iter().map(|purpose| alloc::format!("{purpose}")).collect();
            unsafe { Pointer::write(out, Buffer::from_vec(text.join(",").into_bytes())) }
        })())
    }

    /// Writes the key identifier of `key` by the first method of RFC 5280 §4.2.1.2 (the SHA-1 of the
    /// `subjectPublicKey`) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_subject_key_identifier_from_public_key(key: *const PublicKey, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let identifier = SubjectKeyIdentifier::from_public_key(key).key_identifier.into_owned();
            unsafe { Pointer::write(out, Buffer::from_vec(identifier)) }
        })())
    }

    /// Writes the DER value of a `SubjectKeyIdentifier` extension of the identifier of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_subject_key_identifier_encode(data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let value = SubjectKeyIdentifier { key_identifier: Cow::Borrowed(data) }.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(value)) }
        })())
    }

    /// Writes the identifier of the `SubjectKeyIdentifier` value of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_subject_key_identifier_decode(data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let identifier = SubjectKeyIdentifier::from_der(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(identifier.key_identifier.into_owned())) }
        })())
    }

    /// Writes the DER value of an `AuthorityKeyIdentifier` extension into `out`: the key identifier
    /// of `identifier_length` bytes at `identifier` if `has_identifier`, and the issuer `issuer`
    /// (null for none) with the serial number of `serial_length` bytes at `serial_number`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_authority_key_identifier_encode(has_identifier: bool, identifier: *const u8, identifier_length: usize, issuer: *const Vec<GeneralName<'static>>, serial_number: *const u8, serial_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes, null or a valid handle, and a writable buffer.
            let identifier = unsafe { Pointer::slice(identifier, identifier_length) }?;
            let issuer = if issuer.is_null() { None } else { Some(unsafe { Pointer::reference(issuer) }?.clone()) };
            let serial = unsafe { Pointer::slice(serial_number, serial_length) }?;
            let serial = if issuer.is_none() && serial.is_empty() {
                None
            } else {
                Some(SerialNumber::new(Cow::Borrowed(serial)).map_err(|error| error.to_status())?)
            };
            let value = AuthorityKeyIdentifier {
                key_identifier: has_identifier.then_some(Cow::Borrowed(identifier)),
                authority_cert_issuer: issuer,
                authority_cert_serial_number: serial,
            };
            let value = value.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(value)) }
        })())
    }

    /// Reads the `AuthorityKeyIdentifier` value of `length` bytes at `data`: writes whether it has a
    /// key identifier into `out_has_identifier` and the identifier (empty if not) into
    /// `out_identifier`; whether it has the issuer and serial number into `out_has_issuer`, the
    /// issuer (null if not) into `out_issuer` and the contents octets of the serial number (empty if
    /// not) into `out_serial_number`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_authority_key_identifier_decode(data: *const u8, length: usize, out_has_identifier: *mut bool, out_identifier: *mut Buffer, out_has_issuer: *mut bool, out_issuer: *mut *mut Vec<GeneralName<'static>>, out_serial_number: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            if out_has_identifier.is_null() || out_identifier.is_null() || out_has_issuer.is_null() || out_issuer.is_null() || out_serial_number.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes readable bytes and writable pointers, checked not null.
            let data = unsafe { Pointer::slice(data, length) }?;
            let value = AuthorityKeyIdentifier::from_der(data).map_err(|error| error.to_status())?.into_owned();
            let serial = value.authority_cert_serial_number.map(|serial| serial.as_bytes().to_vec()).unwrap_or_default();
            unsafe { Pointer::write(out_has_identifier, value.key_identifier.is_some()) }?;
            unsafe { Pointer::write(out_identifier, Buffer::from_vec(value.key_identifier.map(Cow::into_owned).unwrap_or_default())) }?;
            unsafe { Pointer::write(out_has_issuer, value.authority_cert_issuer.is_some()) }?;
            let issuer = value.authority_cert_issuer.map_or(core::ptr::null_mut(), Pointer::into_handle);
            unsafe { Pointer::write(out_issuer, issuer) }?;
            unsafe { Pointer::write(out_serial_number, Buffer::from_vec(serial)) }
        })())
    }

    /// Writes the DER value of a `CRLNumber` extension of the non-negative INTEGER whose contents
    /// octets are the `length` bytes at `number` (up to 20 octets, RFC 5280 §5.2.3) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_crl_number_encode(number: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let number = unsafe { Pointer::slice(number, length) }?;
            let value = CRLNumber { number: Cow::Borrowed(number) }.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(value)) }
        })())
    }

    /// Writes the contents octets of the INTEGER of the `CRLNumber` value of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_crl_number_decode(data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let number = CRLNumber::from_der(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(number.number.into_owned())) }
        })())
    }

    /// Writes the DER value of a `CRLReason` extension of the code `code` (RFC 5280 §5.3.1) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_crl_reason_encode(code: u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let reason = CRLReason::from_code(code as i128).ok_or(&Status::INVALID_ARGUMENT)?;
            let value = reason.to_der().map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable buffer.
            unsafe { Pointer::write(out, Buffer::from_vec(value)) }
        })())
    }

    /// Writes the code of the `CRLReason` value of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_crl_reason_decode(data: *const u8, length: usize, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let reason = CRLReason::from_der(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, reason as u8) }
        })())
    }

    /// Writes a positive serial number of 159 random bits from `random` (its contents octets) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_serial_number_random(random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a generator of the named type and a writable buffer.
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let serial = SerialNumber::random(&mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(serial.as_bytes().to_vec())) }
        })())
    }

    /// Writes the signed fields of a certificate into `out`: the version `version` (0 for v1, 2 for
    /// v3), the serial number of `serial_length` bytes at `serial_number`, the signature algorithm
    /// `signature`, the names `issuer` and `subject`, the validity from `not_before` through
    /// `not_after`, the subject's key `public_key` and the extensions `extensions`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_tbs_certificate_new(version: u8, serial_number: *const u8, serial_length: usize, signature: *const SignatureAlgorithm, issuer: *const Name<'static>, not_before: i64, not_after: i64, subject: *const Name<'static>, public_key: *const PublicKey, extensions: *const Extensions<'static>, out: *mut *mut TBSCertificate<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes, valid handles and a writable pointer.
            let serial = unsafe { Pointer::slice(serial_number, serial_length) }?;
            let signature = unsafe { Pointer::reference(signature) }?;
            let issuer = unsafe { Pointer::reference(issuer) }?;
            let subject = unsafe { Pointer::reference(subject) }?;
            let public_key = unsafe { Pointer::reference(public_key) }?;
            let extensions = unsafe { Pointer::reference(extensions) }?;
            let tbs = TBSCertificate {
                version: X509Status::version(version)?,
                serial_number: SerialNumber::new(Cow::Owned(serial.to_vec())).map_err(|error| error.to_status())?,
                signature: signature.identifier().map_err(|error| error.to_status())?,
                issuer: issuer.clone(),
                validity: Validity { not_before: X509Status::time(not_before)?, not_after: X509Status::time(not_after)? },
                subject: subject.clone(),
                subject_public_key_info: public_key.info().map_err(|error| error.to_status())?.into_owned(),
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: extensions.clone(),
            };
            unsafe { Pointer::write_handle(out, tbs) }
        })())
    }

    /// Succeeds if the fields meet the requirements RFC 5280 places on what CAs issue.
    pub unsafe extern "C" fn umilib_auth_cert_x509_tbs_certificate_check(tbs: *const TBSCertificate<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let tbs = unsafe { Pointer::reference(tbs) }?;
            tbs.check().map_err(|error| error.to_status())
        })())
    }

    /// Writes the DER of the fields into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_tbs_certificate_to_der(tbs: *const TBSCertificate<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let tbs = unsafe { Pointer::reference(tbs) }?;
            let der = tbs.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Writes the certificate of the fields signed by `key` (drawing from `random` where the
    /// algorithm uses random bytes) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_tbs_certificate_sign(tbs: *const TBSCertificate<'static>, key: *const PrivateKey, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut Certificate<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, a generator of the named type and a writable pointer.
            let tbs = unsafe { Pointer::reference(tbs) }?;
            let key = unsafe { Pointer::reference(key) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let certificate = tbs.sign(key, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, certificate) }
        })())
    }

    /// Releases the signed fields of a certificate. Does nothing if `tbs` is null.
    pub unsafe extern "C" fn umilib_auth_cert_x509_tbs_certificate_free(tbs: *mut TBSCertificate<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(tbs) }
    }

    /// Writes the certificate of the DER of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_from_der(data: *const u8, length: usize, out: *mut *mut Certificate<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let certificate = Certificate::from_der(data).map_err(|error| error.to_status())?.into_owned();
            unsafe { Pointer::write_handle(out, certificate) }
        })())
    }

    /// Writes the certificate of the first PEM document (`CERTIFICATE`) of `length` bytes at `text` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_from_pem(text: *const u8, length: usize, out: *mut *mut Certificate<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let certificate = Certificate::from_pem(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, certificate) }
        })())
    }

    /// Writes the DER of the certificate into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_to_der(certificate: *const Certificate<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            let der = certificate.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Writes the PEM text (`CERTIFICATE`) of the certificate into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_to_pem(certificate: *const Certificate<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            let pem = certificate.to_pem().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(pem.into_bytes())) }
        })())
    }

    /// Writes the signed bytes (the DER of the `TBSCertificate` as read) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_tbs_der(certificate: *const Certificate<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(certificate.tbs_encoding().to_vec())) }
        })())
    }

    /// Writes the version (0 for v1, 2 for v3) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_version(certificate: *const Certificate<'static>, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            unsafe { Pointer::write(out, certificate.tbs_certificate().version.to_integer() as u8) }
        })())
    }

    /// Writes the contents octets of the serial number into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_serial_number(certificate: *const Certificate<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(certificate.tbs_certificate().serial_number.as_bytes().to_vec())) }
        })())
    }

    /// Writes the DER `AlgorithmIdentifier` of the signature algorithm into `out` (also for an
    /// algorithm this module does not know).
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_signature_algorithm(certificate: *const Certificate<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            let der = certificate.signature_algorithm().to_der().map_err(|error| X509Error::from(error).to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Writes the octets of the signature into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_signature(certificate: *const Certificate<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(certificate.signature().to_vec())) }
        })())
    }

    /// Writes the issuer's name into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_issuer(certificate: *const Certificate<'static>, out: *mut *mut Name<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            unsafe { Pointer::write_handle(out, certificate.tbs_certificate().issuer.clone()) }
        })())
    }

    /// Writes the subject's name into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_subject(certificate: *const Certificate<'static>, out: *mut *mut Name<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            unsafe { Pointer::write_handle(out, certificate.tbs_certificate().subject.clone()) }
        })())
    }

    /// Writes the start and the end of the validity, in seconds since the epoch, into `out_not_before` and `out_not_after`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_validity(certificate: *const Certificate<'static>, out_not_before: *mut i64, out_not_after: *mut i64) -> *const Status {
        Status::from_result((|| {
            if out_not_before.is_null() || out_not_after.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a valid handle and writable pointers.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            let validity = certificate.tbs_certificate().validity;
            unsafe { Pointer::write(out_not_before, validity.not_before.to_unix_seconds()) }?;
            unsafe { Pointer::write(out_not_after, validity.not_after.to_unix_seconds()) }
        })())
    }

    /// Writes the subject's public key, within the default key limits, into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_public_key(certificate: *const Certificate<'static>, out: *mut *mut PublicKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            let key = certificate.public_key().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Writes a copy of the extensions into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_extensions(certificate: *const Certificate<'static>, out: *mut *mut Extensions<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            unsafe { Pointer::write_handle(out, certificate.tbs_certificate().extensions.clone()) }
        })())
    }

    /// Succeeds if the signature verifies under `issuer`, the public key of the issuer.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_verify(certificate: *const Certificate<'static>, issuer: *const PublicKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            let issuer = unsafe { Pointer::reference(issuer) }?;
            certificate.verify(issuer).map_err(|error| error.to_status())
        })())
    }

    /// Writes whether the issuer and subject names are the same encoding into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_is_self_issued(certificate: *const Certificate<'static>, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            unsafe { Pointer::write(out, certificate.is_self_issued()) }
        })())
    }

    /// Releases a certificate. Does nothing if `certificate` is null.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_free(certificate: *mut Certificate<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(certificate) }
    }

    /// Writes an empty list of certificates into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificates_new(out: *mut *mut Vec<Certificate<'static>>) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, Vec::<Certificate<'static>>::new()) })
    }

    /// Appends a copy of `certificate` to the list.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificates_push(certificates: *mut Vec<Certificate<'static>>, certificate: *const Certificate<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let certificates = unsafe { Pointer::reference_mut(certificates) }?;
            let certificate = unsafe { Pointer::reference(certificate) }?;
            certificates.push(certificate.clone());
            Ok(())
        })())
    }

    /// Writes the certificates of every PEM document (each `CERTIFICATE`) of `length` bytes at `text` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificates_from_pem(text: *const u8, length: usize, out: *mut *mut Vec<Certificate<'static>>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let certificates = Certificate::from_pem_all(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, certificates) }
        })())
    }

    /// Writes the number of certificates of the list into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificates_count(certificates: *const Vec<Certificate<'static>>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let certificates = unsafe { Pointer::reference(certificates) }?;
            unsafe { Pointer::write(out, certificates.len()) }
        })())
    }

    /// Writes a copy of the certificate at `index` of the list into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificates_get(certificates: *const Vec<Certificate<'static>>, index: usize, out: *mut *mut Certificate<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let certificates = unsafe { Pointer::reference(certificates) }?;
            let certificate = certificates.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, certificate.clone()) }
        })())
    }

    /// Releases a list of certificates. Does nothing if `certificates` is null.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificates_free(certificates: *mut Vec<Certificate<'static>>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(certificates) }
    }

    /// Writes an empty list of CRLs into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_lists_new(out: *mut *mut Vec<CertificateList<'static>>) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, Vec::<CertificateList<'static>>::new()) })
    }

    /// Appends a copy of the CRL `list` to the list of CRLs.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_lists_push(lists: *mut Vec<CertificateList<'static>>, list: *const CertificateList<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let lists = unsafe { Pointer::reference_mut(lists) }?;
            let list = unsafe { Pointer::reference(list) }?;
            lists.push(list.clone());
            Ok(())
        })())
    }

    /// Writes the number of CRLs of the list into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_lists_count(lists: *const Vec<CertificateList<'static>>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let lists = unsafe { Pointer::reference(lists) }?;
            unsafe { Pointer::write(out, lists.len()) }
        })())
    }

    /// Writes a copy of the CRL at `index` of the list into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_lists_get(lists: *const Vec<CertificateList<'static>>, index: usize, out: *mut *mut CertificateList<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let lists = unsafe { Pointer::reference(lists) }?;
            let list = lists.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, list.clone()) }
        })())
    }

    /// Releases a list of CRLs. Does nothing if `lists` is null.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_lists_free(lists: *mut Vec<CertificateList<'static>>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(lists) }
    }

    /// Writes the signed fields of a CRL into `out`: the version `version` (0 for v1, 1 for v2), the
    /// signature algorithm `signature`, the issuer `issuer`, `this_update`, `next_update` (if
    /// `has_next_update`) and the CRL extensions `extensions`, without entries.
    pub unsafe extern "C" fn umilib_auth_cert_x509_tbs_cert_list_new(version: u8, signature: *const SignatureAlgorithm, issuer: *const Name<'static>, this_update: i64, has_next_update: bool, next_update: i64, extensions: *const Extensions<'static>, out: *mut *mut TBSCertList<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let signature = unsafe { Pointer::reference(signature) }?;
            let issuer = unsafe { Pointer::reference(issuer) }?;
            let extensions = unsafe { Pointer::reference(extensions) }?;
            let tbs = TBSCertList {
                version: X509Status::version(version)?,
                signature: signature.identifier().map_err(|error| error.to_status())?,
                issuer: issuer.clone(),
                this_update: X509Status::time(this_update)?,
                next_update: if has_next_update { Some(X509Status::time(next_update)?) } else { None },
                revoked_certificates: Vec::new(),
                extensions: extensions.clone(),
            };
            unsafe { Pointer::write_handle(out, tbs) }
        })())
    }

    /// Appends the entry of the serial number of `serial_length` bytes at `serial_number`, revoked
    /// at `revocation_date`, with the entry extensions `extensions`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_tbs_cert_list_push(tbs: *mut TBSCertList<'static>, serial_number: *const u8, serial_length: usize, revocation_date: i64, extensions: *const Extensions<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and readable bytes.
            let tbs = unsafe { Pointer::reference_mut(tbs) }?;
            let serial = unsafe { Pointer::slice(serial_number, serial_length) }?;
            let extensions = unsafe { Pointer::reference(extensions) }?;
            tbs.revoked_certificates.push(RevokedCertificate {
                serial_number: SerialNumber::new(Cow::Owned(serial.to_vec())).map_err(|error| error.to_status())?,
                revocation_date: X509Status::time(revocation_date)?,
                extensions: extensions.clone(),
            });
            Ok(())
        })())
    }

    /// Writes the CRL of the fields signed by `key` (drawing from `random` where the algorithm uses
    /// random bytes) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_tbs_cert_list_sign(tbs: *const TBSCertList<'static>, key: *const PrivateKey, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut CertificateList<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, a generator of the named type and a writable pointer.
            let tbs = unsafe { Pointer::reference(tbs) }?;
            let key = unsafe { Pointer::reference(key) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let list = tbs.sign(key, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, list) }
        })())
    }

    /// Releases the signed fields of a CRL. Does nothing if `tbs` is null.
    pub unsafe extern "C" fn umilib_auth_cert_x509_tbs_cert_list_free(tbs: *mut TBSCertList<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(tbs) }
    }

    /// Writes the CRL of the DER of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_list_from_der(data: *const u8, length: usize, out: *mut *mut CertificateList<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let list = CertificateList::from_der(data).map_err(|error| error.to_status())?.into_owned();
            unsafe { Pointer::write_handle(out, list) }
        })())
    }

    /// Writes the CRL of the first PEM document (`X509 CRL`) of `length` bytes at `text` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_list_from_pem(text: *const u8, length: usize, out: *mut *mut CertificateList<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let list = CertificateList::from_pem(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, list) }
        })())
    }

    /// Writes the DER of the CRL into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_list_to_der(list: *const CertificateList<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let list = unsafe { Pointer::reference(list) }?;
            let der = list.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Writes the PEM text (`X509 CRL`) of the CRL into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_list_to_pem(list: *const CertificateList<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let list = unsafe { Pointer::reference(list) }?;
            let pem = list.to_pem().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(pem.into_bytes())) }
        })())
    }

    /// Writes the version (0 for v1, 1 for v2) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_list_version(list: *const CertificateList<'static>, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let list = unsafe { Pointer::reference(list) }?;
            unsafe { Pointer::write(out, list.tbs_cert_list().version.to_integer() as u8) }
        })())
    }

    /// Writes the issuer's name into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_list_issuer(list: *const CertificateList<'static>, out: *mut *mut Name<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let list = unsafe { Pointer::reference(list) }?;
            unsafe { Pointer::write_handle(out, list.tbs_cert_list().issuer.clone()) }
        })())
    }

    /// Writes `thisUpdate` into `out`, in seconds since the epoch.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_list_this_update(list: *const CertificateList<'static>, out: *mut i64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let list = unsafe { Pointer::reference(list) }?;
            unsafe { Pointer::write(out, list.tbs_cert_list().this_update.to_unix_seconds()) }
        })())
    }

    /// Writes whether the CRL has a `nextUpdate` into `out_found` and, if it has, the time into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_list_next_update(list: *const CertificateList<'static>, out_found: *mut bool, out: *mut i64) -> *const Status {
        Status::from_result((|| {
            if out_found.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a valid handle and writable pointers.
            let list = unsafe { Pointer::reference(list) }?;
            let next_update = list.tbs_cert_list().next_update;
            unsafe { Pointer::write(out_found, next_update.is_some()) }?;
            unsafe { Pointer::write(out, next_update.map_or(0, |time| time.to_unix_seconds())) }
        })())
    }

    /// Writes a copy of the CRL extensions into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_list_extensions(list: *const CertificateList<'static>, out: *mut *mut Extensions<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let list = unsafe { Pointer::reference(list) }?;
            unsafe { Pointer::write_handle(out, list.tbs_cert_list().extensions.clone()) }
        })())
    }

    /// Writes the number of entries into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_list_count(list: *const CertificateList<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let list = unsafe { Pointer::reference(list) }?;
            unsafe { Pointer::write(out, list.tbs_cert_list().revoked_certificates.len()) }
        })())
    }

    /// Writes the serial number (contents octets), the revocation date and a copy of the entry
    /// extensions of the entry at `index` into `out_serial_number`, `out_revocation_date` and `out_extensions`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_list_get(list: *const CertificateList<'static>, index: usize, out_serial_number: *mut Buffer, out_revocation_date: *mut i64, out_extensions: *mut *mut Extensions<'static>) -> *const Status {
        Status::from_result((|| {
            if out_serial_number.is_null() || out_revocation_date.is_null() || out_extensions.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a valid handle and writable pointers.
            let list = unsafe { Pointer::reference(list) }?;
            let entry = list.tbs_cert_list().revoked_certificates.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out_serial_number, Buffer::from_vec(entry.serial_number.as_bytes().to_vec())) }?;
            unsafe { Pointer::write(out_revocation_date, entry.revocation_date.to_unix_seconds()) }?;
            unsafe { Pointer::write_handle(out_extensions, entry.extensions.clone()) }
        })())
    }

    /// Writes whether the CRL lists the serial number of `length` bytes at `serial_number` into
    /// `out_found` and, if it does, the index of its entry into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_list_find(list: *const CertificateList<'static>, serial_number: *const u8, length: usize, out_found: *mut bool, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            if out_found.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a valid handle, readable bytes and writable pointers.
            let list = unsafe { Pointer::reference(list) }?;
            let serial = unsafe { Pointer::slice(serial_number, length) }?;
            let index = list.tbs_cert_list().revoked_certificates.iter().position(|entry| entry.serial_number.as_bytes() == serial);
            unsafe { Pointer::write(out_found, index.is_some()) }?;
            unsafe { Pointer::write(out, index.unwrap_or(0)) }
        })())
    }

    /// Succeeds if the signature verifies under `issuer`, the public key of the CRL issuer.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_list_verify(list: *const CertificateList<'static>, issuer: *const PublicKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let list = unsafe { Pointer::reference(list) }?;
            let issuer = unsafe { Pointer::reference(issuer) }?;
            list.verify(issuer).map_err(|error| error.to_status())
        })())
    }

    /// Releases a CRL. Does nothing if `list` is null.
    pub unsafe extern "C" fn umilib_auth_cert_x509_certificate_list_free(list: *mut CertificateList<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(list) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "x509",
    definitions: &[
        Definition::Opaque { name: "umilib_auth_cert_x509_Name", documentation: " A distinguished name." },
        Definition::Opaque { name: "umilib_auth_cert_x509_GeneralNames", documentation: " A list of general names." },
        Definition::Opaque {
            name: "umilib_auth_cert_x509_Extensions",
            documentation: " A list of extensions, each of a different type.",
        },
        Definition::Opaque { name: "umilib_auth_cert_x509_Certificate", documentation: " A certificate." },
        Definition::Opaque { name: "umilib_auth_cert_x509_Certificates", documentation: " A list of certificates." },
        Definition::Opaque {
            name: "umilib_auth_cert_x509_TBSCertificate",
            documentation: " The signed fields of a certificate.",
        },
        Definition::Opaque { name: "umilib_auth_cert_x509_CertificateList", documentation: " A CRL." },
        Definition::Opaque { name: "umilib_auth_cert_x509_CertificateLists", documentation: " A list of CRLs." },
        Definition::Opaque { name: "umilib_auth_cert_x509_TBSCertList", documentation: " The signed fields of a CRL." },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
