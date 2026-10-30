//! The C ABI of [`crate::auth::cert::csr`].
//!
//! Requests and their signed information are handles; names, keys and
//! extensions are the handles of [`crate::ffi::auth::cert::x509`] and
//! [`crate::ffi::auth::cert::key`]. Attribute types are dotted text and
//! attribute values the DER of one element.

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::ffi::c_void;

use crate::auth::cert::csr::{CertificationRequest, CertificationRequestInfo};
use crate::auth::cert::key::{PrivateKey, PublicKey, SignatureAlgorithm};
use crate::auth::cert::x509::{Attribute, AttributeTypeAndValue, Extensions, Name, X509Error};
use crate::ffi::auth::cert::x509::X509Status;
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for CertificationRequestInfo<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_csr_CertificationRequestInfo");
}

impl Value for CertificationRequest<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_csr_CertificationRequest");
}

crate::ffi_functions! {
    const FUNCTIONS;

    /// Writes the information of a request into `out`: the subject `subject`, its key `public_key`
    /// and, if `extensions` is not empty, an `extensionRequest` attribute of `extensions`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_info_new(subject: *const Name<'static>, public_key: *const PublicKey, extensions: *const Extensions<'static>, out: *mut *mut CertificationRequestInfo<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let subject = unsafe { Pointer::reference(subject) }?;
            let public_key = unsafe { Pointer::reference(public_key) }?;
            let extensions = unsafe { Pointer::reference(extensions) }?;
            let mut attributes = Vec::new();
            if !extensions.is_empty() {
                attributes.push(CertificationRequestInfo::extension_request(extensions).map_err(|error| error.to_status())?);
            }
            let info = CertificationRequestInfo {
                subject: subject.clone(),
                subject_public_key_info: public_key.info().map_err(|error| error.to_status())?.into_owned(),
                attributes,
            };
            unsafe { Pointer::write_handle(out, info) }
        })())
    }

    /// Appends an attribute of the type `oid` (dotted text of `oid_length` bytes) with one value, the
    /// DER element of `length` bytes at `value`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_info_push(info: *mut CertificationRequestInfo<'static>, oid: *const u8, oid_length: usize, value: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let info = unsafe { Pointer::reference_mut(info) }?;
            let oid = X509Status::oid(unsafe { Pointer::text(oid, oid_length) }?)?;
            let value = unsafe { Pointer::slice(value, length) }?;
            AttributeTypeAndValue::check_value(value).map_err(|_| X509Error::InvalidAttribute.to_status())?;
            info.attributes.push(Attribute { oid, values: alloc::vec![Cow::Owned(value.to_vec())] });
            Ok(())
        })())
    }

    /// Writes the DER of the information into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_info_to_der(info: *const CertificationRequestInfo<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let info = unsafe { Pointer::reference(info) }?;
            let der = info.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Writes the request of the information signed by `key`, the private key of the subject, with
    /// `algorithm` (drawing from `random` where the algorithm uses random bytes) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_info_sign(info: *const CertificationRequestInfo<'static>, key: *const PrivateKey, algorithm: *const SignatureAlgorithm, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut CertificationRequest<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, a generator of the named type and a writable pointer.
            let info = unsafe { Pointer::reference(info) }?;
            let key = unsafe { Pointer::reference(key) }?;
            let algorithm = unsafe { Pointer::reference(algorithm) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let request = info.sign(key, algorithm, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, request) }
        })())
    }

    /// Releases the information of a request. Does nothing if `info` is null.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_info_free(info: *mut CertificationRequestInfo<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(info) }
    }

    /// Writes the request of the DER of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_from_der(data: *const u8, length: usize, out: *mut *mut CertificationRequest<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let request = CertificationRequest::from_der(data).map_err(|error| error.to_status())?.into_owned();
            unsafe { Pointer::write_handle(out, request) }
        })())
    }

    /// Writes the request of the first PEM document (`CERTIFICATE REQUEST` or `NEW CERTIFICATE
    /// REQUEST`) of `length` bytes at `text` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_from_pem(text: *const u8, length: usize, out: *mut *mut CertificationRequest<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let request = CertificationRequest::from_pem(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, request) }
        })())
    }

    /// Writes the DER of the request into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_to_der(request: *const CertificationRequest<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let request = unsafe { Pointer::reference(request) }?;
            let der = request.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Writes the PEM text (`CERTIFICATE REQUEST`) of the request into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_to_pem(request: *const CertificationRequest<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let request = unsafe { Pointer::reference(request) }?;
            let pem = request.to_pem().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(pem.into_bytes())) }
        })())
    }

    /// Writes the subject's name into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_subject(request: *const CertificationRequest<'static>, out: *mut *mut Name<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let request = unsafe { Pointer::reference(request) }?;
            unsafe { Pointer::write_handle(out, request.info().subject.clone()) }
        })())
    }

    /// Writes the subject's public key into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_public_key(request: *const CertificationRequest<'static>, out: *mut *mut PublicKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let request = unsafe { Pointer::reference(request) }?;
            let key = request.public_key().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Writes the requested extensions (empty without an `extensionRequest`) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_extensions(request: *const CertificationRequest<'static>, out: *mut *mut Extensions<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let request = unsafe { Pointer::reference(request) }?;
            let extensions = request.info().extensions().map_err(|error| error.to_status())?.into_owned();
            unsafe { Pointer::write_handle(out, extensions) }
        })())
    }

    /// Writes the number of attributes into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_attribute_count(request: *const CertificationRequest<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let request = unsafe { Pointer::reference(request) }?;
            unsafe { Pointer::write(out, request.info().attributes.len()) }
        })())
    }

    /// Writes the type (dotted text) and the number of values of the attribute at `index` into `out_oid` and `out_count`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_attribute(request: *const CertificationRequest<'static>, index: usize, out_oid: *mut Buffer, out_count: *mut usize) -> *const Status {
        Status::from_result((|| {
            if out_oid.is_null() || out_count.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a valid handle and writable pointers.
            let request = unsafe { Pointer::reference(request) }?;
            let attribute = request.info().attributes.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out_oid, Buffer::from_vec(alloc::format!("{}", attribute.oid).into_bytes())) }?;
            unsafe { Pointer::write(out_count, attribute.values.len()) }
        })())
    }

    /// Writes the DER of the value at `value_index` of the attribute at `index` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_attribute_value(request: *const CertificationRequest<'static>, index: usize, value_index: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let request = unsafe { Pointer::reference(request) }?;
            let attribute = request.info().attributes.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            let value = attribute.values.get(value_index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, Buffer::from_vec(value.to_vec())) }
        })())
    }

    /// Writes the DER `AlgorithmIdentifier` of the signature algorithm into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_signature_algorithm(request: *const CertificationRequest<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let request = unsafe { Pointer::reference(request) }?;
            let der = request.signature_algorithm().to_der().map_err(|error| X509Error::from(error).to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Succeeds if the signature verifies under the subject's public key of the request.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_verify(request: *const CertificationRequest<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let request = unsafe { Pointer::reference(request) }?;
            request.verify().map_err(|error| error.to_status())
        })())
    }

    /// Releases a request. Does nothing if `request` is null.
    pub unsafe extern "C" fn umilib_auth_cert_csr_certification_request_free(request: *mut CertificationRequest<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(request) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "csr",
    definitions: &[
        Definition::Opaque {
            name: "umilib_auth_cert_csr_CertificationRequestInfo",
            documentation: " The signed information of a certification request.",
        },
        Definition::Opaque {
            name: "umilib_auth_cert_csr_CertificationRequest",
            documentation: " A certification request (PKCS #10).",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
