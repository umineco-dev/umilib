//! The C ABI of [`crate::auth::cert::ocsp`].
//!
//! Certificate identifiers, configurations, requests, responses and their
//! parts are handles; certificates, names, lists of certificates and
//! extensions are the handles of [`crate::ffi::auth::cert::x509`], keys and
//! algorithms those of [`crate::ffi::auth::cert::key`]. Times are seconds
//! since 1970-01-01T00:00:00Z. A certificate status is a kind ([`CertStatusKind`])
//! with, when revoked, the revocation time and the code of the reason, if
//! any. A list of certificates passed as null is the absent field.

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::ffi::c_void;

use crate::auth::cert::key::{HashAlgorithm, KeyLimits, PrivateKey, PublicKey, SignatureAlgorithm};
use crate::auth::cert::ocsp::{
    BasicOCSPResponse, CertID, CertStatus, OCSPConfig, OCSPError, OCSPNonce, OCSPRequest, OCSPResponse,
    OCSPResponseStatus, Request, ResponderID, ResponseData, SingleResponse, TBSRequest,
};
use crate::auth::cert::x509::{CRLReason, Certificate, Extension, Extensions, Name};
use crate::codec::asn1::ASN1Time;
use crate::ffi::auth::cert::key::KeyStatus;
use crate::ffi::auth::cert::x509::X509Status;
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};

/// The statuses of this module, one per variant of [`OCSPError`] (encoding
/// and key errors keep those of x509 and key).
pub struct OCSPStatus;

impl OCSPStatus {
    pub const VERSION: Status = Status::new(c"auth.cert.ocsp", c"Version", c"unknown version");
    pub const STATUS: Status = Status::new(c"auth.cert.ocsp", c"Status", c"the response is not successful");
    pub const RESPONSE_TYPE: Status = Status::new(
        c"auth.cert.ocsp",
        c"ResponseType",
        c"not a basic response, or response bytes that do not go with the status",
    );
    pub const ALGORITHM: Status =
        Status::new(c"auth.cert.ocsp", c"Algorithm", c"a signature algorithm the configuration does not accept");
    pub const SIGNER: Status = Status::new(c"auth.cert.ocsp", c"Signer", c"the signer is not authorized");
    pub const NOT_FOUND: Status = Status::new(c"auth.cert.ocsp", c"NotFound", c"no status for the certificate");
    pub const TIME: Status = Status::new(c"auth.cert.ocsp", c"Time", c"the status is not current");
    pub const NONCE: Status = Status::new(c"auth.cert.ocsp", c"Nonce", c"the nonce does not match");
    pub const UNKNOWN_CRITICAL_EXTENSION: Status =
        Status::new(c"auth.cert.ocsp", c"UnknownCriticalExtension", c"an unknown critical extension");
    pub const WORK: Status = Status::new(c"auth.cert.ocsp", c"Work", c"too many signatures to verify");

    /// The time `seconds` after the epoch.
    pub fn time(seconds: i64) -> Result<ASN1Time, &'static Status> {
        ASN1Time::from_unix_seconds(seconds).map_err(|_| &X509Status::INVALID_TIME)
    }

    /// A copy of the list of certificates `certificates`, or `None` for null.
    ///
    /// # Safety
    /// `certificates` is null or a valid handle.
    pub unsafe fn certificates(
        certificates: *const Vec<Certificate<'static>>,
    ) -> Result<Option<Vec<Certificate<'static>>>, &'static Status> {
        if certificates.is_null() {
            return Ok(None);
        }
        // SAFETY: the caller passes a valid handle.
        Ok(Some(unsafe { Pointer::reference(certificates) }?.clone()))
    }

    /// Replaces the nonce extension of `extensions` with one of `nonce`.
    pub fn set_nonce(extensions: &mut Extensions<'static>, nonce: &[u8]) -> Result<(), &'static Status> {
        let nonce = OCSPNonce { nonce: Cow::Borrowed(nonce) };
        let extension = Extension::new(&nonce, false).map_err(|error| error.to_status())?;
        extensions.entries.retain(|entry| entry.oid != extension.oid);
        extensions.entries.push(extension);
        Ok(())
    }

    /// Writes the nonce of `extensions`, if any, into `out_has` and `out`.
    ///
    /// # Safety
    /// `out_has` and `out` are writable.
    pub unsafe fn write_nonce(
        extensions: &Extensions<'_>,
        out_has: *mut bool,
        out: *mut Buffer,
    ) -> Result<(), &'static Status> {
        if out_has.is_null() || out.is_null() {
            return Err(&Status::NULL_POINTER);
        }
        let nonce = extensions.typed::<OCSPNonce<'_>>().map_err(|error| error.to_status())?;
        // SAFETY: the caller passes writable pointers.
        unsafe { Pointer::write(out_has, nonce.is_some()) }?;
        let bytes = nonce.map(|nonce| nonce.nonce.into_owned()).unwrap_or_default();
        unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
    }
}

impl ToStatus for OCSPError {
    fn to_status(&self) -> &'static Status {
        match self {
            OCSPError::X509(error) => error.to_status(),
            OCSPError::Key(error) => error.to_status(),
            OCSPError::Version => &OCSPStatus::VERSION,
            OCSPError::Status(_) => &OCSPStatus::STATUS,
            OCSPError::ResponseType => &OCSPStatus::RESPONSE_TYPE,
            OCSPError::Algorithm => &OCSPStatus::ALGORITHM,
            OCSPError::Signer => &OCSPStatus::SIGNER,
            OCSPError::NotFound => &OCSPStatus::NOT_FOUND,
            OCSPError::Time => &OCSPStatus::TIME,
            OCSPError::Nonce => &OCSPStatus::NONCE,
            OCSPError::UnknownCriticalExtension => &OCSPStatus::UNKNOWN_CRITICAL_EXTENSION,
            OCSPError::Work => &OCSPStatus::WORK,
        }
    }
}

/// The [`CertStatus`] kinds of the C ABI.
pub struct CertStatusKind;

impl CertStatusKind {
    pub const GOOD: u8 = 0;
    pub const REVOKED: u8 = 1;
    pub const UNKNOWN: u8 = 2;
    /// The reason written for a revoked status without a reason.
    pub const NO_REASON: u8 = u8::MAX;

    /// The status of `kind`, with the revocation `time` and reason `reason` (or [`CertStatusKind::NO_REASON`]) when revoked.
    pub fn decode(kind: u8, time: i64, reason: u8) -> Result<CertStatus, &'static Status> {
        match kind {
            CertStatusKind::GOOD => Ok(CertStatus::Good),
            CertStatusKind::UNKNOWN => Ok(CertStatus::Unknown),
            CertStatusKind::REVOKED => {
                let reason = match reason {
                    CertStatusKind::NO_REASON => None,
                    code => Some(CRLReason::from_code(code as i128).ok_or(&Status::INVALID_ARGUMENT)?),
                };
                Ok(CertStatus::Revoked { time: OCSPStatus::time(time)?, reason })
            }
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    /// The kind, revocation time (0 unless revoked) and reason of `status`.
    pub fn encode(status: &CertStatus) -> (u8, i64, u8) {
        match status {
            CertStatus::Good => (CertStatusKind::GOOD, 0, CertStatusKind::NO_REASON),
            CertStatus::Unknown => (CertStatusKind::UNKNOWN, 0, CertStatusKind::NO_REASON),
            CertStatus::Revoked { time, reason } => (
                CertStatusKind::REVOKED,
                time.to_unix_seconds(),
                reason.map_or(CertStatusKind::NO_REASON, |reason| reason as u8),
            ),
        }
    }
}

impl Value for CertID<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_ocsp_CertID");
}

impl Value for OCSPConfig {
    const TYPE: Type = Type::Named("umilib_auth_cert_ocsp_OCSPConfig");
}

impl Value for TBSRequest<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_ocsp_TBSRequest");
}

impl Value for OCSPRequest<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_ocsp_OCSPRequest");
}

impl Value for SingleResponse<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_ocsp_SingleResponse");
}

impl Value for ResponseData<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_ocsp_ResponseData");
}

impl Value for BasicOCSPResponse<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_ocsp_BasicOCSPResponse");
}

impl Value for OCSPResponse<'static> {
    const TYPE: Type = Type::Named("umilib_auth_cert_ocsp_OCSPResponse");
}

crate::ffi_functions! {
    const FUNCTIONS;

    /// Writes the identifier of `certificate`, issued by the holder of `issuer_key`, with the hash
    /// function `hash` (an index of the hash functions of key) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_cert_id_new(certificate: *const Certificate<'static>, issuer_key: *const PublicKey, hash: u8, out: *mut *mut CertID<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            let issuer_key = unsafe { Pointer::reference(issuer_key) }?;
            let hash = KeyStatus::index(&HashAlgorithm::ALL, hash)?;
            unsafe { Pointer::write_handle(out, CertID::new(certificate, issuer_key.key(), hash)) }
        })())
    }

    /// Writes the identifier of the DER of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_cert_id_from_der(data: *const u8, length: usize, out: *mut *mut CertID<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let cert_id = CertID::from_der(data).map_err(|error| error.to_status())?.into_owned();
            unsafe { Pointer::write_handle(out, cert_id) }
        })())
    }

    /// Writes the DER of the identifier into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_cert_id_to_der(cert_id: *const CertID<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let cert_id = unsafe { Pointer::reference(cert_id) }?;
            let der = cert_id.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Writes the contents octets of the INTEGER of the serial number into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_cert_id_serial_number(cert_id: *const CertID<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let cert_id = unsafe { Pointer::reference(cert_id) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(cert_id.serial_number.as_bytes().to_vec())) }
        })())
    }

    /// Writes whether both identifiers name the same certificate into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_cert_id_matches(cert_id: *const CertID<'static>, other: *const CertID<'static>, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let cert_id = unsafe { Pointer::reference(cert_id) }?;
            let other = unsafe { Pointer::reference(other) }?;
            unsafe { Pointer::write(out, cert_id.matches(other)) }
        })())
    }

    /// Writes whether the identifier names `certificate`, issued by the holder of `issuer_key`, into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_cert_id_identifies(cert_id: *const CertID<'static>, certificate: *const Certificate<'static>, issuer_key: *const PublicKey, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let cert_id = unsafe { Pointer::reference(cert_id) }?;
            let certificate = unsafe { Pointer::reference(certificate) }?;
            let issuer_key = unsafe { Pointer::reference(issuer_key) }?;
            unsafe { Pointer::write(out, cert_id.identifies(certificate, issuer_key.key())) }
        })())
    }

    /// Releases an identifier. Does nothing if `cert_id` is null.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_cert_id_free(cert_id: *mut CertID<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(cert_id) }
    }

    /// Writes the defaults of the checks of a response at `time` into `out`: no nonce, the default
    /// key limits, SHA-1 refused, a status without `nextUpdate` current for a day, 9 signatures.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_config_new(time: i64, out: *mut *mut OCSPConfig) -> *const Status {
        Status::from_result((|| {
            let time = OCSPStatus::time(time)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, OCSPConfig::new(time)) }
        })())
    }

    /// Sets the nonce of the request, which the response must repeat (`length` 0 removes it).
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_config_set_nonce(config: *mut OCSPConfig, nonce: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let config = unsafe { Pointer::reference_mut(config) }?;
            let nonce = unsafe { Pointer::slice(nonce, length) }?;
            config.nonce = if nonce.is_empty() { None } else { Some(nonce.to_vec()) };
            Ok(())
        })())
    }

    /// Sets the largest RSA modulus and exponent (in bits) of delegated responders' keys.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_config_set_key_limits(config: *mut OCSPConfig, maximum_rsa_bits: u32, maximum_rsa_exponent_bits: u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.key_limits = KeyLimits { maximum_rsa_bits, maximum_rsa_exponent_bits };
            Ok(())
        })())
    }

    /// Sets whether signatures that hash with SHA-1 are accepted.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_config_set_accept_sha1(config: *mut OCSPConfig, accept: bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.accept_sha1 = accept;
            Ok(())
        })())
    }

    /// Sets how long (in seconds) a status without `nextUpdate` is current, and the most signatures
    /// the search of a response's signer verifies.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_config_set_limits(config: *mut OCSPConfig, lifetime_without_next_update: u64, maximum_signatures: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.lifetime_without_next_update = lifetime_without_next_update;
            config.maximum_signatures = maximum_signatures;
            Ok(())
        })())
    }

    /// Releases a configuration. Does nothing if `config` is null.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_config_free(config: *mut OCSPConfig) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(config) }
    }

    /// Writes a nonce of 32 random octets (RFC 8954) drawn from `random` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_nonce_random(random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a generator of the named type and a writable buffer.
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let nonce = OCSPNonce::random(&mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(nonce.nonce.into_owned())) }
        })())
    }

    /// Writes the fields of a request without certificates, requestor or extensions into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_tbs_request_new(out: *mut *mut TBSRequest<'static>) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, TBSRequest::default()) })
    }

    /// Appends a request for the certificate `cert_id` names.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_tbs_request_push(tbs: *mut TBSRequest<'static>, cert_id: *const CertID<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let tbs = unsafe { Pointer::reference_mut(tbs) }?;
            let cert_id = unsafe { Pointer::reference(cert_id) }?;
            tbs.requests.push(Request { cert_id: cert_id.clone(), extensions: Extensions::new() });
            Ok(())
        })())
    }

    /// Sets the requestor's name, the general name of `kind` and `length` bytes at `data` (see x509).
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_tbs_request_set_requestor_name(tbs: *mut TBSRequest<'static>, kind: u8, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let tbs = unsafe { Pointer::reference_mut(tbs) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            tbs.requestor_name = Some(X509Status::general_name(kind, data)?);
            Ok(())
        })())
    }

    /// Sets the nonce of `length` bytes at `nonce` (1 to 32, RFC 8954).
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_tbs_request_set_nonce(tbs: *mut TBSRequest<'static>, nonce: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let tbs = unsafe { Pointer::reference_mut(tbs) }?;
            let nonce = unsafe { Pointer::slice(nonce, length) }?;
            OCSPStatus::set_nonce(&mut tbs.extensions, nonce)
        })())
    }

    /// Releases the fields of a request. Does nothing if `tbs` is null.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_tbs_request_free(tbs: *mut TBSRequest<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(tbs) }
    }

    /// Writes the unsigned request of `tbs` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_request_new(tbs: *const TBSRequest<'static>, out: *mut *mut OCSPRequest<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let tbs = unsafe { Pointer::reference(tbs) }?;
            let request = OCSPRequest::new(tbs.clone()).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, request) }
        })())
    }

    /// Writes the request of `tbs` signed by `key` with `algorithm`, with the certificates
    /// `certificates` (null for none), drawing from `random`, into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_request_sign(tbs: *const TBSRequest<'static>, key: *const PrivateKey, algorithm: *const SignatureAlgorithm, certificates: *const Vec<Certificate<'static>>, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut OCSPRequest<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles (or a null list), a generator of the named type and a writable pointer.
            let tbs = unsafe { Pointer::reference(tbs) }?;
            let key = unsafe { Pointer::reference(key) }?;
            let algorithm = unsafe { Pointer::reference(algorithm) }?;
            let certificates = unsafe { OCSPStatus::certificates(certificates) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let request = OCSPRequest::sign(tbs.clone(), key, algorithm, certificates, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, request) }
        })())
    }

    /// Writes the request of the DER of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_request_from_der(data: *const u8, length: usize, out: *mut *mut OCSPRequest<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let request = OCSPRequest::from_der(data).map_err(|error| error.to_status())?.into_owned();
            unsafe { Pointer::write_handle(out, request) }
        })())
    }

    /// Writes the DER of the request into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_request_to_der(request: *const OCSPRequest<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let request = unsafe { Pointer::reference(request) }?;
            let der = request.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Writes the number of certificates the request asks about into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_request_count(request: *const OCSPRequest<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let request = unsafe { Pointer::reference(request) }?;
            unsafe { Pointer::write(out, request.tbs_request().requests.len()) }
        })())
    }

    /// Writes the identifier of the certificate at `index` the request asks about into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_request_cert_id(request: *const OCSPRequest<'static>, index: usize, out: *mut *mut CertID<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let request = unsafe { Pointer::reference(request) }?;
            let single = request.tbs_request().requests.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, single.cert_id.clone()) }
        })())
    }

    /// Writes whether the request has a requestor's name into `out_has` and, if it has, its general
    /// name (see x509) into `out_kind` and `out` (0 and empty otherwise).
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_request_requestor_name(request: *const OCSPRequest<'static>, out_has: *mut bool, out_kind: *mut u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            if out_has.is_null() || out_kind.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a valid handle and writable pointers.
            let request = unsafe { Pointer::reference(request) }?;
            let name = request.tbs_request().requestor_name.as_ref();
            unsafe { Pointer::write(out_has, name.is_some()) }?;
            unsafe { Pointer::write(out_kind, name.map_or(0, |name| name.tag_number() as u8)) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(name.map(X509Status::general_name_data).unwrap_or_default())) }
        })())
    }

    /// Writes whether the request has a nonce into `out_has` and, if it has, the nonce into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_request_nonce(request: *const OCSPRequest<'static>, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let request = unsafe { Pointer::reference(request) }?;
            unsafe { OCSPStatus::write_nonce(&request.tbs_request().extensions, out_has, out) }
        })())
    }

    /// Writes whether the request is signed into `out_signed` and, if it is, whether it has a list
    /// of certificates into `out_has` and a copy of the list into `out` (empty otherwise).
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_request_certificates(request: *const OCSPRequest<'static>, out_signed: *mut bool, out_has: *mut bool, out: *mut *mut Vec<Certificate<'static>>) -> *const Status {
        Status::from_result((|| {
            if out_signed.is_null() || out_has.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a valid handle and writable pointers.
            let request = unsafe { Pointer::reference(request) }?;
            let certificates = request.signature().and_then(|signature| signature.certificates.clone());
            unsafe { Pointer::write(out_signed, request.signature().is_some()) }?;
            unsafe { Pointer::write(out_has, certificates.is_some()) }?;
            unsafe { Pointer::write_handle(out, certificates.unwrap_or_default()) }
        })())
    }

    /// Succeeds if the request is signed and its signature verifies under `key`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_request_verify(request: *const OCSPRequest<'static>, key: *const PublicKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let request = unsafe { Pointer::reference(request) }?;
            let key = unsafe { Pointer::reference(key) }?;
            request.verify(key).map_err(|error| error.to_status())
        })())
    }

    /// Releases a request. Does nothing if `request` is null.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_request_free(request: *mut OCSPRequest<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(request) }
    }

    /// Writes the status of the certificate `cert_id` names into `out`: the status `kind` (with the
    /// revocation time `revocation_time` and the reason `reason` when revoked), current from
    /// `this_update` to `next_update` (if `has_next_update`), with the extensions `extensions`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_single_response_new(cert_id: *const CertID<'static>, kind: u8, revocation_time: i64, reason: u8, this_update: i64, has_next_update: bool, next_update: i64, extensions: *const Extensions<'static>, out: *mut *mut SingleResponse<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let cert_id = unsafe { Pointer::reference(cert_id) }?;
            let extensions = unsafe { Pointer::reference(extensions) }?;
            let single = SingleResponse {
                cert_id: cert_id.clone(),
                status: CertStatusKind::decode(kind, revocation_time, reason)?,
                this_update: OCSPStatus::time(this_update)?,
                next_update: if has_next_update { Some(OCSPStatus::time(next_update)?) } else { None },
                extensions: extensions.clone(),
            };
            unsafe { Pointer::write_handle(out, single) }
        })())
    }

    /// Writes the identifier of the certificate into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_single_response_cert_id(single: *const SingleResponse<'static>, out: *mut *mut CertID<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let single = unsafe { Pointer::reference(single) }?;
            unsafe { Pointer::write_handle(out, single.cert_id.clone()) }
        })())
    }

    /// Writes the status kind into `out_kind` and, when revoked, the revocation time and the reason
    /// (255 for none) into `out_time` and `out_reason` (0 and 255 otherwise).
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_single_response_status(single: *const SingleResponse<'static>, out_kind: *mut u8, out_time: *mut i64, out_reason: *mut u8) -> *const Status {
        Status::from_result((|| {
            if out_kind.is_null() || out_time.is_null() || out_reason.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a valid handle and writable pointers.
            let single = unsafe { Pointer::reference(single) }?;
            let (kind, time, reason) = CertStatusKind::encode(&single.status);
            unsafe { Pointer::write(out_kind, kind) }?;
            unsafe { Pointer::write(out_time, time) }?;
            unsafe { Pointer::write(out_reason, reason) }
        })())
    }

    /// Writes `thisUpdate` into `out_this_update`, whether there is a `nextUpdate` into
    /// `out_has_next_update` and the `nextUpdate` (0 without one) into `out_next_update`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_single_response_updates(single: *const SingleResponse<'static>, out_this_update: *mut i64, out_has_next_update: *mut bool, out_next_update: *mut i64) -> *const Status {
        Status::from_result((|| {
            if out_this_update.is_null() || out_has_next_update.is_null() || out_next_update.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a valid handle and writable pointers.
            let single = unsafe { Pointer::reference(single) }?;
            unsafe { Pointer::write(out_this_update, single.this_update.to_unix_seconds()) }?;
            unsafe { Pointer::write(out_has_next_update, single.next_update.is_some()) }?;
            unsafe { Pointer::write(out_next_update, single.next_update.map_or(0, |next| next.to_unix_seconds())) }
        })())
    }

    /// Writes a copy of the extensions into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_single_response_extensions(single: *const SingleResponse<'static>, out: *mut *mut Extensions<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let single = unsafe { Pointer::reference(single) }?;
            unsafe { Pointer::write_handle(out, single.extensions.clone()) }
        })())
    }

    /// Releases a status. Does nothing if `single` is null.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_single_response_free(single: *mut SingleResponse<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(single) }
    }

    /// Writes the fields of a response produced at `produced_at` by the responder of the name `name`
    /// into `out`, without statuses or extensions.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_response_data_new_by_name(name: *const Name<'static>, produced_at: i64, out: *mut *mut ResponseData<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let name = unsafe { Pointer::reference(name) }?;
            let data = ResponseData {
                responder_id: ResponderID::ByName(name.clone()),
                produced_at: OCSPStatus::time(produced_at)?,
                responses: Vec::new(),
                extensions: Extensions::new(),
            };
            unsafe { Pointer::write_handle(out, data) }
        })())
    }

    /// Writes the fields of a response produced at `produced_at` by the responder of the key `key`
    /// (named by the SHA-1 hash of its key) into `out`, without statuses or extensions.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_response_data_new_by_key(key: *const PublicKey, produced_at: i64, out: *mut *mut ResponseData<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let key = unsafe { Pointer::reference(key) }?;
            let data = ResponseData {
                responder_id: ResponderID::by_key(key.key()),
                produced_at: OCSPStatus::time(produced_at)?,
                responses: Vec::new(),
                extensions: Extensions::new(),
            };
            unsafe { Pointer::write_handle(out, data) }
        })())
    }

    /// Appends a copy of the status `single`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_response_data_push(data: *mut ResponseData<'static>, single: *const SingleResponse<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let data = unsafe { Pointer::reference_mut(data) }?;
            let single = unsafe { Pointer::reference(single) }?;
            data.responses.push(single.clone());
            Ok(())
        })())
    }

    /// Sets the nonce of `length` bytes at `nonce` (that of the request answered).
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_response_data_set_nonce(data: *mut ResponseData<'static>, nonce: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let data = unsafe { Pointer::reference_mut(data) }?;
            let nonce = unsafe { Pointer::slice(nonce, length) }?;
            OCSPStatus::set_nonce(&mut data.extensions, nonce)
        })())
    }

    /// Writes the basic response of the fields signed by `key` with `algorithm`, with the
    /// certificates `certificates` (null for none), drawing from `random`, into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_response_data_sign(data: *const ResponseData<'static>, key: *const PrivateKey, algorithm: *const SignatureAlgorithm, certificates: *const Vec<Certificate<'static>>, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut BasicOCSPResponse<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles (or a null list), a generator of the named type and a writable pointer.
            let data = unsafe { Pointer::reference(data) }?;
            let key = unsafe { Pointer::reference(key) }?;
            let algorithm = unsafe { Pointer::reference(algorithm) }?;
            let certificates = unsafe { OCSPStatus::certificates(certificates) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let response = data.sign(key, algorithm, certificates, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, response) }
        })())
    }

    /// Releases the fields of a response. Does nothing if `data` is null.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_response_data_free(data: *mut ResponseData<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(data) }
    }

    /// Writes the basic response of the DER of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_basic_ocsp_response_from_der(data: *const u8, length: usize, out: *mut *mut BasicOCSPResponse<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let response = BasicOCSPResponse::from_der(data).map_err(|error| error.to_status())?.into_owned();
            unsafe { Pointer::write_handle(out, response) }
        })())
    }

    /// Writes the DER of the basic response into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_basic_ocsp_response_to_der(response: *const BasicOCSPResponse<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let response = unsafe { Pointer::reference(response) }?;
            let der = response.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Writes whether the responder is named by key into `out_by_key` and the DER of its name, or
    /// the SHA-1 hash of its key, into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_basic_ocsp_response_responder_id(response: *const BasicOCSPResponse<'static>, out_by_key: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            if out_by_key.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a valid handle and writable pointers.
            let response = unsafe { Pointer::reference(response) }?;
            let (by_key, bytes) = match &response.tbs_response_data().responder_id {
                ResponderID::ByName(name) => (false, name.as_der().to_vec()),
                ResponderID::ByKey(hash) => (true, hash.to_vec()),
            };
            unsafe { Pointer::write(out_by_key, by_key) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }

    /// Writes the time the response was produced at into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_basic_ocsp_response_produced_at(response: *const BasicOCSPResponse<'static>, out: *mut i64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let response = unsafe { Pointer::reference(response) }?;
            unsafe { Pointer::write(out, response.tbs_response_data().produced_at.to_unix_seconds()) }
        })())
    }

    /// Writes the number of statuses into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_basic_ocsp_response_count(response: *const BasicOCSPResponse<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let response = unsafe { Pointer::reference(response) }?;
            unsafe { Pointer::write(out, response.tbs_response_data().responses.len()) }
        })())
    }

    /// Writes a copy of the status at `index` into `out`, unchecked.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_basic_ocsp_response_get(response: *const BasicOCSPResponse<'static>, index: usize, out: *mut *mut SingleResponse<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let response = unsafe { Pointer::reference(response) }?;
            let single = response.tbs_response_data().responses.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, single.clone()) }
        })())
    }

    /// Writes a copy of the response extensions into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_basic_ocsp_response_extensions(response: *const BasicOCSPResponse<'static>, out: *mut *mut Extensions<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let response = unsafe { Pointer::reference(response) }?;
            unsafe { Pointer::write_handle(out, response.tbs_response_data().extensions.clone()) }
        })())
    }

    /// Writes whether the response has a nonce into `out_has` and, if it has, the nonce into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_basic_ocsp_response_nonce(response: *const BasicOCSPResponse<'static>, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let response = unsafe { Pointer::reference(response) }?;
            unsafe { OCSPStatus::write_nonce(&response.tbs_response_data().extensions, out_has, out) }
        })())
    }

    /// Writes a copy of the certificates of the response (empty without the field) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_basic_ocsp_response_certificates(response: *const BasicOCSPResponse<'static>, out: *mut *mut Vec<Certificate<'static>>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let response = unsafe { Pointer::reference(response) }?;
            unsafe { Pointer::write_handle(out, response.certificates().to_vec()) }
        })())
    }

    /// Writes the DER `AlgorithmIdentifier` of the signature algorithm into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_basic_ocsp_response_signature_algorithm(response: *const BasicOCSPResponse<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let response = unsafe { Pointer::reference(response) }?;
            let der = response.signature_algorithm().to_der().map_err(|error| OCSPError::from(error).to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Writes the key that signed the response into `out`, if it may answer for the certificates of
    /// the CA of the name `issuer_name` and the key `issuer_key` under `config` (RFC 6960 4.2.2.2).
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_basic_ocsp_response_signer(response: *const BasicOCSPResponse<'static>, issuer_name: *const Name<'static>, issuer_key: *const PublicKey, config: *const OCSPConfig, out: *mut *mut PublicKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let response = unsafe { Pointer::reference(response) }?;
            let issuer_name = unsafe { Pointer::reference(issuer_name) }?;
            let issuer_key = unsafe { Pointer::reference(issuer_key) }?;
            let config = unsafe { Pointer::reference(config) }?;
            let signer = response.signer(issuer_name, issuer_key, config).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, signer) }
        })())
    }

    /// Writes a copy of the status of the certificate `cert_id` names into `out`, after checking the
    /// response as RFC 6960 section 3.2 requires, for the CA of the name `issuer_name` and the key
    /// `issuer_key`, under `config`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_basic_ocsp_response_verify(response: *const BasicOCSPResponse<'static>, cert_id: *const CertID<'static>, issuer_name: *const Name<'static>, issuer_key: *const PublicKey, config: *const OCSPConfig, out: *mut *mut SingleResponse<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let response = unsafe { Pointer::reference(response) }?;
            let cert_id = unsafe { Pointer::reference(cert_id) }?;
            let issuer_name = unsafe { Pointer::reference(issuer_name) }?;
            let issuer_key = unsafe { Pointer::reference(issuer_key) }?;
            let config = unsafe { Pointer::reference(config) }?;
            let single = response.verify(cert_id, issuer_name, issuer_key, config).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, single.clone()) }
        })())
    }

    /// Releases a basic response. Does nothing if `response` is null.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_basic_ocsp_response_free(response: *mut BasicOCSPResponse<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(response) }
    }

    /// Writes the response of the status `status` (an `OCSPResponseStatus` code) into `out`, with a
    /// copy of the basic response `basic` if successful (null otherwise).
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_response_new(status: u8, basic: *const BasicOCSPResponse<'static>, out: *mut *mut OCSPResponse<'static>) -> *const Status {
        Status::from_result((|| {
            let status = OCSPResponseStatus::from_code(status as i128).ok_or(&Status::INVALID_ARGUMENT)?;
            let response = if basic.is_null() {
                None
            } else {
                // SAFETY: the caller passes a valid handle.
                Some(unsafe { Pointer::reference(basic) }?.clone())
            };
            if (status == OCSPResponseStatus::Successful) != response.is_some() {
                return Err(&OCSPStatus::RESPONSE_TYPE);
            }
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, OCSPResponse { status, response }) }
        })())
    }

    /// Writes the response of the DER of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_response_from_der(data: *const u8, length: usize, out: *mut *mut OCSPResponse<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let response = OCSPResponse::from_der(data).map_err(|error| error.to_status())?.into_owned();
            unsafe { Pointer::write_handle(out, response) }
        })())
    }

    /// Writes the DER of the response into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_response_to_der(response: *const OCSPResponse<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let response = unsafe { Pointer::reference(response) }?;
            let der = response.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Writes the code of the response status into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_response_status(response: *const OCSPResponse<'static>, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let response = unsafe { Pointer::reference(response) }?;
            unsafe { Pointer::write(out, response.status as u8) }
        })())
    }

    /// Writes a copy of the basic response of a successful response into `out`; fails with `Status` otherwise.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_response_basic(response: *const OCSPResponse<'static>, out: *mut *mut BasicOCSPResponse<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let response = unsafe { Pointer::reference(response) }?;
            let basic = response.basic().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, basic.clone()) }
        })())
    }

    /// Releases a response. Does nothing if `response` is null.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_response_free(response: *mut OCSPResponse<'static>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(response) }
    }
}

#[cfg(umilib_feature = "auth-cert-path")]
crate::ffi_functions! {
    const SOURCES;

    /// Appends a copy of the basic response to the revocation sources `sources` of path validation.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_basic_ocsp_response_add_to(response: *const BasicOCSPResponse<'static>, sources: *mut crate::ffi::auth::cert::path::RevocationSources) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let response = unsafe { Pointer::reference(response) }?;
            let sources = unsafe { Pointer::reference_mut(sources) }?;
            sources.sources.push(alloc::boxed::Box::new(response.clone()));
            Ok(())
        })())
    }

    /// Appends a copy of the response to the revocation sources `sources` of path validation.
    pub unsafe extern "C" fn umilib_auth_cert_ocsp_ocsp_response_add_to(response: *const OCSPResponse<'static>, sources: *mut crate::ffi::auth::cert::path::RevocationSources) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let response = unsafe { Pointer::reference(response) }?;
            let sources = unsafe { Pointer::reference_mut(sources) }?;
            sources.sources.push(alloc::boxed::Box::new(response.clone()));
            Ok(())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ocsp",
    definitions: &[
        Definition::Opaque { name: "umilib_auth_cert_ocsp_CertID", documentation: " The identifier of a certificate." },
        Definition::Opaque {
            name: "umilib_auth_cert_ocsp_OCSPConfig",
            documentation: " The inputs of the checks of a response.",
        },
        Definition::Opaque { name: "umilib_auth_cert_ocsp_TBSRequest", documentation: " The fields of a request." },
        Definition::Opaque { name: "umilib_auth_cert_ocsp_OCSPRequest", documentation: " An OCSP request." },
        Definition::Opaque {
            name: "umilib_auth_cert_ocsp_SingleResponse",
            documentation: " The status of one certificate in a response.",
        },
        Definition::Opaque {
            name: "umilib_auth_cert_ocsp_ResponseData",
            documentation: " The signed fields of a basic response.",
        },
        Definition::Opaque { name: "umilib_auth_cert_ocsp_BasicOCSPResponse", documentation: " A basic response." },
        Definition::Opaque { name: "umilib_auth_cert_ocsp_OCSPResponse", documentation: " An OCSP response." },
    ],
    #[cfg(umilib_feature = "auth-cert-path")]
    functions: &crate::ffi::Function::concat::<{ FUNCTIONS.len() + SOURCES.len() }>(&[FUNCTIONS, SOURCES]),
    #[cfg(not(umilib_feature = "auth-cert-path"))]
    functions: FUNCTIONS,
    modules: &[],
};
