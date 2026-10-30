//! The C ABI of [`crate::protocol::jwt`].
//!
//! Headers, keys, key sets, configurations, JWS, JWE, claims, validations
//! and JWTs are handles; JSON values are the handles of
//! [`crate::ffi::codec::json`], keys of certificates those of
//! [`crate::ffi::auth::cert::key`]. Algorithms cross as their index in
//! [`JWSAlgorithm::ALL`], [`JWEAlgorithm::ALL`] and [`JWEEncryption::ALL`],
//! hash functions as their index in [`HashAlgorithm::ALL`]. Texts (JSON,
//! serializations, names) are UTF-8, written into buffers. A recipient of a
//! JWE or a signature of a JWS is named by its index. A header or a JWE AAD
//! passed as null is absent.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::c_void;

use crate::auth::cert::key::{HashAlgorithm, PrivateKey, PublicKey};
use crate::codec::json::JSONValue;
use crate::ffi::auth::cert::key::KeyStatus;
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::jwt::{
    JOSEHeader, JWE, JWEAlgorithm, JWEConfig, JWEEncryption, JWK, JWKSet, JWS, JWSAlgorithm, JWSConfig, JWT, JWTClaims,
    JWTError, JWTValidation,
};

/// The statuses of this module, one per variant of [`JWTError`] (JSON, key
/// and cryptographic errors keep those of their modules).
pub struct JWTStatus;

impl JWTStatus {
    pub const BASE64: Status = Status::new(c"protocol.jwt", c"Base64", c"not canonical base64url without padding");
    pub const FORMAT: Status = Status::new(c"protocol.jwt", c"Format", c"a malformed serialization, JWK or JWK Set");
    pub const HEADER: Status =
        Status::new(c"protocol.jwt", c"Header", c"a header parameter missing, misplaced or of another type");
    pub const UNKNOWN_ALGORITHM: Status =
        Status::new(c"protocol.jwt", c"UnknownAlgorithm", c"an algorithm this library does not implement");
    pub const UNKNOWN_KEY_TYPE: Status =
        Status::new(c"protocol.jwt", c"UnknownKeyType", c"a key type or curve this library does not know");
    pub const ALGORITHM_NOT_ALLOWED: Status =
        Status::new(c"protocol.jwt", c"AlgorithmNotAllowed", c"an algorithm the configuration does not allow");
    pub const KEY_MISMATCH: Status =
        Status::new(c"protocol.jwt", c"KeyMismatch", c"a key that does not fit the algorithm or the operation");
    pub const CRITICAL: Status =
        Status::new(c"protocol.jwt", c"Critical", c"a critical header parameter not understood");
    pub const SIGNATURE: Status = Status::new(c"protocol.jwt", c"Signature", c"no signature verifies");
    pub const DECRYPTION: Status = Status::new(c"protocol.jwt", c"Decryption", c"the JWE does not decrypt");
    pub const COMPRESSION: Status =
        Status::new(c"protocol.jwt", c"Compression", c"compression refused or beyond the limit");
    pub const LIMIT: Status = Status::new(c"protocol.jwt", c"Limit", c"more signatures or recipients than the limit");
    pub const EXPIRED: Status = Status::new(c"protocol.jwt", c"Expired", c"the JWT has expired");
    pub const NOT_YET_VALID: Status = Status::new(c"protocol.jwt", c"NotYetValid", c"the JWT is not valid yet");
    pub const ISSUER: Status = Status::new(c"protocol.jwt", c"Issuer", c"the issuer is not the one expected");
    pub const AUDIENCE: Status =
        Status::new(c"protocol.jwt", c"Audience", c"the audience does not hold the one expected");
    pub const SUBJECT: Status = Status::new(c"protocol.jwt", c"Subject", c"the subject is not the one expected");
    pub const TYPE: Status = Status::new(c"protocol.jwt", c"Type", c"the type is not the one expected");
    pub const MISSING_CLAIM: Status = Status::new(c"protocol.jwt", c"MissingClaim", c"a required claim is missing");
    pub const INVALID_CLAIM: Status =
        Status::new(c"protocol.jwt", c"InvalidClaim", c"a claim of another type than its definition");

    /// The algorithms of the `count` indices at `indices` in `all`.
    ///
    /// # Safety
    /// `indices` is readable for `count` bytes.
    pub unsafe fn algorithms<T: Copy>(all: &[T], indices: *const u8, count: usize) -> Result<Vec<T>, &'static Status> {
        // SAFETY: the caller passes readable bytes.
        let indices = unsafe { Pointer::slice(indices, count) }?;
        indices.iter().map(|&index| KeyStatus::index(all, index)).collect()
    }
}

impl ToStatus for JWTError {
    fn to_status(&self) -> &'static Status {
        match *self {
            JWTError::Base64 => &JWTStatus::BASE64,
            JWTError::JSON(error) => error.to_status(),
            JWTError::Key(error) => error.to_status(),
            JWTError::Crypto(error) => error.to_status(),
            JWTError::Format => &JWTStatus::FORMAT,
            JWTError::Header => &JWTStatus::HEADER,
            JWTError::UnknownAlgorithm => &JWTStatus::UNKNOWN_ALGORITHM,
            JWTError::UnknownKeyType => &JWTStatus::UNKNOWN_KEY_TYPE,
            JWTError::AlgorithmNotAllowed => &JWTStatus::ALGORITHM_NOT_ALLOWED,
            JWTError::KeyMismatch => &JWTStatus::KEY_MISMATCH,
            JWTError::Critical => &JWTStatus::CRITICAL,
            JWTError::Signature => &JWTStatus::SIGNATURE,
            JWTError::Decryption => &JWTStatus::DECRYPTION,
            JWTError::Compression => &JWTStatus::COMPRESSION,
            JWTError::Limit => &JWTStatus::LIMIT,
            JWTError::Expired => &JWTStatus::EXPIRED,
            JWTError::NotYetValid => &JWTStatus::NOT_YET_VALID,
            JWTError::Issuer => &JWTStatus::ISSUER,
            JWTError::Audience => &JWTStatus::AUDIENCE,
            JWTError::Subject => &JWTStatus::SUBJECT,
            JWTError::Type => &JWTStatus::TYPE,
            JWTError::MissingClaim => &JWTStatus::MISSING_CLAIM,
            JWTError::InvalidClaim => &JWTStatus::INVALID_CLAIM,
        }
    }
}

impl Value for JOSEHeader {
    const TYPE: Type = Type::Named("umilib_protocol_jwt_JOSEHeader");
}

impl Value for JWK {
    const TYPE: Type = Type::Named("umilib_protocol_jwt_JWK");
}

impl Value for JWKSet {
    const TYPE: Type = Type::Named("umilib_protocol_jwt_JWKSet");
}

impl Value for JWSConfig {
    const TYPE: Type = Type::Named("umilib_protocol_jwt_JWSConfig");
}

impl Value for JWS {
    const TYPE: Type = Type::Named("umilib_protocol_jwt_JWS");
}

impl Value for JWEConfig {
    const TYPE: Type = Type::Named("umilib_protocol_jwt_JWEConfig");
}

impl Value for JWE {
    const TYPE: Type = Type::Named("umilib_protocol_jwt_JWE");
}

impl Value for JWTClaims {
    const TYPE: Type = Type::Named("umilib_protocol_jwt_JWTClaims");
}

impl Value for JWTValidation {
    const TYPE: Type = Type::Named("umilib_protocol_jwt_JWTValidation");
}

impl Value for JWT {
    const TYPE: Type = Type::Named("umilib_protocol_jwt_JWT");
}

crate::ffi_functions! {
    /// Writes an empty header into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jose_header_new(out: *mut *mut JOSEHeader) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, JOSEHeader::new()) })
    }

    /// Writes the header of the JSON text at `data`, an object without duplicate parameters, into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jose_header_decode(data: *const u8, length: usize, out: *mut *mut JOSEHeader) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let header = JOSEHeader::decode(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, header) }
        })())
    }

    /// Writes the JSON text of the header into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jose_header_encode(header: *const JOSEHeader, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let header = unsafe { Pointer::reference(header) }?;
            unsafe { Pointer::write_text(out, header.encode()) }
        })())
    }

    /// Writes whether the parameter named by the UTF-8 text at `name` is present into `out_found` and,
    /// if so, a copy of its value into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jose_header_get(header: *const JOSEHeader, name: *const u8, name_length: usize, out_found: *mut bool, out: *mut *mut JSONValue) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(name, name_length)], &[Pointer::range(out_found, 1)])?;
            // SAFETY: the caller passes a valid handle, readable text and writable pointers.
            let header = unsafe { Pointer::reference(header) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            let value = header.get(name);
            unsafe { Pointer::write(out_found, value.is_some()) }?;
            match value {
                Some(value) => unsafe { Pointer::write_handle(out, value.clone()) },
                None => Ok(()),
            }
        })())
    }

    /// Sets the parameter named by the UTF-8 text at `name` to a copy of `value`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jose_header_set(header: *mut JOSEHeader, name: *const u8, name_length: usize, value: *const JSONValue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and readable text.
            let header = unsafe { Pointer::reference_mut(header) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            let value = unsafe { Pointer::reference(value) }?;
            header.set(name, value.clone());
            Ok(())
        })())
    }

    /// Sets the parameter named by the UTF-8 text at `name` to the string at `value`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jose_header_set_string(header: *mut JOSEHeader, name: *const u8, name_length: usize, value: *const u8, value_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let header = unsafe { Pointer::reference_mut(header) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            let value = unsafe { Pointer::text(value, value_length) }?;
            header.set_string(name, value);
            Ok(())
        })())
    }

    /// Removes the parameter named by the UTF-8 text at `name`; writes whether it was present into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jose_header_remove(header: *mut JOSEHeader, name: *const u8, name_length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(name, name_length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable text and a writable pointer.
            let header = unsafe { Pointer::reference_mut(header) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            let removed = header.remove(name).is_some();
            unsafe { Pointer::write(out, removed) }
        })())
    }

    /// Writes a copy of the header into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jose_header_clone(header: *const JOSEHeader, out: *mut *mut JOSEHeader) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let header = unsafe { Pointer::reference(header) }?;
            unsafe { Pointer::write_handle(out, header.clone()) }
        })())
    }

    /// Releases a header. Does nothing if `header` is null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jose_header_free(header: *mut JOSEHeader) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(header) }
    }

    /// Writes the JWK of the JSON text at `data` (RFC 7517 §4, checked) into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_from_json(data: *const u8, length: usize, out: *mut *mut JWK) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let jwk = JWK::from_json(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, jwk) }
        })())
    }

    /// Writes the JSON text of the JWK into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_to_json(jwk: *const JWK, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let jwk = unsafe { Pointer::reference(jwk) }?;
            unsafe { Pointer::write_text(out, jwk.to_json()) }
        })())
    }

    /// Writes the symmetric (`oct`) JWK of the `length` bytes at `k` into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_symmetric(k: *const u8, length: usize, out: *mut *mut JWK) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let k = unsafe { Pointer::slice(k, length) }?;
            unsafe { Pointer::write_handle(out, JWK::symmetric(k)) }
        })())
    }

    /// Writes the JWK without its private parameters into `out`; fails with KeyMismatch for a symmetric key.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_to_public(jwk: *const JWK, out: *mut *mut JWK) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let jwk = unsafe { Pointer::reference(jwk) }?;
            let public = jwk.to_public().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, public) }
        })())
    }

    /// Writes whether the JWK holds secret material (a symmetric key or private parameters) into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_is_secret(jwk: *const JWK, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let jwk = unsafe { Pointer::reference(jwk) }?;
            unsafe { Pointer::write(out, jwk.key.is_secret()) }
        })())
    }

    /// Writes the key type (`kty`) of the JWK into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_key_type(jwk: *const JWK, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let jwk = unsafe { Pointer::reference(jwk) }?;
            unsafe { Pointer::write_text(out, jwk.key.type_name().to_string()) }
        })())
    }

    /// Writes the `kid` of the JWK, if any, into `out_has` and `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_key_id(jwk: *const JWK, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let jwk = unsafe { Pointer::reference(jwk) }?;
            unsafe { Pointer::write_optional_text(out_has, out, jwk.key_id.as_deref()) }
        })())
    }

    /// Sets the `kid` of the JWK to the UTF-8 text at `key_id`, or removes it for null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_set_key_id(jwk: *mut JWK, key_id: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and null or readable text.
            let jwk = unsafe { Pointer::reference_mut(jwk) }?;
            jwk.key_id = unsafe { Pointer::optional_text(key_id, length).map(|text| text.map(String::from)) }?;
            Ok(())
        })())
    }

    /// Writes the `alg` of the JWK, if any, into `out_has` and `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_algorithm(jwk: *const JWK, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let jwk = unsafe { Pointer::reference(jwk) }?;
            unsafe { Pointer::write_optional_text(out_has, out, jwk.algorithm.as_deref()) }
        })())
    }

    /// Sets the `alg` of the JWK to the UTF-8 text at `algorithm`, or removes it for null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_set_algorithm(jwk: *mut JWK, algorithm: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and null or readable text.
            let jwk = unsafe { Pointer::reference_mut(jwk) }?;
            jwk.algorithm = unsafe { Pointer::optional_text(algorithm, length).map(|text| text.map(String::from)) }?;
            Ok(())
        })())
    }

    /// Writes the `use` of the JWK, if any, into `out_has` and `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_key_use(jwk: *const JWK, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let jwk = unsafe { Pointer::reference(jwk) }?;
            unsafe { Pointer::write_optional_text(out_has, out, jwk.key_use.as_deref()) }
        })())
    }

    /// Sets the `use` of the JWK to the UTF-8 text at `key_use`, or removes it for null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_set_key_use(jwk: *mut JWK, key_use: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and null or readable text.
            let jwk = unsafe { Pointer::reference_mut(jwk) }?;
            jwk.key_use = unsafe { Pointer::optional_text(key_use, length).map(|text| text.map(String::from)) }?;
            Ok(())
        })())
    }

    /// Checks the rules of RFC 7517 the JWK must follow (consistent `use` and `key_ops`, private
    /// parameters of its public key, an `x5c` of its key).
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_check(jwk: *const JWK) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let jwk = unsafe { Pointer::reference(jwk) }?;
            jwk.check().map_err(|error| error.to_status())
        })())
    }

    /// Writes the thumbprint (RFC 7638) of the JWK with the hash function `hash` into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_thumbprint(jwk: *const JWK, hash: u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let jwk = unsafe { Pointer::reference(jwk) }?;
            let hash = KeyStatus::index(&HashAlgorithm::ALL, hash)?;
            let thumbprint = jwk.thumbprint(hash).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(thumbprint)) }
        })())
    }

    /// Writes the thumbprint URI (RFC 9278) of the JWK with the hash function `hash` into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_thumbprint_uri(jwk: *const JWK, hash: u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let jwk = unsafe { Pointer::reference(jwk) }?;
            let hash = KeyStatus::index(&HashAlgorithm::ALL, hash)?;
            let uri = jwk.thumbprint_uri(hash).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, uri) }
        })())
    }

    /// Writes the public key of the JWK into `out`; fails with KeyMismatch for a symmetric key.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_public_key(jwk: *const JWK, out: *mut *mut PublicKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let jwk = unsafe { Pointer::reference(jwk) }?;
            let key = jwk.public_key().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Writes the private key of the JWK into `out`; fails with KeyMismatch for a public or symmetric key.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_private_key(jwk: *const JWK, out: *mut *mut PrivateKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let jwk = unsafe { Pointer::reference(jwk) }?;
            let key = jwk.private_key().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Writes the JWK of the public key `key` into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_from_public_key(key: *const PublicKey, out: *mut *mut JWK) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let key = unsafe { Pointer::reference(key) }?;
            let jwk = JWK::from_public_key(key).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, jwk) }
        })())
    }

    /// Writes the JWK of the private key `key`, with its private parameters, into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_from_private_key(key: *const PrivateKey, out: *mut *mut JWK) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let key = unsafe { Pointer::reference(key) }?;
            let jwk = JWK::from_private_key(key).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, jwk) }
        })())
    }

    /// Writes a copy of the JWK into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_clone(jwk: *const JWK, out: *mut *mut JWK) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let jwk = unsafe { Pointer::reference(jwk) }?;
            unsafe { Pointer::write_handle(out, jwk.clone()) }
        })())
    }

    /// Releases a JWK, zeroizing its secret parameters. Does nothing if `jwk` is null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_free(jwk: *mut JWK) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(jwk) }
    }

    /// Writes the JWK Set of the JSON text at `data` (RFC 7517 §5; keys of unknown types are skipped) into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_set_from_json(data: *const u8, length: usize, out: *mut *mut JWKSet) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let set = JWKSet::from_json(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, set) }
        })())
    }

    /// Writes the JSON text of the JWK Set into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_set_to_json(set: *const JWKSet, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let set = unsafe { Pointer::reference(set) }?;
            unsafe { Pointer::write_text(out, set.to_json()) }
        })())
    }

    /// Writes the number of keys of the set into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_set_len(set: *const JWKSet, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let set = unsafe { Pointer::reference(set) }?;
            unsafe { Pointer::write(out, set.keys.len()) }
        })())
    }

    /// Writes a copy of the key at `index` of the set into `out`; InvalidArgument past the end.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_set_key(set: *const JWKSet, index: usize, out: *mut *mut JWK) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let set = unsafe { Pointer::reference(set) }?;
            let key = set.keys.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, key.clone()) }
        })())
    }

    /// Appends a copy of `jwk` to the set.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_set_push(set: *mut JWKSet, jwk: *const JWK) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let set = unsafe { Pointer::reference_mut(set) }?;
            let jwk = unsafe { Pointer::reference(jwk) }?;
            set.keys.push(jwk.clone());
            Ok(())
        })())
    }

    /// Writes an empty JWK Set into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_set_new(out: *mut *mut JWKSet) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, JWKSet::default()) })
    }

    /// Releases a JWK Set. Does nothing if `set` is null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwk_set_free(set: *mut JWKSet) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(set) }
    }

    /// Writes the configuration accepting the `count` algorithms of the indices at `algorithms` into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_config_new(algorithms: *const u8, count: usize, out: *mut *mut JWSConfig) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let algorithms = unsafe { JWTStatus::algorithms(&JWSAlgorithm::ALL, algorithms, count) }?;
            unsafe { Pointer::write_handle(out, JWSConfig::new(&algorithms)) }
        })())
    }

    /// Adds the critical header parameter named by the UTF-8 text at `name` to those understood.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_config_understand(config: *mut JWSConfig, name: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let config = unsafe { Pointer::reference_mut(config) }?;
            let name = unsafe { Pointer::text(name, length) }?;
            config.critical.push(name.to_string());
            Ok(())
        })())
    }

    /// Sets the most signatures a JWS may have.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_config_set_maximum_signatures(config: *mut JWSConfig, maximum: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.maximum_signatures = maximum;
            Ok(())
        })())
    }

    /// Releases a configuration. Does nothing if `config` is null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_config_free(config: *mut JWSConfig) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(config) }
    }

    /// Writes a JWS of the `length` bytes at `payload`, without signatures, into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_new(payload: *const u8, length: usize, out: *mut *mut JWS) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let payload = unsafe { Pointer::slice(payload, length) }?;
            unsafe { Pointer::write_handle(out, JWS::new(payload.to_vec())) }
        })())
    }

    /// Writes the payload of the JWS into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_payload(jws: *const JWS, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let jws = unsafe { Pointer::reference(jws) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(jws.payload.clone())) }
        })())
    }

    /// Writes the number of signatures of the JWS into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_signature_count(jws: *const JWS, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let jws = unsafe { Pointer::reference(jws) }?;
            unsafe { Pointer::write(out, jws.signatures.len()) }
        })())
    }

    /// Writes the JOSE Header (the union of its headers) of the signature at `index` into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_signature_header(jws: *const JWS, index: usize, out: *mut *mut JOSEHeader) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let jws = unsafe { Pointer::reference(jws) }?;
            let signature = jws.signatures.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            let header = signature.joined_header().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, header) }
        })())
    }

    /// Adds the signature of the payload with the protected header `protected_header` and the unprotected header
    /// `header` (null for none) under `key`, drawing from `random`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_sign(jws: *mut JWS, protected_header: *const JOSEHeader, header: *const JOSEHeader, key: *const JWK, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles (`header` may be null) and a generator of the named type.
            let jws = unsafe { Pointer::reference_mut(jws) }?;
            let protected_header = unsafe { Pointer::reference(protected_header) }?;
            let header = unsafe { Pointer::optional_reference(header) }?;
            let key = unsafe { Pointer::reference(key) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            jws.sign(protected_header, header, key, &mut random).map_err(|error| error.to_status())
        })())
    }

    /// Verifies the JWS under `key` (RFC 7515 §5.2); writes the index of the signature that verifies into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_verify(jws: *const JWS, key: *const JWK, config: *const JWSConfig, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let jws = unsafe { Pointer::reference(jws) }?;
            let key = unsafe { Pointer::reference(key) }?;
            let config = unsafe { Pointer::reference(config) }?;
            let signature = jws.verify(key, config).map_err(|error| error.to_status())?;
            let index = jws.signatures.iter().position(|other| core::ptr::eq(other, signature)).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, index) }
        })())
    }

    /// Accepts an Unsecured JWS (RFC 7518 §3.6): one signature with the `alg` of `none` and no signature.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_verify_unsecured(jws: *const JWS) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let jws = unsafe { Pointer::reference(jws) }?;
            jws.verify_unsecured().map_err(|error| error.to_status())
        })())
    }

    /// Writes the JWS of the compact serialization at `text` into `out`; with a payload at `payload`
    /// (`has_payload`), that of a serialization with the payload detached.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_from_compact(text: *const u8, length: usize, payload: *const u8, payload_length: usize, has_payload: bool, out: *mut *mut JWS) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let detached = if has_payload { Some(unsafe { Pointer::slice(payload, payload_length) }?) } else { None };
            let jws = JWS::from_compact_parts(text, detached).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, jws) }
        })())
    }

    /// Writes the compact serialization of the JWS, with the payload or `detached`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_to_compact(jws: *const JWS, detached: bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let jws = unsafe { Pointer::reference(jws) }?;
            let text = if detached { jws.to_compact_detached() } else { jws.to_compact() };
            unsafe { Pointer::write_text(out, text.map_err(|error| error.to_status())?) }
        })())
    }

    /// Writes the JWS of the JSON serialization at `data` (general or flattened) into `out`; with a
    /// payload at `payload` (`has_payload`), that of a serialization with the payload detached.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_from_json(data: *const u8, length: usize, payload: *const u8, payload_length: usize, has_payload: bool, out: *mut *mut JWS) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let detached = if has_payload { Some(unsafe { Pointer::slice(payload, payload_length) }?) } else { None };
            let jws = JWS::from_json_parts(data, detached).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, jws) }
        })())
    }

    /// Writes the JSON serialization of the JWS, general or `flattened`, with the payload or `detached`,
    /// into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_to_json(jws: *const JWS, flattened: bool, detached: bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let jws = unsafe { Pointer::reference(jws) }?;
            let object = jws.json_object(flattened, detached).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, JSONValue::Object(object).encode()) }
        })())
    }

    /// Writes a copy of the JWS into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_clone(jws: *const JWS, out: *mut *mut JWS) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let jws = unsafe { Pointer::reference(jws) }?;
            unsafe { Pointer::write_handle(out, jws.clone()) }
        })())
    }

    /// Releases a JWS. Does nothing if `jws` is null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jws_free(jws: *mut JWS) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(jws) }
    }

    /// Writes the configuration accepting the `algorithm_count` key management algorithms at `algorithms`
    /// and the `encryption_count` content encryption algorithms at `encryptions` (as indices) into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_config_new(algorithms: *const u8, algorithm_count: usize, encryptions: *const u8, encryption_count: usize, out: *mut *mut JWEConfig) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let algorithms = unsafe { JWTStatus::algorithms(&JWEAlgorithm::ALL, algorithms, algorithm_count) }?;
            let encryptions = unsafe { JWTStatus::algorithms(&JWEEncryption::ALL, encryptions, encryption_count) }?;
            unsafe { Pointer::write_handle(out, JWEConfig::new(&algorithms, &encryptions)) }
        })())
    }

    /// Adds the critical header parameter named by the UTF-8 text at `name` to those understood.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_config_understand(config: *mut JWEConfig, name: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let config = unsafe { Pointer::reference_mut(config) }?;
            let name = unsafe { Pointer::text(name, length) }?;
            config.critical.push(name.to_string());
            Ok(())
        })())
    }

    /// Sets the largest PBES2 iteration count accepted (RFC 8725 §3.2).
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_config_set_maximum_pbes2_count(config: *mut JWEConfig, count: u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.maximum_pbes2_count = count;
            Ok(())
        })())
    }

    /// Sets the most recipients a JWE may have.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_config_set_maximum_recipients(config: *mut JWEConfig, maximum: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.maximum_recipients = maximum;
            Ok(())
        })())
    }

    /// Sets whether compressed plaintexts (`zip`) are accepted, and the largest plaintext they decompress to.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_config_set_compression(config: *mut JWEConfig, compression: bool, maximum_decompressed: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.compression = compression;
            config.maximum_decompressed = maximum_decompressed;
            Ok(())
        })())
    }

    /// Releases a configuration. Does nothing if `config` is null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_config_free(config: *mut JWEConfig) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(config) }
    }

    /// Writes the JWE of the `length` bytes at `plaintext` (RFC 7516 §5.1) into `out`: for the `count`
    /// recipients of the keys at `keys` and of the per-recipient headers at `headers` (null, or an array
    /// whose entries may be null), with the headers `protected_header` and `unprotected` (null for none) and the
    /// JWE AAD at `aad` (`has_aad`), drawing from `random`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_encrypt(plaintext: *const u8, length: usize, protected_header: *const JOSEHeader, unprotected: *const JOSEHeader, keys: *const *const JWK, headers: *const *const JOSEHeader, count: usize, aad: *const u8, aad_length: usize, has_aad: bool, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut JWE) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes, valid handles (the optional ones may be null), arrays
            // of `count` handles, a generator of the named type and a writable pointer.
            let plaintext = unsafe { Pointer::slice(plaintext, length) }?;
            let protected_header = unsafe { Pointer::reference(protected_header) }?;
            let unprotected = unsafe { Pointer::optional_reference(unprotected) }?;
            let keys = unsafe { Pointer::slice_of(keys, count) }?;
            let headers = if headers.is_null() { None } else { Some(unsafe { Pointer::slice_of(headers, count) }?) };
            let mut recipients = Vec::with_capacity(count);
            for (index, &key) in keys.iter().enumerate() {
                let key = unsafe { Pointer::reference(key) }?;
                let header = match headers {
                    Some(headers) => unsafe { Pointer::optional_reference(headers[index]) }?.cloned(),
                    None => None,
                };
                recipients.push((key, header));
            }
            let aad = if has_aad { Some(unsafe { Pointer::slice(aad, aad_length) }?) } else { None };
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let jwe = JWE::encrypt(plaintext, protected_header, unprotected, &recipients, aad, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, jwe) }
        })())
    }

    /// Decrypts the JWE with `key` (RFC 7516 §5.2), drawing from `random`: writes the plaintext into `out`
    /// and the index of the recipient it was decrypted for into `out_recipient`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_decrypt(jwe: *const JWE, key: *const JWK, config: *const JWEConfig, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer, out_recipient: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(random_type, random_type_length)],
                &[Pointer::range(out_recipient, 1)],
            )?;
            // SAFETY: the caller passes valid handles, a generator of the named type and writable pointers.
            let jwe = unsafe { Pointer::reference(jwe) }?;
            let key = unsafe { Pointer::reference(key) }?;
            let config = unsafe { Pointer::reference(config) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let (plaintext, recipient) = jwe.decrypt(key, config, &mut random).map_err(|error| error.to_status())?;
            let index = jwe.recipients.iter().position(|other| core::ptr::eq(other, recipient)).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out_recipient, index) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(plaintext)) }
        })())
    }

    /// Writes the number of recipients of the JWE into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_recipient_count(jwe: *const JWE, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let jwe = unsafe { Pointer::reference(jwe) }?;
            unsafe { Pointer::write(out, jwe.recipients.len()) }
        })())
    }

    /// Writes the JOSE Header (the union of the protected, shared and per-recipient headers) of the
    /// recipient at `index` into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_recipient_header(jwe: *const JWE, index: usize, out: *mut *mut JOSEHeader) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let jwe = unsafe { Pointer::reference(jwe) }?;
            let recipient = jwe.recipients.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            let header = jwe.joined_header(recipient).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, header) }
        })())
    }

    /// Writes the JWE of the compact serialization at `text` into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_from_compact(text: *const u8, length: usize, out: *mut *mut JWE) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let jwe = JWE::from_compact(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, jwe) }
        })())
    }

    /// Writes the compact serialization of the JWE into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_to_compact(jwe: *const JWE, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let jwe = unsafe { Pointer::reference(jwe) }?;
            unsafe { Pointer::write_text(out, jwe.to_compact().map_err(|error| error.to_status())?) }
        })())
    }

    /// Writes the JWE of the JSON serialization at `data` (general or flattened) into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_from_json(data: *const u8, length: usize, out: *mut *mut JWE) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let jwe = JWE::from_json(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, jwe) }
        })())
    }

    /// Writes the JSON serialization of the JWE, general or `flattened`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_to_json(jwe: *const JWE, flattened: bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let jwe = unsafe { Pointer::reference(jwe) }?;
            let object = jwe.json_object(flattened).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, JSONValue::Object(object).encode()) }
        })())
    }

    /// Writes a copy of the JWE into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_clone(jwe: *const JWE, out: *mut *mut JWE) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let jwe = unsafe { Pointer::reference(jwe) }?;
            unsafe { Pointer::write_handle(out, jwe.clone()) }
        })())
    }

    /// Releases a JWE. Does nothing if `jwe` is null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwe_free(jwe: *mut JWE) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(jwe) }
    }

    /// Writes an empty claims set into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_claims_new(out: *mut *mut JWTClaims) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, JWTClaims::new()) })
    }

    /// Writes the claims of the JSON text at `data`, an object without duplicate names, into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_claims_decode(data: *const u8, length: usize, out: *mut *mut JWTClaims) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let claims = JWTClaims::decode(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, claims) }
        })())
    }

    /// Writes the JSON text of the claims into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_claims_encode(claims: *const JWTClaims, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let claims = unsafe { Pointer::reference(claims) }?;
            unsafe { Pointer::write_text(out, claims.encode()) }
        })())
    }

    /// Writes whether the claim named by the UTF-8 text at `name` is present into `out_found` and, if so,
    /// a copy of its value into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_claims_get(claims: *const JWTClaims, name: *const u8, name_length: usize, out_found: *mut bool, out: *mut *mut JSONValue) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(name, name_length)], &[Pointer::range(out_found, 1)])?;
            // SAFETY: the caller passes a valid handle, readable text and writable pointers.
            let claims = unsafe { Pointer::reference(claims) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            let value = claims.get(name);
            unsafe { Pointer::write(out_found, value.is_some()) }?;
            match value {
                Some(value) => unsafe { Pointer::write_handle(out, value.clone()) },
                None => Ok(()),
            }
        })())
    }

    /// Sets the claim named by the UTF-8 text at `name` to a copy of `value`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_claims_set(claims: *mut JWTClaims, name: *const u8, name_length: usize, value: *const JSONValue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and readable text.
            let claims = unsafe { Pointer::reference_mut(claims) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            let value = unsafe { Pointer::reference(value) }?;
            claims.set(name, value.clone());
            Ok(())
        })())
    }

    /// Sets the claim named by the UTF-8 text at `name` to the string at `value`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_claims_set_string(claims: *mut JWTClaims, name: *const u8, name_length: usize, value: *const u8, value_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let claims = unsafe { Pointer::reference_mut(claims) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            let value = unsafe { Pointer::text(value, value_length) }?;
            claims.set_string(name, value);
            Ok(())
        })())
    }

    /// Sets the claim named by the UTF-8 text at `name` to the NumericDate `seconds` (RFC 7519 §2).
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_claims_set_numeric_date(claims: *mut JWTClaims, name: *const u8, name_length: usize, seconds: i64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let claims = unsafe { Pointer::reference_mut(claims) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            claims.set_numeric_date(name, seconds);
            Ok(())
        })())
    }

    /// Removes the claim named by the UTF-8 text at `name`; writes whether it was present into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_claims_remove(claims: *mut JWTClaims, name: *const u8, name_length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(name, name_length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable text and a writable pointer.
            let claims = unsafe { Pointer::reference_mut(claims) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            let removed = claims.remove(name).is_some();
            unsafe { Pointer::write(out, removed) }
        })())
    }

    /// Writes a copy of the claims into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_claims_clone(claims: *const JWTClaims, out: *mut *mut JWTClaims) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let claims = unsafe { Pointer::reference(claims) }?;
            unsafe { Pointer::write_handle(out, claims.clone()) }
        })())
    }

    /// Releases a claims set. Does nothing if `claims` is null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_claims_free(claims: *mut JWTClaims) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(claims) }
    }

    /// Writes the validation at `now` (seconds since 1970-01-01T00:00:00Z), without leeway, expectations
    /// or required claims, into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_validation_new(now: i64, out: *mut *mut JWTValidation) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, JWTValidation::new(now)) })
    }

    /// Sets the tolerance for `exp` and `nbf`, in seconds.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_validation_set_leeway(validation: *mut JWTValidation, leeway: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let validation = unsafe { Pointer::reference_mut(validation) }?;
            validation.leeway = leeway;
            Ok(())
        })())
    }

    /// Sets the issuer expected to the UTF-8 text at `issuer`, or none for null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_validation_set_issuer(validation: *mut JWTValidation, issuer: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and null or readable text.
            let validation = unsafe { Pointer::reference_mut(validation) }?;
            validation.issuer = unsafe { Pointer::optional_text(issuer, length).map(|text| text.map(String::from)) }?;
            Ok(())
        })())
    }

    /// Sets the audience expected (the identifier of the recipient) to the UTF-8 text at `audience`, or
    /// none for null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_validation_set_audience(validation: *mut JWTValidation, audience: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and null or readable text.
            let validation = unsafe { Pointer::reference_mut(validation) }?;
            validation.audience = unsafe { Pointer::optional_text(audience, length).map(|text| text.map(String::from)) }?;
            Ok(())
        })())
    }

    /// Sets the subject expected to the UTF-8 text at `subject`, or none for null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_validation_set_subject(validation: *mut JWTValidation, subject: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and null or readable text.
            let validation = unsafe { Pointer::reference_mut(validation) }?;
            validation.subject = unsafe { Pointer::optional_text(subject, length).map(|text| text.map(String::from)) }?;
            Ok(())
        })())
    }

    /// Sets the `typ` expected (RFC 8725 §3.11) to the UTF-8 text at `token_type`, or none for null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_validation_set_token_type(validation: *mut JWTValidation, token_type: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and null or readable text.
            let validation = unsafe { Pointer::reference_mut(validation) }?;
            validation.token_type = unsafe { Pointer::optional_text(token_type, length).map(|text| text.map(String::from)) }?;
            Ok(())
        })())
    }

    /// Adds the claim named by the UTF-8 text at `name` to those required.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_validation_require(validation: *mut JWTValidation, name: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let validation = unsafe { Pointer::reference_mut(validation) }?;
            let name = unsafe { Pointer::text(name, length) }?;
            validation.required.push(name.to_string());
            Ok(())
        })())
    }

    /// Checks `claims` held by `header` against the validation.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_validation_validate(validation: *const JWTValidation, header: *const JOSEHeader, claims: *const JWTClaims) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let validation = unsafe { Pointer::reference(validation) }?;
            let header = unsafe { Pointer::reference(header) }?;
            let claims = unsafe { Pointer::reference(claims) }?;
            validation.validate(header, claims).map_err(|error| error.to_status())
        })())
    }

    /// Releases a validation. Does nothing if `validation` is null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_validation_free(validation: *mut JWTValidation) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(validation) }
    }

    /// Writes the compact JWS of `claims` with the protected header `header` under `key` into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_sign(claims: *const JWTClaims, header: *const JOSEHeader, key: *const JWK, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, a generator of the named type and a writable buffer.
            let claims = unsafe { Pointer::reference(claims) }?;
            let header = unsafe { Pointer::reference(header) }?;
            let key = unsafe { Pointer::reference(key) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let token = JWT::sign(claims, header, key, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, token) }
        })())
    }

    /// Writes the JWT of the compact JWS at `text`, verified under `key` and validated, into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_verify(text: *const u8, length: usize, key: *const JWK, config: *const JWSConfig, validation: *const JWTValidation, out: *mut *mut JWT) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text, valid handles and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let key = unsafe { Pointer::reference(key) }?;
            let config = unsafe { Pointer::reference(config) }?;
            let validation = unsafe { Pointer::reference(validation) }?;
            let jwt = JWT::verify(text, key, config, validation).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, jwt) }
        })())
    }

    /// Writes the JWT of the Unsecured JWS at `text` (RFC 7519 §6), validated, into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_verify_unsecured(text: *const u8, length: usize, validation: *const JWTValidation, out: *mut *mut JWT) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text, a valid handle and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let validation = unsafe { Pointer::reference(validation) }?;
            let jwt = JWT::verify_unsecured(text, validation).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, jwt) }
        })())
    }

    /// Writes the compact JWE of `claims` with the protected header `header` for `key` into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_encrypt(claims: *const JWTClaims, header: *const JOSEHeader, key: *const JWK, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, a generator of the named type and a writable buffer.
            let claims = unsafe { Pointer::reference(claims) }?;
            let header = unsafe { Pointer::reference(header) }?;
            let key = unsafe { Pointer::reference(key) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let token = JWT::encrypt(claims, header, key, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, token) }
        })())
    }

    /// Writes the JWT of the compact JWE at `text`, decrypted with `key` and validated, into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_decrypt(text: *const u8, length: usize, key: *const JWK, config: *const JWEConfig, validation: *const JWTValidation, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut JWT) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text, valid handles, a generator of the named type and a
            // writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let key = unsafe { Pointer::reference(key) }?;
            let config = unsafe { Pointer::reference(config) }?;
            let validation = unsafe { Pointer::reference(validation) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let jwt = JWT::decrypt(text, key, config, validation, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, jwt) }
        })())
    }

    /// Writes the Nested JWT (RFC 7519 §5.2) of `claims`: signed under `signing_key` with
    /// `signing_header`, encrypted for `encryption_key` with `encryption_header` and the `cty` of "JWT".
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_sign_and_encrypt(claims: *const JWTClaims, signing_header: *const JOSEHeader, signing_key: *const JWK, encryption_header: *const JOSEHeader, encryption_key: *const JWK, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, a generator of the named type and a writable buffer.
            let claims = unsafe { Pointer::reference(claims) }?;
            let signing_header = unsafe { Pointer::reference(signing_header) }?;
            let signing_key = unsafe { Pointer::reference(signing_key) }?;
            let encryption_header = unsafe { Pointer::reference(encryption_header) }?;
            let encryption_key = unsafe { Pointer::reference(encryption_key) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let token = JWT::sign_and_encrypt(claims, signing_header, signing_key, encryption_header, encryption_key, &mut random)
                .map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, token) }
        })())
    }

    /// Writes the JWT of the Nested JWT at `text`: decrypted with `decryption_key`, verified under
    /// `verification_key` and validated, into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_decrypt_and_verify(text: *const u8, length: usize, decryption_key: *const JWK, decryption: *const JWEConfig, verification_key: *const JWK, verification: *const JWSConfig, validation: *const JWTValidation, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut JWT) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text, valid handles, a generator of the named type and a
            // writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let decryption_key = unsafe { Pointer::reference(decryption_key) }?;
            let decryption = unsafe { Pointer::reference(decryption) }?;
            let verification_key = unsafe { Pointer::reference(verification_key) }?;
            let verification = unsafe { Pointer::reference(verification) }?;
            let validation = unsafe { Pointer::reference(validation) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let jwt = JWT::decrypt_and_verify(text, decryption_key, decryption, verification_key, verification, validation, &mut random)
                .map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, jwt) }
        })())
    }

    /// Writes a copy of the header that holds the claims of the JWT into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_header(jwt: *const JWT, out: *mut *mut JOSEHeader) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let jwt = unsafe { Pointer::reference(jwt) }?;
            unsafe { Pointer::write_handle(out, jwt.header.clone()) }
        })())
    }

    /// Writes a copy of the claims of the JWT into `out`.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_claims(jwt: *const JWT, out: *mut *mut JWTClaims) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let jwt = unsafe { Pointer::reference(jwt) }?;
            unsafe { Pointer::write_handle(out, jwt.claims.clone()) }
        })())
    }

    /// Releases a JWT. Does nothing if `jwt` is null.
    pub unsafe extern "C" fn umilib_protocol_jwt_jwt_free(jwt: *mut JWT) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(jwt) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "jwt",
    definitions: &[
        Definition::Opaque {
            name: "umilib_protocol_jwt_JOSEHeader",
            documentation: " A JOSE Header (RFC 7515 §4, RFC 7516 §4).",
        },
        Definition::Opaque { name: "umilib_protocol_jwt_JWK", documentation: " A JSON Web Key (RFC 7517)." },
        Definition::Opaque { name: "umilib_protocol_jwt_JWKSet", documentation: " A JWK Set (RFC 7517 §5)." },
        Definition::Opaque {
            name: "umilib_protocol_jwt_JWSConfig",
            documentation: " What verifying a JWS accepts (RFC 8725 §3.1).",
        },
        Definition::Opaque { name: "umilib_protocol_jwt_JWS", documentation: " A JSON Web Signature (RFC 7515)." },
        Definition::Opaque {
            name: "umilib_protocol_jwt_JWEConfig",
            documentation: " What decrypting a JWE accepts (RFC 8725 §3.1).",
        },
        Definition::Opaque { name: "umilib_protocol_jwt_JWE", documentation: " A JSON Web Encryption (RFC 7516)." },
        Definition::Opaque {
            name: "umilib_protocol_jwt_JWTClaims", documentation: " A JWT Claims Set (RFC 7519 §4)."
        },
        Definition::Opaque {
            name: "umilib_protocol_jwt_JWTValidation",
            documentation: " What a JWT must satisfy (RFC 7519 §7.2, RFC 8725 §3).",
        },
        Definition::Opaque {
            name: "umilib_protocol_jwt_JWT",
            documentation: " A verified or decrypted JWT: its header and its claims.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
