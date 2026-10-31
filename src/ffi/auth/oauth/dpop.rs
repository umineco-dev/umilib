//! The C ABI of DPoP proofs and [`DPoPVerifier`].

use alloc::string::ToString;
use core::ffi::c_void;

use super::OAuthStatus;
use crate::auth::oauth::{DPoPConfig, DPoPProof, DPoPTarget, DPoPVerifier};
use crate::ffi::{Buffer, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::jwt::JWK;

impl Value for DPoPVerifier {
    const TYPE: Type = Type::Named("umilib_auth_oauth_DPoPVerifier");
}

impl OAuthStatus {
    /// The request of the method at `method`, the URI at `uri` and the access token at
    /// `access_token` (null for none).
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn target<'a>(
        method: *const u8,
        method_length: usize,
        uri: *const u8,
        uri_length: usize,
        access_token: *const u8,
        access_token_length: usize,
    ) -> Result<DPoPTarget<'a>, &'static Status> {
        // SAFETY: guaranteed by the caller.
        Ok(DPoPTarget {
            method: unsafe { Pointer::text(method, method_length) }?,
            uri: unsafe { Pointer::text(uri, uri_length) }?,
            access_token: unsafe { Pointer::optional_text(access_token, access_token_length) }?,
        })
    }
}

crate::ffi_functions! {
    /// Writes a DPoP proof (RFC 9449 §4.2) for a request of the method at `method` to the URI
    /// at `uri` presenting the access token at `access_token` (null for none), signed with the
    /// private `key` by the JWS algorithm `algorithm` at `now`, with the nonce at `nonce` (null
    /// for none), into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_dpop_proof_create(key: *const JWK, algorithm: u8, method: *const u8, method_length: usize, uri: *const u8, uri_length: usize, access_token: *const u8, access_token_length: usize, now: i64, nonce: *const u8, nonce_length: usize, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(method, method_length), Pointer::range(uri, uri_length), Pointer::range(access_token, access_token_length), Pointer::range(nonce, nonce_length)], &[Pointer::range(out, 1)])?;
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes a valid key, readable text or null, a generator and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let target = unsafe { OAuthStatus::target(method, method_length, uri, uri_length, access_token, access_token_length) }?;
            let nonce = unsafe { Pointer::optional_text(nonce, nonce_length) }?;
            let mut random = unsafe { OAuthStatus::random(random, random_type, random_type_length) }?;
            let proof = DPoPProof::create(key, OAuthStatus::algorithm(algorithm)?, &target, now, nonce, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, proof) }
        })())
    }

    /// Checks the DPoP proof at `proof` for a request of the method at `method` to the URI at
    /// `uri` presenting the access token at `access_token` (null for none), signed by one of the
    /// `count` JWS algorithms at `algorithms`, at `now`, with an `iat` at most `maximum_age`
    /// seconds old and `leeway` seconds ahead (RFC 9449 §4.3, without the replay and nonce
    /// checks); writes the base64url thumbprint of its key into `out_thumbprint` and its claims
    /// (JSON) into `out_claims`.
    pub unsafe extern "C" fn umilib_auth_oauth_dpop_proof_verify(proof: *const u8, proof_length: usize, algorithms: *const u8, count: usize, method: *const u8, method_length: usize, uri: *const u8, uri_length: usize, access_token: *const u8, access_token_length: usize, now: i64, maximum_age: i64, leeway: i64, out_thumbprint: *mut Buffer, out_claims: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let inputs = [Pointer::range(proof, proof_length), Pointer::range(algorithms, count), Pointer::range(method, method_length), Pointer::range(uri, uri_length), Pointer::range(access_token, access_token_length)];
            Pointer::check_ranges(&inputs, &[Pointer::range(out_thumbprint, 1), Pointer::range(out_claims, 1)])?;
            Pointer::check_range(out_thumbprint, 1)?;
            Pointer::check_range(out_claims, 1)?;
            // SAFETY: the caller passes readable text and bytes or null and writable buffers.
            let proof = unsafe { Pointer::text(proof, proof_length) }?;
            let algorithms = unsafe { OAuthStatus::algorithms(algorithms, count) }?;
            let target = unsafe { OAuthStatus::target(method, method_length, uri, uri_length, access_token, access_token_length) }?;
            let checked = DPoPProof::verify(proof, &algorithms, &target, now, maximum_age, leeway).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out_thumbprint, checked.thumbprint.clone()) }?;
            unsafe { Pointer::write_text(out_claims, checked.claims.encode()) }
        })())
    }

    /// Writes the base64url JWK SHA-256 thumbprint of `key` (RFC 7638, RFC 9449 §6.1) into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_dpop_proof_thumbprint(key: *const JWK, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid key and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let thumbprint = DPoPProof::thumbprint(key).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, thumbprint) }
        })())
    }

    /// Writes the `ath` of the access token at `access_token` (RFC 9449 §4.2) into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_dpop_proof_access_token_hash(access_token: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(access_token, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable buffer.
            let access_token = unsafe { Pointer::text(access_token, length) }?;
            unsafe { Pointer::write_text(out, DPoPProof::access_token_hash(access_token)) }
        })())
    }

    /// Writes the URI at `uri` as an `htu` is compared (RFC 9449 §4.3) into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_dpop_proof_target(uri: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(uri, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable buffer.
            let uri = unsafe { Pointer::text(uri, length) }?;
            let target = DPoPProof::target(uri).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, target) }
        })())
    }

    /// Writes a verifier taking the `count` JWS algorithms at `algorithms`, with an `iat` at most
    /// `maximum_age` seconds old and `leeway` seconds ahead, requiring a nonce if
    /// `require_nonce`, keeping at most `maximum_proofs` identifiers, and taking the
    /// `previous_nonces` nonces made before the current one, into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_dpop_verifier_new(algorithms: *const u8, count: usize, maximum_age: i64, leeway: i64, require_nonce: bool, maximum_proofs: usize, previous_nonces: usize, out: *mut *mut DPoPVerifier) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let algorithms = unsafe { OAuthStatus::algorithms(algorithms, count) }?;
            let config = DPoPConfig { algorithms, maximum_age, leeway, require_nonce, maximum_proofs, previous_nonces };
            unsafe { Pointer::write_handle(out, DPoPVerifier::new(config)) }
        })())
    }

    /// Releases a verifier. Does nothing if `verifier` is null.
    pub unsafe extern "C" fn umilib_auth_oauth_dpop_verifier_free(verifier: *mut DPoPVerifier) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(verifier) }
    }

    /// Checks the proof at `proof` for the request of the method at `method` to the URI at `uri`
    /// presenting the access token at `access_token` (null for none) at `now`, with every check
    /// of RFC 9449 §4.3; writes the thumbprint of its key into `out` and its claims (JSON) into
    /// `out_claims`. A refused proof fails with Response, the JSON of `invalid_dpop_proof` or
    /// `use_dpop_nonce` into `out_error`.
    pub unsafe extern "C" fn umilib_auth_oauth_dpop_verifier_check(verifier: *mut DPoPVerifier, proof: *const u8, proof_length: usize, method: *const u8, method_length: usize, uri: *const u8, uri_length: usize, access_token: *const u8, access_token_length: usize, now: i64, out: *mut Buffer, out_claims: *mut Buffer, out_error: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a valid handle, readable text or null and writable buffers.
        let checked: Result<_, &'static Status> = (|| {
            let inputs = [Pointer::range(proof, proof_length), Pointer::range(method, method_length), Pointer::range(uri, uri_length), Pointer::range(access_token, access_token_length)];
            Pointer::check_ranges(&inputs, &[Pointer::range(out, 1), Pointer::range(out_claims, 1), Pointer::range(out_error, 1)])?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_claims, 1)?;
            let proof = unsafe { Pointer::text(proof, proof_length) }?;
            let target = unsafe { OAuthStatus::target(method, method_length, uri, uri_length, access_token, access_token_length) }?;
            let verifier = unsafe { Pointer::reference_mut(verifier) }?;
            Ok((proof, target, verifier))
        })();
        let (proof, target, verifier) = match checked {
            Ok(checked) => checked,
            Err(status) => return status,
        };
        match verifier.check(proof, &target, now) {
            // SAFETY: `out` is writable, checked above.
            Ok(proof) => Status::from_result(unsafe { Pointer::write_text(out, proof.thumbprint) }.and_then(|()| unsafe { Pointer::write_text(out_claims, proof.claims.encode()) })),
            // SAFETY: the caller passes null or a writable buffer.
            Err(error) => unsafe { OAuthStatus::fail(crate::auth::oauth::OAuthError::Response(error), out_error) },
        }
    }

    /// Makes a new nonce (RFC 9449 §8) and writes it into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_dpop_verifier_rotate_nonce(verifier: *mut DPoPVerifier, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, a generator and a writable buffer.
            let mut random = unsafe { OAuthStatus::random(random, random_type, random_type_length) }?;
            Pointer::check_range(out, 1)?;
            let verifier = unsafe { Pointer::reference_mut(verifier) }?;
            let nonce = verifier.rotate_nonce(&mut random).map_err(|error| error.to_status())?.to_string();
            unsafe { Pointer::write_text(out, nonce) }
        })())
    }

    /// Writes whether the verifier made a nonce into `out_has` and the current one into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_dpop_verifier_nonce(verifier: *const DPoPVerifier, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_has, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let verifier = unsafe { Pointer::reference(verifier) }?;
            unsafe { Pointer::write_optional_text(out_has, out, verifier.nonce()) }
        })())
    }
}
