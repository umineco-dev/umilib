//! The C ABI of [`OAuthResourceServer`], the tokens it takes and the challenges it sends.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::c_void;

use super::OAuthStatus;
use crate::auth::oauth::{
    DPoPConfig, OAuthChallenge, OAuthEndpointRequest, OAuthHTTPResponse, OAuthIntrospectionResponse,
    OAuthPresentedToken, OAuthResourceConfig, OAuthResourceError, OAuthResourceServer, OAuthTokenInfo,
    OAuthTokenScheme, OAuthTokenValidation,
};
use crate::ffi::{Buffer, Char, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::jwt::JWKSet;

impl Value for OAuthResourceServer {
    const TYPE: Type = Type::Named("umilib_auth_oauth_OAuthResourceServer");
}

impl Value for OAuthTokenInfo {
    const TYPE: Type = Type::Named("umilib_auth_oauth_OAuthTokenInfo");
}

impl Value for OAuthResourceError {
    const TYPE: Type = Type::Named("umilib_auth_oauth_OAuthResourceError");
}

impl Value for Vec<OAuthChallenge> {
    const TYPE: Type = Type::Named("umilib_auth_oauth_OAuthChallenges");
}

impl OAuthStatus {
    /// The [`OAuthTokenScheme`] values of the C ABI: `0` Bearer, `1` DPoP.
    pub fn scheme(value: u8) -> Result<OAuthTokenScheme, &'static Status> {
        match value {
            0 => Ok(OAuthTokenScheme::Bearer),
            1 => Ok(OAuthTokenScheme::DPoP),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    /// The C value of `scheme`.
    pub fn scheme_value(scheme: OAuthTokenScheme) -> u8 {
        match scheme {
            OAuthTokenScheme::Bearer => 0,
            OAuthTokenScheme::DPoP => 1,
        }
    }

    /// Writes `result` into `out_accepted`, `out` (the value, or null) and `out_refusal` (the
    /// refusal, or null).
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn outcome<T>(
        result: Result<T, OAuthResourceError>,
        out_accepted: *mut bool,
        out: *mut *mut T,
        out_refusal: *mut *mut OAuthResourceError,
    ) -> Result<(), &'static Status> {
        Pointer::check_ranges(
            &[],
            &[Pointer::range(out_accepted, 1), Pointer::range(out, 1), Pointer::range(out_refusal, 1)],
        )?;
        Pointer::check_range(out_accepted, 1)?;
        Pointer::check_range(out_refusal, 1)?;
        // SAFETY: guaranteed by the caller; the outputs are checked above.
        match result {
            Ok(value) => {
                unsafe { Pointer::write(out_accepted, true) }?;
                unsafe { Pointer::write(out_refusal, core::ptr::null_mut()) }?;
                if out.is_null() { Ok(()) } else { unsafe { Pointer::write_handle(out, value) } }
            }
            Err(refusal) => {
                unsafe { Pointer::write(out_accepted, false) }?;
                if !out.is_null() {
                    unsafe { Pointer::write(out, core::ptr::null_mut()) }?;
                }
                unsafe { Pointer::write_handle(out_refusal, refusal) }
            }
        }
    }
}

crate::ffi_functions! {
    /// Writes the checks of the resource at `resource` into `out`: with the realm at `realm` and
    /// the metadata URL at `resource_metadata` in its challenges (null for none); taking the JWT
    /// access tokens of the issuer at `issuer`, signed by one of `keys` with one of the
    /// `algorithm_count` JWS algorithms at `algorithms`, or, if `issuer` is null, introspected
    /// ones; only DPoP-bound ones if `require_dpop`; DPoP proofs signed by one of the
    /// `dpop_count` algorithms at `dpop_algorithms`, with an `iat` at most `dpop_maximum_age`
    /// seconds old and `dpop_leeway` ahead, a nonce if `dpop_require_nonce`, and at most
    /// `dpop_maximum_proofs` identifiers kept, `dpop_previous_nonces` nonces before the current
    /// one taken; `leeway` seconds of clock skew on `exp`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_resource_server_new(resource: *const u8, resource_length: usize, realm: *const u8, realm_length: usize, resource_metadata: *const u8, resource_metadata_length: usize, issuer: *const u8, issuer_length: usize, keys: *const JWKSet, algorithms: *const u8, algorithm_count: usize, require_dpop: bool, dpop_algorithms: *const u8, dpop_count: usize, dpop_maximum_age: i64, dpop_leeway: i64, dpop_require_nonce: bool, dpop_maximum_proofs: usize, dpop_previous_nonces: usize, leeway: u64, out: *mut *mut OAuthResourceServer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes or null, a key set or null and a writable pointer.
            let resource = unsafe { Pointer::text(resource, resource_length) }?;
            let realm = unsafe { Pointer::optional_text(realm, realm_length) }?;
            let resource_metadata = unsafe { Pointer::optional_text(resource_metadata, resource_metadata_length) }?;
            let issuer = unsafe { Pointer::optional_text(issuer, issuer_length) }?;
            let validation = match issuer {
                Some(issuer) => OAuthTokenValidation::JWT {
                    issuer: issuer.to_string(),
                    keys: unsafe { Pointer::reference(keys) }?.clone(),
                    algorithms: unsafe { OAuthStatus::algorithms(algorithms, algorithm_count) }?,
                },
                None => OAuthTokenValidation::Introspection,
            };
            let dpop = DPoPConfig {
                algorithms: unsafe { OAuthStatus::algorithms(dpop_algorithms, dpop_count) }?,
                maximum_age: dpop_maximum_age,
                leeway: dpop_leeway,
                require_nonce: dpop_require_nonce,
                maximum_proofs: dpop_maximum_proofs,
                previous_nonces: dpop_previous_nonces,
            };
            let config = OAuthResourceConfig {
                resource: resource.to_string(),
                realm: realm.map(str::to_string),
                resource_metadata: resource_metadata.map(str::to_string),
                validation,
                require_dpop,
                dpop,
                leeway,
            };
            Pointer::check_range(out, 1)?;
            let server = OAuthResourceServer::new(config).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, server) }
        })())
    }

    /// Releases a resource server. Does nothing if `server` is null.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_resource_server_free(server: *mut OAuthResourceServer) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(server) }
    }

    /// Writes the JSON of the resource's metadata document (RFC 9728 §2), naming the
    /// `server_count` authorization servers at `servers` and the `scope_count` scopes at
    /// `scopes`, into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_resource_server_metadata(server: *const OAuthResourceServer, servers: *const *const Char, server_count: usize, scopes: *const *const Char, scope_count: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, arrays of strings and a writable buffer.
            let server = unsafe { Pointer::reference(server) }?;
            let servers = unsafe { Pointer::strings(servers, server_count) }?;
            let scopes = unsafe { Pointer::strings(scopes, scope_count) }?;
            let servers: Vec<&str> = servers.iter().map(String::as_str).collect();
            let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
            unsafe { Pointer::write_text(out, server.metadata(&servers, &scopes).encode()) }
        })())
    }

    /// Writes into `out` the refusal of the error response whose JSON is at `error` (null for a
    /// request without credentials), challenged with `scheme` (0 Bearer, 1 DPoP) if `has_scheme`,
    /// or with every scheme the resource takes.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_resource_server_refuse(server: *const OAuthResourceServer, error: *const u8, error_length: usize, has_scheme: bool, scheme: u8, out: *mut *mut OAuthResourceError) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes or null and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            let error = match unsafe { Pointer::optional_text(error, error_length) }? {
                Some(body) => match crate::auth::oauth::OAuthTokenResponse::decode(400, body.as_bytes()) {
                    Err(crate::auth::oauth::OAuthError::Response(response)) => Some(response),
                    Err(error) => return Err(error.to_status()),
                    Ok(_) => return Err(&OAuthStatus::INVALID),
                },
                None => None,
            };
            let scheme = if has_scheme { Some(OAuthStatus::scheme(scheme)?) } else { None };
            unsafe { Pointer::write_handle(out, server.refuse(error.as_ref(), scheme)) }
        })())
    }

    /// Reads the access token of `request` (RFC 6750 §2.1, RFC 9449 §7.1): writes whether there
    /// is one into `out_accepted`, its scheme (0 Bearer, 1 DPoP) into `out_scheme` and the token
    /// into `out_token`, or the refusal into `out_refusal`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_resource_server_presented(server: *const OAuthResourceServer, request: *const OAuthEndpointRequest, out_accepted: *mut bool, out_scheme: *mut u8, out_token: *mut Buffer, out_refusal: *mut *mut OAuthResourceError) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_accepted, 1), Pointer::range(out_scheme, 1), Pointer::range(out_token, 1), Pointer::range(out_refusal, 1)])?;
            for check in [Pointer::check_range(out_accepted, 1), Pointer::check_range(out_scheme, 1), Pointer::check_range(out_token, 1), Pointer::check_range(out_refusal, 1)] {
                check?;
            }
            // SAFETY: the caller passes valid handles and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            let request = unsafe { Pointer::reference(request) }?;
            let presented = server.presented(request);
            let (scheme, token) = presented.as_ref().map(|token| (OAuthStatus::scheme_value(token.scheme), token.token.clone())).unwrap_or_default();
            unsafe { Pointer::write(out_scheme, scheme) }?;
            unsafe { Pointer::write_text(out_token, token) }?;
            unsafe { OAuthStatus::outcome(presented.map(|_| ()), out_accepted, core::ptr::null_mut::<*mut ()>(), out_refusal) }
        })())
    }

    /// Takes the JWT access token of `request` at `now` (RFC 9068 §4, RFC 9449 §7): writes whether
    /// it was taken into `out_accepted` and what it says into `out`, or the refusal into
    /// `out_refusal`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_resource_server_accept_jwt(server: *mut OAuthResourceServer, request: *const OAuthEndpointRequest, now: i64, out_accepted: *mut bool, out: *mut *mut OAuthTokenInfo, out_refusal: *mut *mut OAuthResourceError) -> *const Status {
        Status::from_result((|| {
            Pointer::check_range(out_accepted, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_refusal, 1)?;
            // SAFETY: the caller passes valid handles and writable pointers.
            let request = unsafe { Pointer::reference(request) }?;
            let server = unsafe { Pointer::reference_mut(server) }?;
            unsafe { OAuthStatus::outcome(server.accept_jwt(request, now), out_accepted, out, out_refusal) }
        })())
    }

    /// Takes the access token of `request` as the introspection response whose JSON is at
    /// `introspection` describes it (RFC 7662 §2.2, RFC 9449 §7), as
    /// `umilib_auth_oauth_oauth_resource_server_accept_jwt` does.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_resource_server_accept_introspection(server: *mut OAuthResourceServer, request: *const OAuthEndpointRequest, introspection: *const u8, length: usize, now: i64, out_accepted: *mut bool, out: *mut *mut OAuthTokenInfo, out_refusal: *mut *mut OAuthResourceError) -> *const Status {
        Status::from_result((|| {
            Pointer::check_range(out_accepted, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_refusal, 1)?;
            // SAFETY: the caller passes valid handles, readable bytes and writable pointers.
            let request = unsafe { Pointer::reference(request) }?;
            let body = unsafe { Pointer::slice(introspection, length) }?;
            let introspection = OAuthIntrospectionResponse::decode(200, body).map_err(|error| error.to_status())?;
            let server = unsafe { Pointer::reference_mut(server) }?;
            unsafe { OAuthStatus::outcome(server.accept_introspection(request, &introspection, now), out_accepted, out, out_refusal) }
        })())
    }

    /// Checks that `info` grants the scope at `scope` (null for none; RFC 6750 §3.1), challenged with `scheme`:
    /// writes whether it does into `out_accepted`, or the refusal into `out_refusal`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_resource_server_require_scope(server: *const OAuthResourceServer, info: *const OAuthTokenInfo, scope: *const u8, length: usize, scheme: u8, out_accepted: *mut bool, out_refusal: *mut *mut OAuthResourceError) -> *const Status {
        Status::from_result((|| {
            Pointer::check_range(out_accepted, 1)?;
            Pointer::check_range(out_refusal, 1)?;
            // SAFETY: the caller passes valid handles, readable text and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            let info = unsafe { Pointer::reference(info) }?;
            let scope = unsafe { OAuthStatus::scope(scope, length) }?.unwrap_or_default();
            let result = server.require_scope(info, &scope, OAuthStatus::scheme(scheme)?);
            unsafe { OAuthStatus::outcome(result, out_accepted, core::ptr::null_mut::<*mut ()>(), out_refusal) }
        })())
    }

    /// Checks that the user of `info` authenticated at most `max_age` seconds before `now` (if
    /// `has_max_age`) and with one of the `count` contexts at `acr_values` (RFC 9470 §3),
    /// challenged with `scheme`, as `umilib_auth_oauth_oauth_resource_server_require_scope` does.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_resource_server_require_authentication(server: *const OAuthResourceServer, info: *const OAuthTokenInfo, now: i64, has_max_age: bool, max_age: i64, acr_values: *const *const Char, count: usize, scheme: u8, out_accepted: *mut bool, out_refusal: *mut *mut OAuthResourceError) -> *const Status {
        Status::from_result((|| {
            Pointer::check_range(out_accepted, 1)?;
            Pointer::check_range(out_refusal, 1)?;
            // SAFETY: the caller passes valid handles, an array of strings and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            let info = unsafe { Pointer::reference(info) }?;
            let acr_values = unsafe { Pointer::strings(acr_values, count) }?;
            let acr_values: Vec<&str> = acr_values.iter().map(String::as_str).collect();
            let result = server.require_authentication(info, now, has_max_age.then_some(max_age), &acr_values, OAuthStatus::scheme(scheme)?);
            unsafe { OAuthStatus::outcome(result, out_accepted, core::ptr::null_mut::<*mut ()>(), out_refusal) }
        })())
    }

    /// Makes a new DPoP nonce (RFC 9449 §9) and writes it into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_resource_server_rotate_dpop_nonce(server: *mut OAuthResourceServer, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, a generator and a writable buffer.
            let mut random = unsafe { OAuthStatus::random(random, random_type, random_type_length) }?;
            Pointer::check_range(out, 1)?;
            let server = unsafe { Pointer::reference_mut(server) }?;
            let nonce = server.dpop().rotate_nonce(&mut random).map_err(|error| error.to_status())?.to_string();
            unsafe { Pointer::write_text(out, nonce) }
        })())
    }

    // What a token says.

    /// Writes what a token says: the client at `client_id` and the user at `subject` (null for
    /// none), the scope at `scope`, the `count` audiences at `audience`, the expiry (if
    /// `has_expires`), the thumbprint of its DPoP key at `confirmation` (null for none), and
    /// when (if `has_authentication_time`) and how (`context`, null for none) the user
    /// authenticated, into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_token_info_new(client_id: *const u8, client_id_length: usize, subject: *const u8, subject_length: usize, scope: *const u8, scope_length: usize, audience: *const *const Char, count: usize, has_expires: bool, expires: i64, confirmation: *const u8, confirmation_length: usize, has_authentication_time: bool, authentication_time: i64, context: *const u8, context_length: usize, out: *mut *mut OAuthTokenInfo) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text or null, an array of strings and a writable pointer.
            let info = OAuthTokenInfo {
                client_id: unsafe { Pointer::optional_text(client_id, client_id_length) }?.map(str::to_string),
                subject: unsafe { Pointer::optional_text(subject, subject_length) }?.map(str::to_string),
                scope: unsafe { OAuthStatus::scope(scope, scope_length) }?.unwrap_or_default(),
                audience: unsafe { Pointer::strings(audience, count) }?,
                expires: has_expires.then_some(expires),
                confirmation: unsafe { Pointer::optional_text(confirmation, confirmation_length) }?.map(str::to_string),
                authentication_time: has_authentication_time.then_some(authentication_time),
                authentication_context: unsafe { Pointer::optional_text(context, context_length) }?.map(str::to_string),
            };
            unsafe { Pointer::write_handle(out, info) }
        })())
    }

    /// Releases what a token says. Does nothing if `info` is null.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_token_info_free(info: *mut OAuthTokenInfo) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(info) }
    }

    /// Writes the texts of `info`: the client and the user (each with whether it is present),
    /// the scope, the audiences joined by LF, the DPoP thumbprint and the authentication context
    /// (each with whether it is present).
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_token_info_texts(info: *const OAuthTokenInfo, out_has_client_id: *mut bool, out_client_id: *mut Buffer, out_has_subject: *mut bool, out_subject: *mut Buffer, out_scope: *mut Buffer, out_audience: *mut Buffer, out_has_confirmation: *mut bool, out_confirmation: *mut Buffer, out_has_context: *mut bool, out_context: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let outputs = [
                Pointer::range(out_has_client_id, 1), Pointer::range(out_client_id, 1), Pointer::range(out_has_subject, 1), Pointer::range(out_subject, 1),
                Pointer::range(out_scope, 1), Pointer::range(out_audience, 1), Pointer::range(out_has_confirmation, 1), Pointer::range(out_confirmation, 1),
                Pointer::range(out_has_context, 1), Pointer::range(out_context, 1),
            ];
            Pointer::check_ranges(&[], &outputs)?;
            for (output, _) in outputs {
                Pointer::check_range(output, 1)?;
            }
            // SAFETY: the caller passes a valid handle and writable pointers.
            let info = unsafe { Pointer::reference(info) }?;
            unsafe { Pointer::write_optional_text(out_has_client_id, out_client_id, info.client_id.as_deref()) }?;
            unsafe { Pointer::write_optional_text(out_has_subject, out_subject, info.subject.as_deref()) }?;
            unsafe { Pointer::write_text(out_scope, info.scope.to_string()) }?;
            unsafe { Pointer::write_text(out_audience, info.audience.join("\n")) }?;
            unsafe { Pointer::write_optional_text(out_has_confirmation, out_confirmation, info.confirmation.as_deref()) }?;
            unsafe { Pointer::write_optional_text(out_has_context, out_context, info.authentication_context.as_deref()) }
        })())
    }

    /// Writes the times of `info`: the expiry and when the user authenticated, each with whether
    /// it is present.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_token_info_times(info: *const OAuthTokenInfo, out_has_expires: *mut bool, out_expires: *mut i64, out_has_authentication_time: *mut bool, out_authentication_time: *mut i64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_has_expires, 1), Pointer::range(out_expires, 1), Pointer::range(out_has_authentication_time, 1), Pointer::range(out_authentication_time, 1)])?;
            for check in [Pointer::check_range(out_has_expires, 1), Pointer::check_range(out_has_authentication_time, 1), Pointer::check_range(out_expires, 1), Pointer::check_range(out_authentication_time, 1)] {
                check?;
            }
            // SAFETY: the caller passes a valid handle and writable pointers.
            let info = unsafe { Pointer::reference(info) }?;
            unsafe { Pointer::write_optional(info.expires, out_has_expires, out_expires) }?;
            unsafe { Pointer::write_optional(info.authentication_time, out_has_authentication_time, out_authentication_time) }
        })())
    }

    // Refusals and challenges.

    /// Releases a refusal. Does nothing if `refusal` is null.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_resource_error_free(refusal: *mut OAuthResourceError) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(refusal) }
    }

    /// Writes the status of `refusal` into `out_status`, whether it sends a DPoP nonce into
    /// `out_has_nonce`, the nonce into `out_nonce` and a copy of its challenges into
    /// `out_challenges`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_resource_error_parts(refusal: *const OAuthResourceError, out_status: *mut u16, out_has_nonce: *mut bool, out_nonce: *mut Buffer, out_challenges: *mut *mut Vec<OAuthChallenge>) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_status, 1), Pointer::range(out_has_nonce, 1), Pointer::range(out_nonce, 1), Pointer::range(out_challenges, 1)])?;
            Pointer::check_range(out_status, 1)?;
            Pointer::check_range(out_has_nonce, 1)?;
            Pointer::check_range(out_nonce, 1)?;
            Pointer::check_range(out_challenges, 1)?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let refusal = unsafe { Pointer::reference(refusal) }?;
            unsafe { Pointer::write(out_status, refusal.status) }?;
            unsafe { Pointer::write_optional_text(out_has_nonce, out_nonce, refusal.nonce.as_deref()) }?;
            unsafe { Pointer::write_handle(out_challenges, refusal.challenges.clone()) }
        })())
    }

    /// Writes the HTTP response of `refusal` (one `WWW-Authenticate` field per challenge) into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_resource_error_to_response(refusal: *const OAuthResourceError, out: *mut *mut OAuthHTTPResponse) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let refusal = unsafe { Pointer::reference(refusal) }?;
            unsafe { Pointer::write_handle(out, refusal.to_response()) }
        })())
    }

    /// Writes the challenges of the `WWW-Authenticate` value at `value` (RFC 9110 §11.6.1) into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_challenges_parse(value: *const u8, length: usize, out: *mut *mut Vec<OAuthChallenge>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let value = unsafe { Pointer::text(value, length) }?;
            Pointer::check_range(out, 1)?;
            let challenges = OAuthChallenge::parse(value).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, challenges) }
        })())
    }

    /// Releases a list of challenges. Does nothing if `challenges` is null.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_challenges_free(challenges: *mut Vec<OAuthChallenge>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(challenges) }
    }

    /// Writes the number of challenges into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_challenges_count(challenges: *const Vec<OAuthChallenge>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let challenges = unsafe { Pointer::reference(challenges) }?;
            unsafe { Pointer::write(out, challenges.len()) }
        })())
    }

    /// Writes the scheme of the challenge `index` into `out_scheme`, the names of its parameters
    /// joined by LF into `out_names` and their values joined by LF into `out_values` (a quoted
    /// value has no LF, RFC 9110 §5.6.4).
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_challenges_get(challenges: *const Vec<OAuthChallenge>, index: usize, out_scheme: *mut Buffer, out_names: *mut Buffer, out_values: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_scheme, 1), Pointer::range(out_names, 1), Pointer::range(out_values, 1)])?;
            for output in [out_scheme, out_names, out_values] {
                Pointer::check_range(output, 1)?;
            }
            // SAFETY: the caller passes a valid handle and writable buffers.
            let challenges = unsafe { Pointer::reference(challenges) }?;
            let challenge = challenges.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            let names: Vec<&str> = challenge.parameters.iter().map(|(name, _)| name.as_str()).collect();
            let values: Vec<&str> = challenge.parameters.iter().map(|(_, value)| value.as_str()).collect();
            unsafe { Pointer::write_text(out_scheme, challenge.scheme.clone()) }?;
            unsafe { Pointer::write_text(out_names, names.join("\n")) }?;
            unsafe { Pointer::write_text(out_values, values.join("\n")) }
        })())
    }

    /// Writes the challenge of the scheme at `scheme` and the `count` parameters of the names at
    /// `names` and the values at `values`, as `WWW-Authenticate` carries it, into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_challenge_encode(scheme: *const u8, length: usize, names: *const *const Char, values: *const *const Char, count: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(scheme, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text, arrays of strings and a writable buffer.
            let scheme = unsafe { Pointer::text(scheme, length) }?;
            let names = unsafe { Pointer::strings(names, count) }?;
            let values = unsafe { Pointer::strings(values, count) }?;
            let challenge = OAuthChallenge { scheme: scheme.to_string(), parameters: names.into_iter().zip(values).collect() };
            let text = challenge.encode().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, text) }
        })())
    }

    /// Writes whether the `Authorization` value at `value` presents a token of the Bearer or
    /// DPoP scheme into `out_found`, the scheme (0 Bearer, 1 DPoP) into `out_scheme` and the
    /// token into `out_token` (RFC 6750 §2.1, RFC 9449 §7.1).
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_presented_token_from_authorization(value: *const u8, length: usize, out_found: *mut bool, out_scheme: *mut u8, out_token: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(value, length)], &[Pointer::range(out_found, 1), Pointer::range(out_scheme, 1), Pointer::range(out_token, 1)])?;
            for check in [Pointer::check_range(out_found, 1), Pointer::check_range(out_scheme, 1), Pointer::check_range(out_token, 1)] {
                check?;
            }
            // SAFETY: the caller passes readable text and writable pointers.
            let value = unsafe { Pointer::text(value, length) }?;
            let token = OAuthPresentedToken::from_authorization(value).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_found, token.is_some()) }?;
            unsafe { Pointer::write(out_scheme, token.as_ref().map_or(0, |token| OAuthStatus::scheme_value(token.scheme))) }?;
            unsafe { Pointer::write_text(out_token, token.map(|token| token.token).unwrap_or_default()) }
        })())
    }
}
