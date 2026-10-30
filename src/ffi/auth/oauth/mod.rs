//! The C ABI of [`crate::auth::oauth`].
//!
//! Messages cross as their text on the wire, as the other protocols' do: parameters as their
//! form encoding (through an [`OAuthParameters`] handle), documents and responses as their
//! JSON. A function that reads a message checks it with the Rust types and writes back its
//! canonical text. A scope crosses as its space-delimited text, a list of strings as text
//! joined by LF, a header field list as `name: value` lines joined by LF. A JWS algorithm is
//! its index in `JWSAlgorithm::ALL`, as in the JWT module. Random bytes come from a generator
//! handle of the random module and its type name (`random`, `random_type`).
//!
//! When the other side answered with an OAuth error (`OAuthError::Response`), the function
//! fails with the status `Response` and writes the JSON of the error response into its
//! `out_error` buffer.
//!
//! The clients, servers and resource servers are handles; so are the requests and responses
//! of their endpoints ([`OAuthEndpointRequest`], [`OAuthHTTPRequest`], [`OAuthHTTPResponse`]).

pub mod client;
pub mod dpop;
pub mod resource;
pub mod server;

pub use server::FFIOAuthServerLimits;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::c_void;

use crate::auth::oauth::{
    OAuthAuthorizationRequest, OAuthAuthorizationResponse, OAuthClientAuthentication, OAuthDeviceAuthorizationResponse,
    OAuthEndpointRequest, OAuthError, OAuthErrorCode, OAuthErrorResponse, OAuthHTTPRequest, OAuthHTTPResponse,
    OAuthIntrospectionResponse, OAuthMetadata, OAuthMetadataKind, OAuthParameters, OAuthPushedAuthorizationResponse,
    OAuthScope, OAuthTokenRequest, OAuthTokenResponse, PKCEChallenge, PKCEMethod, PKCEVerifier,
};
use crate::ffi::auth::cert::key::KeyStatus;
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Buffer, Char, Definition, Function, Module, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::jwt::{JWK, JWSAlgorithm};
use crate::secret::Secret;

impl Value for OAuthParameters {
    const TYPE: Type = Type::Named("umilib_auth_oauth_OAuthParameters");
}

impl Value for PKCEVerifier {
    const TYPE: Type = Type::Named("umilib_auth_oauth_PKCEVerifier");
}

impl Value for OAuthEndpointRequest {
    const TYPE: Type = Type::Named("umilib_auth_oauth_OAuthEndpointRequest");
}

impl Value for OAuthHTTPRequest {
    const TYPE: Type = Type::Named("umilib_auth_oauth_OAuthHTTPRequest");
}

impl Value for OAuthHTTPResponse {
    const TYPE: Type = Type::Named("umilib_auth_oauth_OAuthHTTPResponse");
}

/// The statuses of [`OAuthError`], one per variant of its own (the errors it wraps keep their
/// modules' statuses).
pub struct OAuthStatus;

impl OAuthStatus {
    pub const REPEATED: Status = Status::new(c"auth.oauth", c"Repeated", c"a parameter is given more than once");
    pub const MISSING: Status = Status::new(c"auth.oauth", c"Missing", c"a required parameter is missing");
    pub const INVALID: Status = Status::new(c"auth.oauth", c"Invalid", c"a parameter is not valid");
    pub const RESPONSE: Status =
        Status::new(c"auth.oauth", c"Response", c"the other side answered with an OAuth error");
    pub const STATE: Status = Status::new(c"auth.oauth", c"State", c"a state that matches no pending request");
    pub const ISSUER: Status = Status::new(c"auth.oauth", c"Issuer", c"an issuer that is not the one expected");
    pub const LIMIT: Status = Status::new(c"auth.oauth", c"Limit", c"a configured limit was reached");

    /// The [`PKCEMethod`] values of the C ABI: `0` S256.
    pub fn method(value: u8) -> Result<PKCEMethod, &'static Status> {
        match value {
            0 => Ok(PKCEMethod::S256),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    /// The [`OAuthMetadataKind`] values of the C ABI: `0` Server, `1` Resource.
    pub fn kind(value: u8) -> Result<OAuthMetadataKind, &'static Status> {
        match value {
            0 => Ok(OAuthMetadataKind::Server),
            1 => Ok(OAuthMetadataKind::Resource),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    /// The JWS algorithm of index `index` in `JWSAlgorithm::ALL`.
    pub fn algorithm(index: u8) -> Result<JWSAlgorithm, &'static Status> {
        KeyStatus::index(&JWSAlgorithm::ALL, index)
    }

    /// The JWS algorithms of the `count` indices at `indices`.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn algorithms(indices: *const u8, count: usize) -> Result<Vec<JWSAlgorithm>, &'static Status> {
        // SAFETY: guaranteed by the caller.
        let indices = unsafe { Pointer::slice(indices, count) }?;
        indices.iter().map(|&index| OAuthStatus::algorithm(index)).collect()
    }

    /// The status of `error`, and the JSON of the error response into `out_error` when it is
    /// [`OAuthError::Response`] and `out_error` is not null.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn fail(error: OAuthError, out_error: *mut Buffer) -> &'static Status {
        if let OAuthError::Response(response) = &error
            && !out_error.is_null()
        {
            // SAFETY: guaranteed by the caller; the pointer is not null.
            if let Err(status) = unsafe { Pointer::write_text(out_error, response.encode()) } {
                return status;
            }
        }
        error.to_status()
    }

    /// The lines of `pairs`: `name: value`, joined by LF.
    pub fn header_lines(pairs: &[(String, String)]) -> String {
        pairs.iter().map(|(name, value)| alloc::format!("{name}: {value}")).collect::<Vec<_>>().join("\n")
    }

    /// The pairs of `name: value` lines joined by LF.
    pub fn header_pairs(text: &str) -> Result<Vec<(String, String)>, &'static Status> {
        text.split('\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (name, value) = line.split_once(':').ok_or(&Status::INVALID_ARGUMENT)?;
                Ok((name.trim().to_string(), value.trim().to_string()))
            })
            .collect()
    }

    /// The scope of the text at `scope`, or `None` for a null pointer.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn scope(scope: *const u8, length: usize) -> Result<Option<OAuthScope>, &'static Status> {
        // SAFETY: guaranteed by the caller.
        let text = unsafe { Pointer::optional_text(scope, length) }?;
        text.map(|text| OAuthScope::parse(text).map_err(|error| error.to_status())).transpose()
    }

    /// A random source of the C ABI.
    ///
    /// # Safety
    ///
    /// See [`RandomSource::from_handle`].
    pub unsafe fn random<'a>(
        random: *mut c_void,
        kind: *const u8,
        length: usize,
    ) -> Result<RandomSource<'a>, &'static Status> {
        // SAFETY: guaranteed by the caller.
        unsafe { RandomSource::from_handle(random, kind, length) }
    }

    /// The client authentication of `method` (0 none, 1 client_secret_basic, 2
    /// client_secret_post, 3 private_key_jwt) for `client_id`, with `secret` for the secret
    /// methods and `key` and `algorithm` for private_key_jwt.
    pub fn authentication(
        method: u8,
        client_id: &str,
        secret: Option<&str>,
        key: Option<&JWK>,
        algorithm: u8,
    ) -> Result<OAuthClientAuthentication, &'static Status> {
        let client_id = client_id.to_string();
        let secret = || secret.map(|secret| Secret::new(secret.to_string())).ok_or(&Status::NULL_POINTER);
        Ok(match method {
            0 => OAuthClientAuthentication::None { client_id },
            1 => OAuthClientAuthentication::SecretBasic { client_id, secret: secret()? },
            2 => OAuthClientAuthentication::SecretPost { client_id, secret: secret()? },
            3 => OAuthClientAuthentication::PrivateKeyJWT {
                client_id,
                key: alloc::boxed::Box::new(key.ok_or(&Status::NULL_POINTER)?.clone()),
                algorithm: OAuthStatus::algorithm(algorithm)?,
            },
            _ => return Err(&Status::INVALID_ARGUMENT),
        })
    }
}

impl ToStatus for OAuthError {
    fn to_status(&self) -> &'static Status {
        match self {
            OAuthError::Repeated { .. } => &OAuthStatus::REPEATED,
            OAuthError::Missing { .. } => &OAuthStatus::MISSING,
            OAuthError::Invalid { .. } => &OAuthStatus::INVALID,
            OAuthError::Response(_) => &OAuthStatus::RESPONSE,
            OAuthError::State => &OAuthStatus::STATE,
            OAuthError::Issuer => &OAuthStatus::ISSUER,
            OAuthError::Limit => &OAuthStatus::LIMIT,
            OAuthError::URI(error) => error.to_status(),
            OAuthError::JSON(error) => error.to_status(),
            OAuthError::JWT(error) => error.to_status(),
            OAuthError::Random(error) => error.to_status(),
        }
    }
}

crate::ffi_functions! {
    // Parameters.

    /// Writes an empty list of parameters into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_parameters_new(out: *mut *mut OAuthParameters) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, OAuthParameters::new()) })
    }

    /// Releases a list of parameters. Does nothing if `parameters` is null.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_parameters_free(parameters: *mut OAuthParameters) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(parameters) }
    }

    /// Writes the parameters of the form-encoded `length` bytes at `input` into `out`: those
    /// named by the `count` strings at `repeatable` may be given more than once.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_parameters_parse(input: *const u8, length: usize, repeatable: *const *const Char, count: usize, out: *mut *mut OAuthParameters) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes, an array of strings and a writable pointer.
            let input = unsafe { Pointer::slice(input, length) }?;
            let repeatable = unsafe { Pointer::strings(repeatable, count) }?;
            Pointer::check_range(out, 1)?;
            let names: Vec<&str> = repeatable.iter().map(String::as_str).collect();
            let parameters = OAuthParameters::parse_with(input, &names).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, parameters) }
        })())
    }

    /// Writes the parameters of the query of the URI reference at `uri` into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_parameters_from_query(uri: *const u8, length: usize, out: *mut *mut OAuthParameters) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let uri = unsafe { Pointer::text(uri, length) }?;
            Pointer::check_range(out, 1)?;
            let reference = crate::codec::uri::URIReference::parse(uri).map_err(|error| error.to_status())?;
            let parameters = OAuthParameters::from_query(&reference).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, parameters) }
        })())
    }

    /// Writes the URI reference at `uri` with the parameters added to its query into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_parameters_add_to_query(parameters: *const OAuthParameters, uri: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(uri, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable text and a writable buffer.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            let uri = unsafe { Pointer::text(uri, length) }?;
            let reference = crate::codec::uri::URIReference::parse(uri).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, parameters.add_to_query(&reference).to_string()) }
        })())
    }

    /// Writes the number of parameters into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_parameters_count(parameters: *const OAuthParameters, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            unsafe { Pointer::write(out, parameters.pairs().len()) }
        })())
    }

    /// Writes the name of the parameter `index` into `out_name` and its value into `out_value`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_parameters_entry(parameters: *const OAuthParameters, index: usize, out_name: *mut Buffer, out_value: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_name, 1), Pointer::range(out_value, 1)])?;
            Pointer::check_range(out_name, 1)?;
            Pointer::check_range(out_value, 1)?;
            // SAFETY: the caller passes a valid handle and writable buffers.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            let (name, value) = parameters.pairs().get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_text(out_name, name.clone()) }?;
            unsafe { Pointer::write_text(out_value, value.clone()) }
        })())
    }

    /// Writes whether the parameter of the name at `name` is present into `out_has` and its
    /// first value into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_parameters_get(parameters: *const OAuthParameters, name: *const u8, length: usize, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(name, length)], &[Pointer::range(out_has, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable text and writable pointers.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            let name = unsafe { Pointer::text(name, length) }?;
            unsafe { Pointer::write_optional_text(out_has, out, parameters.get(name)) }
        })())
    }

    /// Appends the parameter of the UTF-8 `name` and `value`; an empty value is not added.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_parameters_push(parameters: *mut OAuthParameters, name: *const u8, name_length: usize, value: *const u8, value_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let name = unsafe { Pointer::text(name, name_length) }?;
            let value = unsafe { Pointer::text(value, value_length) }?;
            let parameters = unsafe { Pointer::reference_mut(parameters) }?;
            parameters.push(name, value);
            Ok(())
        })())
    }

    /// Removes every value of the parameter of the name at `name`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_parameters_remove(parameters: *mut OAuthParameters, name: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let name = unsafe { Pointer::text(name, length) }?;
            let parameters = unsafe { Pointer::reference_mut(parameters) }?;
            parameters.remove(name);
            Ok(())
        })())
    }

    /// Writes the parameters in the form encoding into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_parameters_encode(parameters: *const OAuthParameters, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            unsafe { Pointer::write_text(out, parameters.encode()) }
        })())
    }

    // Scopes.

    /// Writes the scope of the space-delimited text at `scope` (RFC 6749 §3.3), each token once,
    /// into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_scope_parse(scope: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(scope, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable buffer.
            let scope = unsafe { Pointer::text(scope, length) }?;
            let scope = OAuthScope::parse(scope).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, scope.to_string()) }
        })())
    }

    /// Writes whether every token of the scope at `scope` is in the scope at `other` into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_scope_is_subset_of(scope: *const u8, length: usize, other: *const u8, other_length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(scope, length), Pointer::range(other, other_length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable pointer.
            let scope = unsafe { OAuthStatus::scope(scope, length) }?.ok_or(&Status::NULL_POINTER)?;
            let other = unsafe { OAuthStatus::scope(other, other_length) }?.ok_or(&Status::NULL_POINTER)?;
            unsafe { Pointer::write(out, scope.is_subset_of(&other)) }
        })())
    }

    /// Writes the tokens of the scope at `scope` that are in the scope at `other` into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_scope_intersection(scope: *const u8, length: usize, other: *const u8, other_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(scope, length), Pointer::range(other, other_length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable buffer.
            let scope = unsafe { OAuthStatus::scope(scope, length) }?.ok_or(&Status::NULL_POINTER)?;
            let other = unsafe { OAuthStatus::scope(other, other_length) }?.ok_or(&Status::NULL_POINTER)?;
            unsafe { Pointer::write_text(out, scope.intersection(&other).to_string()) }
        })())
    }

    // PKCE.

    /// Writes the code verifier of the text at `text` (RFC 7636 §4.1) into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_pkce_verifier_new(text: *const u8, length: usize, out: *mut *mut PKCEVerifier) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            Pointer::check_range(out, 1)?;
            let verifier = PKCEVerifier::new(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, verifier) }
        })())
    }

    /// Writes a code verifier of 32 random octets into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_pkce_verifier_generate(random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut PKCEVerifier) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a generator handle of the named type and a writable pointer.
            let mut random = unsafe { OAuthStatus::random(random, random_type, random_type_length) }?;
            Pointer::check_range(out, 1)?;
            let verifier = PKCEVerifier::generate(&mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, verifier) }
        })())
    }

    /// Zeroizes and releases a verifier. Does nothing if `verifier` is null.
    pub unsafe extern "C" fn umilib_auth_oauth_pkce_verifier_free(verifier: *mut PKCEVerifier) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(verifier) }
    }

    /// Writes the verifier's text into `out`, which the caller zeroizes.
    pub unsafe extern "C" fn umilib_auth_oauth_pkce_verifier_text(verifier: *const PKCEVerifier, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let verifier = unsafe { Pointer::reference(verifier) }?;
            unsafe { Pointer::write_text(out, verifier.as_str().to_string()) }
        })())
    }

    /// Writes the challenge of the verifier by `method` (0 S256) into `out` (RFC 7636 §4.2).
    pub unsafe extern "C" fn umilib_auth_oauth_pkce_verifier_challenge(verifier: *const PKCEVerifier, method: u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let verifier = unsafe { Pointer::reference(verifier) }?;
            let method = OAuthStatus::method(method)?;
            unsafe { Pointer::write_text(out, verifier.challenge(method).value) }
        })())
    }

    /// Writes the method of the name at `name` (`S256`; `plain` and others fail) into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_pkce_method_parse(name: *const u8, length: usize, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(name, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable pointer.
            let name = unsafe { Pointer::text(name, length) }?;
            let method = PKCEMethod::parse(name).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, match method { PKCEMethod::S256 => 0 }) }
        })())
    }

    /// Succeeds if the text at `value` is a challenge of `method` (0 S256).
    pub unsafe extern "C" fn umilib_auth_oauth_pkce_challenge_check(method: u8, value: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text.
            let value = unsafe { Pointer::text(value, length) }?;
            PKCEChallenge::new(OAuthStatus::method(method)?, value).map_err(|error| error.to_status())?;
            Ok(())
        })())
    }

    /// Writes whether `verifier` is the verifier of the challenge at `value` of `method` (RFC 7636
    /// §4.6, compared in constant time) into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_pkce_challenge_verify(method: u8, value: *const u8, length: usize, verifier: *const PKCEVerifier, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(value, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text, a valid handle and a writable pointer.
            let value = unsafe { Pointer::text(value, length) }?;
            let verifier = unsafe { Pointer::reference(verifier) }?;
            let challenge = PKCEChallenge::new(OAuthStatus::method(method)?, value).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, challenge.verify(verifier)) }
        })())
    }

    // Error responses.

    /// Writes the JSON of the error response of the code at `code`, the description at
    /// `description` and the URI at `uri` (null for none), checked against RFC 6749 Appendix A,
    /// into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_error_response_encode(code: *const u8, code_length: usize, description: *const u8, description_length: usize, uri: *const u8, uri_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(code, code_length), Pointer::range(description, description_length), Pointer::range(uri, uri_length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text or null and a writable buffer.
            let code = unsafe { Pointer::text(code, code_length) }?;
            let description = unsafe { Pointer::optional_text(description, description_length) }?;
            let uri = unsafe { Pointer::optional_text(uri, uri_length) }?;
            let response = OAuthErrorResponse {
                code: OAuthErrorCode::parse(code).map_err(|error| error.to_status())?,
                description: description.map(str::to_string),
                uri: uri.map(str::to_string),
            };
            response.check().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, response.encode()) }
        })())
    }

    /// Writes the code, whether there is a description, the description, whether there is a
    /// URI and the URI of the error response of the JSON at `body` (RFC 6749 §5.2).
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_error_response_decode(body: *const u8, length: usize, out_code: *mut Buffer, out_has_description: *mut bool, out_description: *mut Buffer, out_has_uri: *mut bool, out_uri: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let outputs = [Pointer::range(out_code, 1), Pointer::range(out_has_description, 1), Pointer::range(out_description, 1), Pointer::range(out_has_uri, 1), Pointer::range(out_uri, 1)];
            Pointer::check_ranges(&[Pointer::range(body, length)], &outputs)?;
            Pointer::check_range(out_code, 1)?;
            Pointer::check_range(out_has_description, 1)?;
            Pointer::check_range(out_description, 1)?;
            Pointer::check_range(out_has_uri, 1)?;
            Pointer::check_range(out_uri, 1)?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let body = unsafe { Pointer::slice(body, length) }?;
            let response = match OAuthTokenResponse::decode(400, body) {
                Err(OAuthError::Response(response)) => response,
                Err(error) => return Err(error.to_status()),
                Ok(_) => return Err(&OAuthStatus::INVALID),
            };
            unsafe { Pointer::write_optional_text(out_has_description, out_description, response.description.as_deref()) }?;
            unsafe { Pointer::write_optional_text(out_has_uri, out_uri, response.uri.as_deref()) }?;
            unsafe { Pointer::write_text(out_code, response.code.as_str().to_string()) }
        })())
    }

    // Messages: each read from its parameters or JSON and written back canonical.

    /// Writes the canonical parameters of the authorization request of `parameters` (RFC 6749
    /// §4.1.1, RFC 7636 §4.3, RFC 8707, RFC 9126 §4, RFC 9449 §10) into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_authorization_request_check(parameters: *const OAuthParameters, out: *mut *mut OAuthParameters) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            Pointer::check_range(out, 1)?;
            let request = OAuthAuthorizationRequest::from_parameters(parameters).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, request.to_parameters()) }
        })())
    }

    /// Writes the canonical parameters of the authorization response of `parameters` (RFC 6749
    /// §4.1.2, RFC 9207) into `out`; an error response fails with Response.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_authorization_response_check(parameters: *const OAuthParameters, out: *mut *mut OAuthParameters, out_error: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a valid handle and writable pointers.
        let result = (|| {
            let parameters = unsafe { Pointer::reference(parameters) }.map_err(|status| (status, None))?;
            Pointer::check_range(out, 1).map_err(|status| (status, None))?;
            let response = OAuthAuthorizationResponse::from_parameters(parameters).map_err(|error| (&OAuthStatus::RESPONSE, Some(error)))?;
            unsafe { Pointer::write_handle(out, response.to_parameters()) }.map_err(|status| (status, None))
        })();
        match result {
            Ok(()) => core::ptr::null(),
            Err((_, Some(error))) => unsafe { OAuthStatus::fail(error, out_error) },
            Err((status, None)) => status,
        }
    }

    /// Writes the canonical parameters of the token request of `parameters` (RFC 6749 §3.2,
    /// §4.1.3, §4.4.2, §6; RFC 8628 §3.4; RFC 7523 §2.1), without client authentication, into
    /// `out`; an unknown grant type fails with Invalid.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_token_request_check(parameters: *const OAuthParameters, out: *mut *mut OAuthParameters) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            Pointer::check_range(out, 1)?;
            let request = OAuthTokenRequest::from_parameters(parameters).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, request.to_parameters()) }
        })())
    }

    /// Writes the canonical JSON of the token response of `status` and the body at `body`
    /// (RFC 6749 §5.1) into `out`; an error response fails with Response.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_token_response_decode(status: u16, body: *const u8, length: usize, out: *mut Buffer, out_error: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes readable bytes and writable buffers.
        unsafe { OAuthStatus::document(body, length, out, out_error, |body| OAuthTokenResponse::decode(status, body).map(|response| response.encode())) }
    }

    /// Writes the canonical JSON of the introspection response of `status` and `body` (RFC 7662
    /// §2.2) into `out`; an error response fails with Response.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_introspection_response_decode(status: u16, body: *const u8, length: usize, out: *mut Buffer, out_error: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes readable bytes and writable buffers.
        unsafe { OAuthStatus::document(body, length, out, out_error, |body| OAuthIntrospectionResponse::decode(status, body).map(|response| response.encode())) }
    }

    /// Writes the canonical JSON of the device authorization response of `status` and `body`
    /// (RFC 8628 §3.2) into `out`; an error response fails with Response.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_device_authorization_response_decode(status: u16, body: *const u8, length: usize, out: *mut Buffer, out_error: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes readable bytes and writable buffers.
        unsafe { OAuthStatus::document(body, length, out, out_error, |body| OAuthDeviceAuthorizationResponse::decode(status, body).map(|response| response.encode())) }
    }

    /// Writes the canonical JSON of the pushed authorization response of `status` and `body`
    /// (RFC 9126 §2.2) into `out`; an error response fails with Response.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_pushed_authorization_response_decode(status: u16, body: *const u8, length: usize, out: *mut Buffer, out_error: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes readable bytes and writable buffers.
        unsafe { OAuthStatus::document(body, length, out, out_error, |body| OAuthPushedAuthorizationResponse::decode(status, body).map(|response| response.encode())) }
    }

    // Metadata.

    /// Writes the canonical JSON of the metadata document of `kind` (0 server, RFC 8414; 1
    /// resource, RFC 9728) at `body` into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_metadata_decode(kind: u8, body: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(body, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let body = unsafe { Pointer::slice(body, length) }?;
            let metadata = OAuthMetadata::decode(OAuthStatus::kind(kind)?, body).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, metadata.encode()) }
        })())
    }

    /// Succeeds if the metadata document of `kind` at `body` describes the identifier at
    /// `expected` (RFC 8414 §3.3, RFC 9728 §3.3); fails with Issuer otherwise.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_metadata_check(kind: u8, body: *const u8, length: usize, expected: *const u8, expected_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and text.
            let body = unsafe { Pointer::slice(body, length) }?;
            let expected = unsafe { Pointer::text(expected, expected_length) }?;
            let metadata = OAuthMetadata::decode(OAuthStatus::kind(kind)?, body).map_err(|error| error.to_status())?;
            metadata.check(expected).map_err(|error| error.to_status())
        })())
    }

    /// Writes the URL of the metadata document of `kind` of the identifier at `identifier`
    /// (RFC 8414 §3.1, RFC 9728 §3.1) into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_metadata_location(kind: u8, identifier: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(identifier, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable buffer.
            let identifier = unsafe { Pointer::text(identifier, length) }?;
            let location = OAuthMetadata::location(OAuthStatus::kind(kind)?, identifier).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, location) }
        })())
    }

    // Client authentication.

    /// Adds the client authentication of `method` (0 none, 1 client_secret_basic, 2
    /// client_secret_post, 3 private_key_jwt) of the client at `client_id`, with the secret at
    /// `secret` or the private `key` and the JWS algorithm `algorithm`, to a request to the
    /// server `audience` at `now`, an assertion living `lifetime` seconds (RFC 6749 §2.3,
    /// RFC 7523 §2.2): parameters go into
    /// `parameters`; whether there is an `Authorization` header goes into `out_has` and its
    /// value, which the caller zeroizes, into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_client_authentication_apply(method: u8, client_id: *const u8, client_id_length: usize, secret: *const u8, secret_length: usize, key: *const JWK, algorithm: u8, audience: *const u8, audience_length: usize, now: i64, lifetime: i64, random: *mut c_void, random_type: *const u8, random_type_length: usize, parameters: *mut OAuthParameters, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(client_id, client_id_length), Pointer::range(secret, secret_length), Pointer::range(audience, audience_length)], &[Pointer::range(out_has, 1), Pointer::range(out, 1)])?;
            Pointer::check_range(out_has, 1)?;
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes readable text or null, valid handles and writable pointers.
            let client_id = unsafe { Pointer::text(client_id, client_id_length) }?;
            let secret = unsafe { Pointer::optional_text(secret, secret_length) }?;
            let key = if key.is_null() { None } else { Some(unsafe { Pointer::reference(key) }?) };
            let audience = unsafe { Pointer::text(audience, audience_length) }?;
            let mut random = unsafe { OAuthStatus::random(random, random_type, random_type_length) }?;
            let parameters = unsafe { Pointer::reference_mut(parameters) }?;
            let authentication = OAuthStatus::authentication(method, client_id, secret, key, algorithm)?;
            let header = authentication.apply(audience, now, lifetime, &mut random, parameters).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_optional_text(out_has, out, header.as_ref().map(|header| header.expose().as_str())) }
        })())
    }

    /// Writes the value of the `Authorization` header of client_secret_basic for the client
    /// at `client_id` and the secret at `secret` (RFC 6749 §2.3.1) into `out`, which the caller
    /// zeroizes.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_client_authentication_basic_credentials(client_id: *const u8, client_id_length: usize, secret: *const u8, secret_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(client_id, client_id_length), Pointer::range(secret, secret_length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable buffer.
            let client_id = unsafe { Pointer::text(client_id, client_id_length) }?;
            let secret = unsafe { Pointer::text(secret, secret_length) }?;
            let header = OAuthClientAuthentication::basic_credentials(client_id, secret);
            unsafe { Pointer::write_text(out, header.expose().clone()) }
        })())
    }

    // Requests and responses of endpoints.

    /// Writes a request of the method at `method`, the URI at `uri` and the `length` bytes at
    /// `body`, without header fields, into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_endpoint_request_new(method: *const u8, method_length: usize, uri: *const u8, uri_length: usize, body: *const u8, length: usize, out: *mut *mut OAuthEndpointRequest) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let method = unsafe { Pointer::text(method, method_length) }?;
            let uri = unsafe { Pointer::text(uri, uri_length) }?;
            let body = unsafe { Pointer::slice(body, length) }?;
            let request = OAuthEndpointRequest { method: method.to_string(), uri: uri.to_string(), body: body.to_vec(), ..OAuthEndpointRequest::default() };
            unsafe { Pointer::write_handle(out, request) }
        })())
    }

    /// Releases a request. Does nothing if `request` is null.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_endpoint_request_free(request: *mut OAuthEndpointRequest) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(request) }
    }

    /// Sets the `Authorization`, `DPoP` and `Content-Type` header fields of the request to the
    /// texts at `authorization`, `dpop` and `content_type` (null for none).
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_endpoint_request_set_fields(request: *mut OAuthEndpointRequest, authorization: *const u8, authorization_length: usize, dpop: *const u8, dpop_length: usize, content_type: *const u8, content_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text or null.
            let authorization = unsafe { Pointer::optional_text(authorization, authorization_length) }?;
            let dpop = unsafe { Pointer::optional_text(dpop, dpop_length) }?;
            let content_type = unsafe { Pointer::optional_text(content_type, content_type_length) }?;
            let request = unsafe { Pointer::reference_mut(request) }?;
            request.authorization = authorization.map(str::to_string);
            request.dpop = dpop.map(str::to_string);
            request.content_type = content_type.map(str::to_string);
            Ok(())
        })())
    }

    /// Releases a request made by a client. Does nothing if `request` is null.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_http_request_free(request: *mut OAuthHTTPRequest) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(request) }
    }

    /// Writes the method, the URI, the header fields (`name: value` lines joined by LF) and the
    /// body of a request made by a client into the outputs; the caller zeroizes the fields and
    /// the body, which may hold secrets.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_http_request_parts(request: *const OAuthHTTPRequest, out_method: *mut Buffer, out_uri: *mut Buffer, out_headers: *mut Buffer, out_body: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let outputs = [Pointer::range(out_method, 1), Pointer::range(out_uri, 1), Pointer::range(out_headers, 1), Pointer::range(out_body, 1)];
            Pointer::check_ranges(&[], &outputs)?;
            for output in [out_method, out_uri, out_headers, out_body] {
                Pointer::check_range(output, 1)?;
            }
            // SAFETY: the caller passes a valid handle and writable buffers.
            let request = unsafe { Pointer::reference(request) }?;
            unsafe { Pointer::write_text(out_method, request.method.clone()) }?;
            unsafe { Pointer::write_text(out_uri, request.uri.clone()) }?;
            unsafe { Pointer::write_text(out_headers, OAuthStatus::header_lines(&request.headers)) }?;
            unsafe { Pointer::write(out_body, Buffer::from_vec(request.body.clone())) }
        })())
    }

    /// Releases a response. Does nothing if `response` is null.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_http_response_free(response: *mut OAuthHTTPResponse) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(response) }
    }

    /// Writes the status, the header fields (`name: value` lines joined by LF) and the body of a
    /// response into the outputs.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_http_response_parts(response: *const OAuthHTTPResponse, out_status: *mut u16, out_headers: *mut Buffer, out_body: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_status, 1), Pointer::range(out_headers, 1), Pointer::range(out_body, 1)])?;
            Pointer::check_range(out_status, 1)?;
            Pointer::check_range(out_headers, 1)?;
            Pointer::check_range(out_body, 1)?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let response = unsafe { Pointer::reference(response) }?;
            unsafe { Pointer::write(out_status, response.status) }?;
            unsafe { Pointer::write_text(out_headers, OAuthStatus::header_lines(&response.headers)) }?;
            unsafe { Pointer::write(out_body, Buffer::from_vec(response.body.clone())) }
        })())
    }
}

impl OAuthStatus {
    /// The canonical text `read` makes of the `length` bytes at `body`, into `out`; an error
    /// response fails with Response and its JSON goes into `out_error`.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn document(
        body: *const u8,
        length: usize,
        out: *mut Buffer,
        out_error: *mut Buffer,
        read: impl FnOnce(&[u8]) -> Result<String, OAuthError>,
    ) -> *const Status {
        let ranges = Pointer::check_ranges(
            &[Pointer::range(body, length)],
            &[Pointer::range(out, 1), Pointer::range(out_error, 1)],
        );
        if let Err(status) = ranges.and_then(|()| Pointer::check_range(out, 1)) {
            return status;
        }
        // SAFETY: guaranteed by the caller.
        let body = match unsafe { Pointer::slice(body, length) } {
            Ok(body) => body,
            Err(status) => return status,
        };
        match read(body) {
            // SAFETY: guaranteed by the caller; `out` is not null.
            Ok(text) => Status::from_result(unsafe { Pointer::write_text(out, text) }),
            // SAFETY: guaranteed by the caller.
            Err(error) => unsafe { OAuthStatus::fail(error, out_error) },
        }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "oauth",
    definitions: &[
        Definition::Opaque {
            name: "umilib_auth_oauth_OAuthParameters",
            documentation: " The parameters of a request or a response, in order.",
        },
        Definition::Opaque {
            name: "umilib_auth_oauth_PKCEVerifier",
            documentation: " A PKCE code verifier, zeroized when released.",
        },
        Definition::Opaque {
            name: "umilib_auth_oauth_OAuthEndpointRequest",
            documentation: " A request that reached an endpoint.",
        },
        Definition::Opaque {
            name: "umilib_auth_oauth_OAuthHTTPRequest",
            documentation: " A request a client asks to send.",
        },
        Definition::Opaque {
            name: "umilib_auth_oauth_OAuthHTTPResponse",
            documentation: " The response of an endpoint.",
        },
        Definition::Opaque {
            name: "umilib_auth_oauth_OAuthClient",
            documentation: " A client of the authorization code grant and the token endpoint.",
        },
        Definition::Opaque { name: "umilib_auth_oauth_OAuthServer", documentation: " An authorization server." },
        Definition::Opaque {
            name: "umilib_auth_oauth_OAuthServerConfig",
            documentation: " The configuration of an authorization server.",
        },
        server::LIMITS,
        Definition::Opaque {
            name: "umilib_auth_oauth_OAuthAuthorization",
            documentation: " An authorization request waiting for the user's decision.",
        },
        Definition::Opaque {
            name: "umilib_auth_oauth_OAuthResourceServer",
            documentation: " The checks of a protected resource.",
        },
        Definition::Opaque {
            name: "umilib_auth_oauth_OAuthTokenInfo",
            documentation: " What a resource server knows of a token it took.",
        },
        Definition::Opaque {
            name: "umilib_auth_oauth_OAuthResourceError",
            documentation: " A refusal of a resource server.",
        },
        Definition::Opaque {
            name: "umilib_auth_oauth_OAuthChallenges",
            documentation: " The challenges of a WWW-Authenticate value.",
        },
        Definition::Opaque {
            name: "umilib_auth_oauth_DPoPVerifier",
            documentation: " The checks of DPoP proofs that keep state.",
        },
    ],
    functions: &Function::concat::<
        {
            FUNCTIONS.len()
                + client::FUNCTIONS.len()
                + server::FUNCTIONS.len()
                + resource::FUNCTIONS.len()
                + dpop::FUNCTIONS.len()
        },
    >(&[FUNCTIONS, client::FUNCTIONS, server::FUNCTIONS, resource::FUNCTIONS, dpop::FUNCTIONS]),
    modules: &[],
};
