//! The C ABI of [`OAuthClient`].

use alloc::string::ToString;
use core::ffi::c_void;

use super::OAuthStatus;
use crate::auth::oauth::{
    OAuthClient, OAuthClientConfig, OAuthHTTPRequest, OAuthMetadata, OAuthMetadataKind, OAuthParameters,
    OAuthTokenRequest,
};
use crate::codec::uri::URIReference;
use crate::ffi::{Buffer, Char, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::jwt::JWK;

impl Value for OAuthClient {
    const TYPE: Type = Type::Named("umilib_auth_oauth_OAuthClient");
}

crate::ffi_functions! {
    /// Writes a client of the server whose metadata document (checked against its issuer) is
    /// the JSON at `metadata` into `out`: it authenticates with `method` (0 none, 1
    /// client_secret_basic, 2 client_secret_post, 3 private_key_jwt) as the client at
    /// `client_id`, with the secret at `secret` or the private `key` and the JWS algorithm
    /// `algorithm`, and is redirected to the URI at `redirect_uri`; the limits are the defaults.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_client_new(metadata: *const u8, metadata_length: usize, method: u8, client_id: *const u8, client_id_length: usize, secret: *const u8, secret_length: usize, key: *const JWK, algorithm: u8, redirect_uri: *const u8, redirect_uri_length: usize, out: *mut *mut OAuthClient) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and text or null, a valid key or null and a writable pointer.
            let metadata = unsafe { Pointer::slice(metadata, metadata_length) }?;
            let client_id = unsafe { Pointer::text(client_id, client_id_length) }?;
            let secret = unsafe { Pointer::optional_text(secret, secret_length) }?;
            let key = if key.is_null() { None } else { Some(unsafe { Pointer::reference(key) }?) };
            let redirect_uri = unsafe { Pointer::text(redirect_uri, redirect_uri_length) }?;
            Pointer::check_range(out, 1)?;
            let metadata = OAuthMetadata::decode(OAuthMetadataKind::Server, metadata).map_err(|error| error.to_status())?;
            let authentication = OAuthStatus::authentication(method, client_id, secret, key, algorithm)?;
            let config = OAuthClientConfig::from_metadata(&metadata, authentication, redirect_uri).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, OAuthClient::new(config)) }
        })())
    }

    /// Releases a client. Does nothing if `client` is null.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_client_free(client: *mut OAuthClient) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(client) }
    }

    /// Writes the limits of the client: the most pending requests, their lifetime in seconds,
    /// the random octets of a state, and the seconds a client assertion lives.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_client_limits(client: *const OAuthClient, out_maximum_pending: *mut usize, out_pending_lifetime: *mut i64, out_state_octets: *mut usize, out_assertion_lifetime: *mut i64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_maximum_pending, 1), Pointer::range(out_pending_lifetime, 1), Pointer::range(out_state_octets, 1), Pointer::range(out_assertion_lifetime, 1)])?;
            Pointer::check_range(out_maximum_pending, 1)?;
            Pointer::check_range(out_pending_lifetime, 1)?;
            Pointer::check_range(out_state_octets, 1)?;
            Pointer::check_range(out_assertion_lifetime, 1)?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let config = unsafe { Pointer::reference(client) }?.config();
            unsafe { Pointer::write(out_maximum_pending, config.maximum_pending) }?;
            unsafe { Pointer::write(out_pending_lifetime, config.pending_lifetime) }?;
            unsafe { Pointer::write(out_state_octets, config.state_octets) }?;
            unsafe { Pointer::write(out_assertion_lifetime, config.assertion_lifetime) }
        })())
    }

    /// Writes the number of authorization requests waiting for their response into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_client_pending_count(client: *const OAuthClient, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write(out, client.pending().len()) }
        })())
    }

    /// Writes the URL to send the user's browser to (RFC 6749 §4.1.1 with PKCE, RFC 7636 §4.3)
    /// for the scope at `scope` (null for none) and the `count` resources at `resources`, at
    /// `now`, into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_client_authorize(client: *mut OAuthClient, scope: *const u8, scope_length: usize, resources: *const *const Char, count: usize, now: i64, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(scope, scope_length)], &[Pointer::range(out, 1)])?;
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes a valid handle, readable text or null, an array of strings, a generator and a writable buffer.
            let scope = unsafe { OAuthStatus::scope(scope, scope_length) }?;
            let resources = unsafe { Pointer::strings(resources, count) }?;
            let mut random = unsafe { OAuthStatus::random(random, random_type, random_type_length) }?;
            let client = unsafe { Pointer::reference_mut(client) }?;
            let resources: alloc::vec::Vec<&str> = resources.iter().map(alloc::string::String::as_str).collect();
            let url = client.authorize(scope.as_ref(), &resources, now, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, url.to_string()) }
        })())
    }

    /// Writes the canonical parameters of the token request of the authorization response at
    /// the URI `redirect` (RFC 6749 §4.1.2, §10.12; RFC 9207 §2.4) into `out`; an error
    /// response fails with Response after the same checks, its JSON into `out_error`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_client_callback(client: *mut OAuthClient, redirect: *const u8, length: usize, now: i64, out: *mut *mut OAuthParameters, out_error: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a valid handle, readable text and writable pointers.
        let checked: Result<_, &'static Status> = (|| {
            Pointer::check_ranges(&[Pointer::range(redirect, length)], &[Pointer::range(out, 1), Pointer::range(out_error, 1)])?;
            let redirect = unsafe { Pointer::text(redirect, length) }?;
            Pointer::check_range(out, 1)?;
            let reference = URIReference::parse(redirect).map_err(|error| error.to_status())?;
            let client = unsafe { Pointer::reference_mut(client) }?;
            Ok((reference, client))
        })();
        let (reference, client) = match checked {
            Ok(checked) => checked,
            Err(status) => return status,
        };
        match client.callback(&reference, now) {
            // SAFETY: `out` is writable, checked above.
            Ok(request) => Status::from_result(unsafe { Pointer::write_handle(out, request.to_parameters()) }),
            // SAFETY: the caller passes null or a writable buffer.
            Err(error) => unsafe { OAuthStatus::fail(error, out_error) },
        }
    }

    /// Writes the HTTP request of the token request of `parameters` (its canonical
    /// parameters), with the client's authentication (RFC 6749 §3.2, §2.3), at `now`, into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_client_token_request(client: *const OAuthClient, parameters: *const OAuthParameters, now: i64, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut OAuthHTTPRequest) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, a generator and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            let parameters = unsafe { Pointer::reference(parameters) }?;
            let mut random = unsafe { OAuthStatus::random(random, random_type, random_type_length) }?;
            Pointer::check_range(out, 1)?;
            let request = OAuthTokenRequest::from_parameters(parameters).map_err(|error| error.to_status())?;
            let http = client.token_request(&request, now, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, http) }
        })())
    }

    /// Writes the HTTP POST of `parameters` to the endpoint at `endpoint` of the server, with
    /// the client's authentication, at `now`, into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_client_endpoint_request(client: *const OAuthClient, endpoint: *const u8, length: usize, parameters: *const OAuthParameters, now: i64, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut OAuthHTTPRequest) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, readable text, a generator and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            let endpoint = unsafe { Pointer::text(endpoint, length) }?;
            let parameters = unsafe { Pointer::reference(parameters) }?.clone();
            let mut random = unsafe { OAuthStatus::random(random, random_type, random_type_length) }?;
            Pointer::check_range(out, 1)?;
            let http = client.endpoint_request(endpoint, parameters, now, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, http) }
        })())
    }
}
