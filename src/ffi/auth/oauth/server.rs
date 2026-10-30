//! The C ABI of [`OAuthServer`] and its configuration.

use alloc::string::{String, ToString};
use core::ffi::c_void;

use super::OAuthStatus;
use crate::auth::oauth::{
    OAuthAccessTokenFormat, OAuthAuthorization, OAuthAuthorizationFailure, OAuthClientMethod, OAuthClientRegistration,
    OAuthEndpointRequest, OAuthGrantRecord, OAuthHTTPResponse, OAuthParameters, OAuthServer, OAuthServerConfig,
};
use crate::ffi::{Buffer, Char, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::jwt::{JWK, JWKSet};

impl Value for OAuthServer {
    const TYPE: Type = Type::Named("umilib_auth_oauth_OAuthServer");
}

impl Value for OAuthServerConfig {
    const TYPE: Type = Type::Named("umilib_auth_oauth_OAuthServerConfig");
}

impl Value for OAuthAuthorization {
    const TYPE: Type = Type::Named("umilib_auth_oauth_OAuthAuthorization");
}

/// The scalar settings of an [`OAuthServerConfig`], with those of its DPoP checks: the C form
/// of its booleans, lifetimes (seconds) and limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FFIOAuthServerLimits {
    pub require_pkce: bool,
    pub require_pushed_authorization_requests: bool,
    pub rotate_refresh_tokens: bool,
    pub dpop_require_nonce: bool,
    pub code_lifetime: i64,
    pub access_token_lifetime: i64,
    pub refresh_token_lifetime: i64,
    pub pushed_request_lifetime: i64,
    pub device_code_lifetime: i64,
    pub device_interval: i64,
    pub maximum_assertion_lifetime: i64,
    pub dpop_maximum_age: i64,
    pub dpop_leeway: i64,
    pub token_octets: usize,
    pub maximum_codes: usize,
    pub maximum_tokens: usize,
    pub maximum_pushed_requests: usize,
    pub maximum_devices: usize,
    pub maximum_assertions: usize,
    pub dpop_maximum_proofs: usize,
    pub user_code_length: usize,
    pub maximum_parameters: usize,
    pub maximum_codes_per_client: usize,
    pub maximum_tokens_per_client: usize,
    pub maximum_pushed_requests_per_client: usize,
    pub maximum_devices_per_client: usize,
    pub maximum_assertions_per_client: usize,
}

impl Value for FFIOAuthServerLimits {
    const TYPE: Type = Type::Named("umilib_auth_oauth_OAuthServerLimits");
}

impl FFIOAuthServerLimits {
    /// The fields of the structure, for the manifest.
    pub const FIELDS: &'static [Parameter] = &[
        Parameter { name: "require_pkce", value: <bool as Value>::TYPE },
        Parameter { name: "require_pushed_authorization_requests", value: <bool as Value>::TYPE },
        Parameter { name: "rotate_refresh_tokens", value: <bool as Value>::TYPE },
        Parameter { name: "dpop_require_nonce", value: <bool as Value>::TYPE },
        Parameter { name: "code_lifetime", value: <i64 as Value>::TYPE },
        Parameter { name: "access_token_lifetime", value: <i64 as Value>::TYPE },
        Parameter { name: "refresh_token_lifetime", value: <i64 as Value>::TYPE },
        Parameter { name: "pushed_request_lifetime", value: <i64 as Value>::TYPE },
        Parameter { name: "device_code_lifetime", value: <i64 as Value>::TYPE },
        Parameter { name: "device_interval", value: <i64 as Value>::TYPE },
        Parameter { name: "maximum_assertion_lifetime", value: <i64 as Value>::TYPE },
        Parameter { name: "dpop_maximum_age", value: <i64 as Value>::TYPE },
        Parameter { name: "dpop_leeway", value: <i64 as Value>::TYPE },
        Parameter { name: "token_octets", value: <usize as Value>::TYPE },
        Parameter { name: "maximum_codes", value: <usize as Value>::TYPE },
        Parameter { name: "maximum_tokens", value: <usize as Value>::TYPE },
        Parameter { name: "maximum_pushed_requests", value: <usize as Value>::TYPE },
        Parameter { name: "maximum_devices", value: <usize as Value>::TYPE },
        Parameter { name: "maximum_assertions", value: <usize as Value>::TYPE },
        Parameter { name: "dpop_maximum_proofs", value: <usize as Value>::TYPE },
        Parameter { name: "user_code_length", value: <usize as Value>::TYPE },
        Parameter { name: "maximum_parameters", value: <usize as Value>::TYPE },
        Parameter { name: "maximum_codes_per_client", value: <usize as Value>::TYPE },
        Parameter { name: "maximum_tokens_per_client", value: <usize as Value>::TYPE },
        Parameter { name: "maximum_pushed_requests_per_client", value: <usize as Value>::TYPE },
        Parameter { name: "maximum_devices_per_client", value: <usize as Value>::TYPE },
        Parameter { name: "maximum_assertions_per_client", value: <usize as Value>::TYPE },
    ];

    /// The settings of `config`.
    pub fn of(config: &OAuthServerConfig) -> FFIOAuthServerLimits {
        FFIOAuthServerLimits {
            require_pkce: config.require_pkce,
            require_pushed_authorization_requests: config.require_pushed_authorization_requests,
            rotate_refresh_tokens: config.rotate_refresh_tokens,
            dpop_require_nonce: config.dpop.require_nonce,
            code_lifetime: config.code_lifetime,
            access_token_lifetime: config.access_token_lifetime,
            refresh_token_lifetime: config.refresh_token_lifetime,
            pushed_request_lifetime: config.pushed_request_lifetime,
            device_code_lifetime: config.device_code_lifetime,
            device_interval: config.device_interval,
            maximum_assertion_lifetime: config.maximum_assertion_lifetime,
            dpop_maximum_age: config.dpop.maximum_age,
            dpop_leeway: config.dpop.leeway,
            token_octets: config.token_octets,
            maximum_codes: config.maximum_codes,
            maximum_tokens: config.maximum_tokens,
            maximum_pushed_requests: config.maximum_pushed_requests,
            maximum_devices: config.maximum_devices,
            maximum_assertions: config.maximum_assertions,
            dpop_maximum_proofs: config.dpop.maximum_proofs,
            user_code_length: config.user_code_length,
            maximum_parameters: config.maximum_parameters,
            maximum_codes_per_client: config.maximum_codes_per_client,
            maximum_tokens_per_client: config.maximum_tokens_per_client,
            maximum_pushed_requests_per_client: config.maximum_pushed_requests_per_client,
            maximum_devices_per_client: config.maximum_devices_per_client,
            maximum_assertions_per_client: config.maximum_assertions_per_client,
        }
    }

    /// Sets the settings of `config` to these.
    pub fn apply(&self, config: &mut OAuthServerConfig) {
        config.require_pkce = self.require_pkce;
        config.require_pushed_authorization_requests = self.require_pushed_authorization_requests;
        config.rotate_refresh_tokens = self.rotate_refresh_tokens;
        config.dpop.require_nonce = self.dpop_require_nonce;
        config.code_lifetime = self.code_lifetime;
        config.access_token_lifetime = self.access_token_lifetime;
        config.refresh_token_lifetime = self.refresh_token_lifetime;
        config.pushed_request_lifetime = self.pushed_request_lifetime;
        config.device_code_lifetime = self.device_code_lifetime;
        config.device_interval = self.device_interval;
        config.maximum_assertion_lifetime = self.maximum_assertion_lifetime;
        config.dpop.maximum_age = self.dpop_maximum_age;
        config.dpop.leeway = self.dpop_leeway;
        config.token_octets = self.token_octets;
        config.maximum_codes = self.maximum_codes;
        config.maximum_tokens = self.maximum_tokens;
        config.maximum_pushed_requests = self.maximum_pushed_requests;
        config.maximum_devices = self.maximum_devices;
        config.maximum_assertions = self.maximum_assertions;
        config.dpop.maximum_proofs = self.dpop_maximum_proofs;
        config.user_code_length = self.user_code_length;
        config.maximum_parameters = self.maximum_parameters;
        config.maximum_codes_per_client = self.maximum_codes_per_client;
        config.maximum_tokens_per_client = self.maximum_tokens_per_client;
        config.maximum_pushed_requests_per_client = self.maximum_pushed_requests_per_client;
        config.maximum_devices_per_client = self.maximum_devices_per_client;
        config.maximum_assertions_per_client = self.maximum_assertions_per_client;
    }
}

crate::ffi_functions! {
    // The configuration.

    /// Writes the configuration of the issuer at `issuer`, with the endpoints and settings of
    /// `OAuthServerConfig::new`, into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_config_new(issuer: *const u8, length: usize, out: *mut *mut OAuthServerConfig) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let issuer = unsafe { Pointer::text(issuer, length) }?;
            unsafe { Pointer::write_handle(out, OAuthServerConfig::new(issuer)) }
        })())
    }

    /// Releases a configuration. Does nothing if `config` is null.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_config_free(config: *mut OAuthServerConfig) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(config) }
    }

    /// Writes the scalar settings of `config` into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_config_limits(config: *const OAuthServerConfig, out: *mut FFIOAuthServerLimits) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            unsafe { Pointer::write(out, FFIOAuthServerLimits::of(config)) }
        })())
    }

    /// Sets the scalar settings of `config` to `limits`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_config_set_limits(config: *mut OAuthServerConfig, limits: FFIOAuthServerLimits) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            limits.apply(config);
            Ok(())
        })())
    }

    /// Writes the endpoints of `config`, LF-joined in the order authorization, token,
    /// introspection, revocation, pushed authorization request, device authorization,
    /// verification, JWKS (an absent one empty), into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_config_endpoints(config: *const OAuthServerConfig, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let config = unsafe { Pointer::reference(config) }?;
            let optional = [
                &config.introspection_endpoint,
                &config.revocation_endpoint,
                &config.pushed_authorization_request_endpoint,
                &config.device_authorization_endpoint,
                &config.verification_uri,
                &config.jwks_uri,
            ];
            let mut lines = alloc::vec![config.authorization_endpoint.clone(), config.token_endpoint.clone()];
            lines.extend(optional.iter().map(|value| (*value).clone().unwrap_or_default()));
            unsafe { Pointer::write_text(out, lines.join("\n")) }
        })())
    }

    /// Sets the endpoints of `config` to the `count` (8) strings at `endpoints`, in the order of
    /// `umilib_auth_oauth_oauth_server_config_endpoints`; an empty one after the token endpoint
    /// is absent.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_config_set_endpoints(config: *mut OAuthServerConfig, endpoints: *const *const Char, count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and an array of strings.
            let endpoints = unsafe { Pointer::strings(endpoints, count) }?;
            let config = unsafe { Pointer::reference_mut(config) }?;
            let [authorization, token, introspection, revocation, pushed, device, verification, jwks] = endpoints.as_slice() else {
                return Err(&Status::INVALID_ARGUMENT);
            };
            let optional = |value: &String| (!value.is_empty()).then(|| value.clone());
            config.authorization_endpoint = authorization.clone();
            config.token_endpoint = token.clone();
            config.introspection_endpoint = optional(introspection);
            config.revocation_endpoint = optional(revocation);
            config.pushed_authorization_request_endpoint = optional(pushed);
            config.device_authorization_endpoint = optional(device);
            config.verification_uri = optional(verification);
            config.jwks_uri = optional(jwks);
            Ok(())
        })())
    }

    /// Sets the signature algorithms of client assertions and of DPoP proofs to the indices at
    /// `assertion` and `dpop`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_config_set_algorithms(config: *mut OAuthServerConfig, assertion: *const u8, assertion_count: usize, dpop: *const u8, dpop_count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let assertion = unsafe { OAuthStatus::algorithms(assertion, assertion_count) }?;
            let dpop = unsafe { OAuthStatus::algorithms(dpop, dpop_count) }?;
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.assertion_algorithms = assertion;
            config.dpop.algorithms = dpop;
            Ok(())
        })())
    }

    /// Writes the indices of the signature algorithms of client assertions into `out_assertion`
    /// and of DPoP proofs into `out_dpop`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_config_algorithms(config: *const OAuthServerConfig, out_assertion: *mut Buffer, out_dpop: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_assertion, 1), Pointer::range(out_dpop, 1)])?;
            Pointer::check_range(out_assertion, 1)?;
            Pointer::check_range(out_dpop, 1)?;
            // SAFETY: the caller passes a valid handle and writable buffers.
            let config = unsafe { Pointer::reference(config) }?;
            let indices = |algorithms: &[crate::protocol::jwt::JWSAlgorithm]| -> alloc::vec::Vec<u8> {
                algorithms.iter().filter_map(|algorithm| crate::protocol::jwt::JWSAlgorithm::ALL.iter().position(|known| known == algorithm)).map(|index| index as u8).collect()
            };
            unsafe { Pointer::write(out_assertion, Buffer::from_vec(indices(&config.assertion_algorithms))) }?;
            unsafe { Pointer::write(out_dpop, Buffer::from_vec(indices(&config.dpop.algorithms))) }
        })())
    }

    /// Makes the access tokens of `config` opaque if `key` is null, or JWTs of RFC 9068 signed
    /// with the private `key` by the JWS algorithm `algorithm`, whose default audience is the
    /// text at `default_audience`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_config_set_access_token_format(config: *mut OAuthServerConfig, key: *const JWK, algorithm: u8, default_audience: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles or null and readable text.
            let format = if key.is_null() {
                OAuthAccessTokenFormat::Opaque
            } else {
                let key = alloc::boxed::Box::new(unsafe { Pointer::reference(key) }?.clone());
                let default_audience = unsafe { Pointer::text(default_audience, length) }?.to_string();
                OAuthAccessTokenFormat::JWT { key, algorithm: OAuthStatus::algorithm(algorithm)?, default_audience }
            };
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.access_token_format = format;
            Ok(())
        })())
    }

    // The server.

    /// Writes a server of a copy of `config` into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_new(config: *const OAuthServerConfig, out: *mut *mut OAuthServer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?.clone();
            unsafe { Pointer::write_handle(out, OAuthServer::new(config)) }
        })())
    }

    /// Releases a server. Does nothing if `server` is null.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_free(server: *mut OAuthServer) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(server) }
    }

    /// Writes a copy of the configuration of `server` into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_config(server: *const OAuthServer, out: *mut *mut OAuthServerConfig) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write_handle(out, server.config().clone()) }
        })())
    }

    /// Registers the client at `client_id`, which authenticates with `method` (0 none, 1
    /// client_secret_basic, 2 client_secret_post, 3 private_key_jwt) and the secret at `secret`
    /// or the public `keys`, may be redirected to the `redirect_count` URIs at `redirect_uris`,
    /// may use the `grant_count` grant types at `grant_types` and the scope at `scope`, and
    /// may ask for the `resource_count` resources at `resources` (any if `resources` is null),
    /// and may introspect if `introspection`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_register(server: *mut OAuthServer, client_id: *const u8, client_id_length: usize, method: u8, secret: *const u8, secret_length: usize, keys: *const JWKSet, redirect_uris: *const *const Char, redirect_count: usize, grant_types: *const *const Char, grant_count: usize, scope: *const u8, scope_length: usize, resources: *const *const Char, resource_count: usize, introspection: bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text or null, arrays of strings and a key set or null.
            let client_id = unsafe { Pointer::text(client_id, client_id_length) }?;
            let secret = unsafe { Pointer::optional_text(secret, secret_length) }?;
            let keys = if keys.is_null() { None } else { Some(unsafe { Pointer::reference(keys) }?.clone()) };
            let redirect_uris = unsafe { Pointer::strings(redirect_uris, redirect_count) }?;
            let grant_types = unsafe { Pointer::strings(grant_types, grant_count) }?;
            let scope = unsafe { OAuthStatus::scope(scope, scope_length) }?.unwrap_or_default();
            let resources = if resources.is_null() { None } else { Some(unsafe { Pointer::strings(resources, resource_count) }?) };
            let method = match method {
                0 => OAuthClientMethod::None,
                1 => OAuthClientMethod::SecretBasic,
                2 => OAuthClientMethod::SecretPost,
                3 => OAuthClientMethod::PrivateKeyJWT,
                _ => return Err(&Status::INVALID_ARGUMENT),
            };
            let server = unsafe { Pointer::reference_mut(server) }?;
            let registered = server.register(OAuthClientRegistration {
                client_id: client_id.to_string(),
                method,
                secret_digest: secret.map(OAuthClientRegistration::digest),
                keys,
                redirect_uris,
                grant_types,
                scope,
                resources,
                introspection,
            });
            registered.map_err(|error| error.to_status())
        })())
    }

    /// Removes the client at `client_id` and revokes what it was issued; writes whether it was
    /// registered into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_unregister(server: *mut OAuthServer, client_id: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(client_id, length)], &[Pointer::range(out, 1)])?;
            // The output is checked before the client is removed.
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes a valid handle, readable text and a writable pointer.
            let client_id = unsafe { Pointer::text(client_id, length) }?;
            let server = unsafe { Pointer::reference_mut(server) }?;
            unsafe { Pointer::write(out, server.unregister(client_id).is_some()) }
        })())
    }

    /// Writes the JSON of the server's metadata document (RFC 8414 §2) into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_metadata(server: *const OAuthServer, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write_text(out, server.metadata().encode()) }
        })())
    }

    /// Writes whether the server issues JWT access tokens into `out_has` and the JSON of the
    /// JWK Set of their public key into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_jwks(server: *const OAuthServer, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_has, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            let jwks = server.jwks().map(|jwks| jwks.to_json());
            unsafe { Pointer::write_optional_text(out_has, out, jwks.as_deref()) }
        })())
    }

    /// Checks the authorization request of `parameters` at `now` (RFC 6749 §4.1.1, RFC 9126
    /// §4). Writes into `out_kind` 0 if it was taken, the authorization into `out`; 1 if the user
    /// is to be told of the error, its JSON into `out_text`; 2 if the user agent is to be sent to
    /// the URI written into `out_text`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_authorize(server: *mut OAuthServer, parameters: *const OAuthParameters, now: i64, out_kind: *mut u8, out: *mut *mut OAuthAuthorization, out_text: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_kind, 1), Pointer::range(out, 1), Pointer::range(out_text, 1)])?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_text, 1)?;
            // SAFETY: the caller passes valid handles and writable pointers.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            let server = unsafe { Pointer::reference_mut(server) }?;
            match server.authorize(parameters, now) {
                Ok(authorization) => {
                    unsafe { Pointer::write(out_kind, 0) }?;
                    unsafe { Pointer::write_text(out_text, String::new()) }?;
                    unsafe { Pointer::write_handle(out, authorization) }
                }
                Err(OAuthAuthorizationFailure::Local(error)) => {
                    unsafe { Pointer::write(out_kind, 1) }?;
                    unsafe { Pointer::write(out, core::ptr::null_mut()) }?;
                    unsafe { Pointer::write_text(out_text, error.encode()) }
                }
                Err(OAuthAuthorizationFailure::Redirect(uri)) => {
                    unsafe { Pointer::write(out_kind, 2) }?;
                    unsafe { Pointer::write(out, core::ptr::null_mut()) }?;
                    unsafe { Pointer::write_text(out_text, uri.to_string()) }
                }
            }
        })())
    }

    /// Releases an authorization. Does nothing if `authorization` is null.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_authorization_free(authorization: *mut OAuthAuthorization) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(authorization) }
    }

    /// Writes the client, the redirect URI, the scope, the state (whether there is one into
    /// `out_has_state`), the resources (joined by LF) and the parameters the server does not
    /// know of `authorization` into the outputs.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_authorization_parts(authorization: *const OAuthAuthorization, out_client_id: *mut Buffer, out_redirect_uri: *mut Buffer, out_scope: *mut Buffer, out_has_state: *mut bool, out_state: *mut Buffer, out_resources: *mut Buffer, out_other: *mut *mut OAuthParameters) -> *const Status {
        Status::from_result((|| {
            let outputs = [Pointer::range(out_client_id, 1), Pointer::range(out_redirect_uri, 1), Pointer::range(out_scope, 1), Pointer::range(out_has_state, 1), Pointer::range(out_state, 1), Pointer::range(out_resources, 1), Pointer::range(out_other, 1)];
            Pointer::check_ranges(&[], &outputs)?;
            for output in [out_client_id, out_redirect_uri, out_scope, out_state, out_resources] {
                Pointer::check_range(output, 1)?;
            }
            Pointer::check_range(out_has_state, 1)?;
            Pointer::check_range(out_other, 1)?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let authorization = unsafe { Pointer::reference(authorization) }?;
            unsafe { Pointer::write_text(out_client_id, authorization.client_id.clone()) }?;
            unsafe { Pointer::write_text(out_redirect_uri, authorization.redirect_uri.clone()) }?;
            unsafe { Pointer::write_text(out_scope, authorization.scope.to_string()) }?;
            unsafe { Pointer::write_optional_text(out_has_state, out_state, authorization.state.as_deref()) }?;
            unsafe { Pointer::write_text(out_resources, authorization.resources.join("\n")) }?;
            unsafe { Pointer::write_handle(out_other, authorization.other.clone()) }
        })())
    }

    /// Issues a code for `authorization`, which the resource owner at `subject` approved for the
    /// scope at `scope` and the `count` resources at `resources` (their own or narrower),
    /// having authenticated at `authentication_time` (if `has_authentication_time`) with the
    /// context at `context` (null for none); writes the URI to send the user agent to into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_approve(server: *mut OAuthServer, authorization: *const OAuthAuthorization, subject: *const u8, subject_length: usize, scope: *const u8, scope_length: usize, resources: *const *const Char, count: usize, has_authentication_time: bool, authentication_time: i64, context: *const u8, context_length: usize, now: i64, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(subject, subject_length), Pointer::range(scope, scope_length), Pointer::range(context, context_length)], &[Pointer::range(out, 1)])?;
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes valid handles, readable text or null, an array of strings, a generator and a writable buffer.
            let authorization = unsafe { Pointer::reference(authorization) }?;
            let grant = unsafe { OAuthServerEndpoint::grant(&authorization.client_id, subject, subject_length, scope, scope_length, resources, count, has_authentication_time, authentication_time, context, context_length) }?;
            let mut random = unsafe { OAuthStatus::random(random, random_type, random_type_length) }?;
            let server = unsafe { Pointer::reference_mut(server) }?;
            let uri = server.approve(authorization, grant, now, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, uri.to_string()) }
        })())
    }

    /// Writes the URI to send the user agent to when the resource owner denies `authorization`
    /// into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_deny(server: *const OAuthServer, authorization: *const OAuthAuthorization, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable buffer.
            let server = unsafe { Pointer::reference(server) }?;
            let authorization = unsafe { Pointer::reference(authorization) }?;
            let uri = server.deny(authorization).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, uri.to_string()) }
        })())
    }

    /// Writes the response of the token endpoint to `request` at `now` into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_token(server: *mut OAuthServer, request: *const OAuthEndpointRequest, now: i64, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut OAuthHTTPResponse) -> *const Status {
        // SAFETY: the caller passes valid handles, a generator and a writable pointer.
        unsafe { OAuthServerEndpoint::answer(server, request, random, random_type, random_type_length, out, |server, request, random| server.token(request, now, random)) }
    }

    /// Writes the response of the introspection endpoint to `request` at `now` into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_introspect(server: *mut OAuthServer, request: *const OAuthEndpointRequest, now: i64, out: *mut *mut OAuthHTTPResponse) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let request = unsafe { Pointer::reference(request) }?;
            Pointer::check_range(out, 1)?;
            let server = unsafe { Pointer::reference_mut(server) }?;
            unsafe { Pointer::write_handle(out, server.introspect(request, now)) }
        })())
    }

    /// Writes the response of the revocation endpoint to `request` at `now` into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_revoke(server: *mut OAuthServer, request: *const OAuthEndpointRequest, now: i64, out: *mut *mut OAuthHTTPResponse) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let request = unsafe { Pointer::reference(request) }?;
            Pointer::check_range(out, 1)?;
            let server = unsafe { Pointer::reference_mut(server) }?;
            unsafe { Pointer::write_handle(out, server.revoke(request, now)) }
        })())
    }

    /// Writes the response of the pushed authorization request endpoint to `request` at `now`
    /// into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_push(server: *mut OAuthServer, request: *const OAuthEndpointRequest, now: i64, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut OAuthHTTPResponse) -> *const Status {
        // SAFETY: the caller passes valid handles, a generator and a writable pointer.
        unsafe { OAuthServerEndpoint::answer(server, request, random, random_type, random_type_length, out, |server, request, random| server.push(request, now, random)) }
    }

    /// Writes the response of the device authorization endpoint to `request` at `now` into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_device_authorize(server: *mut OAuthServer, request: *const OAuthEndpointRequest, now: i64, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut OAuthHTTPResponse) -> *const Status {
        // SAFETY: the caller passes valid handles, a generator and a writable pointer.
        unsafe { OAuthServerEndpoint::answer(server, request, random, random_type, random_type_length, out, |server, request, random| server.device_authorize(request, now, random)) }
    }

    /// Writes the JSON of what introspection says of the token at `token` at `now` (RFC 7662
    /// §2.2) into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_introspection(server: *const OAuthServer, token: *const u8, length: usize, now: i64, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(token, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable text and a writable buffer.
            let server = unsafe { Pointer::reference(server) }?;
            let token = unsafe { Pointer::text(token, length) }?;
            unsafe { Pointer::write_text(out, server.introspection(token, now).encode()) }
        })())
    }

    /// Writes whether a pending device authorization has the user code at `user_code` into
    /// `out_found`, and its client, scope and resources (joined by LF) into the other outputs.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_device(server: *const OAuthServer, user_code: *const u8, length: usize, now: i64, out_found: *mut bool, out_client_id: *mut Buffer, out_scope: *mut Buffer, out_resources: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let outputs = [Pointer::range(out_found, 1), Pointer::range(out_client_id, 1), Pointer::range(out_scope, 1), Pointer::range(out_resources, 1)];
            Pointer::check_ranges(&[Pointer::range(user_code, length)], &outputs)?;
            Pointer::check_range(out_found, 1)?;
            for output in [out_client_id, out_scope, out_resources] {
                Pointer::check_range(output, 1)?;
            }
            // SAFETY: the caller passes a valid handle, readable text and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            let user_code = unsafe { Pointer::text(user_code, length) }?;
            let device = server.device(user_code, now);
            unsafe { Pointer::write(out_found, device.is_some()) }?;
            unsafe { Pointer::write_text(out_client_id, device.map(|device| device.client_id.clone()).unwrap_or_default()) }?;
            unsafe { Pointer::write_text(out_scope, device.map(|device| device.scope.to_string()).unwrap_or_default()) }?;
            unsafe { Pointer::write_text(out_resources, device.map(|device| device.resources.join("\n")).unwrap_or_default()) }
        })())
    }

    /// Records that the user at `subject` approved the device authorization of the user code
    /// at `user_code` for the scope at `scope` and the `count` resources at `resources`, having
    /// authenticated as `umilib_auth_oauth_oauth_server_approve` takes it.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_device_approve(server: *mut OAuthServer, user_code: *const u8, user_code_length: usize, subject: *const u8, subject_length: usize, scope: *const u8, scope_length: usize, resources: *const *const Char, count: usize, has_authentication_time: bool, authentication_time: i64, context: *const u8, context_length: usize, now: i64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text or null and an array of strings.
            let user_code = unsafe { Pointer::text(user_code, user_code_length) }?;
            let server = unsafe { Pointer::reference_mut(server) }?;
            let client_id = server.device(user_code, now).map(|device| device.client_id.clone()).ok_or(&OAuthStatus::STATE)?;
            let grant = unsafe { OAuthServerEndpoint::grant(&client_id, subject, subject_length, scope, scope_length, resources, count, has_authentication_time, authentication_time, context, context_length) }?;
            server.device_approve(user_code, grant, now).map_err(|error| error.to_status())
        })())
    }

    /// Records that the user denied the device authorization of the user code at `user_code`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_device_deny(server: *mut OAuthServer, user_code: *const u8, length: usize, now: i64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let user_code = unsafe { Pointer::text(user_code, length) }?;
            let server = unsafe { Pointer::reference_mut(server) }?;
            server.device_deny(user_code, now).map_err(|error| error.to_status())
        })())
    }

    /// Revokes every token issued for the resource owner at `subject`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_revoke_subject(server: *mut OAuthServer, subject: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let subject = unsafe { Pointer::text(subject, length) }?;
            let server = unsafe { Pointer::reference_mut(server) }?;
            server.revoke_subject(subject);
            Ok(())
        })())
    }

    /// Forgets what expired before `now`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_expire(server: *mut OAuthServer, now: i64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let server = unsafe { Pointer::reference_mut(server) }?;
            server.expire(now);
            Ok(())
        })())
    }

    /// Makes a new DPoP nonce (RFC 9449 §8) and writes it into `out`.
    pub unsafe extern "C" fn umilib_auth_oauth_oauth_server_rotate_dpop_nonce(server: *mut OAuthServer, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, a generator and a writable buffer.
            let mut random = unsafe { OAuthStatus::random(random, random_type, random_type_length) }?;
            Pointer::check_range(out, 1)?;
            let server = unsafe { Pointer::reference_mut(server) }?;
            let nonce = server.dpop().rotate_nonce(&mut random).map_err(|error| error.to_status())?.to_string();
            unsafe { Pointer::write_text(out, nonce) }
        })())
    }
}

/// The shared steps of the endpoints that take randomness.
pub struct OAuthServerEndpoint;

impl OAuthServerEndpoint {
    /// The grant of `client_id` for `subject` with the scope at `scope`, the `count`
    /// resources at `resources`, and how the user authenticated.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn grant(
        client_id: &str,
        subject: *const u8,
        subject_length: usize,
        scope: *const u8,
        scope_length: usize,
        resources: *const *const Char,
        count: usize,
        has_authentication_time: bool,
        authentication_time: i64,
        context: *const u8,
        context_length: usize,
    ) -> Result<OAuthGrantRecord, &'static Status> {
        // SAFETY: guaranteed by the caller.
        let subject = unsafe { Pointer::text(subject, subject_length) }?;
        let scope = unsafe { OAuthStatus::scope(scope, scope_length) }?.unwrap_or_default();
        let resources = unsafe { Pointer::strings(resources, count) }?;
        let context = unsafe { Pointer::optional_text(context, context_length) }?;
        Ok(OAuthGrantRecord {
            client_id: client_id.to_string(),
            subject: Some(subject.to_string()),
            scope,
            resources,
            confirmation: None,
            authentication_time: has_authentication_time.then_some(authentication_time),
            authentication_context: context.map(str::to_string),
        })
    }

    /// Writes the response `answer` gives to `request` into `out`.
    ///
    /// # Safety
    ///
    /// See [`Pointer`] and [`crate::ffi::crypto::random::RandomSource::from_handle`].
    pub unsafe fn answer(
        server: *mut OAuthServer,
        request: *const OAuthEndpointRequest,
        random: *mut c_void,
        random_type: *const u8,
        random_type_length: usize,
        out: *mut *mut OAuthHTTPResponse,
        answer: impl FnOnce(
            &mut OAuthServer,
            &OAuthEndpointRequest,
            &mut crate::ffi::crypto::random::RandomSource<'_>,
        ) -> OAuthHTTPResponse,
    ) -> *const Status {
        Status::from_result((|| {
            // SAFETY: guaranteed by the caller.
            let request = unsafe { Pointer::reference(request) }?;
            let mut random = unsafe { OAuthStatus::random(random, random_type, random_type_length) }?;
            Pointer::check_range(out, 1)?;
            let server = unsafe { Pointer::reference_mut(server) }?;
            let response = answer(server, request, &mut random);
            unsafe { Pointer::write_handle(out, response) }
        })())
    }
}

/// The values of the manifest for the server's structure.
pub const LIMITS: crate::ffi::Definition = crate::ffi::Definition::Structure {
    name: "umilib_auth_oauth_OAuthServerLimits",
    documentation: " The scalar settings of a server's configuration: lifetimes in seconds, and limits.",
    fields: FFIOAuthServerLimits::FIELDS,
};
