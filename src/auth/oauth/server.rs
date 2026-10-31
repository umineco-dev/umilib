use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::codec::json::{JSONNumber, JSONObject, JSONValue};
use crate::codec::uri::URIReference;
use crate::crypto::random::Random;
use crate::hash::Digest;
use crate::hash::sha::v2::SHA256;
use crate::protocol::jwt::{
    Base64URL, JOSEHeader, JWK, JWKSet, JWS, JWSAlgorithm, JWSConfig, JWT, JWTClaims, JWTValidation,
};

use super::{
    DPoPConfig, DPoPProof, DPoPTarget, DPoPVerifier, OAuthAuthorizationRequest, OAuthAuthorizationResponse,
    OAuthClientAuthentication, OAuthClientCredentials, OAuthClientMethod, OAuthClientRegistration,
    OAuthDeviceAuthorizationResponse, OAuthEndpointRequest, OAuthError, OAuthErrorCode, OAuthErrorResponse, OAuthGrant,
    OAuthHTTPResponse, OAuthIntrospectionResponse, OAuthMembers, OAuthMetadata, OAuthMetadataKind, OAuthParameters,
    OAuthPushedAuthorizationResponse, OAuthRecord, OAuthScope, OAuthTable, OAuthTokenRequest, OAuthTokenResponse,
    PKCEChallenge,
};

/// The form of the access tokens an authorization server issues.
#[derive(Clone, Debug)]
pub enum OAuthAccessTokenFormat {
    /// Random strings that only the server can look up (with introspection, RFC 7662).
    Opaque,
    /// JWTs of RFC 9068, signed with `key` by `algorithm`; `default_audience` is the `aud` of a
    /// token whose request named no resource (RFC 9068 §3).
    JWT { key: Box<JWK>, algorithm: JWSAlgorithm, default_audience: String },
}

/// The configuration of an [`OAuthServer`]: its identifier, its endpoints, the lifetimes of
/// what it issues and its limits. Lifetimes are in seconds.
#[derive(Clone, Debug)]
pub struct OAuthServerConfig {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub introspection_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub pushed_authorization_request_endpoint: Option<String>,
    pub device_authorization_endpoint: Option<String>,
    /// The page where the user enters a user code (RFC 8628 §3.2 `verification_uri`).
    pub verification_uri: Option<String>,
    pub jwks_uri: Option<String>,
    pub access_token_format: OAuthAccessTokenFormat,
    /// Whether every authorization request must have a code challenge (RFC 9700 §2.1.1).
    pub require_pkce: bool,
    /// Whether every authorization request must be pushed first (RFC 9126 §5).
    pub require_pushed_authorization_requests: bool,
    /// Whether a refresh token is replaced by a new one each time it is used (RFC 9700 §4.14.2);
    /// a replaced token used again revokes every token of its grant.
    pub rotate_refresh_tokens: bool,
    pub code_lifetime: i64,
    pub access_token_lifetime: i64,
    pub refresh_token_lifetime: i64,
    pub pushed_request_lifetime: i64,
    pub device_code_lifetime: i64,
    /// The seconds a device waits between polls (RFC 8628 §3.2), raised by 5 on `slow_down`.
    pub device_interval: i64,
    /// The longest lifetime of a client assertion (`exp` past the time it is received).
    pub maximum_assertion_lifetime: i64,
    /// The random octets of codes and tokens.
    pub token_octets: usize,
    /// The characters of a user code (RFC 8628 §6.1: 8 of the 20 consonants are about 34 bits).
    pub user_code_length: usize,
    /// The most parameters of a request.
    pub maximum_parameters: usize,
    /// The most records of each table, and of one client in each (so that one client cannot
    /// fill a table for the others).
    pub maximum_codes: usize,
    pub maximum_codes_per_client: usize,
    pub maximum_tokens: usize,
    pub maximum_tokens_per_client: usize,
    pub maximum_pushed_requests: usize,
    pub maximum_pushed_requests_per_client: usize,
    pub maximum_devices: usize,
    pub maximum_devices_per_client: usize,
    pub maximum_assertions: usize,
    pub maximum_assertions_per_client: usize,
    /// The signature algorithms taken for client assertions.
    pub assertion_algorithms: Vec<JWSAlgorithm>,
    /// The checks of DPoP proofs (RFC 9449).
    pub dpop: DPoPConfig,
}

impl OAuthServerConfig {
    /// A configuration of the issuer `issuer` whose endpoints are the paths `/authorize`,
    /// `/token`, `/introspect`, `/revoke`, `/par` and `/device` under it, with opaque tokens,
    /// PKCE required, rotated refresh tokens and short lifetimes.
    pub fn new(issuer: &str) -> OAuthServerConfig {
        let base = issuer.trim_end_matches('/');
        OAuthServerConfig {
            issuer: issuer.to_string(),
            authorization_endpoint: format!("{base}/authorize"),
            token_endpoint: format!("{base}/token"),
            introspection_endpoint: Some(format!("{base}/introspect")),
            revocation_endpoint: Some(format!("{base}/revoke")),
            pushed_authorization_request_endpoint: Some(format!("{base}/par")),
            device_authorization_endpoint: Some(format!("{base}/device")),
            verification_uri: Some(format!("{base}/device/verify")),
            jwks_uri: None,
            access_token_format: OAuthAccessTokenFormat::Opaque,
            require_pkce: true,
            require_pushed_authorization_requests: false,
            rotate_refresh_tokens: true,
            code_lifetime: 60,
            access_token_lifetime: 600,
            refresh_token_lifetime: 30 * 24 * 3600,
            pushed_request_lifetime: 60,
            device_code_lifetime: 600,
            device_interval: 5,
            maximum_assertion_lifetime: 300,
            token_octets: 32,
            user_code_length: 8,
            maximum_parameters: 256,
            maximum_codes: 4096,
            maximum_codes_per_client: 256,
            maximum_tokens: 65536,
            maximum_tokens_per_client: 4096,
            maximum_pushed_requests: 4096,
            maximum_pushed_requests_per_client: 64,
            maximum_devices: 1024,
            maximum_devices_per_client: 64,
            maximum_assertions: 4096,
            maximum_assertions_per_client: 256,
            assertion_algorithms: alloc::vec![
                JWSAlgorithm::ES256,
                JWSAlgorithm::ES384,
                JWSAlgorithm::ES512,
                JWSAlgorithm::PS256,
                JWSAlgorithm::PS384,
                JWSAlgorithm::PS512,
                JWSAlgorithm::RS256,
                JWSAlgorithm::Ed25519,
                JWSAlgorithm::EdDSA,
            ],
            dpop: DPoPConfig::default(),
        }
    }
}

/// What a grant gave: to which client, for which user, with which scope and resources, bound to
/// which key, and how the user authenticated (RFC 9470 §4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuthGrantRecord {
    pub client_id: String,
    /// The resource owner; `None` for the client credentials grant.
    pub subject: Option<String>,
    pub scope: OAuthScope,
    pub resources: Vec<String>,
    /// The base64url JWK SHA-256 thumbprint of the key the tokens are bound to (RFC 9449 §6).
    pub confirmation: Option<String>,
    /// `auth_time`: when the user authenticated.
    pub authentication_time: Option<i64>,
    /// `acr`: the authentication context class.
    pub authentication_context: Option<String>,
}

/// An authorization code waiting to be exchanged (RFC 6749 §4.1.2).
#[derive(Clone, Debug)]
pub struct OAuthCodeRecord {
    pub grant: OAuthGrantRecord,
    /// The redirect URI of the authorization request, if it named one (§4.1.3).
    pub redirect_uri: Option<String>,
    pub challenge: Option<PKCEChallenge>,
    /// The thumbprint of the DPoP key the code is bound to (RFC 9449 §10).
    pub dpop_jkt: Option<String>,
    pub expires: i64,
    pub family: u64,
    /// Whether the code was exchanged: a second exchange revokes what the first issued (§4.1.2).
    pub redeemed: bool,
}

/// The kind of a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OAuthTokenKind {
    Access,
    Refresh,
}

/// A token the server issued.
#[derive(Clone, Debug)]
pub struct OAuthTokenRecord {
    pub kind: OAuthTokenKind,
    pub grant: OAuthGrantRecord,
    pub issued: i64,
    pub expires: i64,
    /// The grant the token belongs to: the tokens of one code, one client credentials request,
    /// or one device authorization, and the refresh tokens that replaced them.
    pub family: u64,
    /// The `jti` of the token.
    pub identifier: String,
    /// Whether a refresh token was replaced by another (RFC 9700 §4.14.2). Of the refresh
    /// tokens a family replaced, only the last is kept, to tell a stolen one from a new one.
    pub replaced: bool,
}

/// An authorization request pushed to the server (RFC 9126 §2).
#[derive(Clone, Debug)]
pub struct OAuthPushedRecord {
    pub client_id: String,
    pub parameters: OAuthParameters,
    pub expires: i64,
}

/// The state of a device authorization (RFC 8628 §3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OAuthDeviceState {
    Pending,
    Approved(OAuthGrantRecord),
    Denied,
}

/// A device authorization waiting for the user (RFC 8628 §3.1).
#[derive(Clone, Debug)]
pub struct OAuthDeviceRecord {
    pub client_id: String,
    pub scope: OAuthScope,
    pub resources: Vec<String>,
    pub user_code: String,
    pub expires: i64,
    pub interval: i64,
    pub last_poll: Option<i64>,
    pub state: OAuthDeviceState,
}

impl OAuthRecord for OAuthCodeRecord {
    fn client_id(&self) -> &str {
        &self.grant.client_id
    }
}

impl OAuthRecord for OAuthTokenRecord {
    fn client_id(&self) -> &str {
        &self.grant.client_id
    }
}

impl OAuthRecord for OAuthPushedRecord {
    fn client_id(&self) -> &str {
        &self.client_id
    }
}

impl OAuthRecord for OAuthDeviceRecord {
    fn client_id(&self) -> &str {
        &self.client_id
    }
}

/// An authorization request the server took, waiting for the user's decision: the client asks
/// for `scope` and `resources`, and the user is to be sent back to `redirect_uri`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthAuthorization {
    pub client_id: String,
    pub redirect_uri: String,
    /// Whether the request named the redirect URI, which binds the token request (§4.1.3).
    pub redirect_uri_given: bool,
    pub scope: OAuthScope,
    pub state: Option<String>,
    pub challenge: Option<PKCEChallenge>,
    pub resources: Vec<String>,
    /// The thumbprint of the DPoP key the code is to be bound to (RFC 9449 §10).
    pub dpop_jkt: Option<String>,
    /// The parameters the server does not know, for the application (such as `prompt`).
    pub other: OAuthParameters,
}

/// Why an authorization request was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OAuthAuthorizationFailure {
    /// The client or the redirect URI is not valid: tell the user, and do not redirect
    /// (RFC 6749 §4.1.2.1, §10.15).
    Local(OAuthErrorResponse),
    /// Send the user agent to this URI, which carries the error.
    Redirect(Box<URIReference>),
}

/// An authorization server without I/O (RFC 6749 §3; RFC 7662, RFC 7009, RFC 9126, RFC 8628,
/// RFC 9068): it keeps its clients, the codes and tokens it issued in bounded tables, and
/// answers the requests its endpoints receive, which the user's HTTP server hands it.
///
/// The user authenticates the resource owner and asks for consent between
/// [`OAuthServer::authorize`] and [`OAuthServer::approve`]. Codes and tokens are kept only as
/// their SHA-256 digests. Every table is an [`OAuthTable`]: bounded in all and per client,
/// and pruned by expiry without a scan. Times are seconds since 1970.
pub struct OAuthServer {
    config: OAuthServerConfig,
    clients: BTreeMap<String, OAuthClientRegistration>,
    codes: OAuthTable<[u8; 32], OAuthCodeRecord>,
    tokens: OAuthTable<[u8; 32], OAuthTokenRecord>,
    pushed: OAuthTable<String, OAuthPushedRecord>,
    devices: OAuthTable<[u8; 32], OAuthDeviceRecord>,
    user_codes: BTreeMap<String, [u8; 32]>,
    /// The identifiers of client assertions used, by client and `jti` (the value is the client).
    assertions: OAuthTable<(String, String), String>,
    /// The last refresh token each family replaced.
    replaced: BTreeMap<u64, [u8; 32]>,
    dpop: DPoPVerifier,
    next_family: u64,
}

impl OAuthServer {
    /// The prefix of the `request_uri` of a pushed request (RFC 9126 §2.2).
    pub const REQUEST_URI_PREFIX: &'static str = "urn:ietf:params:oauth:request_uri:";
    /// The characters of user codes (RFC 8628 §6.1): consonants, which make no words and are
    /// not confused with digits.
    pub const USER_CODE_CHARACTERS: &'static [u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";
    pub fn new(config: OAuthServerConfig) -> OAuthServer {
        OAuthServer {
            dpop: DPoPVerifier::new(config.dpop.clone()),
            clients: BTreeMap::new(),
            codes: OAuthTable::new(config.maximum_codes, config.maximum_codes_per_client),
            tokens: OAuthTable::new(config.maximum_tokens, config.maximum_tokens_per_client),
            pushed: OAuthTable::new(config.maximum_pushed_requests, config.maximum_pushed_requests_per_client),
            devices: OAuthTable::new(config.maximum_devices, config.maximum_devices_per_client),
            user_codes: BTreeMap::new(),
            assertions: OAuthTable::new(config.maximum_assertions, config.maximum_assertions_per_client),
            replaced: BTreeMap::new(),
            next_family: 0,
            config,
        }
    }

    pub fn config(&self) -> &OAuthServerConfig {
        &self.config
    }

    /// The checks of DPoP proofs, whose nonce the user rotates (RFC 9449 §8).
    pub fn dpop(&mut self) -> &mut DPoPVerifier {
        &mut self.dpop
    }

    /// Registers `registration`, replacing a client of the same identifier. Its redirect URIs
    /// must be absolute URIs without a fragment (RFC 6749 §3.1.2), or it fails with Invalid.
    pub fn register(&mut self, registration: OAuthClientRegistration) -> Result<(), OAuthError> {
        if !registration.redirect_uris.iter().all(|uri| OAuthServer::is_resource(uri)) {
            return Err(OAuthError::Invalid { parameter: "redirect_uri" });
        }
        if !OAuthClientAuthentication::is_client_id(&registration.client_id) {
            return Err(OAuthError::Invalid { parameter: "client_id" });
        }
        self.clients.insert(registration.client_id.clone(), registration);
        Ok(())
    }

    /// Removes the client `client_id` and revokes every token issued to it.
    pub fn unregister(&mut self, client_id: &str) -> Option<OAuthClientRegistration> {
        self.codes.retain(|_, code| code.grant.client_id != client_id);
        self.tokens.retain(|_, token| token.grant.client_id != client_id);
        self.forget_replaced();
        self.clients.remove(client_id)
    }

    /// The client `client_id`.
    pub fn client(&self, client_id: &str) -> Option<&OAuthClientRegistration> {
        self.clients.get(client_id)
    }

    /// The metadata document of the server (RFC 8414 §2).
    pub fn metadata(&self) -> OAuthMetadata {
        let config = &self.config;
        let mut metadata = OAuthMetadata::new(OAuthMetadataKind::Server, &config.issuer);
        metadata.set_string(OAuthMetadata::AUTHORIZATION_ENDPOINT, &config.authorization_endpoint);
        metadata.set_string(OAuthMetadata::TOKEN_ENDPOINT, &config.token_endpoint);
        let optional = [
            (OAuthMetadata::INTROSPECTION_ENDPOINT, &config.introspection_endpoint),
            (OAuthMetadata::REVOCATION_ENDPOINT, &config.revocation_endpoint),
            (OAuthMetadata::PUSHED_AUTHORIZATION_REQUEST_ENDPOINT, &config.pushed_authorization_request_endpoint),
            (OAuthMetadata::DEVICE_AUTHORIZATION_ENDPOINT, &config.device_authorization_endpoint),
            (OAuthMetadata::JWKS_URI, &config.jwks_uri),
        ];
        for (name, value) in optional {
            if let Some(value) = value {
                metadata.set_string(name, value);
            }
        }
        metadata.set_strings(OAuthMetadata::RESPONSE_TYPES_SUPPORTED, &["code"]);
        // RFC 8414 §2: without it, ["query", "fragment"] would be assumed.
        metadata.set_strings(OAuthMetadata::RESPONSE_MODES_SUPPORTED, &["query"]);
        let mut grants =
            alloc::vec![OAuthGrant::AUTHORIZATION_CODE, OAuthGrant::CLIENT_CREDENTIALS, OAuthGrant::REFRESH_TOKEN];
        if config.device_authorization_endpoint.is_some() {
            grants.push(OAuthGrant::DEVICE_CODE);
        }
        metadata.set_strings(OAuthMetadata::GRANT_TYPES_SUPPORTED, &grants);
        let methods = ["none", "client_secret_basic", "client_secret_post", "private_key_jwt"];
        metadata.set_strings(OAuthMetadata::TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, &methods);
        let algorithms: Vec<&str> = config.assertion_algorithms.iter().map(|algorithm| algorithm.name()).collect();
        metadata.set_strings(OAuthMetadata::TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED, &algorithms);
        metadata.set_strings(OAuthMetadata::CODE_CHALLENGE_METHODS_SUPPORTED, &["S256"]);
        let algorithms: Vec<&str> = config.dpop.algorithms.iter().map(|algorithm| algorithm.name()).collect();
        metadata.set_strings(OAuthMetadata::DPOP_SIGNING_ALG_VALUES_SUPPORTED, &algorithms);
        metadata.set_boolean(OAuthMetadata::AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED, true);
        if config.require_pushed_authorization_requests {
            metadata.set_boolean(OAuthMetadata::REQUIRE_PUSHED_AUTHORIZATION_REQUESTS, true);
        }
        let mut scopes = OAuthScope::default();
        for client in self.clients.values() {
            for token in client.scope.tokens() {
                let _ = scopes.insert(token);
            }
        }
        let scopes: Vec<&str> = scopes.tokens().iter().map(String::as_str).collect();
        if !scopes.is_empty() {
            metadata.set_strings(OAuthMetadata::SCOPES_SUPPORTED, &scopes);
        }
        metadata
    }

    /// The public keys of JWT access tokens, for the `jwks_uri` document, or `None` with opaque
    /// tokens.
    pub fn jwks(&self) -> Option<JWKSet> {
        match &self.config.access_token_format {
            OAuthAccessTokenFormat::Opaque => None,
            OAuthAccessTokenFormat::JWT { key, .. } => {
                Some(JWKSet { keys: alloc::vec![key.to_public().ok()?], other: JSONObject::new() })
            }
        }
    }

    /// Forgets the codes, tokens, pushed requests, device authorizations and assertion
    /// identifiers that expired before `now`.
    pub fn expire(&mut self, now: i64) {
        self.codes.expire(now);
        for (digest, token) in self.tokens.expire(now) {
            if self.replaced.get(&token.family) == Some(&digest) {
                self.replaced.remove(&token.family);
            }
        }
        self.pushed.expire(now);
        for (_, device) in self.devices.expire(now) {
            self.user_codes.remove(&device.user_code);
        }
        self.assertions.expire(now);
    }

    /// Forgets the replaced refresh tokens whose records are gone.
    fn forget_replaced(&mut self) {
        let tokens = &self.tokens;
        self.replaced.retain(|_, digest| tokens.get(digest).is_some());
    }

    /// The digest a code or a token is kept as.
    pub fn digest(token: &str) -> [u8; 32] {
        SHA256::digest(token.as_bytes())
    }

    /// The record of the token `token`, if it was issued and has not expired or been revoked.
    pub fn token_record(&self, token: &str, now: i64) -> Option<&OAuthTokenRecord> {
        self.tokens.get(&OAuthServer::digest(token)).filter(|record| record.expires >= now && !record.replaced)
    }

    /// Revokes every token of the grant `family`.
    pub fn revoke_family(&mut self, family: u64) {
        self.tokens.retain(|_, token| token.family != family);
        self.codes.retain(|_, code| code.family != family);
        self.replaced.remove(&family);
    }

    /// Revokes every token issued for the resource owner `subject`.
    pub fn revoke_subject(&mut self, subject: &str) {
        self.tokens.retain(|_, token| token.grant.subject.as_deref() != Some(subject));
        self.codes.retain(|_, code| code.grant.subject.as_deref() != Some(subject));
        self.forget_replaced();
    }

    // The authorization endpoint (RFC 6749 §3.1, §4.1.1).

    /// Checks the authorization request of `parameters` (the query of the request, or its form
    /// body), taking the pushed request a `request_uri` names, once (RFC 9126 §4).
    pub fn authorize(
        &mut self,
        parameters: &OAuthParameters,
        now: i64,
    ) -> Result<OAuthAuthorization, OAuthAuthorizationFailure> {
        let local = |description: &str| {
            OAuthAuthorizationFailure::Local(OAuthErrorResponse::with_description(
                OAuthErrorCode::InvalidRequest,
                description,
            ))
        };
        if parameters.pairs().len() > self.config.maximum_parameters {
            return Err(local("too many parameters"));
        }
        let request = match OAuthAuthorizationRequest::from_parameters(parameters) {
            Ok(request) => request,
            // RFC 6749 §4.1.2.1: once the client and its redirect URI are known, errors go back
            // to the client.
            Err(_) => {
                let client_id = parameters.get("client_id").unwrap_or_default();
                let Some((_, target)) = self.redirect_target(client_id, parameters.get("redirect_uri")) else {
                    return Err(local("the request is not valid"));
                };
                return Err(self.redirect_error(
                    &target,
                    parameters.get("state"),
                    OAuthErrorCode::InvalidRequest,
                    "the request is not valid",
                ));
            }
        };
        let Some(request_uri) = &request.request_uri else {
            return self.check_authorization(&request, false);
        };
        // The request is used once, by the client that pushed it.
        let owned = self
            .pushed
            .get(request_uri)
            .is_some_and(|record| record.client_id == request.client_id && record.expires >= now);
        if !owned {
            return Err(local("the request_uri is unknown, expired or of another client"));
        }
        let record = self.pushed.remove(request_uri).ok_or_else(|| local("the request_uri is unknown"))?;
        let pushed = OAuthAuthorizationRequest::from_parameters(&record.parameters)
            .map_err(|_| local("the pushed request is not valid"))?;
        self.check_authorization(&pushed, true)
    }

    /// The redirect URI an authorization request of `client_id` goes back to: `redirect_uri`
    /// if it is one of the client's (RFC 9700 §2.1, RFC 8252 §7.3), or the client's only one
    /// when the request names none (RFC 6749 §3.1.2.3); `None` if there is none to trust.
    pub fn redirect_target(&self, client_id: &str, redirect_uri: Option<&str>) -> Option<(String, URIReference)> {
        let client = self.clients.get(client_id)?;
        let redirect_uri = match redirect_uri {
            Some(given) => client.redirect_uri(given).map(|_| given.to_string())?,
            None if client.redirect_uris.len() == 1 => client.redirect_uris[0].clone(),
            None => return None,
        };
        let target = URIReference::parse(&redirect_uri).ok()?;
        Some((redirect_uri, target))
    }

    /// The failure that sends the user agent back to `target` with the error `code`, the
    /// `state` and the issuer (RFC 6749 §4.1.2.1, RFC 9207).
    pub fn redirect_error(
        &self,
        target: &URIReference,
        state: Option<&str>,
        code: OAuthErrorCode,
        description: &str,
    ) -> OAuthAuthorizationFailure {
        let mut response = OAuthParameters::new();
        OAuthErrorResponse::with_description(code, description).to_parameters(&mut response);
        response.push_optional("state", state);
        response.push("iss", &self.config.issuer);
        OAuthAuthorizationFailure::Redirect(Box::new(response.add_to_query(target)))
    }

    /// Checks the authorization request `request` (RFC 6749 §4.1.1), `pushed` or not: the
    /// client, the redirect URI, the response type, PKCE, the scope and the resources.
    pub fn check_authorization(
        &self,
        request: &OAuthAuthorizationRequest,
        pushed: bool,
    ) -> Result<OAuthAuthorization, OAuthAuthorizationFailure> {
        let local = |description: &str| {
            OAuthAuthorizationFailure::Local(OAuthErrorResponse::with_description(
                OAuthErrorCode::InvalidRequest,
                description,
            ))
        };
        let client = self.clients.get(&request.client_id).ok_or_else(|| local("the client is unknown"))?;
        let (redirect_uri, target) = self
            .redirect_target(&request.client_id, request.redirect_uri.as_deref())
            .ok_or_else(|| local("the redirect_uri is not registered"))?;
        let redirect_error =
            |code, description: &str| self.redirect_error(&target, request.state.as_deref(), code, description);
        if self.config.require_pushed_authorization_requests && !pushed {
            return Err(redirect_error(OAuthErrorCode::InvalidRequest, "the request must be pushed"));
        }
        if request.response_type.as_deref() != Some("code") {
            return Err(redirect_error(
                OAuthErrorCode::UnsupportedResponseType,
                "only the code response type is supported",
            ));
        }
        if !client.allows_grant(OAuthGrant::AUTHORIZATION_CODE) {
            return Err(redirect_error(OAuthErrorCode::UnauthorizedClient, "the client may not use this grant"));
        }
        if request.code_challenge.is_none() && self.config.require_pkce {
            return Err(redirect_error(OAuthErrorCode::InvalidRequest, "a code_challenge of S256 is required"));
        }
        let scope = match &request.scope {
            Some(scope) if scope.is_subset_of(&client.scope) => scope.clone(),
            Some(_) => return Err(redirect_error(OAuthErrorCode::InvalidScope, "the scope is not allowed")),
            None => client.scope.clone(),
        };
        if request
            .resources
            .iter()
            .any(|resource| !OAuthServer::is_resource(resource) || !client.allows_resource(resource))
        {
            return Err(redirect_error(OAuthErrorCode::InvalidTarget, "a resource is not allowed"));
        }
        Ok(OAuthAuthorization {
            client_id: request.client_id.clone(),
            redirect_uri,
            redirect_uri_given: request.redirect_uri.is_some(),
            scope,
            state: request.state.clone(),
            challenge: request.code_challenge.clone(),
            resources: request.resources.clone(),
            dpop_jkt: request.dpop_jkt.clone(),
            other: request.other.clone(),
        })
    }

    /// Whether `resource` may be a resource indicator: an absolute URI without a fragment
    /// (RFC 8707 §2).
    pub fn is_resource(resource: &str) -> bool {
        URIReference::parse(resource).is_ok_and(|uri| uri.is_absolute())
    }

    /// Issues a code for `authorization`, which the resource owner `subject` approved for
    /// `grant` (whose client, scope and resources must be those of the authorization or
    /// narrower), and returns the URI to send the user agent to (RFC 6749 §4.1.2, RFC 9207).
    pub fn approve<R: Random>(
        &mut self,
        authorization: &OAuthAuthorization,
        grant: OAuthGrantRecord,
        now: i64,
        random: &mut R,
    ) -> Result<URIReference, OAuthError> {
        let target = self.check_decision(authorization)?;
        let narrower = grant.client_id == authorization.client_id
            && grant.scope.is_subset_of(&authorization.scope)
            && OAuthServer::is_subset(&grant.resources, &authorization.resources)
            && grant.subject.is_some();
        if !narrower {
            return Err(OAuthError::Invalid { parameter: "scope" });
        }
        if authorization.challenge.is_none() && self.config.require_pkce {
            return Err(OAuthError::Missing { parameter: "code_challenge" });
        }
        self.expire(now);
        if !self.codes.has_room(&authorization.client_id, 1) {
            return Err(OAuthError::Limit);
        }
        let code = self.random_token(random)?;
        let family = self.family();
        let expires = now + self.config.code_lifetime;
        let record = OAuthCodeRecord {
            grant,
            redirect_uri: authorization.redirect_uri_given.then(|| authorization.redirect_uri.clone()),
            challenge: authorization.challenge.clone(),
            dpop_jkt: authorization.dpop_jkt.clone(),
            expires,
            family,
            redeemed: false,
        };
        self.codes.insert(OAuthServer::digest(&code), record, expires)?;
        let response = OAuthAuthorizationResponse {
            code,
            state: authorization.state.clone(),
            issuer: Some(self.config.issuer.clone()),
        };
        Ok(response.to_parameters().add_to_query(&target))
    }

    /// The URI to send the user agent to when the resource owner denies `authorization`
    /// (`access_denied`, RFC 6749 §4.1.2.1).
    pub fn deny(&self, authorization: &OAuthAuthorization) -> Result<URIReference, OAuthError> {
        let target = self.check_decision(authorization)?;
        let mut parameters = OAuthParameters::new();
        OAuthErrorResponse::new(OAuthErrorCode::AccessDenied).to_parameters(&mut parameters);
        parameters.push_optional("state", authorization.state.as_deref());
        parameters.push("iss", &self.config.issuer);
        Ok(parameters.add_to_query(&target))
    }

    /// The redirect URI of `authorization`, checked again against the registration: the
    /// authorization may have been carried through the consent page, where it could be changed.
    pub fn check_decision(&self, authorization: &OAuthAuthorization) -> Result<URIReference, OAuthError> {
        let client =
            self.clients.get(&authorization.client_id).ok_or(OAuthError::Invalid { parameter: "client_id" })?;
        if !client.allows_grant(OAuthGrant::AUTHORIZATION_CODE)
            || client.redirect_uri(&authorization.redirect_uri).is_none()
        {
            return Err(OAuthError::Invalid { parameter: "redirect_uri" });
        }
        Ok(URIReference::parse(&authorization.redirect_uri)?)
    }

    /// Whether every one of `items` is in `set`, in time O((n + m) log m).
    pub fn is_subset(items: &[String], set: &[String]) -> bool {
        let set: BTreeSet<&str> = set.iter().map(String::as_str).collect();
        items.iter().all(|item| set.contains(item.as_str()))
    }

    // The token endpoint (RFC 6749 §3.2, §4.1.3, §4.4, §6; RFC 8628 §3.4).

    /// Answers a request to the token endpoint.
    pub fn token<R: Random>(&mut self, request: &OAuthEndpointRequest, now: i64, random: &mut R) -> OAuthHTTPResponse {
        self.expire(now);
        let result = self.token_response(request, now, random);
        self.respond(request, result.map(|response| OAuthHTTPResponse::json(200, response.encode())))
    }

    fn token_response<R: Random>(
        &mut self,
        request: &OAuthEndpointRequest,
        now: i64,
        random: &mut R,
    ) -> Result<OAuthTokenResponse, OAuthErrorResponse> {
        let parameters = self.form(request)?;
        let client = self.authenticate(request, &parameters, now)?;
        // RFC 9449 §5: a proof binds the access token to its key.
        let proof = match &request.dpop {
            Some(text) => {
                let target = DPoPTarget { method: "POST", uri: &self.config.token_endpoint, access_token: None };
                Some(self.dpop.check(text, &target, now)?)
            }
            None => None,
        };
        let confirmation = proof.as_ref().map(|proof: &DPoPProof| proof.thumbprint.clone());
        let token_request = OAuthTokenRequest::from_parameters(&parameters).map_err(|error| match error {
            OAuthError::Invalid { parameter: "grant_type" } => OAuthErrorResponse::with_description(
                OAuthErrorCode::UnsupportedGrantType,
                "the grant type is not supported",
            ),
            _ => OAuthErrorResponse::with_description(OAuthErrorCode::InvalidRequest, "the request is not valid"),
        })?;
        if matches!(token_request.grant, OAuthGrant::JWTBearer { .. }) {
            return Err(OAuthErrorResponse::with_description(
                OAuthErrorCode::UnsupportedGrantType,
                "the grant type is not supported",
            ));
        }
        if !client.allows_grant(token_request.grant.grant_type()) {
            return Err(OAuthErrorResponse::with_description(
                OAuthErrorCode::UnauthorizedClient,
                "the client may not use this grant",
            ));
        }
        let invalid_grant =
            |description: &str| OAuthErrorResponse::with_description(OAuthErrorCode::InvalidGrant, description);
        match &token_request.grant {
            OAuthGrant::AuthorizationCode { code, redirect_uri, code_verifier } => {
                let digest = OAuthServer::digest(code);
                let record = self
                    .codes
                    .update(&digest, |record, _| {
                        let first = !record.redeemed;
                        record.redeemed = true;
                        (first, record.clone())
                    })
                    .ok_or_else(|| invalid_grant("the code is not valid"))?;
                let (first, record) = record;
                if !first {
                    // RFC 6749 §4.1.2: a code used twice revokes what it gave.
                    self.revoke_family(record.family);
                    return Err(invalid_grant("the code was already used"));
                }
                if record.grant.client_id != client.client_id || record.expires < now {
                    return Err(invalid_grant("the code is not valid"));
                }
                if record.redirect_uri.is_some() && record.redirect_uri != *redirect_uri {
                    return Err(invalid_grant("the redirect_uri differs from the authorization request's"));
                }
                match (&record.challenge, code_verifier) {
                    (Some(challenge), Some(verifier)) if challenge.verify(verifier) => {}
                    (None, None) => {}
                    _ => return Err(invalid_grant("the code_verifier does not match")),
                }
                // RFC 9449 §10: a code bound to a key is exchanged with a proof of that key.
                if record.dpop_jkt.is_some() && record.dpop_jkt != confirmation {
                    return Err(invalid_grant("the DPoP key differs from the dpop_jkt of the authorization request"));
                }
                let mut grant = record.grant.clone();
                grant.resources = OAuthServer::narrow_resources(&grant.resources, &token_request.resources)?;
                grant.scope = OAuthServer::narrow_scope(&grant.scope, token_request.scope.as_ref())?;
                grant.confirmation = confirmation;
                let refresh = client.allows_grant(OAuthGrant::REFRESH_TOKEN);
                self.issue(grant, record.family, refresh, client.method.is_confidential(), now, random)
            }
            OAuthGrant::ClientCredentials => {
                // RFC 6749 §4.4: confidential clients only, and no refresh token (§4.4.3).
                if !client.method.is_confidential() {
                    return Err(OAuthErrorResponse::with_description(
                        OAuthErrorCode::UnauthorizedClient,
                        "a public client may not use this grant",
                    ));
                }
                let scope = match &token_request.scope {
                    Some(scope) if scope.is_subset_of(&client.scope) => scope.clone(),
                    Some(_) => return Err(OAuthErrorResponse::new(OAuthErrorCode::InvalidScope)),
                    None => client.scope.clone(),
                };
                for resource in &token_request.resources {
                    if !OAuthServer::is_resource(resource) || !client.allows_resource(resource) {
                        return Err(OAuthErrorResponse::new(OAuthErrorCode::InvalidTarget));
                    }
                }
                let grant = OAuthGrantRecord {
                    client_id: client.client_id.clone(),
                    scope,
                    resources: token_request.resources.clone(),
                    confirmation,
                    ..OAuthGrantRecord::default()
                };
                let family = self.family();
                self.issue(grant, family, false, true, now, random)
            }
            OAuthGrant::RefreshToken { refresh_token } => {
                let digest = OAuthServer::digest(refresh_token);
                let record = self
                    .tokens
                    .get(&digest)
                    .filter(|record| record.kind == OAuthTokenKind::Refresh && record.expires >= now)
                    .cloned()
                    .ok_or_else(|| invalid_grant("the refresh token is not valid"))?;
                if record.grant.client_id != client.client_id {
                    return Err(invalid_grant("the refresh token is not valid"));
                }
                if record.replaced {
                    // RFC 9700 §4.14.2: a replaced refresh token used again was stolen.
                    self.revoke_family(record.family);
                    return Err(invalid_grant("the refresh token was already used"));
                }
                // RFC 9449 §5: the refresh token of a public client is bound to its key.
                if record.grant.confirmation.is_some() && record.grant.confirmation != confirmation {
                    return Err(invalid_grant("the refresh token is bound to another DPoP key"));
                }
                let mut grant = record.grant.clone();
                grant.scope = OAuthServer::narrow_scope(&record.grant.scope, token_request.scope.as_ref())?;
                grant.resources = OAuthServer::narrow_resources(&record.grant.resources, &token_request.resources)?;
                grant.confirmation = confirmation;
                let unbound = client.method.is_confidential();
                if self.config.rotate_refresh_tokens {
                    // The old token is replaced only once the new ones are issued: a refused
                    // refresh (a full table) leaves the grant as it was.
                    let response = self.issue(grant, record.family, true, unbound, now, random)?;
                    self.tokens.update(&digest, |old, _| old.replaced = true);
                    if let Some(previous) = self.replaced.insert(record.family, digest)
                        && previous != digest
                    {
                        self.tokens.remove(&previous);
                    }
                    // The new refresh token keeps the grant's scope and lifetime, not a narrowed
                    // scope (§6) or a longer life.
                    if let Some(new) = response.refresh_token.as_deref().map(OAuthServer::digest) {
                        self.tokens.update(&new, |new, until| {
                            new.grant.scope = record.grant.scope.clone();
                            new.grant.resources = record.grant.resources.clone();
                            new.expires = record.expires;
                            *until = record.expires;
                        });
                    }
                    Ok(response)
                } else {
                    self.issue(grant, record.family, false, unbound, now, random)
                }
            }
            OAuthGrant::DeviceCode { device_code } => {
                let digest = OAuthServer::digest(device_code);
                let device = self
                    .devices
                    .update(&digest, |device, _| {
                        let too_soon = device.last_poll.is_some_and(|last| now - last < device.interval);
                        device.last_poll = Some(now);
                        if too_soon {
                            device.interval += 5;
                        }
                        (too_soon, device.clone())
                    })
                    .ok_or_else(|| invalid_grant("the device code is not valid"))?;
                let (too_soon, device) = device;
                if device.client_id != client.client_id {
                    return Err(invalid_grant("the device code is not valid"));
                }
                // An expired code is kept a while past its expiry, to answer this (RFC 8628 §3.5).
                if device.expires < now {
                    self.devices.remove(&digest);
                    self.user_codes.remove(&device.user_code);
                    return Err(OAuthErrorResponse::new(OAuthErrorCode::ExpiredToken));
                }
                if too_soon {
                    return Err(OAuthErrorResponse::new(OAuthErrorCode::SlowDown));
                }
                match device.state.clone() {
                    OAuthDeviceState::Pending => Err(OAuthErrorResponse::new(OAuthErrorCode::AuthorizationPending)),
                    OAuthDeviceState::Denied => {
                        self.devices.remove(&digest);
                        self.user_codes.remove(&device.user_code);
                        Err(OAuthErrorResponse::new(OAuthErrorCode::AccessDenied))
                    }
                    OAuthDeviceState::Approved(mut grant) => {
                        self.devices.remove(&digest);
                        self.user_codes.remove(&device.user_code);
                        let family = self.family();
                        let refresh = client.allows_grant(OAuthGrant::REFRESH_TOKEN);
                        grant.confirmation = confirmation;
                        self.issue(grant, family, refresh, client.method.is_confidential(), now, random)
                    }
                }
            }
            OAuthGrant::JWTBearer { .. } => Err(OAuthErrorResponse::new(OAuthErrorCode::UnsupportedGrantType)),
        }
    }

    /// The scope `asked` narrowed from `granted`: all of it when nothing is asked (RFC 6749 §6).
    pub fn narrow_scope(granted: &OAuthScope, asked: Option<&OAuthScope>) -> Result<OAuthScope, OAuthErrorResponse> {
        match asked {
            Some(asked) if asked.is_subset_of(granted) => Ok(asked.clone()),
            Some(_) => {
                Err(OAuthErrorResponse::with_description(OAuthErrorCode::InvalidScope, "the scope exceeds the grant"))
            }
            None => Ok(granted.clone()),
        }
    }

    /// The resources `asked` narrowed from `granted` (RFC 8707 §2.2): all of them when nothing
    /// is asked.
    pub fn narrow_resources(granted: &[String], asked: &[String]) -> Result<Vec<String>, OAuthErrorResponse> {
        if asked.is_empty() {
            return Ok(granted.to_vec());
        }
        if OAuthServer::is_subset(asked, granted) {
            Ok(asked.to_vec())
        } else {
            Err(OAuthErrorResponse::with_description(OAuthErrorCode::InvalidTarget, "a resource exceeds the grant"))
        }
    }

    /// Issues an access token, and a refresh token if `refresh`, for `grant` of `family`. The
    /// access token is bound to the key of `grant.confirmation`, if any; the refresh token too,
    /// unless `unbound_refresh` (RFC 9449 §5: only the refresh tokens of public clients are
    /// bound).
    pub fn issue<R: Random>(
        &mut self,
        grant: OAuthGrantRecord,
        family: u64,
        refresh: bool,
        unbound_refresh: bool,
        now: i64,
        random: &mut R,
    ) -> Result<OAuthTokenResponse, OAuthErrorResponse> {
        let unavailable =
            || OAuthErrorResponse::with_description(OAuthErrorCode::TemporarilyUnavailable, "too many tokens");
        if !self.tokens.has_room(&grant.client_id, 1 + usize::from(refresh)) {
            return Err(unavailable());
        }
        let failed = |_| OAuthErrorResponse::new(OAuthErrorCode::ServerError);
        let identifier = self.random_token(random).map_err(failed)?;
        let access_token = match &self.config.access_token_format {
            OAuthAccessTokenFormat::Opaque => self.random_token(random).map_err(failed)?,
            OAuthAccessTokenFormat::JWT { key, algorithm, default_audience } => {
                let claims = self.access_token_claims(&grant, &identifier, default_audience, now);
                let mut header = JOSEHeader::new();
                header.set_string("typ", "at+jwt");
                header.set_string("alg", algorithm.name());
                if let Some(key_id) = &key.key_id {
                    header.set_string("kid", key_id);
                }
                JWT::sign(&claims, &header, key, random)
                    .map_err(|_| OAuthErrorResponse::new(OAuthErrorCode::ServerError))?
            }
        };
        let token_type = if grant.confirmation.is_some() { "DPoP" } else { "Bearer" };
        let record = |kind, expires, identifier: String| OAuthTokenRecord {
            kind,
            grant: OAuthGrantRecord {
                confirmation: if kind == OAuthTokenKind::Refresh && unbound_refresh {
                    None
                } else {
                    grant.confirmation.clone()
                },
                ..grant.clone()
            },
            issued: now,
            expires,
            family,
            identifier,
            replaced: false,
        };
        // Both are made before either is kept, so that a failure keeps neither.
        let refresh_token = match refresh {
            true => Some((self.random_token(random).map_err(failed)?, self.random_token(random).map_err(failed)?)),
            false => None,
        };
        let expires = now + self.config.access_token_lifetime;
        let kept = self.tokens.insert(
            OAuthServer::digest(&access_token),
            record(OAuthTokenKind::Access, expires, identifier),
            expires,
        );
        kept.map_err(|_| unavailable())?;
        let refresh_token = match refresh_token {
            Some((token, identifier)) => {
                let expires = now + self.config.refresh_token_lifetime;
                let kept = self.tokens.insert(
                    OAuthServer::digest(&token),
                    record(OAuthTokenKind::Refresh, expires, identifier),
                    expires,
                );
                if kept.is_err() {
                    self.tokens.remove(&OAuthServer::digest(&access_token));
                    return Err(unavailable());
                }
                Some(token)
            }
            None => None,
        };
        Ok(OAuthTokenResponse {
            access_token,
            token_type: token_type.to_string(),
            expires_in: u64::try_from(self.config.access_token_lifetime).ok(),
            refresh_token,
            // An empty scope has no text of RFC 6749 §3.3: the member is left out.
            scope: (!grant.scope.is_empty()).then(|| grant.scope.clone()),
            other: JSONObject::new(),
        })
    }

    /// The claims of a JWT access token (RFC 9068 §2.2).
    pub fn access_token_claims(
        &self,
        grant: &OAuthGrantRecord,
        identifier: &str,
        default_audience: &str,
        now: i64,
    ) -> JWTClaims {
        let mut claims = JWTClaims::new();
        claims.set_string("iss", &self.config.issuer);
        claims.set_numeric_date("exp", now + self.config.access_token_lifetime);
        match grant.resources.as_slice() {
            [] => claims.set_string("aud", default_audience),
            [one] => claims.set_string("aud", one),
            many => {
                claims.set("aud", JSONValue::Array(many.iter().map(|value| JSONValue::String(value.clone())).collect()))
            }
        }
        // §2.2: without a resource owner, `sub` names the client.
        claims.set_string("sub", grant.subject.as_deref().unwrap_or(&grant.client_id));
        claims.set_string("client_id", &grant.client_id);
        claims.set_numeric_date("iat", now);
        claims.set_string("jti", identifier);
        if !grant.scope.is_empty() {
            claims.set_string("scope", &grant.scope.to_string());
        }
        if let Some(time) = grant.authentication_time {
            claims.set_numeric_date("auth_time", time);
        }
        if let Some(context) = &grant.authentication_context {
            claims.set_string("acr", context);
        }
        OAuthMembers::insert_confirmation(&mut claims.claims, grant.confirmation.as_deref());
        claims
    }

    // Introspection (RFC 7662) and revocation (RFC 7009).

    /// Answers a request to the introspection endpoint (RFC 7662 §2). Only clients registered
    /// with `introspection` may ask.
    pub fn introspect(&mut self, request: &OAuthEndpointRequest, now: i64) -> OAuthHTTPResponse {
        self.expire(now);
        let result = (|| {
            let parameters = self.form(request)?;
            let client = self.authenticate(request, &parameters, now)?;
            if !client.introspection {
                return Err(OAuthErrorResponse::with_description(
                    OAuthErrorCode::UnauthorizedClient,
                    "the client may not introspect",
                ));
            }
            let token =
                parameters.get("token").ok_or_else(|| OAuthErrorResponse::new(OAuthErrorCode::InvalidRequest))?;
            Ok(OAuthHTTPResponse::json(200, self.introspection(token, now).encode()))
        })();
        self.respond(request, result)
    }

    /// What introspection says of `token` (RFC 7662 §2.2).
    pub fn introspection(&self, token: &str, now: i64) -> OAuthIntrospectionResponse {
        let Some(record) = self.token_record(token, now) else {
            return OAuthIntrospectionResponse::inactive();
        };
        let audience = match (&self.config.access_token_format, record.grant.resources.is_empty()) {
            (OAuthAccessTokenFormat::JWT { default_audience, .. }, true) => alloc::vec![default_audience.clone()],
            _ => record.grant.resources.clone(),
        };
        // RFC 7662 §2.2: `token_type` is an access token type (RFC 6749 §5.1).
        let token_type = match (record.kind, record.grant.confirmation.is_some()) {
            (OAuthTokenKind::Refresh, _) => None,
            (OAuthTokenKind::Access, true) => Some("DPoP"),
            (OAuthTokenKind::Access, false) => Some("Bearer"),
        };
        let mut other = JSONObject::new();
        if let Some(time) = record.grant.authentication_time {
            other.insert("auth_time".to_string(), JSONValue::Number(JSONNumber::from(time)));
        }
        if let Some(context) = &record.grant.authentication_context {
            other.insert("acr".to_string(), JSONValue::String(context.clone()));
        }
        OAuthIntrospectionResponse {
            active: true,
            scope: (!record.grant.scope.is_empty()).then(|| record.grant.scope.clone()),
            client_id: Some(record.grant.client_id.clone()),
            username: None,
            token_type: token_type.map(str::to_string),
            expires: Some(record.expires),
            issued_at: Some(record.issued),
            not_before: None,
            subject: Some(record.grant.subject.clone().unwrap_or_else(|| record.grant.client_id.clone())),
            audience,
            issuer: Some(self.config.issuer.clone()),
            identifier: Some(record.identifier.clone()),
            confirmation: record.grant.confirmation.clone(),
            other,
        }
    }

    /// Answers a request to the revocation endpoint (RFC 7009 §2). The answer is 200 whether the
    /// token was known or not (§2.2), but a token of another client is refused with
    /// `unauthorized_client` (§2.1). Revoking a refresh token revokes the access tokens of its
    /// grant (§2.1).
    pub fn revoke(&mut self, request: &OAuthEndpointRequest, now: i64) -> OAuthHTTPResponse {
        self.expire(now);
        let result = (|| {
            let parameters = self.form(request)?;
            let client = self.authenticate(request, &parameters, now)?;
            let token =
                parameters.get("token").ok_or_else(|| OAuthErrorResponse::new(OAuthErrorCode::InvalidRequest))?;
            let digest = OAuthServer::digest(token);
            if let Some(record) = self.tokens.get(&digest) {
                if record.grant.client_id != client.client_id {
                    return Err(OAuthErrorResponse::with_description(
                        OAuthErrorCode::UnauthorizedClient,
                        "the token was issued to another client",
                    ));
                }
                match record.kind {
                    OAuthTokenKind::Refresh => {
                        let family = record.family;
                        self.revoke_family(family);
                    }
                    OAuthTokenKind::Access => {
                        self.tokens.remove(&digest);
                    }
                }
            }
            Ok(OAuthHTTPResponse {
                status: 200,
                headers: alloc::vec![("cache-control".to_string(), "no-store".to_string())],
                body: Vec::new(),
            })
        })();
        self.respond(request, result)
    }

    // Pushed authorization requests (RFC 9126).

    /// Answers a request to the pushed authorization request endpoint (RFC 9126 §2): the
    /// request is checked as the authorization endpoint would, and kept for a short time under a
    /// one-time `request_uri`.
    pub fn push<R: Random>(&mut self, request: &OAuthEndpointRequest, now: i64, random: &mut R) -> OAuthHTTPResponse {
        self.expire(now);
        let result = (|| {
            let parameters = self.form(request)?;
            let client = self.authenticate(request, &parameters, now)?;
            if parameters.get("request_uri").is_some() {
                return Err(OAuthErrorResponse::with_description(
                    OAuthErrorCode::InvalidRequest,
                    "request_uri may not be pushed",
                ));
            }
            if parameters.get("client_id").is_some_and(|client_id| client_id != client.client_id) {
                return Err(OAuthErrorResponse::new(OAuthErrorCode::InvalidRequest));
            }
            let mut stored = OAuthParameters::new();
            for (name, value) in parameters.pairs() {
                if !["client_secret", "client_assertion", "client_assertion_type", "client_id"].contains(&name.as_str())
                {
                    stored.push(name, value);
                }
            }
            stored.push("client_id", &client.client_id);
            // RFC 9449 §10.1: a proof at this endpoint binds the code to its key, as `dpop_jkt`.
            if let Some(text) = &request.dpop {
                let endpoint = self.config.pushed_authorization_request_endpoint.clone().unwrap_or_default();
                let target = DPoPTarget { method: "POST", uri: &endpoint, access_token: None };
                let proof = self.dpop.check(text, &target, now)?;
                if stored.get("dpop_jkt").is_some_and(|thumbprint| thumbprint != proof.thumbprint) {
                    return Err(OAuthErrorResponse::with_description(
                        OAuthErrorCode::InvalidDPoPProof,
                        "the dpop_jkt differs from the key of the DPoP proof",
                    ));
                }
                stored.remove("dpop_jkt");
                stored.push("dpop_jkt", &proof.thumbprint);
            }
            // The checks of the authorization endpoint, answered as JSON (§2.3).
            let pushed_request = OAuthAuthorizationRequest::from_parameters(&stored).map_err(|_| {
                OAuthErrorResponse::with_description(OAuthErrorCode::InvalidRequest, "the request is not valid")
            })?;
            match self.check_authorization(&pushed_request, true) {
                Ok(_) => {}
                Err(OAuthAuthorizationFailure::Local(error)) => return Err(error),
                Err(OAuthAuthorizationFailure::Redirect(uri)) => {
                    let parameters = OAuthParameters::from_query(&uri)
                        .map_err(|_| OAuthErrorResponse::new(OAuthErrorCode::ServerError))?;
                    return Err(OAuthErrorResponse::from_parameters(&parameters)
                        .and_then(Result::ok)
                        .unwrap_or_else(|| OAuthErrorResponse::new(OAuthErrorCode::InvalidRequest)));
                }
            }
            if !self.pushed.has_room(&client.client_id, 1) {
                return Err(OAuthErrorResponse::new(OAuthErrorCode::TemporarilyUnavailable));
            }
            let request_uri = format!(
                "{}{}",
                OAuthServer::REQUEST_URI_PREFIX,
                self.random_token(random).map_err(|_| OAuthErrorResponse::new(OAuthErrorCode::ServerError))?
            );
            let expires = now + self.config.pushed_request_lifetime;
            let record = OAuthPushedRecord { client_id: client.client_id.clone(), parameters: stored, expires };
            self.pushed
                .insert(request_uri.clone(), record, expires)
                .map_err(|_| OAuthErrorResponse::new(OAuthErrorCode::TemporarilyUnavailable))?;
            let response = OAuthPushedAuthorizationResponse {
                request_uri,
                expires_in: u64::try_from(self.config.pushed_request_lifetime).unwrap_or(0),
            };
            Ok(OAuthHTTPResponse::json(201, response.encode()))
        })();
        self.respond(request, result)
    }

    // Device authorization (RFC 8628).

    /// Answers a request to the device authorization endpoint (RFC 8628 §3.1, §3.2).
    pub fn device_authorize<R: Random>(
        &mut self,
        request: &OAuthEndpointRequest,
        now: i64,
        random: &mut R,
    ) -> OAuthHTTPResponse {
        self.expire(now);
        let result = (|| {
            let parameters = self.form(request)?;
            let client = self.authenticate(request, &parameters, now)?;
            if !client.allows_grant(OAuthGrant::DEVICE_CODE) {
                return Err(OAuthErrorResponse::new(OAuthErrorCode::UnauthorizedClient));
            }
            let verification_uri = self
                .config
                .verification_uri
                .clone()
                .ok_or_else(|| OAuthErrorResponse::new(OAuthErrorCode::ServerError))?;
            let scope = match parameters.get("scope").map(OAuthScope::parse).transpose() {
                Ok(Some(scope)) if scope.is_subset_of(&client.scope) => scope,
                Ok(None) => client.scope.clone(),
                _ => return Err(OAuthErrorResponse::new(OAuthErrorCode::InvalidScope)),
            };
            let resources: Vec<String> = parameters.all("resource").map(str::to_string).collect();
            if resources.iter().any(|resource| !OAuthServer::is_resource(resource) || !client.allows_resource(resource))
            {
                return Err(OAuthErrorResponse::new(OAuthErrorCode::InvalidTarget));
            }
            if !self.devices.has_room(&client.client_id, 1) {
                return Err(OAuthErrorResponse::new(OAuthErrorCode::TemporarilyUnavailable));
            }
            let failed = |_| OAuthErrorResponse::new(OAuthErrorCode::ServerError);
            let device_code = self.random_token(random).map_err(failed)?;
            let user_code = loop {
                let code = OAuthServer::user_code(self.config.user_code_length, random).map_err(failed)?;
                if !self.user_codes.contains_key(&code) {
                    break code;
                }
            };
            let digest = OAuthServer::digest(&device_code);
            let expires = now + self.config.device_code_lifetime;
            let record = OAuthDeviceRecord {
                client_id: client.client_id.clone(),
                scope,
                resources,
                user_code: user_code.clone(),
                expires,
                interval: self.config.device_interval,
                last_poll: None,
                state: OAuthDeviceState::Pending,
            };
            // Kept for one more lifetime past its expiry, to answer `expired_token` (§3.5).
            let kept = expires.saturating_add(self.config.device_code_lifetime);
            self.devices
                .insert(digest, record, kept)
                .map_err(|_| OAuthErrorResponse::new(OAuthErrorCode::TemporarilyUnavailable))?;
            self.user_codes.insert(user_code.clone(), digest);
            let display = OAuthServer::display_user_code(&user_code);
            let complete = URIReference::parse(&verification_uri).ok().map(|uri| {
                let mut parameters = OAuthParameters::new();
                parameters.push("user_code", &display);
                parameters.add_to_query(&uri).to_string()
            });
            let response = OAuthDeviceAuthorizationResponse {
                device_code,
                user_code: display,
                verification_uri,
                verification_uri_complete: complete,
                expires_in: u64::try_from(self.config.device_code_lifetime).unwrap_or(0),
                interval: u64::try_from(self.config.device_interval).ok(),
            };
            Ok(OAuthHTTPResponse::json(200, response.encode()))
        })();
        self.respond(request, result)
    }

    /// A new user code: `length` characters of [`OAuthServer::USER_CODE_CHARACTERS`], uniformly
    /// chosen (8 are about 34 bits, RFC 8628 §6.1).
    pub fn user_code<R: Random>(length: usize, random: &mut R) -> Result<String, OAuthError> {
        let characters = OAuthServer::USER_CODE_CHARACTERS;
        let limit = 256 - 256 % characters.len();
        let mut code = String::with_capacity(length);
        while code.len() < length {
            let mut byte = [0u8; 1];
            random.fill(&mut byte)?;
            if usize::from(byte[0]) < limit {
                code.push(char::from(characters[usize::from(byte[0]) % characters.len()]));
            }
        }
        Ok(code)
    }

    /// `code` as it is shown to the user: in groups of four joined by `-` (RFC 8628 §6.1).
    pub fn display_user_code(code: &str) -> String {
        let groups: Vec<&str> =
            code.as_bytes().chunks(4).map(|group| core::str::from_utf8(group).unwrap_or_default()).collect();
        groups.join("-")
    }

    /// `text` as a user code is compared: in upper case, without dashes and spaces (RFC 8628
    /// §6.1).
    pub fn normalize_user_code(text: &str) -> String {
        text.chars()
            .filter(|character| *character != '-' && !character.is_whitespace())
            .map(|character| character.to_ascii_uppercase())
            .collect()
    }

    /// The device authorization of the user code `user_code`, as the user entered it, to show
    /// the user what the device asks for.
    pub fn device(&self, user_code: &str, now: i64) -> Option<&OAuthDeviceRecord> {
        let digest = self.user_codes.get(&OAuthServer::normalize_user_code(user_code))?;
        self.devices.get(digest).filter(|device| device.expires >= now && device.state == OAuthDeviceState::Pending)
    }

    /// Records that the user approved the device authorization of `user_code` for `grant`, whose
    /// scope and resources must be those of the request or narrower.
    pub fn device_approve(&mut self, user_code: &str, grant: OAuthGrantRecord, now: i64) -> Result<(), OAuthError> {
        let device = self.device(user_code, now).ok_or(OAuthError::State)?;
        let narrower = grant.client_id == device.client_id
            && grant.scope.is_subset_of(&device.scope)
            && OAuthServer::is_subset(&grant.resources, &device.resources)
            && grant.subject.is_some();
        if !narrower {
            return Err(OAuthError::Invalid { parameter: "scope" });
        }
        let digest = *self.user_codes.get(&OAuthServer::normalize_user_code(user_code)).ok_or(OAuthError::State)?;
        self.devices.update(&digest, |device, _| device.state = OAuthDeviceState::Approved(grant));
        Ok(())
    }

    /// Records that the user denied the device authorization of `user_code`.
    pub fn device_deny(&mut self, user_code: &str, now: i64) -> Result<(), OAuthError> {
        self.device(user_code, now).ok_or(OAuthError::State)?;
        let digest = *self.user_codes.get(&OAuthServer::normalize_user_code(user_code)).ok_or(OAuthError::State)?;
        self.devices.update(&digest, |device, _| device.state = OAuthDeviceState::Denied);
        Ok(())
    }

    // Shared steps.

    /// The parameters of a POST of a form body (RFC 6749 §3.2: the token endpoint takes POST
    /// only, and the other endpoints follow it), at most `maximum_parameters` of them.
    pub fn form(&self, request: &OAuthEndpointRequest) -> Result<OAuthParameters, OAuthErrorResponse> {
        if request.method != "POST" || !request.is_form() {
            return Err(OAuthErrorResponse::with_description(
                OAuthErrorCode::InvalidRequest,
                "a POST of a form body is required",
            ));
        }
        if request.body.split(|byte| *byte == b'&').count() > self.config.maximum_parameters {
            return Err(OAuthErrorResponse::with_description(OAuthErrorCode::InvalidRequest, "too many parameters"));
        }
        OAuthParameters::parse(&request.body).map_err(|error| match error {
            OAuthError::Repeated { .. } => {
                OAuthErrorResponse::with_description(OAuthErrorCode::InvalidRequest, "a parameter is repeated")
            }
            _ => OAuthErrorResponse::with_description(OAuthErrorCode::InvalidRequest, "the body is not a form"),
        })
    }

    /// The client that `request` authenticates, checked against its registration (RFC 6749
    /// §2.3, §3.2.1; RFC 7523 §3).
    pub fn authenticate(
        &mut self,
        request: &OAuthEndpointRequest,
        parameters: &OAuthParameters,
        now: i64,
    ) -> Result<OAuthClientRegistration, OAuthErrorResponse> {
        let invalid = || {
            OAuthErrorResponse::with_description(OAuthErrorCode::InvalidClient, "the client could not be authenticated")
        };
        let credentials =
            OAuthClientCredentials::from_request(request.authorization.as_deref(), parameters).map_err(|error| {
                match error {
                    OAuthError::Invalid { parameter: "client_id" } => OAuthErrorResponse::with_description(
                        OAuthErrorCode::InvalidRequest,
                        "more than one authentication method",
                    ),
                    _ => invalid(),
                }
            })?;
        match credentials {
            OAuthClientCredentials::None { client_id } => {
                let client = self
                    .clients
                    .get(&client_id)
                    .filter(|client| client.method == OAuthClientMethod::None)
                    .ok_or_else(invalid)?;
                Ok(client.clone())
            }
            OAuthClientCredentials::SecretBasic { client_id, secret } => {
                let client = self
                    .clients
                    .get(&client_id)
                    .filter(|client| client.method == OAuthClientMethod::SecretBasic)
                    .ok_or_else(invalid)?;
                if !client.verify_secret(secret.expose()) {
                    return Err(invalid());
                }
                Ok(client.clone())
            }
            OAuthClientCredentials::SecretPost { client_id, secret } => {
                let method = OAuthClientMethod::SecretPost;
                let client =
                    self.clients.get(&client_id).filter(|client| client.method == method).ok_or_else(invalid)?;
                if !client.verify_secret(secret.expose()) {
                    return Err(invalid());
                }
                Ok(client.clone())
            }
            OAuthClientCredentials::Assertion { client_id, assertion } => {
                let unverified = JWS::from_compact(&assertion).map_err(|_| invalid())?;
                let claims = JWTClaims::decode(&unverified.payload).map_err(|_| invalid())?;
                let subject = claims.subject().ok().flatten().ok_or_else(invalid)?.to_string();
                if client_id.as_ref().is_some_and(|client_id| *client_id != subject) {
                    return Err(invalid());
                }
                let client = self
                    .clients
                    .get(&subject)
                    .filter(|client| client.method == OAuthClientMethod::PrivateKeyJWT)
                    .ok_or_else(invalid)?
                    .clone();
                let keys = client.keys.as_ref().ok_or_else(invalid)?;
                let config = JWSConfig::new(&self.config.assertion_algorithms);
                let mut verified = None;
                // RFC 7523 §3 and RFC 9126 §2: the issuer, the token endpoint or the pushed
                // authorization request endpoint identifies this server.
                let audiences: Vec<&String> = [
                    Some(&self.config.issuer),
                    Some(&self.config.token_endpoint),
                    self.config.pushed_authorization_request_endpoint.as_ref(),
                ]
                .into_iter()
                .flatten()
                .collect();
                'keys: for key in &keys.keys {
                    for audience in &audiences {
                        let mut validation = JWTValidation::new(now);
                        validation.issuer = Some(subject.clone());
                        validation.subject = Some(subject.clone());
                        validation.audience = Some(audience.to_string());
                        validation.required = alloc::vec!["exp".to_string(), "jti".to_string()];
                        if let Ok(jwt) = JWT::verify(&assertion, key, &config, &validation) {
                            verified = Some(jwt);
                            break 'keys;
                        }
                    }
                }
                let jwt = verified.ok_or_else(invalid)?;
                let expires = jwt.claims.expiration().ok().flatten().ok_or_else(invalid)? as i64;
                if expires - now > self.config.maximum_assertion_lifetime {
                    return Err(invalid());
                }
                let identifier = jwt.claims.jwt_id().ok().flatten().ok_or_else(invalid)?.to_string();
                // RFC 7523 §3: an assertion is used once.
                let key = (subject.clone(), identifier);
                if self.assertions.get(&key).is_some() {
                    return Err(invalid());
                }
                if self.assertions.insert(key, subject, expires).is_err() {
                    return Err(OAuthErrorResponse::with_description(
                        OAuthErrorCode::TemporarilyUnavailable,
                        "too many client assertions",
                    ));
                }
                Ok(client)
            }
        }
    }

    /// The HTTP response of `result`: an error as JSON with its status (RFC 6749 §5.2), and
    /// `WWW-Authenticate` for a client that failed to authenticate with the `Authorization`
    /// header.
    pub fn respond(
        &self,
        request: &OAuthEndpointRequest,
        result: Result<OAuthHTTPResponse, OAuthErrorResponse>,
    ) -> OAuthHTTPResponse {
        match result {
            Ok(response) => response,
            Err(error) => {
                let status = match error.code {
                    OAuthErrorCode::InvalidClient => 401,
                    OAuthErrorCode::TemporarilyUnavailable => 503,
                    OAuthErrorCode::ServerError => 500,
                    _ => 400,
                };
                let mut response = OAuthHTTPResponse::json(status, error.encode());
                if error.code == OAuthErrorCode::UseDPoPNonce
                    && let Some(nonce) = self.dpop.nonce()
                {
                    response.headers.push(("dpop-nonce".to_string(), nonce.to_string()));
                }
                if status == 401 && request.authorization.is_some() {
                    response.headers.push((
                        "www-authenticate".to_string(),
                        format!("Basic realm=\"{}\"", self.config.issuer.replace(['"', '\\'], "")),
                    ));
                }
                response
            }
        }
    }

    /// A new code or token: `token_octets` random octets in base64url.
    pub fn random_token<R: Random>(&self, random: &mut R) -> Result<String, OAuthError> {
        let mut octets = alloc::vec![0u8; self.config.token_octets];
        random.fill(&mut octets)?;
        Ok(Base64URL::encode(&octets))
    }

    fn family(&mut self) -> u64 {
        self.next_family += 1;
        self.next_family
    }
}
