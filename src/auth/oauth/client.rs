use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::codec::uri::URIReference;
use crate::crypto::random::Random;
use crate::protocol::jwt::Base64URL;
use crate::secret::ConstantTimeEq;

use super::{
    OAuthAuthorizationRequest, OAuthAuthorizationResponse, OAuthClientAuthentication, OAuthError, OAuthErrorResponse,
    OAuthGrant, OAuthHTTPRequest, OAuthMetadata, OAuthMetadataKind, OAuthParameters, OAuthScope, OAuthTokenRequest,
    PKCEMethod, PKCEVerifier,
};

/// The configuration of an [`OAuthClient`]: who the client is, the authorization server it
/// talks to, and its limits.
#[derive(Clone, Debug)]
pub struct OAuthClientConfig {
    pub authentication: OAuthClientAuthentication,
    /// The redirect URI registered for the client, sent in every authorization request.
    pub redirect_uri: String,
    /// The issuer identifier of the authorization server.
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// Whether an authorization response must carry `iss` (RFC 9207 §2.4): true when the
    /// server's metadata says it sends one.
    pub issuer_parameter_required: bool,
    /// The most authorization requests waiting for their response; the oldest is forgotten
    /// to make room.
    pub maximum_pending: usize,
    /// The seconds an authorization request waits for its response.
    pub pending_lifetime: i64,
    /// The random octets of a `state`.
    pub state_octets: usize,
    /// The seconds a client assertion lives (`private_key_jwt`).
    pub assertion_lifetime: i64,
}

impl OAuthClientConfig {
    /// A configuration from the metadata of the authorization server, which must have been
    /// checked against the issuer it was fetched for (`OAuthMetadata::check`), with the
    /// default limits.
    pub fn from_metadata(
        metadata: &OAuthMetadata,
        authentication: OAuthClientAuthentication,
        redirect_uri: &str,
    ) -> Result<OAuthClientConfig, OAuthError> {
        if metadata.kind != OAuthMetadataKind::Server {
            return Err(OAuthError::Invalid { parameter: "issuer" });
        }
        let required = |name: &'static str| -> Result<String, OAuthError> {
            Ok(metadata.string(name)?.ok_or(OAuthError::Missing { parameter: name })?.to_string())
        };
        Ok(OAuthClientConfig {
            authentication,
            redirect_uri: redirect_uri.to_string(),
            issuer: metadata.identifier()?.to_string(),
            authorization_endpoint: required(OAuthMetadata::AUTHORIZATION_ENDPOINT)?,
            token_endpoint: required(OAuthMetadata::TOKEN_ENDPOINT)?,
            issuer_parameter_required: metadata
                .boolean(OAuthMetadata::AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED)?
                .unwrap_or(false),
            maximum_pending: 16,
            pending_lifetime: 600,
            state_octets: 16,
            assertion_lifetime: OAuthClientAuthentication::ASSERTION_LIFETIME,
        })
    }
}

/// An authorization request waiting for its response: its `state`, the PKCE verifier, the
/// resources asked for and when it was made.
#[derive(Clone)]
pub struct OAuthPendingAuthorization {
    pub state: String,
    pub verifier: PKCEVerifier,
    pub resources: Vec<String>,
    pub created: i64,
}

/// A client of the authorization code grant with PKCE (RFC 6749 §4.1, RFC 7636) and of the
/// token endpoint, without I/O: it makes the authorization URL, checks the response the
/// browser brings back, and makes the token requests, which the user sends over HTTP.
///
/// Times are seconds since 1970.
pub struct OAuthClient {
    config: OAuthClientConfig,
    pending: Vec<OAuthPendingAuthorization>,
}

impl OAuthClient {
    pub fn new(config: OAuthClientConfig) -> OAuthClient {
        OAuthClient { config, pending: Vec::new() }
    }

    pub fn config(&self) -> &OAuthClientConfig {
        &self.config
    }

    /// The authorization requests waiting for their response.
    pub fn pending(&self) -> &[OAuthPendingAuthorization] {
        &self.pending
    }

    /// The URL to send the user's browser to: an authorization request for `scope` and
    /// `resources` with a new random `state` and an S256 code challenge (RFC 7636 §4.3), added
    /// to the query of the authorization endpoint.
    pub fn authorize<R: Random>(
        &mut self,
        scope: Option<&OAuthScope>,
        resources: &[&str],
        now: i64,
        random: &mut R,
    ) -> Result<URIReference, OAuthError> {
        let endpoint = URIReference::parse(&self.config.authorization_endpoint)?;
        let mut octets = alloc::vec![0u8; self.config.state_octets];
        random.fill(&mut octets)?;
        let state = Base64URL::encode(&octets);
        let verifier = PKCEVerifier::generate(random)?;
        let request = OAuthAuthorizationRequest {
            response_type: Some("code".to_string()),
            client_id: self.config.authentication.client_id().to_string(),
            redirect_uri: Some(self.config.redirect_uri.clone()),
            scope: scope.cloned(),
            state: Some(state.clone()),
            code_challenge: Some(verifier.challenge(PKCEMethod::S256)),
            resources: resources.iter().map(|resource| resource.to_string()).collect(),
            ..OAuthAuthorizationRequest::default()
        };
        self.expire(now);
        if self.config.maximum_pending == 0 {
            return Err(OAuthError::Limit);
        }
        while self.pending.len() >= self.config.maximum_pending {
            self.pending.remove(0);
        }
        self.pending.push(OAuthPendingAuthorization {
            state,
            verifier,
            resources: request.resources.clone(),
            created: now,
        });
        Ok(request.to_parameters().add_to_query(&endpoint))
    }

    /// Forgets the authorization requests older than the pending lifetime.
    pub fn expire(&mut self, now: i64) {
        let lifetime = self.config.pending_lifetime;
        self.pending.retain(|pending| now.saturating_sub(pending.created) <= lifetime);
    }

    /// The token request of the authorization response at `redirect`, the URI the browser was
    /// sent back to. The response must carry the `state` of a pending request, which is then
    /// forgotten (RFC 6749 §10.12), and, if it carries `iss` or the server always sends one,
    /// the issuer of the server (RFC 9207 §2.4). An error response fails with
    /// [`OAuthError::Response`] after the same checks.
    pub fn callback(&mut self, redirect: &URIReference, now: i64) -> Result<OAuthTokenRequest, OAuthError> {
        self.expire(now);
        let parameters = OAuthParameters::from_query(redirect)?;
        let state = parameters.get("state").ok_or(OAuthError::State)?;
        let mut found = None;
        for (index, pending) in self.pending.iter().enumerate() {
            if pending.state.as_bytes().ct_eq(state.as_bytes()).into_bool() {
                found = Some(index);
            }
        }
        let pending = self.pending.remove(found.ok_or(OAuthError::State)?);
        match parameters.get("iss") {
            Some(issuer) if issuer != self.config.issuer => return Err(OAuthError::Issuer),
            None if self.config.issuer_parameter_required => return Err(OAuthError::Issuer),
            _ => {}
        }
        if let Some(error) = OAuthErrorResponse::from_parameters(&parameters) {
            return Err(OAuthError::Response(error?));
        }
        let response = OAuthAuthorizationResponse::from_parameters(&parameters)?;
        let mut request = OAuthTokenRequest::new(OAuthGrant::AuthorizationCode {
            code: response.code,
            redirect_uri: Some(self.config.redirect_uri.clone()),
            code_verifier: Some(pending.verifier),
        });
        request.resources = pending.resources;
        Ok(request)
    }

    /// The HTTP request of the token request `request`, with the client's authentication
    /// (RFC 6749 §3.2, §2.3).
    pub fn token_request<R: Random>(
        &self,
        request: &OAuthTokenRequest,
        now: i64,
        random: &mut R,
    ) -> Result<OAuthHTTPRequest, OAuthError> {
        self.endpoint_request(&self.config.token_endpoint, request.to_parameters(), now, random)
    }

    /// The HTTP POST of `parameters` to `endpoint` of the authorization server, with the
    /// client's authentication: the form of the token, introspection, revocation, pushed
    /// authorization and device authorization endpoints.
    pub fn endpoint_request<R: Random>(
        &self,
        endpoint: &str,
        mut parameters: OAuthParameters,
        now: i64,
        random: &mut R,
    ) -> Result<OAuthHTTPRequest, OAuthError> {
        let authorization = self.config.authentication.apply(
            &self.config.issuer,
            now,
            self.config.assertion_lifetime,
            random,
            &mut parameters,
        )?;
        let mut headers = alloc::vec![("content-type".to_string(), OAuthHTTPRequest::FORM.to_string())];
        if let Some(authorization) = authorization {
            headers.push(("authorization".to_string(), authorization.expose().clone()));
        }
        Ok(OAuthHTTPRequest {
            method: "POST".to_string(),
            uri: endpoint.to_string(),
            headers,
            body: parameters.encode().into_bytes(),
        })
    }
}
