//! OAuth 2.0 (RFC 6749) with the practices of RFC 9700 (BCP 240): the authorization code grant
//! with PKCE (RFC 7636, S256 only), client credentials, refresh tokens, Bearer tokens
//! (RFC 6750), metadata of authorization servers (RFC 8414) and protected resources
//! (RFC 9728), the issuer parameter (RFC 9207), resource indicators (RFC 8707) and JWT client
//! authentication (RFC 7523).
//!
//! Messages are values ([`OAuthAuthorizationRequest`], [`OAuthTokenRequest`],
//! [`OAuthTokenResponse`], [`OAuthErrorResponse`], [`OAuthMetadata`]) read from and written to
//! [`OAuthParameters`] or JSON. [`OAuthClient`] drives a client and [`OAuthServer`] an
//! authorization server (with introspection, RFC 7662; revocation, RFC 7009; pushed
//! authorization requests, RFC 9126; device authorization, RFC 8628; JWT access tokens,
//! RFC 9068) and [`OAuthResourceServer`] a protected resource (Bearer and DPoP tokens,
//! RFC 6750 and RFC 9449; step-up, RFC 9470), all without I/O: the HTTP requests and responses they make
//! ([`OAuthHTTPRequest`], [`OAuthHTTPResponse`]) are sent by the user.

mod authorization;
mod client;
mod client_authentication;
mod documents;
mod dpop;
mod error;
mod http;
mod metadata;
mod parameters;
mod pkce;
mod registration;
mod resource;
mod response;
mod scope;
mod server;
mod table;
mod token;

pub use authorization::{OAuthAuthorizationRequest, OAuthAuthorizationResponse};
pub use client::{OAuthClient, OAuthClientConfig, OAuthPendingAuthorization};
pub use client_authentication::{OAuthClientAuthentication, OAuthClientCredentials};
pub use documents::{
    OAuthDeviceAuthorizationResponse, OAuthIntrospectionResponse, OAuthMembers, OAuthPushedAuthorizationResponse,
};
pub use dpop::{DPoPConfig, DPoPProof, DPoPTarget, DPoPVerifier};
pub use error::OAuthError;
pub use http::{OAuthEndpointRequest, OAuthHTTPRequest, OAuthHTTPResponse};
pub use metadata::{OAuthMetadata, OAuthMetadataKind};
pub use parameters::OAuthParameters;
pub use pkce::{PKCEChallenge, PKCEMethod, PKCEVerifier};
pub use registration::{OAuthClientMethod, OAuthClientRegistration};
pub use resource::{
    OAuthChallenge, OAuthPresentedToken, OAuthResourceConfig, OAuthResourceError, OAuthResourceServer, OAuthTokenInfo,
    OAuthTokenScheme, OAuthTokenValidation,
};
pub use response::{OAuthErrorCode, OAuthErrorResponse};
pub use scope::OAuthScope;
pub use server::{
    OAuthAccessTokenFormat, OAuthAuthorization, OAuthAuthorizationFailure, OAuthCodeRecord, OAuthDeviceRecord,
    OAuthDeviceState, OAuthGrantRecord, OAuthPushedRecord, OAuthServer, OAuthServerConfig, OAuthTokenKind,
    OAuthTokenRecord,
};
pub use table::{OAuthRecord, OAuthTable};
pub use token::{OAuthGrant, OAuthTokenRequest, OAuthTokenResponse};
