use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::codec::uri::{URIHostKind, URIReference};
use crate::hash::Digest;
use crate::hash::sha::v2::SHA256;
use crate::protocol::jwt::JWKSet;
use crate::secret::ConstantTimeEq;

use super::{OAuthGrant, OAuthScope};

/// How a registered client authenticates (RFC 7591 §2, `token_endpoint_auth_method`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OAuthClientMethod {
    /// A public client: no credentials (RFC 6749 §2.1).
    None,
    SecretBasic,
    SecretPost,
    PrivateKeyJWT,
}

impl OAuthClientMethod {
    /// The name of the method in the registry of RFC 7591 §2.
    pub fn name(self) -> &'static str {
        match self {
            OAuthClientMethod::None => "none",
            OAuthClientMethod::SecretBasic => "client_secret_basic",
            OAuthClientMethod::SecretPost => "client_secret_post",
            OAuthClientMethod::PrivateKeyJWT => "private_key_jwt",
        }
    }

    /// Whether a client of this method is confidential (RFC 6749 §2.1).
    pub fn is_confidential(self) -> bool {
        self != OAuthClientMethod::None
    }
}

/// A client registered with an authorization server: its identifier, how it authenticates,
/// where it may be redirected, and what it may ask for.
#[derive(Clone, Debug)]
pub struct OAuthClientRegistration {
    pub client_id: String,
    pub method: OAuthClientMethod,
    /// The SHA-256 digest of the client secret, for the secret methods: the secret itself is
    /// not kept.
    pub secret_digest: Option<[u8; 32]>,
    /// The public keys of `private_key_jwt`.
    pub keys: Option<JWKSet>,
    /// The redirect URIs, compared exactly (RFC 9700 §2.1), except for the port of a loopback
    /// `http` URI (RFC 8252 §7.3).
    pub redirect_uris: Vec<String>,
    /// The values of `grant_type` the client may use.
    pub grant_types: Vec<String>,
    /// The scope the client may be granted; a request without a scope gets all of it.
    pub scope: OAuthScope,
    /// The resources the client may ask for (RFC 8707), or `None` for any.
    pub resources: Option<Vec<String>>,
    /// Whether the client may call the introspection endpoint (a protected resource, RFC 7662 §2.1).
    pub introspection: bool,
}

impl OAuthClientRegistration {
    /// A public client that uses the authorization code grant from `redirect_uris`, with
    /// refresh tokens.
    pub fn public(client_id: &str, redirect_uris: &[&str], scope: OAuthScope) -> OAuthClientRegistration {
        OAuthClientRegistration {
            client_id: client_id.to_string(),
            method: OAuthClientMethod::None,
            secret_digest: None,
            keys: None,
            redirect_uris: redirect_uris.iter().map(|uri| uri.to_string()).collect(),
            grant_types: alloc::vec![OAuthGrant::AUTHORIZATION_CODE.to_string(), OAuthGrant::REFRESH_TOKEN.to_string()],
            scope,
            resources: None,
            introspection: false,
        }
    }

    /// A confidential client of `method` (a secret method) and `secret`, with the grants
    /// `grant_types`.
    pub fn confidential(
        client_id: &str,
        method: OAuthClientMethod,
        secret: &str,
        grant_types: &[&str],
        scope: OAuthScope,
    ) -> OAuthClientRegistration {
        OAuthClientRegistration {
            client_id: client_id.to_string(),
            method,
            secret_digest: Some(OAuthClientRegistration::digest(secret)),
            keys: None,
            redirect_uris: Vec::new(),
            grant_types: grant_types.iter().map(|grant| grant.to_string()).collect(),
            scope,
            resources: None,
            introspection: false,
        }
    }

    /// The digest a secret is kept as.
    pub fn digest(secret: &str) -> [u8; 32] {
        SHA256::digest(secret.as_bytes())
    }

    /// Whether `secret` is the client's secret, compared in constant time.
    pub fn verify_secret(&self, secret: &str) -> bool {
        self.secret_digest.is_some_and(|digest| digest.ct_eq(&OAuthClientRegistration::digest(secret)).into_bool())
    }

    /// Whether the client may use the grant `grant_type`.
    pub fn allows_grant(&self, grant_type: &str) -> bool {
        self.grant_types.iter().any(|grant| grant == grant_type)
    }

    /// Whether the client may ask for `resource`.
    pub fn allows_resource(&self, resource: &str) -> bool {
        self.resources.as_ref().is_none_or(|resources| resources.iter().any(|own| own == resource))
    }

    /// The registered redirect URI that `redirect_uri` stands for: the identical one, or one of
    /// the loopback rule of RFC 8252 §7.3 (`http`, the host `127.0.0.1` or `[::1]`, any port,
    /// the rest identical).
    pub fn redirect_uri(&self, redirect_uri: &str) -> Option<&str> {
        self.redirect_uris
            .iter()
            .find(|registered| {
                *registered == redirect_uri || OAuthClientRegistration::same_loopback(registered, redirect_uri)
            })
            .map(String::as_str)
    }

    /// Whether `registered` and `given` are loopback redirect URIs that differ at most in their
    /// port (RFC 8252 §7.3). `localhost` is not loopback here (RFC 8252 §8.3).
    pub fn same_loopback(registered: &str, given: &str) -> bool {
        let (Ok(registered), Ok(given)) = (URIReference::parse(registered), URIReference::parse(given)) else {
            return false;
        };
        let loopback = |uri: &URIReference| {
            uri.scheme.as_deref() == Some("http")
                && uri.authority.as_ref().is_some_and(|authority| {
                    authority.userinfo.is_none()
                        && (authority.host == "127.0.0.1"
                            || (authority.host_kind() == URIHostKind::IPv6 && authority.host == "[::1]"))
                })
        };
        if !loopback(&registered) || !loopback(&given) {
            return false;
        }
        let (Some(first), Some(second)) = (&registered.authority, &given.authority) else {
            return false;
        };
        first.host == second.host
            && registered.path == given.path
            && registered.query == given.query
            && given.fragment.is_none()
    }
}
