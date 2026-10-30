use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};

use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;
use crate::codec::uri::URIForm;
use crate::crypto::random::Random;
use crate::protocol::jwt::{Base64URL, JOSEHeader, JWK, JWSAlgorithm, JWT, JWTClaims};
use crate::secret::Secret;

use super::{OAuthError, OAuthParameters};

/// How a client authenticates to the token endpoint and the other endpoints of an
/// authorization server (RFC 6749 §2.3, RFC 7523 §2.2), named as the
/// `token_endpoint_auth_method` registry of RFC 7591 names them.
#[derive(Clone)]
pub enum OAuthClientAuthentication {
    /// `none`: a public client, which sends only its `client_id` (RFC 6749 §3.2.1).
    None { client_id: String },
    /// `client_secret_basic`: the identifier and the secret in an HTTP Basic `Authorization`
    /// header, each form-encoded first (RFC 6749 §2.3.1).
    SecretBasic { client_id: String, secret: Secret<String> },
    /// `client_secret_post`: the identifier and the secret as parameters of the body
    /// (RFC 6749 §2.3.1; NOT RECOMMENDED there, for clients that cannot send the header).
    SecretPost { client_id: String, secret: Secret<String> },
    /// `private_key_jwt`: a JWT signed with the client's private key (RFC 7523 §2.2).
    PrivateKeyJWT { client_id: String, key: Box<JWK>, algorithm: JWSAlgorithm },
}

impl OAuthClientAuthentication {
    /// The `client_assertion_type` of a JWT assertion (RFC 7523 §2.2).
    pub const JWT_BEARER: &'static str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    /// The default lifetime of a client assertion, in seconds: short, as the assertion is used
    /// once.
    pub const ASSERTION_LIFETIME: i64 = 60;
    /// The random octets of the `jti` of an assertion.
    pub const ASSERTION_ID_OCTETS: usize = 16;

    /// The identifier of the client.
    pub fn client_id(&self) -> &str {
        match self {
            OAuthClientAuthentication::None { client_id }
            | OAuthClientAuthentication::SecretBasic { client_id, .. }
            | OAuthClientAuthentication::SecretPost { client_id, .. }
            | OAuthClientAuthentication::PrivateKeyJWT { client_id, .. } => client_id,
        }
    }

    /// The name of the method in the registry of RFC 7591 §2.
    pub fn method(&self) -> &'static str {
        match self {
            OAuthClientAuthentication::None { .. } => "none",
            OAuthClientAuthentication::SecretBasic { .. } => "client_secret_basic",
            OAuthClientAuthentication::SecretPost { .. } => "client_secret_post",
            OAuthClientAuthentication::PrivateKeyJWT { .. } => "private_key_jwt",
        }
    }

    /// The value of the `Authorization` header of `client_secret_basic`: `Basic`, and the
    /// base64 of the form-encoded identifier, `:` and the form-encoded secret (RFC 6749 §2.3.1).
    pub fn basic_credentials(client_id: &str, secret: &str) -> Secret<String> {
        let joined = Secret::new(format!("{}:{}", URIForm::encode_text(client_id), URIForm::encode_text(secret)));
        Secret::new(format!("Basic {}", Base64::STANDARD.encode(joined.expose().as_bytes())))
    }

    /// Adds this authentication to a request to an endpoint of the authorization server
    /// `audience` (its issuer identifier, the audience of an assertion): parameters go into
    /// `parameters`, and the value of the `Authorization` header, if the method uses one, is
    /// returned. `now` is the time in seconds since 1970, and `lifetime` the seconds an
    /// assertion lives.
    pub fn apply<R: Random>(
        &self,
        audience: &str,
        now: i64,
        lifetime: i64,
        random: &mut R,
        parameters: &mut OAuthParameters,
    ) -> Result<Option<Secret<String>>, OAuthError> {
        for name in ["client_id", "client_secret", "client_assertion_type", "client_assertion"] {
            parameters.remove(name);
        }
        match self {
            OAuthClientAuthentication::None { client_id } => {
                parameters.push("client_id", client_id);
                Ok(None)
            }
            OAuthClientAuthentication::SecretBasic { client_id, secret } => {
                Ok(Some(OAuthClientAuthentication::basic_credentials(client_id, secret.expose())))
            }
            OAuthClientAuthentication::SecretPost { client_id, secret } => {
                parameters.push("client_id", client_id);
                parameters.push("client_secret", secret.expose());
                Ok(None)
            }
            OAuthClientAuthentication::PrivateKeyJWT { client_id, key, algorithm } => {
                let assertion =
                    OAuthClientAuthentication::assertion(client_id, audience, now, lifetime, key, *algorithm, random)?;
                parameters.push("client_id", client_id);
                parameters.push("client_assertion_type", OAuthClientAuthentication::JWT_BEARER);
                parameters.push("client_assertion", &assertion);
                Ok(None)
            }
        }
    }

    /// A client assertion (RFC 7523 §3): `iss` and `sub` the client, `aud` the authorization
    /// server, a random `jti`, `iat` now and `exp` `lifetime` seconds later, signed with `key`.
    pub fn assertion<R: Random>(
        client_id: &str,
        audience: &str,
        now: i64,
        lifetime: i64,
        key: &JWK,
        algorithm: JWSAlgorithm,
        random: &mut R,
    ) -> Result<String, OAuthError> {
        let mut identifier = [0u8; OAuthClientAuthentication::ASSERTION_ID_OCTETS];
        random.fill(&mut identifier)?;
        let mut claims = JWTClaims::new();
        claims.set_string("iss", client_id);
        claims.set_string("sub", client_id);
        claims.set_string("aud", audience);
        claims.set_string("jti", &Base64URL::encode(&identifier));
        claims.set_numeric_date("iat", now);
        claims.set_numeric_date("exp", now.saturating_add(lifetime));
        let mut header = JOSEHeader::new();
        header.set_string("alg", algorithm.name());
        if let Some(key_id) = &key.key_id {
            header.set_string("kid", key_id);
        }
        Ok(JWT::sign(&claims, &header, key, random)?)
    }

    /// Whether `client_id` is of the grammar of RFC 6749 Appendix A.1 (`*VSCHAR`) and not empty.
    pub fn is_client_id(client_id: &str) -> bool {
        !client_id.is_empty() && client_id.bytes().all(|byte| (0x20..=0x7E).contains(&byte))
    }
}

impl core::fmt::Debug for OAuthClientAuthentication {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "OAuthClientAuthentication({}, {:?})", self.method(), self.client_id())
    }
}

/// The credentials a client presented in a request to the authorization server, as read by the
/// server (RFC 6749 §2.3, RFC 7523 §2.2), before they are checked.
#[derive(Clone)]
pub enum OAuthClientCredentials {
    /// Only a `client_id` parameter: a public client.
    None { client_id: String },
    /// HTTP Basic credentials, each decoded from the form encoding (RFC 6749 §2.3.1).
    SecretBasic { client_id: String, secret: Secret<String> },
    /// `client_id` and `client_secret` parameters.
    SecretPost { client_id: String, secret: Secret<String> },
    /// A JWT assertion (RFC 7523 §2.2); `client_id`, if given, must be the assertion's `sub`.
    Assertion { client_id: Option<String>, assertion: String },
}

impl OAuthClientCredentials {
    /// The credentials of a request whose `Authorization` header is `authorization` and whose
    /// body has `parameters`. A request that uses more than one method (RFC 6749 §2.3), or no
    /// way of naming the client, fails with Invalid.
    pub fn from_request(
        authorization: Option<&str>,
        parameters: &OAuthParameters,
    ) -> Result<OAuthClientCredentials, OAuthError> {
        let basic = authorization.and_then(|value| {
            let (scheme, credentials) = value.split_once(' ')?;
            scheme.eq_ignore_ascii_case("Basic").then(|| credentials.trim())
        });
        let secret = parameters.get("client_secret");
        let assertion = parameters.get("client_assertion");
        let methods = usize::from(basic.is_some()) + usize::from(secret.is_some()) + usize::from(assertion.is_some());
        if methods > 1 {
            return Err(OAuthError::Invalid { parameter: "client_id" });
        }
        let client_id = parameters.get("client_id");
        if let Some(credentials) = basic {
            let invalid = OAuthError::Invalid { parameter: "authorization" };
            let decoded = Secret::new(Base64::STANDARD.decode(credentials.as_bytes()).map_err(|_| invalid.clone())?);
            let text = core::str::from_utf8(decoded.expose()).map_err(|_| invalid.clone())?;
            let (id, secret) = text.split_once(':').ok_or(invalid)?;
            let id = URIForm::decode(id.as_bytes())?;
            if client_id.is_some_and(|given| given != id) {
                return Err(OAuthError::Invalid { parameter: "client_id" });
            }
            return Ok(OAuthClientCredentials::SecretBasic {
                client_id: id,
                secret: Secret::new(URIForm::decode(secret.as_bytes())?),
            });
        }
        if let Some(assertion) = assertion {
            if parameters.get("client_assertion_type") != Some(OAuthClientAuthentication::JWT_BEARER) {
                return Err(OAuthError::Invalid { parameter: "client_assertion_type" });
            }
            return Ok(OAuthClientCredentials::Assertion {
                client_id: client_id.map(str::to_string),
                assertion: assertion.to_string(),
            });
        }
        let client_id = client_id.ok_or(OAuthError::Missing { parameter: "client_id" })?.to_string();
        Ok(match secret {
            Some(secret) => OAuthClientCredentials::SecretPost { client_id, secret: Secret::new(secret.to_string()) },
            None => OAuthClientCredentials::None { client_id },
        })
    }

    /// The name of the method in the registry of RFC 7591 §2.
    pub fn method(&self) -> &'static str {
        match self {
            OAuthClientCredentials::None { .. } => "none",
            OAuthClientCredentials::SecretBasic { .. } => "client_secret_basic",
            OAuthClientCredentials::SecretPost { .. } => "client_secret_post",
            OAuthClientCredentials::Assertion { .. } => "private_key_jwt",
        }
    }
}

impl core::fmt::Debug for OAuthClientCredentials {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "OAuthClientCredentials({})", self.method())
    }
}
