use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{OAuthError, OAuthErrorResponse, OAuthParameters, OAuthScope, PKCEChallenge, PKCEMethod};

/// An authorization request (RFC 6749 §4.1.1) with PKCE (RFC 7636 §4.3), resource indicators
/// (RFC 8707 §2), the `request_uri` of a pushed request (RFC 9126 §4) and the DPoP key
/// binding of the code (RFC 9449 §10).
///
/// Parameters this type does not know are kept in `other`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuthAuthorizationRequest {
    pub response_type: Option<String>,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<OAuthScope>,
    pub state: Option<String>,
    pub code_challenge: Option<PKCEChallenge>,
    pub resources: Vec<String>,
    pub request_uri: Option<String>,
    /// The thumbprint of the DPoP key the code is to be bound to (RFC 9449 §10).
    pub dpop_jkt: Option<String>,
    pub other: OAuthParameters,
}

impl OAuthAuthorizationRequest {
    /// The names of the parameters this type holds in its own fields.
    pub const PARAMETERS: &'static [&'static str] = &[
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
        "resource",
        "request_uri",
        "dpop_jkt",
    ];

    /// The request of `parameters`. A `code_challenge` without `code_challenge_method` means
    /// `plain` (RFC 7636 §4.3), which is refused like any method but S256.
    pub fn from_parameters(parameters: &OAuthParameters) -> Result<OAuthAuthorizationRequest, OAuthError> {
        let code_challenge = match parameters.get("code_challenge") {
            Some(value) => {
                let method = PKCEMethod::parse(parameters.get("code_challenge_method").unwrap_or("plain"))?;
                Some(PKCEChallenge::new(method, value)?)
            }
            None if parameters.get("code_challenge_method").is_some() => {
                return Err(OAuthError::Missing { parameter: "code_challenge" });
            }
            None => None,
        };
        let mut other = OAuthParameters::new();
        for (name, value) in parameters.pairs() {
            if !OAuthAuthorizationRequest::PARAMETERS.contains(&name.as_str()) {
                other.push(name, value);
            }
        }
        Ok(OAuthAuthorizationRequest {
            response_type: parameters.get("response_type").map(str::to_string),
            client_id: parameters.required("client_id")?.to_string(),
            redirect_uri: parameters.get("redirect_uri").map(str::to_string),
            scope: parameters.get("scope").map(OAuthScope::parse).transpose()?,
            state: parameters.get("state").map(str::to_string),
            code_challenge,
            resources: parameters.all("resource").map(str::to_string).collect(),
            request_uri: parameters.get("request_uri").map(str::to_string),
            dpop_jkt: parameters.get("dpop_jkt").map(str::to_string),
            other,
        })
    }

    /// The parameters of this request.
    pub fn to_parameters(&self) -> OAuthParameters {
        let mut parameters = OAuthParameters::new();
        parameters.push_optional("response_type", self.response_type.as_deref());
        parameters.push("client_id", &self.client_id);
        parameters.push_optional("redirect_uri", self.redirect_uri.as_deref());
        if let Some(scope) = &self.scope {
            parameters.push("scope", &scope.to_string());
        }
        parameters.push_optional("state", self.state.as_deref());
        if let Some(challenge) = &self.code_challenge {
            parameters.push("code_challenge", &challenge.value);
            parameters.push("code_challenge_method", challenge.method.as_str());
        }
        for resource in &self.resources {
            parameters.push("resource", resource);
        }
        parameters.push_optional("request_uri", self.request_uri.as_deref());
        parameters.push_optional("dpop_jkt", self.dpop_jkt.as_deref());
        for (name, value) in self.other.pairs() {
            parameters.push(name, value);
        }
        parameters
    }
}

/// A successful authorization response (RFC 6749 §4.1.2) with the issuer identifier of
/// RFC 9207.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuthAuthorizationResponse {
    pub code: String,
    pub state: Option<String>,
    pub issuer: Option<String>,
}

impl OAuthAuthorizationResponse {
    /// The response of the parameters of a redirect; an error response fails with
    /// [`OAuthError::Response`].
    pub fn from_parameters(parameters: &OAuthParameters) -> Result<OAuthAuthorizationResponse, OAuthError> {
        if let Some(error) = OAuthErrorResponse::from_parameters(parameters) {
            return Err(OAuthError::Response(error?));
        }
        Ok(OAuthAuthorizationResponse {
            code: parameters.required("code")?.to_string(),
            state: parameters.get("state").map(str::to_string),
            issuer: parameters.get("iss").map(str::to_string),
        })
    }

    /// The parameters of this response.
    pub fn to_parameters(&self) -> OAuthParameters {
        let mut parameters = OAuthParameters::new();
        parameters.push("code", &self.code);
        parameters.push_optional("state", self.state.as_deref());
        parameters.push_optional("iss", self.issuer.as_deref());
        parameters
    }
}
