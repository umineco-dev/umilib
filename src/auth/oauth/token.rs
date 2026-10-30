use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::codec::json::{JSONConfig, JSONEncoder, JSONNumber, JSONObject, JSONValue};

use super::{OAuthError, OAuthErrorResponse, OAuthParameters, OAuthScope, PKCEVerifier};

/// The grant of a token request (RFC 6749 §4.1.3, §4.4.2, §6; RFC 8628 §3.4; RFC 7523 §2.1).
#[derive(Clone)]
pub enum OAuthGrant {
    /// `authorization_code`: the code, the redirect URI of the authorization request if it
    /// had one, and the PKCE verifier.
    AuthorizationCode { code: String, redirect_uri: Option<String>, code_verifier: Option<PKCEVerifier> },
    /// `client_credentials`.
    ClientCredentials,
    /// `refresh_token`.
    RefreshToken { refresh_token: String },
    /// `urn:ietf:params:oauth:grant-type:device_code` (RFC 8628 §3.4).
    DeviceCode { device_code: String },
    /// `urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7523 §2.1).
    JWTBearer { assertion: String },
}

impl OAuthGrant {
    pub const AUTHORIZATION_CODE: &'static str = "authorization_code";
    pub const CLIENT_CREDENTIALS: &'static str = "client_credentials";
    pub const REFRESH_TOKEN: &'static str = "refresh_token";
    pub const DEVICE_CODE: &'static str = "urn:ietf:params:oauth:grant-type:device_code";
    pub const JWT_BEARER: &'static str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    /// The value of `grant_type`.
    pub fn grant_type(&self) -> &'static str {
        match self {
            OAuthGrant::AuthorizationCode { .. } => OAuthGrant::AUTHORIZATION_CODE,
            OAuthGrant::ClientCredentials => OAuthGrant::CLIENT_CREDENTIALS,
            OAuthGrant::RefreshToken { .. } => OAuthGrant::REFRESH_TOKEN,
            OAuthGrant::DeviceCode { .. } => OAuthGrant::DEVICE_CODE,
            OAuthGrant::JWTBearer { .. } => OAuthGrant::JWT_BEARER,
        }
    }
}

/// A token request (RFC 6749 §3.2): a grant, the scope asked for, and resource indicators
/// (RFC 8707 §2.2). Client authentication is separate (`OAuthClientAuthentication`); its
/// parameters (`client_id`, `client_secret`, `client_assertion_type`, `client_assertion`)
/// are not part of this type.
#[derive(Clone)]
pub struct OAuthTokenRequest {
    pub grant: OAuthGrant,
    pub scope: Option<OAuthScope>,
    pub resources: Vec<String>,
    pub other: OAuthParameters,
}

impl OAuthTokenRequest {
    /// The names of the parameters this type holds in its own fields, or that belong to client
    /// authentication.
    pub const PARAMETERS: &'static [&'static str] = &[
        "grant_type",
        "code",
        "redirect_uri",
        "code_verifier",
        "refresh_token",
        "device_code",
        "assertion",
        "scope",
        "resource",
        "client_id",
        "client_secret",
        "client_assertion_type",
        "client_assertion",
    ];

    /// A request of `grant`, without a scope or resources.
    pub fn new(grant: OAuthGrant) -> OAuthTokenRequest {
        OAuthTokenRequest { grant, scope: None, resources: Vec::new(), other: OAuthParameters::new() }
    }

    /// The request of `parameters`; an unknown `grant_type` fails with Invalid.
    pub fn from_parameters(parameters: &OAuthParameters) -> Result<OAuthTokenRequest, OAuthError> {
        let grant = match parameters.required("grant_type")? {
            OAuthGrant::AUTHORIZATION_CODE => OAuthGrant::AuthorizationCode {
                code: parameters.required("code")?.to_string(),
                redirect_uri: parameters.get("redirect_uri").map(str::to_string),
                code_verifier: parameters.get("code_verifier").map(PKCEVerifier::new).transpose()?,
            },
            OAuthGrant::CLIENT_CREDENTIALS => OAuthGrant::ClientCredentials,
            OAuthGrant::REFRESH_TOKEN => {
                OAuthGrant::RefreshToken { refresh_token: parameters.required("refresh_token")?.to_string() }
            }
            OAuthGrant::DEVICE_CODE => {
                OAuthGrant::DeviceCode { device_code: parameters.required("device_code")?.to_string() }
            }
            OAuthGrant::JWT_BEARER => {
                OAuthGrant::JWTBearer { assertion: parameters.required("assertion")?.to_string() }
            }
            _ => return Err(OAuthError::Invalid { parameter: "grant_type" }),
        };
        let mut other = OAuthParameters::new();
        for (name, value) in parameters.pairs() {
            if !OAuthTokenRequest::PARAMETERS.contains(&name.as_str()) {
                other.push(name, value);
            }
        }
        Ok(OAuthTokenRequest {
            grant,
            scope: parameters.get("scope").map(OAuthScope::parse).transpose()?,
            resources: parameters.all("resource").map(str::to_string).collect(),
            other,
        })
    }

    /// The parameters of this request, without client authentication.
    pub fn to_parameters(&self) -> OAuthParameters {
        let mut parameters = OAuthParameters::new();
        parameters.push("grant_type", self.grant.grant_type());
        match &self.grant {
            OAuthGrant::AuthorizationCode { code, redirect_uri, code_verifier } => {
                parameters.push("code", code);
                parameters.push_optional("redirect_uri", redirect_uri.as_deref());
                parameters.push_optional("code_verifier", code_verifier.as_ref().map(PKCEVerifier::as_str));
            }
            OAuthGrant::ClientCredentials => {}
            OAuthGrant::RefreshToken { refresh_token } => parameters.push("refresh_token", refresh_token),
            OAuthGrant::DeviceCode { device_code } => parameters.push("device_code", device_code),
            OAuthGrant::JWTBearer { assertion } => parameters.push("assertion", assertion),
        }
        if let Some(scope) = &self.scope {
            parameters.push("scope", &scope.to_string());
        }
        for resource in &self.resources {
            parameters.push("resource", resource);
        }
        for (name, value) in self.other.pairs() {
            parameters.push(name, value);
        }
        parameters
    }
}

/// A successful token response (RFC 6749 §5.1). Members this type does not know are kept in
/// `other`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    /// `Bearer` (RFC 6750) or `DPoP` (RFC 9449); compared without regard to case.
    pub token_type: String,
    /// The lifetime of the access token in seconds.
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    /// The scope granted, if it differs from the one asked for or none was asked for (§5.1).
    pub scope: Option<OAuthScope>,
    pub other: JSONObject,
}

impl OAuthTokenResponse {
    /// The names of the members this type holds in its own fields.
    pub const MEMBERS: &'static [&'static str] =
        &["access_token", "token_type", "expires_in", "refresh_token", "scope"];

    /// The response of a body: a success for status 200, otherwise the error response, which
    /// fails with [`OAuthError::Response`] (RFC 6749 §5.2).
    pub fn decode(status: u16, body: &[u8]) -> Result<OAuthTokenResponse, OAuthError> {
        let value = JSONValue::decode(body, JSONConfig::default())?;
        let object = value.as_object().ok_or(OAuthError::Invalid { parameter: "body" })?;
        if status != 200 {
            return Err(OAuthError::Response(OAuthErrorResponse::from_object(object)?));
        }
        OAuthTokenResponse::from_object(object)
    }

    /// The response of the members of `object`.
    pub fn from_object(object: &JSONObject) -> Result<OAuthTokenResponse, OAuthError> {
        let string = |name: &'static str| match object.get(name) {
            None => Ok(None),
            Some(JSONValue::String(text)) if !text.is_empty() => Ok(Some(text.clone())),
            Some(_) => Err(OAuthError::Invalid { parameter: name }),
        };
        let expires_in = match object.get("expires_in") {
            None => None,
            Some(JSONValue::Number(number)) => {
                Some(number.as_u64().map_err(|_| OAuthError::Invalid { parameter: "expires_in" })?)
            }
            Some(_) => return Err(OAuthError::Invalid { parameter: "expires_in" }),
        };
        let scope = match object.get("scope") {
            None => None,
            Some(JSONValue::String(text)) => Some(OAuthScope::parse(text)?),
            Some(_) => return Err(OAuthError::Invalid { parameter: "scope" }),
        };
        let mut other = JSONObject::new();
        for (name, value) in &object.members {
            if !OAuthTokenResponse::MEMBERS.contains(&name.as_str()) {
                other.insert(name.clone(), value.clone());
            }
        }
        Ok(OAuthTokenResponse {
            access_token: string("access_token")?.ok_or(OAuthError::Missing { parameter: "access_token" })?,
            token_type: string("token_type")?.ok_or(OAuthError::Missing { parameter: "token_type" })?,
            expires_in,
            refresh_token: string("refresh_token")?,
            scope,
            other,
        })
    }

    /// Whether the token type is `name`, compared without regard to case (RFC 6749 §5.1).
    pub fn is_token_type(&self, name: &str) -> bool {
        self.token_type.eq_ignore_ascii_case(name)
    }

    /// The members as a JSON object.
    pub fn to_object(&self) -> JSONObject {
        let mut object = JSONObject::new();
        object.insert("access_token".to_string(), JSONValue::String(self.access_token.clone()));
        object.insert("token_type".to_string(), JSONValue::String(self.token_type.clone()));
        if let Some(seconds) = self.expires_in {
            object.insert("expires_in".to_string(), JSONValue::Number(JSONNumber::from(seconds)));
        }
        if let Some(token) = &self.refresh_token {
            object.insert("refresh_token".to_string(), JSONValue::String(token.clone()));
        }
        if let Some(scope) = &self.scope {
            object.insert("scope".to_string(), JSONValue::String(scope.to_string()));
        }
        for (name, value) in &self.other.members {
            if !OAuthTokenResponse::MEMBERS.contains(&name.as_str()) {
                object.insert(name.clone(), value.clone());
            }
        }
        object
    }

    /// The members as the JSON text of a response body.
    pub fn encode(&self) -> String {
        JSONEncoder::COMPACT.encode(&JSONValue::Object(self.to_object()))
    }
}
