use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::codec::json::{JSONConfig, JSONEncoder, JSONObject, JSONValue};
use crate::codec::uri::URIReference;

use super::OAuthError;

/// The two kinds of metadata documents: of an authorization server (RFC 8414) and of a
/// protected resource (RFC 9728).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OAuthMetadataKind {
    Server,
    Resource,
}

impl OAuthMetadataKind {
    /// The member that holds the identifier the document describes: `issuer` (RFC 8414 §2) or
    /// `resource` (RFC 9728 §2).
    pub fn identifier_member(self) -> &'static str {
        match self {
            OAuthMetadataKind::Server => "issuer",
            OAuthMetadataKind::Resource => "resource",
        }
    }

    /// The well-known URI suffix of the document (RFC 8414 §3, RFC 9728 §3).
    pub fn well_known(self) -> &'static str {
        match self {
            OAuthMetadataKind::Server => "oauth-authorization-server",
            OAuthMetadataKind::Resource => "oauth-protected-resource",
        }
    }
}

/// A metadata document (RFC 8414 §2, RFC 9728 §2): a JSON object whose members are read and
/// set by name. The names of the registered members are constants of this type.
#[derive(Clone, Debug, PartialEq)]
pub struct OAuthMetadata {
    pub kind: OAuthMetadataKind,
    pub object: JSONObject,
}

impl OAuthMetadata {
    // RFC 8414 §2.
    pub const ISSUER: &'static str = "issuer";
    pub const AUTHORIZATION_ENDPOINT: &'static str = "authorization_endpoint";
    pub const TOKEN_ENDPOINT: &'static str = "token_endpoint";
    pub const JWKS_URI: &'static str = "jwks_uri";
    pub const REGISTRATION_ENDPOINT: &'static str = "registration_endpoint";
    pub const SCOPES_SUPPORTED: &'static str = "scopes_supported";
    pub const RESPONSE_TYPES_SUPPORTED: &'static str = "response_types_supported";
    pub const RESPONSE_MODES_SUPPORTED: &'static str = "response_modes_supported";
    pub const GRANT_TYPES_SUPPORTED: &'static str = "grant_types_supported";
    pub const TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED: &'static str = "token_endpoint_auth_methods_supported";
    pub const TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED: &'static str =
        "token_endpoint_auth_signing_alg_values_supported";
    pub const SERVICE_DOCUMENTATION: &'static str = "service_documentation";
    pub const REVOCATION_ENDPOINT: &'static str = "revocation_endpoint";
    pub const REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED: &'static str = "revocation_endpoint_auth_methods_supported";
    pub const INTROSPECTION_ENDPOINT: &'static str = "introspection_endpoint";
    pub const INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED: &'static str =
        "introspection_endpoint_auth_methods_supported";
    pub const CODE_CHALLENGE_METHODS_SUPPORTED: &'static str = "code_challenge_methods_supported";
    // RFC 9126 §5, RFC 9207 §3, RFC 8628 §4, RFC 9449 §5.1, RFC 9728 §4.
    pub const PUSHED_AUTHORIZATION_REQUEST_ENDPOINT: &'static str = "pushed_authorization_request_endpoint";
    pub const REQUIRE_PUSHED_AUTHORIZATION_REQUESTS: &'static str = "require_pushed_authorization_requests";
    pub const AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED: &'static str =
        "authorization_response_iss_parameter_supported";
    pub const DEVICE_AUTHORIZATION_ENDPOINT: &'static str = "device_authorization_endpoint";
    pub const DPOP_SIGNING_ALG_VALUES_SUPPORTED: &'static str = "dpop_signing_alg_values_supported";
    pub const PROTECTED_RESOURCES: &'static str = "protected_resources";
    // RFC 9728 §2.
    pub const RESOURCE: &'static str = "resource";
    pub const AUTHORIZATION_SERVERS: &'static str = "authorization_servers";
    pub const BEARER_METHODS_SUPPORTED: &'static str = "bearer_methods_supported";
    pub const RESOURCE_SIGNING_ALG_VALUES_SUPPORTED: &'static str = "resource_signing_alg_values_supported";
    pub const RESOURCE_NAME: &'static str = "resource_name";
    pub const RESOURCE_DOCUMENTATION: &'static str = "resource_documentation";
    pub const DPOP_BOUND_ACCESS_TOKENS_REQUIRED: &'static str = "dpop_bound_access_tokens_required";

    /// A document of `kind` describing `identifier`, without other members.
    pub fn new(kind: OAuthMetadataKind, identifier: &str) -> OAuthMetadata {
        let mut metadata = OAuthMetadata { kind, object: JSONObject::new() };
        metadata.set_string(kind.identifier_member(), identifier);
        metadata
    }

    /// The document of the JSON text `body`, which must be an object with the identifier member.
    pub fn decode(kind: OAuthMetadataKind, body: &[u8]) -> Result<OAuthMetadata, OAuthError> {
        let mut value = JSONValue::decode(body, JSONConfig::default())?;
        let object = value.as_object_mut().map(core::mem::take).ok_or(OAuthError::Invalid { parameter: "body" })?;
        let metadata = OAuthMetadata { kind, object };
        metadata.identifier()?;
        Ok(metadata)
    }

    /// The JSON text of the document.
    pub fn encode(&self) -> String {
        JSONEncoder::COMPACT.encode(&JSONValue::Object(self.object.clone()))
    }

    /// The identifier the document describes.
    pub fn identifier(&self) -> Result<&str, OAuthError> {
        let member = self.kind.identifier_member();
        let parameter = match self.kind {
            OAuthMetadataKind::Server => OAuthMetadata::ISSUER,
            OAuthMetadataKind::Resource => OAuthMetadata::RESOURCE,
        };
        debug_assert_eq!(member, parameter);
        self.string(parameter)?.ok_or(OAuthError::Missing { parameter })
    }

    /// Checks that the document describes `expected`, the identifier its location was made of:
    /// the two must be identical (RFC 8414 §3.3, RFC 9728 §3.3), or it fails with Issuer.
    pub fn check(&self, expected: &str) -> Result<(), OAuthError> {
        if self.identifier()? == expected { Ok(()) } else { Err(OAuthError::Issuer) }
    }

    /// The URL of the document of `identifier` (RFC 8414 §3.1, RFC 9728 §3.1): the well-known
    /// path put between the authority and the path, a terminating `/` of the path removed. An
    /// issuer may have no query (RFC 8414 §2); the query of a resource is kept. Neither may
    /// have a fragment.
    pub fn location(kind: OAuthMetadataKind, identifier: &str) -> Result<String, OAuthError> {
        let parameter = kind.identifier_member();
        let parameter = if parameter == "issuer" { OAuthMetadata::ISSUER } else { OAuthMetadata::RESOURCE };
        let uri = URIReference::parse(identifier)?;
        let valid = uri.scheme.is_some()
            && uri.authority.is_some()
            && uri.fragment.is_none()
            && (kind == OAuthMetadataKind::Resource || uri.query.is_none());
        if !valid {
            return Err(OAuthError::Invalid { parameter });
        }
        let path = uri.path.strip_suffix('/').unwrap_or(&uri.path);
        let mut location = uri.clone();
        location.path = format!("/.well-known/{}{}", kind.well_known(), path);
        Ok(location.to_string())
    }

    /// The string member `name`; a member of another type fails with Invalid.
    pub fn string(&self, name: &'static str) -> Result<Option<&str>, OAuthError> {
        match self.object.get(name) {
            None => Ok(None),
            Some(JSONValue::String(text)) => Ok(Some(text)),
            Some(_) => Err(OAuthError::Invalid { parameter: name }),
        }
    }

    /// The member `name`, an array of strings.
    pub fn strings(&self, name: &'static str) -> Result<Option<Vec<&str>>, OAuthError> {
        match self.object.get(name) {
            None => Ok(None),
            Some(JSONValue::Array(values)) => values
                .iter()
                .map(|value| match value {
                    JSONValue::String(text) => Ok(text.as_str()),
                    _ => Err(OAuthError::Invalid { parameter: name }),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Some),
            Some(_) => Err(OAuthError::Invalid { parameter: name }),
        }
    }

    /// The boolean member `name`.
    pub fn boolean(&self, name: &'static str) -> Result<Option<bool>, OAuthError> {
        match self.object.get(name) {
            None => Ok(None),
            Some(JSONValue::Bool(value)) => Ok(Some(*value)),
            Some(_) => Err(OAuthError::Invalid { parameter: name }),
        }
    }

    /// Whether the array member `name` lists `value`; an absent member lists nothing.
    pub fn lists(&self, name: &'static str, value: &str) -> Result<bool, OAuthError> {
        Ok(self.strings(name)?.is_some_and(|values| values.contains(&value)))
    }

    /// Sets the string member `name`.
    pub fn set_string(&mut self, name: &str, value: &str) {
        self.object.insert(name.to_string(), JSONValue::String(value.to_string()));
    }

    /// Sets the member `name` to an array of strings.
    pub fn set_strings(&mut self, name: &str, values: &[&str]) {
        let values = values.iter().map(|value| JSONValue::String(value.to_string())).collect();
        self.object.insert(name.to_string(), JSONValue::Array(values));
    }

    /// Sets the boolean member `name`.
    pub fn set_boolean(&mut self, name: &str, value: bool) {
        self.object.insert(name.to_string(), JSONValue::Bool(value));
    }
}
