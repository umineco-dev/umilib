use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::codec::json::{JSONConfig, JSONEncoder, JSONNumber, JSONObject, JSONValue};

use super::{OAuthError, OAuthErrorResponse, OAuthScope};

/// The members of a JSON object read by name, each of the type its specification gives it.
pub struct OAuthMembers<'a> {
    pub object: &'a JSONObject,
}

impl<'a> OAuthMembers<'a> {
    /// The object of a JSON body: a success for status `success`, otherwise the error response,
    /// which fails with [`OAuthError::Response`].
    pub fn decode(status: u16, success: u16, body: &[u8]) -> Result<JSONObject, OAuthError> {
        let mut value = JSONValue::decode(body, JSONConfig::default())?;
        let object = value.as_object_mut().map(core::mem::take).ok_or(OAuthError::Invalid { parameter: "body" })?;
        if status != success {
            return Err(OAuthError::Response(OAuthErrorResponse::from_object(&object)?));
        }
        Ok(object)
    }

    /// The string member `name`.
    pub fn string(&self, name: &'static str) -> Result<Option<String>, OAuthError> {
        match self.object.get(name) {
            None => Ok(None),
            Some(JSONValue::String(text)) => Ok(Some(text.clone())),
            Some(_) => Err(OAuthError::Invalid { parameter: name }),
        }
    }

    /// The string member `name`, which is required and not empty.
    pub fn required_string(&self, name: &'static str) -> Result<String, OAuthError> {
        match self.string(name)? {
            Some(text) if !text.is_empty() => Ok(text),
            Some(_) => Err(OAuthError::Invalid { parameter: name }),
            None => Err(OAuthError::Missing { parameter: name }),
        }
    }

    /// The member `name`, a non-negative integer.
    pub fn unsigned(&self, name: &'static str) -> Result<Option<u64>, OAuthError> {
        match self.object.get(name) {
            None => Ok(None),
            Some(JSONValue::Number(number)) => {
                number.as_u64().map(Some).map_err(|_| OAuthError::Invalid { parameter: name })
            }
            Some(_) => Err(OAuthError::Invalid { parameter: name }),
        }
    }

    /// The member `name`, an integer.
    pub fn integer(&self, name: &'static str) -> Result<Option<i64>, OAuthError> {
        match self.object.get(name) {
            None => Ok(None),
            Some(JSONValue::Number(number)) => {
                number.as_i64().map(Some).map_err(|_| OAuthError::Invalid { parameter: name })
            }
            Some(_) => Err(OAuthError::Invalid { parameter: name }),
        }
    }

    /// The member `name`, a string or an array of strings (as `aud`, RFC 7519 §4.1.3).
    pub fn strings(&self, name: &'static str) -> Result<Vec<String>, OAuthError> {
        match self.object.get(name) {
            None => Ok(Vec::new()),
            Some(JSONValue::String(text)) => Ok(alloc::vec![text.clone()]),
            Some(JSONValue::Array(values)) => values
                .iter()
                .map(|value| value.as_str().map(str::to_string).ok_or(OAuthError::Invalid { parameter: name }))
                .collect(),
            Some(_) => Err(OAuthError::Invalid { parameter: name }),
        }
    }

    /// The members whose names are not in `known`.
    pub fn others(&self, known: &[&str]) -> JSONObject {
        let mut other = JSONObject::new();
        for (name, value) in &self.object.members {
            if !known.contains(&name.as_str()) {
                other.insert(name.clone(), value.clone());
            }
        }
        other
    }

    /// Inserts the string member `name` if there is a value.
    pub fn insert_string(object: &mut JSONObject, name: &str, value: Option<&str>) {
        if let Some(value) = value {
            object.insert(name.to_string(), JSONValue::String(value.to_string()));
        }
    }

    /// Inserts the number member `name` if there is a value.
    pub fn insert_number<N: Into<JSONNumber>>(object: &mut JSONObject, name: &str, value: Option<N>) {
        if let Some(value) = value {
            object.insert(name.to_string(), JSONValue::Number(value.into()));
        }
    }

    /// The JSON text of `object`.
    pub fn encode(object: JSONObject) -> String {
        JSONEncoder::COMPACT.encode(&JSONValue::Object(object))
    }
}

/// The response of the pushed authorization request endpoint (RFC 9126 §2.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthPushedAuthorizationResponse {
    pub request_uri: String,
    pub expires_in: u64,
}

impl OAuthPushedAuthorizationResponse {
    /// The response of a body; status 201 is a success (RFC 9126 §2.2), any other an error.
    pub fn decode(status: u16, body: &[u8]) -> Result<OAuthPushedAuthorizationResponse, OAuthError> {
        let object = OAuthMembers::decode(status, 201, body)?;
        let members = OAuthMembers { object: &object };
        Ok(OAuthPushedAuthorizationResponse {
            request_uri: members.required_string("request_uri")?,
            expires_in: members.unsigned("expires_in")?.ok_or(OAuthError::Missing { parameter: "expires_in" })?,
        })
    }

    /// The JSON text of the response.
    pub fn encode(&self) -> String {
        let mut object = JSONObject::new();
        OAuthMembers::insert_string(&mut object, "request_uri", Some(&self.request_uri));
        OAuthMembers::insert_number(&mut object, "expires_in", Some(self.expires_in));
        OAuthMembers::encode(object)
    }
}

/// The response of the device authorization endpoint (RFC 8628 §3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthDeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    /// The seconds between polls; 5 when absent (§3.2).
    pub interval: Option<u64>,
}

impl OAuthDeviceAuthorizationResponse {
    /// The response of a body; status 200 is a success.
    pub fn decode(status: u16, body: &[u8]) -> Result<OAuthDeviceAuthorizationResponse, OAuthError> {
        let object = OAuthMembers::decode(status, 200, body)?;
        let members = OAuthMembers { object: &object };
        Ok(OAuthDeviceAuthorizationResponse {
            device_code: members.required_string("device_code")?,
            user_code: members.required_string("user_code")?,
            verification_uri: members.required_string("verification_uri")?,
            verification_uri_complete: members.string("verification_uri_complete")?,
            expires_in: members.unsigned("expires_in")?.ok_or(OAuthError::Missing { parameter: "expires_in" })?,
            interval: members.unsigned("interval")?,
        })
    }

    /// The JSON text of the response.
    pub fn encode(&self) -> String {
        let mut object = JSONObject::new();
        OAuthMembers::insert_string(&mut object, "device_code", Some(&self.device_code));
        OAuthMembers::insert_string(&mut object, "user_code", Some(&self.user_code));
        OAuthMembers::insert_string(&mut object, "verification_uri", Some(&self.verification_uri));
        OAuthMembers::insert_string(
            &mut object,
            "verification_uri_complete",
            self.verification_uri_complete.as_deref(),
        );
        OAuthMembers::insert_number(&mut object, "expires_in", Some(self.expires_in));
        OAuthMembers::insert_number(&mut object, "interval", self.interval);
        OAuthMembers::encode(object)
    }
}

/// The response of the introspection endpoint (RFC 7662 §2.2). Members this type does not
/// know are kept in `other`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct OAuthIntrospectionResponse {
    pub active: bool,
    pub scope: Option<OAuthScope>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub expires: Option<i64>,
    pub issued_at: Option<i64>,
    pub not_before: Option<i64>,
    pub subject: Option<String>,
    pub audience: Vec<String>,
    pub issuer: Option<String>,
    pub identifier: Option<String>,
    /// The JWK SHA-256 thumbprint of the key the token is bound to (`cnf.jkt`, RFC 9449 §6.2).
    pub confirmation: Option<String>,
    pub other: JSONObject,
}

impl OAuthIntrospectionResponse {
    /// The names of the members this type holds in its own fields.
    pub const MEMBERS: &'static [&'static str] = &[
        "active",
        "scope",
        "client_id",
        "username",
        "token_type",
        "exp",
        "iat",
        "nbf",
        "sub",
        "aud",
        "iss",
        "jti",
        "cnf",
    ];

    /// The response of an inactive token: `{"active":false}` (§2.2).
    pub fn inactive() -> OAuthIntrospectionResponse {
        OAuthIntrospectionResponse::default()
    }

    /// The response of a body; status 200 is a success.
    pub fn decode(status: u16, body: &[u8]) -> Result<OAuthIntrospectionResponse, OAuthError> {
        let object = OAuthMembers::decode(status, 200, body)?;
        let members = OAuthMembers { object: &object };
        let active = match object.get("active") {
            Some(JSONValue::Bool(active)) => *active,
            Some(_) => return Err(OAuthError::Invalid { parameter: "active" }),
            None => return Err(OAuthError::Missing { parameter: "active" }),
        };
        let confirmation = match object.get("cnf") {
            None => None,
            Some(JSONValue::Object(cnf)) => OAuthMembers { object: cnf }.string("jkt")?,
            Some(_) => return Err(OAuthError::Invalid { parameter: "cnf" }),
        };
        Ok(OAuthIntrospectionResponse {
            active,
            scope: members.string("scope")?.map(|scope| OAuthScope::parse(&scope)).transpose()?,
            client_id: members.string("client_id")?,
            username: members.string("username")?,
            token_type: members.string("token_type")?,
            expires: members.integer("exp")?,
            issued_at: members.integer("iat")?,
            not_before: members.integer("nbf")?,
            subject: members.string("sub")?,
            audience: members.strings("aud")?,
            issuer: members.string("iss")?,
            identifier: members.string("jti")?,
            confirmation,
            other: members.others(OAuthIntrospectionResponse::MEMBERS),
        })
    }

    /// The members as a JSON object; an inactive response has only `active` (§2.2: SHOULD NOT
    /// include more).
    pub fn to_object(&self) -> JSONObject {
        let mut object = JSONObject::new();
        object.insert("active".to_string(), JSONValue::Bool(self.active));
        if !self.active {
            return object;
        }
        let scope = self.scope.as_ref().map(OAuthScope::to_string);
        OAuthMembers::insert_string(&mut object, "scope", scope.as_deref());
        OAuthMembers::insert_string(&mut object, "client_id", self.client_id.as_deref());
        OAuthMembers::insert_string(&mut object, "username", self.username.as_deref());
        OAuthMembers::insert_string(&mut object, "token_type", self.token_type.as_deref());
        OAuthMembers::insert_number(&mut object, "exp", self.expires);
        OAuthMembers::insert_number(&mut object, "iat", self.issued_at);
        OAuthMembers::insert_number(&mut object, "nbf", self.not_before);
        OAuthMembers::insert_string(&mut object, "sub", self.subject.as_deref());
        match self.audience.as_slice() {
            [] => {}
            [one] => OAuthMembers::insert_string(&mut object, "aud", Some(one)),
            many => {
                let values = many.iter().map(|value| JSONValue::String(value.clone())).collect();
                object.insert("aud".to_string(), JSONValue::Array(values));
            }
        }
        OAuthMembers::insert_string(&mut object, "iss", self.issuer.as_deref());
        OAuthMembers::insert_string(&mut object, "jti", self.identifier.as_deref());
        if let Some(thumbprint) = &self.confirmation {
            let mut cnf = JSONObject::new();
            OAuthMembers::insert_string(&mut cnf, "jkt", Some(thumbprint));
            object.insert("cnf".to_string(), JSONValue::Object(cnf));
        }
        for (name, value) in &self.other.members {
            if !OAuthIntrospectionResponse::MEMBERS.contains(&name.as_str()) {
                object.insert(name.clone(), value.clone());
            }
        }
        object
    }

    /// The JSON text of the response.
    pub fn encode(&self) -> String {
        OAuthMembers::encode(self.to_object())
    }
}
