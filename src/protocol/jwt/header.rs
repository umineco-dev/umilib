use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{JOSEMembers, JWEAlgorithm, JWEEncryption, JWK, JWSAlgorithm, JWTError};
use crate::codec::json::{JSONConfig, JSONObject, JSONValue};

/// A JOSE Header (RFC 7515 §4, RFC 7516 §4): a JSON object of header
/// parameters, kept in order, with readers of the parameters JOSE
/// registers. A parameter of another type than its definition fails with
/// [`JWTError::Header`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct JOSEHeader {
    pub parameters: JSONObject,
}

impl JOSEHeader {
    /// The header parameters defined by RFC 7515, RFC 7516 and RFC 7518,
    /// which `crit` must not list (RFC 7515 §4.1.11).
    pub const REGISTERED: [&'static str; 20] = [
        "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "enc", "zip", "epk", "apu",
        "apv", "iv", "tag", "p2s", "p2c",
    ];

    pub fn new() -> JOSEHeader {
        JOSEHeader::default()
    }

    /// The header of the JSON text `bytes`, an object without duplicate
    /// parameters (RFC 7515 §4, RFC 7516 §4).
    pub fn decode(bytes: &[u8]) -> Result<JOSEHeader, JWTError> {
        let mut value = JSONValue::decode(bytes, JSONConfig::default())?;
        let parameters = core::mem::take(value.as_object_mut().ok_or(JWTError::Header)?);
        Ok(JOSEHeader { parameters })
    }

    /// The JSON text of the header.
    pub fn encode(&self) -> String {
        JSONValue::Object(self.parameters.clone()).encode()
    }

    pub fn is_empty(&self) -> bool {
        self.parameters.is_empty()
    }

    pub fn get(&self, name: &str) -> Option<&JSONValue> {
        self.parameters.get(name)
    }

    /// Sets the parameter `name` to `value`.
    pub fn set(&mut self, name: &str, value: JSONValue) {
        self.parameters.insert(name.to_string(), value);
    }

    /// Sets the parameter `name` to the string `value`.
    pub fn set_string(&mut self, name: &str, value: &str) {
        self.set(name, JSONValue::String(value.to_string()));
    }

    pub fn remove(&mut self, name: &str) -> Option<JSONValue> {
        self.parameters.remove(name)
    }

    pub fn members(&self) -> JOSEMembers<'_> {
        JOSEMembers::new(&self.parameters, JWTError::Header)
    }

    /// The string parameter `name`, if present.
    pub fn string(&self, name: &str) -> Result<Option<&str>, JWTError> {
        self.members().string(name)
    }

    /// The JWS algorithm `alg`, which must be present (RFC 7515 §4.1.1).
    pub fn jws_algorithm(&self) -> Result<JWSAlgorithm, JWTError> {
        let name = self.string("alg")?.ok_or(JWTError::Header)?;
        JWSAlgorithm::from_name(name).ok_or(JWTError::UnknownAlgorithm)
    }

    /// The JWE key management algorithm `alg`, which must be present (RFC 7516 §4.1.1).
    pub fn jwe_algorithm(&self) -> Result<JWEAlgorithm, JWTError> {
        let name = self.string("alg")?.ok_or(JWTError::Header)?;
        JWEAlgorithm::from_name(name).ok_or(JWTError::UnknownAlgorithm)
    }

    /// The content encryption algorithm `enc`, which must be present (RFC 7516 §4.1.2).
    pub fn encryption(&self) -> Result<JWEEncryption, JWTError> {
        let name = self.string("enc")?.ok_or(JWTError::Header)?;
        JWEEncryption::from_name(name).ok_or(JWTError::UnknownAlgorithm)
    }

    /// `kid` (RFC 7515 §4.1.4).
    pub fn key_id(&self) -> Result<Option<&str>, JWTError> {
        self.string("kid")
    }

    /// `typ` (RFC 7515 §4.1.9).
    pub fn token_type(&self) -> Result<Option<&str>, JWTError> {
        self.string("typ")
    }

    /// `cty` (RFC 7515 §4.1.10).
    pub fn content_type(&self) -> Result<Option<&str>, JWTError> {
        self.string("cty")
    }

    /// `b64` (RFC 7797 §3): whether the payload is base64url-encoded; true
    /// when absent.
    pub fn b64(&self) -> Result<bool, JWTError> {
        match self.get("b64") {
            None => Ok(true),
            Some(value) => value.as_bool().ok_or(JWTError::Header),
        }
    }

    /// `crit` (RFC 7515 §4.1.11), if present.
    pub fn critical(&self) -> Result<Option<Vec<&str>>, JWTError> {
        self.members().strings("crit")
    }

    /// `epk` (RFC 7518 §4.6.1.1), a public JWK.
    pub fn ephemeral_key(&self) -> Result<Option<JWK>, JWTError> {
        let Some(object) = self.members().object("epk")? else { return Ok(None) };
        let key = JWK::from_object(object).map_err(|_| JWTError::Header)?;
        if key.key.is_secret() {
            return Err(JWTError::Header);
        }
        Ok(Some(key))
    }

    /// The union of `headers`, whose parameter names must be disjoint (RFC
    /// 7515 §7.2.1, RFC 7516 §7.2.1); [`JWTError::Header`] otherwise.
    pub fn union(headers: &[&JOSEHeader]) -> Result<JOSEHeader, JWTError> {
        let mut union = JOSEHeader::new();
        for header in headers {
            for (name, value) in header.parameters.iter() {
                if union.parameters.insert(name.clone(), value.clone()).is_some() {
                    return Err(JWTError::Header);
                }
            }
        }
        Ok(union)
    }

    /// Checks `crit` (RFC 7515 §4.1.11): it is in the protected header
    /// `protected` and in none of the unprotected headers `unprotected`, it
    /// is not empty, and it lists, once each, parameters JOSE does not
    /// define that are among `understood` and present in the JOSE Header
    /// (`protected` or `unprotected`).
    pub fn check_critical(
        protected: &JOSEHeader,
        unprotected: &[&JOSEHeader],
        understood: &[&str],
    ) -> Result<(), JWTError> {
        if unprotected.iter().any(|header| header.get("crit").is_some()) {
            return Err(JWTError::Critical);
        }
        let Some(listed) = protected.critical().map_err(|_| JWTError::Critical)? else { return Ok(()) };
        if listed.is_empty() {
            return Err(JWTError::Critical);
        }
        for (index, name) in listed.iter().enumerate() {
            let registered = JOSEHeader::REGISTERED.contains(name);
            let repeated = listed[..index].contains(name);
            // RFC 7515 §4.1.11: a name that occurs in the JOSE Header, the union of the headers.
            let present = protected.get(name).is_some() || unprotected.iter().any(|header| header.get(name).is_some());
            if registered || repeated || !understood.contains(name) || !present {
                return Err(JWTError::Critical);
            }
        }
        Ok(())
    }
}
