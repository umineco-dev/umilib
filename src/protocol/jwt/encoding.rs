use alloc::string::String;
use alloc::vec::Vec;

use super::JWTError;
use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;

/// The base64url encoding of JOSE (RFC 7515 §2): the URL-safe alphabet
/// of RFC 4648 §5 without padding, no other characters, canonical (the
/// unused bits of the last character zero, so each value has one text).
pub struct Base64URL;

impl Base64URL {
    pub fn encode(data: &[u8]) -> String {
        Base64::URL_SAFE_NO_PADDING.encode(data)
    }

    /// The bytes of `text`; fails with [`JWTError::Base64`].
    pub fn decode(text: &str) -> Result<Vec<u8>, JWTError> {
        Base64::URL_SAFE_NO_PADDING.decode(text.as_bytes()).map_err(|_| JWTError::Base64)
    }
}

/// The unsigned integers of JWKs (`Base64urlUInt`, RFC 7518 §2): the
/// big-endian bytes of the value in base64url, in the fewest bytes (one
/// zero byte for zero).
pub struct Base64URLUInt;

impl Base64URLUInt {
    /// The text of the big-endian `value`, whose leading zeros are dropped.
    pub fn encode(value: &[u8]) -> String {
        let start = value.iter().position(|&byte| byte != 0).unwrap_or(value.len().saturating_sub(1));
        Base64URL::encode(&value[start..])
    }

    /// The big-endian bytes of `text`; fails with [`JWTError::Base64`] for
    /// no bytes or a leading zero byte that is not the only one.
    pub fn decode(text: &str) -> Result<Vec<u8>, JWTError> {
        let bytes = Base64URL::decode(text)?;
        if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == 0) {
            return Err(JWTError::Base64);
        }
        Ok(bytes)
    }
}

/// The members of a JSON object of JOSE (a header, a JWK, a JWS or JWE
/// JSON serialization) read with their types: a member of another type
/// than its definition fails with `error`.
pub struct JOSEMembers<'o> {
    pub object: &'o crate::codec::json::JSONObject,
    pub error: JWTError,
}

impl<'o> JOSEMembers<'o> {
    pub fn new(object: &'o crate::codec::json::JSONObject, error: JWTError) -> JOSEMembers<'o> {
        JOSEMembers { object, error }
    }

    /// The string member `name`, if present.
    pub fn string(&self, name: &str) -> Result<Option<&'o str>, JWTError> {
        match self.object.get(name) {
            None => Ok(None),
            Some(value) => value.as_str().map(Some).ok_or(self.error),
        }
    }

    /// The string member `name`, which must be present.
    pub fn required_string(&self, name: &str) -> Result<&'o str, JWTError> {
        self.string(name)?.ok_or(self.error)
    }

    /// The bytes of the base64url member `name`, if present.
    pub fn bytes(&self, name: &str) -> Result<Option<Vec<u8>>, JWTError> {
        self.string(name)?.map(Base64URL::decode).transpose()
    }

    /// The bytes of the base64url member `name`, which must be present.
    pub fn required_bytes(&self, name: &str) -> Result<Vec<u8>, JWTError> {
        self.bytes(name)?.ok_or(self.error)
    }

    /// The array of strings `name`, if present.
    pub fn strings(&self, name: &str) -> Result<Option<Vec<&'o str>>, JWTError> {
        let Some(value) = self.object.get(name) else { return Ok(None) };
        let array = value.as_array().ok_or(self.error)?;
        array.iter().map(|item| item.as_str().ok_or(self.error)).collect::<Result<Vec<_>, _>>().map(Some)
    }

    /// The object member `name`, if present.
    pub fn object(&self, name: &str) -> Result<Option<&'o crate::codec::json::JSONObject>, JWTError> {
        match self.object.get(name) {
            None => Ok(None),
            Some(value) => value.as_object().map(Some).ok_or(self.error),
        }
    }
}
