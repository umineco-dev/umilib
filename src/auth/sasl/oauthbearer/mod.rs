//! OAUTHBEARER (RFC 7628): the client sends an OAuth 2.0 bearer token
//! (RFC 6750) in key/value pairs after a GS2 header; on failure the server
//! answers with a JSON error result, to which the client sends the dummy
//! response before the server fails the exchange. It requires TLS.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{GS2ChannelBinding, GS2Header, SASLError};
use crate::codec::json::{JSONConfig, JSONObject, JSONValue};

/// The initial client response of OAUTHBEARER (RFC 7628 §3.1): a GS2
/// header and key/value pairs, each `key=value` followed by %x01.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAUTHBEARERMessage {
    pub header: GS2Header,
    pub pairs: Vec<(String, String)>,
}

impl OAUTHBEARERMessage {
    /// The separator of the pairs, `kvsep`.
    pub const SEPARATOR: u8 = 0x01;
    /// The response a client sends after an error result (RFC 7628 §3.2.3).
    pub const DUMMY: [u8; 1] = [OAUTHBEARERMessage::SEPARATOR];
    /// The keys RFC 7628 §3.1 defines; each may occur once.
    pub const KEYS: [&'static str; 3] = ["auth", "host", "port"];

    /// The response of the bearer token `token` (`auth=Bearer <token>`),
    /// with the authorization identity, the host and the port the client
    /// connected to, if given.
    pub fn new(authzid: Option<&str>, token: &str, host: Option<&str>, port: Option<u16>) -> OAUTHBEARERMessage {
        let mut pairs = Vec::new();
        if let Some(host) = host {
            pairs.push((String::from("host"), String::from(host)));
        }
        if let Some(port) = port {
            pairs.push((String::from("port"), port.to_string()));
        }
        pairs.push((String::from("auth"), alloc::format!("Bearer {token}")));
        OAUTHBEARERMessage { header: GS2Header::new(GS2ChannelBinding::Unsupported, authzid), pairs }
    }

    /// `gs2-header kvsep *kvpair kvsep`; fails with [`SASLError::Format`]
    /// unless the pairs are as [`OAUTHBEARERMessage::check`] requires.
    pub fn encode(&self) -> Result<Vec<u8>, SASLError> {
        OAUTHBEARERMessage::check(&self.pairs)?;
        let mut message = self.header.encode()?.into_bytes();
        message.push(OAUTHBEARERMessage::SEPARATOR);
        for (key, value) in &self.pairs {
            message.extend_from_slice(key.as_bytes());
            message.push(b'=');
            message.extend_from_slice(value.as_bytes());
            message.push(OAUTHBEARERMessage::SEPARATOR);
        }
        message.push(OAUTHBEARERMessage::SEPARATOR);
        Ok(message)
    }

    /// The response of `message`, whose pairs are as
    /// [`OAUTHBEARERMessage::check`] requires; unknown keys are kept (the
    /// server ignores them). The dummy response is not one (see
    /// [`OAUTHBEARERMessage::is_dummy`]).
    pub fn decode(message: &[u8]) -> Result<OAUTHBEARERMessage, SASLError> {
        let text = core::str::from_utf8(message).map_err(|_| SASLError::Format)?;
        let (header, rest) = GS2Header::decode(text)?;
        let separator = char::from(OAUTHBEARERMessage::SEPARATOR);
        let body =
            rest.strip_prefix(separator).and_then(|body| body.strip_suffix(separator)).ok_or(SASLError::Format)?;
        let mut pairs: Vec<(String, String)> = Vec::new();
        if !body.is_empty() {
            let body = body.strip_suffix(separator).ok_or(SASLError::Format)?;
            for pair in body.split(separator) {
                let (key, value) = pair.split_once('=').ok_or(SASLError::Format)?;
                pairs.push((String::from(key), String::from(value)));
            }
        }
        OAUTHBEARERMessage::check(&pairs)?;
        Ok(OAUTHBEARERMessage { header, pairs })
    }

    /// The rules of the pairs (RFC 7628 §3.1): keys of letters, values of
    /// VCHAR, SP, HTAB, CR and LF, `auth` present (it is REQUIRED), the keys
    /// the RFC defines at most once, and `port` a positive decimal integer
    /// without leading zeros; [`SASLError::Format`] otherwise.
    pub fn check(pairs: &[(String, String)]) -> Result<(), SASLError> {
        for (index, (key, value)) in pairs.iter().enumerate() {
            if !OAUTHBEARERMessage::is_key(key) || !OAUTHBEARERMessage::is_value(value) {
                return Err(SASLError::Format);
            }
            if OAUTHBEARERMessage::KEYS.contains(&key.as_str()) && pairs[..index].iter().any(|(own, _)| own == key) {
                return Err(SASLError::Format);
            }
            if key == "port" && OAUTHBEARERMessage::positive_integer(value).is_none() {
                return Err(SASLError::Format);
            }
        }
        if !pairs.iter().any(|(key, _)| key == "auth") {
            return Err(SASLError::Format);
        }
        Ok(())
    }

    /// The port of `text`: a positive decimal integer without leading zeros.
    pub fn positive_integer(text: &str) -> Option<u16> {
        if text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        text.parse().ok().filter(|&port| port != 0)
    }

    /// Whether `message` is the dummy response, a single %x01.
    pub fn is_dummy(message: &[u8]) -> bool {
        message == OAUTHBEARERMessage::DUMMY
    }

    /// Whether `key` is `1*ALPHA`.
    pub fn is_key(key: &str) -> bool {
        !key.is_empty() && key.bytes().all(|byte| byte.is_ascii_alphabetic())
    }

    /// Whether `value` is `*(VCHAR / SP / HTAB / CR / LF)`.
    pub fn is_value(value: &str) -> bool {
        value.bytes().all(|byte| matches!(byte, 0x21..=0x7E | b' ' | b'\t' | b'\r' | b'\n'))
    }

    /// The value of `key`, the first if it occurs more than once.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs.iter().find(|(own, _)| own == key).map(|(_, value)| value.as_str())
    }

    /// `auth`, the payload of the HTTP Authorization header (required for the exchange to succeed).
    pub fn auth(&self) -> Option<&str> {
        self.get("auth")
    }

    pub fn host(&self) -> Option<&str> {
        self.get("host")
    }

    /// `port`, if present.
    pub fn port(&self) -> Option<u16> {
        OAUTHBEARERMessage::positive_integer(self.get("port")?)
    }

    /// The bearer token of `auth`: the scheme `Bearer` (in any case, RFC
    /// 7628 §4), spaces, and a `b64token` (RFC 6750 §2.1); `None` otherwise.
    pub fn bearer_token(&self) -> Option<&str> {
        let auth = self.auth()?;
        let scheme = auth.get(..6).filter(|scheme| scheme.eq_ignore_ascii_case("Bearer"))?;
        let token = auth[scheme.len()..].strip_prefix(' ')?.trim_start_matches(' ');
        let body = token.trim_end_matches('=');
        let valid = !body.is_empty()
            && body
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/'));
        valid.then_some(token)
    }
}

/// The error result of a failed OAUTHBEARER exchange (RFC 7628 §3.2.2):
/// the error code, and the scope and the OpenID configuration URL the
/// client may use to obtain a token.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OAUTHBEARERErrorResult {
    pub status: String,
    pub scope: Option<String>,
    pub openid_configuration: Option<String>,
}

impl OAUTHBEARERErrorResult {
    pub fn new(status: &str) -> OAUTHBEARERErrorResult {
        OAUTHBEARERErrorResult { status: String::from(status), scope: None, openid_configuration: None }
    }

    /// The JSON object of the result.
    pub fn encode(&self) -> Vec<u8> {
        let mut object = JSONObject::default();
        object.insert(String::from("status"), JSONValue::String(self.status.clone()));
        if let Some(scope) = &self.scope {
            object.insert(String::from("scope"), JSONValue::String(scope.clone()));
        }
        if let Some(configuration) = &self.openid_configuration {
            object.insert(String::from("openid-configuration"), JSONValue::String(configuration.clone()));
        }
        JSONValue::Object(object).encode().into_bytes()
    }

    /// The result of the JSON `message`: an object with the string
    /// `status`, and `scope` and `openid-configuration` strings if present;
    /// other members are ignored.
    pub fn decode(message: &[u8]) -> Result<OAUTHBEARERErrorResult, SASLError> {
        let value = JSONValue::decode(message, JSONConfig::default()).map_err(|_| SASLError::Format)?;
        let object = value.as_object().ok_or(SASLError::Format)?;
        let string = |name: &str| match object.get(name) {
            None => Ok(None),
            Some(value) => value.as_str().map(|text| Some(String::from(text))).ok_or(SASLError::Format),
        };
        Ok(OAUTHBEARERErrorResult {
            status: string("status")?.ok_or(SASLError::Format)?,
            scope: string("scope")?,
            openid_configuration: string("openid-configuration")?,
        })
    }
}
