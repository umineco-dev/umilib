use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{JOSEHeader, JWE, JWEConfig, JWK, JWS, JWSConfig, JWTError};
use crate::codec::json::{JSONConfig, JSONObject, JSONValue};
use crate::crypto::random::Random;

/// A JWT Claims Set (RFC 7519 §4): a JSON object of claims, kept in order,
/// with readers of the claims RFC 7519 registers. A registered claim of
/// another type than its definition fails with [`JWTError::InvalidClaim`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct JWTClaims {
    pub claims: JSONObject,
}

impl JWTClaims {
    /// The claims of RFC 7519 §4.1.
    pub const REGISTERED: [&'static str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

    pub fn new() -> JWTClaims {
        JWTClaims::default()
    }

    /// The claims of the JSON text `bytes`: an object without duplicate
    /// claim names (RFC 7519 §4, §7.2 step 10).
    pub fn decode(bytes: &[u8]) -> Result<JWTClaims, JWTError> {
        let mut value = JSONValue::decode(bytes, JSONConfig::default())?;
        let claims = core::mem::take(value.as_object_mut().ok_or(JWTError::Format)?);
        Ok(JWTClaims { claims })
    }

    /// The JSON text of the claims.
    pub fn encode(&self) -> String {
        JSONValue::Object(self.claims.clone()).encode()
    }

    pub fn get(&self, name: &str) -> Option<&JSONValue> {
        self.claims.get(name)
    }

    pub fn set(&mut self, name: &str, value: JSONValue) {
        self.claims.insert(name.to_string(), value);
    }

    pub fn set_string(&mut self, name: &str, value: &str) {
        self.set(name, JSONValue::String(value.to_string()));
    }

    /// Sets `name` to the NumericDate `seconds` (RFC 7519 §2).
    pub fn set_numeric_date(&mut self, name: &str, seconds: i64) {
        self.set(name, JSONValue::from(seconds));
    }

    pub fn remove(&mut self, name: &str) -> Option<JSONValue> {
        self.claims.remove(name)
    }

    /// The string claim `name`, if present.
    pub fn string(&self, name: &str) -> Result<Option<&str>, JWTError> {
        match self.get(name) {
            None => Ok(None),
            Some(value) => value.as_str().map(Some).ok_or(JWTError::InvalidClaim),
        }
    }

    /// The NumericDate claim `name` (RFC 7519 §2): seconds from the epoch,
    /// which may have a fraction.
    pub fn numeric_date(&self, name: &str) -> Result<Option<f64>, JWTError> {
        match self.get(name) {
            None => Ok(None),
            Some(value) => value.as_number().and_then(|number| number.as_f64()).map(Some).ok_or(JWTError::InvalidClaim),
        }
    }

    /// `iss` (RFC 7519 §4.1.1).
    pub fn issuer(&self) -> Result<Option<&str>, JWTError> {
        self.string("iss")
    }

    /// `sub` (RFC 7519 §4.1.2).
    pub fn subject(&self) -> Result<Option<&str>, JWTError> {
        self.string("sub")
    }

    /// `aud` (RFC 7519 §4.1.3): a string or an array of strings; empty
    /// when absent.
    pub fn audience(&self) -> Result<Vec<&str>, JWTError> {
        match self.get("aud") {
            None => Ok(Vec::new()),
            Some(JSONValue::String(audience)) => Ok(alloc::vec![audience.as_str()]),
            Some(JSONValue::Array(values)) => {
                values.iter().map(|value| value.as_str().ok_or(JWTError::InvalidClaim)).collect()
            }
            Some(_) => Err(JWTError::InvalidClaim),
        }
    }

    /// `exp` (RFC 7519 §4.1.4).
    pub fn expiration(&self) -> Result<Option<f64>, JWTError> {
        self.numeric_date("exp")
    }

    /// `nbf` (RFC 7519 §4.1.5).
    pub fn not_before(&self) -> Result<Option<f64>, JWTError> {
        self.numeric_date("nbf")
    }

    /// `iat` (RFC 7519 §4.1.6).
    pub fn issued_at(&self) -> Result<Option<f64>, JWTError> {
        self.numeric_date("iat")
    }

    /// `jti` (RFC 7519 §4.1.7).
    pub fn jwt_id(&self) -> Result<Option<&str>, JWTError> {
        self.string("jti")
    }

    /// Checks the type of each registered claim present.
    pub fn check(&self) -> Result<(), JWTError> {
        self.issuer()?;
        self.subject()?;
        self.audience()?;
        self.expiration()?;
        self.not_before()?;
        self.issued_at()?;
        self.jwt_id()?;
        Ok(())
    }
}

/// What a JWT must satisfy beyond its signature or encryption (RFC 7519
/// §7.2, RFC 8725 §3): the current time `now` in seconds from the epoch,
/// with `leeway` seconds of tolerance for `exp` and `nbf`; the issuer, the
/// audience (the identifier of the recipient) and the subject expected;
/// the expected `typ` (explicit typing, RFC 8725 §3.11); and the claims
/// required.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JWTValidation {
    pub now: i64,
    pub leeway: u64,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub subject: Option<String>,
    pub token_type: Option<String>,
    pub required: Vec<String>,
}

impl JWTValidation {
    /// The validation at `now` without leeway, expectations or required claims.
    pub fn new(now: i64) -> JWTValidation {
        JWTValidation {
            now,
            leeway: 0,
            issuer: None,
            audience: None,
            subject: None,
            token_type: None,
            required: Vec::new(),
        }
    }

    /// Checks `claims` and `header`, the header that holds them:
    /// - `typ` is the type expected, if one is (RFC 8725 §3.11);
    /// - the registered claims have their types (RFC 7519 §4.1);
    /// - `now` is before `exp` and not before `nbf`, give or take the
    ///   leeway (RFC 7519 §4.1.4, §4.1.5);
    /// - `iss` and `sub` are those expected, if they are (RFC 8725 §3.8);
    /// - an audience is expected exactly when `aud` is present, and `aud`
    ///   holds it (RFC 7519 §4.1.3, RFC 8725 §3.9);
    /// - the required claims are present.
    pub fn validate(&self, header: &JOSEHeader, claims: &JWTClaims) -> Result<(), JWTError> {
        if let Some(expected) = &self.token_type {
            let actual = header.token_type()?.ok_or(JWTError::Type)?;
            if !JWTValidation::same_type(expected, actual) {
                return Err(JWTError::Type);
            }
        }
        claims.check()?;
        let now = self.now as f64;
        let leeway = self.leeway as f64;
        if claims.expiration()?.is_some_and(|expiration| now >= expiration + leeway) {
            return Err(JWTError::Expired);
        }
        if claims.not_before()?.is_some_and(|not_before| now + leeway < not_before) {
            return Err(JWTError::NotYetValid);
        }
        if let Some(expected) = &self.issuer
            && claims.issuer()? != Some(expected.as_str())
        {
            return Err(JWTError::Issuer);
        }
        if let Some(expected) = &self.subject
            && claims.subject()? != Some(expected.as_str())
        {
            return Err(JWTError::Subject);
        }
        let audience = claims.audience()?;
        let present = claims.get("aud").is_some();
        match &self.audience {
            Some(expected) if !audience.contains(&expected.as_str()) => return Err(JWTError::Audience),
            None if present => return Err(JWTError::Audience),
            _ => {}
        }
        if self.required.iter().any(|name| claims.get(name).is_none()) {
            return Err(JWTError::MissingClaim);
        }
        Ok(())
    }

    /// Whether the media types `first` and `second` are the same: compared
    /// without regard to case, "application/" omitted or not (RFC 7515 §4.1.9).
    pub fn same_type(first: &str, second: &str) -> bool {
        let short = |media: &str| {
            let prefix = "application/";
            match media.get(..prefix.len()) {
                Some(head) if head.eq_ignore_ascii_case(prefix) => media[prefix.len()..].to_string(),
                _ => media.to_string(),
            }
        };
        short(first).eq_ignore_ascii_case(&short(second))
    }
}

/// A JWT that verified or decrypted: the header that holds its claims (that
/// of the JWS, or the JOSE Header of the JWE without a JWS inside) and the
/// claims. A JWT is a JWS, a JWE, or a JWS inside a JWE (RFC 7519 §5.2,
/// §11.2); each has its pair of functions, so that the form a token must
/// have is the choice of the application (RFC 8725 §3.12).
#[derive(Clone, Debug, PartialEq)]
pub struct JWT {
    pub header: JOSEHeader,
    pub claims: JWTClaims,
}

impl JWT {
    /// The content type of a JWT inside another (RFC 7519 §5.2).
    pub const NESTED: &'static str = "JWT";

    /// The JWS of `claims` with the protected header `header` under `key`,
    /// in the compact serialization (RFC 7519 §7.1).
    pub fn sign<R: Random>(
        claims: &JWTClaims,
        header: &JOSEHeader,
        key: &JWK,
        random: &mut R,
    ) -> Result<String, JWTError> {
        if !header.b64()? {
            return Err(JWTError::Header);
        }
        let mut jws = JWS::new(claims.encode().into_bytes());
        jws.sign(header, None, key, random)?;
        jws.to_compact()
    }

    /// The JWT of the compact JWS `text`, verified under `key` with the
    /// algorithms of `config` and validated (RFC 7519 §7.2). A payload that
    /// is a JWT itself (`cty` of "JWT") is refused.
    pub fn verify(text: &str, key: &JWK, config: &JWSConfig, validation: &JWTValidation) -> Result<JWT, JWTError> {
        let jws = JWS::from_compact(text)?;
        if !jws.b64()? {
            return Err(JWTError::Header);
        }
        let header = jws.verify(key, config)?.joined_header()?;
        JWT::claims_of(header, &jws.payload, validation)
    }

    /// The JWT of an Unsecured JWS `text` (RFC 7519 §6), validated:
    /// accepting one is a decision of the application (RFC 8725 §3.1),
    /// which this function makes explicit.
    pub fn verify_unsecured(text: &str, validation: &JWTValidation) -> Result<JWT, JWTError> {
        let jws = JWS::from_compact(text)?;
        if !jws.b64()? {
            return Err(JWTError::Header);
        }
        jws.verify_unsecured()?;
        let header = jws.signatures[0].joined_header()?;
        JWT::claims_of(header, &jws.payload, validation)
    }

    /// The JWE of `claims` with the protected header `header` for `key`, in
    /// the compact serialization (RFC 7519 §7.1).
    pub fn encrypt<R: Random>(
        claims: &JWTClaims,
        header: &JOSEHeader,
        key: &JWK,
        random: &mut R,
    ) -> Result<String, JWTError> {
        JWE::encrypt(claims.encode().as_bytes(), header, None, &[(key, None)], None, random)?.to_compact()
    }

    /// The JWT of the compact JWE `text`, decrypted with `key` under the
    /// algorithms of `config` and validated (RFC 7519 §7.2). A plaintext
    /// that is a JWT itself (`cty` of "JWT") is refused: see
    /// [`JWT::decrypt_and_verify`].
    pub fn decrypt<R: Random>(
        text: &str,
        key: &JWK,
        config: &JWEConfig,
        validation: &JWTValidation,
        random: &mut R,
    ) -> Result<JWT, JWTError> {
        let jwe = JWE::from_compact(text)?;
        let (plaintext, recipient) = jwe.decrypt(key, config, random)?;
        let header = jwe.joined_header(recipient)?;
        JWT::claims_of(header, &plaintext, validation)
    }

    /// A Nested JWT (RFC 7519 §5.2, §A.2): the JWS of `claims` under
    /// `signing_key`, encrypted for `encryption_key` in a JWE whose header
    /// `encryption_header` gets the `cty` of "JWT".
    pub fn sign_and_encrypt<R: Random>(
        claims: &JWTClaims,
        signing_header: &JOSEHeader,
        signing_key: &JWK,
        encryption_header: &JOSEHeader,
        encryption_key: &JWK,
        random: &mut R,
    ) -> Result<String, JWTError> {
        let signed = JWT::sign(claims, signing_header, signing_key, random)?;
        let mut header = encryption_header.clone();
        header.set_string("cty", JWT::NESTED);
        JWE::encrypt(signed.as_bytes(), &header, None, &[(encryption_key, None)], None, random)?.to_compact()
    }

    /// The JWT of a Nested JWT `text`: the compact JWE, decrypted with
    /// `decryption_key`, must have the `cty` of "JWT" and hold a compact JWS,
    /// verified under `verification_key` and validated.
    pub fn decrypt_and_verify<R: Random>(
        text: &str,
        decryption_key: &JWK,
        decryption: &JWEConfig,
        verification_key: &JWK,
        verification: &JWSConfig,
        validation: &JWTValidation,
        random: &mut R,
    ) -> Result<JWT, JWTError> {
        let jwe = JWE::from_compact(text)?;
        let (plaintext, recipient) = jwe.decrypt(decryption_key, decryption, random)?;
        let outer = jwe.joined_header(recipient)?;
        if !outer.content_type()?.is_some_and(|content| JWTValidation::same_type(content, JWT::NESTED)) {
            return Err(JWTError::Type);
        }
        let inner = core::str::from_utf8(&plaintext).map_err(|_| JWTError::Format)?;
        JWT::verify(inner, verification_key, verification, validation)
    }

    /// The JWT of the claims `payload` held by `header`, validated; a
    /// header announcing a nested JWT (`cty` of "JWT") is refused.
    pub fn claims_of(header: JOSEHeader, payload: &[u8], validation: &JWTValidation) -> Result<JWT, JWTError> {
        if header.content_type()?.is_some_and(|content| JWTValidation::same_type(content, JWT::NESTED)) {
            return Err(JWTError::Type);
        }
        let claims = JWTClaims::decode(payload)?;
        validation.validate(&header, &claims)?;
        Ok(JWT { header, claims })
    }
}
