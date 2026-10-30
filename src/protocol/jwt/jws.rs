use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{Base64URL, JOSEHeader, JOSEMembers, JWK, JWSAlgorithm, JWTError};
use crate::codec::json::{JSONConfig, JSONObject, JSONValue};
use crate::crypto::random::Random;

/// What verifying a JWS accepts (RFC 8725 §3.1): the algorithms, the
/// critical header parameters understood beyond `b64` (RFC 7797), which
/// this module always understands, and the most signatures a JWS may have,
/// which bounds the work of one verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JWSConfig {
    pub algorithms: Vec<JWSAlgorithm>,
    pub critical: Vec<String>,
    pub maximum_signatures: usize,
}

impl JWSConfig {
    pub const MAXIMUM_SIGNATURES: usize = 16;

    /// The configuration accepting `algorithms`, no other critical parameter
    /// and [`JWSConfig::MAXIMUM_SIGNATURES`] signatures.
    pub fn new(algorithms: &[JWSAlgorithm]) -> JWSConfig {
        JWSConfig {
            algorithms: algorithms.to_vec(),
            critical: Vec::new(),
            maximum_signatures: JWSConfig::MAXIMUM_SIGNATURES,
        }
    }

    /// The critical header parameters understood: `b64` and those of the configuration.
    pub fn understood(&self) -> Vec<&str> {
        let mut understood: Vec<&str> = self.critical.iter().map(String::as_str).collect();
        understood.extend(JWS::UNDERSTOOD);
        understood
    }
}

/// One signature of a JWS (RFC 7515 §7.2.1): the protected header as it
/// was encoded (the text the signature covers) and as decoded, the
/// unprotected header, and the signature.
#[derive(Clone, Debug, PartialEq)]
pub struct JWSSignature {
    /// The base64url text of the protected header; empty without one.
    pub protected: String,
    pub protected_header: JOSEHeader,
    pub header: Option<JOSEHeader>,
    pub signature: Vec<u8>,
}

impl JWSSignature {
    /// The JOSE Header: the union of the protected and unprotected headers,
    /// which must not share a parameter (RFC 7515 §7.2.1).
    pub fn joined_header(&self) -> Result<JOSEHeader, JWTError> {
        match &self.header {
            Some(header) => JOSEHeader::union(&[&self.protected_header, header]),
            None => Ok(self.protected_header.clone()),
        }
    }

    /// The algorithm of the signature (`alg`, RFC 7515 §4.1.1).
    pub fn algorithm(&self) -> Result<JWSAlgorithm, JWTError> {
        self.joined_header()?.jws_algorithm()
    }
}

/// A JWS (RFC 7515): a payload and its signatures, each with its headers.
/// The compact serialization holds one signature; the JSON serializations
/// any number.
#[derive(Clone, Debug, PartialEq)]
pub struct JWS {
    pub payload: Vec<u8>,
    pub signatures: Vec<JWSSignature>,
}

impl JWS {
    /// The critical header parameters this module understands.
    pub const UNDERSTOOD: [&'static str; 1] = ["b64"];

    /// A JWS of `payload`, without signatures yet.
    pub fn new(payload: Vec<u8>) -> JWS {
        JWS { payload, signatures: Vec::new() }
    }

    /// Whether the payload is base64url-encoded in the signing input and in
    /// the serializations (RFC 7797 §3): the `b64` of every signature, which
    /// must agree; true without signatures.
    pub fn b64(&self) -> Result<bool, JWTError> {
        let mut values = self.signatures.iter().map(|signature| signature.protected_header.b64());
        let Some(first) = values.next().transpose()? else { return Ok(true) };
        for value in values {
            if value? != first {
                return Err(JWTError::Header);
            }
        }
        Ok(first)
    }

    /// The JWS Signing Input (RFC 7515 §5.1, RFC 7797 §3) of the protected
    /// header text `protected`: protected || '.' || the payload, in base64url
    /// when `b64`.
    pub fn signing_input(&self, protected: &str, b64: bool) -> Vec<u8> {
        let mut input = Vec::with_capacity(protected.len() + 1 + self.payload.len() * 4 / 3 + 4);
        input.extend_from_slice(protected.as_bytes());
        input.push(b'.');
        if b64 {
            input.extend_from_slice(Base64URL::encode(&self.payload).as_bytes());
        } else {
            input.extend_from_slice(&self.payload);
        }
        input
    }

    /// Checks the rules of a signature's headers: disjoint headers,
    /// `crit` (with `understood`), and `b64` only in the protected header
    /// and listed in `crit` (RFC 7797 §6).
    pub fn check_headers(signature: &JWSSignature, understood: &[&str]) -> Result<JOSEHeader, JWTError> {
        let header = signature.joined_header()?;
        let unprotected: Vec<&JOSEHeader> = signature.header.iter().collect();
        JOSEHeader::check_critical(&signature.protected_header, &unprotected, understood)?;
        if signature.header.as_ref().is_some_and(|header| header.get("b64").is_some()) {
            return Err(JWTError::Header);
        }
        if signature.protected_header.get("b64").is_some() {
            let listed = signature.protected_header.critical()?.unwrap_or_default();
            if !listed.contains(&"b64") {
                return Err(JWTError::Critical);
            }
        }
        Ok(header)
    }

    /// Adds the signature of the payload with the headers `protected` and
    /// `header` (whose union has the `alg`) under `key`. An `alg` of `none`
    /// adds the empty signature of an Unsecured JWS (RFC 7518 §3.6).
    pub fn sign<R: Random>(
        &mut self,
        protected: &JOSEHeader,
        header: Option<&JOSEHeader>,
        key: &JWK,
        random: &mut R,
    ) -> Result<(), JWTError> {
        let protected_text =
            if protected.is_empty() { String::new() } else { Base64URL::encode(protected.encode().as_bytes()) };
        let mut signature = JWSSignature {
            protected: protected_text,
            protected_header: protected.clone(),
            header: header.cloned(),
            signature: Vec::new(),
        };
        // The producer understands the extensions it lists in `crit`.
        let mut understood = protected.critical()?.unwrap_or_default();
        understood.extend(JWS::UNDERSTOOD);
        let joined = JWS::check_headers(&signature, &understood)?;
        let algorithm = joined.jws_algorithm()?;
        let b64 = protected.b64()?;
        if !self.signatures.is_empty() && self.b64()? != b64 {
            return Err(JWTError::Header);
        }
        if algorithm != JWSAlgorithm::None {
            let input = self.signing_input(&signature.protected, b64);
            signature.signature = algorithm.sign(key, &input, random)?;
        }
        self.signatures.push(signature);
        Ok(())
    }

    /// Verifies the JWS under `key` (RFC 7515 §5.2): the first signature
    /// whose algorithm `config` allows and fits `key` and that verifies.
    /// Fails with [`JWTError::Limit`] for more signatures than `config`
    /// accepts, with [`JWTError::AlgorithmNotAllowed`] if no signature uses
    /// an allowed algorithm, with the error of a header that breaks the
    /// rules, and with [`JWTError::Signature`] otherwise.
    pub fn verify(&self, key: &JWK, config: &JWSConfig) -> Result<&JWSSignature, JWTError> {
        if self.signatures.len() > config.maximum_signatures {
            return Err(JWTError::Limit);
        }
        let understood = config.understood();
        let b64 = self.b64()?;
        let mut error = JWTError::AlgorithmNotAllowed;
        for signature in &self.signatures {
            let header = JWS::check_headers(signature, &understood)?;
            let algorithm = match header.jws_algorithm() {
                Ok(algorithm) => algorithm,
                // An algorithm this module does not know is one no configuration allows.
                Err(JWTError::UnknownAlgorithm) => continue,
                Err(error) => return Err(error),
            };
            if algorithm == JWSAlgorithm::None || !config.algorithms.contains(&algorithm) {
                continue;
            }
            let input = self.signing_input(&signature.protected, b64);
            match algorithm.verify(key, &input, &signature.signature) {
                Ok(()) => return Ok(signature),
                Err(JWTError::KeyMismatch) if error == JWTError::AlgorithmNotAllowed => error = JWTError::KeyMismatch,
                Err(_) => error = JWTError::Signature,
            }
        }
        Err(error)
    }

    /// Accepts an Unsecured JWS (RFC 7518 §3.6): one signature, whose `alg`
    /// is `none` and whose signature is empty. Accepting one is a decision
    /// of the application (RFC 8725 §3.1), which this function makes explicit.
    pub fn verify_unsecured(&self) -> Result<(), JWTError> {
        let [signature] = self.signatures.as_slice() else { return Err(JWTError::Signature) };
        let header = JWS::check_headers(signature, &JWS::UNDERSTOOD)?;
        if header.jws_algorithm()? != JWSAlgorithm::None || !signature.signature.is_empty() {
            return Err(JWTError::Signature);
        }
        Ok(())
    }

    /// The JWS of the compact serialization `text` (RFC 7515 §7.1):
    /// protected header, payload and signature, separated by `.`.
    pub fn from_compact(text: &str) -> Result<JWS, JWTError> {
        JWS::from_compact_parts(text, None)
    }

    /// The JWS of a compact serialization whose payload is detached (RFC
    /// 7515 appendix F): the payload part is empty, the payload is `payload`.
    pub fn from_compact_detached(text: &str, payload: &[u8]) -> Result<JWS, JWTError> {
        JWS::from_compact_parts(text, Some(payload))
    }

    pub fn from_compact_parts(text: &str, detached: Option<&[u8]>) -> Result<JWS, JWTError> {
        let mut parts = text.split('.');
        let (Some(protected), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JWTError::Format);
        };
        let protected_header = JOSEHeader::decode(&Base64URL::decode(protected)?)?;
        let payload = match detached {
            Some(detached) if payload.is_empty() => detached.to_vec(),
            Some(_) => return Err(JWTError::Format),
            None if protected_header.b64()? => Base64URL::decode(payload)?,
            None => payload.as_bytes().to_vec(),
        };
        let signature = JWSSignature {
            protected: protected.to_string(),
            protected_header,
            header: None,
            signature: Base64URL::decode(signature)?,
        };
        Ok(JWS { payload, signatures: alloc::vec![signature] })
    }

    /// The compact serialization: one signature without an unprotected
    /// header (RFC 7515 §7.1). An unencoded payload must not contain `.`
    /// (RFC 7797 §5.2) and must be text.
    pub fn to_compact(&self) -> Result<String, JWTError> {
        let (protected, signature) = self.compact_parts()?;
        let payload = if self.b64()? {
            Base64URL::encode(&self.payload)
        } else {
            let text = core::str::from_utf8(&self.payload).map_err(|_| JWTError::Format)?;
            if text.contains('.') {
                return Err(JWTError::Format);
            }
            text.to_string()
        };
        Ok(alloc::format!("{protected}.{payload}.{signature}"))
    }

    /// The compact serialization with the payload detached (RFC 7515 appendix F).
    pub fn to_compact_detached(&self) -> Result<String, JWTError> {
        let (protected, signature) = self.compact_parts()?;
        Ok(alloc::format!("{protected}..{signature}"))
    }

    /// The protected header text and the signature text of the one
    /// signature of a compact serialization.
    pub fn compact_parts(&self) -> Result<(&str, String), JWTError> {
        let [signature] = self.signatures.as_slice() else { return Err(JWTError::Format) };
        if signature.header.is_some() || signature.protected.is_empty() {
            return Err(JWTError::Format);
        }
        Ok((&signature.protected, Base64URL::encode(&signature.signature)))
    }

    /// The JWS of a JSON serialization `text` (RFC 7515 §7.2): general,
    /// with `signatures`, or flattened, with the members of one signature.
    pub fn from_json(text: &[u8]) -> Result<JWS, JWTError> {
        JWS::from_json_parts(text, None)
    }

    /// The JWS of a JSON serialization whose payload is detached (RFC 7515
    /// appendix F, RFC 7797 §4.2): without `payload`, the payload is `payload`.
    pub fn from_json_detached(text: &[u8], payload: &[u8]) -> Result<JWS, JWTError> {
        JWS::from_json_parts(text, Some(payload))
    }

    pub fn from_json_parts(text: &[u8], detached: Option<&[u8]>) -> Result<JWS, JWTError> {
        let value = JSONValue::decode(text, JSONConfig::default())?;
        let object = value.as_object().ok_or(JWTError::Format)?;
        let members = JOSEMembers::new(object, JWTError::Format);
        let mut signatures = Vec::new();
        match object.get("signatures") {
            Some(list) => {
                if object.get("signature").is_some()
                    || object.get("protected").is_some()
                    || object.get("header").is_some()
                {
                    return Err(JWTError::Format);
                }
                for item in list.as_array().ok_or(JWTError::Format)? {
                    signatures.push(JWS::signature_of(item.as_object().ok_or(JWTError::Format)?)?);
                }
            }
            None => signatures.push(JWS::signature_of(object)?),
        }
        let mut jws = JWS { payload: Vec::new(), signatures };
        jws.payload = match (members.string("payload")?, detached) {
            (None, Some(detached)) => detached.to_vec(),
            (Some(payload), None) if jws.b64()? => Base64URL::decode(payload)?,
            (Some(payload), None) => payload.as_bytes().to_vec(),
            _ => return Err(JWTError::Format),
        };
        Ok(jws)
    }

    /// The signature of the members `object` of a JSON serialization.
    pub fn signature_of(object: &JSONObject) -> Result<JWSSignature, JWTError> {
        let members = JOSEMembers::new(object, JWTError::Format);
        let protected = members.string("protected")?.unwrap_or_default();
        let protected_header =
            if protected.is_empty() { JOSEHeader::new() } else { JOSEHeader::decode(&Base64URL::decode(protected)?)? };
        let header = members.object("header")?.map(|parameters| JOSEHeader { parameters: parameters.clone() });
        if protected.is_empty() && header.is_none() {
            return Err(JWTError::Format);
        }
        Ok(JWSSignature {
            protected: protected.to_string(),
            protected_header,
            header,
            signature: members.required_bytes("signature")?,
        })
    }

    /// The members of one signature in a JSON serialization.
    pub fn signature_object(signature: &JWSSignature, object: &mut JSONObject) {
        if !signature.protected.is_empty() {
            object.insert(String::from("protected"), JSONValue::String(signature.protected.clone()));
        }
        if let Some(header) = &signature.header {
            object.insert(String::from("header"), JSONValue::Object(header.parameters.clone()));
        }
        object.insert(String::from("signature"), JSONValue::String(Base64URL::encode(&signature.signature)));
    }

    /// The `payload` member of a JSON serialization.
    pub fn payload_value(&self) -> Result<JSONValue, JWTError> {
        Ok(JSONValue::String(if self.b64()? {
            Base64URL::encode(&self.payload)
        } else {
            String::from_utf8(self.payload.clone()).map_err(|_| JWTError::Format)?
        }))
    }

    /// The JSON object of a JSON serialization: general or `flattened`
    /// (one signature), with the payload or without it (`detached`).
    pub fn json_object(&self, flattened: bool, detached: bool) -> Result<JSONObject, JWTError> {
        let mut object = JSONObject::default();
        if !detached {
            object.insert(String::from("payload"), self.payload_value()?);
        }
        if flattened {
            let [signature] = self.signatures.as_slice() else { return Err(JWTError::Format) };
            JWS::signature_object(signature, &mut object);
        } else {
            let signatures = self
                .signatures
                .iter()
                .map(|signature| {
                    let mut member = JSONObject::default();
                    JWS::signature_object(signature, &mut member);
                    JSONValue::Object(member)
                })
                .collect();
            object.insert(String::from("signatures"), JSONValue::Array(signatures));
        }
        Ok(object)
    }

    /// The general JSON serialization (RFC 7515 §7.2.1).
    pub fn to_json(&self) -> Result<String, JWTError> {
        Ok(JSONValue::Object(self.json_object(false, false)?).encode())
    }

    /// The flattened JSON serialization of a JWS of one signature (RFC 7515 §7.2.2).
    pub fn to_flattened_json(&self) -> Result<String, JWTError> {
        Ok(JSONValue::Object(self.json_object(true, false)?).encode())
    }

    /// The general JSON serialization without the payload.
    pub fn to_json_detached(&self) -> Result<String, JWTError> {
        Ok(JSONValue::Object(self.json_object(false, true)?).encode())
    }

    /// The flattened JSON serialization without the payload.
    pub fn to_flattened_json_detached(&self) -> Result<String, JWTError> {
        Ok(JSONValue::Object(self.json_object(true, true)?).encode())
    }
}
