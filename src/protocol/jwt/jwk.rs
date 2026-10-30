use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{Base64URL, Base64URLUInt, JOSEMembers, JWSAlgorithm, JWTError};
use crate::auth::cert::key::{HashAlgorithm, KeyAlgorithm, MLDSAParameterSet, NamedCurve, PrivateKey, PublicKey};
use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;
use crate::codec::json::{JSONConfig, JSONObject, JSONValue};
use crate::math::bigint::BoxedUint;
use crate::secret::Secret;

/// A curve of a JWK: of an `EC` key (RFC 7518 §6.2.1.1, RFC 8812 §3.1) or
/// of an `OKP` key (RFC 8037 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JWKCurve {
    P256,
    P384,
    P521,
    Secp256k1,
    Ed25519,
    Ed448,
    X25519,
    X448,
}

impl JWKCurve {
    pub const ALL: [JWKCurve; 8] = [
        JWKCurve::P256,
        JWKCurve::P384,
        JWKCurve::P521,
        JWKCurve::Secp256k1,
        JWKCurve::Ed25519,
        JWKCurve::Ed448,
        JWKCurve::X25519,
        JWKCurve::X448,
    ];

    /// The name of the curve in the IANA registry, the value of `crv`.
    pub const fn name(self) -> &'static str {
        match self {
            JWKCurve::P256 => "P-256",
            JWKCurve::P384 => "P-384",
            JWKCurve::P521 => "P-521",
            JWKCurve::Secp256k1 => "secp256k1",
            JWKCurve::Ed25519 => "Ed25519",
            JWKCurve::Ed448 => "Ed448",
            JWKCurve::X25519 => "X25519",
            JWKCurve::X448 => "X448",
        }
    }

    pub fn from_name(name: &str) -> Option<JWKCurve> {
        JWKCurve::ALL.into_iter().find(|curve| curve.name() == name)
    }

    /// Whether the curve is of `OKP` keys rather than `EC` keys.
    pub const fn is_okp(self) -> bool {
        matches!(self, JWKCurve::Ed25519 | JWKCurve::Ed448 | JWKCurve::X25519 | JWKCurve::X448)
    }

    /// The bytes of the coordinates and the private key: the size of the
    /// field for `EC` keys (RFC 7518 §6.2.1.2), the key size for `OKP` keys
    /// (RFC 8037 §2).
    pub const fn size(self) -> usize {
        match self {
            JWKCurve::P256 | JWKCurve::Secp256k1 | JWKCurve::Ed25519 | JWKCurve::X25519 => 32,
            JWKCurve::P384 => 48,
            JWKCurve::P521 => 66,
            JWKCurve::Ed448 => 57,
            JWKCurve::X448 => 56,
        }
    }

    /// The key algorithm of keys on the curve.
    pub const fn key_algorithm(self) -> KeyAlgorithm {
        match self {
            JWKCurve::P256 => KeyAlgorithm::EC(NamedCurve::P256),
            JWKCurve::P384 => KeyAlgorithm::EC(NamedCurve::P384),
            JWKCurve::P521 => KeyAlgorithm::EC(NamedCurve::P521),
            JWKCurve::Secp256k1 => KeyAlgorithm::EC(NamedCurve::Secp256k1),
            JWKCurve::Ed25519 => KeyAlgorithm::Ed25519,
            JWKCurve::Ed448 => KeyAlgorithm::Ed448,
            JWKCurve::X25519 => KeyAlgorithm::X25519,
            JWKCurve::X448 => KeyAlgorithm::X448,
        }
    }

    /// The curve of keys of `algorithm`, if JOSE has one.
    pub fn from_key_algorithm(algorithm: &KeyAlgorithm) -> Option<JWKCurve> {
        JWKCurve::ALL.into_iter().find(|curve| curve.key_algorithm() == *algorithm)
    }
}

/// The private parameters of an RSA JWK (RFC 7518 §6.3.2): the private
/// exponent, and the primes with their exponents and coefficient, which
/// are all present or all absent. Other primes (`oth`) are not supported.
#[derive(Clone, Debug)]
pub struct RSAPrivateParameters {
    pub d: Secret<Vec<u8>>,
    pub primes: Option<RSAPrimeParameters>,
}

/// `p`, `q`, `dp`, `dq` and `qi` of an RSA JWK (RFC 7518 §6.3.2.2 to §6.3.2.6).
#[derive(Clone, Debug)]
pub struct RSAPrimeParameters {
    pub p: Secret<Vec<u8>>,
    pub q: Secret<Vec<u8>>,
    pub dp: Secret<Vec<u8>>,
    pub dq: Secret<Vec<u8>>,
    pub qi: Secret<Vec<u8>>,
}

/// The key of a JWK by its type (`kty`), with its parameters as bytes.
/// Integers of RSA keys are big-endian without leading zeros; coordinates
/// and private keys of curves have the size of the curve.
#[derive(Clone, Debug)]
pub enum JWKKey {
    /// An elliptic curve key (RFC 7518 §6.2).
    EC { curve: JWKCurve, x: Vec<u8>, y: Vec<u8>, d: Option<Secret<Vec<u8>>> },
    /// An RSA key (RFC 7518 §6.3).
    RSA { n: Vec<u8>, e: Vec<u8>, private: Option<Box<RSAPrivateParameters>> },
    /// A symmetric key (RFC 7518 §6.4).
    Oct { k: Secret<Vec<u8>> },
    /// An octet key pair of Edwards or Montgomery curves (RFC 8037 §2).
    OKP { curve: JWKCurve, x: Vec<u8>, d: Option<Secret<Vec<u8>>> },
    /// An algorithm key pair (RFC 9964 §4), whose algorithm is the `alg`
    /// of the JWK: the public key and, for a private key, the seed.
    AKP { public: Vec<u8>, private: Option<Secret<Vec<u8>>> },
}

impl JWKKey {
    /// The value of `kty`.
    pub const fn type_name(&self) -> &'static str {
        match self {
            JWKKey::EC { .. } => "EC",
            JWKKey::RSA { .. } => "RSA",
            JWKKey::Oct { .. } => "oct",
            JWKKey::OKP { .. } => "OKP",
            JWKKey::AKP { .. } => "AKP",
        }
    }

    /// Whether the key holds secret material: a private key or a symmetric key.
    pub const fn is_secret(&self) -> bool {
        match self {
            JWKKey::EC { d, .. } | JWKKey::OKP { d, .. } => d.is_some(),
            JWKKey::RSA { private, .. } => private.is_some(),
            JWKKey::Oct { .. } => true,
            JWKKey::AKP { private, .. } => private.is_some(),
        }
    }
}

/// A JSON Web Key (RFC 7517): a key and the parameters that say how it
/// may be used. Members this library does not define are kept in `other`.
#[derive(Clone, Debug)]
pub struct JWK {
    pub key: JWKKey,
    /// `use`: "sig" or "enc" (RFC 7517 §4.2).
    pub key_use: Option<String>,
    /// `key_ops` (RFC 7517 §4.3).
    pub key_operations: Option<Vec<String>>,
    /// `alg` (RFC 7517 §4.4); required for `AKP` keys (RFC 9964 §4).
    pub algorithm: Option<String>,
    /// `kid` (RFC 7517 §4.5).
    pub key_id: Option<String>,
    /// `x5u` (RFC 7517 §4.6).
    pub x509_url: Option<String>,
    /// `x5c`: DER certificates, the first holding the key (RFC 7517 §4.7).
    pub x509_chain: Option<Vec<Vec<u8>>>,
    /// `x5t` (RFC 7517 §4.8).
    pub x509_sha1: Option<Vec<u8>>,
    /// `x5t#S256` (RFC 7517 §4.9).
    pub x509_sha256: Option<Vec<u8>>,
    pub other: JSONObject,
}

impl JWK {
    /// The key operations of RFC 7517 §4.3.
    pub const OPERATIONS: [&'static str; 8] =
        ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"];
    /// The members defined by RFC 7517 §4 for every key type.
    pub const COMMON_MEMBERS: [&'static str; 10] =
        ["kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256", "crv"];

    /// The JWK of `key` without the optional parameters.
    pub fn new(key: JWKKey) -> JWK {
        JWK {
            key,
            key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_chain: None,
            x509_sha1: None,
            x509_sha256: None,
            other: JSONObject::default(),
        }
    }

    /// The symmetric JWK of the bytes `k`.
    pub fn symmetric(k: &[u8]) -> JWK {
        JWK::new(JWKKey::Oct { k: Secret::new(k.to_vec()) })
    }

    /// The JWK of the JSON text `text` (duplicate members refused).
    pub fn from_json(text: &[u8]) -> Result<JWK, JWTError> {
        let value = JSONValue::decode(text, JSONConfig::default())?;
        JWK::from_object(value.as_object().ok_or(JWTError::Format)?)
    }

    /// The JWK of the JSON object `object`, validated: the parameters of its
    /// type, with the sizes of RFC 7518, the public key a key of its
    /// algorithm or curve, the private parameters, if any, those of the
    /// public key, `use` and `key_ops` consistent, and the first
    /// certificate of `x5c`, if any, of the same key.
    pub fn from_object(object: &JSONObject) -> Result<JWK, JWTError> {
        let members = JOSEMembers::new(object, JWTError::Format);
        let secret = |name: &str| members.bytes(name).map(|bytes| bytes.map(Secret::new));
        let key = match members.required_string("kty")? {
            "EC" | "OKP" => {
                let kty = members.required_string("kty")?;
                let curve = JWKCurve::from_name(members.required_string("crv")?).ok_or(JWTError::UnknownKeyType)?;
                if curve.is_okp() != (kty == "OKP") {
                    return Err(JWTError::UnknownKeyType);
                }
                let x = members.required_bytes("x")?;
                let d = secret("d")?;
                let sized = |bytes: &[u8]| bytes.len() == curve.size();
                if !sized(&x) || d.as_ref().is_some_and(|d| !sized(d.expose())) {
                    return Err(JWTError::Key(crate::auth::cert::key::KeyError::InvalidKey));
                }
                if curve.is_okp() {
                    JWKKey::OKP { curve, x, d }
                } else {
                    let y = members.required_bytes("y")?;
                    if !sized(&y) {
                        return Err(JWTError::Key(crate::auth::cert::key::KeyError::InvalidKey));
                    }
                    JWKKey::EC { curve, x, y, d }
                }
            }
            "RSA" => {
                let uint = |name: &str| members.string(name)?.map(Base64URLUInt::decode).transpose();
                let n = uint("n")?.ok_or(JWTError::Format)?;
                let e = uint("e")?.ok_or(JWTError::Format)?;
                if object.get("oth").is_some() {
                    return Err(JWTError::Key(crate::auth::cert::key::KeyError::Unsupported));
                }
                let names = ["p", "q", "dp", "dq", "qi"];
                let mut values: Vec<Secret<Vec<u8>>> = Vec::new();
                for name in names {
                    if let Some(value) = uint(name)? {
                        values.push(Secret::new(value));
                    }
                }
                let private = match uint("d")? {
                    None if values.is_empty() => None,
                    None => return Err(JWTError::Format),
                    Some(d) => {
                        let primes = match values.len() {
                            0 => None,
                            5 => {
                                let mut values = values.into_iter();
                                let mut next = || values.next().expect("five values");
                                Some(RSAPrimeParameters { p: next(), q: next(), dp: next(), dq: next(), qi: next() })
                            }
                            // RFC 7518 §6.3.2: the other parameters are all present or all absent.
                            _ => return Err(JWTError::Format),
                        };
                        Some(Box::new(RSAPrivateParameters { d: Secret::new(d), primes }))
                    }
                };
                JWKKey::RSA { n, e, private }
            }
            "oct" => JWKKey::Oct { k: Secret::new(members.required_bytes("k")?) },
            "AKP" => {
                if members.string("alg")?.is_none() {
                    return Err(JWTError::Format);
                }
                JWKKey::AKP { public: members.required_bytes("pub")?, private: secret("priv")? }
            }
            _ => return Err(JWTError::UnknownKeyType),
        };
        let x509_chain = match members.strings("x5c")? {
            None => None,
            Some(texts) => Some(
                texts
                    .into_iter()
                    .map(|text| Base64::STANDARD.decode(text.as_bytes()).map_err(|_| JWTError::Base64))
                    .collect::<Result<Vec<Vec<u8>>, JWTError>>()?,
            ),
        };
        let mut other = JSONObject::default();
        for (name, value) in object.iter() {
            if !JWK::COMMON_MEMBERS.contains(&name.as_str()) && !JWK::key_members(&key).contains(&name.as_str()) {
                other.insert(name.clone(), value.clone());
            }
        }
        let jwk = JWK {
            key,
            key_use: members.string("use")?.map(String::from),
            key_operations: members
                .strings("key_ops")?
                .map(|operations| operations.into_iter().map(String::from).collect()),
            algorithm: members.string("alg")?.map(String::from),
            key_id: members.string("kid")?.map(String::from),
            x509_url: members.string("x5u")?.map(String::from),
            x509_chain,
            x509_sha1: members.bytes("x5t")?,
            x509_sha256: members.bytes("x5t#S256")?,
            other,
        };
        jwk.check()?;
        Ok(jwk)
    }

    /// The members of the parameters of the type of `key`.
    pub const fn key_members(key: &JWKKey) -> &'static [&'static str] {
        match key {
            JWKKey::EC { .. } => &["x", "y", "d"],
            JWKKey::RSA { .. } => &["n", "e", "d", "p", "q", "dp", "dq", "qi", "oth"],
            JWKKey::Oct { .. } => &["k"],
            JWKKey::OKP { .. } => &["x", "d"],
            JWKKey::AKP { .. } => &["pub", "priv"],
        }
    }

    /// Checks the rules [`JWK::from_object`] applies.
    pub fn check(&self) -> Result<(), JWTError> {
        if let Some(operations) = &self.key_operations {
            // RFC 7517 §4.3: no operation twice.
            if operations.iter().enumerate().any(|(index, operation)| operations[..index].contains(operation)) {
                return Err(JWTError::Format);
            }
            // RFC 7517 §4.3: `use` and `key_ops` consistent.
            if let Some(key_use) = &self.key_use
                && operations.iter().any(|operation| JWK::use_of(operation).is_some_and(|expected| expected != key_use))
            {
                return Err(JWTError::Format);
            }
        }
        if self.key.is_secret() && !matches!(self.key, JWKKey::Oct { .. }) {
            // The private parameters must be those of the public key.
            let derived = JWK::from_private_key(&self.private_key()?)?;
            if derived.thumbprint_input()? != self.thumbprint_input()? {
                return Err(JWTError::Key(crate::auth::cert::key::KeyError::Inconsistent));
            }
        } else if !matches!(self.key, JWKKey::Oct { .. }) {
            self.public_key()?;
        }
        if let Some(first) = self.x509_chain.as_ref().and_then(|chain| chain.first()) {
            let certificate = crate::auth::cert::x509::Certificate::from_der(first)
                .map_err(|_| JWTError::Key(crate::auth::cert::key::KeyError::InvalidKey))?;
            let key =
                certificate.public_key().map_err(|_| JWTError::Key(crate::auth::cert::key::KeyError::InvalidKey))?;
            if JWK::from_public_key(&key)?.thumbprint_input()? != self.thumbprint_input()? {
                return Err(JWTError::Key(crate::auth::cert::key::KeyError::Inconsistent));
            }
        }
        Ok(())
    }

    /// The `use` an operation belongs to: "sig" for signing and verifying,
    /// "enc" for the others (RFC 7517 §4.2, §4.3).
    pub fn use_of(operation: &str) -> Option<&'static str> {
        match operation {
            "sign" | "verify" => Some("sig"),
            "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits" => Some("enc"),
            _ => None,
        }
    }

    /// Whether the key may serve `operation` (one of [`JWK::OPERATIONS`])
    /// with the algorithm named `algorithm`: its `alg`, `use` and `key_ops`,
    /// where present, allow it.
    pub fn allows(&self, operation: &str, algorithm: &str) -> bool {
        self.algorithm.as_deref().is_none_or(|own| own == algorithm)
            && self.key_use.as_deref().is_none_or(|key_use| JWK::use_of(operation) == Some(key_use))
            && self.key_operations.as_ref().is_none_or(|operations| operations.iter().any(|own| own == operation))
    }

    /// The JSON object of the JWK.
    pub fn to_object(&self) -> JSONObject {
        let mut object = JSONObject::default();
        let mut put = |name: &str, value: JSONValue| {
            object.insert(name.to_string(), value);
        };
        let text = |value: &str| JSONValue::String(value.to_string());
        let bytes = |value: &[u8]| JSONValue::String(Base64URL::encode(value));
        let uint = |value: &[u8]| JSONValue::String(Base64URLUInt::encode(value));
        put("kty", text(self.key.type_name()));
        match &self.key {
            JWKKey::EC { curve, x, y, d } => {
                put("crv", text(curve.name()));
                put("x", bytes(x));
                put("y", bytes(y));
                if let Some(d) = d {
                    put("d", bytes(d.expose()));
                }
            }
            JWKKey::RSA { n, e, private } => {
                put("n", uint(n));
                put("e", uint(e));
                if let Some(private) = private {
                    put("d", uint(private.d.expose()));
                    if let Some(primes) = &private.primes {
                        put("p", uint(primes.p.expose()));
                        put("q", uint(primes.q.expose()));
                        put("dp", uint(primes.dp.expose()));
                        put("dq", uint(primes.dq.expose()));
                        put("qi", uint(primes.qi.expose()));
                    }
                }
            }
            JWKKey::Oct { k } => put("k", bytes(k.expose())),
            JWKKey::OKP { curve, x, d } => {
                put("crv", text(curve.name()));
                put("x", bytes(x));
                if let Some(d) = d {
                    put("d", bytes(d.expose()));
                }
            }
            JWKKey::AKP { public, private } => {
                put("pub", bytes(public));
                if let Some(private) = private {
                    put("priv", bytes(private.expose()));
                }
            }
        }
        if let Some(key_use) = &self.key_use {
            put("use", text(key_use));
        }
        if let Some(operations) = &self.key_operations {
            put("key_ops", JSONValue::Array(operations.iter().map(|operation| text(operation)).collect()));
        }
        if let Some(algorithm) = &self.algorithm {
            put("alg", text(algorithm));
        }
        if let Some(key_id) = &self.key_id {
            put("kid", text(key_id));
        }
        if let Some(url) = &self.x509_url {
            put("x5u", text(url));
        }
        if let Some(chain) = &self.x509_chain {
            put(
                "x5c",
                JSONValue::Array(chain.iter().map(|der| JSONValue::String(Base64::STANDARD.encode(der))).collect()),
            );
        }
        if let Some(sha1) = &self.x509_sha1 {
            put("x5t", bytes(sha1));
        }
        if let Some(sha256) = &self.x509_sha256 {
            put("x5t#S256", bytes(sha256));
        }
        for (name, value) in self.other.iter() {
            put(name, value.clone());
        }
        object
    }

    /// The JSON text of the JWK.
    pub fn to_json(&self) -> String {
        JSONValue::Object(self.to_object()).encode()
    }

    /// The JWK without its private parameters (the same JWK for a public
    /// key); fails with [`JWTError::KeyMismatch`] for a symmetric key,
    /// which has no public part.
    pub fn to_public(&self) -> Result<JWK, JWTError> {
        let key = match &self.key {
            JWKKey::EC { curve, x, y, .. } => JWKKey::EC { curve: *curve, x: x.clone(), y: y.clone(), d: None },
            JWKKey::RSA { n, e, .. } => JWKKey::RSA { n: n.clone(), e: e.clone(), private: None },
            JWKKey::Oct { .. } => return Err(JWTError::KeyMismatch),
            JWKKey::OKP { curve, x, .. } => JWKKey::OKP { curve: *curve, x: x.clone(), d: None },
            JWKKey::AKP { public, .. } => JWKKey::AKP { public: public.clone(), private: None },
        };
        Ok(JWK { key, ..self.clone() })
    }

    /// The ML-DSA parameter set of an `AKP` key, from its `alg`.
    pub fn mldsa(&self) -> Result<MLDSAParameterSet, JWTError> {
        let algorithm = self.algorithm.as_deref().and_then(JWSAlgorithm::from_name);
        algorithm.and_then(JWSAlgorithm::mldsa).ok_or(JWTError::UnknownAlgorithm)
    }

    /// The public key of the JWK (of a private key, its public part);
    /// fails with [`JWTError::KeyMismatch`] for a symmetric key.
    pub fn public_key(&self) -> Result<PublicKey, JWTError> {
        Ok(match &self.key {
            JWKKey::EC { curve, x, y, .. } => PublicKey::new(curve.key_algorithm(), &[&[0x04][..], x, y].concat())?,
            JWKKey::RSA { n, e, .. } => {
                let integer = |bytes: &[u8]| {
                    BoxedUint::from_be_bytes(bytes, (bytes.len().max(1) * 8) as u32)
                        .map_err(|_| JWTError::Key(crate::auth::cert::key::KeyError::InvalidKey))
                };
                let public = crate::crypto::rsa::RSAPublicKey::new(&integer(n)?, &integer(e)?)?;
                PublicKey::new(KeyAlgorithm::RSA, &public.to_pkcs1_der())?
            }
            JWKKey::Oct { .. } => return Err(JWTError::KeyMismatch),
            JWKKey::OKP { curve, x, .. } => PublicKey::new(curve.key_algorithm(), x)?,
            JWKKey::AKP { public, .. } => PublicKey::new(KeyAlgorithm::MLDSA(self.mldsa()?), public)?,
        })
    }

    /// The private key of the JWK; fails with [`JWTError::KeyMismatch`]
    /// for a public or symmetric key.
    pub fn private_key(&self) -> Result<PrivateKey, JWTError> {
        let mismatch = Err(JWTError::KeyMismatch);
        Ok(match &self.key {
            JWKKey::EC { curve, d: Some(d), .. } | JWKKey::OKP { curve, d: Some(d), .. } => {
                PrivateKey::from_raw(curve.key_algorithm(), d.expose())?
            }
            JWKKey::AKP { private: Some(private), .. } => {
                PrivateKey::from_raw(KeyAlgorithm::MLDSA(self.mldsa()?), private.expose())?
            }
            JWKKey::RSA { n, e, private: Some(private) } => {
                use crate::crypto::rsa::{RSAPrivateKey, RSAPublicKey};
                let integer = |bytes: &[u8]| {
                    BoxedUint::from_be_bytes(bytes, (bytes.len().max(1) * 8) as u32)
                        .map_err(|_| JWTError::Key(crate::auth::cert::key::KeyError::InvalidKey))
                };
                let public = RSAPublicKey::new(&integer(n)?, &integer(e)?)?;
                let d = integer(private.d.expose())?;
                let key = match &private.primes {
                    None => RSAPrivateKey::new(public, &d)?,
                    Some(primes) => RSAPrivateKey::from_components(
                        public,
                        &d,
                        &integer(primes.p.expose())?,
                        &integer(primes.q.expose())?,
                        &integer(primes.dp.expose())?,
                        &integer(primes.dq.expose())?,
                        &integer(primes.qi.expose())?,
                    )?,
                };
                PrivateKey::from_key(KeyAlgorithm::RSA, key)?
            }
            _ => return mismatch,
        })
    }

    /// The JWK of `key`: `EC`, `RSA`, `OKP` or `AKP` (ML-DSA, with its
    /// `alg`); fails with [`JWTError::UnknownKeyType`] for an algorithm JOSE
    /// has no key type for.
    pub fn from_public_key(key: &PublicKey) -> Result<JWK, JWTError> {
        let algorithm = key.algorithm();
        if let Some(curve) = JWKCurve::from_key_algorithm(algorithm) {
            if curve.is_okp() {
                return Ok(JWK::new(JWKKey::OKP { curve, x: key.key().to_vec(), d: None }));
            }
            let point = key.uncompressed_point()?;
            let (x, y) = point[1..].split_at(curve.size());
            return Ok(JWK::new(JWKKey::EC { curve, x: x.to_vec(), y: y.to_vec(), d: None }));
        }
        match algorithm {
            KeyAlgorithm::RSA | KeyAlgorithm::RSAPSS(_) => {
                let rsa = key.typed::<crate::crypto::rsa::RSAPublicKey>()?;
                let minimal = |value: &BoxedUint| {
                    let bytes = value.to_be_bytes();
                    let start = bytes.iter().position(|&byte| byte != 0).unwrap_or(bytes.len().saturating_sub(1));
                    bytes[start..].to_vec()
                };
                Ok(JWK::new(JWKKey::RSA { n: minimal(rsa.n()), e: minimal(rsa.e()), private: None }))
            }
            KeyAlgorithm::MLDSA(set) => {
                let name = match set {
                    MLDSAParameterSet::MLDSA44 => JWSAlgorithm::MLDSA44,
                    MLDSAParameterSet::MLDSA65 => JWSAlgorithm::MLDSA65,
                    MLDSAParameterSet::MLDSA87 => JWSAlgorithm::MLDSA87,
                };
                let mut jwk = JWK::new(JWKKey::AKP { public: key.key().to_vec(), private: None });
                jwk.algorithm = Some(name.name().to_string());
                Ok(jwk)
            }
            _ => Err(JWTError::UnknownKeyType),
        }
    }

    /// The JWK of `key` with its private parameters (see
    /// [`JWK::from_public_key`]); ML-DSA keys need their seed (RFC 9964 §4).
    pub fn from_private_key(key: &PrivateKey) -> Result<JWK, JWTError> {
        let mut jwk = JWK::from_public_key(&key.public_key()?)?;
        match &mut jwk.key {
            JWKKey::EC { d, .. } | JWKKey::OKP { d, .. } => *d = Some(key.raw()?),
            JWKKey::AKP { private, .. } => *private = Some(key.raw()?),
            JWKKey::RSA { private, .. } => {
                let rsa = key.typed::<crate::crypto::rsa::RSAPrivateKey>()?;
                let minimal = |value: &BoxedUint| {
                    let bytes = value.to_be_bytes();
                    let start = bytes.iter().position(|&byte| byte != 0).unwrap_or(bytes.len().saturating_sub(1));
                    Secret::new(bytes[start..].to_vec())
                };
                let primes = rsa.primes().map(|primes| RSAPrimeParameters {
                    p: minimal(primes.p()),
                    q: minimal(primes.q()),
                    dp: minimal(primes.dp()),
                    dq: minimal(primes.dq()),
                    qi: minimal(primes.q_inverse()),
                });
                *private = Some(Box::new(RSAPrivateParameters { d: minimal(rsa.d()), primes }));
            }
            JWKKey::Oct { .. } => return Err(JWTError::KeyMismatch),
        }
        Ok(jwk)
    }

    /// The input of the thumbprint (RFC 7638 §3.2): the JSON object of the
    /// required members of the key type in lexicographic order, without
    /// white space; for `OKP` keys those of RFC 8037 §2, for `AKP` keys
    /// those of RFC 9964 §6.
    pub fn thumbprint_input(&self) -> Result<String, JWTError> {
        let string = |value: &str| JSONValue::String(value.to_string()).encode();
        let members: Vec<(&str, String)> = match &self.key {
            JWKKey::EC { curve, x, y, .. } => alloc::vec![
                ("crv", string(curve.name())),
                ("kty", string("EC")),
                ("x", string(&Base64URL::encode(x))),
                ("y", string(&Base64URL::encode(y))),
            ],
            JWKKey::RSA { n, e, .. } => alloc::vec![
                ("e", string(&Base64URLUInt::encode(e))),
                ("kty", string("RSA")),
                ("n", string(&Base64URLUInt::encode(n))),
            ],
            JWKKey::Oct { k } => alloc::vec![("k", string(&Base64URL::encode(k.expose()))), ("kty", string("oct"))],
            JWKKey::OKP { curve, x, .. } => {
                alloc::vec![("crv", string(curve.name())), ("kty", string("OKP")), ("x", string(&Base64URL::encode(x))),]
            }
            JWKKey::AKP { public, .. } => alloc::vec![
                ("alg", string(self.algorithm.as_deref().ok_or(JWTError::Format)?)),
                ("kty", string("AKP")),
                ("pub", string(&Base64URL::encode(public))),
            ],
        };
        let mut text = String::from("{");
        for (index, (name, value)) in members.iter().enumerate() {
            if index > 0 {
                text.push(',');
            }
            text.push('"');
            text.push_str(name);
            text.push_str("\":");
            text.push_str(value);
        }
        text.push('}');
        Ok(text)
    }

    /// The JWK Thumbprint (RFC 7638) with the hash function `hash`.
    pub fn thumbprint(&self, hash: HashAlgorithm) -> Result<Vec<u8>, JWTError> {
        let mut digest = [0u8; 64];
        let length = hash.digest(self.thumbprint_input()?.as_bytes(), &mut digest);
        Ok(digest[..length].to_vec())
    }

    /// The name of `hash` in the Named Information Hash Algorithm Registry,
    /// which JWK Thumbprint URIs use (RFC 9278 §3).
    pub fn hash_name(hash: HashAlgorithm) -> Option<&'static str> {
        match hash {
            HashAlgorithm::SHA256 => Some("sha-256"),
            HashAlgorithm::SHA384 => Some("sha-384"),
            HashAlgorithm::SHA512 => Some("sha-512"),
            HashAlgorithm::SHA3_224 => Some("sha3-224"),
            HashAlgorithm::SHA3_256 => Some("sha3-256"),
            HashAlgorithm::SHA3_384 => Some("sha3-384"),
            HashAlgorithm::SHA3_512 => Some("sha3-512"),
            _ => None,
        }
    }

    /// The JWK Thumbprint URI (RFC 9278 §3):
    /// `urn:ietf:params:oauth:jwk-thumbprint:<hash>:<thumbprint>`.
    pub fn thumbprint_uri(&self, hash: HashAlgorithm) -> Result<String, JWTError> {
        let name = JWK::hash_name(hash).ok_or(JWTError::UnknownAlgorithm)?;
        let thumbprint = Base64URL::encode(&self.thumbprint(hash)?);
        Ok(alloc::format!("urn:ietf:params:oauth:jwk-thumbprint:{name}:{thumbprint}"))
    }
}

/// A JWK Set (RFC 7517 §5): keys, and the members of the set this library
/// does not define. Keys of a type this library does not know are left
/// out, as RFC 7517 §5 asks.
#[derive(Clone, Debug, Default)]
pub struct JWKSet {
    pub keys: Vec<JWK>,
    pub other: JSONObject,
}

impl JWKSet {
    pub fn from_json(text: &[u8]) -> Result<JWKSet, JWTError> {
        let value = JSONValue::decode(text, JSONConfig::default())?;
        let object = value.as_object().ok_or(JWTError::Format)?;
        let keys = object.get("keys").and_then(JSONValue::as_array).ok_or(JWTError::Format)?;
        let mut set = JWKSet::default();
        for key in keys {
            // RFC 7517 §5: keys of types not understood, missing members or
            // with values out of the supported ranges are ignored.
            if let Ok(jwk) = JWK::from_object(key.as_object().ok_or(JWTError::Format)?) {
                set.keys.push(jwk);
            }
        }
        for (name, value) in object.iter().filter(|(name, _)| name != "keys") {
            set.other.insert(name.clone(), value.clone());
        }
        Ok(set)
    }

    pub fn to_json(&self) -> String {
        let mut object = JSONObject::default();
        let keys = self.keys.iter().map(|key| JSONValue::Object(key.to_object())).collect();
        object.insert(String::from("keys"), JSONValue::Array(keys));
        for (name, value) in self.other.iter() {
            object.insert(name.clone(), value.clone());
        }
        JSONValue::Object(object).encode()
    }

    /// The keys whose `kid` is `key_id`.
    pub fn find(&self, key_id: &str) -> impl Iterator<Item = &JWK> {
        self.keys.iter().filter(move |key| key.key_id.as_deref() == Some(key_id))
    }
}
