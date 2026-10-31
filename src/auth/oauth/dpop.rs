use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::auth::cert::key::HashAlgorithm;
use crate::codec::json::JSONValue;
use crate::codec::uri::URIReference;
use crate::crypto::random::Random;
use crate::hash::Digest;
use crate::hash::sha::v2::SHA256;
use crate::protocol::jwt::{Base64URL, JOSEHeader, JWK, JWS, JWSAlgorithm, JWSConfig, JWT, JWTClaims, JWTValidation};

use super::{OAuthError, OAuthErrorCode, OAuthErrorResponse};

/// The HTTP request a DPoP proof is for: its method, its target URI, and the access token it
/// presents, if any (RFC 9449 §4.2: `htm`, `htu`, `ath`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DPoPTarget<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub access_token: Option<&'a str>,
}

/// A DPoP proof (RFC 9449 §4): a JWT signed with the key it carries in its header, for one
/// HTTP request.
#[derive(Clone, Debug)]
pub struct DPoPProof {
    pub header: JOSEHeader,
    pub claims: JWTClaims,
    /// The public key of the `jwk` header.
    pub key: JWK,
    /// The base64url JWK SHA-256 thumbprint of the key (RFC 7638; `jkt`, RFC 9449 §6.1).
    pub thumbprint: String,
}

impl DPoPProof {
    /// The `typ` of a proof (§4.2).
    pub const TYPE: &'static str = "dpop+jwt";
    /// The random octets of the `jti` of a proof (§4.2: at least 96 bits).
    pub const IDENTIFIER_OCTETS: usize = 16;

    /// A proof for the request `target` (the query and fragment of its URI left out, the hash of
    /// its access token as `ath`, §4.2), signed with the private `key` by `algorithm`, at `now`,
    /// with the server's `nonce` (§8) when it asked for one.
    pub fn create<R: Random>(
        key: &JWK,
        algorithm: JWSAlgorithm,
        target: &DPoPTarget<'_>,
        now: i64,
        nonce: Option<&str>,
        random: &mut R,
    ) -> Result<String, OAuthError> {
        let public = key.to_public()?;
        let mut header = JOSEHeader::new();
        header.set_string("typ", DPoPProof::TYPE);
        header.set_string("alg", algorithm.name());
        header.set("jwk", JSONValue::Object(public.to_object()));
        let mut identifier = [0u8; DPoPProof::IDENTIFIER_OCTETS];
        random.fill(&mut identifier)?;
        let mut claims = JWTClaims::new();
        claims.set_string("jti", &Base64URL::encode(&identifier));
        claims.set_string("htm", target.method);
        claims.set_string("htu", &DPoPProof::target(target.uri)?);
        claims.set_numeric_date("iat", now);
        if let Some(token) = target.access_token {
            claims.set_string("ath", &DPoPProof::access_token_hash(token));
        }
        if let Some(nonce) = nonce {
            claims.set_string("nonce", nonce);
        }
        Ok(JWT::sign(&claims, &header, key, random)?)
    }

    /// The `ath` of `access_token`: the base64url SHA-256 of its ASCII (§4.2).
    pub fn access_token_hash(access_token: &str) -> String {
        Base64URL::encode(SHA256::digest(access_token.as_bytes()).as_ref())
    }

    /// The base64url JWK SHA-256 thumbprint of `key` (RFC 7638, §6.1).
    pub fn thumbprint(key: &JWK) -> Result<String, OAuthError> {
        Ok(Base64URL::encode(&key.thumbprint(HashAlgorithm::SHA256)?))
    }

    /// `uri` as an `htu` is compared (§4.3): without its query and fragment, normalized by its
    /// syntax (RFC 3986 §6.2.2) and, for `http` and `https`, by its scheme (§6.2.3: the default
    /// port dropped, an empty path written as `/`).
    pub fn target(uri: &str) -> Result<String, OAuthError> {
        let mut reference = URIReference::parse(uri)?;
        if reference.scheme.is_none() {
            return Err(OAuthError::Invalid { parameter: "htu" });
        }
        reference.query = None;
        reference.fragment = None;
        let mut reference = reference.normalize();
        let default_port = match reference.scheme.as_deref() {
            Some("http") => Some("80"),
            Some("https") => Some("443"),
            _ => None,
        };
        if let Some(default_port) = default_port {
            if let Some(authority) = &mut reference.authority
                && authority.port.as_deref() == Some(default_port)
            {
                authority.port = None;
            }
            if reference.authority.is_some() && reference.path.is_empty() {
                reference.path = "/".to_string();
            }
        }
        Ok(reference.to_string())
    }

    /// The proof `text` with the checks that need no state (§4.3, steps 2 to 9 and 11 but the
    /// nonce and the replay check): one compact JWS of type `dpop+jwt`, signed by one of
    /// `algorithms` (never a MAC or `none`) with the public key of its `jwk` header; `htm` and
    /// `htu` those of `target`; `iat` not older than `maximum_age` seconds nor more than
    /// `leeway` seconds ahead of `now`; and `ath` the hash of the access token of `target`,
    /// exactly when it presents one.
    pub fn verify(
        text: &str,
        algorithms: &[JWSAlgorithm],
        target: &DPoPTarget<'_>,
        now: i64,
        maximum_age: i64,
        leeway: i64,
    ) -> Result<DPoPProof, OAuthError> {
        let invalid = OAuthError::Invalid { parameter: "DPoP" };
        let jws = JWS::from_compact(text).map_err(|_| invalid.clone())?;
        let [signature] = jws.signatures.as_slice() else {
            return Err(invalid);
        };
        let header = signature.protected_header.clone();
        let algorithm = header.jws_algorithm().map_err(|_| invalid.clone())?;
        let asymmetric =
            !matches!(algorithm, JWSAlgorithm::HS256 | JWSAlgorithm::HS384 | JWSAlgorithm::HS512 | JWSAlgorithm::None);
        if !asymmetric || !algorithms.contains(&algorithm) {
            return Err(invalid);
        }
        let key = match header.get("jwk") {
            Some(JSONValue::Object(object)) => JWK::from_object(object).map_err(|_| invalid.clone())?,
            _ => return Err(invalid),
        };
        if key.key.is_secret() {
            return Err(invalid);
        }
        let mut validation = JWTValidation::new(now);
        validation.token_type = Some(DPoPProof::TYPE.to_string());
        validation.required = ["jti", "htm", "htu", "iat"].iter().map(|name| name.to_string()).collect();
        let jwt = JWT::verify(text, &key, &JWSConfig::new(&[algorithm]), &validation).map_err(|_| invalid.clone())?;
        let claims = jwt.claims;
        let string = |name| claims.string(name).ok().flatten();
        if string("htm") != Some(target.method) {
            return Err(invalid);
        }
        let htu = string("htu").ok_or(invalid.clone())?;
        if DPoPProof::target(htu).ok() != Some(DPoPProof::target(target.uri)?) {
            return Err(invalid);
        }
        let issued = claims.issued_at().ok().flatten().ok_or(invalid.clone())?;
        if issued < (now - maximum_age) as f64 || issued > (now + leeway) as f64 {
            return Err(invalid);
        }
        match (target.access_token, string("ath")) {
            (Some(token), Some(hash)) if hash == DPoPProof::access_token_hash(token) => {}
            (None, None) => {}
            _ => return Err(invalid),
        }
        let thumbprint = DPoPProof::thumbprint(&key)?;
        Ok(DPoPProof { header: jwt.header, claims, key, thumbprint })
    }

    /// The `jti` of the proof.
    pub fn identifier(&self) -> Option<&str> {
        self.claims.string("jti").ok().flatten()
    }

    /// The `nonce` of the proof.
    pub fn nonce(&self) -> Option<&str> {
        self.claims.string("nonce").ok().flatten()
    }
}

/// The configuration of a [`DPoPVerifier`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DPoPConfig {
    /// The signature algorithms taken (`dpop_signing_alg_values_supported`, §5.1).
    pub algorithms: Vec<JWSAlgorithm>,
    /// The oldest `iat` taken, in seconds before now.
    pub maximum_age: i64,
    /// The seconds an `iat` may be ahead of now (clock skew).
    pub leeway: i64,
    /// Whether every proof must carry the current nonce (§8, §9).
    pub require_nonce: bool,
    /// The most proof identifiers kept for the replay check; a proof is refused when it is full.
    pub maximum_proofs: usize,
    /// How many nonces made before the current one are still taken, so that a rotation does not
    /// refuse the requests in flight (§8.1 leaves how long a nonce stays valid to the server).
    pub previous_nonces: usize,
}

impl Default for DPoPConfig {
    fn default() -> DPoPConfig {
        DPoPConfig {
            algorithms: alloc::vec![
                JWSAlgorithm::ES256,
                JWSAlgorithm::ES384,
                JWSAlgorithm::ES512,
                JWSAlgorithm::PS256,
                JWSAlgorithm::PS384,
                JWSAlgorithm::PS512,
                JWSAlgorithm::RS256,
                JWSAlgorithm::Ed25519,
                JWSAlgorithm::EdDSA,
            ],
            maximum_age: 300,
            leeway: 60,
            require_nonce: false,
            maximum_proofs: 65536,
            previous_nonces: 1,
        }
    }
}

/// The checks of DPoP proofs that keep state (RFC 9449 §4.3 steps 10 and 11, §8, §11.1): the
/// identifiers of the proofs seen, so that none is used twice, and the server's nonces.
pub struct DPoPVerifier {
    config: DPoPConfig,
    seen: BTreeMap<String, i64>,
    /// The nonces still taken, the current one last: at most `previous_nonces` before it.
    nonces: Vec<String>,
}

impl DPoPVerifier {
    pub fn new(config: DPoPConfig) -> DPoPVerifier {
        DPoPVerifier { config, seen: BTreeMap::new(), nonces: Vec::new() }
    }

    pub fn config(&self) -> &DPoPConfig {
        &self.config
    }

    /// The nonce to send in `DPoP-Nonce`, if one was made.
    pub fn nonce(&self) -> Option<&str> {
        self.nonces.last().map(String::as_str)
    }

    /// Makes a new nonce; the `previous_nonces` made last before it are still taken.
    pub fn rotate_nonce<R: Random>(&mut self, random: &mut R) -> Result<&str, OAuthError> {
        let mut octets = [0u8; 16];
        random.fill(&mut octets)?;
        self.nonces.push(Base64URL::encode(&octets));
        let kept = self.config.previous_nonces.saturating_add(1);
        let excess = self.nonces.len().saturating_sub(kept);
        self.nonces.drain(..excess);
        Ok(self.nonces.last().map(String::as_str).unwrap_or_default())
    }

    /// Forgets the identifiers of proofs too old to be taken again.
    pub fn expire(&mut self, now: i64) {
        self.seen.retain(|_, until| *until >= now);
    }

    /// The proof `text` of the request `target`, with every check of §4.3; the error is
    /// `invalid_dpop_proof`, or `use_dpop_nonce` when the nonce is missing or old (§8).
    pub fn check(&mut self, text: &str, target: &DPoPTarget<'_>, now: i64) -> Result<DPoPProof, OAuthErrorResponse> {
        let invalid =
            |description: &str| OAuthErrorResponse::with_description(OAuthErrorCode::InvalidDPoPProof, description);
        let config = &self.config;
        let proof = DPoPProof::verify(text, &config.algorithms, target, now, config.maximum_age, config.leeway)
            .map_err(|_| invalid("the DPoP proof is not valid"))?;
        if config.require_nonce && self.nonces.is_empty() {
            // No nonce to ask for: the server must rotate one before it serves (§8).
            return Err(OAuthErrorResponse::with_description(OAuthErrorCode::ServerError, "no DPoP nonce was made"));
        }
        if config.require_nonce {
            let fresh = proof.nonce().is_some_and(|nonce| self.nonces.iter().any(|own| own == nonce));
            if !fresh {
                return Err(OAuthErrorResponse::with_description(
                    OAuthErrorCode::UseDPoPNonce,
                    "a DPoP nonce is required",
                ));
            }
        }
        self.expire(now);
        let identifier = proof.identifier().ok_or_else(|| invalid("the DPoP proof has no jti"))?.to_string();
        if self.seen.contains_key(&identifier) {
            return Err(invalid("the DPoP proof was already used"));
        }
        if self.seen.len() >= self.config.maximum_proofs {
            return Err(invalid("too many DPoP proofs"));
        }
        let issued = proof.claims.issued_at().ok().flatten().unwrap_or_default() as i64;
        self.seen.insert(identifier, issued + self.config.maximum_age + self.config.leeway);
        Ok(proof)
    }
}
