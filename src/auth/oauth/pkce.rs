use alloc::string::String;

use crate::crypto::random::Random;
use crate::hash::Digest;
use crate::hash::sha::v2::SHA256;
use crate::protocol::jwt::Base64URL;
use crate::secret::{ConstantTimeEq, Secret};

use super::OAuthError;

/// A transformation of a code verifier into a code challenge (RFC 7636 §4.2).
///
/// Only `S256` is taken. `plain` sends the verifier itself, which protects nothing against an
/// attacker who reads the authorization request (RFC 9700 §2.1.1: S256 is to be used).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PKCEMethod {
    S256,
}

impl PKCEMethod {
    /// The name of the method, as `code_challenge_method` carries it.
    pub fn as_str(self) -> &'static str {
        match self {
            PKCEMethod::S256 => "S256",
        }
    }

    /// The method named `name`; `plain` and unknown names fail.
    pub fn parse(name: &str) -> Result<PKCEMethod, OAuthError> {
        match name {
            "S256" => Ok(PKCEMethod::S256),
            _ => Err(OAuthError::Invalid { parameter: "code_challenge_method" }),
        }
    }
}

/// A code verifier (RFC 7636 §4.1): 43 to 128 unreserved characters, kept secret by the client
/// until the token request.
#[derive(Clone)]
pub struct PKCEVerifier {
    text: Secret<String>,
}

impl PKCEVerifier {
    /// The shortest verifier (§4.1).
    pub const MINIMUM_LENGTH: usize = 43;
    /// The longest verifier (§4.1).
    pub const MAXIMUM_LENGTH: usize = 128;
    /// The random octets of a generated verifier: 32, which give the 43 characters §4.1
    /// recommends.
    pub const RANDOM_OCTETS: usize = 32;

    /// The verifier `text`, checked against `43*128unreserved`.
    pub fn new(text: &str) -> Result<PKCEVerifier, OAuthError> {
        let valid = (PKCEVerifier::MINIMUM_LENGTH..=PKCEVerifier::MAXIMUM_LENGTH).contains(&text.len())
            && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'));
        if !valid {
            return Err(OAuthError::Invalid { parameter: "code_verifier" });
        }
        Ok(PKCEVerifier { text: Secret::new(String::from(text)) })
    }

    /// A verifier of 32 octets from `random`, base64url-encoded (§4.1).
    pub fn generate<R: Random>(random: &mut R) -> Result<PKCEVerifier, OAuthError> {
        let mut octets = Secret::new([0u8; PKCEVerifier::RANDOM_OCTETS]);
        random.fill(octets.expose_mut())?;
        Ok(PKCEVerifier { text: Secret::new(Base64URL::encode(octets.expose())) })
    }

    /// The verifier, as `code_verifier` carries it.
    pub fn as_str(&self) -> &str {
        self.text.expose()
    }

    /// The challenge of this verifier by `method` (§4.2).
    pub fn challenge(&self, method: PKCEMethod) -> PKCEChallenge {
        match method {
            PKCEMethod::S256 => {
                PKCEChallenge { method, value: Base64URL::encode(SHA256::digest(self.as_str().as_bytes()).as_ref()) }
            }
        }
    }
}

/// A code challenge (RFC 7636 §4.2) and the method that made it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PKCEChallenge {
    pub method: PKCEMethod,
    pub value: String,
}

impl PKCEChallenge {
    /// The challenge `value` of `method`, checked: for S256, the 43 characters of a base64url
    /// SHA-256 digest without padding.
    pub fn new(method: PKCEMethod, value: &str) -> Result<PKCEChallenge, OAuthError> {
        let valid = match method {
            PKCEMethod::S256 => Base64URL::decode(value).is_ok_and(|digest| digest.len() == 32),
        };
        if !valid {
            return Err(OAuthError::Invalid { parameter: "code_challenge" });
        }
        Ok(PKCEChallenge { method, value: String::from(value) })
    }

    /// Whether `verifier` is the verifier of this challenge (§4.6), compared in constant time.
    pub fn verify(&self, verifier: &PKCEVerifier) -> bool {
        let expected = verifier.challenge(self.method);
        expected.value.as_bytes().ct_eq(self.value.as_bytes()).into_bool()
    }
}
