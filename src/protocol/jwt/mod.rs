//! JSON Object Signing and Encryption and JSON Web Tokens:
//! - JWK and JWK Sets (RFC 7517), with the key types of RFC 7518, RFC 8037
//!   and RFC 9964, thumbprints (RFC 7638) and thumbprint URIs (RFC 9278);
//! - JWS (RFC 7515) with the algorithms of RFC 7518, RFC 8812, RFC 9864 and
//!   RFC 9964, and unencoded payloads (RFC 7797);
//! - JWE (RFC 7516) with the algorithms of RFC 7518 and RFC 8037;
//! - JWT (RFC 7519) with the validation of RFC 8725.

mod algorithm;
mod content;
mod encoding;
mod error;
mod header;
mod jwe;
mod jwk;
mod jws;
// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod jwt;
mod key_management;
mod signature;

pub use algorithm::{JWEAlgorithm, JWEEncryption, JWSAlgorithm};
pub use encoding::{Base64URL, Base64URLUInt, JOSEMembers};
pub use error::JWTError;
pub use header::JOSEHeader;
pub use jwe::{JWE, JWEConfig, JWERecipient};
pub use jwk::{JWK, JWKCurve, JWKKey, JWKSet, RSAPrimeParameters, RSAPrivateParameters};
pub use jws::{JWS, JWSConfig, JWSSignature};
pub use jwt::{JWT, JWTClaims, JWTValidation};
pub use key_management::JWEEncryptedKey;
