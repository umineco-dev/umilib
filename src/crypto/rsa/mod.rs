//! RSA (RFC 8017, FIPS 186-5): keys, the primitives and the schemes.
//!
//! [`RSAPublicKey`] and [`RSAPrivateKey`] hold the keys of RFC 8017 section
//! 3 with integers of the size of the key (see
//! [`BoxedUint`](crate::math::bigint::BoxedUint)). The private operation uses
//! the Chinese remainder theorem when the primes are known, multiplicative
//! blinding with bytes of a [`Random`](crate::crypto::random::Random) source,
//! and a check of its result against the public operation (against faults).
//!
//! The schemes are generic over the hash function `H` (and the hash `G` of
//! MGF1, `H` by default): [`RSAPKCS1v15`] (RSASSA-PKCS1-v1_5, section 8.2),
//! [`RSAPSS`] (RSASSA-PSS, section 8.1) and [`RSAOAEP`] (RSAES-OAEP, section
//! 7.1). RSAES-PKCS1-v1_5 encryption is not provided: its decryption cannot
//! be made safe against padding oracles (RFC 8017 section 7.2, RFC 8996).
//!
//! The PKCS #1 DER encodings of the keys (`RSAPublicKey` and
//! `RSAPrivateKey` of appendix A.1) are available with `codec-asn1-der`.

mod mgf1;
mod oaep;
mod pkcs1v15;
mod private_key;
mod pss;
mod public_key;

pub use mgf1::MGF1;
pub use oaep::RSAOAEP;
pub use pkcs1v15::{PKCS1Digest, RSAPKCS1v15};
pub use private_key::{RSAPrimes, RSAPrivateKey};
pub use pss::RSAPSS;
pub use public_key::RSAPublicKey;
