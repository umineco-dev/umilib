//! DNS: `dnssec` — the DNS Security Extensions (RFC 4033, 4034, 4035):
//! keys and their algorithms (RFC 9904), signing and verifying RRsets,
//! checking keys against DS records and trust anchors (RFC 9718), and the
//! denials of existence of NSEC, NSEC3 (RFC 5155) and Compact Denial (RFC 9824).

mod algorithm;
mod anchor;
mod denial;
mod key;
mod resolver;
mod signature;
mod signer;
mod validator;
mod zone;

pub use algorithm::{DNSSECAlgorithm, DNSSECDigest};
pub use anchor::{DNSSECKeyDigest, DNSSECTrustAnchor};
pub use denial::{DNSSECNSEC, DNSSECNSEC3};
pub use key::{DNSSECKey, DNSSECPrivateKey, DNSSECPublicKey};
pub use resolver::{DNSSECResolver, DNSSECResolverEvent, DNSSECStatus, DNSSECStep, DNSSECValidation, DNSSECZoneTrust};
pub use signer::DNSSECSigner;
pub use validator::{DNSSECConfig, DNSSECProof, DNSSECTrust, DNSSECValidator, DNSSECVerified};
