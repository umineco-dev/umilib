//! Certification requests (PKCS #10, RFC 2986): reading, writing, signing
//! and verifying them, with the extensions they request (PKCS #9
//! `extensionRequest`, RFC 2985 §5.4.2).

mod request;

pub use request::{CertificationRequest, CertificationRequestInfo};
