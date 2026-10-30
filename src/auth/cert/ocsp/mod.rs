//! The Online Certificate Status Protocol (RFC 6960): requests, responses,
//! and the checks a client makes of a response (RFC 6960 §3.2, §4.2.2.2),
//! with the nonce of RFC 8954. With `auth-cert-path`, responses are
//! revocation sources of path validation.

pub mod cert_id;
pub mod config;
pub mod error;
pub mod request;
pub mod response;
#[cfg(umilib_feature = "auth-cert-path")]
pub mod revocation;

pub use cert_id::CertID;
pub use config::OCSPConfig;
pub use error::OCSPError;
pub use request::{BasicOCSPCertificates, OCSPNonce, OCSPRequest, OCSPSignature, Request, TBSRequest};
pub use response::{
    BasicOCSPResponse, CertStatus, OCSPResponse, OCSPResponseStatus, ResponderID, ResponseData, SingleResponse,
};
