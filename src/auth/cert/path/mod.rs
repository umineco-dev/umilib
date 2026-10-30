//! Certification path building and validation (RFC 5280 §6, RFC 4158):
//! - the algorithm of RFC 5280 §6.1 with the policy graph of RFC 9618, name
//!   constraints of every name form RFC 5280 defines, and CRLs (§6.3,
//!   indirect and delta CRLs included), and other revocation sources such
//!   as OCSP ([`RevocationSource`]);
//! - the profile of RFC 5280 §4 and the rules of the Web PKI, as options
//!   ([`PathProfile`]);
//! - the identity a certificate must name (RFC 9525), its key usage and
//!   extended key usage;
//! - path building that backtracks over candidate issuers within a budget.

mod anchor;
mod config;
mod constraints;
mod error;
mod extensions;
mod identity;
mod names;
mod policy;
mod profile;
mod revocation;
mod validator;

pub use anchor::TrustAnchor;
pub use config::{PathConfig, PathProfile, RevocationConfig};
pub use constraints::NameConstraintsState;
pub use error::{PathError, PathErrorReason};
pub use extensions::PathExtensions;
pub use identity::ServiceIdentity;
pub use names::NameMatching;
pub use policy::{PolicyGraph, PolicyNode};
pub use profile::CertificateRole;
pub use revocation::{RevocationSource, RevocationStatus};
pub use validator::{PathBudget, PathValidator, ValidatedPath};
