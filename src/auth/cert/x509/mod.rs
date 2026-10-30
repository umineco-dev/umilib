//! X.509 certificates and CRLs (RFC 5280):
//! - names (`Name`, RFC 5280 §4.1.2.4, with the string representation of
//!   RFC 4514) and general names (§4.2.1.6);
//! - every extension of RFC 5280 §4.2 and §5.2–§5.3, kept as their
//!   encoding and decoded by type ([`ExtensionValue`]);
//! - certificates (§4.1) and CRLs (§5.1): reading, writing, signing and
//!   verifying their signature.
//!
//! Reading accepts the DER of the syntax of RFC 5280, with the structural
//! requirements (versions, repeated extensions, sizes, empty sequences)
//! checked. Four deviations of the deployed base that change no meaning are
//! accepted: values equal to their `DEFAULT` written out (a v1 version, a
//! FALSE `critical` or `cA`), trailing zero bits of named bit lists,
//! GeneralizedTime before 2050, and an empty list of revoked certificates
//! written out. The requirements RFC 5280 places on what
//! CAs issue are checked by `check`, which signing runs.

mod access;
mod alternative_name;
mod attribute;
mod certificate;
mod constraints;
mod crl;
mod crl_extension;
mod distribution_point;
mod error;
mod extension;
mod general_name;
mod key_identifier;
mod name;
mod policy;
mod serial_number;
mod time;
mod usage;

pub use access::{AccessDescription, AuthorityInformationAccess, SubjectInformationAccess};
pub use alternative_name::{CertificateIssuer, IssuerAlternativeName, SubjectAlternativeName};
pub use attribute::{Attribute, SubjectDirectoryAttributes};
pub use certificate::{Certificate, TBSCertificate, Version};
pub use constraints::{BasicConstraints, GeneralSubtree, InhibitAnyPolicy, NameConstraints, PolicyConstraints};
pub use crl::{CertificateList, RevokedCertificate, TBSCertList};
pub use crl_extension::{CRLNumber, CRLReason, DeltaCRLIndicator, HoldInstructionCode, InvalidityDate};
pub use distribution_point::{
    CRLDistributionPoints, DistributionPoint, DistributionPointName, FreshestCRL, IssuingDistributionPoint, ReasonFlags,
};
pub use error::X509Error;
pub use extension::{Extension, ExtensionValue, Extensions};
pub use general_name::{GeneralName, OtherName};
pub use key_identifier::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
pub use name::{
    AttributeSyntax, AttributeTypeAndValue, ComparableValue, Name, NameAttribute, RelativeDistinguishedName,
};
pub use policy::{
    CertificatePolicies, DisplayText, NoticeReference, PolicyInformation, PolicyMapping, PolicyMappings,
    PolicyQualifierInfo, UserNotice,
};
pub use serial_number::SerialNumber;
pub use time::{Time, Validity};
pub use usage::{ExtendedKeyUsage, KeyUsage, PrivateKeyUsagePeriod};
