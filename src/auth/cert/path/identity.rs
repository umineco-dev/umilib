use alloc::string::String;
use alloc::vec::Vec;

use super::NameMatching;
use crate::auth::cert::x509::{Certificate, GeneralName, SubjectAlternativeName, X509Error};

/// The identity a certificate must name (a reference identifier, RFC 9525
/// §6), compared with the subject alternative names only: RFC 9525 §6.3
/// no longer allows the common name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ServiceIdentity {
    /// A DNS domain name in A-labels, matched against dNSName (RFC 9525 §6.3).
    DNS(String),
    /// An address of 4 or 16 octets, matched against iPAddress (RFC 9525 §6.4).
    IPAddress(Vec<u8>),
    /// A mailbox, matched against rfc822Name (RFC 5280 §7.5): the same
    /// local part, the same domain without case.
    Email(String),
}

impl ServiceIdentity {
    /// Whether `certificate` names the identity; fails if its subject
    /// alternative names do not decode.
    pub fn matches(&self, certificate: &Certificate<'_>) -> Result<bool, X509Error> {
        let Some(names) = certificate.tbs_certificate().extensions.typed::<SubjectAlternativeName<'_>>()? else {
            return Ok(false);
        };
        Ok(names.names.iter().any(|name| self.matches_name(name)))
    }

    /// Whether the presented identifier `name` matches the identity.
    pub fn matches_name(&self, name: &GeneralName<'_>) -> bool {
        match (self, name) {
            (ServiceIdentity::DNS(reference), GeneralName::DNSName(presented)) => {
                NameMatching::is_dns_name(reference, false) && NameMatching::dns_matches(presented, reference)
            }
            (ServiceIdentity::IPAddress(reference), GeneralName::IPAddress(presented)) => {
                reference.as_slice() == presented.as_ref()
            }
            (ServiceIdentity::Email(reference), GeneralName::RFC822Name(presented)) => {
                match (NameMatching::mailbox(reference), NameMatching::mailbox(presented)) {
                    (Some((local, domain)), Some((presented_local, presented_domain))) => {
                        local == presented_local && domain.eq_ignore_ascii_case(presented_domain)
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }
}
