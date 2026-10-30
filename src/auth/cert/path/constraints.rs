use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::{NameMatching, PathErrorReason};
use crate::auth::cert::x509::{
    Certificate, GeneralName, GeneralSubtree, NameAttribute, NameConstraints, SubjectAlternativeName, X509Error,
};

/// The name constraints in force along a path (RFC 5280 §6.1.2 (b), (c),
/// §6.1.4 (g)): every set of constraints met so far. A name must be within
/// the permitted subtrees of each set that has subtrees of its form (their
/// intersection) and within no excluded subtree (their union).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameConstraintsState {
    pub sets: Vec<NameConstraints<'static>>,
}

impl NameConstraintsState {
    pub const fn new() -> NameConstraintsState {
        NameConstraintsState { sets: Vec::new() }
    }

    pub fn push(&mut self, constraints: NameConstraints<'static>) {
        self.sets.push(constraints);
    }

    /// The names of `certificate` that name constraints apply to (RFC 5280
    /// §4.2.1.10): its subject if not empty, its subject alternative names,
    /// and, without subject alternative names, the emailAddress attributes
    /// of its subject as rfc822Name.
    pub fn names<'c>(certificate: &'c Certificate<'_>) -> Result<Vec<GeneralName<'c>>, X509Error> {
        let tbs = certificate.tbs_certificate();
        let mut names = Vec::new();
        if !tbs.subject.is_empty() {
            names.push(GeneralName::DirectoryName(tbs.subject.clone()));
        }
        match tbs.extensions.typed::<SubjectAlternativeName<'_>>()? {
            Some(alternative) => names.extend(alternative.names),
            None => {
                for attribute in tbs.subject.attributes() {
                    if attribute.attribute() == Some(NameAttribute::EmailAddress) {
                        let text = attribute.text().map_err(|_| X509Error::InvalidName)?.into_owned();
                        names.push(GeneralName::RFC822Name(Cow::Owned(text)));
                    }
                }
            }
        }
        Ok(names)
    }

    /// Whether `subtree` constrains names of the form of `name`: the same
    /// form, and for addresses the same family (a malformed address
    /// constraint applies to every address, so that it is refused).
    pub fn applies(subtree: &GeneralSubtree<'_>, name: &GeneralName<'_>) -> bool {
        match (&subtree.base, name) {
            (GeneralName::IPAddress(base), GeneralName::IPAddress(address)) => {
                base.len() == 2 * address.len() || (base.len() != 8 && base.len() != 32)
            }
            (base, name) => base.tag_number() == name.tag_number(),
        }
    }

    /// Whether `name` is within `subtree`, which [`NameConstraintsState::applies`]
    /// to it; with `wildcard`, whether some name a wildcard DNS name stands
    /// for is (for excluded subtrees). Fails for a subtree or a name the
    /// comparison cannot be made with: a form this module does not compare
    /// (otherName, x400Address, ediPartyName, registeredID), a minimum or a
    /// maximum other than the profile's, a malformed constraint or a
    /// malformed name (RFC 5280 §4.2.1.10 requires processing or rejection).
    pub fn within(
        subtree: &GeneralSubtree<'_>,
        name: &GeneralName<'_>,
        wildcard: bool,
    ) -> Result<bool, PathErrorReason> {
        let refused = Err(PathErrorReason::NameConstraints);
        if subtree.minimum != 0 || subtree.maximum.is_some() {
            return refused;
        }
        match (&subtree.base, name) {
            (GeneralName::DirectoryName(base), GeneralName::DirectoryName(name)) => Ok(name.is_within(base)),
            (GeneralName::DNSName(base), GeneralName::DNSName(name)) => {
                if !NameMatching::is_dns_constraint(base) || !NameMatching::is_dns_name(name, true) {
                    return refused;
                }
                Ok(if wildcard { NameMatching::dns_meets(name, base) } else { NameMatching::dns_within(name, base) })
            }
            (GeneralName::RFC822Name(base), GeneralName::RFC822Name(name)) => {
                if !NameMatching::is_email_constraint(base) {
                    return refused;
                }
                NameMatching::email_within(name, base).ok_or(PathErrorReason::NameConstraints)
            }
            (GeneralName::URI(base), GeneralName::URI(name)) => {
                if !NameMatching::is_uri_constraint(base) {
                    return refused;
                }
                NameMatching::uri_within(name, base).ok_or(PathErrorReason::NameConstraints)
            }
            (GeneralName::IPAddress(base), GeneralName::IPAddress(address)) => {
                NameMatching::ip_within(address, base).ok_or(PathErrorReason::NameConstraints)
            }
            _ => refused,
        }
    }

    /// Checks `name` against one set of constraints.
    pub fn check_name(constraints: &NameConstraints<'_>, name: &GeneralName<'_>) -> Result<(), PathErrorReason> {
        for subtree in
            constraints.excluded_subtrees.iter().filter(|subtree| NameConstraintsState::applies(subtree, name))
        {
            if NameConstraintsState::within(subtree, name, true)? {
                return Err(PathErrorReason::NameConstraints);
            }
        }
        let mut permitted = constraints
            .permitted_subtrees
            .iter()
            .filter(|subtree| NameConstraintsState::applies(subtree, name))
            .peekable();
        if permitted.peek().is_none() {
            return Ok(());
        }
        for subtree in permitted {
            if NameConstraintsState::within(subtree, name, false)? {
                return Ok(());
            }
        }
        Err(PathErrorReason::NameConstraints)
    }

    /// Checks the names of `certificate` against every set (RFC 5280 §6.1.3
    /// (b), (c)), spending one of `budget` for each comparison of a name with
    /// a subtree; fails with `Work` when none is left.
    pub fn check(&self, certificate: &Certificate<'_>, budget: &mut usize) -> Result<(), PathErrorReason> {
        if self.sets.is_empty() {
            return Ok(());
        }
        let names = NameConstraintsState::names(certificate).map_err(PathErrorReason::Certificate)?;
        for constraints in &self.sets {
            let comparisons =
                names.len().saturating_mul(constraints.permitted_subtrees.len() + constraints.excluded_subtrees.len());
            *budget = budget.checked_sub(comparisons).ok_or(PathErrorReason::Work)?;
            names.iter().try_for_each(|name| NameConstraintsState::check_name(constraints, name))?;
        }
        Ok(())
    }
}
