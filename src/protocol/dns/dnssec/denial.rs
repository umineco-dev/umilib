use alloc::vec::Vec;
use core::cmp::Ordering;

use super::super::{DNSData, DNSError, DNSExtendedError, DNSNSEC3, DNSName, DNSRecord, DNSType, DNSTypeBitmap};
use super::{DNSSECProof, DNSSECValidator};

/// An NSEC record of a zone (RFC 4034 §4), as a denial reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DNSSECNSEC<'a> {
    pub owner: &'a DNSName,
    pub next: &'a DNSName,
    pub types: &'a DNSTypeBitmap,
}

impl<'a> DNSSECNSEC<'a> {
    /// The NSEC records of `records` owned in `zone`.
    pub fn of(records: &'a [DNSRecord], zone: &DNSName) -> Vec<DNSSECNSEC<'a>> {
        records
            .iter()
            .filter(|record| record.kind == DNSType::NSEC && record.name.is_subdomain_of(zone))
            .filter_map(|record| match &record.data {
                DNSData::NSEC { next, types } => Some(DNSSECNSEC { owner: &record.name, next, types }),
                _ => None,
            })
            .collect()
    }

    /// Whether `name` is between the owner and the next name in canonical
    /// order (RFC 4034 §6.1), the last NSEC of a zone covering the names
    /// after its owner.
    pub fn covers(&self, name: &DNSName) -> bool {
        let after_owner = self.owner.canonical_cmp(name) == Ordering::Less;
        let before_next = name.canonical_cmp(self.next) == Ordering::Less;
        let last = self.next.canonical_cmp(self.owner) != Ordering::Greater;
        after_owner && (before_next || last)
    }

    /// Whether the owner is a zone cut seen from `zone`, its parent: such an
    /// NSEC denies DS and nothing else at or below its owner (RFC 6840 §4.1).
    pub fn is_cut(&self, zone: &DNSName) -> bool {
        self.types.contains(DNSType::NS) && !self.types.contains(DNSType::SOA) && self.owner != zone
    }

    /// Whether it may deny `name`, which it covers: not if `name` is below
    /// a zone cut or a DNAME at its owner (RFC 6840 §4.1, RFC 6672 §5.3.4).
    pub fn may_deny(&self, name: &DNSName, zone: &DNSName) -> bool {
        let below = name != self.owner && name.is_subdomain_of(self.owner);
        !below || (!self.is_cut(zone) && !self.types.contains(DNSType::DNAME))
    }

    /// Whether neither `kind` nor CNAME is at the owner (RFC 4035 §5.4).
    pub fn lacks(&self, kind: DNSType) -> bool {
        !self.types.contains(kind) && !self.types.contains(DNSType::CNAME)
    }

    /// The closest encloser of `name`, which it covers: the longest
    /// ancestor of `name` that is an ancestor of the owner or of the next
    /// name, both of which exist (RFC 4592 §3.3.1).
    pub fn closest_encloser(&self, name: &DNSName) -> DNSName {
        let (owner, next) = (name.common_ancestor(self.owner), name.common_ancestor(self.next));
        if owner.label_count() >= next.label_count() { owner } else { next }
    }
}

/// An NSEC3 record of a zone (RFC 5155 §3), with the hash its owner names.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSSECNSEC3<'a> {
    pub owner: &'a DNSName,
    pub hash: Vec<u8>,
    pub data: &'a DNSNSEC3,
}

impl<'a> DNSSECNSEC3<'a> {
    /// The NSEC3 records of `records` whose owner is a hash label before
    /// `zone`, of SHA-1 (RFC 5155 §8.1) and of flags 0 or 1 (§8.2); others
    /// are ignored.
    pub fn of(records: &'a [DNSRecord], zone: &DNSName) -> Vec<DNSSECNSEC3<'a>> {
        records
            .iter()
            .filter(|record| record.kind == DNSType::NSEC3 && record.name.parent().as_ref() == Some(zone))
            .filter_map(|record| {
                let DNSData::NSEC3(data) = &record.data else { return None };
                let hash = DNSNSEC3::owner_hash(&record.name)?;
                let valid = data.algorithm == DNSNSEC3::SHA1 && data.flags <= 1 && hash.len() == data.next_hashed.len();
                valid.then_some(DNSSECNSEC3 { owner: &record.name, hash, data })
            })
            .collect()
    }

    pub fn matches(&self, hash: &[u8]) -> bool {
        self.hash == hash
    }

    /// Whether `hash` is between the owner's hash and the next one, the
    /// last NSEC3 covering past the end of the hash space (RFC 5155 §3.1.7).
    pub fn covers(&self, hash: &[u8]) -> bool {
        let (owner, next) = (self.hash.as_slice(), self.data.next_hashed.as_slice());
        match next.cmp(owner) {
            Ordering::Greater => owner < hash && hash < next,
            _ => owner < hash || hash < next,
        }
    }

    /// Whether the original owner is a zone cut or a DNAME: such an NSEC3
    /// cannot be of a closest encloser (RFC 5155 §8.3).
    pub fn is_cut(&self) -> bool {
        let types = &self.data.types;
        (types.contains(DNSType::NS) && !types.contains(DNSType::SOA)) || types.contains(DNSType::DNAME)
    }

    /// Whether neither `kind` nor CNAME is at the original owner (RFC 5155 §8.5).
    pub fn lacks(&self, kind: DNSType) -> bool {
        !self.data.types.contains(kind) && !self.data.types.contains(DNSType::CNAME)
    }
}

impl DNSSECValidator {
    /// Proves that `name` does not exist in `zone` (NXDOMAIN) with the NSEC
    /// or NSEC3 records of `records`, whose signatures are verified: an NSEC
    /// covering it and one covering the wildcard of its closest encloser
    /// (RFC 4035 §5.4), a closest encloser proof and an NSEC3 covering the
    /// wildcard (RFC 5155 §8.4), or a Compact Denial NSEC or NSEC3 of the
    /// name listing NXNAME (RFC 9824 §3). A proof whose next closer name is
    /// in an Opt-Out span is insecure: an unsigned delegation may be there.
    pub fn prove_nonexistence(
        &self,
        name: &DNSName,
        zone: &DNSName,
        records: &[DNSRecord],
    ) -> Result<DNSSECProof, DNSError> {
        DNSSECValidator::check_zone(name, zone)?;
        let nsec = DNSSECNSEC::of(records, zone);
        if !nsec.is_empty() {
            if let Some(matching) = nsec.iter().find(|record| record.owner == name) {
                return match matching.types.contains(DNSType::NXNAME) {
                    true => Ok(DNSSECProof::Secure),
                    false => Err(DNSSECValidator::bogus("an NSEC of the name said not to exist")),
                };
            }
            let cover = DNSSECValidator::cover(&nsec, name, zone)?;
            if cover.next.is_subdomain_of(name) {
                return Err(DNSSECValidator::bogus("an NSEC of names below the name said not to exist"));
            }
            let wildcard = DNSSECValidator::wildcard(&cover.closest_encloser(name))?;
            DNSSECValidator::cover(&nsec, &wildcard, zone)?;
            return Ok(DNSSECProof::Secure);
        }
        let chain = self.nsec3_chain(records, zone)?;
        if let Some(stop) = self.check_iterations(&chain)? {
            return Ok(stop);
        }
        let hash = DNSSECValidator::nsec3_hash(&chain, name);
        if chain.iter().any(|record| record.matches(&hash) && record.data.types.contains(DNSType::NXNAME)) {
            return Ok(DNSSECProof::Secure);
        }
        let (encloser, opt_out) = DNSSECValidator::closest_encloser(&chain, name, zone)?;
        let wildcard = DNSSECValidator::nsec3_hash(&chain, &DNSSECValidator::wildcard(&encloser)?);
        if !chain.iter().any(|record| record.covers(&wildcard)) {
            return Err(DNSSECValidator::missing("no NSEC3 covering the wildcard"));
        }
        Ok(DNSSECValidator::opt_out(opt_out))
    }

    /// Proves that `name` in `zone` has no records of `kind` (NODATA): an
    /// NSEC or NSEC3 of the name without the type and CNAME, of an empty
    /// non-terminal, or of a wildcard that would have answered (RFC 4035
    /// §5.4, RFC 5155 §8.5–8.7), or an NSEC3 Opt-Out span over an empty
    /// non-terminal of unsigned delegations (insecure, RFC 5155 Erratum
    /// 3441). A DS is denied by the parent zone only:
    /// an NSEC at a zone cut denies DS and nothing else, and an NSEC3 Opt-Out
    /// span over the name makes the denial of DS insecure (§8.6).
    pub fn prove_nodata(
        &self,
        name: &DNSName,
        kind: DNSType,
        zone: &DNSName,
        records: &[DNSRecord],
    ) -> Result<DNSSECProof, DNSError> {
        DNSSECValidator::check_zone(name, zone)?;
        let ds = kind == DNSType::DS;
        if ds && name == zone && !zone.is_root() {
            return Err(DNSSECValidator::bogus("a DS denied by the zone below its cut"));
        }
        let nsec = DNSSECNSEC::of(records, zone);
        if !nsec.is_empty() {
            if let Some(matching) = nsec.iter().find(|record| record.owner == name) {
                if (ds && matching.types.contains(DNSType::SOA) && !name.is_root()) || (!ds && matching.is_cut(zone)) {
                    return Err(DNSSECValidator::bogus("an NSEC of the other side of a zone cut"));
                }
                return match matching.lacks(kind) {
                    true => Ok(DNSSECProof::Secure),
                    false => Err(DNSSECValidator::bogus("an NSEC that lists the type")),
                };
            }
            let cover = DNSSECValidator::cover(&nsec, name, zone)?;
            if cover.next.is_subdomain_of(name) {
                return Ok(DNSSECProof::Secure);
            }
            let wildcard = DNSSECValidator::wildcard(&cover.closest_encloser(name))?;
            return match nsec.iter().find(|record| *record.owner == wildcard) {
                Some(matching) if matching.lacks(kind) => Ok(DNSSECProof::Secure),
                Some(_) => Err(DNSSECValidator::bogus("a wildcard NSEC that lists the type")),
                None => Err(DNSSECValidator::missing("no NSEC of the name or its wildcard")),
            };
        }
        let chain = self.nsec3_chain(records, zone)?;
        if let Some(stop) = self.check_iterations(&chain)? {
            return Ok(stop);
        }
        let hash = DNSSECValidator::nsec3_hash(&chain, name);
        if let Some(matching) = chain.iter().find(|record| record.matches(&hash)) {
            let cut = matching.data.types.contains(DNSType::NS) && !matching.data.types.contains(DNSType::SOA);
            if (ds && matching.data.types.contains(DNSType::SOA)) || (!ds && cut) {
                return Err(DNSSECValidator::bogus("an NSEC3 of the other side of a zone cut"));
            }
            return match matching.lacks(kind) {
                true => Ok(DNSSECProof::Secure),
                false => Err(DNSSECValidator::bogus("an NSEC3 that lists the type")),
            };
        }
        let (encloser, opt_out) = DNSSECValidator::closest_encloser(&chain, name, zone)?;
        if ds {
            return match opt_out {
                true => Ok(DNSSECProof::Insecure(None)),
                false => Err(DNSSECValidator::missing("no NSEC3 of the name, nor an Opt-Out span over it")),
            };
        }
        let wildcard = DNSSECValidator::nsec3_hash(&chain, &DNSSECValidator::wildcard(&encloser)?);
        match chain.iter().find(|record| record.matches(&wildcard)) {
            Some(matching) if matching.lacks(kind) => Ok(DNSSECValidator::opt_out(opt_out)),
            Some(_) => Err(DNSSECValidator::bogus("a wildcard NSEC3 that lists the type")),
            // RFC 5155 Erratum 3441: an empty non-terminal of an unsigned
            // delegation in an Opt-Out span has no NSEC3.
            None if opt_out => Ok(DNSSECProof::Insecure(None)),
            None => Err(DNSSECValidator::missing("no NSEC3 of the name or its wildcard")),
        }
    }

    /// Proves that `name`, answered by records expanded from the wildcard
    /// below `closest_encloser` (as [`super::DNSSECVerified`] tells), does
    /// not exist itself, so that the wildcard was the one to answer: an
    /// NSEC covering it whose closest encloser is that one (RFC 4035
    /// §5.3.4), or an NSEC3 covering the next closer name (RFC 5155 §8.8).
    pub fn prove_expansion(
        &self,
        name: &DNSName,
        closest_encloser: &DNSName,
        zone: &DNSName,
        records: &[DNSRecord],
    ) -> Result<DNSSECProof, DNSError> {
        DNSSECValidator::check_zone(name, zone)?;
        if !closest_encloser.is_subdomain_of(zone)
            || !name.is_subdomain_of(closest_encloser)
            || name.label_count() <= closest_encloser.label_count()
        {
            return Err(DNSSECValidator::bogus("a closest encloser that is not an ancestor of the name"));
        }
        let nsec = DNSSECNSEC::of(records, zone);
        if !nsec.is_empty() {
            let cover = DNSSECValidator::cover(&nsec, name, zone)?;
            return match cover.closest_encloser(name) == *closest_encloser {
                true => Ok(DNSSECProof::Secure),
                false => Err(DNSSECValidator::bogus("a wildcard other than the closest encloser's")),
            };
        }
        let chain = self.nsec3_chain(records, zone)?;
        if let Some(stop) = self.check_iterations(&chain)? {
            return Ok(stop);
        }
        let next_closer = DNSSECValidator::nsec3_hash(&chain, &name.suffix(closest_encloser.label_count() + 1));
        match chain.iter().find(|record| record.covers(&next_closer)) {
            Some(cover) => Ok(DNSSECValidator::opt_out(cover.data.is_opt_out())),
            None => Err(DNSSECValidator::missing("no NSEC3 covering the next closer name")),
        }
    }

    /// Proves that the delegation of `name` from `zone` has no DS, so that
    /// the zone below is unsigned: an NSEC or NSEC3 of the name with NS and
    /// without DS and SOA (RFC 4035 §5.2, RFC 5155 §8.9), or an NSEC3
    /// Opt-Out span over it (insecure).
    pub fn prove_unsigned_delegation(
        &self,
        name: &DNSName,
        zone: &DNSName,
        records: &[DNSRecord],
    ) -> Result<DNSSECProof, DNSError> {
        DNSSECValidator::check_zone(name, zone)?;
        if name == zone {
            return Err(DNSSECValidator::bogus("a delegation of the zone's apex"));
        }
        let delegates = |types: &DNSTypeBitmap| {
            types.contains(DNSType::NS) && !types.contains(DNSType::DS) && !types.contains(DNSType::SOA)
        };
        let nsec = DNSSECNSEC::of(records, zone);
        if !nsec.is_empty() {
            return match nsec.iter().find(|record| record.owner == name) {
                Some(matching) if delegates(matching.types) => Ok(DNSSECProof::Secure),
                Some(_) => Err(DNSSECValidator::bogus("an NSEC that is not of an unsigned delegation")),
                None => Err(DNSSECValidator::missing("no NSEC of the delegation")),
            };
        }
        let chain = self.nsec3_chain(records, zone)?;
        if let Some(stop) = self.check_iterations(&chain)? {
            return Ok(stop);
        }
        let hash = DNSSECValidator::nsec3_hash(&chain, name);
        if let Some(matching) = chain.iter().find(|record| record.matches(&hash)) {
            return match delegates(&matching.data.types) {
                true => Ok(DNSSECProof::Secure),
                false => Err(DNSSECValidator::bogus("an NSEC3 that is not of an unsigned delegation")),
            };
        }
        match DNSSECValidator::closest_encloser(&chain, name, zone)? {
            (_, true) => Ok(DNSSECProof::Insecure(None)),
            (_, false) => Err(DNSSECValidator::missing("no NSEC3 of the delegation, nor an Opt-Out span over it")),
        }
    }

    /// The NSEC3 records of `zone` in `records`; a denial needs one, and
    /// all of one hash, iterations and salt (RFC 5155 §8.2 allows calling
    /// a mix bogus).
    pub fn nsec3_chain<'a>(&self, records: &'a [DNSRecord], zone: &DNSName) -> Result<Vec<DNSSECNSEC3<'a>>, DNSError> {
        let chain = DNSSECNSEC3::of(records, zone);
        let first = chain.first().ok_or(DNSSECValidator::missing("no NSEC or NSEC3 of the zone"))?;
        let same = |record: &DNSSECNSEC3<'_>| {
            record.data.iterations == first.data.iterations && record.data.salt == first.data.salt
        };
        match chain.iter().all(same) {
            true => Ok(chain),
            false => Err(DNSSECValidator::bogus("NSEC3 records of different parameters")),
        }
    }

    /// A denial of NSEC3 records of more iterations than the configured
    /// limits: bogus or insecure (RFC 9276 §3.2), so that no hash is computed.
    pub fn check_iterations(&self, chain: &[DNSSECNSEC3<'_>]) -> Result<Option<DNSSECProof>, DNSError> {
        let iterations = chain.first().map_or(0, |record| record.data.iterations);
        if iterations > self.config.bogus_nsec3_iterations {
            return Err(DNSError::Bogus {
                code: DNSExtendedError::UNSUPPORTED_NSEC3_ITERATIONS,
                reason: "NSEC3 records of too many iterations",
            });
        }
        if iterations > self.config.insecure_nsec3_iterations {
            return Ok(Some(DNSSECProof::Insecure(Some(DNSExtendedError::UNSUPPORTED_NSEC3_ITERATIONS))));
        }
        Ok(None)
    }

    /// The hash of `name` with the parameters of `chain`, which [`DNSSECValidator::nsec3_chain`] made one.
    pub fn nsec3_hash(chain: &[DNSSECNSEC3<'_>], name: &DNSName) -> Vec<u8> {
        chain.first().and_then(|record| record.data.hash(name)).unwrap_or_default()
    }

    /// The closest encloser proof of `name` (RFC 5155 §8.3): the longest
    /// ancestor whose hash an NSEC3 matches, the name one label longer
    /// (the next closer name) covered by another; and whether that one is Opt-Out.
    pub fn closest_encloser(
        chain: &[DNSSECNSEC3<'_>],
        name: &DNSName,
        zone: &DNSName,
    ) -> Result<(DNSName, bool), DNSError> {
        let mut covered: Option<bool> = None;
        for count in (zone.label_count()..=name.label_count()).rev() {
            let ancestor = name.suffix(count);
            let hash = DNSSECValidator::nsec3_hash(chain, &ancestor);
            if let Some(matching) = chain.iter().find(|record| record.matches(&hash)) {
                let opt_out = covered.ok_or(DNSSECValidator::bogus("an NSEC3 of a name said not to exist"))?;
                if matching.is_cut() {
                    return Err(DNSSECValidator::bogus("a closest encloser at a zone cut or DNAME"));
                }
                return Ok((ancestor, opt_out));
            }
            covered = chain.iter().find(|record| record.covers(&hash)).map(|record| record.data.is_opt_out());
        }
        Err(DNSSECValidator::missing("no closest encloser proof"))
    }

    /// The NSEC of `nsec` that may deny `name`.
    pub fn cover<'a, 'b>(
        nsec: &'b [DNSSECNSEC<'a>],
        name: &DNSName,
        zone: &DNSName,
    ) -> Result<&'b DNSSECNSEC<'a>, DNSError> {
        nsec.iter()
            .find(|record| record.covers(name) && record.may_deny(name, zone))
            .ok_or(DNSSECValidator::missing("no NSEC covering the name"))
    }

    /// The wildcard below `encloser` (RFC 4592 §2.1.1).
    pub fn wildcard(encloser: &DNSName) -> Result<DNSName, DNSError> {
        encloser.prepend(b"*").map_err(|_| DNSSECValidator::bogus("a closest encloser without room for its wildcard"))
    }

    pub fn check_zone(name: &DNSName, zone: &DNSName) -> Result<(), DNSError> {
        match name.is_subdomain_of(zone) {
            true => Ok(()),
            false => Err(DNSSECValidator::bogus("a denial by a zone above which the name is not")),
        }
    }

    pub fn opt_out(opt_out: bool) -> DNSSECProof {
        if opt_out { DNSSECProof::Insecure(None) } else { DNSSECProof::Secure }
    }

    pub fn bogus(reason: &'static str) -> DNSError {
        DNSError::Bogus { code: DNSExtendedError::DNSSEC_BOGUS, reason }
    }

    pub fn missing(reason: &'static str) -> DNSError {
        DNSError::Bogus { code: DNSExtendedError::NSEC_MISSING, reason }
    }
}
