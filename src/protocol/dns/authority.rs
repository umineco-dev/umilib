use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::protocol::ip::IPEndpointPattern;

use super::{
    DNSClass, DNSCookie, DNSData, DNSEDNS, DNSError, DNSExtendedError, DNSHeader, DNSKeepalive, DNSMessage, DNSNSEC3,
    DNSName, DNSOpcode, DNSOption, DNSOptionCode, DNSPeer, DNSRecord, DNSResponseCode, DNSTransport, DNSType,
};

/// The data of a zone that a server is authoritative for (RFC 1034 §4.2):
/// its records by owner in canonical order, and its NSEC3 owners by hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DNSZone {
    pub origin: DNSName,
    pub class: DNSClass,
    pub nodes: BTreeMap<DNSName, Vec<DNSRecord>>,
    /// The hash each NSEC3 owner names, in order, and the owner (RFC 5155 §3).
    pub nsec3: Vec<(Vec<u8>, DNSName)>,
}

/// Where the descent from a zone's origin to a name stops (RFC 1034 §4.3.2 step 3b, RFC 6672 §3.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DNSDescent {
    /// The name is in the zone's authoritative data, or below none of what follows.
    Authoritative,
    /// A zone cut at or above the name: the zone delegates it.
    Cut(DNSName),
    /// A DNAME above the name, which redirects it.
    Redirection(DNSName),
}

/// What a zone answers to a question (RFC 1034 §4.3.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSLookup {
    pub rcode: DNSResponseCode,
    /// AA: the answer is of the zone's own data (not a referral, RFC 1035 §4.1.1).
    pub authoritative: bool,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub additionals: Vec<DNSRecord>,
    /// The first records of the additional section that a response must
    /// keep or be truncated: the in-domain glue of a referral (RFC 9471 §2.1).
    pub glue: usize,
}

impl Default for DNSLookup {
    fn default() -> DNSLookup {
        DNSLookup {
            rcode: DNSResponseCode::NOERROR,
            authoritative: true,
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            glue: 0,
        }
    }
}

impl DNSZone {
    /// The zone of `origin` and `records`. Every record is at or below the
    /// origin and of the class of the one SOA, at the origin; a CNAME is
    /// alone at its name but for DNSSEC records (RFC 2181 §10.1, RFC 4035
    /// §2.5), and a name has at most one CNAME or DNAME. Duplicates are
    /// dropped (RFC 2181 §5).
    pub fn new(origin: DNSName, records: Vec<DNSRecord>) -> Result<DNSZone, DNSError> {
        let mut soa: Vec<&DNSRecord> = records.iter().filter(|record| record.kind == DNSType::SOA).collect();
        soa.dedup();
        let [soa] = soa.as_slice() else { return Err(DNSError::Config) };
        if soa.name != origin {
            return Err(DNSError::Config);
        }
        let class = soa.class;
        let mut nodes: BTreeMap<DNSName, Vec<DNSRecord>> = BTreeMap::new();
        for record in records {
            if !record.name.is_subdomain_of(&origin) || record.class != class || !record.kind.is_data() {
                return Err(DNSError::Config);
            }
            let node = nodes.entry(record.name.clone()).or_default();
            if !node.contains(&record) {
                node.push(record);
            }
        }
        for node in nodes.values() {
            let count = |kind: DNSType| node.iter().filter(|record| record.kind == kind).count();
            let dnssec = |kind: DNSType| matches!(kind, DNSType::RRSIG | DNSType::NSEC | DNSType::CNAME);
            if count(DNSType::CNAME) > 1 || count(DNSType::DNAME) > 1 {
                return Err(DNSError::Config);
            }
            if count(DNSType::CNAME) == 1 && node.iter().any(|record| !dnssec(record.kind)) {
                return Err(DNSError::Config);
            }
        }
        let mut nsec3: Vec<(Vec<u8>, DNSName)> = nodes
            .iter()
            .filter(|(name, records)| {
                name.parent().as_ref() == Some(&origin) && records.iter().any(|record| record.kind == DNSType::NSEC3)
            })
            .filter_map(|(name, _)| Some((DNSNSEC3::owner_hash(name)?, name.clone())))
            .collect();
        nsec3.sort();
        Ok(DNSZone { origin, class, nodes, nsec3 })
    }

    pub fn records(&self) -> impl Iterator<Item = &DNSRecord> {
        self.nodes.values().flatten()
    }

    pub fn soa(&self) -> Option<&DNSRecord> {
        self.rrset(&self.origin, DNSType::SOA).next()
    }

    /// The records of `name` of type `kind` (RRSIG records only if `kind` is RRSIG).
    pub fn rrset<'a>(&'a self, name: &DNSName, kind: DNSType) -> impl Iterator<Item = &'a DNSRecord> + 'a {
        self.nodes.get(name).into_iter().flatten().filter(move |record| record.kind == kind)
    }

    /// The RRSIG records of `name` that cover `kind`.
    pub fn signatures<'a>(&'a self, name: &DNSName, kind: DNSType) -> impl Iterator<Item = &'a DNSRecord> + 'a {
        self.rrset(name, DNSType::RRSIG)
            .filter(move |record| matches!(&record.data, DNSData::RRSIG(rrsig) if rrsig.type_covered == kind))
    }

    pub fn has(&self, name: &DNSName, kind: DNSType) -> bool {
        self.rrset(name, kind).next().is_some()
    }

    /// Whether `name` exists: it has records other than an NSEC3 and its
    /// signature, which are not of the name (RFC 5155 §7.2.8 and Erratum
    /// 4622), or it is an empty non-terminal, with names below it (RFC 4592 §2.2.2).
    pub fn exists(&self, name: &DNSName) -> bool {
        let own = |records: &Vec<DNSRecord>| {
            records.iter().any(|record| match &record.data {
                DNSData::NSEC3(_) => false,
                DNSData::RRSIG(rrsig) => rrsig.type_covered != DNSType::NSEC3,
                _ => true,
            })
        };
        if self.nodes.get(name).is_some_and(own) {
            return true;
        }
        // In canonical order, the names below a name follow it.
        self.nodes
            .range::<DNSName, _>((core::ops::Bound::Excluded(name), core::ops::Bound::Unbounded))
            .take_while(|(below, _)| below.is_subdomain_of(name))
            .any(|(_, records)| own(records))
    }

    /// Whether the zone is signed: its apex has a DNSKEY RRset with signatures.
    pub fn is_signed(&self) -> bool {
        self.has(&self.origin, DNSType::DNSKEY) && self.signatures(&self.origin, DNSType::DNSKEY).next().is_some()
    }

    /// The hash, iterations and salt of the zone's NSEC3 chain: its
    /// NSEC3PARAM of flags 0 (RFC 5155 §4.1.2), if it denies with NSEC3.
    pub fn nsec3_parameters(&self) -> Option<(u8, u16, &[u8])> {
        self.rrset(&self.origin, DNSType::NSEC3PARAM).find_map(|record| match &record.data {
            DNSData::NSEC3PARAM { algorithm, flags: 0, iterations, salt } => {
                Some((*algorithm, *iterations, salt.as_slice()))
            }
            _ => None,
        })
    }

    /// Where the descent from the origin to `name` stops: at the highest
    /// zone cut (NS below the origin) at or above it, but for DS at the
    /// cut itself, which is the parent's (RFC 4035 §3.1.4.1); or at the
    /// highest DNAME above it.
    pub fn descend(&self, name: &DNSName, kind: DNSType) -> DNSDescent {
        let top = self.origin.label_count();
        for count in top..=name.label_count() {
            let ancestor = name.suffix(count);
            if count > top && self.has(&ancestor, DNSType::NS) && !(ancestor == *name && kind == DNSType::DS) {
                return DNSDescent::Cut(ancestor);
            }
            if ancestor != *name && self.has(&ancestor, DNSType::DNAME) {
                return DNSDescent::Redirection(ancestor);
            }
        }
        DNSDescent::Authoritative
    }

    /// The longest ancestor of `name` that exists (RFC 4592 §3.3.1).
    pub fn closest_encloser(&self, name: &DNSName) -> DNSName {
        let mut ancestor = name.clone();
        while ancestor != self.origin && !self.exists(&ancestor) {
            match ancestor.parent() {
                Some(parent) if parent.is_subdomain_of(&self.origin) => ancestor = parent,
                _ => return self.origin.clone(),
            }
        }
        ancestor
    }

    /// What the zone answers to `name` and `kind` (RFC 1034 §4.3.2, RFC
    /// 4592 §3.3 for wildcards, RFC 6672 §3.2 for DNAME), following CNAME
    /// and DNAME in the zone at most `maximum_chain` times; with DNSSEC
    /// records and proofs (RFC 4035 §3.1, RFC 5155 §7.2) if `dnssec` and the
    /// zone is signed. Unless `minimal`, a positive answer adds the apex's NS
    /// and the addresses of what its records name.
    pub fn lookup(
        &self,
        name: &DNSName,
        kind: DNSType,
        dnssec: bool,
        minimal: bool,
        maximum_chain: usize,
    ) -> DNSLookup {
        let dnssec = dnssec && self.is_signed();
        let mut lookup = DNSLookup::default();
        let mut current = name.clone();
        for _ in 0..=maximum_chain {
            match self.descend(&current, kind) {
                DNSDescent::Cut(cut) => {
                    self.refer(&mut lookup, &cut, dnssec);
                    return lookup;
                }
                DNSDescent::Redirection(owner) => {
                    self.push(&mut lookup.answers, &owner, DNSType::DNAME, dnssec);
                    let Some(dname) = self.rrset(&owner, DNSType::DNAME).next() else { return lookup };
                    let DNSData::DNAME(target) = &dname.data else { return lookup };
                    // The labels of the name below the DNAME's owner, before its target.
                    let mut wire = current.wire()[..current.wire().len() - owner.wire().len()].to_vec();
                    wire.extend_from_slice(target.wire());
                    // RFC 6672 §2.2: a name too long to substitute is YXDOMAIN.
                    let Ok(substituted) = DNSName::from_wire(&wire) else {
                        lookup.rcode = DNSResponseCode::YXDOMAIN;
                        return lookup;
                    };
                    lookup.answers.push(DNSRecord {
                        class: dname.class,
                        ..DNSRecord::new(current.clone(), dname.ttl, DNSData::CNAME(substituted.clone()))
                    });
                    if !substituted.is_subdomain_of(&self.origin) {
                        return lookup;
                    }
                    current = substituted;
                    continue;
                }
                DNSDescent::Authoritative => {}
            }
            if self.exists(&current) {
                if kind == DNSType::ANY || self.has(&current, kind) {
                    self.answer(&mut lookup, &current, &current, kind, dnssec, minimal);
                    return lookup;
                }
                if kind != DNSType::CNAME
                    && let Some(target) = self.cname(&current)
                {
                    self.push(&mut lookup.answers, &current, DNSType::CNAME, dnssec);
                    if !target.is_subdomain_of(&self.origin) {
                        return lookup;
                    }
                    current = target;
                    continue;
                }
                self.deny_data(&mut lookup, &current, dnssec);
                return lookup;
            }
            let encloser = self.closest_encloser(&current);
            let wildcard = encloser.prepend(b"*").ok().filter(|wildcard| self.exists(wildcard));
            let Some(wildcard) = wildcard else {
                // RFC 6604 §2.1: after a CNAME, the code is of the last name of the chain.
                lookup.rcode = DNSResponseCode::NXDOMAIN;
                self.negative(&mut lookup);
                if dnssec {
                    self.deny_name(&mut lookup, &current, &encloser);
                }
                return lookup;
            };
            if kind == DNSType::ANY || self.has(&wildcard, kind) {
                self.answer(&mut lookup, &wildcard, &current, kind, dnssec, minimal);
                if dnssec {
                    self.deny_closer(&mut lookup, &current, &encloser);
                }
                return lookup;
            }
            if kind != DNSType::CNAME
                && let Some(target) = self.cname(&wildcard)
            {
                self.push_as(&mut lookup.answers, &wildcard, DNSType::CNAME, &current, dnssec);
                if dnssec {
                    self.deny_closer(&mut lookup, &current, &encloser);
                }
                if !target.is_subdomain_of(&self.origin) {
                    return lookup;
                }
                current = target;
                continue;
            }
            self.negative(&mut lookup);
            if dnssec {
                self.deny_wildcard_data(&mut lookup, &current, &encloser, &wildcard);
            }
            return lookup;
        }
        lookup
    }

    /// The target of the CNAME of `name`.
    pub fn cname(&self, name: &DNSName) -> Option<DNSName> {
        self.rrset(name, DNSType::CNAME).find_map(|record| match &record.data {
            DNSData::CNAME(target) => Some(target.clone()),
            _ => None,
        })
    }

    /// Appends the RRset of `name` and `kind` to `section`, with its
    /// signatures if `dnssec`, leaving out what it already has.
    pub fn push(&self, section: &mut Vec<DNSRecord>, name: &DNSName, kind: DNSType, dnssec: bool) {
        self.push_as(section, name, kind, name, dnssec);
    }

    /// [`DNSZone::push`] with the records owned by `owner` (a wildcard's
    /// records as the name they answer, RFC 4592 §3.3.3; their RRSIG keeps
    /// the wildcard's labels, RFC 4035 §3.1.3.3).
    pub fn push_as(&self, section: &mut Vec<DNSRecord>, name: &DNSName, kind: DNSType, owner: &DNSName, dnssec: bool) {
        let signatures = self.signatures(name, kind).filter(|_| dnssec && kind != DNSType::RRSIG);
        for record in self.rrset(name, kind).chain(signatures) {
            let record = DNSRecord { name: owner.clone(), ..record.clone() };
            if !section.contains(&record) {
                section.push(record);
            }
        }
    }

    /// A positive answer: the RRsets of `kind` (or all, for ANY) of
    /// `source`, owned by `name`, and what else the response carries.
    pub fn answer(
        &self,
        lookup: &mut DNSLookup,
        source: &DNSName,
        name: &DNSName,
        kind: DNSType,
        dnssec: bool,
        minimal: bool,
    ) {
        let mut kinds: Vec<DNSType> = match kind {
            // ANY: every RRset, the signatures with their RRsets.
            DNSType::ANY => self
                .nodes
                .get(source)
                .into_iter()
                .flatten()
                .map(|record| record.kind)
                .filter(|kind| *kind != DNSType::RRSIG)
                .collect(),
            _ => alloc::vec![kind],
        };
        kinds.sort();
        kinds.dedup();
        for kind in kinds {
            self.push_as(&mut lookup.answers, source, kind, name, dnssec);
        }
        if minimal {
            return;
        }
        if !(kind == DNSType::NS && *source == self.origin) {
            self.push(&mut lookup.authorities, &self.origin, DNSType::NS, dnssec);
        }
        let named: Vec<DNSName> = lookup.answers.iter().chain(&lookup.authorities).filter_map(DNSZone::named).collect();
        for target in named {
            self.push_addresses(&mut lookup.additionals, &target, dnssec);
        }
    }

    /// The name a record's data names for additional addresses (RFC 1035 §3.3, RFC 2782, RFC 9460 §4.1).
    pub fn named(record: &DNSRecord) -> Option<DNSName> {
        match &record.data {
            DNSData::NS(target) | DNSData::MX { exchange: target, .. } | DNSData::SRV { target, .. } => {
                Some(target.clone())
            }
            DNSData::SVCB(binding) if !binding.target.is_root() => Some(binding.target.clone()),
            _ => None,
        }
    }

    /// Appends the A and AAAA records of `name` if the zone has them as its own data.
    pub fn push_addresses(&self, section: &mut Vec<DNSRecord>, name: &DNSName, dnssec: bool) {
        if !name.is_subdomain_of(&self.origin) || self.descend(name, DNSType::A) != DNSDescent::Authoritative {
            return;
        }
        for kind in [DNSType::A, DNSType::AAAA] {
            self.push(section, name, kind, dnssec);
        }
    }

    /// A referral to the zone below `cut` (RFC 1034 §4.3.2 step 3b): its NS
    /// records, its DS or the proof it has none (RFC 4035 §3.1.4, RFC 5155
    /// §7.2.7), and glue: in-domain glue first, which the response must keep
    /// (RFC 9471 §2.1), then sibling glue in the zone.
    pub fn refer(&self, lookup: &mut DNSLookup, cut: &DNSName, dnssec: bool) {
        lookup.authoritative = !lookup.answers.is_empty();
        self.push(&mut lookup.authorities, cut, DNSType::NS, false);
        if dnssec {
            match self.has(cut, DNSType::DS) {
                true => self.push(&mut lookup.authorities, cut, DNSType::DS, true),
                false => self.prove_data(lookup, cut),
            }
        }
        let targets: Vec<DNSName> = self.rrset(cut, DNSType::NS).filter_map(DNSZone::named).collect();
        let glue = |target: &DNSName| {
            let mut records: Vec<DNSRecord> = Vec::new();
            for kind in [DNSType::A, DNSType::AAAA] {
                records.extend(self.rrset(target, kind).cloned());
            }
            records
        };
        for target in targets.iter().filter(|target| target.is_subdomain_of(cut)) {
            for record in glue(target) {
                if !lookup.additionals.contains(&record) {
                    lookup.additionals.push(record);
                }
            }
        }
        lookup.glue = lookup.additionals.len();
        // Sibling glue (RFC 9471 §2.2): of the zone's own data, or below another of its cuts.
        for target in
            targets.iter().filter(|target| !target.is_subdomain_of(cut) && target.is_subdomain_of(&self.origin))
        {
            match self.descend(target, DNSType::A) {
                DNSDescent::Authoritative => self.push_addresses(&mut lookup.additionals, target, dnssec),
                DNSDescent::Cut(_) => {
                    for record in glue(target) {
                        if !lookup.additionals.contains(&record) {
                            lookup.additionals.push(record);
                        }
                    }
                }
                DNSDescent::Redirection(_) => {}
            }
        }
    }

    /// The SOA of a negative answer, of the TTL of RFC 2308 §3: the lesser
    /// of its TTL and its minimum.
    pub fn negative(&self, lookup: &mut DNSLookup) {
        for record in self.rrset(&self.origin, DNSType::SOA) {
            let ttl = match &record.data {
                DNSData::SOA(soa) => record.ttl.min(soa.minimum),
                _ => record.ttl,
            };
            lookup.authorities.push(DNSRecord { ttl, ..record.clone() });
        }
        if lookup.authorities.iter().any(|record| record.kind == DNSType::SOA) {
            let signatures: Vec<DNSRecord> = self.signatures(&self.origin, DNSType::SOA).cloned().collect();
            lookup.authorities.extend(signatures);
        }
    }

    /// A no-data answer for `name`, which exists: the SOA and, if `dnssec`, the proof.
    pub fn deny_data(&self, lookup: &mut DNSLookup, name: &DNSName, dnssec: bool) {
        self.negative(lookup);
        if dnssec {
            self.prove_data(lookup, name);
        }
    }

    /// The proof that `name` has no data of the question's type: its NSEC
    /// (RFC 4035 §3.1.3.1) or, at an empty non-terminal, the NSEC covering
    /// it; its NSEC3, or the closest encloser proof of an empty non-terminal
    /// in an Opt-Out span (RFC 5155 §7.2.3, §7.2.4 and Erratum 3441).
    pub fn prove_data(&self, lookup: &mut DNSLookup, name: &DNSName) {
        match self.nsec3_parameters() {
            None => match self.has(name, DNSType::NSEC) {
                true => self.push(&mut lookup.authorities, name, DNSType::NSEC, true),
                false => self.push_covering(&mut lookup.authorities, name),
            },
            Some(_) => match self.nsec3_matching(name) {
                Some(owner) => self.push(&mut lookup.authorities, &owner, DNSType::NSEC3, true),
                None => self.push_closest_encloser(&mut lookup.authorities, name, &self.provable_encloser(name)),
            },
        }
    }

    /// The proof that `name` does not exist: NSEC covering it and the
    /// wildcard of its closest encloser (RFC 4035 §3.1.3.2), or the closest
    /// encloser proof and an NSEC3 covering the wildcard (RFC 5155 §7.2.2).
    pub fn deny_name(&self, lookup: &mut DNSLookup, name: &DNSName, encloser: &DNSName) {
        let wildcard = encloser.prepend(b"*").unwrap_or_else(|_| encloser.clone());
        match self.nsec3_parameters() {
            None => {
                self.push_covering(&mut lookup.authorities, name);
                self.push_covering(&mut lookup.authorities, &wildcard);
            }
            Some(_) => {
                // The closest encloser that an NSEC3 proves: not an empty
                // non-terminal of unsigned delegations in an Opt-Out span.
                let encloser = self.provable_encloser(name);
                let wildcard = encloser.prepend(b"*").unwrap_or_else(|_| encloser.clone());
                self.push_closest_encloser(&mut lookup.authorities, name, &encloser);
                if let Some(owner) = self.nsec3_covering(&wildcard) {
                    self.push(&mut lookup.authorities, &owner, DNSType::NSEC3, true);
                }
            }
        }
    }

    /// The longest ancestor of `name`, not itself, that an NSEC3 matches:
    /// the closest provable encloser (RFC 5155 §7.2.1); the origin if none
    /// below it does, or if `name` is the origin or not of the zone.
    pub fn provable_encloser(&self, name: &DNSName) -> DNSName {
        let mut ancestor = name.clone();
        while ancestor != self.origin {
            match ancestor.parent() {
                Some(parent) if parent.is_subdomain_of(&self.origin) => ancestor = parent,
                _ => break,
            }
            if self.nsec3_matching(&ancestor).is_some() {
                return ancestor;
            }
        }
        self.origin.clone()
    }

    /// The proof that `name`, answered by the wildcard below `encloser`, does
    /// not exist itself (RFC 4035 §3.1.3.3, RFC 5155 §7.2.6).
    pub fn deny_closer(&self, lookup: &mut DNSLookup, name: &DNSName, encloser: &DNSName) {
        match self.nsec3_parameters() {
            None => self.push_covering(&mut lookup.authorities, name),
            Some(_) => {
                let next_closer = name.suffix(encloser.label_count() + 1);
                if let Some(owner) = self.nsec3_covering(&next_closer) {
                    self.push(&mut lookup.authorities, &owner, DNSType::NSEC3, true);
                }
            }
        }
    }

    /// The proof that neither `name` nor the type at `wildcard`, its
    /// closest encloser's, exists (RFC 4035 §3.1.3.4, RFC 5155 §7.2.5).
    pub fn deny_wildcard_data(&self, lookup: &mut DNSLookup, name: &DNSName, encloser: &DNSName, wildcard: &DNSName) {
        match self.nsec3_parameters() {
            None => {
                self.push_covering(&mut lookup.authorities, name);
                self.push(&mut lookup.authorities, wildcard, DNSType::NSEC, true);
            }
            Some(_) => {
                self.push_closest_encloser(&mut lookup.authorities, name, encloser);
                if let Some(owner) = self.nsec3_matching(wildcard) {
                    self.push(&mut lookup.authorities, &owner, DNSType::NSEC3, true);
                }
            }
        }
    }

    /// Appends the NSEC whose owner is the last before `name` in canonical
    /// order, which covers it (RFC 4034 §4.1.1), and its signature.
    pub fn push_covering(&self, section: &mut Vec<DNSRecord>, name: &DNSName) {
        let covering = self
            .nodes
            .range::<DNSName, _>(..=name)
            .rev()
            .find(|(owner, records)| *owner != name && records.iter().any(|record| record.kind == DNSType::NSEC));
        if let Some((owner, _)) = covering {
            self.push(section, owner, DNSType::NSEC, true);
        }
    }

    /// Appends the closest encloser proof of `name` (RFC 5155 §7.2.1): the
    /// NSEC3 matching `encloser` and the one covering the next closer name.
    pub fn push_closest_encloser(&self, section: &mut Vec<DNSRecord>, name: &DNSName, encloser: &DNSName) {
        if let Some(owner) = self.nsec3_matching(encloser) {
            self.push(section, &owner, DNSType::NSEC3, true);
        }
        if name.label_count() > encloser.label_count()
            && let Some(owner) = self.nsec3_covering(&name.suffix(encloser.label_count() + 1))
        {
            self.push(section, &owner, DNSType::NSEC3, true);
        }
    }

    /// The hash of `name` with the zone's NSEC3 parameters.
    pub fn nsec3_hash(&self, name: &DNSName) -> Option<Vec<u8>> {
        let (algorithm, iterations, salt) = self.nsec3_parameters()?;
        DNSNSEC3::digest(algorithm, iterations, salt, name)
    }

    /// The owner of the NSEC3 of `name`'s hash.
    pub fn nsec3_matching(&self, name: &DNSName) -> Option<DNSName> {
        let hash = self.nsec3_hash(name)?;
        let index = self.nsec3.binary_search_by(|(owner, _)| owner.as_slice().cmp(&hash)).ok()?;
        Some(self.nsec3[index].1.clone())
    }

    /// The owner of the NSEC3 covering `name`'s hash: the last hash before
    /// it, or the last of all before the first (RFC 5155 §3.1.7).
    pub fn nsec3_covering(&self, name: &DNSName) -> Option<DNSName> {
        let hash = self.nsec3_hash(name)?;
        let index = match self.nsec3.binary_search_by(|(owner, _)| owner.as_slice().cmp(&hash)) {
            Ok(_) => return None,
            Err(index) => index,
        };
        let index = index.checked_sub(1).unwrap_or(self.nsec3.len().checked_sub(1)?);
        Some(self.nsec3[index].1.clone())
    }
}

/// What an authoritative server does beyond its zones.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSAuthorityConfig {
    /// Positive answers carry their answer alone, without the apex's NS
    /// and additional addresses (referrals keep their glue).
    pub minimal: bool,
    /// The largest response over UDP, whatever larger size a query offers (RFC 9715 §3.2).
    pub udp_size: u16,
    /// The most CNAME and DNAME a lookup follows in its zone.
    pub maximum_chain: usize,
    /// The secrets of server cookies (RFC 9018 §5): the first makes them,
    /// any verifies them. With none, cookies are ignored (RFC 7873 §5.2).
    pub cookie_secrets: Vec<[u8; 16]>,
    /// The clients that may transfer zones (RFC 5936 §6): none by default.
    pub transfers: Vec<IPEndpointPattern>,
    /// Responses over encrypted transports to queries with the Padding
    /// option are padded to a multiple of this (RFC 8467 §4.1: 468); 0 does not pad.
    pub padding: usize,
    /// The largest message of a zone transfer.
    pub transfer_size: usize,
    /// The idle timeout told, over TCP and TLS, to queries with the
    /// edns-tcp-keepalive option (RFC 7828 §3.3.2); never over UDP or QUIC
    /// (RFC 9250 §5.5.2). None does not tell.
    pub keepalive: Option<core::time::Duration>,
}

impl Default for DNSAuthorityConfig {
    fn default() -> DNSAuthorityConfig {
        DNSAuthorityConfig {
            minimal: true,
            udp_size: DNSEDNS::DEFAULT_UDP_SIZE,
            maximum_chain: 16,
            cookie_secrets: Vec::new(),
            transfers: Vec::new(),
            padding: 468,
            transfer_size: 16384,
            keepalive: Some(core::time::Duration::from_secs(10)),
        }
    }
}

/// A response of an authoritative server, before it is written.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSResponse {
    pub message: DNSMessage,
    /// The additional records the response must keep or be truncated ([`DNSLookup::glue`]).
    pub glue: usize,
    /// Whether to pad it (the query asked to, over an encrypted transport).
    pub padded: bool,
}

impl DNSResponse {
    /// The response in at most `limit` bytes: truncated if the glue it
    /// must carry does not fit (RFC 9471 §3), padded with the Padding
    /// option to a multiple of `block` if asked to (RFC 7830 §3, RFC 8467).
    pub fn encode(&self, limit: usize, block: usize) -> Result<Vec<u8>, DNSError> {
        let mut bytes = self.message.encode(limit)?;
        let edns = usize::from(self.message.edns.is_some());
        let additionals = usize::from(u16::from_be_bytes([bytes[10], bytes[11]])) - edns;
        if additionals < self.glue {
            bytes[2] |= 0x02;
        }
        if self.padded && block > 0 && self.message.edns.is_some() {
            // The option's own 4 bytes, then zeros up to the next multiple.
            let length = bytes.len() + 4;
            let padding = (block - length % block) % block;
            if bytes.len() + 4 + padding <= limit {
                let mut message = self.message.clone();
                if let Some(edns) = &mut message.edns {
                    edns.set_option(DNSOption { code: DNSOptionCode::PADDING, data: alloc::vec![0; padding] });
                }
                let truncated = bytes[2] & 0x02;
                bytes = message.encode(limit)?;
                bytes[2] |= truncated;
            }
        }
        Ok(bytes)
    }
}

/// An authoritative name server (RFC 1034 §4.3.2, RFC 1035): the zones it
/// answers for, and the checks and options of the queries it takes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DNSAuthority {
    pub zones: Vec<DNSZone>,
    pub config: DNSAuthorityConfig,
}

impl DNSAuthority {
    pub fn new(zones: Vec<DNSZone>, config: DNSAuthorityConfig) -> DNSAuthority {
        DNSAuthority { zones, config }
    }

    /// The zone that answers for `name`: the one of the longest origin it
    /// is at or below; for DS, the one above the name's own if there is
    /// one, the parent's (RFC 4035 §3.1.4.1).
    pub fn zone(&self, name: &DNSName, kind: DNSType) -> Option<&DNSZone> {
        let longest = |above: bool| {
            self.zones
                .iter()
                .filter(|zone| name.is_subdomain_of(&zone.origin) && !(above && zone.origin == *name))
                .max_by_key(|zone| zone.origin.label_count())
        };
        match kind {
            DNSType::DS => longest(true).or_else(|| longest(false)),
            _ => longest(false),
        }
    }

    /// The responses to the message `query` from `peer` at `now` (seconds
    /// since 1970, for cookies): none to what is not a query (RFC 1035
    /// §4.1.1), a FORMERR to what cannot be read past its header, more
    /// than one for a zone transfer (RFC 5936 §2.2).
    pub fn respond(&self, query: &[u8], peer: &DNSPeer, now: u32) -> Vec<Vec<u8>> {
        let limit = |message: &DNSMessage| match peer.transport.is_stream() {
            true => DNSMessage::MAXIMUM_SIZE,
            false => message.udp_response_limit(self.config.udp_size),
        };
        let message = match DNSMessage::decode(query) {
            Ok(message) => message,
            Err(_) => {
                let Ok((header, _)) = DNSHeader::decode(query) else { return Vec::new() };
                if header.response {
                    return Vec::new();
                }
                let mut response = DNSMessage {
                    header: DNSHeader { id: header.id, opcode: header.opcode, ..DNSHeader::default() },
                    ..DNSMessage::default()
                };
                response.header.response = true;
                response.set_rcode(DNSResponseCode::FORMERR);
                return response.encode(DNSMessage::UDP_SIZE).into_iter().collect();
            }
        };
        let limit = limit(&message);
        self.answer(&message, peer, now)
            .iter()
            .filter_map(|response| response.encode(limit, self.config.padding).ok())
            .collect()
    }

    /// The responses to `query` (see [`DNSAuthority::respond`]).
    pub fn answer(&self, query: &DNSMessage, peer: &DNSPeer, now: u32) -> Vec<DNSResponse> {
        if query.header.response {
            return Vec::new();
        }
        let padded = peer.transport.is_encrypted()
            && query.edns.as_ref().is_some_and(|edns| edns.option(DNSOptionCode::PADDING).is_some());
        let respond = |message: DNSMessage| alloc::vec![DNSResponse { message, glue: 0, padded }];
        let mut response = DNSMessage::response(query, DNSResponseCode::NOERROR);
        if let Some(edns) = &mut response.edns {
            edns.udp_size = self.config.udp_size;
        }
        // RFC 6891 §6.1.3: a version above 0 is BADVERS, answered in version 0.
        if query.edns.as_ref().is_some_and(|edns| edns.version != 0) {
            response.set_rcode(DNSResponseCode::BADVERS);
            return respond(response);
        }
        let cookie = match self.cookie(query, peer, now) {
            Ok(cookie) => cookie,
            Err(_) => {
                response.set_rcode(DNSResponseCode::FORMERR);
                return respond(response);
            }
        };
        if let (Some(cookie), Some(edns)) = (&cookie, &mut response.edns) {
            edns.set_option(cookie.encode());
        }
        let asks = query.edns.as_ref().is_some_and(|edns| edns.option(DNSOptionCode::TCP_KEEPALIVE).is_some());
        if asks
            && matches!(peer.transport, DNSTransport::TCP | DNSTransport::TLS)
            && let (Some(timeout), Some(edns)) = (self.config.keepalive, &mut response.edns)
        {
            edns.set_option(DNSKeepalive::response(timeout));
        }
        if query.header.opcode != DNSOpcode::QUERY {
            response.set_rcode(DNSResponseCode::NOTIMP);
            return respond(response);
        }
        let [question] = query.questions.as_slice() else {
            // RFC 7873 §5.4: no question but a cookie asks for the server cookie, given here;
            // BADCOOKIE if the server cookie sent is not valid.
            let sent = query.edns.as_ref().and_then(|edns| edns.cookie()).and_then(Result::ok);
            let invalid = sent.is_some_and(|sent| {
                sent.server.is_some()
                    && sent.check_server(&self.config.cookie_secrets, &peer.endpoint.address, now).is_none()
            });
            let rcode = match (query.questions.is_empty() && cookie.is_some(), invalid) {
                (true, true) => DNSResponseCode::BADCOOKIE,
                (true, false) => DNSResponseCode::NOERROR,
                (false, _) => DNSResponseCode::FORMERR,
            };
            response.set_rcode(rcode);
            return respond(response);
        };
        let kind = question.kind;
        // RFC 9824 §3.5 for NXNAME, and the other meta-types that are not
        // questions (RFC 6895 §3.1): FORMERR, with Invalid Query Type.
        let meta = kind == DNSType::OPT || (128..=250).contains(&kind.0);
        if meta {
            response.set_rcode(DNSResponseCode::FORMERR);
            if let Some(edns) = &mut response.edns {
                let error = DNSExtendedError {
                    info_code: DNSExtendedError::INVALID_QUERY_TYPE,
                    text: alloc::string::String::new(),
                };
                edns.options.push(error.encode());
            }
            return respond(response);
        }
        // MAILB and MAILA (RFC 1035 §3.2.3) are obsolete.
        if kind.0 == 253 || kind.0 == 254 {
            response.set_rcode(DNSResponseCode::NOTIMP);
            return respond(response);
        }
        let Some(zone) = self.zone(&question.name, kind) else {
            response.set_rcode(match kind {
                DNSType::AXFR | DNSType::IXFR => DNSResponseCode::NOTAUTH,
                _ => DNSResponseCode::REFUSED,
            });
            return respond(response);
        };
        if question.class != zone.class && question.class != DNSClass::ANY {
            response.set_rcode(DNSResponseCode::REFUSED);
            return respond(response);
        }
        if kind == DNSType::AXFR || kind == DNSType::IXFR {
            return self.transfer(query, response, zone, peer, padded);
        }
        let dnssec = query.edns.as_ref().is_some_and(|edns| edns.dnssec_ok);
        let lookup = zone.lookup(&question.name, kind, dnssec, self.config.minimal, self.config.maximum_chain);
        response.header.authoritative = lookup.authoritative;
        response.set_rcode(lookup.rcode);
        response.answers = lookup.answers;
        response.authorities = lookup.authorities;
        response.additionals = lookup.additionals;
        alloc::vec![DNSResponse { message: response, glue: lookup.glue, padded }]
    }

    /// The cookie of the response to `query` (RFC 7873 §5.2): none without
    /// secrets or a cookie in the query; the client's with the server's
    /// own if that one is valid, of the current secret and less than half an
    /// hour old, else with a new one (RFC 9018 §4.3, §5). A cookie of a
    /// wrong length is an error (FORMERR, RFC 7873 §5.2.2) to a server of
    /// cookies; a server without secrets has none, and ignores the option.
    pub fn cookie(&self, query: &DNSMessage, peer: &DNSPeer, now: u32) -> Result<Option<DNSCookie>, DNSError> {
        let Some(secret) = self.config.cookie_secrets.first() else { return Ok(None) };
        let Some(cookie) = query.edns.as_ref().and_then(|edns| edns.cookie()) else { return Ok(None) };
        let cookie = cookie?;
        let address = &peer.endpoint.address;
        // A cookie of an older secret is renewed with the current one (RFC 9018 §5, stage 2).
        let fresh =
            cookie.check_server(&self.config.cookie_secrets, address, now).is_some_and(|(timestamp, secret)| {
                secret == 0 && (now.wrapping_sub(timestamp) as i32) < DNSCookie::SERVER_RENEWAL as i32
            });
        if fresh {
            return Ok(Some(cookie));
        }
        let server = DNSCookie::server_cookie(secret, &cookie.client, address, now);
        Ok(Some(DNSCookie { client: cookie.client, server: Some(server.to_vec()) }))
    }

    /// A zone transfer (RFC 5936): over a stream only, to the clients the
    /// configuration lists, of a zone's origin; the SOA, every other
    /// record, and the SOA again, in messages of at most the configured
    /// size. IXFR is answered so, with the whole zone (RFC 1995 §4); over
    /// UDP, with the SOA alone, so that the client uses TCP.
    pub fn transfer(
        &self,
        query: &DNSMessage,
        mut response: DNSMessage,
        zone: &DNSZone,
        peer: &DNSPeer,
        padded: bool,
    ) -> Vec<DNSResponse> {
        let respond = |message: DNSMessage| alloc::vec![DNSResponse { message, glue: 0, padded }];
        let Some(question) = query.question() else { return Vec::new() };
        if question.name != zone.origin {
            response.set_rcode(DNSResponseCode::NOTAUTH);
            return respond(response);
        }
        if !self.config.transfers.iter().any(|pattern| pattern.matches(&peer.endpoint)) {
            response.set_rcode(DNSResponseCode::REFUSED);
            return respond(response);
        }
        let Some(soa) = zone.soa() else { return Vec::new() };
        response.header.authoritative = true;
        if !peer.transport.is_stream() {
            if question.kind == DNSType::IXFR {
                response.answers.push(soa.clone());
            } else {
                response.set_rcode(DNSResponseCode::FORMERR);
            }
            return respond(response);
        }
        let mut records: Vec<&DNSRecord> = alloc::vec![soa];
        records.extend(zone.records().filter(|record| record.kind != DNSType::SOA));
        records.push(soa);
        let mut messages = Vec::new();
        let mut message = response.clone();
        for record in records {
            message.answers.push(record.clone());
            let fits = message.encode(self.config.transfer_size).is_ok_and(|bytes| bytes[2] & 0x02 == 0);
            if !fits && message.answers.len() > 1 {
                message.answers.pop();
                messages.push(message);
                message =
                    DNSMessage { questions: Vec::new(), answers: alloc::vec![record.clone()], ..response.clone() };
            }
        }
        messages.push(message);
        messages.into_iter().map(|message| DNSResponse { message, glue: 0, padded }).collect()
    }
}
