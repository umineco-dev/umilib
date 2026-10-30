use alloc::vec::Vec;

use crate::crypto::random::Random;

use super::super::{DNSData, DNSDescent, DNSError, DNSName, DNSRecord, DNSType, DNSTypeBitmap, DNSZone};
use super::{DNSSECKey, DNSSECSigner};

impl DNSZone {
    /// The zone signed by `signers` (RFC 4035 §2), valid from `inception`
    /// to `expiration` (seconds since 1970, modulo 2^32): its RRSIG, NSEC
    /// and NSEC3 records replaced by the signers' DNSKEY records, an NSEC
    /// chain of its authoritative names (§2.3; of the TTL of RFC 9077 §3.3,
    /// the lesser of the SOA's TTL and minimum), and the signatures of
    /// every authoritative RRset (§2.2): the DNSKEY RRset by every signer,
    /// the others by the signers that are not secure entry points, or by
    /// all if each is one. At a zone cut only DS and NSEC are signed, and
    /// names below a cut (glue) have neither.
    pub fn sign<R: Random>(
        &self,
        signers: &[DNSSECSigner],
        inception: u32,
        expiration: u32,
        random: &mut R,
    ) -> Result<DNSZone, DNSError> {
        let soa = self.soa().ok_or(DNSError::Config)?;
        let DNSData::SOA(data) = &soa.data else { return Err(DNSError::Config) };
        let nsec_ttl = soa.ttl.min(data.minimum);
        if signers.is_empty() || signers.iter().any(|signer| signer.zone != self.origin) {
            return Err(DNSError::Config);
        }
        let mut records: Vec<DNSRecord> = self
            .records()
            .filter(|record| {
                !matches!(record.kind, DNSType::RRSIG | DNSType::NSEC | DNSType::NSEC3 | DNSType::NSEC3PARAM)
            })
            .cloned()
            .collect();
        let ttl = self.rrset(&self.origin, DNSType::DNSKEY).next().map_or(soa.ttl, |record| record.ttl);
        for signer in signers {
            let dnskey = DNSRecord { class: self.class, ..signer.dnskey(ttl) };
            if !records.contains(&dnskey) {
                records.push(dnskey);
            }
        }
        let unsigned = DNSZone::new(self.origin.clone(), records)?;
        // The names of the chain: the authoritative ones, the cuts among them.
        let names: Vec<&DNSName> = unsigned
            .nodes
            .keys()
            .filter(|name| match unsigned.descend(name, DNSType::DS) {
                DNSDescent::Authoritative => true,
                DNSDescent::Cut(_) | DNSDescent::Redirection(_) => false,
            })
            .collect();
        let mut signed: Vec<DNSRecord> = unsigned.records().cloned().collect();
        for (index, name) in names.iter().enumerate() {
            let next = names[(index + 1) % names.len()];
            let mut types: Vec<DNSType> = unsigned.nodes[*name].iter().map(|record| record.kind).collect();
            let cut = **name != self.origin && unsigned.has(name, DNSType::NS);
            if cut {
                types.retain(|kind| *kind == DNSType::NS || *kind == DNSType::DS);
            }
            types.extend([DNSType::NSEC, DNSType::RRSIG]);
            let nsec = DNSData::NSEC { next: next.clone(), types: DNSTypeBitmap::new(&types) };
            signed.push(DNSRecord { class: self.class, ..DNSRecord::new((*name).clone(), nsec_ttl, nsec) });
        }
        let chained = DNSZone::new(self.origin.clone(), signed)?;
        let key_signing: Vec<&DNSSECSigner> = signers.iter().collect();
        let mut zone_signing: Vec<&DNSSECSigner> =
            signers.iter().filter(|signer| signer.flags & DNSSECKey::SECURE_ENTRY_POINT == 0).collect();
        if zone_signing.is_empty() {
            zone_signing = key_signing.clone();
        }
        let mut signatures = Vec::new();
        for name in &names {
            let cut = **name != self.origin && chained.has(name, DNSType::NS);
            let mut kinds: Vec<DNSType> = chained.nodes[*name].iter().map(|record| record.kind).collect();
            kinds.sort();
            kinds.dedup();
            for kind in kinds {
                if cut && kind != DNSType::DS && kind != DNSType::NSEC {
                    continue;
                }
                let set: Vec<DNSRecord> = chained.rrset(name, kind).cloned().collect();
                let by = if kind == DNSType::DNSKEY { &key_signing } else { &zone_signing };
                for signer in by {
                    signatures.push(signer.sign(&set, inception, expiration, random)?);
                }
            }
        }
        let mut all: Vec<DNSRecord> = chained.records().cloned().collect();
        all.extend(signatures.into_iter().map(|record| DNSRecord { class: self.class, ..record }));
        DNSZone::new(self.origin.clone(), all)
    }
}
