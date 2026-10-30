use alloc::vec::Vec;

use super::SMTPError;
use crate::crypto::random::Random;
use crate::protocol::dns::{DNSData, DNSName, DNSRecord};

/// A host to deliver the mail of a domain to (RFC 5321 §5.1): an exchange of an MX record and its preference.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SMTPMailExchanger {
    pub preference: u16,
    pub host: DNSName,
}

impl SMTPMailExchanger {
    /// The hosts of the mail of `domain`, in the order to try them (RFC
    /// 5321 §5.1), of the MX records of `records` owned by `domain` (the
    /// name a CNAME led to, if any): by preference, the lowest first, those
    /// of one preference in a random order; the domain itself as an implicit
    /// MX of preference 0 if it has none. A host of `local` (this host, if
    /// it is an MX of the domain) and every host of a preference not lower
    /// than its own are removed, as is the null MX (RFC 7505), which alone
    /// means the domain takes no mail. Fails with NoMail then, and when no
    /// host is left.
    pub fn order<R: Random>(
        domain: &DNSName,
        records: &[DNSRecord],
        local: &[DNSName],
        random: &mut R,
    ) -> Result<Vec<SMTPMailExchanger>, SMTPError> {
        let mut exchangers: Vec<SMTPMailExchanger> = records
            .iter()
            .filter(|record| record.name == *domain)
            .filter_map(|record| match &record.data {
                DNSData::MX { preference, exchange } => {
                    Some(SMTPMailExchanger { preference: *preference, host: exchange.clone() })
                }
                _ => None,
            })
            .collect();
        if exchangers.is_empty() {
            return Ok(alloc::vec![SMTPMailExchanger { preference: 0, host: domain.clone() }]);
        }
        exchangers.retain(|exchanger| !exchanger.host.is_root());
        if exchangers.is_empty() {
            return Err(SMTPError::NoMail);
        }
        if let Some(own) = exchangers
            .iter()
            .filter(|exchanger| local.contains(&exchanger.host))
            .map(|exchanger| exchanger.preference)
            .min()
        {
            exchangers.retain(|exchanger| exchanger.preference < own);
        }
        if exchangers.is_empty() {
            return Err(SMTPError::NoMail);
        }
        // Each preference in a random order (Fisher-Yates), then the preferences in order.
        for index in (1..exchangers.len()).rev() {
            let other =
                random.next_u64().map_err(|_| SMTPError::State { reason: "no randomness" })? % (index as u64 + 1);
            exchangers.swap(index, other as usize);
        }
        exchangers.sort_by_key(|exchanger| exchanger.preference);
        Ok(exchangers)
    }
}
