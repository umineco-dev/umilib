use alloc::vec::Vec;
use core::fmt;

use super::{DNSClass, DNSCompression, DNSData, DNSError, DNSName, DNSType};

/// A question (RFC 1035 §4.1.2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DNSQuestion {
    pub name: DNSName,
    pub kind: DNSType,
    pub class: DNSClass,
}

impl DNSQuestion {
    pub fn new(name: DNSName, kind: DNSType) -> DNSQuestion {
        DNSQuestion { name, kind, class: DNSClass::IN }
    }

    /// The question at `offset` of `message`, and the offset after it.
    pub fn decode(message: &[u8], offset: usize) -> Result<(DNSQuestion, usize), DNSError> {
        let (name, offset) = DNSName::decode(message, offset)?;
        let fields = message.get(offset..offset + 4).ok_or(DNSError::Malformed("a question cut short"))?;
        let kind = DNSType(u16::from_be_bytes([fields[0], fields[1]]));
        let class = DNSClass(u16::from_be_bytes([fields[2], fields[3]]));
        Ok((DNSQuestion { name, kind, class }, offset + 4))
    }

    pub fn encode(&self, out: &mut Vec<u8>, compression: Option<&mut DNSCompression>) {
        self.name.encode(out, compression);
        out.extend_from_slice(&self.kind.0.to_be_bytes());
        out.extend_from_slice(&self.class.0.to_be_bytes());
    }
}

/// A resource record (RFC 1035 §4.1.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSRecord {
    pub name: DNSName,
    pub kind: DNSType,
    pub class: DNSClass,
    pub ttl: u32,
    pub data: DNSData,
}

impl DNSRecord {
    pub fn new(name: DNSName, ttl: u32, data: DNSData) -> DNSRecord {
        let kind = DNSRecord::kind_of(&data);
        DNSRecord { name, kind, class: DNSClass::IN, ttl, data }
    }

    /// The type a datum has unless set otherwise (CDS and CDNSKEY share DS's
    /// and DNSKEY's data, HTTPS SVCB's).
    pub fn kind_of(data: &DNSData) -> DNSType {
        match data {
            DNSData::A(_) => DNSType::A,
            DNSData::AAAA(_) => DNSType::AAAA,
            DNSData::NS(_) => DNSType::NS,
            DNSData::CNAME(_) => DNSType::CNAME,
            DNSData::DNAME(_) => DNSType::DNAME,
            DNSData::PTR(_) => DNSType::PTR,
            DNSData::SOA(_) => DNSType::SOA,
            DNSData::MX { .. } => DNSType::MX,
            DNSData::TXT(_) => DNSType::TXT,
            DNSData::HINFO { .. } => DNSType::HINFO,
            DNSData::SRV { .. } => DNSType::SRV,
            DNSData::NAPTR(_) => DNSType::NAPTR,
            DNSData::CAA { .. } => DNSType::CAA,
            DNSData::DS { .. } => DNSType::DS,
            DNSData::DNSKEY { .. } => DNSType::DNSKEY,
            DNSData::RRSIG(_) => DNSType::RRSIG,
            DNSData::NSEC { .. } => DNSType::NSEC,
            DNSData::NSEC3(_) => DNSType::NSEC3,
            DNSData::NSEC3PARAM { .. } => DNSType::NSEC3PARAM,
            DNSData::TLSA { .. } => DNSType::TLSA,
            DNSData::SVCB(_) => DNSType::SVCB,
            DNSData::Unknown(_) => DNSType(0),
        }
    }

    /// The record at `offset` of `message`, the offset after it, and where
    /// its RDATA is.
    pub fn decode(message: &[u8], offset: usize) -> Result<(DNSRecord, usize, core::ops::Range<usize>), DNSError> {
        let (name, offset) = DNSName::decode(message, offset)?;
        let fields = message.get(offset..offset + 10).ok_or(DNSError::Malformed("a record cut short"))?;
        let kind = DNSType(u16::from_be_bytes([fields[0], fields[1]]));
        let class = DNSClass(u16::from_be_bytes([fields[2], fields[3]]));
        let ttl = u32::from_be_bytes([fields[4], fields[5], fields[6], fields[7]]);
        let length = usize::from(u16::from_be_bytes([fields[8], fields[9]]));
        let start = offset + 10;
        let end = start + length;
        if end > message.len() {
            return Err(DNSError::Malformed("RDATA cut short"));
        }
        let data = if kind == DNSType::OPT {
            DNSData::Unknown(message[start..end].to_vec())
        } else {
            DNSData::decode(kind, message, start, end)?
        };
        Ok((DNSRecord { name, kind, class, ttl, data }, end, start..end))
    }

    /// Appends the record, compressed with `compression` where its type allows.
    pub fn encode(&self, out: &mut Vec<u8>, mut compression: Option<&mut DNSCompression>) {
        self.name.encode(out, compression.as_deref_mut());
        out.extend_from_slice(&self.kind.0.to_be_bytes());
        out.extend_from_slice(&self.class.0.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        let at = out.len();
        out.extend_from_slice(&[0, 0]);
        self.data.encode(self.kind, out, compression);
        let length = (out.len() - at - 2) as u16;
        out[at..at + 2].copy_from_slice(&length.to_be_bytes());
    }

    /// Whether `other` is of the same RRset: owner, type and class (RFC 2181 §5).
    pub fn same_set(&self, other: &DNSRecord) -> bool {
        self.name == other.name && self.kind == other.kind && self.class == other.class
    }
}

/// The record in the presentation format: owner, TTL, class, type, data.
impl fmt::Display for DNSRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {} {} {} {}", self.name, self.ttl, self.class, self.kind, self.data.display(self.kind))
    }
}
