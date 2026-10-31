use alloc::string::String;
use core::fmt;

use super::DNSError;

/// A type of resource record (RFC 1035 §3.2.2, IANA's DNS parameters);
/// any other number is a type this crate keeps as opaque data (RFC 3597).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DNSType(pub u16);

impl DNSType {
    pub const A: DNSType = DNSType(1);
    pub const NS: DNSType = DNSType(2);
    pub const CNAME: DNSType = DNSType(5);
    pub const SOA: DNSType = DNSType(6);
    pub const PTR: DNSType = DNSType(12);
    pub const HINFO: DNSType = DNSType(13);
    pub const MX: DNSType = DNSType(15);
    pub const TXT: DNSType = DNSType(16);
    pub const AAAA: DNSType = DNSType(28);
    pub const SRV: DNSType = DNSType(33);
    pub const NAPTR: DNSType = DNSType(35);
    pub const DNAME: DNSType = DNSType(39);
    pub const OPT: DNSType = DNSType(41);
    pub const DS: DNSType = DNSType(43);
    pub const RRSIG: DNSType = DNSType(46);
    pub const NSEC: DNSType = DNSType(47);
    pub const DNSKEY: DNSType = DNSType(48);
    pub const NSEC3: DNSType = DNSType(50);
    pub const NSEC3PARAM: DNSType = DNSType(51);
    pub const TLSA: DNSType = DNSType(52);
    pub const CDS: DNSType = DNSType(59);
    pub const CDNSKEY: DNSType = DNSType(60);
    pub const SVCB: DNSType = DNSType(64);
    pub const HTTPS: DNSType = DNSType(65);
    /// The type of nothing, which Compact Denial of Existence lists for a name that does not exist (RFC 9824 §2).
    pub const NXNAME: DNSType = DNSType(128);
    pub const IXFR: DNSType = DNSType(251);
    pub const AXFR: DNSType = DNSType(252);
    pub const ANY: DNSType = DNSType(255);
    pub const CAA: DNSType = DNSType(257);

    pub const NAMES: [(DNSType, &'static str); 29] = [
        (DNSType::A, "A"),
        (DNSType::NS, "NS"),
        (DNSType::CNAME, "CNAME"),
        (DNSType::SOA, "SOA"),
        (DNSType::PTR, "PTR"),
        (DNSType::HINFO, "HINFO"),
        (DNSType::MX, "MX"),
        (DNSType::TXT, "TXT"),
        (DNSType::AAAA, "AAAA"),
        (DNSType::SRV, "SRV"),
        (DNSType::NAPTR, "NAPTR"),
        (DNSType::DNAME, "DNAME"),
        (DNSType::OPT, "OPT"),
        (DNSType::DS, "DS"),
        (DNSType::RRSIG, "RRSIG"),
        (DNSType::NSEC, "NSEC"),
        (DNSType::DNSKEY, "DNSKEY"),
        (DNSType::NSEC3, "NSEC3"),
        (DNSType::NSEC3PARAM, "NSEC3PARAM"),
        (DNSType::TLSA, "TLSA"),
        (DNSType::CDS, "CDS"),
        (DNSType::CDNSKEY, "CDNSKEY"),
        (DNSType::SVCB, "SVCB"),
        (DNSType::HTTPS, "HTTPS"),
        (DNSType::NXNAME, "NXNAME"),
        (DNSType::IXFR, "IXFR"),
        (DNSType::AXFR, "AXFR"),
        (DNSType::ANY, "ANY"),
        (DNSType::CAA, "CAA"),
    ];

    /// The type of its mnemonic, without case, or of "TYPEn" (RFC 3597 §5).
    pub fn parse(text: &str) -> Result<DNSType, DNSError> {
        if let Some((kind, _)) = DNSType::NAMES.iter().find(|(_, name)| name.eq_ignore_ascii_case(text)) {
            return Ok(*kind);
        }
        let digits = text.get(..4).filter(|prefix| prefix.eq_ignore_ascii_case("TYPE")).map(|_| &text[4..]);
        digits.and_then(|digits| digits.parse::<u16>().ok()).map(DNSType).ok_or(DNSError::Syntax("not a type"))
    }

    /// Whether a record of this type is data of a zone: not a meta-type
    /// (OPT, NXNAME) nor a type of queries (AXFR, ANY), RFC 6895 §3.1.
    pub const fn is_data(self) -> bool {
        !matches!(self.0, 41 | 128..=255)
    }

    /// Whether a sender compresses the names in its data: the types of RFC
    /// 1035 this crate writes (RFC 3597 §4: no others).
    pub const fn compresses_names(self) -> bool {
        matches!(self.0, 2 | 5 | 6 | 12 | 15)
    }

    /// Whether a receiver decompresses the names in its data: those of the
    /// types of RFC 1035 (MUST), and of RP, AFSDB, RT, SIG, PX, NXT, NAPTR
    /// and SRV (SHOULD), RFC 3597 §4.
    pub const fn decompresses_names(self) -> bool {
        matches!(self.0, 2..=9 | 12 | 14 | 15 | 17 | 18 | 21 | 24 | 26 | 30 | 33 | 35)
    }

    /// Whether the canonical form lowercases the names in its data: NS,
    /// MD, MF, CNAME, SOA, MB, MG, MR, PTR, HINFO, MINFO, MX, RP, AFSDB,
    /// RT, SIG, PX, NXT, NAPTR, KX, SRV, DNAME, A6 and RRSIG (RFC 4034
    /// §6.2, without NSEC as RFC 6840 §5.1 says).
    pub const fn lowercases_names(self) -> bool {
        matches!(self.0, 2..=9 | 12..=15 | 17 | 18 | 21 | 24 | 26 | 30 | 33 | 35 | 36 | 38 | 39 | 46)
    }
}

impl fmt::Display for DNSType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match DNSType::NAMES.iter().find(|(kind, _)| kind == self) {
            Some((_, name)) => formatter.write_str(name),
            None => write!(formatter, "TYPE{}", self.0),
        }
    }
}

/// A class (RFC 1035 §3.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DNSClass(pub u16);

impl DNSClass {
    pub const IN: DNSClass = DNSClass(1);
    pub const CH: DNSClass = DNSClass(3);
    pub const HS: DNSClass = DNSClass(4);
    pub const NONE: DNSClass = DNSClass(254);
    pub const ANY: DNSClass = DNSClass(255);

    /// The class of its mnemonic or of "CLASSn" (RFC 3597 §5).
    pub fn parse(text: &str) -> Result<DNSClass, DNSError> {
        let class = match text.to_ascii_uppercase().as_str() {
            "IN" => DNSClass::IN,
            "CH" => DNSClass::CH,
            "HS" => DNSClass::HS,
            "NONE" => DNSClass::NONE,
            "ANY" => DNSClass::ANY,
            upper => {
                let digits = upper.strip_prefix("CLASS").ok_or(DNSError::Syntax("not a class"))?;
                DNSClass(digits.parse().map_err(|_| DNSError::Syntax("not a class"))?)
            }
        };
        Ok(class)
    }
}

impl fmt::Display for DNSClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            DNSClass::IN => "IN",
            DNSClass::CH => "CH",
            DNSClass::HS => "HS",
            DNSClass::NONE => "NONE",
            DNSClass::ANY => "ANY",
            other => return write!(formatter, "CLASS{}", other.0),
        };
        formatter.write_str(name)
    }
}

/// An operation code (RFC 1035 §4.1.1, RFC 6895 §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DNSOpcode(pub u8);

impl DNSOpcode {
    pub const QUERY: DNSOpcode = DNSOpcode(0);
    pub const STATUS: DNSOpcode = DNSOpcode(2);
    pub const NOTIFY: DNSOpcode = DNSOpcode(4);
    pub const UPDATE: DNSOpcode = DNSOpcode(5);
    pub const DSO: DNSOpcode = DNSOpcode(6);
}

/// A response code, 12 bits with the upper 8 of EDNS (RFC 6891 §6.1.3, RFC 6895 §2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DNSResponseCode(pub u16);

impl DNSResponseCode {
    pub const NOERROR: DNSResponseCode = DNSResponseCode(0);
    pub const FORMERR: DNSResponseCode = DNSResponseCode(1);
    pub const SERVFAIL: DNSResponseCode = DNSResponseCode(2);
    pub const NXDOMAIN: DNSResponseCode = DNSResponseCode(3);
    pub const NOTIMP: DNSResponseCode = DNSResponseCode(4);
    pub const REFUSED: DNSResponseCode = DNSResponseCode(5);
    pub const YXDOMAIN: DNSResponseCode = DNSResponseCode(6);
    pub const NOTAUTH: DNSResponseCode = DNSResponseCode(9);
    pub const NOTZONE: DNSResponseCode = DNSResponseCode(10);
    /// BADVERS, an EDNS version this end does not speak (RFC 6891 §6.1.3).
    pub const BADVERS: DNSResponseCode = DNSResponseCode(16);
    /// BADCOOKIE (RFC 7873 §8).
    pub const BADCOOKIE: DNSResponseCode = DNSResponseCode(23);

    pub fn name(&self) -> String {
        let name = match self.0 {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            6 => "YXDOMAIN",
            9 => "NOTAUTH",
            10 => "NOTZONE",
            16 => "BADVERS",
            23 => "BADCOOKIE",
            code => return alloc::format!("RCODE{code}"),
        };
        String::from(name)
    }
}
