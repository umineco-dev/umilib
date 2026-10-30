use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::codec::base::Encoding;
use crate::codec::base::base16::Base16;
use crate::codec::base::base32::Base32;
use crate::codec::base::base64::Base64;
use crate::hash::Digest;
use crate::hash::sha::v1::SHA1;
use crate::protocol::ip::{IPv4Address, IPv6Address};

use super::{DNSCompression, DNSError, DNSName, DNSServiceBinding, DNSToken, DNSType, DNSTypeBitmap};

/// The data of an SOA record (RFC 1035 §3.3.13).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSSOA {
    pub mname: DNSName,
    pub rname: DNSName,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    /// The TTL of negative answers (RFC 2308 §4).
    pub minimum: u32,
}

/// The data of an RRSIG record (RFC 4034 §3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSRRSIG {
    pub type_covered: DNSType,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    /// Seconds since 1970, modulo 2^32 (RFC 4034 §3.1.5).
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer: DNSName,
    pub signature: Vec<u8>,
}

/// The data of an NSEC3 record (RFC 5155 §3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSNSEC3 {
    pub algorithm: u8,
    /// The Opt-Out flag is bit 0 (RFC 5155 §3.1.2.1).
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
    pub next_hashed: Vec<u8>,
    pub types: DNSTypeBitmap,
}

/// The data of a NAPTR record (RFC 3403 §4.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSNAPTR {
    pub order: u16,
    pub preference: u16,
    pub flags: Vec<u8>,
    pub services: Vec<u8>,
    pub regexp: Vec<u8>,
    pub replacement: DNSName,
}

/// The data of a resource record, by its type. A type this crate does not
/// know, or data of a known one that it cannot read, is
/// [`DNSData::Unknown`]: kept as it is (RFC 3597).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DNSData {
    A(IPv4Address),
    AAAA(IPv6Address),
    NS(DNSName),
    CNAME(DNSName),
    DNAME(DNSName),
    PTR(DNSName),
    SOA(Box<DNSSOA>),
    MX {
        preference: u16,
        exchange: DNSName,
    },
    /// One or more character-strings (RFC 1035 §3.3.14).
    TXT(Vec<Vec<u8>>),
    HINFO {
        cpu: Vec<u8>,
        os: Vec<u8>,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: DNSName,
    },
    NAPTR(Box<DNSNAPTR>),
    /// RFC 8659 §4.1.
    CAA {
        flags: u8,
        tag: Vec<u8>,
        value: Vec<u8>,
    },
    /// DS and CDS (RFC 4034 §5, RFC 7344 §3.1).
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    /// DNSKEY and CDNSKEY (RFC 4034 §2, RFC 7344 §3.2).
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },
    RRSIG(Box<DNSRRSIG>),
    NSEC {
        next: DNSName,
        types: DNSTypeBitmap,
    },
    NSEC3(Box<DNSNSEC3>),
    NSEC3PARAM {
        algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
    },
    /// RFC 6698 §2.1.
    TLSA {
        usage: u8,
        selector: u8,
        matching_type: u8,
        data: Vec<u8>,
    },
    /// SVCB and HTTPS (RFC 9460).
    SVCB(Box<DNSServiceBinding>),
    Unknown(Vec<u8>),
}

impl DNSData {
    /// The data of type `kind` in `message[start..end]`, the RDATA of a
    /// record. Names are decompressed for the types RFC 3597 §4 says
    /// ([`DNSType::decompresses_names`]), and kept uncompressed in the data
    /// of the types kept as bytes; the data must be read whole.
    pub fn decode(kind: DNSType, message: &[u8], start: usize, end: usize) -> Result<DNSData, DNSError> {
        let malformed = DNSError::Malformed("RDATA of another length than its type's");
        let mut reader = DNSReader { message, position: start, end, compressed: kind.decompresses_names() };
        let value = match kind {
            DNSType::A => DNSData::A(IPv4Address(reader.rest().try_into().map_err(|_| malformed)?)),
            DNSType::AAAA => DNSData::AAAA(IPv6Address(reader.rest().try_into().map_err(|_| malformed)?)),
            DNSType::NS => DNSData::NS(reader.name()?),
            DNSType::CNAME => DNSData::CNAME(reader.name()?),
            DNSType::DNAME => DNSData::DNAME(reader.name()?),
            DNSType::PTR => DNSData::PTR(reader.name()?),
            DNSType::SOA => DNSData::SOA(Box::new(DNSSOA {
                mname: reader.name()?,
                rname: reader.name()?,
                serial: reader.u32()?,
                refresh: reader.u32()?,
                retry: reader.u32()?,
                expire: reader.u32()?,
                minimum: reader.u32()?,
            })),
            DNSType::MX => DNSData::MX { preference: reader.u16()?, exchange: reader.name()? },
            DNSType::TXT => {
                let mut strings = Vec::new();
                while !reader.is_empty() {
                    strings.push(reader.string()?);
                }
                if strings.is_empty() {
                    return Err(DNSError::Malformed("TXT without a string"));
                }
                DNSData::TXT(strings)
            }
            DNSType::HINFO => DNSData::HINFO { cpu: reader.string()?, os: reader.string()? },
            DNSType::SRV => DNSData::SRV {
                priority: reader.u16()?,
                weight: reader.u16()?,
                port: reader.u16()?,
                target: reader.name()?,
            },
            DNSType::NAPTR => DNSData::NAPTR(Box::new(DNSNAPTR {
                order: reader.u16()?,
                preference: reader.u16()?,
                flags: reader.string()?,
                services: reader.string()?,
                regexp: reader.string()?,
                replacement: reader.name()?,
            })),
            DNSType::CAA => {
                let flags = reader.u8()?;
                let tag = reader.string()?;
                if tag.is_empty() || !tag.iter().all(u8::is_ascii_alphanumeric) {
                    return Err(DNSError::Malformed("a CAA tag not of letters and digits"));
                }
                DNSData::CAA { flags, tag, value: reader.rest().to_vec() }
            }
            DNSType::DS | DNSType::CDS => DNSData::DS {
                key_tag: reader.u16()?,
                algorithm: reader.u8()?,
                digest_type: reader.u8()?,
                digest: reader.rest().to_vec(),
            },
            DNSType::DNSKEY | DNSType::CDNSKEY => DNSData::DNSKEY {
                flags: reader.u16()?,
                protocol: reader.u8()?,
                algorithm: reader.u8()?,
                public_key: reader.rest().to_vec(),
            },
            DNSType::RRSIG => DNSData::RRSIG(Box::new(DNSRRSIG {
                type_covered: DNSType(reader.u16()?),
                algorithm: reader.u8()?,
                labels: reader.u8()?,
                original_ttl: reader.u32()?,
                expiration: reader.u32()?,
                inception: reader.u32()?,
                key_tag: reader.u16()?,
                signer: reader.name()?,
                signature: reader.rest().to_vec(),
            })),
            DNSType::NSEC => DNSData::NSEC { next: reader.name()?, types: DNSTypeBitmap::decode(reader.rest())? },
            DNSType::NSEC3 => {
                let (algorithm, flags, iterations) = (reader.u8()?, reader.u8()?, reader.u16()?);
                let salt = reader.string()?;
                let next_hashed = reader.string()?;
                if next_hashed.is_empty() {
                    return Err(DNSError::Malformed("an NSEC3 of an empty hash"));
                }
                let types = DNSTypeBitmap::decode(reader.rest())?;
                DNSData::NSEC3(Box::new(DNSNSEC3 { algorithm, flags, iterations, salt, next_hashed, types }))
            }
            DNSType::NSEC3PARAM => DNSData::NSEC3PARAM {
                algorithm: reader.u8()?,
                flags: reader.u8()?,
                iterations: reader.u16()?,
                salt: reader.string()?,
            },
            DNSType::TLSA => DNSData::TLSA {
                usage: reader.u8()?,
                selector: reader.u8()?,
                matching_type: reader.u8()?,
                data: reader.rest().to_vec(),
            },
            DNSType::SVCB | DNSType::HTTPS => {
                let priority = reader.u16()?;
                let target = reader.name()?;
                DNSData::SVCB(Box::new(DNSServiceBinding::decode_params(priority, target, reader.rest())?))
            }
            _ => DNSData::Unknown(match DNSField::of(kind) {
                Some(fields) => DNSField::read(fields, &mut reader)?,
                None => reader.rest().to_vec(),
            }),
        };
        if !reader.is_empty() {
            return Err(DNSError::Malformed("RDATA longer than its fields"));
        }
        Ok(value)
    }

    /// Appends the RDATA (without its length), names compressed with
    /// `compression` for the types of RFC 1035 only (RFC 3597 §4).
    pub fn encode(&self, kind: DNSType, out: &mut Vec<u8>, compression: Option<&mut DNSCompression>) {
        let mut compression = compression.filter(|_| kind.compresses_names());
        let mut name = |out: &mut Vec<u8>, name: &DNSName| name.encode(out, compression.as_deref_mut());
        let string = |out: &mut Vec<u8>, bytes: &[u8]| {
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        };
        match self {
            DNSData::A(address) => out.extend_from_slice(&address.0),
            DNSData::AAAA(address) => out.extend_from_slice(&address.0),
            DNSData::NS(target) | DNSData::CNAME(target) | DNSData::DNAME(target) | DNSData::PTR(target) => {
                name(out, target)
            }
            DNSData::SOA(soa) => {
                name(out, &soa.mname);
                name(out, &soa.rname);
                for value in [soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
            }
            DNSData::MX { preference, exchange } => {
                out.extend_from_slice(&preference.to_be_bytes());
                name(out, exchange);
            }
            DNSData::TXT(strings) => strings.iter().for_each(|text| string(out, text)),
            DNSData::HINFO { cpu, os } => {
                string(out, cpu);
                string(out, os);
            }
            DNSData::SRV { priority, weight, port, target } => {
                for value in [priority, weight, port] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
                name(out, target);
            }
            DNSData::NAPTR(naptr) => {
                out.extend_from_slice(&naptr.order.to_be_bytes());
                out.extend_from_slice(&naptr.preference.to_be_bytes());
                string(out, &naptr.flags);
                string(out, &naptr.services);
                string(out, &naptr.regexp);
                name(out, &naptr.replacement);
            }
            DNSData::CAA { flags, tag, value } => {
                out.push(*flags);
                string(out, tag);
                out.extend_from_slice(value);
            }
            DNSData::DS { key_tag, algorithm, digest_type, digest } => {
                out.extend_from_slice(&key_tag.to_be_bytes());
                out.extend_from_slice(&[*algorithm, *digest_type]);
                out.extend_from_slice(digest);
            }
            DNSData::DNSKEY { flags, protocol, algorithm, public_key } => {
                out.extend_from_slice(&flags.to_be_bytes());
                out.extend_from_slice(&[*protocol, *algorithm]);
                out.extend_from_slice(public_key);
            }
            DNSData::RRSIG(signature) => {
                signature.encode_fields(out);
                out.extend_from_slice(&signature.signature);
            }
            DNSData::NSEC { next, types } => {
                name(out, next);
                types.encode(out);
            }
            DNSData::NSEC3(nsec3) => {
                out.extend_from_slice(&[nsec3.algorithm, nsec3.flags]);
                out.extend_from_slice(&nsec3.iterations.to_be_bytes());
                string(out, &nsec3.salt);
                string(out, &nsec3.next_hashed);
                nsec3.types.encode(out);
            }
            DNSData::NSEC3PARAM { algorithm, flags, iterations, salt } => {
                out.extend_from_slice(&[*algorithm, *flags]);
                out.extend_from_slice(&iterations.to_be_bytes());
                string(out, salt);
            }
            DNSData::TLSA { usage, selector, matching_type, data } => {
                out.extend_from_slice(&[*usage, *selector, *matching_type]);
                out.extend_from_slice(data);
            }
            DNSData::SVCB(binding) => binding.encode(out),
            DNSData::Unknown(data) => out.extend_from_slice(data),
        }
    }

    /// The RDATA in its canonical form (RFC 4034 §6.2): uncompressed, the
    /// names of the types RFC 4034 §6.2 (as amended by RFC 6840 §5.1) lists lowercased.
    pub fn canonical(&self, kind: DNSType) -> Vec<u8> {
        let lowered = match self {
            DNSData::NS(name) => DNSData::NS(name.canonical()),
            DNSData::CNAME(name) => DNSData::CNAME(name.canonical()),
            DNSData::DNAME(name) => DNSData::DNAME(name.canonical()),
            DNSData::PTR(name) => DNSData::PTR(name.canonical()),
            DNSData::SOA(soa) => DNSData::SOA(Box::new(DNSSOA {
                mname: soa.mname.canonical(),
                rname: soa.rname.canonical(),
                ..(**soa).clone()
            })),
            DNSData::MX { preference, exchange } => {
                DNSData::MX { preference: *preference, exchange: exchange.canonical() }
            }
            DNSData::SRV { priority, weight, port, target } => {
                DNSData::SRV { priority: *priority, weight: *weight, port: *port, target: target.canonical() }
            }
            DNSData::NAPTR(naptr) => {
                DNSData::NAPTR(Box::new(DNSNAPTR { replacement: naptr.replacement.canonical(), ..(**naptr).clone() }))
            }
            DNSData::RRSIG(signature) => {
                DNSData::RRSIG(Box::new(DNSRRSIG { signer: signature.signer.canonical(), ..(**signature).clone() }))
            }
            DNSData::Unknown(data) => match DNSField::of(kind).and_then(|fields| DNSField::lowercase(fields, data)) {
                Some(lowered) => return lowered,
                None => return data.clone(),
            },
            other => other.clone(),
        };
        let mut out = Vec::new();
        lowered.encode(kind, &mut out, None);
        out
    }

    /// The data of type `kind` of the presentation format's `tokens` (RFC
    /// 1035 §5.1 and the RFC of each type), relative names under `origin`;
    /// `\# length hex` for any type (RFC 3597 §5).
    pub fn parse(kind: DNSType, tokens: &[DNSToken], origin: Option<&DNSName>) -> Result<DNSData, DNSError> {
        let syntax = DNSError::Syntax;
        if tokens.first().is_some_and(|token| !token.quoted && token.text == b"\\#") {
            let length: usize = tokens.get(1).ok_or(syntax("\\# without a length"))?.number()?;
            let hex: Vec<u8> = tokens[2..].iter().flat_map(|token| token.text.iter().copied()).collect();
            let data = if length == 0 { Vec::new() } else { DNSToken::hex(&hex)? };
            if data.len() != length {
                return Err(syntax("\\# of another length than its data"));
            }
            let mut message = Vec::new();
            message.extend_from_slice(&data);
            return DNSData::decode(kind, &message, 0, message.len()).or(Ok(DNSData::Unknown(data)));
        }
        let mut tokens = DNSTokens { tokens, origin };
        let value = match kind {
            DNSType::A => DNSData::A(tokens.word()?.parse().map_err(|_| syntax("not an IPv4 address"))?),
            DNSType::AAAA => DNSData::AAAA(tokens.word()?.parse().map_err(|_| syntax("not an IPv6 address"))?),
            DNSType::NS => DNSData::NS(tokens.name()?),
            DNSType::CNAME => DNSData::CNAME(tokens.name()?),
            DNSType::DNAME => DNSData::DNAME(tokens.name()?),
            DNSType::PTR => DNSData::PTR(tokens.name()?),
            DNSType::SOA => DNSData::SOA(Box::new(DNSSOA {
                mname: tokens.name()?,
                rname: tokens.name()?,
                serial: tokens.number()?,
                refresh: tokens.ttl()?,
                retry: tokens.ttl()?,
                expire: tokens.ttl()?,
                minimum: tokens.ttl()?,
            })),
            DNSType::MX => DNSData::MX { preference: tokens.number()?, exchange: tokens.name()? },
            DNSType::TXT => {
                let mut strings = Vec::new();
                while !tokens.is_empty() {
                    strings.push(tokens.string()?);
                }
                if strings.is_empty() {
                    return Err(syntax("TXT without a string"));
                }
                DNSData::TXT(strings)
            }
            DNSType::HINFO => DNSData::HINFO { cpu: tokens.string()?, os: tokens.string()? },
            DNSType::SRV => DNSData::SRV {
                priority: tokens.number()?,
                weight: tokens.number()?,
                port: tokens.number()?,
                target: tokens.name()?,
            },
            DNSType::NAPTR => DNSData::NAPTR(Box::new(DNSNAPTR {
                order: tokens.number()?,
                preference: tokens.number()?,
                flags: tokens.string()?,
                services: tokens.string()?,
                regexp: tokens.string()?,
                replacement: tokens.name()?,
            })),
            DNSType::CAA => {
                let flags = tokens.number()?;
                let tag = tokens.word()?.as_bytes().to_vec();
                if tag.is_empty() || !tag.iter().all(u8::is_ascii_alphanumeric) {
                    return Err(syntax("a CAA tag not of letters and digits"));
                }
                DNSData::CAA { flags, tag, value: tokens.string()? }
            }
            DNSType::DS | DNSType::CDS => DNSData::DS {
                key_tag: tokens.number()?,
                algorithm: tokens.number()?,
                digest_type: tokens.number()?,
                digest: DNSToken::hex(&tokens.joined())?,
            },
            DNSType::DNSKEY | DNSType::CDNSKEY => DNSData::DNSKEY {
                flags: tokens.number()?,
                protocol: tokens.number()?,
                algorithm: tokens.number()?,
                public_key: DNSToken::base64(&tokens.joined())?,
            },
            DNSType::RRSIG => DNSData::RRSIG(Box::new(DNSRRSIG {
                type_covered: DNSType::parse(tokens.word()?)?,
                algorithm: tokens.number()?,
                labels: tokens.number()?,
                original_ttl: tokens.number()?,
                expiration: DNSToken::time(tokens.word()?)?,
                inception: DNSToken::time(tokens.word()?)?,
                key_tag: tokens.number()?,
                signer: tokens.name()?,
                signature: DNSToken::base64(&tokens.joined())?,
            })),
            DNSType::NSEC => DNSData::NSEC { next: tokens.name()?, types: tokens.types()? },
            DNSType::NSEC3 => DNSData::NSEC3(Box::new(DNSNSEC3 {
                algorithm: tokens.number()?,
                flags: tokens.number()?,
                iterations: tokens.number()?,
                salt: tokens.salt()?,
                next_hashed: DNSToken::base32hex(tokens.word()?.as_bytes())?,
                types: tokens.types()?,
            })),
            DNSType::NSEC3PARAM => DNSData::NSEC3PARAM {
                algorithm: tokens.number()?,
                flags: tokens.number()?,
                iterations: tokens.number()?,
                salt: tokens.salt()?,
            },
            DNSType::TLSA => DNSData::TLSA {
                usage: tokens.number()?,
                selector: tokens.number()?,
                matching_type: tokens.number()?,
                data: DNSToken::hex(&tokens.joined())?,
            },
            DNSType::SVCB | DNSType::HTTPS => {
                let priority = tokens.number()?;
                let target = tokens.name()?;
                let rest = core::mem::take(&mut tokens.tokens);
                DNSData::SVCB(Box::new(DNSServiceBinding::parse_params(priority, target, rest)?))
            }
            _ => return Err(syntax("data of an unknown type not in \\# form")),
        };
        if !tokens.is_empty() {
            return Err(syntax("more fields than the type has"));
        }
        Ok(value)
    }

    /// The presentation format of the data (RFC 1035 §5.1 and each type's RFC).
    pub fn display(&self, kind: DNSType) -> DNSDataDisplay<'_> {
        DNSDataDisplay { data: self, kind }
    }
}

impl DNSRRSIG {
    /// The fields before the signature, in the wire form (RFC 4034 §3.1):
    /// what the signed data starts with (§3.1.8.1), the signer canonical.
    pub fn encode_fields(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.type_covered.0.to_be_bytes());
        out.extend_from_slice(&[self.algorithm, self.labels]);
        for value in [self.original_ttl, self.expiration, self.inception] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&self.key_tag.to_be_bytes());
        self.signer.encode(out, None);
    }
}

/// A field of the RDATA of a type kept as bytes ([`DNSData::Unknown`])
/// whose names matter: a receiver decompresses them (RFC 3597 §4) and the
/// canonical form lowercases them (RFC 4034 §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DNSField {
    Name,
    Bytes(usize),
    /// What is left.
    Rest,
}

impl DNSField {
    /// The fields of the RDATA of `kind`, for the types of names this crate
    /// keeps as bytes: MD, MF, MB, MG, MR (RFC 1035 §3.3), MINFO, RP (RFC
    /// 1183), AFSDB, RT, KX (RFC 2230), PX (RFC 2163), SIG (RFC 2535) and
    /// NXT (RFC 2535). A6 (RFC 2874), whose layout depends on its data, is
    /// not among them.
    pub fn of(kind: DNSType) -> Option<&'static [DNSField]> {
        Some(match kind.0 {
            3 | 4 | 7 | 8 | 9 => &[DNSField::Name],
            14 | 17 => &[DNSField::Name, DNSField::Name],
            18 | 21 | 36 => &[DNSField::Bytes(2), DNSField::Name],
            26 => &[DNSField::Bytes(2), DNSField::Name, DNSField::Name],
            24 => &[DNSField::Bytes(18), DNSField::Name, DNSField::Rest],
            30 => &[DNSField::Name, DNSField::Rest],
            _ => return None,
        })
    }

    /// The data of `fields` read by `reader`, its names uncompressed.
    pub fn read(fields: &[DNSField], reader: &mut DNSReader<'_>) -> Result<Vec<u8>, DNSError> {
        let mut out = Vec::new();
        for field in fields {
            match field {
                DNSField::Name => out.extend_from_slice(reader.name()?.wire()),
                DNSField::Bytes(count) => out.extend_from_slice(reader.bytes(*count)?),
                DNSField::Rest => out.extend_from_slice(reader.rest()),
            }
        }
        Ok(out)
    }

    /// `data`, of `fields`, its names lowercased; none if it is not of them.
    pub fn lowercase(fields: &[DNSField], data: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(data.len());
        let mut position = 0;
        for field in fields {
            match field {
                DNSField::Name => {
                    let (name, length) = DNSName::decode(data.get(position..)?, 0).ok()?;
                    out.extend_from_slice(name.canonical().wire());
                    position += length;
                }
                DNSField::Bytes(count) => {
                    out.extend_from_slice(data.get(position..position.checked_add(*count)?)?);
                    position += count;
                }
                DNSField::Rest => {
                    out.extend_from_slice(&data[position..]);
                    position = data.len();
                }
            }
        }
        (position == data.len()).then_some(out)
    }
}

/// A cursor over RDATA, for [`DNSData::decode`].
#[derive(Clone, Copy, Debug)]
pub struct DNSReader<'a> {
    pub message: &'a [u8],
    pub position: usize,
    pub end: usize,
    /// Whether names may be compressed.
    pub compressed: bool,
}

impl<'a> DNSReader<'a> {
    pub fn is_empty(&self) -> bool {
        self.position >= self.end
    }

    pub fn bytes(&mut self, count: usize) -> Result<&'a [u8], DNSError> {
        let end = self.position.checked_add(count).filter(|end| *end <= self.end);
        let end = end.ok_or(DNSError::Malformed("RDATA cut short"))?;
        let bytes = &self.message[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    pub fn u8(&mut self) -> Result<u8, DNSError> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, DNSError> {
        Ok(u16::from_be_bytes(self.bytes(2)?.try_into().unwrap_or_default()))
    }

    pub fn u32(&mut self) -> Result<u32, DNSError> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into().unwrap_or_default()))
    }

    /// A character-string: a length byte, then its bytes (RFC 1035 §3.3).
    pub fn string(&mut self) -> Result<Vec<u8>, DNSError> {
        let length = self.u8()? as usize;
        Ok(self.bytes(length)?.to_vec())
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let rest = &self.message[self.position..self.end];
        self.position = self.end;
        rest
    }

    /// A name: within the RDATA unless compressed, when a pointer may reach the message before.
    pub fn name(&mut self) -> Result<DNSName, DNSError> {
        let (name, next) = if self.compressed {
            DNSName::decode(self.message, self.position)?
        } else {
            let (name, length) = DNSName::decode(&self.message[self.position..self.end], 0)
                .map_err(|_| DNSError::Malformed("a name of RDATA that is compressed or cut short"))?;
            (name, self.position + length)
        };
        if next > self.end {
            return Err(DNSError::Malformed("a name past its RDATA"));
        }
        self.position = next;
        Ok(name)
    }
}

/// The fields of presentation data being read, for [`DNSData::parse`].
#[derive(Clone, Copy, Debug)]
pub struct DNSTokens<'a> {
    pub tokens: &'a [DNSToken],
    pub origin: Option<&'a DNSName>,
}

impl<'a> DNSTokens<'a> {
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    pub fn token(&mut self) -> Result<&'a DNSToken, DNSError> {
        let (first, rest) = self.tokens.split_first().ok_or(DNSError::Syntax("a field missing"))?;
        self.tokens = rest;
        Ok(first)
    }

    /// A field of plain text (no escapes, not quoted).
    pub fn word(&mut self) -> Result<&'a str, DNSError> {
        let token = self.token()?;
        if token.quoted {
            return Err(DNSError::Syntax("a quoted string where a word is expected"));
        }
        core::str::from_utf8(&token.text).map_err(|_| DNSError::Syntax("a field not of text"))
    }

    pub fn number<T: core::str::FromStr>(&mut self) -> Result<T, DNSError> {
        self.token()?.number()
    }

    /// A TTL in seconds, or with units ("1h30m", BIND's form).
    pub fn ttl(&mut self) -> Result<u32, DNSError> {
        DNSToken::ttl(self.word()?)
    }

    pub fn name(&mut self) -> Result<DNSName, DNSError> {
        DNSName::parse(self.word()?, self.origin)
    }

    pub fn string(&mut self) -> Result<Vec<u8>, DNSError> {
        let text = self.token()?.unescaped()?;
        if text.len() > 255 {
            return Err(DNSError::Syntax("a character-string longer than 255 bytes"));
        }
        Ok(text)
    }

    /// An NSEC3 salt: "-" for none, else hexadecimal (RFC 5155 §3.3).
    pub fn salt(&mut self) -> Result<Vec<u8>, DNSError> {
        match self.word()? {
            "-" => Ok(Vec::new()),
            hex => DNSToken::hex(hex.as_bytes()),
        }
    }

    /// The rest of the fields, joined: base64 and hexadecimal may be split by spaces.
    pub fn joined(&mut self) -> Vec<u8> {
        let joined = self.tokens.iter().flat_map(|token| token.text.iter().copied()).collect();
        self.tokens = &[];
        joined
    }

    /// The rest of the fields, as the types of a bitmap.
    pub fn types(&mut self) -> Result<DNSTypeBitmap, DNSError> {
        let mut types = Vec::new();
        while !self.is_empty() {
            types.push(DNSType::parse(self.word()?)?);
        }
        Ok(DNSTypeBitmap::new(&types))
    }
}

/// The presentation format of [`DNSData`].
#[derive(Clone, Copy, Debug)]
pub struct DNSDataDisplay<'a> {
    pub data: &'a DNSData,
    pub kind: DNSType,
}

impl fmt::Display for DNSDataDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let quoted = |bytes: &[u8]| DNSToken::quote(bytes);
        let hex = |bytes: &[u8]| Base16::UPPER.encode(bytes);
        let base64 = |bytes: &[u8]| Base64::STANDARD.encode(bytes);
        match self.data {
            DNSData::A(address) => write!(f, "{address}"),
            DNSData::AAAA(address) => write!(f, "{address}"),
            DNSData::NS(name) | DNSData::CNAME(name) | DNSData::DNAME(name) | DNSData::PTR(name) => write!(f, "{name}"),
            DNSData::SOA(soa) => write!(
                f,
                "{} {} {} {} {} {} {}",
                soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
            ),
            DNSData::MX { preference, exchange } => write!(f, "{preference} {exchange}"),
            DNSData::TXT(strings) => {
                let texts: Vec<String> = strings.iter().map(|text| quoted(text)).collect();
                f.write_str(&texts.join(" "))
            }
            DNSData::HINFO { cpu, os } => write!(f, "{} {}", quoted(cpu), quoted(os)),
            DNSData::SRV { priority, weight, port, target } => write!(f, "{priority} {weight} {port} {target}"),
            DNSData::NAPTR(naptr) => write!(
                f,
                "{} {} {} {} {} {}",
                naptr.order,
                naptr.preference,
                quoted(&naptr.flags),
                quoted(&naptr.services),
                quoted(&naptr.regexp),
                naptr.replacement
            ),
            DNSData::CAA { flags, tag, value } => {
                write!(f, "{flags} {} {}", String::from_utf8_lossy(tag), quoted(value))
            }
            DNSData::DS { key_tag, algorithm, digest_type, digest } => {
                write!(f, "{key_tag} {algorithm} {digest_type} {}", hex(digest))
            }
            DNSData::DNSKEY { flags, protocol, algorithm, public_key } => {
                write!(f, "{flags} {protocol} {algorithm} {}", base64(public_key))
            }
            DNSData::RRSIG(signature) => write!(
                f,
                "{} {} {} {} {} {} {} {} {}",
                signature.type_covered,
                signature.algorithm,
                signature.labels,
                signature.original_ttl,
                DNSToken::format_time(signature.expiration),
                DNSToken::format_time(signature.inception),
                signature.key_tag,
                signature.signer,
                base64(&signature.signature)
            ),
            DNSData::NSEC { next, types } => write!(f, "{next}{types}"),
            DNSData::NSEC3(nsec3) => {
                let salt = if nsec3.salt.is_empty() { String::from("-") } else { hex(&nsec3.salt) };
                let next = Base32::HEX_NO_PADDING.encode(&nsec3.next_hashed);
                write!(f, "{} {} {} {salt} {next}{}", nsec3.algorithm, nsec3.flags, nsec3.iterations, nsec3.types)
            }
            DNSData::NSEC3PARAM { algorithm, flags, iterations, salt } => {
                let salt = if salt.is_empty() { String::from("-") } else { hex(salt) };
                write!(f, "{algorithm} {flags} {iterations} {salt}")
            }
            DNSData::TLSA { usage, selector, matching_type, data } => {
                write!(f, "{usage} {selector} {matching_type} {}", hex(data))
            }
            DNSData::SVCB(binding) => write!(f, "{binding}"),
            DNSData::Unknown(data) if data.is_empty() => f.write_str("\\# 0"),
            DNSData::Unknown(data) => write!(f, "\\# {} {}", data.len(), hex(data)),
        }
    }
}

impl DNSNSEC3 {
    /// The only hash algorithm, SHA-1 (RFC 5155 §11).
    pub const SHA1: u8 = 1;
    /// The flag of an NSEC3 that may cover unsigned delegations (RFC 5155 §3.1.2.1).
    pub const OPT_OUT: u8 = 1;

    /// The hash of `name` (RFC 5155 §5): the hash of its canonical wire
    /// form and the salt, then `iterations` more times of the hash and the
    /// salt. None for an algorithm other than SHA-1.
    pub fn digest(algorithm: u8, iterations: u16, salt: &[u8], name: &DNSName) -> Option<Vec<u8>> {
        if algorithm != DNSNSEC3::SHA1 {
            return None;
        }
        let mut hash = SHA1::default();
        hash.update(name.canonical().wire());
        hash.update(salt);
        let mut digest = hash.finalize_reset();
        for _ in 0..iterations {
            hash.update(&digest);
            hash.update(salt);
            digest = hash.finalize_reset();
        }
        Some(digest.to_vec())
    }

    /// The hash of `name` with this record's parameters.
    pub fn hash(&self, name: &DNSName) -> Option<Vec<u8>> {
        DNSNSEC3::digest(self.algorithm, self.iterations, &self.salt, name)
    }

    pub fn is_opt_out(&self) -> bool {
        self.flags & DNSNSEC3::OPT_OUT != 0
    }

    /// The owner of the NSEC3 of `hash` in `zone`: the hash in Base32 of
    /// the extended hex alphabet, as a label before the zone's name (RFC 5155 §3).
    pub fn owner(hash: &[u8], zone: &DNSName) -> Result<DNSName, DNSError> {
        let base32 = crate::codec::base::base32::Base32::new(
            crate::codec::base::base32::Base32::HEX_ALPHABET,
            crate::codec::base::Padding::Forbidden,
        );
        zone.prepend(base32.encode(hash).as_bytes())
    }

    /// The hash an NSEC3's owner `owner` names: its first label in Base32
    /// of the extended hex alphabet, of any case.
    pub fn owner_hash(owner: &DNSName) -> Option<Vec<u8>> {
        DNSToken::base32hex(owner.labels().next()?).ok()
    }
}
