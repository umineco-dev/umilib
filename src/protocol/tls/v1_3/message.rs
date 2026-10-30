use alloc::vec::Vec;

use crate::bytes::{Reader, Writer};
use crate::protocol::tls::{TLSError, TLSExtension, TLSVector};

/// EncryptedExtensions (RFC 9846 §4.4.1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TLS13EncryptedExtensions {
    pub extensions: Vec<TLSExtension>,
}

impl TLS13EncryptedExtensions {
    pub fn decode(body: &[u8]) -> Result<TLS13EncryptedExtensions, TLSError> {
        let mut reader = Reader::new(body);
        let extensions = TLSExtension::decode_list(&mut reader, 0)?;
        TLSVector::finish(&reader)?;
        Ok(TLS13EncryptedExtensions { extensions })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        TLSExtension::encode_list(&self.extensions, out)
    }
}

/// CertificateRequest (RFC 9846 §4.4.2).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TLS13CertificateRequest {
    pub context: Vec<u8>,
    pub extensions: Vec<TLSExtension>,
}

impl TLS13CertificateRequest {
    pub fn decode(body: &[u8]) -> Result<TLS13CertificateRequest, TLSError> {
        let mut reader = Reader::new(body);
        let context = TLSVector::read(&mut reader, 1, 0, 0xFF)?.to_vec();
        let extensions = TLSExtension::decode_list(&mut reader, 0)?;
        TLSVector::finish(&reader)?;
        Ok(TLS13CertificateRequest { context, extensions })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        TLSVector::write(out, 1, 0xFF, &self.context)?;
        TLSExtension::encode_list(&self.extensions, out)
    }
}

/// One certificate of a Certificate message: DER X.509 and its extensions
/// (RFC 9846 §4.5.1). Raw public keys (RFC 7250) are not negotiated.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLS13CertificateEntry {
    pub data: Vec<u8>,
    pub extensions: Vec<TLSExtension>,
}

/// Certificate (RFC 9846 §4.5.1): the request's context (empty in the
/// handshake), and the chain, the end-entity certificate first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TLS13Certificate {
    pub context: Vec<u8>,
    pub entries: Vec<TLS13CertificateEntry>,
}

impl TLS13Certificate {
    pub fn decode(body: &[u8]) -> Result<TLS13Certificate, TLSError> {
        let mut reader = Reader::new(body);
        let context = TLSVector::read(&mut reader, 1, 0, 0xFF)?.to_vec();
        let mut list = TLSVector::read_reader(&mut reader, 3, 0, 0xFF_FFFF)?;
        TLSVector::finish(&reader)?;
        let mut entries = Vec::new();
        while !list.is_empty() {
            let data = TLSVector::read(&mut list, 3, 1, 0xFF_FFFF)?.to_vec();
            let extensions = TLSExtension::decode_list(&mut list, 0)?;
            entries.push(TLS13CertificateEntry { data, extensions });
        }
        Ok(TLS13Certificate { context, entries })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        TLSVector::write(out, 1, 0xFF, &self.context)?;
        TLSVector::write_with(out, 3, 0xFF_FFFF, |list| {
            for entry in &self.entries {
                TLSVector::write(list, 3, 0xFF_FFFF, &entry.data)?;
                TLSExtension::encode_list(&entry.extensions, list)?;
            }
            Ok(())
        })
    }
}

/// NewSessionTicket (RFC 9846 §4.7.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLS13NewSessionTicket {
    /// Seconds, at most 604800 (seven days).
    pub lifetime: u32,
    pub age_add: u32,
    pub nonce: Vec<u8>,
    pub ticket: Vec<u8>,
    pub extensions: Vec<TLSExtension>,
}

impl TLS13NewSessionTicket {
    /// The longest lifetime: seven days (RFC 9846 §4.7.1).
    pub const MAXIMUM_LIFETIME: u32 = 604_800;

    /// Fails with `illegal_parameter` for a lifetime above seven days (RFC 9846 §4.7.1).
    pub fn decode(body: &[u8]) -> Result<TLS13NewSessionTicket, TLSError> {
        let mut reader = Reader::new(body);
        let lifetime = reader.read_be().map_err(|_| TLSError::decode())?;
        let age_add = reader.read_be().map_err(|_| TLSError::decode())?;
        let nonce = TLSVector::read(&mut reader, 1, 0, 0xFF)?.to_vec();
        let ticket = TLSVector::read(&mut reader, 2, 1, 0xFFFF)?.to_vec();
        let extensions = TLSExtension::decode_list(&mut reader, 0)?;
        TLSVector::finish(&reader)?;
        if lifetime > TLS13NewSessionTicket::MAXIMUM_LIFETIME {
            return Err(TLSError::illegal());
        }
        Ok(TLS13NewSessionTicket { lifetime, age_add, nonce, ticket, extensions })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        out.write_be(self.lifetime)?;
        out.write_be(self.age_add)?;
        TLSVector::write(out, 1, 0xFF, &self.nonce)?;
        TLSVector::write(out, 2, 0xFFFF, &self.ticket)?;
        TLSExtension::encode_list(&self.extensions, out)
    }
}

/// KeyUpdate (RFC 9846 §4.7.3): whether the peer is asked to update too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TLS13KeyUpdate {
    pub request_update: bool,
}

impl TLS13KeyUpdate {
    /// Fails with `illegal_parameter` for a value other than 0 or 1 (RFC 9846 §4.7.3).
    pub fn decode(body: &[u8]) -> Result<TLS13KeyUpdate, TLSError> {
        match body {
            [0] => Ok(TLS13KeyUpdate { request_update: false }),
            [1] => Ok(TLS13KeyUpdate { request_update: true }),
            [_] => Err(TLSError::illegal()),
            _ => Err(TLSError::decode()),
        }
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        Ok(out.write_u8(self.request_update as u8)?)
    }
}
