use alloc::vec::Vec;

use crate::auth::cert::key::KeyAlgorithm;
use crate::bytes::{Reader, Writer};
use crate::protocol::tls::{TLSCertificateVerify, TLSError, TLSNamedGroup, TLSSignatureScheme, TLSVector};

/// Certificate of TLS 1.2 (RFC 5246 §7.4.2): the chain, the end-entity
/// certificate first, without extensions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TLS12Certificate {
    pub chain: Vec<Vec<u8>>,
}

impl TLS12Certificate {
    pub fn decode(body: &[u8]) -> Result<TLS12Certificate, TLSError> {
        let mut reader = Reader::new(body);
        let mut list = TLSVector::read_reader(&mut reader, 3, 0, 0xFF_FFFF)?;
        TLSVector::finish(&reader)?;
        let mut chain = Vec::new();
        while !list.is_empty() {
            chain.push(TLSVector::read(&mut list, 3, 1, 0xFF_FFFF)?.to_vec());
        }
        Ok(TLS12Certificate { chain })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        TLSVector::write_with(out, 3, 0xFF_FFFF, |list| {
            self.chain.iter().try_for_each(|certificate| TLSVector::write(list, 3, 0xFF_FFFF, certificate))
        })
    }
}

/// ServerKeyExchange of the ECDHE key exchanges (RFC 8422 §5.4): the named
/// curve, the server's public key, and its signature of both randoms and
/// the parameters.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLS12ServerKeyExchange {
    pub group: TLSNamedGroup,
    pub public: Vec<u8>,
    pub signature: TLSCertificateVerify,
}

impl TLS12ServerKeyExchange {
    /// `ECCurveType` named_curve (RFC 8422 §5.4): the only one allowed.
    pub const NAMED_CURVE: u8 = 3;

    /// Fails with `illegal_parameter` for a curve type other than named_curve.
    pub fn decode(body: &[u8]) -> Result<TLS12ServerKeyExchange, TLSError> {
        let mut reader = Reader::new(body);
        if reader.read_u8().map_err(|_| TLSError::decode())? != TLS12ServerKeyExchange::NAMED_CURVE {
            return Err(TLSError::illegal());
        }
        let group = TLSNamedGroup(reader.read_be().map_err(|_| TLSError::decode())?);
        let public = TLSVector::read(&mut reader, 1, 1, 0xFF)?.to_vec();
        let signature = TLSCertificateVerify::decode(&mut reader)?;
        TLSVector::finish(&reader)?;
        Ok(TLS12ServerKeyExchange { group, public, signature })
    }

    /// The `ServerECDHParams`: what is signed after both randoms.
    pub fn parameters(group: TLSNamedGroup, public: &[u8]) -> Result<Vec<u8>, TLSError> {
        let mut parameters = Vec::with_capacity(4 + public.len());
        parameters.push(TLS12ServerKeyExchange::NAMED_CURVE);
        parameters.extend_from_slice(&group.0.to_be_bytes());
        TLSVector::write(&mut parameters, 1, 0xFF, public)?;
        Ok(parameters)
    }

    /// What the server signs: client_random + server_random + params (RFC 8422 §5.4).
    pub fn signed(client_random: &[u8; 32], server_random: &[u8; 32], parameters: &[u8]) -> Vec<u8> {
        [client_random.as_slice(), server_random.as_slice(), parameters].concat()
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        out.write(&TLS12ServerKeyExchange::parameters(self.group, &self.public)?)?;
        self.signature.encode(out)
    }
}

/// ClientKeyExchange of the ECDHE key exchanges (RFC 8422 §5.7): the
/// client's public key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLS12ClientKeyExchange {
    pub public: Vec<u8>,
}

impl TLS12ClientKeyExchange {
    pub fn decode(body: &[u8]) -> Result<TLS12ClientKeyExchange, TLSError> {
        let mut reader = Reader::new(body);
        let public = TLSVector::read(&mut reader, 1, 1, 0xFF)?.to_vec();
        TLSVector::finish(&reader)?;
        Ok(TLS12ClientKeyExchange { public })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        TLSVector::write(out, 1, 0xFF, &self.public)
    }
}

/// CertificateRequest of TLS 1.2 (RFC 5246 §7.4.4): the kinds of
/// certificates, the signature schemes, and the CAs' names accepted.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TLS12CertificateRequest {
    /// `ClientCertificateType`s: rsa_sign (1), ecdsa_sign (64).
    pub types: Vec<u8>,
    pub schemes: Vec<TLSSignatureScheme>,
    /// DER `Name`s.
    pub authorities: Vec<Vec<u8>>,
}

impl TLS12CertificateRequest {
    pub const RSA_SIGN: u8 = 1;
    pub const ECDSA_SIGN: u8 = 64;

    /// Whether a certificate's key of `key` is of a type asked for: rsa_sign
    /// for RSA keys, ecdsa_sign for ECDSA and EdDSA keys (RFC 5246 §7.4.4,
    /// RFC 8422 §5.5).
    pub fn accepts(&self, key: &KeyAlgorithm) -> bool {
        let kind = match key {
            KeyAlgorithm::RSA | KeyAlgorithm::RSAPSS(_) => TLS12CertificateRequest::RSA_SIGN,
            KeyAlgorithm::EC(_) | KeyAlgorithm::Ed25519 | KeyAlgorithm::Ed448 => TLS12CertificateRequest::ECDSA_SIGN,
            _ => return false,
        };
        self.types.contains(&kind)
    }

    pub fn decode(body: &[u8]) -> Result<TLS12CertificateRequest, TLSError> {
        let mut reader = Reader::new(body);
        let types = TLSVector::read(&mut reader, 1, 1, 0xFF)?.to_vec();
        let schemes = TLSVector::read_u16s(&mut reader, 2, 2, 0xFFFE)?.into_iter().map(TLSSignatureScheme).collect();
        let mut list = TLSVector::read_reader(&mut reader, 2, 0, 0xFFFF)?;
        TLSVector::finish(&reader)?;
        let mut authorities = Vec::new();
        while !list.is_empty() {
            authorities.push(TLSVector::read(&mut list, 2, 1, 0xFFFF)?.to_vec());
        }
        Ok(TLS12CertificateRequest { types, schemes, authorities })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        TLSVector::write(out, 1, 0xFF, &self.types)?;
        let values: Vec<u16> = self.schemes.iter().map(|scheme| scheme.0).collect();
        TLSVector::write_u16s(out, 2, 0xFFFE, &values)?;
        TLSVector::write_with(out, 2, 0xFFFF, |list| {
            self.authorities.iter().try_for_each(|name| TLSVector::write(list, 2, 0xFFFF, name))
        })
    }
}
