use alloc::vec::Vec;

use crate::bytes::{Reader, Writer};

use super::{TLSError, TLSSignatureScheme, TLSVector};

/// A signature and its scheme: TLS 1.3's CertificateVerify (RFC 9846
/// §4.5.2), and TLS 1.2's `digitally-signed` struct of CertificateVerify
/// and ServerKeyExchange (RFC 5246 §4.7, §7.4.1.4.1), which has the same
/// form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLSCertificateVerify {
    pub algorithm: TLSSignatureScheme,
    pub signature: Vec<u8>,
}

impl TLSCertificateVerify {
    pub fn decode(reader: &mut Reader<'_>) -> Result<TLSCertificateVerify, TLSError> {
        let algorithm = TLSSignatureScheme(reader.read_be().map_err(|_| TLSError::decode())?);
        let signature = TLSVector::read(reader, 2, 0, 0xFFFF)?.to_vec();
        Ok(TLSCertificateVerify { algorithm, signature })
    }

    /// The CertificateVerify of a handshake message's whole body.
    pub fn decode_body(body: &[u8]) -> Result<TLSCertificateVerify, TLSError> {
        let mut reader = Reader::new(body);
        let verify = TLSCertificateVerify::decode(&mut reader)?;
        TLSVector::finish(&reader)?;
        Ok(verify)
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        out.write_be(self.algorithm.0)?;
        TLSVector::write(out, 2, 0xFFFF, &self.signature)
    }
}

/// A Finished message: its `verify_data` (RFC 9846 §4.5.3, RFC 5246
/// §7.4.9).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLSFinished {
    pub verify_data: Vec<u8>,
}

impl TLSFinished {
    /// The Finished of a body of `length` bytes, the length of the hash in
    /// TLS 1.3 and 12 in TLS 1.2; fails with `decode_error` otherwise.
    pub fn decode(body: &[u8], length: usize) -> Result<TLSFinished, TLSError> {
        if body.len() != length {
            return Err(TLSError::decode());
        }
        Ok(TLSFinished { verify_data: body.to_vec() })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        Ok(out.write(&self.verify_data)?)
    }
}
