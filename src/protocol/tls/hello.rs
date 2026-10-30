use alloc::vec::Vec;

use crate::bytes::{Buffer, Reader, Writer};

use super::{TLSCipherSuite, TLSError, TLSExtension, TLSExtensionType, TLSVector, TLSVersion};

/// A ClientHello (RFC 9846 §4.2.2, RFC 5246 §7.4.1.2). One type serves
/// both versions: TLS 1.3 kept the format and moved its negotiation into
/// extensions. The extension block may be absent in TLS 1.2, which reads as
/// an empty list.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLSClientHello {
    pub legacy_version: TLSVersion,
    pub random: [u8; 32],
    pub legacy_session_id: Vec<u8>,
    pub cipher_suites: Vec<TLSCipherSuite>,
    pub legacy_compression_methods: Vec<u8>,
    pub extensions: Vec<TLSExtension>,
}

impl TLSClientHello {
    /// Reads the body of a ClientHello. Fails with `decode_error` for
    /// malformed vectors and with `illegal_parameter` for two extensions
    /// of one type.
    pub fn decode(body: &[u8]) -> Result<TLSClientHello, TLSError> {
        let mut reader = Reader::new(body);
        let hello = TLSClientHello::read(&mut reader, true)?;
        TLSVector::finish(&reader)?;
        Ok(hello)
    }

    /// Reads a ClientHello from `reader`, leaving what follows it. Without
    /// `optional_extensions` the extension block must be there, as in TLS
    /// 1.3 and in an EncodedClientHelloInner, which padding follows (RFC
    /// 9849 §5.1).
    pub fn read(reader: &mut Reader<'_>, optional_extensions: bool) -> Result<TLSClientHello, TLSError> {
        let legacy_version = TLSVersion(reader.read_be().map_err(|_| TLSError::decode())?);
        let random = reader.read_array().map_err(|_| TLSError::decode())?;
        let legacy_session_id = TLSVector::read(reader, 1, 0, 32)?.to_vec();
        let cipher_suites = TLSVector::read_u16s(reader, 2, 2, 0xFFFE)?.into_iter().map(TLSCipherSuite).collect();
        let legacy_compression_methods = TLSVector::read(reader, 1, 1, 0xFF)?.to_vec();
        let extensions =
            if optional_extensions && reader.is_empty() { Vec::new() } else { TLSExtension::decode_list(reader, 0)? };
        Ok(TLSClientHello {
            legacy_version,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions,
        })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        out.write_be(self.legacy_version.0)?;
        out.write(&self.random)?;
        TLSVector::write(out, 1, 32, &self.legacy_session_id)?;
        let suites: Vec<u16> = self.cipher_suites.iter().map(|suite| suite.0).collect();
        TLSVector::write_u16s(out, 2, 0xFFFE, &suites)?;
        TLSVector::write(out, 1, 0xFF, &self.legacy_compression_methods)?;
        TLSExtension::encode_list(&self.extensions, out)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, TLSError> {
        let mut body = Buffer::new();
        self.encode(&mut body)?;
        Ok(body.into_vec())
    }

    /// The data of the extension of `kind`, if any.
    pub fn extension(&self, kind: TLSExtensionType) -> Option<&[u8]> {
        TLSExtension::find(&self.extensions, kind)
    }
}

/// A ServerHello, or a HelloRetryRequest, which is a ServerHello whose
/// `random` is [`TLSServerHello::RETRY_RANDOM`] (RFC 9846 §4.2.3, §4.2.4).
/// The extension block may be absent in TLS 1.2, which reads as an empty
/// list; an empty list is written as no block.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLSServerHello {
    pub legacy_version: TLSVersion,
    pub random: [u8; 32],
    pub legacy_session_id_echo: Vec<u8>,
    pub cipher_suite: TLSCipherSuite,
    pub legacy_compression_method: u8,
    pub extensions: Vec<TLSExtension>,
}

impl TLSServerHello {
    /// The random of a HelloRetryRequest: SHA-256 of "HelloRetryRequest" (RFC 9846 §4.2.3).
    pub const RETRY_RANDOM: [u8; 32] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2,
        0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ];
    /// The last 8 bytes of the random of a TLS 1.3 server that negotiates
    /// TLS 1.2 (RFC 9846 §4.2.3).
    pub const DOWNGRADE_TLS1_2: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
    /// The same for TLS 1.1 or below.
    pub const DOWNGRADE_TLS1_1: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];

    pub fn decode(body: &[u8]) -> Result<TLSServerHello, TLSError> {
        let mut reader = Reader::new(body);
        let legacy_version = TLSVersion(reader.read_be().map_err(|_| TLSError::decode())?);
        let random = reader.read_array().map_err(|_| TLSError::decode())?;
        let legacy_session_id_echo = TLSVector::read(&mut reader, 1, 0, 32)?.to_vec();
        let cipher_suite = TLSCipherSuite(reader.read_be().map_err(|_| TLSError::decode())?);
        let legacy_compression_method = reader.read_u8().map_err(|_| TLSError::decode())?;
        let extensions = if reader.is_empty() { Vec::new() } else { TLSExtension::decode_list(&mut reader, 0)? };
        TLSVector::finish(&reader)?;
        Ok(TLSServerHello {
            legacy_version,
            random,
            legacy_session_id_echo,
            cipher_suite,
            legacy_compression_method,
            extensions,
        })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        out.write_be(self.legacy_version.0)?;
        out.write(&self.random)?;
        TLSVector::write(out, 1, 32, &self.legacy_session_id_echo)?;
        out.write_be(self.cipher_suite.0)?;
        out.write_u8(self.legacy_compression_method)?;
        if !self.extensions.is_empty() {
            TLSExtension::encode_list(&self.extensions, out)?;
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, TLSError> {
        let mut body = Buffer::new();
        self.encode(&mut body)?;
        Ok(body.into_vec())
    }

    /// Whether this is a HelloRetryRequest.
    pub fn is_retry(&self) -> bool {
        self.random == TLSServerHello::RETRY_RANDOM
    }

    /// The data of the extension of `kind`, if any.
    pub fn extension(&self, kind: TLSExtensionType) -> Option<&[u8]> {
        TLSExtension::find(&self.extensions, kind)
    }
}
