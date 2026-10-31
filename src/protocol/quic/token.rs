use alloc::vec::Vec;

use crate::bytes::{Reader, Writer};
use crate::crypto::random::Random;
use crate::protocol::ip::IPEndpoint;
use crate::protocol::tls::{TLSAEAD, TLSAEADAlgorithm};

use super::{QUICConnectionID, QUICError, QUICVersion};

/// What a server's token says (RFC 9000 §8.1): a Retry token binds the
/// original Destination Connection ID and the Retry's Source Connection ID;
/// a NEW_TOKEN token only the address and the version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QUICTokenKind {
    Retry { original_destination: QUICConnectionID, retry_source: QUICConnectionID },
    NewToken,
}

/// A token's content: its kind, the client's address it validates (with
/// the port for a Retry token, which the same attempt keeps; without it for
/// NEW_TOKEN, as later connections come from other ports), the version it
/// was issued for (RFC 9369 §5), and when, in seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QUICToken {
    pub kind: QUICTokenKind,
    pub address: IPEndpoint,
    pub version: QUICVersion,
    pub time: u64,
}

/// The key that seals a server's tokens (RFC 9000 §8.1.4): AES-256-GCM
/// under a key of the deployment, with a random nonce, so that only the
/// servers that share it can read and trust them.
#[derive(Debug)]
pub struct QUICTokenKey {
    pub aead: TLSAEAD,
}

impl QUICTokenKey {
    /// The first byte of each token, so that tokens of other formats are told apart.
    pub const FORMAT: u8 = 1;
    /// The default of `QUICEndpointConfig::retry_token_lifetime`, in seconds:
    /// long enough for one round trip, short enough to limit replay.
    pub const RETRY_LIFETIME: u64 = 10;
    /// The default of `QUICEndpointConfig::new_token_lifetime`, in seconds: one day.
    pub const NEW_TOKEN_LIFETIME: u64 = 86_400;

    pub fn new(key: &[u8; 32]) -> Result<QUICTokenKey, QUICError> {
        Ok(QUICTokenKey { aead: TLSAEAD::new(TLSAEADAlgorithm::AES256GCM, key).map_err(|_| QUICError::Config)? })
    }

    /// Seals `token`.
    pub fn seal(&self, token: &QUICToken, random: &mut (dyn Random + Send)) -> Result<Vec<u8>, QUICError> {
        let mut plaintext = Vec::new();
        match token.kind {
            QUICTokenKind::Retry { original_destination, retry_source } => {
                plaintext.push(0);
                plaintext.push(original_destination.len() as u8);
                plaintext.extend_from_slice(original_destination.as_slice());
                plaintext.push(retry_source.len() as u8);
                plaintext.extend_from_slice(retry_source.as_slice());
                plaintext.write_be(token.address.port)?;
            }
            QUICTokenKind::NewToken => plaintext.push(1),
        }
        plaintext.write_be(token.version.0)?;
        plaintext.write_be(token.time)?;
        let mut nonce = [0u8; 12];
        random.fill(&mut nonce).map_err(|_| QUICError::Random)?;
        let mut out = alloc::vec![QUICTokenKey::FORMAT];
        out.extend_from_slice(&nonce);
        let associated = QUICTokenKey::associated(&token.address);
        let mut sealed = plaintext;
        self.aead.seal(&nonce, &associated, &mut sealed).map_err(|_| QUICError::Config)?;
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// The content of `bytes` if this key sealed it for a client at
    /// `address`; `None` for any other token.
    pub fn open(&self, bytes: &[u8], address: &IPEndpoint) -> Option<QUICToken> {
        let (&format, rest) = bytes.split_first()?;
        if format != QUICTokenKey::FORMAT || rest.len() < 12 {
            return None;
        }
        let (nonce, sealed) = rest.split_at(12);
        let mut plaintext = sealed.to_vec();
        self.aead.open(nonce, &QUICTokenKey::associated(address), &mut plaintext).ok()?;
        let mut reader = Reader::new(&plaintext);
        let kind = match reader.read_u8().ok()? {
            0 => {
                let length = reader.read_u8().ok()? as usize;
                let original_destination = QUICConnectionID::new(reader.read_slice(length).ok()?)?;
                let length = reader.read_u8().ok()? as usize;
                let retry_source = QUICConnectionID::new(reader.read_slice(length).ok()?)?;
                if reader.read_be::<u16>().ok()? != address.port {
                    return None;
                }
                QUICTokenKind::Retry { original_destination, retry_source }
            }
            1 => QUICTokenKind::NewToken,
            _ => return None,
        };
        let version = QUICVersion(reader.read_be().ok()?);
        let time = reader.read_be().ok()?;
        reader.is_empty().then_some(QUICToken { kind, address: *address, version, time })
    }

    /// The associated data: the client's address, which the token validates.
    pub fn associated(address: &IPEndpoint) -> Vec<u8> {
        let mut associated = Vec::with_capacity(17);
        match address.address {
            crate::protocol::ip::IPAddress::V4(address) => {
                associated.push(4);
                associated.extend_from_slice(&address.0);
            }
            crate::protocol::ip::IPAddress::V6(address) => {
                associated.push(6);
                associated.extend_from_slice(&address.0);
            }
        }
        associated
    }
}
