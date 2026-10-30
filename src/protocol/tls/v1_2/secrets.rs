use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::protocol::tls::{TLSAEADAlgorithm, TLSAlertDescription, TLSCipherSuite, TLSError, TLSTranscript};
use crate::secret::{ConstantTimeEq, Secret};

use super::{TLS12PRF, TLS12RecordProtection};

/// The secrets of a TLS 1.2 handshake once the key exchange is done: the
/// main secret and the record protection of both directions (RFC 5246 §6.3,
/// §8.1, RFC 7627).
pub struct TLS12Secrets {
    pub prf: TLS12PRF,
    pub aead: TLSAEADAlgorithm,
    pub main: Secret<Vec<u8>>,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
}

impl TLS12Secrets {
    /// The secrets of `suite` from the preliminary secret, with the session
    /// hash of the extended main secret if it was negotiated.
    pub fn new(
        suite: TLSCipherSuite,
        preliminary: &[u8],
        session_hash: Option<&[u8]>,
        client_random: [u8; 32],
        server_random: [u8; 32],
    ) -> Result<TLS12Secrets, TLSError> {
        let (Some(hash), Some(aead)) = (suite.hash(), suite.aead()) else {
            return Err(TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR));
        };
        let prf = TLS12PRF::new(hash);
        let main = prf.main_secret(preliminary, session_hash, &client_random, &server_random);
        Ok(TLS12Secrets { prf, aead, main, client_random, server_random })
    }

    /// The record protection of the client's and the server's writes, from
    /// the key block: client key, server key, client IV, server IV (RFC
    /// 5246 §6.3; AEADs have no MAC keys).
    pub fn protections(&self) -> Result<(Box<TLS12RecordProtection>, Box<TLS12RecordProtection>), TLSError> {
        let (key, iv) = (self.aead.key_length(), TLS12RecordProtection::iv_length(self.aead));
        let block = self.prf.key_block(self.main.expose(), &self.client_random, &self.server_random, 2 * (key + iv));
        let block = block.expose();
        let client = TLS12RecordProtection::new(self.aead, &block[..key], &block[2 * key..2 * key + iv])?;
        let server = TLS12RecordProtection::new(self.aead, &block[key..2 * key], &block[2 * key + iv..])?;
        Ok((Box::new(client), Box::new(server)))
    }

    /// The `verify_data` of the client's or the server's Finished.
    pub fn finished(&self, client: bool, transcript: &TLSTranscript) -> Vec<u8> {
        self.prf.finished(self.main.expose(), client, &transcript.hash())
    }

    /// Checks a peer's Finished in constant time (`decrypt_error`, RFC 5246 §7.4.9).
    pub fn check_finished(&self, client: bool, body: &[u8], transcript: &TLSTranscript) -> Result<(), TLSError> {
        let expected = self.finished(client, transcript);
        if body.len() != expected.len() || !body.ct_eq(expected.as_slice()).into_bool() {
            return Err(TLSError::Protocol(TLSAlertDescription::DECRYPT_ERROR));
        }
        Ok(())
    }
}
