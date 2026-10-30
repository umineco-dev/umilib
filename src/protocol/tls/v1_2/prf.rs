use alloc::vec::Vec;

use crate::protocol::tls::{TLSError, TLSHashAlgorithm, TLSVector};
use crate::secret::Secret;

/// The PRF of TLS 1.2 (RFC 5246 §5): P_hash with HMAC of the cipher
/// suite's hash, and what it derives: the main secret, with the extended
/// main secret of RFC 7627, the key block, Finished, and exporters (RFC 5705).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TLS12PRF {
    pub hash: TLSHashAlgorithm,
}

impl TLS12PRF {
    /// The length of the main secret.
    pub const MAIN_SECRET_LENGTH: usize = 48;
    /// The length of `verify_data` (RFC 5246 §7.4.9).
    pub const VERIFY_DATA_LENGTH: usize = 12;

    pub fn new(hash: TLSHashAlgorithm) -> TLS12PRF {
        TLS12PRF { hash }
    }

    /// PRF(secret, label, seed) of `length` bytes: P_hash(secret, label + seed).
    pub fn derive(&self, secret: &[u8], label: &[u8], seed: &[u8], length: usize) -> Secret<Vec<u8>> {
        let mut label_seed = Vec::with_capacity(label.len() + seed.len());
        label_seed.extend_from_slice(label);
        label_seed.extend_from_slice(seed);
        let mut out = Secret::new(Vec::with_capacity(length + self.hash.length()));
        // A(1) = HMAC(secret, label + seed); A(i) = HMAC(secret, A(i-1)). The
        // intermediate values are as secret as the output.
        let mut a = Secret::new(self.hash.hmac(secret, &label_seed));
        while out.expose().len() < length {
            let mut input = Secret::new(Vec::with_capacity(a.expose().len() + label_seed.len()));
            input.expose_mut().extend_from_slice(a.expose());
            input.expose_mut().extend_from_slice(&label_seed);
            let block = Secret::new(self.hash.hmac(secret, input.expose()));
            out.expose_mut().extend_from_slice(block.expose());
            a = Secret::new(self.hash.hmac(secret, a.expose()));
        }
        out.expose_mut().truncate(length);
        out
    }

    /// The main secret: with EMS, PRF(preliminary, "extended master
    /// secret", session_hash) (RFC 7627 §4); otherwise PRF(preliminary,
    /// "master secret", client_random + server_random) (RFC 5246 §8.1).
    /// The labels keep "master" for compatibility (RFC 9846 Appendix D).
    pub fn main_secret(
        &self,
        preliminary: &[u8],
        extended: Option<&[u8]>,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> Secret<Vec<u8>> {
        match extended {
            Some(session_hash) => {
                self.derive(preliminary, b"extended master secret", session_hash, TLS12PRF::MAIN_SECRET_LENGTH)
            }
            None => {
                let seed = [client_random.as_slice(), server_random.as_slice()].concat();
                self.derive(preliminary, b"master secret", &seed, TLS12PRF::MAIN_SECRET_LENGTH)
            }
        }
    }

    /// The key block (RFC 5246 §6.3): PRF(main, "key expansion",
    /// server_random + client_random).
    pub fn key_block(
        &self,
        main: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        length: usize,
    ) -> Secret<Vec<u8>> {
        let seed = [server_random.as_slice(), client_random.as_slice()].concat();
        self.derive(main, b"key expansion", &seed, length)
    }

    /// The `verify_data` of a Finished (RFC 5246 §7.4.9): of the client if
    /// `client`, over the hash of the handshake messages.
    pub fn finished(&self, main: &[u8], client: bool, transcript_hash: &[u8]) -> Vec<u8> {
        let label: &[u8] = if client { b"client finished" } else { b"server finished" };
        self.derive(main, label, transcript_hash, TLS12PRF::VERIFY_DATA_LENGTH).expose().clone()
    }

    /// The exporter of RFC 5705 §4: PRF(main, label, client_random +
    /// server_random, and the context with its 16-bit length if there is
    /// one). A context of 2^16 bytes or more cannot be encoded: it fails.
    pub fn export(
        &self,
        main: &[u8],
        label: &[u8],
        context: Option<&[u8]>,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        out: &mut [u8],
    ) -> Result<(), TLSError> {
        let mut seed = [client_random.as_slice(), server_random.as_slice()].concat();
        if let Some(context) = context {
            TLSVector::write(&mut seed, 2, 0xFFFF, context)?;
        }
        out.copy_from_slice(self.derive(main, label, &seed, out.len()).expose());
        Ok(())
    }
}
