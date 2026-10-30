use alloc::vec;
use alloc::vec::Vec;

use crate::bytes::{Buffer, Writer};
use crate::crypto::hkdf::HKDF;
use crate::hash::sha::v2::{SHA256, SHA384};
use crate::protocol::tls::{TLSAlertDescription, TLSError, TLSHashAlgorithm, TLSVector};
use crate::secret::Secret;

/// The key schedule of TLS 1.3 (RFC 9846 §7.1): HKDF-Extract and
/// HKDF-Expand-Label over the hash of the cipher suite, and the secrets of
/// Figure 5.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TLS13KeySchedule {
    pub hash: TLSHashAlgorithm,
}

impl TLS13KeySchedule {
    pub fn new(hash: TLSHashAlgorithm) -> TLS13KeySchedule {
        TLS13KeySchedule { hash }
    }

    /// HKDF-Extract(salt, ikm) (RFC 5869 §2.2); an empty salt or IKM is the
    /// string of Hash.length zeros the key schedule calls "0".
    pub fn extract(&self, salt: &[u8], ikm: &[u8]) -> Secret<Vec<u8>> {
        let zeros = vec![0u8; self.hash.length()];
        let salt = if salt.is_empty() { &zeros } else { salt };
        let ikm = if ikm.is_empty() { &zeros } else { ikm };
        Secret::new(match self.hash {
            TLSHashAlgorithm::SHA256 => HKDF::<SHA256>::extract(salt, ikm).to_vec(),
            TLSHashAlgorithm::SHA384 => HKDF::<SHA384>::extract(salt, ikm).to_vec(),
        })
    }

    /// HKDF-Expand-Label(secret, label, context, length) (RFC 9846 §7.1):
    /// the label is prefixed with "tls13 ".
    pub fn expand_label(
        &self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<Secret<Vec<u8>>, TLSError> {
        let internal = |_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR);
        let mut info = Buffer::new();
        info.write_be(length as u16)?;
        let mut full = Vec::with_capacity(6 + label.len());
        full.extend_from_slice(b"tls13 ");
        full.extend_from_slice(label);
        TLSVector::write(&mut info, 1, 255, &full)?;
        TLSVector::write(&mut info, 1, 255, context)?;
        let mut out = Secret::new(vec![0u8; length]);
        match self.hash {
            TLSHashAlgorithm::SHA256 => {
                HKDF::<SHA256>::new(secret).map_err(internal)?.expand(info.as_slice(), out.expose_mut())
            }
            TLSHashAlgorithm::SHA384 => {
                HKDF::<SHA384>::new(secret).map_err(internal)?.expand(info.as_slice(), out.expose_mut())
            }
        }
        .map_err(internal)?;
        Ok(out)
    }

    /// Derive-Secret(secret, label, messages), given the transcript hash of the messages.
    pub fn derive_secret(
        &self,
        secret: &[u8],
        label: &[u8],
        transcript_hash: &[u8],
    ) -> Result<Secret<Vec<u8>>, TLSError> {
        self.expand_label(secret, label, transcript_hash, self.hash.length())
    }

    /// The Early Secret: HKDF-Extract(0, PSK), the PSK being "0" without one.
    pub fn early_secret(&self, psk: Option<&[u8]>) -> Secret<Vec<u8>> {
        self.extract(&[], psk.unwrap_or(&[]))
    }

    /// The secret that follows `secret`: HKDF-Extract(Derive-Secret(secret,
    /// "derived", ""), ikm) — the Handshake Secret with the shared secret,
    /// the Main Secret with "0".
    pub fn next_secret(&self, secret: &[u8], ikm: &[u8]) -> Result<Secret<Vec<u8>>, TLSError> {
        let empty = self.hash.digest(&[]);
        let salt = self.derive_secret(secret, b"derived", &empty)?;
        Ok(self.extract(salt.expose(), ikm))
    }

    /// The write key and IV of a traffic secret (RFC 9846 §7.3).
    pub fn traffic_keys(&self, secret: &[u8], key_length: usize) -> Result<TLS13TrafficKeys, TLSError> {
        Ok(TLS13TrafficKeys {
            key: self.expand_label(secret, b"key", &[], key_length)?,
            iv: self.expand_label(secret, b"iv", &[], 12)?,
        })
    }

    /// The `verify_data` of a Finished message: HMAC(finished_key,
    /// transcript hash), finished_key = HKDF-Expand-Label(base, "finished",
    /// "", Hash.length) (RFC 9846 §4.5.3).
    pub fn finished(&self, base: &[u8], transcript_hash: &[u8]) -> Result<Vec<u8>, TLSError> {
        let key = self.expand_label(base, b"finished", &[], self.hash.length())?;
        Ok(self.hash.hmac(key.expose(), transcript_hash))
    }

    /// The next application traffic secret (RFC 9846 §7.2).
    pub fn next_traffic_secret(&self, secret: &[u8]) -> Result<Secret<Vec<u8>>, TLSError> {
        self.expand_label(secret, b"traffic upd", &[], self.hash.length())
    }

    /// TLS-Exporter(label, context, length) of `secret` (RFC 9846 §7.5): no
    /// context and an empty context give the same value.
    pub fn export(&self, secret: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) -> Result<(), TLSError> {
        let empty = self.hash.digest(&[]);
        let derived = self.derive_secret(secret, label, &empty)?;
        let value = self.expand_label(derived.expose(), b"exporter", &self.hash.digest(context), out.len())?;
        out.copy_from_slice(value.expose());
        Ok(())
    }

    /// The PSK of a ticket: HKDF-Expand-Label(resumption_secret,
    /// "resumption", ticket_nonce, Hash.length) (RFC 9846 §4.7.1).
    pub fn resumption_psk(&self, resumption_secret: &[u8], nonce: &[u8]) -> Result<Secret<Vec<u8>>, TLSError> {
        self.expand_label(resumption_secret, b"resumption", nonce, self.hash.length())
    }
}

/// The write key and IV of a traffic secret (RFC 9846 §7.3).
#[derive(Clone, Debug)]
pub struct TLS13TrafficKeys {
    pub key: Secret<Vec<u8>>,
    pub iv: Secret<Vec<u8>>,
}
