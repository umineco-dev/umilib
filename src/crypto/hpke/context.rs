use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use super::{HPKEAEAD, HPKEKDF, HPKELabels};
use crate::crypto::CryptoError;
use crate::secret::Zeroize;

/// The keys of an HPKE context (RFC 9180 section 5.1): key, base_nonce and
/// exporter_secret of the suite `suite`, and the next sequence number;
/// zeroized when dropped.
pub struct HPKEContext<F: HPKEKDF, A: HPKEAEAD> {
    suite: [u8; 10],
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    exporter_secret: Vec<u8>,
    sequence: u64,
    types: PhantomData<(F, A)>,
}

impl<F: HPKEKDF, A: HPKEAEAD> HPKEContext<F, A> {
    pub fn new(suite: [u8; 10], key: Vec<u8>, base_nonce: Vec<u8>, exporter_secret: Vec<u8>) -> HPKEContext<F, A> {
        HPKEContext { suite, key, base_nonce, exporter_secret, sequence: 0, types: PhantomData }
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn base_nonce(&self) -> &[u8] {
        &self.base_nonce
    }

    pub fn exporter_secret(&self) -> &[u8] {
        &self.exporter_secret
    }

    /// The sequence number of the next message.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// ComputeNonce(seq) of section 5.2: base_nonce XOR I2OSP(seq, Nn).
    pub fn nonce(&self) -> Vec<u8> {
        let mut nonce = self.base_nonce.clone();
        for (byte, sequence) in nonce.iter_mut().rev().zip(self.sequence.to_le_bytes()) {
            *byte ^= sequence;
        }
        nonce
    }

    /// IncrementSeq of section 5.2: fails with `LimitExceeded` once every
    /// sequence number has been used.
    pub fn advance(&mut self) -> Result<(), CryptoError> {
        let maximum = if A::NONCE_SIZE >= 8 { u64::MAX } else { (1u64 << (8 * A::NONCE_SIZE)) - 1 };
        if self.sequence >= maximum {
            return Err(CryptoError::LimitExceeded);
        }
        self.sequence += 1;
        Ok(())
    }

    /// Export(exporter_context, L) of section 5.3: LabeledExpand(exporter_secret,
    /// "sec", exporter_context, L) into `out` of L bytes.
    pub fn export(&self, context: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        HPKELabels::new(&self.suite).expand::<F>(&self.exporter_secret, b"sec", context, out)
    }
}

impl<F: HPKEKDF, A: HPKEAEAD> Zeroize for HPKEContext<F, A> {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.base_nonce.zeroize();
        self.exporter_secret.zeroize();
    }
}

impl<F: HPKEKDF, A: HPKEAEAD> Drop for HPKEContext<F, A> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<F: HPKEKDF, A: HPKEAEAD> fmt::Debug for HPKEContext<F, A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "HPKEContext(sequence: {}, ..)", self.sequence)
    }
}

/// The context of the sender: it seals and exports.
#[derive(Debug)]
pub struct HPKESenderContext<F: HPKEKDF, A: HPKEAEAD> {
    context: HPKEContext<F, A>,
}

impl<F: HPKEKDF, A: HPKEAEAD> HPKESenderContext<F, A> {
    pub fn new(context: HPKEContext<F, A>) -> HPKESenderContext<F, A> {
        HPKESenderContext { context }
    }

    pub fn context(&self) -> &HPKEContext<F, A> {
        &self.context
    }

    /// ContextS.Seal(aad, pt) of section 5.2, with the next sequence number.
    pub fn seal(&mut self, associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut nonce = self.context.nonce();
        let ciphertext = A::seal(&self.context.key, &nonce, associated, plaintext);
        nonce.zeroize();
        let ciphertext = ciphertext?;
        self.context.advance()?;
        Ok(ciphertext)
    }

    /// Writes Export(context, L) into `out` of L bytes.
    pub fn export(&self, context: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        self.context.export(context, out)
    }
}

/// The context of the receiver: it opens and exports.
#[derive(Debug)]
pub struct HPKEReceiverContext<F: HPKEKDF, A: HPKEAEAD> {
    context: HPKEContext<F, A>,
}

impl<F: HPKEKDF, A: HPKEAEAD> HPKEReceiverContext<F, A> {
    pub fn new(context: HPKEContext<F, A>) -> HPKEReceiverContext<F, A> {
        HPKEReceiverContext { context }
    }

    pub fn context(&self) -> &HPKEContext<F, A> {
        &self.context
    }

    /// ContextR.Open(aad, ct) of section 5.2, with the next sequence
    /// number, which advances only when the ciphertext opens.
    pub fn open(&mut self, associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.context.nonce();
        let plaintext = A::open(&self.context.key, &nonce, associated, ciphertext)?;
        self.context.advance()?;
        Ok(plaintext)
    }

    /// Writes Export(context, L) into `out` of L bytes.
    pub fn export(&self, context: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        self.context.export(context, out)
    }
}
