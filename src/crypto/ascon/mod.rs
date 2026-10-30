//! Ascon-AEAD128 (NIST SP 800-232 section 4): the lightweight authenticated
//! encryption of the Ascon family, on the permutation of `hash::ascon`.

use core::fmt;

use crate::crypto::{AEAD, CryptoError, KeyInit};
use crate::hash::ascon::AsconPermutation;
use crate::secret::{ConstantTimeEq, Zeroize};

/// Ascon-AEAD128 with a 128-bit key, a 128-bit nonce and tags of `TAG`
/// bytes: 16, or truncated to at least 4 (section 4.2.1; requirement R4
/// allows less than 8 only after a risk analysis).
///
/// A 32-byte key is K1 || K2 for the nonce-masking option of section
/// 4.2.2: the nonce is N ^ K2. One key must process at most 2^54 bytes in
/// all (R6). Decryption decrypts before it checks the tag; when the tag does
/// not match, it encrypts again, so the buffer holds the ciphertext as it was.
#[derive(Clone)]
pub struct AsconAEAD128<const TAG: usize> {
    key: [u8; 16],
    /// K2 of the nonce-masking option, zero without it.
    nonce_mask: [u8; 16],
}

impl<const TAG: usize> AsconAEAD128<TAG> {
    /// The initial value (table 14).
    pub const IV: u64 = 0x0000_1000_808c_0001;
    /// The rate in bytes.
    pub const RATE: usize = 16;
    const TAG_IS_VALID: () = assert!(TAG >= 4 && TAG <= 16, "Ascon-AEAD128 tags have 4 to 16 bytes");

    pub fn new(key: &[u8; 16]) -> AsconAEAD128<TAG> {
        AsconAEAD128::with_nonce_mask(key, &[0; 16])
    }

    /// The nonce-masking option with K1 = `key` and K2 = `nonce_mask` (section 4.2.2).
    pub fn with_nonce_mask(key: &[u8; 16], nonce_mask: &[u8; 16]) -> AsconAEAD128<TAG> {
        #[allow(clippy::let_unit_value)]
        let () = AsconAEAD128::<TAG>::TAG_IS_VALID;
        AsconAEAD128 { key: *key, nonce_mask: *nonce_mask }
    }

    fn key_words(&self) -> [u64; 2] {
        [
            u64::from_le_bytes(self.key[..8].try_into().expect("eight bytes")),
            u64::from_le_bytes(self.key[8..].try_into().expect("eight bytes")),
        ]
    }

    /// The initialization and the associated data (algorithm 3): the state is
    /// ready for the first block of plaintext or ciphertext.
    pub fn start(&self, nonce: &[u8], associated: &[u8]) -> Result<AsconPermutation, CryptoError> {
        let nonce: &[u8; 16] =
            nonce.try_into().map_err(|_| CryptoError::NonceLength { length: nonce.len(), minimum: 16, maximum: 16 })?;
        let mut masked = *nonce;
        for (byte, mask) in masked.iter_mut().zip(&self.nonce_mask) {
            *byte ^= mask;
        }
        let mut key = self.key_words();
        let mut n = [
            u64::from_le_bytes(masked[..8].try_into().expect("eight bytes")),
            u64::from_le_bytes(masked[8..].try_into().expect("eight bytes")),
        ];
        masked.zeroize();
        // S = IV || K || N, Ascon-p[12], then S ^= 0^192 || K.
        let mut state = AsconPermutation::from_words([AsconAEAD128::<TAG>::IV, key[0], key[1], n[0], n[1]]);
        state.permute(12);
        state.words_mut()[3] ^= key[0];
        state.words_mut()[4] ^= key[1];
        key.zeroize();
        // With nonce masking, N ^ K2 reveals K2 next to the public nonce.
        n.zeroize();
        if !associated.is_empty() {
            let (blocks, rest) = associated.as_chunks::<16>();
            for block in blocks {
                state.xor_bytes(0, block);
                state.permute(8);
            }
            state.xor_bytes(0, rest);
            state.xor_bytes(rest.len(), &[0x01]);
            state.permute(8);
        }
        // The domain separation bit S ^= 0^319 || 1.
        state.words_mut()[4] ^= 1 << 63;
        Ok(state)
    }

    /// The finalization (algorithm 3): S ^= 0^128 || K || 0^64, Ascon-p\[12\], T = S\[192:319\] ^ K, truncated.
    pub fn tag(&self, mut state: AsconPermutation) -> [u8; TAG] {
        let mut key = self.key_words();
        state.words_mut()[2] ^= key[0];
        state.words_mut()[3] ^= key[1];
        state.permute(12);
        state.words_mut()[3] ^= key[0];
        state.words_mut()[4] ^= key[1];
        key.zeroize();
        let mut full = [0u8; 16];
        state.extract_bytes(24, &mut full);
        let mut tag = [0u8; TAG];
        tag.copy_from_slice(&full[..TAG]);
        full.zeroize();
        tag
    }

    /// The plaintext processing of algorithm 3 on `buffer`.
    pub fn encrypt_blocks(state: &mut AsconPermutation, buffer: &mut [u8]) {
        let (blocks, rest) = buffer.as_chunks_mut::<16>();
        for block in blocks {
            state.xor_bytes(0, block);
            state.extract_bytes(0, block);
            state.permute(8);
        }
        state.xor_bytes(0, rest);
        state.extract_bytes(0, rest);
        state.xor_bytes(rest.len(), &[0x01]);
    }

    /// The ciphertext processing of algorithm 4 on `buffer`: P = S[0:ℓ-1] ^ C
    /// and S\[0:ℓ-1\] = C for each block, Ascon-p\[8\] after the whole ones, and
    /// the padding bit after the last one.
    pub fn decrypt_blocks(state: &mut AsconPermutation, buffer: &mut [u8]) {
        let (blocks, rest) = buffer.as_chunks_mut::<16>();
        for block in blocks {
            AsconAEAD128::<TAG>::decrypt_block(state, block);
            state.permute(8);
        }
        AsconAEAD128::<TAG>::decrypt_block(state, rest);
        state.xor_bytes(rest.len(), &[0x01]);
    }

    /// P = S[0:ℓ-1] ^ C and S[0:ℓ-1] = C on the bytes of `block` (at most 16).
    pub fn decrypt_block(state: &mut AsconPermutation, block: &mut [u8]) {
        for (index, byte) in block.iter_mut().enumerate() {
            let ciphertext = *byte;
            *byte ^= state.byte(index);
            state.set_bytes(index, &[ciphertext]);
        }
    }
}

impl<const TAG: usize> AEAD for AsconAEAD128<TAG> {
    const NONCE_SIZE: usize = 16;
    const TAG_SIZE: usize = TAG;
    type Tag = [u8; TAG];

    fn encrypt_in_place(&self, nonce: &[u8], associated: &[u8], buffer: &mut [u8]) -> Result<[u8; TAG], CryptoError> {
        let mut state = self.start(nonce, associated)?;
        AsconAEAD128::<TAG>::encrypt_blocks(&mut state, buffer);
        Ok(self.tag(state))
    }

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        associated: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        if tag.len() != TAG {
            return Err(CryptoError::TagLength { length: tag.len(), minimum: TAG, maximum: TAG });
        }
        let mut state = self.start(nonce, associated)?;
        AsconAEAD128::<TAG>::decrypt_blocks(&mut state, buffer);
        let mut expected = self.tag(state);
        let valid = expected[..].ct_eq(tag).into_bool();
        expected.zeroize();
        if !valid {
            let mut state = self.start(nonce, associated)?;
            AsconAEAD128::<TAG>::encrypt_blocks(&mut state, buffer);
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

/// A key of 16 bytes, or 32 bytes K1 || K2 for nonce masking.
impl<const TAG: usize> KeyInit for AsconAEAD128<TAG> {
    const MINIMUM_KEY_SIZE: usize = 16;
    const MAXIMUM_KEY_SIZE: usize = 32;

    fn new_from_slice(key: &[u8]) -> Result<AsconAEAD128<TAG>, CryptoError> {
        match key.len() {
            16 => Ok(AsconAEAD128::new(key.try_into().expect("16 bytes"))),
            32 => Ok(AsconAEAD128::with_nonce_mask(
                key[..16].try_into().expect("16 bytes"),
                key[16..].try_into().expect("16 bytes"),
            )),
            length => Err(CryptoError::KeyLength { length, minimum: 16, maximum: 32 }),
        }
    }
}

impl<const TAG: usize> Zeroize for AsconAEAD128<TAG> {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.nonce_mask.zeroize();
    }
}

impl<const TAG: usize> Drop for AsconAEAD128<TAG> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const TAG: usize> fmt::Debug for AsconAEAD128<TAG> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AsconAEAD128({TAG}-byte tags, ..)")
    }
}
