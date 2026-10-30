use core::fmt;

use super::AEGISComponents;
use crate::crypto::aes::AESBitslice;
use crate::crypto::{AEAD, CryptoError, KeyInit};
use crate::secret::{ConstantTimeEq, Zeroize};

/// The state of AEGIS-256X with `D` lanes (sections 4 and 5.5): `D` states
/// of six AES blocks; AEGIS-256 is the case `D = 1`. Inputs are absorbed at
/// the rate of `16 × D` bytes.
#[derive(Clone)]
pub struct AEGIS256XState<const D: usize> {
    /// V[j, i] is `lanes[i][j]`.
    lanes: [[[u8; 16]; 6]; D],
}

impl<const D: usize> AEGIS256XState<D> {
    /// R in bytes.
    pub const RATE: usize = 16 * D;
    const DEGREE_IS_VALID: () = assert!(matches!(D, 1 | 2 | 4), "AEGIS-256X has 1, 2 or 4 lanes");

    /// Init(key, nonce) (sections 4.4 and 5.5.2).
    pub fn new(key: &[u8; 32], nonce: &[u8; 32]) -> AEGIS256XState<D> {
        #[allow(clippy::let_unit_value)]
        let () = AEGIS256XState::<D>::DEGREE_IS_VALID;
        let (c0, c1) = (AEGISComponents::C0, AEGISComponents::C1);
        let mut k0: [u8; 16] = key[..16].try_into().expect("16 bytes");
        let mut k1: [u8; 16] = key[16..].try_into().expect("16 bytes");
        let n0: [u8; 16] = nonce[..16].try_into().expect("16 bytes");
        let n1: [u8; 16] = nonce[16..].try_into().expect("16 bytes");
        let (mut k0n0, mut k1n1) = (AEGISComponents::xor(&k0, &n0), AEGISComponents::xor(&k1, &n1));
        let mut lane = [k0n0, k1n1, c1, c0, AEGISComponents::xor(&k0, &c0), AEGISComponents::xor(&k1, &c1)];
        let mut state = AEGIS256XState { lanes: [lane; D] };
        let mut inputs = [[k0; D], [k1; D], [k0n0; D], [k1n1; D]];
        lane.zeroize();
        for secret in [&mut k0, &mut k1, &mut k0n0, &mut k1n1] {
            secret.zeroize();
        }
        for _ in 0..4 {
            for input in &inputs {
                for (index, lane) in state.lanes.iter_mut().enumerate() {
                    let context = AEGISComponents::context(index, D);
                    lane[3] = AEGISComponents::xor(&lane[3], &context);
                    lane[5] = AEGISComponents::xor(&lane[5], &context);
                }
                state.update(input);
            }
        }
        inputs.iter_mut().flatten().for_each(|input| input.zeroize());
        state
    }

    /// The state with the blocks `lanes[i][j]` = V[j, i].
    pub fn from_lanes(lanes: [[[u8; 16]; 6]; D]) -> AEGIS256XState<D> {
        AEGIS256XState { lanes }
    }

    /// The blocks: `lanes()[i][j]` is V[j, i].
    pub fn lanes(&self) -> &[[[u8; 16]; 6]; D] {
        &self.lanes
    }

    /// Update(M) (sections 4.3 and 5.5.1): S'0 = AESRound(S5, S0 ^ M) and S'j = AESRound(S(j-1), Sj) otherwise.
    pub fn update(&mut self, m: &[[u8; 16]; D]) {
        for (lane, m) in self.lanes.iter_mut().zip(m) {
            let mut inputs = [lane[5], lane[0], lane[1], lane[2], lane[3], lane[4]];
            let mut keys = *lane;
            keys[0] = AEGISComponents::xor(&keys[0], m);
            AESBitslice::round(&mut inputs, &keys);
            *lane = inputs;
            inputs.zeroize();
            keys.zeroize();
        }
    }

    /// The key stream z of the next block (sections 4.6 and 5.5.4).
    pub fn keystream(&self, out: &mut [u8]) {
        for (index, lane) in self.lanes.iter().enumerate() {
            let z = AEGISComponents::xor(
                &AEGISComponents::xor(&AEGISComponents::xor(&lane[1], &lane[4]), &lane[5]),
                &AEGISComponents::and(&lane[2], &lane[3]),
            );
            out[16 * index..16 * index + 16].copy_from_slice(&z);
        }
    }

    /// Absorb(ai) of one R-byte block (sections 4.5 and 5.5.3).
    pub fn absorb(&mut self, block: &[u8]) {
        let mut m = [[0u8; 16]; D];
        for (index, lane) in m.iter_mut().enumerate() {
            lane.copy_from_slice(&block[16 * index..16 * index + 16]);
        }
        self.update(&m);
        m.zeroize();
    }

    /// Absorbs `data` zero-padded to whole blocks, as the associated data.
    pub fn absorb_padded(&mut self, data: &[u8]) {
        let mut block = [0u8; 64];
        for chunk in data.chunks(AEGIS256XState::<D>::RATE) {
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()..AEGIS256XState::<D>::RATE].fill(0);
            self.absorb(&block[..AEGIS256XState::<D>::RATE]);
        }
        block.zeroize();
    }

    /// Enc of the blocks of `data`, the last one zero-padded and the output truncated (sections 4.1 and 4.6).
    pub fn encrypt(&mut self, data: &mut [u8]) {
        let rate = AEGIS256XState::<D>::RATE;
        let (mut block, mut z) = ([0u8; 64], [0u8; 64]);
        for chunk in data.chunks_mut(rate) {
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()..rate].fill(0);
            self.keystream(&mut z[..rate]);
            self.absorb(&block[..rate]);
            for (byte, key) in chunk.iter_mut().zip(&z) {
                *byte ^= key;
            }
        }
        block.zeroize();
        z.zeroize();
    }

    /// Dec of the whole blocks of `data` and DecPartial of the rest (sections 4.2, 4.7 and 4.8).
    pub fn decrypt(&mut self, data: &mut [u8]) {
        let rate = AEGIS256XState::<D>::RATE;
        let (mut block, mut z) = ([0u8; 64], [0u8; 64]);
        for chunk in data.chunks_mut(rate) {
            self.keystream(&mut z[..rate]);
            for (byte, key) in chunk.iter_mut().zip(&z) {
                *byte ^= key;
            }
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()..rate].fill(0);
            self.absorb(&block[..rate]);
        }
        block.zeroize();
        z.zeroize();
    }

    /// Finalize(ad_len_bits, msg_len_bits) with a tag of `TAG` (16 or 32) bytes (sections 4.9 and 5.5.7).
    pub fn finalize<const TAG: usize>(mut self, associated_bytes: u64, message_bytes: u64) -> [u8; TAG] {
        let mut u = [0u8; 16];
        u[..8].copy_from_slice(&(8 * associated_bytes).to_le_bytes());
        u[8..].copy_from_slice(&(8 * message_bytes).to_le_bytes());
        let mut t = [[0u8; 16]; D];
        for (block, lane) in t.iter_mut().zip(&self.lanes) {
            *block = AEGISComponents::xor(&lane[3], &u);
        }
        for _ in 0..7 {
            self.update(&t);
        }
        // The xor of the tags of the lanes.
        let (mut tag, mut lane_tag) = ([0u8; TAG], [0u8; TAG]);
        for lane in 0..D {
            self.lane_tag(lane, &mut lane_tag);
            for (byte, value) in tag.iter_mut().zip(&lane_tag) {
                *byte ^= value;
            }
        }
        lane_tag.zeroize();
        t.zeroize();
        self.zeroize();
        tag
    }
}

impl<const D: usize> AEGIS256XState<D> {
    /// The tag of one lane: the xor of its blocks S0 to S5 (16 bytes) or (S0 ^ S1 ^ S2) || (S3 ^ S4 ^ S5) (32 bytes).
    pub fn lane_tag(&self, lane: usize, out: &mut [u8]) {
        let blocks = &self.lanes[lane];
        let fold = |range: core::ops::Range<usize>| {
            range.fold([0u8; 16], |sum, index| AEGISComponents::xor(&sum, &blocks[index]))
        };
        if out.len() == 16 {
            out.copy_from_slice(&fold(0..6));
        } else {
            out[..16].copy_from_slice(&fold(0..3));
            out[16..].copy_from_slice(&fold(3..6));
        }
    }

    /// FinalizeMac(data_len_bits) of AEGISMAC-256X (section 8.4.2); for one
    /// lane it is Finalize(data_len_bits, tag_len_bits) (section 8.2).
    pub fn finalize_mac<const TAG: usize>(mut self, data_bytes: u64) -> [u8; TAG] {
        let mut u = [0u8; 16];
        u[..8].copy_from_slice(&(8 * data_bytes).to_le_bytes());
        u[8..].copy_from_slice(&(8 * TAG as u64).to_le_bytes());
        let mut t = [[0u8; 16]; D];
        for (block, lane) in t.iter_mut().zip(&self.lanes) {
            *block = AEGISComponents::xor(&lane[3], &u);
        }
        for _ in 0..7 {
            self.update(&t);
        }
        if D > 1 {
            // The tags of the lanes 1 to D - 1, absorbed into lane 0 in 16-byte pieces.
            let mut tags = [0u8; 128];
            let mut length = 0;
            for lane in 1..D {
                self.lane_tag(lane, &mut tags[length..length + TAG]);
                length += TAG;
            }
            for piece in tags[..length].as_chunks::<16>().0 {
                let mut m = [[0u8; 16]; D];
                m[0] = *piece;
                self.update(&m);
            }
            tags.zeroize();
            u[..8].copy_from_slice(&(D as u64).to_le_bytes());
            let mut t = [[0u8; 16]; D];
            t[0] = AEGISComponents::xor(&self.lanes[0][3], &u);
            for _ in 0..7 {
                self.update(&t);
            }
        }
        let mut tag = [0u8; TAG];
        self.lane_tag(0, &mut tag);
        self.zeroize();
        tag
    }

    /// Stream(len, key, nonce) (section 7): the key stream, the encryption of zeros.
    pub fn stream(key: &[u8; 32], nonce: &[u8; 32], out: &mut [u8]) {
        out.fill(0);
        AEGIS256XState::<D>::new(key, nonce).encrypt(out);
    }
}

impl<const D: usize> Zeroize for AEGIS256XState<D> {
    fn zeroize(&mut self) {
        self.lanes.iter_mut().for_each(|lane| lane.zeroize());
    }
}

impl<const D: usize> Drop for AEGIS256XState<D> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const D: usize> fmt::Debug for AEGIS256XState<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AEGIS256XState({D} lanes, ..)")
    }
}

/// AEGIS-256X with `D` lanes (1, 2 or 4) and tags of `TAG` bytes (16 or 32):
/// a 256-bit key and a 256-bit nonce (section 5.5).
///
/// Decryption decrypts before it checks the tag; when the tag does not
/// match, the buffer is overwritten with zeros, as section 4.2 requires.
#[derive(Clone)]
pub struct AEGIS256X<const D: usize, const TAG: usize> {
    key: [u8; 32],
}

/// AEGIS-256 (section 4): AEGIS-256X with one lane.
pub type AEGIS256<const TAG: usize> = AEGIS256X<1, TAG>;

impl<const D: usize, const TAG: usize> AEGIS256X<D, TAG> {
    pub const KEY_SIZE: usize = 32;
    const TAG_IS_VALID: () = assert!(TAG == 16 || TAG == 32, "AEGIS tags have 16 or 32 bytes");

    pub fn new(key: &[u8; 32]) -> AEGIS256X<D, TAG> {
        #[allow(clippy::let_unit_value)]
        let () = AEGIS256X::<D, TAG>::TAG_IS_VALID;
        AEGIS256X { key: *key }
    }

    /// The state after Init and the associated data.
    pub fn start(&self, nonce: &[u8], associated: &[u8], data: &[u8]) -> Result<AEGIS256XState<D>, CryptoError> {
        let nonce: &[u8; 32] =
            nonce.try_into().map_err(|_| CryptoError::NonceLength { length: nonce.len(), minimum: 32, maximum: 32 })?;
        AEGISComponents::check(associated, data)?;
        let mut state = AEGIS256XState::new(&self.key, nonce);
        state.absorb_padded(associated);
        Ok(state)
    }
}

impl<const D: usize, const TAG: usize> AEAD for AEGIS256X<D, TAG> {
    const NONCE_SIZE: usize = 32;
    const TAG_SIZE: usize = TAG;
    type Tag = [u8; TAG];

    fn encrypt_in_place(&self, nonce: &[u8], associated: &[u8], buffer: &mut [u8]) -> Result<[u8; TAG], CryptoError> {
        let mut state = self.start(nonce, associated, buffer)?;
        state.encrypt(buffer);
        Ok(state.finalize(associated.len() as u64, buffer.len() as u64))
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
        let mut state = self.start(nonce, associated, buffer)?;
        state.decrypt(buffer);
        let mut expected: [u8; TAG] = state.finalize(associated.len() as u64, buffer.len() as u64);
        let valid = expected[..].ct_eq(tag).into_bool();
        expected.zeroize();
        if !valid {
            buffer.zeroize();
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

impl<const D: usize, const TAG: usize> KeyInit for AEGIS256X<D, TAG> {
    const MINIMUM_KEY_SIZE: usize = 32;
    const MAXIMUM_KEY_SIZE: usize = 32;

    fn new_from_slice(key: &[u8]) -> Result<AEGIS256X<D, TAG>, CryptoError> {
        AEGIS256X::<D, TAG>::check_key_length(key.len())?;
        Ok(AEGIS256X::new(key.try_into().map_err(|_| CryptoError::InvalidParameter)?))
    }
}

impl<const D: usize, const TAG: usize> Zeroize for AEGIS256X<D, TAG> {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<const D: usize, const TAG: usize> Drop for AEGIS256X<D, TAG> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const D: usize, const TAG: usize> fmt::Debug for AEGIS256X<D, TAG> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AEGIS256X({D} lanes, {TAG}-byte tags, ..)")
    }
}
