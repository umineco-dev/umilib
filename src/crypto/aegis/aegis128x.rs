use core::fmt;

use super::AEGISComponents;
use crate::crypto::aes::AESBitslice;
use crate::crypto::{AEAD, CryptoError, KeyInit};
use crate::secret::{ConstantTimeEq, Zeroize};

/// The state of AEGIS-128X with `D` lanes (sections 3 and 5.4): `D` states
/// of eight AES blocks; AEGIS-128L is the case `D = 1`. Inputs are absorbed
/// at the rate of `32 × D` bytes.
#[derive(Clone)]
pub struct AEGIS128XState<const D: usize> {
    /// V[j, i] is `lanes[i][j]`.
    lanes: [[[u8; 16]; 8]; D],
}

impl<const D: usize> AEGIS128XState<D> {
    /// R in bytes.
    pub const RATE: usize = 32 * D;
    const DEGREE_IS_VALID: () = assert!(matches!(D, 1 | 2 | 4), "AEGIS-128X has 1, 2 or 4 lanes");

    /// Init(key, nonce) (sections 3.4 and 5.4.2).
    pub fn new(key: &[u8; 16], nonce: &[u8; 16]) -> AEGIS128XState<D> {
        #[allow(clippy::let_unit_value)]
        let () = AEGIS128XState::<D>::DEGREE_IS_VALID;
        let (c0, c1) = (AEGISComponents::C0, AEGISComponents::C1);
        let mut key_nonce = AEGISComponents::xor(key, nonce);
        let mut lane = [
            key_nonce,
            c1,
            c0,
            c1,
            key_nonce,
            AEGISComponents::xor(key, &c0),
            AEGISComponents::xor(key, &c1),
            AEGISComponents::xor(key, &c0),
        ];
        let mut state = AEGIS128XState { lanes: [lane; D] };
        lane.zeroize();
        key_nonce.zeroize();
        let (nonces, mut keys) = ([*nonce; D], [*key; D]);
        for _ in 0..10 {
            for (index, lane) in state.lanes.iter_mut().enumerate() {
                let context = AEGISComponents::context(index, D);
                lane[3] = AEGISComponents::xor(&lane[3], &context);
                lane[7] = AEGISComponents::xor(&lane[7], &context);
            }
            state.update(&nonces, &keys);
        }
        keys.iter_mut().for_each(|key| key.zeroize());
        state
    }

    /// The state with the blocks `lanes[i][j]` = V[j, i].
    pub fn from_lanes(lanes: [[[u8; 16]; 8]; D]) -> AEGIS128XState<D> {
        AEGIS128XState { lanes }
    }

    /// The blocks: `lanes()[i][j]` is V[j, i].
    pub fn lanes(&self) -> &[[[u8; 16]; 8]; D] {
        &self.lanes
    }

    /// Update(M0, M1) (sections 3.3 and 5.4.1): S'0 = AESRound(S7, S0 ^ M0),
    /// S'4 = AESRound(S3, S4 ^ M1) and S'j = AESRound(S(j-1), Sj) otherwise.
    pub fn update(&mut self, m0: &[[u8; 16]; D], m1: &[[u8; 16]; D]) {
        for (lane, (m0, m1)) in self.lanes.iter_mut().zip(m0.iter().zip(m1)) {
            let mut inputs = [lane[7], lane[0], lane[1], lane[2], lane[3], lane[4], lane[5], lane[6]];
            let mut keys = *lane;
            keys[0] = AEGISComponents::xor(&keys[0], m0);
            keys[4] = AEGISComponents::xor(&keys[4], m1);
            AESBitslice::round(&mut inputs, &keys);
            *lane = inputs;
            inputs.zeroize();
            keys.zeroize();
        }
    }

    /// The input of one update: the halves t0 and t1 of `block` (R bytes), split into lanes.
    pub fn split(block: &[u8]) -> ([[u8; 16]; D], [[u8; 16]; D]) {
        let (mut t0, mut t1) = ([[0u8; 16]; D], [[0u8; 16]; D]);
        for (index, (a, b)) in t0.iter_mut().zip(t1.iter_mut()).enumerate() {
            a.copy_from_slice(&block[16 * index..16 * index + 16]);
            b.copy_from_slice(&block[16 * (D + index)..16 * (D + index) + 16]);
        }
        (t0, t1)
    }

    /// The key stream z0 || z1 of the next block (sections 3.6 and 5.4.4).
    pub fn keystream(&self, out: &mut [u8]) {
        for (index, lane) in self.lanes.iter().enumerate() {
            let z0 = AEGISComponents::xor(
                &AEGISComponents::xor(&lane[6], &lane[1]),
                &AEGISComponents::and(&lane[2], &lane[3]),
            );
            let z1 = AEGISComponents::xor(
                &AEGISComponents::xor(&lane[2], &lane[5]),
                &AEGISComponents::and(&lane[6], &lane[7]),
            );
            out[16 * index..16 * index + 16].copy_from_slice(&z0);
            out[16 * (D + index)..16 * (D + index) + 16].copy_from_slice(&z1);
        }
    }

    /// Absorb(ai) of one R-byte block (sections 3.5 and 5.4.3).
    pub fn absorb(&mut self, block: &[u8]) {
        let (mut t0, mut t1) = AEGIS128XState::<D>::split(block);
        self.update(&t0, &t1);
        t0.zeroize();
        t1.zeroize();
    }

    /// Absorbs `data` zero-padded to whole blocks, as the associated data.
    pub fn absorb_padded(&mut self, data: &[u8]) {
        let mut block = [0u8; 128];
        for chunk in data.chunks(AEGIS128XState::<D>::RATE) {
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()..AEGIS128XState::<D>::RATE].fill(0);
            self.absorb(&block[..AEGIS128XState::<D>::RATE]);
        }
        block.zeroize();
    }

    /// Enc of the blocks of `data`, the last one zero-padded and the output truncated (sections 3.1 and 3.6).
    pub fn encrypt(&mut self, data: &mut [u8]) {
        let rate = AEGIS128XState::<D>::RATE;
        let (mut block, mut z) = ([0u8; 128], [0u8; 128]);
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

    /// Dec of the whole blocks of `data` and DecPartial of the rest (sections 3.2, 3.7 and 3.8).
    pub fn decrypt(&mut self, data: &mut [u8]) {
        let rate = AEGIS128XState::<D>::RATE;
        let (mut block, mut z) = ([0u8; 128], [0u8; 128]);
        for chunk in data.chunks_mut(rate) {
            self.keystream(&mut z[..rate]);
            for (byte, key) in chunk.iter_mut().zip(&z) {
                *byte ^= key;
            }
            // The plaintext, zero-padded, is absorbed: Dec uses out0 || out1 and DecPartial ZeroPad(xn).
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()..rate].fill(0);
            self.absorb(&block[..rate]);
        }
        block.zeroize();
        z.zeroize();
    }

    /// Finalize(ad_len_bits, msg_len_bits) with a tag of `TAG` (16 or 32) bytes (sections 3.9 and 5.4.7).
    pub fn finalize<const TAG: usize>(mut self, associated_bytes: u64, message_bytes: u64) -> [u8; TAG] {
        let mut u = [0u8; 16];
        u[..8].copy_from_slice(&(8 * associated_bytes).to_le_bytes());
        u[8..].copy_from_slice(&(8 * message_bytes).to_le_bytes());
        let mut t = [[0u8; 16]; D];
        for (block, lane) in t.iter_mut().zip(&self.lanes) {
            *block = AEGISComponents::xor(&lane[2], &u);
        }
        for _ in 0..7 {
            self.update(&t, &t);
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

impl<const D: usize> AEGIS128XState<D> {
    /// The tag of one lane: the xor of its blocks S0 to S6 (16 bytes) or (S0 ^ ... ^ S3) || (S4 ^ ... ^ S7) (32 bytes).
    pub fn lane_tag(&self, lane: usize, out: &mut [u8]) {
        let blocks = &self.lanes[lane];
        let fold = |range: core::ops::Range<usize>| {
            range.fold([0u8; 16], |sum, index| AEGISComponents::xor(&sum, &blocks[index]))
        };
        if out.len() == 16 {
            out.copy_from_slice(&fold(0..7));
        } else {
            out[..16].copy_from_slice(&fold(0..4));
            out[16..].copy_from_slice(&fold(4..8));
        }
    }

    /// FinalizeMac(data_len_bits) of AEGISMAC-128X (section 8.3.2); for one
    /// lane it is Finalize(data_len_bits, tag_len_bits) (section 8.1).
    pub fn finalize_mac<const TAG: usize>(mut self, data_bytes: u64) -> [u8; TAG] {
        let mut u = [0u8; 16];
        u[..8].copy_from_slice(&(8 * data_bytes).to_le_bytes());
        u[8..].copy_from_slice(&(8 * TAG as u64).to_le_bytes());
        let mut t = [[0u8; 16]; D];
        for (block, lane) in t.iter_mut().zip(&self.lanes) {
            *block = AEGISComponents::xor(&lane[2], &u);
        }
        for _ in 0..7 {
            self.update(&t, &t);
        }
        if D > 1 {
            // The tags of the lanes (of every lane for 16-byte tags, of the lanes 1 to D - 1 for 32-byte tags).
            let mut tags = [0u8; 128];
            let first = if TAG == 16 { 0 } else { 1 };
            let mut length = 0;
            for lane in first..D {
                self.lane_tag(lane, &mut tags[length..length + TAG]);
                length += TAG;
            }
            // Absorbed into lane 0 in 32-byte pieces; the other lanes are not used anymore.
            for piece in tags[..length].as_chunks::<32>().0 {
                let (mut m0, mut m1) = ([[0u8; 16]; D], [[0u8; 16]; D]);
                m0[0].copy_from_slice(&piece[..16]);
                m1[0].copy_from_slice(&piece[16..]);
                self.update(&m0, &m1);
            }
            tags.zeroize();
            u[..8].copy_from_slice(&(D as u64).to_le_bytes());
            let mut t = [[0u8; 16]; D];
            t[0] = AEGISComponents::xor(&self.lanes[0][2], &u);
            for _ in 0..7 {
                self.update(&t, &t);
            }
        }
        let mut tag = [0u8; TAG];
        self.lane_tag(0, &mut tag);
        self.zeroize();
        tag
    }

    /// Stream(len, key, nonce) (section 7): the key stream, the encryption of zeros.
    pub fn stream(key: &[u8; 16], nonce: &[u8; 16], out: &mut [u8]) {
        out.fill(0);
        AEGIS128XState::<D>::new(key, nonce).encrypt(out);
    }
}

impl<const D: usize> Zeroize for AEGIS128XState<D> {
    fn zeroize(&mut self) {
        self.lanes.iter_mut().for_each(|lane| lane.zeroize());
    }
}

impl<const D: usize> Drop for AEGIS128XState<D> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const D: usize> fmt::Debug for AEGIS128XState<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AEGIS128XState({D} lanes, ..)")
    }
}

/// AEGIS-128X with `D` lanes (1, 2 or 4) and tags of `TAG` bytes (16 or 32):
/// a 128-bit key and a 128-bit nonce (section 5.4).
///
/// Decryption decrypts before it checks the tag; when the tag does not
/// match, the buffer is overwritten with zeros, as section 3.2 requires.
#[derive(Clone)]
pub struct AEGIS128X<const D: usize, const TAG: usize> {
    key: [u8; 16],
}

/// AEGIS-128L (section 3): AEGIS-128X with one lane.
pub type AEGIS128L<const TAG: usize> = AEGIS128X<1, TAG>;

impl<const D: usize, const TAG: usize> AEGIS128X<D, TAG> {
    pub const KEY_SIZE: usize = 16;
    const TAG_IS_VALID: () = assert!(TAG == 16 || TAG == 32, "AEGIS tags have 16 or 32 bytes");

    pub fn new(key: &[u8; 16]) -> AEGIS128X<D, TAG> {
        #[allow(clippy::let_unit_value)]
        let () = AEGIS128X::<D, TAG>::TAG_IS_VALID;
        AEGIS128X { key: *key }
    }

    /// The state after Init and the associated data.
    pub fn start(&self, nonce: &[u8], associated: &[u8], data: &[u8]) -> Result<AEGIS128XState<D>, CryptoError> {
        let nonce: &[u8; 16] =
            nonce.try_into().map_err(|_| CryptoError::NonceLength { length: nonce.len(), minimum: 16, maximum: 16 })?;
        AEGISComponents::check(associated, data)?;
        let mut state = AEGIS128XState::new(&self.key, nonce);
        state.absorb_padded(associated);
        Ok(state)
    }
}

impl<const D: usize, const TAG: usize> AEAD for AEGIS128X<D, TAG> {
    const NONCE_SIZE: usize = 16;
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

impl<const D: usize, const TAG: usize> KeyInit for AEGIS128X<D, TAG> {
    const MINIMUM_KEY_SIZE: usize = 16;
    const MAXIMUM_KEY_SIZE: usize = 16;

    fn new_from_slice(key: &[u8]) -> Result<AEGIS128X<D, TAG>, CryptoError> {
        AEGIS128X::<D, TAG>::check_key_length(key.len())?;
        Ok(AEGIS128X::new(key.try_into().map_err(|_| CryptoError::InvalidParameter)?))
    }
}

impl<const D: usize, const TAG: usize> Zeroize for AEGIS128X<D, TAG> {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<const D: usize, const TAG: usize> Drop for AEGIS128X<D, TAG> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const D: usize, const TAG: usize> fmt::Debug for AEGIS128X<D, TAG> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AEGIS128X({D} lanes, {TAG}-byte tags, ..)")
    }
}
