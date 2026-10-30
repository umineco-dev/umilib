use core::fmt;

use crate::secret::Zeroize;

/// The state of four AES blocks as eight bit planes: bit `j` of plane `b` is
/// bit `b` of byte `j` of the 64 bytes, where byte `j = 16 × block + 4 × column + row`
/// (FIPS 197 section 3.4). Every byte goes through the same operations, so
/// each one is a few word operations for all of them, without tables or
/// data-dependent branches.
///
/// The S-box is computed from its definition (section 5.1.1): the inverse in
/// GF(2^8), as x^254 by four multiplications and seven squarings, then the
/// affine transformation; the inverse S-box applies the inverse affine
/// transformation first.
#[derive(Clone, Copy)]
pub struct AESBitslice {
    planes: [u64; 8],
}

impl AESBitslice {
    /// The number of blocks held.
    pub const BLOCKS: usize = 4;
    /// The constant added by the affine transformation of the S-box.
    pub const AFFINE_CONSTANT: u8 = 0x63;
    /// The constant of its inverse.
    pub const INVERSE_AFFINE_CONSTANT: u8 = 0x05;
    /// The bits of row 0 of every column of every block.
    pub const ROW: u64 = 0x1111_1111_1111_1111;

    pub const fn zero() -> AESBitslice {
        AESBitslice { planes: [0; 8] }
    }

    pub fn planes(&self) -> &[u64; 8] {
        &self.planes
    }

    /// Transposes the 8×8 bit matrix whose rows are the bytes of `x`.
    pub fn transpose(mut x: u64) -> u64 {
        let mut t = (x ^ (x >> 7)) & 0x00AA_00AA_00AA_00AA;
        x ^= t ^ (t << 7);
        t = (x ^ (x >> 14)) & 0x0000_CCCC_0000_CCCC;
        x ^= t ^ (t << 14);
        t = (x ^ (x >> 28)) & 0x0000_0000_F0F0_F0F0;
        x ^= t ^ (t << 28);
        x
    }

    /// Transposes the 8×8 byte matrix whose rows are the words of `words`.
    pub fn transpose_bytes(words: &[u64; 8]) -> [u64; 8] {
        let mut out = [0u64; 8];
        for (row, &word) in words.iter().enumerate() {
            for (column, output) in out.iter_mut().enumerate() {
                *output |= ((word >> (8 * column)) & 0xFF) << (8 * row);
            }
        }
        out
    }

    /// The planes of `blocks`, up to four; missing blocks are zero.
    pub fn from_blocks(blocks: &[[u8; 16]]) -> AESBitslice {
        let mut words = [0u64; 8];
        for (index, block) in blocks.iter().take(AESBitslice::BLOCKS).enumerate() {
            for (half, bytes) in block.as_chunks::<8>().0.iter().enumerate() {
                words[2 * index + half] = AESBitslice::transpose(u64::from_le_bytes(*bytes));
            }
        }
        let planes = AESBitslice::transpose_bytes(&words);
        words.zeroize();
        AESBitslice { planes }
    }

    /// The planes of four copies of `block`, as round keys are held.
    pub fn from_block(block: &[u8; 16]) -> AESBitslice {
        AESBitslice::from_blocks(&[*block; 4])
    }

    /// Writes the blocks into `blocks`, up to four.
    pub fn to_blocks(&self, blocks: &mut [[u8; 16]]) {
        let mut words = AESBitslice::transpose_bytes(&self.planes);
        for (index, block) in blocks.iter_mut().take(AESBitslice::BLOCKS).enumerate() {
            for (half, bytes) in block.as_chunks_mut::<8>().0.iter_mut().enumerate() {
                *bytes = AESBitslice::transpose(words[2 * index + half]).to_le_bytes();
            }
        }
        words.zeroize();
    }

    /// The product of `a` and `b` in GF(2^8) = GF(2)\[x\]/(x^8 + x^4 + x^3 + x + 1), plane by plane.
    pub fn multiply(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
        let mut product = [0u64; 15];
        for i in 0..8 {
            for j in 0..8 {
                product[i + j] ^= a[i] & b[j];
            }
        }
        AESBitslice::reduce(product)
    }

    /// The square of `a`, a linear map in characteristic 2.
    pub fn square(a: &[u64; 8]) -> [u64; 8] {
        let mut product = [0u64; 15];
        for i in 0..8 {
            product[2 * i] = a[i];
        }
        AESBitslice::reduce(product)
    }

    /// Reduces a product of degree up to 14 modulo the AES polynomial,
    /// with x^8 = x^4 + x^3 + x + 1.
    pub fn reduce(mut product: [u64; 15]) -> [u64; 8] {
        for k in (8..15).rev() {
            let high = product[k];
            product[k - 8] ^= high;
            product[k - 7] ^= high;
            product[k - 5] ^= high;
            product[k - 4] ^= high;
        }
        let mut result = [0u64; 8];
        result.copy_from_slice(&product[..8]);
        product.zeroize();
        result
    }

    /// The inverse in GF(2^8), with 0 mapped to 0: x^254.
    pub fn invert(x: &[u64; 8]) -> [u64; 8] {
        let x2 = AESBitslice::square(x);
        let x3 = AESBitslice::multiply(&x2, x);
        let x12 = AESBitslice::square(&AESBitslice::square(&x3));
        let x15 = AESBitslice::multiply(&x12, &x3);
        let x14 = AESBitslice::multiply(&x12, &x2);
        let mut x240 = x15;
        for _ in 0..4 {
            x240 = AESBitslice::square(&x240);
        }
        AESBitslice::multiply(&x240, &x14)
    }

    /// SubBytes (section 5.1.1).
    pub fn sub_bytes(&mut self) {
        let inverse = AESBitslice::invert(&self.planes);
        for bit in 0..8 {
            let mut value = inverse[bit]
                ^ inverse[(bit + 4) % 8]
                ^ inverse[(bit + 5) % 8]
                ^ inverse[(bit + 6) % 8]
                ^ inverse[(bit + 7) % 8];
            if AESBitslice::AFFINE_CONSTANT >> bit & 1 == 1 {
                value = !value;
            }
            self.planes[bit] = value;
        }
    }

    /// InvSubBytes (section 5.3.2).
    pub fn inv_sub_bytes(&mut self) {
        let mut affine = [0u64; 8];
        for (bit, value) in affine.iter_mut().enumerate() {
            *value = self.planes[(bit + 2) % 8] ^ self.planes[(bit + 5) % 8] ^ self.planes[(bit + 7) % 8];
            if AESBitslice::INVERSE_AFFINE_CONSTANT >> bit & 1 == 1 {
                *value = !*value;
            }
        }
        self.planes = AESBitslice::invert(&affine);
    }

    /// Moves every row `r` of every block by `amount × r` columns to the left:
    /// column `c` takes the byte of column `c + amount × r` (mod 4).
    pub fn rotate_rows(x: u64, amount: usize) -> u64 {
        let mut out = x & AESBitslice::ROW;
        for row in 1..4 {
            let shift = (amount * row) % 4;
            let bits = x & (AESBitslice::ROW << row);
            if shift == 0 {
                out |= bits;
                continue;
            }
            // Within each block of 16 bits, the columns from `shift` on move
            // down by `shift` columns and the others wrap around to the top.
            let high = (0xFFFFu64 << (4 * shift)) & 0xFFFF;
            let high = high * 0x0001_0001_0001_0001;
            out |= ((bits & high) >> (4 * shift)) | ((bits & !high) << (16 - 4 * shift));
        }
        out
    }

    /// ShiftRows (section 5.1.2).
    pub fn shift_rows(&mut self) {
        for plane in self.planes.iter_mut() {
            *plane = AESBitslice::rotate_rows(*plane, 1);
        }
    }

    /// InvShiftRows (section 5.3.1).
    pub fn inv_shift_rows(&mut self) {
        for plane in self.planes.iter_mut() {
            *plane = AESBitslice::rotate_rows(*plane, 3);
        }
    }

    /// Row `r` of every column takes the byte of row `r + amount` (mod 4).
    pub fn rotate_columns(x: u64, amount: u32) -> u64 {
        let low = (0xFu64 >> amount) * 0x1111_1111_1111_1111;
        ((x >> amount) & low) | ((x << (4 - amount)) & !low)
    }

    /// Multiplication by x (`{02}`, section 4.2.1), plane by plane.
    pub fn xtime(a: &[u64; 8]) -> [u64; 8] {
        [a[7], a[0] ^ a[7], a[1], a[2] ^ a[7], a[3] ^ a[7], a[4], a[5], a[6]]
    }

    /// MixColumns (section 5.1.3): row `r` becomes
    /// `{02}·a_r + {03}·a_{r+1} + a_{r+2} + a_{r+3}` = `{02}·(a_r + a_{r+1}) + a_{r+1} + a_{r+2} + a_{r+3}`.
    pub fn mix_columns(&mut self) {
        let mut one = [0u64; 8];
        let mut sum = [0u64; 8];
        for bit in 0..8 {
            one[bit] = AESBitslice::rotate_columns(self.planes[bit], 1);
            sum[bit] = self.planes[bit] ^ one[bit];
        }
        let doubled = AESBitslice::xtime(&sum);
        for bit in 0..8 {
            let plane = self.planes[bit];
            self.planes[bit] =
                doubled[bit] ^ one[bit] ^ AESBitslice::rotate_columns(plane, 2) ^ AESBitslice::rotate_columns(plane, 3);
        }
    }

    /// InvMixColumns (section 5.3.3), as MixColumns after adding
    /// `{04}·(a_r + a_{r+2})` to rows `r` and `r + 2`.
    pub fn inv_mix_columns(&mut self) {
        let sum = self.planes.map(|plane| plane ^ AESBitslice::rotate_columns(plane, 2));
        let quadrupled = AESBitslice::xtime(&AESBitslice::xtime(&sum));
        for (plane, value) in self.planes.iter_mut().zip(&quadrupled) {
            *plane ^= value;
        }
        self.mix_columns();
    }

    /// AddRoundKey (section 5.1.4).
    pub fn add(&mut self, key: &AESBitslice) {
        for (plane, key) in self.planes.iter_mut().zip(&key.planes) {
            *plane ^= key;
        }
    }

    /// One round of the cipher (SubBytes, ShiftRows, MixColumns and
    /// AddRoundKey, section 5.1) on each block of `blocks` with the key of
    /// the same index, four blocks at a time: AESRound of AEGIS and other
    /// constructions built from the round function.
    pub fn round(blocks: &mut [[u8; 16]], keys: &[[u8; 16]]) {
        assert_eq!(blocks.len(), keys.len(), "one key for each block");
        for (group, keys) in blocks.chunks_mut(AESBitslice::BLOCKS).zip(keys.chunks(AESBitslice::BLOCKS)) {
            let mut state = AESBitslice::from_blocks(group);
            state.sub_bytes();
            state.shift_rows();
            state.mix_columns();
            let mut key = AESBitslice::from_blocks(keys);
            state.add(&key);
            state.to_blocks(group);
            state.zeroize();
            key.zeroize();
        }
    }
}

impl Zeroize for AESBitslice {
    fn zeroize(&mut self) {
        self.planes.zeroize();
    }
}

impl fmt::Debug for AESBitslice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AESBitslice(..)")
    }
}
