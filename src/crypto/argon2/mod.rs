//! Argon2 (RFC 9106): the memory-hard password hashing and key derivation
//! function, in its variants Argon2d, Argon2i and Argon2id.

use alloc::vec::Vec;
use core::fmt;

use crate::crypto::CryptoError;
use crate::hash::blake::v2::BLAKE2b;
use crate::secret::Zeroize;

/// The variant of Argon2, the type y of RFC 9106 section 3.1.
///
/// Argon2d chooses the reference blocks from the data (fastest, but its
/// memory accesses depend on the password); Argon2i from the position only;
/// Argon2id like Argon2i for the first half of the first pass and like
/// Argon2d after it. Section 4 recommends Argon2id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argon2Type {
    Argon2d = 0,
    Argon2i = 1,
    Argon2id = 2,
}

/// A block of memory: 1024 bytes as 128 little-endian 64-bit words.
pub type Argon2Block = [u64; 128];

/// Argon2 with the memory size m in KiB, the number of passes t and the
/// degree of parallelism p (section 3.1), version 0x13.
///
/// The lanes are computed one after the other within each slice, as section
/// 3.2 allows; the memory (m', rounded down to a multiple of 4p blocks) is
/// allocated for each derivation and zeroized after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2 {
    variant: Argon2Type,
    memory: u32,
    passes: u32,
    lanes: u32,
}

impl Argon2 {
    /// The version number v (section 3.1).
    pub const VERSION: u32 = 0x13;
    /// The number of slices SL (section 3.4).
    pub const SLICES: u32 = 4;
    /// The reference indices of one address block of Argon2i.
    pub const ADDRESSES_PER_BLOCK: usize = 128;
    pub const MINIMUM_TAG: usize = 4;

    /// Checks the parameters of section 3.1: p from 1 to 2^24 - 1, m of at least 8p KiB and t of at least 1.
    pub fn new(variant: Argon2Type, memory: u32, passes: u32, lanes: u32) -> Result<Argon2, CryptoError> {
        if lanes == 0 || lanes >= 1 << 24 || (memory as u64) < 8 * lanes as u64 || passes == 0 {
            return Err(CryptoError::InvalidParameter);
        }
        Ok(Argon2 { variant, memory, passes, lanes })
    }

    pub fn variant(&self) -> Argon2Type {
        self.variant
    }

    /// m' = 4p × ⌊m / 4p⌋, the number of blocks (section 3.2).
    pub fn blocks(&self) -> u32 {
        4 * self.lanes * (self.memory / (4 * self.lanes))
    }

    /// The bytes of memory a derivation allocates.
    pub fn memory_bytes(&self) -> u64 {
        1024 * self.blocks() as u64
    }

    /// H' of the concatenation of `input`, `out.len()` bytes long (1 to 2^32 - 1, section 3.3).
    pub fn variable_hash(input: &[&[u8]], out: &mut [u8]) -> Result<(), CryptoError> {
        let length = u32::try_from(out.len()).map_err(|_| CryptoError::InputLength { length: out.len() })?;
        // H^x of `first` followed by the pieces of `rest`, into `out` (x = out.len() ≤ 64).
        let hash = |first: &[u8], rest: &[&[u8]], out: &mut [u8]| -> Result<(), CryptoError> {
            let mut blake = BLAKE2b::new(out.len()).map_err(|_| CryptoError::InvalidParameter)?;
            blake.update(first);
            for piece in rest {
                blake.update(piece);
            }
            blake.finalize_into(out).map_err(|_| CryptoError::InvalidParameter)
        };
        let prefix = length.to_le_bytes();
        if out.len() <= 64 {
            return hash(&prefix, input, out);
        }
        // V_1 = H^64(LE32(T) || A), V_i = H^64(V_(i-1)); the output is W_1 || ... || W_r || V_(r+1).
        let r = out.len().div_ceil(32) - 2;
        let mut v = [0u8; 64];
        let mut previous;
        hash(&prefix, input, &mut v)?;
        out[..32].copy_from_slice(&v[..32]);
        for index in 1..r {
            previous = v;
            hash(&previous, &[], &mut v)?;
            out[32 * index..32 * index + 32].copy_from_slice(&v[..32]);
        }
        previous = v;
        let result = hash(&previous, &[], &mut out[32 * r..]);
        v.zeroize();
        previous.zeroize();
        result
    }

    /// GB(a, b, c, d) of section 3.6: the additions of BLAKE2b with the products of the low halves.
    pub fn gb(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
        let add = |x: u64, y: u64| {
            x.wrapping_add(y).wrapping_add(2u64.wrapping_mul(x & 0xFFFF_FFFF).wrapping_mul(y & 0xFFFF_FFFF))
        };
        v[a] = add(v[a], v[b]);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = add(v[c], v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = add(v[a], v[b]);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = add(v[c], v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    }

    /// The permutation P (section 3.6) on 16 words.
    pub fn permute(v: &mut [u64; 16]) {
        Argon2::gb(v, 0, 4, 8, 12);
        Argon2::gb(v, 1, 5, 9, 13);
        Argon2::gb(v, 2, 6, 10, 14);
        Argon2::gb(v, 3, 7, 11, 15);
        Argon2::gb(v, 0, 5, 10, 15);
        Argon2::gb(v, 1, 6, 11, 12);
        Argon2::gb(v, 2, 7, 8, 13);
        Argon2::gb(v, 3, 4, 9, 14);
    }

    /// G(X, Y) (section 3.5), xored into `out` when `accumulate` (the passes after the first, section 3.2 step 6).
    pub fn compress(x: &Argon2Block, y: &Argon2Block, out: &mut Argon2Block, accumulate: bool) {
        let mut r = [0u64; 128];
        for (word, (a, b)) in r.iter_mut().zip(x.iter().zip(y)) {
            *word = a ^ b;
        }
        let mut z = r;
        // The rows: registers R_(8i) to R_(8i+7), 16 words each row.
        for row in 0..8 {
            let mut v: [u64; 16] = z[16 * row..16 * row + 16].try_into().expect("16 words");
            Argon2::permute(&mut v);
            z[16 * row..16 * row + 16].copy_from_slice(&v);
        }
        // The columns: registers R_i, R_(i+8), ..., R_(i+56), two words each.
        for column in 0..8 {
            let mut v = [0u64; 16];
            for register in 0..8 {
                v[2 * register] = z[16 * register + 2 * column];
                v[2 * register + 1] = z[16 * register + 2 * column + 1];
            }
            Argon2::permute(&mut v);
            for register in 0..8 {
                z[16 * register + 2 * column] = v[2 * register];
                z[16 * register + 2 * column + 1] = v[2 * register + 1];
            }
        }
        for ((word, z), r) in out.iter_mut().zip(&z).zip(&r) {
            *word = if accumulate { *word ^ z ^ r } else { z ^ r };
        }
        r.zeroize();
        z.zeroize();
    }

    /// H_0 (section 3.2 step 1).
    pub fn initial_hash(
        &self,
        tag_length: usize,
        password: &[u8],
        salt: &[u8],
        secret: &[u8],
        associated: &[u8],
    ) -> Result<[u8; 64], CryptoError> {
        let mut blake = BLAKE2b::new(64).map_err(|_| CryptoError::InvalidParameter)?;
        for value in [self.lanes, tag_length as u32, self.memory, self.passes, Argon2::VERSION, self.variant as u32] {
            blake.update(&value.to_le_bytes());
        }
        for input in [password, salt, secret, associated] {
            blake.update(&(input.len() as u32).to_le_bytes());
            blake.update(input);
        }
        let mut h0 = [0u8; 64];
        blake.finalize_into(&mut h0).map_err(|_| CryptoError::InvalidParameter)?;
        Ok(h0)
    }

    /// The index z of the reference block in its lane (section 3.4.2) for the
    /// block `index` of the segment, from J_1.
    pub fn reference_index(&self, pass: u32, slice: u32, index: u32, j1: u32, same_lane: bool) -> u32 {
        let lane_length = self.blocks() / self.lanes;
        let segment_length = lane_length / Argon2::SLICES;
        // |W|: the blocks finished in the window, without B[i][j-1] in the current lane
        // and without the last one of the window at the start of a segment in another lane.
        let area = if pass == 0 {
            if slice == 0 {
                index - 1
            } else if same_lane {
                slice * segment_length + index - 1
            } else {
                slice * segment_length - (index == 0) as u32
            }
        } else if same_lane {
            lane_length - segment_length + index - 1
        } else {
            lane_length - segment_length - (index == 0) as u32
        };
        let x = (j1 as u64 * j1 as u64) >> 32;
        let y = (area as u64 * x) >> 32;
        let relative = area as u64 - 1 - y;
        // The window starts after the current segment, from the second pass on.
        let start = if pass == 0 || slice == Argon2::SLICES - 1 { 0 } else { (slice + 1) * segment_length };
        ((start as u64 + relative) % lane_length as u64) as u32
    }

    /// The tag of `out.len()` bytes (4 to 2^32 - 1) from the password, the
    /// salt, the optional secret K and the optional associated data X (section 3.2).
    pub fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        secret: &[u8],
        associated: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if out.len() < Argon2::MINIMUM_TAG || out.len() as u64 > u32::MAX as u64 {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        for input in [password, salt, secret, associated] {
            if input.len() as u64 > u32::MAX as u64 {
                return Err(CryptoError::InputLength { length: input.len() });
            }
        }
        let mut memory = self.allocate()?;
        let mut h0 = self.initial_hash(out.len(), password, salt, secret, associated)?;
        let result = self.initialize(&h0, &mut memory).map(|()| {
            for pass in 0..self.passes {
                self.fill_pass(&mut memory, pass);
            }
        });
        h0.zeroize();
        let result = result.and_then(|()| self.tag(&memory, out));
        memory.iter_mut().for_each(|block| block.zeroize());
        result
    }

    /// The m' blocks of memory, zero.
    pub fn allocate(&self) -> Result<Vec<Argon2Block>, CryptoError> {
        let blocks = self.blocks() as usize;
        let mut memory: Vec<Argon2Block> = Vec::new();
        memory.try_reserve_exact(blocks).map_err(|_| CryptoError::Allocation)?;
        memory.resize(blocks, [0u64; 128]);
        Ok(memory)
    }

    /// B\[i\]\[0\] = H'^1024(H_0 || LE32(0) || LE32(i)) and B\[i\]\[1\] = H'^1024(H_0 || LE32(1) || LE32(i)) (steps 3 and 4).
    pub fn initialize(&self, h0: &[u8; 64], memory: &mut [Argon2Block]) -> Result<(), CryptoError> {
        let lane_length = memory.len() / self.lanes as usize;
        let mut bytes = [0u8; 1024];
        for lane in 0..self.lanes as usize {
            for column in 0..2u32 {
                Argon2::variable_hash(&[h0, &column.to_le_bytes(), &(lane as u32).to_le_bytes()], &mut bytes)?;
                for (word, chunk) in
                    memory[lane * lane_length + column as usize].iter_mut().zip(bytes.as_chunks::<8>().0)
                {
                    *word = u64::from_le_bytes(*chunk);
                }
            }
        }
        bytes.zeroize();
        Ok(())
    }

    /// One pass over the memory, slice by slice (steps 5 and 6).
    pub fn fill_pass(&self, memory: &mut [Argon2Block], pass: u32) {
        let blocks = memory.len();
        let lanes = self.lanes as usize;
        let lane_length = blocks / lanes;
        let segment_length = lane_length / Argon2::SLICES as usize;
        let zero = [0u64; 128];
        let (mut address, mut input) = ([0u64; 128], [0u64; 128]);
        for slice in 0..Argon2::SLICES {
            for lane in 0..lanes {
                let independent = match self.variant {
                    Argon2Type::Argon2d => false,
                    Argon2Type::Argon2i => true,
                    Argon2Type::Argon2id => pass == 0 && slice < Argon2::SLICES / 2,
                };
                if independent {
                    // Z of section 3.4.1.2; word 6 counts the address blocks.
                    input = [0u64; 128];
                    input[..6].copy_from_slice(&[
                        pass as u64,
                        lane as u64,
                        slice as u64,
                        blocks as u64,
                        self.passes as u64,
                        self.variant as u64,
                    ]);
                }
                let start = if pass == 0 && slice == 0 { 2 } else { 0 };
                if independent && start != 0 {
                    Argon2::next_addresses(&mut input, &mut address, &zero);
                }
                for index in start..segment_length {
                    let column = slice as usize * segment_length + index;
                    let current = lane * lane_length + column;
                    let previous = if column == 0 { current + lane_length - 1 } else { current - 1 };
                    let pseudo_random = if independent {
                        if index % Argon2::ADDRESSES_PER_BLOCK == 0 {
                            Argon2::next_addresses(&mut input, &mut address, &zero);
                        }
                        address[index % Argon2::ADDRESSES_PER_BLOCK]
                    } else {
                        memory[previous][0]
                    };
                    // J_2 chooses the lane; the first slice of the first pass stays in the current lane.
                    let reference_lane =
                        if pass == 0 && slice == 0 { lane } else { ((pseudo_random >> 32) % lanes as u64) as usize };
                    let reference =
                        self.reference_index(pass, slice, index as u32, pseudo_random as u32, reference_lane == lane)
                            as usize;
                    let (mut x, mut y) = (memory[previous], memory[reference_lane * lane_length + reference]);
                    Argon2::compress(&x, &y, &mut memory[current], pass > 0);
                    x.zeroize();
                    y.zeroize();
                }
            }
        }
        address.zeroize();
        input.zeroize();
    }

    /// C, the xor of the last column, then the tag H'^T(C) (steps 7 and 8).
    pub fn tag(&self, memory: &[Argon2Block], out: &mut [u8]) -> Result<(), CryptoError> {
        let lane_length = memory.len() / self.lanes as usize;
        let mut c = memory[lane_length - 1];
        for lane in 1..self.lanes as usize {
            for (word, value) in c.iter_mut().zip(&memory[lane * lane_length + lane_length - 1]) {
                *word ^= value;
            }
        }
        let mut bytes = [0u8; 1024];
        for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(&c) {
            *chunk = word.to_le_bytes();
        }
        let result = Argon2::variable_hash(&[&bytes], out);
        bytes.zeroize();
        c.zeroize();
        result
    }

    /// The next block of reference indices of Argon2i: G(0, G(0, Z || counter || 0)) (section 3.4.1.2).
    pub fn next_addresses(input: &mut Argon2Block, address: &mut Argon2Block, zero: &Argon2Block) {
        input[6] += 1;
        Argon2::compress(zero, input, address, false);
        let first = *address;
        Argon2::compress(zero, &first, address, false);
    }
}

impl fmt::Display for Argon2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}(m = {}, t = {}, p = {})", self.variant, self.memory, self.passes, self.lanes)
    }
}
