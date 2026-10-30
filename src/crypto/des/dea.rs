use core::fmt;

use crate::crypto::{BlockCipher, CryptoError, KeyInit};
use crate::secret::{Choice, ConstantTimeEq, ConstantTimeTable, Zeroize};

/// The Data Encryption Algorithm (SP 800-67r2 section 2) with one 64-bit key,
/// of which the 56 bits other than the parity bits 8, 16, ..., 64 are used.
///
/// The bit permutations select fixed positions with shifts, and the
/// selection functions are read as [`ConstantTimeTable`]s, so no branch or
/// memory access depends on the key or the data.
#[derive(Clone)]
pub struct DES {
    /// The 48-bit blocks K1 to K16 of the key schedule.
    subkeys: [u64; 16],
}

impl DES {
    pub const KEY_SIZE: usize = 8;
    /// IP: bit `i` of the permuted input is bit `IP[i]` of the input (section 2.1).
    pub const INITIAL_PERMUTATION: [u8; 64] = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40,
        32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63,
        55, 47, 39, 31, 23, 15, 7,
    ];
    /// IP^-1, the inverse of IP (section 2.1).
    pub const FINAL_PERMUTATION: [u8; 64] = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53,
        21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1,
        41, 9, 49, 17, 57, 25,
    ];
    /// E, the bit selection from 32 to 48 bits (table 1).
    pub const EXPANSION: [u8; 48] = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20,
        21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
    ];
    /// P, the permutation of the outputs of the selection functions (table 3).
    pub const PERMUTATION: [u8; 32] = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11,
        4, 25,
    ];
    /// PC-1: the bits of C0 (the first 28) and D0 (the last 28) (appendix A).
    pub const PERMUTED_CHOICE_1: [u8; 56] = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63,
        55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
    ];
    /// PC-2: the bits of Kn chosen from CnDn (appendix A).
    pub const PERMUTED_CHOICE_2: [u8; 48] = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    ];
    /// The left rotations of C and D before each of the iterations 1 to 16 (appendix A).
    pub const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
    /// The selection functions S1 to S8: row `i` (from the first and last bits
    /// of B) and column `j` (the middle four bits) (appendix A).
    pub const SELECTION_FUNCTIONS: [[[u8; 16]; 4]; 8] = [
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        ],
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        ],
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        ],
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        ],
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        ],
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        ],
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        ],
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
        ],
    ];
    /// The selection functions as tables indexed by the 6-bit block B.
    pub const SELECTION_TABLES: [ConstantTimeTable<4, 4>; 8] = [
        ConstantTimeTable::from_bytes(&DES::selection_table(&DES::SELECTION_FUNCTIONS[0])),
        ConstantTimeTable::from_bytes(&DES::selection_table(&DES::SELECTION_FUNCTIONS[1])),
        ConstantTimeTable::from_bytes(&DES::selection_table(&DES::SELECTION_FUNCTIONS[2])),
        ConstantTimeTable::from_bytes(&DES::selection_table(&DES::SELECTION_FUNCTIONS[3])),
        ConstantTimeTable::from_bytes(&DES::selection_table(&DES::SELECTION_FUNCTIONS[4])),
        ConstantTimeTable::from_bytes(&DES::selection_table(&DES::SELECTION_FUNCTIONS[5])),
        ConstantTimeTable::from_bytes(&DES::selection_table(&DES::SELECTION_FUNCTIONS[6])),
        ConstantTimeTable::from_bytes(&DES::selection_table(&DES::SELECTION_FUNCTIONS[7])),
    ];
    /// The weak keys (SP 800-67r2 section 3.3.2), with odd parity.
    pub const WEAK_KEYS: [u64; 4] =
        [0x0101_0101_0101_0101, 0xFEFE_FEFE_FEFE_FEFE, 0xE0E0_E0E0_F1F1_F1F1, 0x1F1F_1F1F_0E0E_0E0E];
    /// The semi-weak keys, in pairs that encrypt identically (section 3.3.2).
    pub const SEMI_WEAK_KEYS: [u64; 12] = [
        0x011F_011F_010E_010E,
        0x1F01_1F01_0E01_0E01,
        0x01E0_01E0_01F1_01F1,
        0xE001_E001_F101_F101,
        0x01FE_01FE_01FE_01FE,
        0xFE01_FE01_FE01_FE01,
        0x1FE0_1FE0_0EF1_0EF1,
        0xE01F_E01F_F10E_F10E,
        0x1FFE_1FFE_0EFE_0EFE,
        0xFE1F_FE1F_FE0E_FE0E,
        0xE0FE_E0FE_F1FE_F1FE,
        0xFEE0_FEE0_FEF1_FEF1,
    ];
    /// The possibly weak keys, which give only four distinct subkeys (section 3.3.2).
    pub const POSSIBLY_WEAK_KEYS: [u64; 48] = [
        0x0101_1F1F_0101_0E0E,
        0x1F1F_0101_0E0E_0101,
        0xE0E0_1F1F_F1F1_0E0E,
        0x0101_E0E0_0101_F1F1,
        0x1F1F_E0E0_0E0E_F1F1,
        0xE0E0_FEFE_F1F1_FEFE,
        0x0101_FEFE_0101_FEFE,
        0x1F1F_FEFE_0E0E_FEFE,
        0xE0FE_011F_F1FE_010E,
        0x011F_1F01_010E_0E01,
        0x1FE0_01FE_0EF1_01FE,
        0xE0FE_1F01_F1FE_0E01,
        0x011F_E0FE_010E_F1FE,
        0x1FE0_E01F_0EF1_F10E,
        0xE0FE_FEE0_F1FE_FEF1,
        0x011F_FEE0_010E_FEF1,
        0x1FE0_FE01_0EF1_FE01,
        0xFE01_01FE_FE01_01FE,
        0x01E0_1FFE_01F1_0EFE,
        0x1FFE_01E0_0EFE_01F1,
        0xFE01_1FE0_FE01_0EF1,
        0xFE01_E01F_FE01_F10E,
        0x1FFE_E001_0EFE_F101,
        0xFE1F_01E0_FE0E_01F1,
        0x01E0_E001_01F1_F101,
        0x1FFE_FE1F_0EFE_FE0E,
        0xFE1F_E001_FE0E_F101,
        0x01E0_FE1F_01F1_FE0E,
        0xE001_01E0_F101_01F1,
        0xFE1F_1FFE_FE0E_0EFE,
        0x01FE_1FE0_01FE_0EF1,
        0xE001_1FFE_F101_0EFE,
        0xFEE0_011F_FEF1_010E,
        0x01FE_E01F_01FE_F10E,
        0xE001_FE1F_F101_FE0E,
        0xFEE0_1F01_FEF1_0E01,
        0x01FE_FE01_01FE_FE01,
        0xE01F_01FE_F10E_01FE,
        0xFEE0_E0FE_FEF1_F1FE,
        0x1F01_011F_0E01_010E,
        0xE01F_1FE0_F10E_0EF1,
        0xFEFE_0101_FEFE_0101,
        0x1F01_E0FE_0E01_F1FE,
        0xE01F_FE01_F10E_FE01,
        0xFEFE_1F1F_FEFE_0E0E,
        0x1F01_FEE0_0E01_FEF1,
        0xE0E0_0101_F1F1_0101,
        0xFEFE_E0E0_FEFE_F1F1,
    ];

    pub fn new(key: &[u8; 8]) -> DES {
        let mut key = u64::from_be_bytes(*key);
        let mut cd = DES::permute(key, 64, &DES::PERMUTED_CHOICE_1);
        key.zeroize();
        let (mut c, mut d) = ((cd >> 28) as u32, (cd & 0x0FFF_FFFF) as u32);
        let mut subkeys = [0u64; 16];
        for (subkey, &shift) in subkeys.iter_mut().zip(&DES::SHIFTS) {
            c = ((c << shift) | (c >> (28 - shift as u32))) & 0x0FFF_FFFF;
            d = ((d << shift) | (d >> (28 - shift as u32))) & 0x0FFF_FFFF;
            *subkey = DES::permute(((c as u64) << 28) | d as u64, 56, &DES::PERMUTED_CHOICE_2);
        }
        cd.zeroize();
        c.zeroize();
        d.zeroize();
        DES { subkeys }
    }

    /// The table of a selection function indexed by B: the row is the first
    /// and last bits of B, the column its middle four bits.
    pub const fn selection_table(function: &[[u8; 16]; 4]) -> [u8; 64] {
        let mut table = [0u8; 64];
        let mut b = 0;
        while b < 64 {
            let row = ((b >> 4) & 2) | (b & 1);
            let column = (b >> 1) & 0xF;
            table[b] = function[row][column];
            b += 1;
        }
        table
    }

    /// The bits of `input`, a block of `width` bits whose bit 1 is the most
    /// significant, at the positions `table` lists, as a block of
    /// `table.len()` bits. The positions are public, so this takes the same
    /// time for every input.
    pub fn permute(input: u64, width: u32, table: &[u8]) -> u64 {
        let mut output = 0u64;
        for &position in table {
            output = (output << 1) | ((input >> (width - position as u32)) & 1);
        }
        output
    }

    /// The function f(R, K) of section 2.3: E, the xor with K, the selection functions and P.
    pub fn f(right: u32, subkey: u64) -> u32 {
        let x = DES::permute(right as u64, 32, &DES::EXPANSION) ^ subkey;
        let mut selected = 0u64;
        for (index, table) in DES::SELECTION_TABLES.iter().enumerate() {
            let b = (x >> (42 - 6 * index)) & 0x3F;
            selected = (selected << 4) | table.get(b as usize) as u64;
        }
        DES::permute(selected, 32, &DES::PERMUTATION) as u32
    }

    /// IP, the 16 iterations with the subkeys in `subkeys`, the final interchange and IP^-1 (section 2.1).
    pub fn apply_rounds<'a>(block: &mut [u8; 8], subkeys: impl Iterator<Item = &'a u64>) {
        let permuted = DES::permute(u64::from_be_bytes(*block), 64, &DES::INITIAL_PERMUTATION);
        let (mut left, mut right) = ((permuted >> 32) as u32, permuted as u32);
        for &subkey in subkeys {
            let next = left ^ DES::f(right, subkey);
            left = right;
            right = next;
        }
        let preoutput = ((right as u64) << 32) | left as u64;
        *block = DES::permute(preoutput, 64, &DES::FINAL_PERMUTATION).to_be_bytes();
    }

    /// Whether `key` is a weak, semi-weak or possibly weak key of section 3.3.2,
    /// ignoring its parity bits; the comparisons take the same time for every key.
    pub fn is_weak(key: &[u8; 8]) -> bool {
        const PARITY: u64 = 0x0101_0101_0101_0101;
        let key = u64::from_be_bytes(*key) & !PARITY;
        let mut weak = Choice::FALSE;
        for candidate in DES::WEAK_KEYS.iter().chain(&DES::SEMI_WEAK_KEYS).chain(&DES::POSSIBLY_WEAK_KEYS) {
            weak |= key.ct_eq(&(candidate & !PARITY));
        }
        weak.into_bool()
    }

    /// The subkeys K1 to K16 (48 bits each).
    pub fn subkeys(&self) -> &[u64; 16] {
        &self.subkeys
    }
}

impl BlockCipher for DES {
    const BLOCK_SIZE: usize = 8;
    type Block = [u8; 8];

    fn encrypt_block(&self, block: &mut [u8; 8]) {
        DES::apply_rounds(block, self.subkeys.iter());
    }

    /// The inverse transformation uses K16 first and K1 last (section 2.2).
    fn decrypt_block(&self, block: &mut [u8; 8]) {
        DES::apply_rounds(block, self.subkeys.iter().rev());
    }
}

impl KeyInit for DES {
    const MINIMUM_KEY_SIZE: usize = 8;
    const MAXIMUM_KEY_SIZE: usize = 8;

    fn new_from_slice(key: &[u8]) -> Result<DES, CryptoError> {
        DES::check_key_length(key.len())?;
        let key: &[u8; 8] = key.try_into().map_err(|_| CryptoError::InvalidParameter)?;
        Ok(DES::new(key))
    }
}

impl Zeroize for DES {
    fn zeroize(&mut self) {
        self.subkeys.zeroize();
    }
}

impl Drop for DES {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for DES {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DES(..)")
    }
}
