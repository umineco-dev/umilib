//! Camellia (RFC 3713, ISO/IEC 18033-3): the 128-bit block cipher of NTT and
//! Mitsubishi Electric, a Feistel network with FL- and FLINV-functions.

use core::fmt;

use crate::crypto::{BlockCipher, CryptoError, KeyInit};
use crate::secret::{ConstantTimeTable, Zeroize};

/// The components of Camellia (RFC 3713 section 2.4) and its key schedule
/// (section 2.2), shared by the three key sizes.
///
/// The S-boxes are read as [`ConstantTimeTable`]s, so no memory access
/// depends on the key or the data.
pub struct CamelliaComponents;

impl CamelliaComponents {
    /// The bytes of SBOX1 (section 2.4.1).
    pub const SBOX1_BYTES: [u8; 256] = [
        0x70, 0x82, 0x2C, 0xEC, 0xB3, 0x27, 0xC0, 0xE5, 0xE4, 0x85, 0x57, 0x35, 0xEA, 0x0C, 0xAE, 0x41, 0x23, 0xEF,
        0x6B, 0x93, 0x45, 0x19, 0xA5, 0x21, 0xED, 0x0E, 0x4F, 0x4E, 0x1D, 0x65, 0x92, 0xBD, 0x86, 0xB8, 0xAF, 0x8F,
        0x7C, 0xEB, 0x1F, 0xCE, 0x3E, 0x30, 0xDC, 0x5F, 0x5E, 0xC5, 0x0B, 0x1A, 0xA6, 0xE1, 0x39, 0xCA, 0xD5, 0x47,
        0x5D, 0x3D, 0xD9, 0x01, 0x5A, 0xD6, 0x51, 0x56, 0x6C, 0x4D, 0x8B, 0x0D, 0x9A, 0x66, 0xFB, 0xCC, 0xB0, 0x2D,
        0x74, 0x12, 0x2B, 0x20, 0xF0, 0xB1, 0x84, 0x99, 0xDF, 0x4C, 0xCB, 0xC2, 0x34, 0x7E, 0x76, 0x05, 0x6D, 0xB7,
        0xA9, 0x31, 0xD1, 0x17, 0x04, 0xD7, 0x14, 0x58, 0x3A, 0x61, 0xDE, 0x1B, 0x11, 0x1C, 0x32, 0x0F, 0x9C, 0x16,
        0x53, 0x18, 0xF2, 0x22, 0xFE, 0x44, 0xCF, 0xB2, 0xC3, 0xB5, 0x7A, 0x91, 0x24, 0x08, 0xE8, 0xA8, 0x60, 0xFC,
        0x69, 0x50, 0xAA, 0xD0, 0xA0, 0x7D, 0xA1, 0x89, 0x62, 0x97, 0x54, 0x5B, 0x1E, 0x95, 0xE0, 0xFF, 0x64, 0xD2,
        0x10, 0xC4, 0x00, 0x48, 0xA3, 0xF7, 0x75, 0xDB, 0x8A, 0x03, 0xE6, 0xDA, 0x09, 0x3F, 0xDD, 0x94, 0x87, 0x5C,
        0x83, 0x02, 0xCD, 0x4A, 0x90, 0x33, 0x73, 0x67, 0xF6, 0xF3, 0x9D, 0x7F, 0xBF, 0xE2, 0x52, 0x9B, 0xD8, 0x26,
        0xC8, 0x37, 0xC6, 0x3B, 0x81, 0x96, 0x6F, 0x4B, 0x13, 0xBE, 0x63, 0x2E, 0xE9, 0x79, 0xA7, 0x8C, 0x9F, 0x6E,
        0xBC, 0x8E, 0x29, 0xF5, 0xF9, 0xB6, 0x2F, 0xFD, 0xB4, 0x59, 0x78, 0x98, 0x06, 0x6A, 0xE7, 0x46, 0x71, 0xBA,
        0xD4, 0x25, 0xAB, 0x42, 0x88, 0xA2, 0x8D, 0xFA, 0x72, 0x07, 0xB9, 0x55, 0xF8, 0xEE, 0xAC, 0x0A, 0x36, 0x49,
        0x2A, 0x68, 0x3C, 0x38, 0xF1, 0xA4, 0x40, 0x28, 0xD3, 0x7B, 0xBB, 0xC9, 0x43, 0xC1, 0x15, 0xE3, 0xAD, 0xF4,
        0x77, 0xC7, 0x80, 0x9E,
    ];
    pub const SBOX1: ConstantTimeTable<32, 8> = ConstantTimeTable::from_bytes(&CamelliaComponents::SBOX1_BYTES);
    /// SBOX2\[x\] = SBOX1\[x\] <<< 1.
    pub const SBOX2: ConstantTimeTable<32, 8> =
        ConstantTimeTable::from_bytes(&CamelliaComponents::rotate_outputs(&CamelliaComponents::SBOX1_BYTES, 1));
    /// SBOX3\[x\] = SBOX1\[x\] <<< 7.
    pub const SBOX3: ConstantTimeTable<32, 8> =
        ConstantTimeTable::from_bytes(&CamelliaComponents::rotate_outputs(&CamelliaComponents::SBOX1_BYTES, 7));
    /// SBOX4\[x\] = SBOX1\[x <<< 1\].
    pub const SBOX4: ConstantTimeTable<32, 8> =
        ConstantTimeTable::from_bytes(&CamelliaComponents::rotate_inputs(&CamelliaComponents::SBOX1_BYTES, 1));
    /// Sigma1 to Sigma6, the keys of the F-functions of the key schedule (section 2.2).
    pub const SIGMA: [u64; 6] = [
        0xA09E_667F_3BCC_908B,
        0xB67A_E858_4CAA_73B2,
        0xC6EF_372F_E94F_82BE,
        0x54FF_53A5_F1D3_6F1C,
        0x10E5_27FA_DE68_2D1D,
        0xB056_88C2_B3E6_C1FD,
    ];

    /// The table of `table[x] <<< rotation`.
    pub const fn rotate_outputs(table: &[u8; 256], rotation: u32) -> [u8; 256] {
        let mut out = [0u8; 256];
        let mut index = 0;
        while index < 256 {
            out[index] = table[index].rotate_left(rotation);
            index += 1;
        }
        out
    }

    /// The table of `table[x <<< rotation]`.
    pub const fn rotate_inputs(table: &[u8; 256], rotation: u32) -> [u8; 256] {
        let mut out = [0u8; 256];
        let mut index = 0;
        while index < 256 {
            out[index] = table[(index as u8).rotate_left(rotation) as usize];
            index += 1;
        }
        out
    }

    /// The F-function (section 2.4.1): the S-boxes on the bytes of `input ^ key`, then the P-function.
    pub fn f(input: u64, key: u64) -> u64 {
        let x = (input ^ key).to_be_bytes();
        let t = [
            CamelliaComponents::SBOX1.get(x[0] as usize) as u8,
            CamelliaComponents::SBOX2.get(x[1] as usize) as u8,
            CamelliaComponents::SBOX3.get(x[2] as usize) as u8,
            CamelliaComponents::SBOX4.get(x[3] as usize) as u8,
            CamelliaComponents::SBOX2.get(x[4] as usize) as u8,
            CamelliaComponents::SBOX3.get(x[5] as usize) as u8,
            CamelliaComponents::SBOX4.get(x[6] as usize) as u8,
            CamelliaComponents::SBOX1.get(x[7] as usize) as u8,
        ];
        let y = [
            t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7],
            t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7],
            t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7],
            t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6],
            t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7],
            t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7],
            t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7],
            t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6],
        ];
        u64::from_be_bytes(y)
    }

    /// The FL-function (section 2.4.2).
    pub fn fl(input: u64, key: u64) -> u64 {
        let (mut x1, mut x2) = ((input >> 32) as u32, input as u32);
        let (k1, k2) = ((key >> 32) as u32, key as u32);
        x2 ^= (x1 & k1).rotate_left(1);
        x1 ^= x2 | k2;
        ((x1 as u64) << 32) | x2 as u64
    }

    /// The FLINV-function, the inverse of the FL-function (section 2.4.2).
    pub fn fl_inverse(input: u64, key: u64) -> u64 {
        let (mut y1, mut y2) = ((input >> 32) as u32, input as u32);
        let (k1, k2) = ((key >> 32) as u32, key as u32);
        y1 ^= y2 | k2;
        y2 ^= (y1 & k1).rotate_left(1);
        ((y1 as u64) << 32) | y2 as u64
    }

    /// KL and KR of a key of 16, 24 or 32 bytes (section 2.2).
    pub fn split_key(key: &[u8]) -> (u128, u128) {
        let kl = u128::from_be_bytes(key[..16].try_into().expect("16 bytes"));
        let kr = match key.len() {
            16 => 0,
            24 => {
                let right = u64::from_be_bytes(key[16..].try_into().expect("eight bytes"));
                ((right as u128) << 64) | !right as u128
            }
            _ => u128::from_be_bytes(key[16..32].try_into().expect("16 bytes")),
        };
        (kl, kr)
    }

    /// KA and KB from KL and KR (section 2.2).
    pub fn derive(kl: u128, kr: u128) -> (u128, u128) {
        let f = CamelliaComponents::f;
        let sigma = CamelliaComponents::SIGMA;
        let mut d1 = ((kl ^ kr) >> 64) as u64;
        let mut d2 = (kl ^ kr) as u64;
        d2 ^= f(d1, sigma[0]);
        d1 ^= f(d2, sigma[1]);
        d1 ^= (kl >> 64) as u64;
        d2 ^= kl as u64;
        d2 ^= f(d1, sigma[2]);
        d1 ^= f(d2, sigma[3]);
        let ka = ((d1 as u128) << 64) | d2 as u128;
        d1 = ((ka ^ kr) >> 64) as u64;
        d2 = (ka ^ kr) as u64;
        d2 ^= f(d1, sigma[4]);
        d1 ^= f(d2, sigma[5]);
        let kb = ((d1 as u128) << 64) | d2 as u128;
        d1.zeroize();
        d2.zeroize();
        (ka, kb)
    }

    /// The left (`high`) or right half of `value <<< rotation`.
    pub fn half(value: u128, rotation: u32, high: bool) -> u64 {
        let rotated = value.rotate_left(rotation);
        if high { (rotated >> 64) as u64 } else { rotated as u64 }
    }

    /// The data randomizing part (sections 2.3.1 and 2.3.2) with the whitening
    /// keys `kw`, the round keys `k` (six rounds between FL-functions) and
    /// the keys `ke` of the FL- and FLINV-functions; decryption takes the
    /// keys in the reverse order (section 2.3.3).
    pub fn process(block: &mut [u8; 16], kw: &[u64; 4], k: &[u64], ke: &[u64], decrypt: bool) {
        let rounds = k.len();
        let round_key = |index: usize| if decrypt { k[rounds - 1 - index] } else { k[index] };
        let fl_key = |index: usize| if decrypt { ke[ke.len() - 1 - index] } else { ke[index] };
        let (pre, post) = if decrypt { ([kw[2], kw[3]], [kw[0], kw[1]]) } else { ([kw[0], kw[1]], [kw[2], kw[3]]) };
        let mut d1 = u64::from_be_bytes(block[..8].try_into().expect("eight bytes")) ^ pre[0];
        let mut d2 = u64::from_be_bytes(block[8..].try_into().expect("eight bytes")) ^ pre[1];
        for round in (0..rounds).step_by(2) {
            if round > 0 && round % 6 == 0 {
                d1 = CamelliaComponents::fl(d1, fl_key(round / 3 - 2));
                d2 = CamelliaComponents::fl_inverse(d2, fl_key(round / 3 - 1));
            }
            d2 ^= CamelliaComponents::f(d1, round_key(round));
            d1 ^= CamelliaComponents::f(d2, round_key(round + 1));
        }
        d2 ^= post[0];
        d1 ^= post[1];
        block[..8].copy_from_slice(&d2.to_be_bytes());
        block[8..].copy_from_slice(&d1.to_be_bytes());
    }
}

macro_rules! camellia {
    ($(#[$documentation:meta])* $name:ident, $key:literal, $rounds:literal) => {
        $(#[$documentation])*
        #[derive(Clone)]
        pub struct $name {
            kw: [u64; 4],
            k: [u64; $rounds],
            ke: [u64; $rounds / 3 - 2],
        }

        impl $name {
            pub const KEY_SIZE: usize = $key;
            pub const ROUNDS: usize = $rounds;

            /// The whitening keys kw1 to kw4.
            pub fn whitening_keys(&self) -> &[u64; 4] {
                &self.kw
            }

            /// The round keys k1 to k18 or k24.
            pub fn round_keys(&self) -> &[u64; $rounds] {
                &self.k
            }

            /// The keys ke1 to ke4 or ke6 of the FL- and FLINV-functions.
            pub fn fl_keys(&self) -> &[u64; $rounds / 3 - 2] {
                &self.ke
            }
        }

        impl BlockCipher for $name {
            const BLOCK_SIZE: usize = 16;
            type Block = [u8; 16];

            fn encrypt_block(&self, block: &mut [u8; 16]) {
                CamelliaComponents::process(block, &self.kw, &self.k, &self.ke, false);
            }

            fn decrypt_block(&self, block: &mut [u8; 16]) {
                CamelliaComponents::process(block, &self.kw, &self.k, &self.ke, true);
            }
        }

        impl KeyInit for $name {
            const MINIMUM_KEY_SIZE: usize = $key;
            const MAXIMUM_KEY_SIZE: usize = $key;

            fn new_from_slice(key: &[u8]) -> Result<$name, CryptoError> {
                $name::check_key_length(key.len())?;
                let key: &[u8; $key] = key.try_into().map_err(|_| CryptoError::InvalidParameter)?;
                Ok($name::new(key))
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.kw.zeroize();
                self.k.zeroize();
                self.ke.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

camellia!(
    /// Camellia with a 128-bit key: 18 rounds.
    Camellia128, 16, 18
);
camellia!(
    /// Camellia with a 192-bit key: 24 rounds.
    Camellia192, 24, 24
);
camellia!(
    /// Camellia with a 256-bit key: 24 rounds.
    Camellia256, 32, 24
);

impl Camellia128 {
    /// The subkeys of a 128-bit key (section 2.2).
    pub fn new(key: &[u8; 16]) -> Camellia128 {
        let (mut kl, _) = CamelliaComponents::split_key(key);
        let (mut ka, _) = CamelliaComponents::derive(kl, 0);
        let half = CamelliaComponents::half;
        let kw = [half(kl, 0, true), half(kl, 0, false), half(ka, 111, true), half(ka, 111, false)];
        let k = [
            half(ka, 0, true),
            half(ka, 0, false),
            half(kl, 15, true),
            half(kl, 15, false),
            half(ka, 15, true),
            half(ka, 15, false),
            half(kl, 45, true),
            half(kl, 45, false),
            half(ka, 45, true),
            half(kl, 60, false),
            half(ka, 60, true),
            half(ka, 60, false),
            half(kl, 94, true),
            half(kl, 94, false),
            half(ka, 94, true),
            half(ka, 94, false),
            half(kl, 111, true),
            half(kl, 111, false),
        ];
        let ke = [half(ka, 30, true), half(ka, 30, false), half(kl, 77, true), half(kl, 77, false)];
        kl.zeroize();
        ka.zeroize();
        Camellia128 { kw, k, ke }
    }
}

macro_rules! camellia_long_key {
    ($name:ident, $key:literal) => {
        impl $name {
            /// The subkeys of a 192-bit or 256-bit key (section 2.2).
            pub fn new(key: &[u8; $key]) -> $name {
                let (mut kl, mut kr) = CamelliaComponents::split_key(key);
                let (mut ka, mut kb) = CamelliaComponents::derive(kl, kr);
                let half = CamelliaComponents::half;
                let kw = [half(kl, 0, true), half(kl, 0, false), half(kb, 111, true), half(kb, 111, false)];
                let k = [
                    half(kb, 0, true),
                    half(kb, 0, false),
                    half(kr, 15, true),
                    half(kr, 15, false),
                    half(ka, 15, true),
                    half(ka, 15, false),
                    half(kb, 30, true),
                    half(kb, 30, false),
                    half(kl, 45, true),
                    half(kl, 45, false),
                    half(ka, 45, true),
                    half(ka, 45, false),
                    half(kr, 60, true),
                    half(kr, 60, false),
                    half(kb, 60, true),
                    half(kb, 60, false),
                    half(kl, 77, true),
                    half(kl, 77, false),
                    half(kr, 94, true),
                    half(kr, 94, false),
                    half(ka, 94, true),
                    half(ka, 94, false),
                    half(kl, 111, true),
                    half(kl, 111, false),
                ];
                let ke = [
                    half(kr, 30, true),
                    half(kr, 30, false),
                    half(kl, 60, true),
                    half(kl, 60, false),
                    half(ka, 77, true),
                    half(ka, 77, false),
                ];
                kl.zeroize();
                kr.zeroize();
                ka.zeroize();
                kb.zeroize();
                $name { kw, k, ke }
            }
        }
    };
}

camellia_long_key!(Camellia192, 24);
camellia_long_key!(Camellia256, 32);
