use super::{SLHDSAHash, SLHDSASHA2Category1, SLHDSASHA2Category3And5, SLHDSASHAKE};

/// The largest values of the parameter sets of FIPS 205, which bound the
/// buffers of [`SLHDSA`](super::SLHDSA).
pub struct SLHDSALimits;

impl SLHDSALimits {
    /// The largest n (32).
    pub const N: usize = 32;
    /// The largest len (67, of n = 32).
    pub const LEN: usize = 67;
    /// The largest k (35).
    pub const K: usize = 35;
    /// The largest m (49).
    pub const M: usize = 49;
    /// The bytes of the largest WOTS+ signature, len n.
    pub const WOTS: usize = SLHDSALimits::LEN * SLHDSALimits::N;
    /// The bytes of the largest FORS roots, k n.
    pub const FORS_ROOTS: usize = SLHDSALimits::K * SLHDSALimits::N;
}

/// A parameter set of SLH-DSA (FIPS 205 table 2): the security parameter n,
/// the height h of the hypertree, its d layers of XMSS trees of height h',
/// the k FORS trees of height a, and the family of hash functions. A
/// parameter set is a type of no value, given to [`SLHDSA`](super::SLHDSA).
pub trait SLHDSAParameters: 'static {
    /// The name of the parameter set, such as `SLH-DSA-SHA2-128s`.
    const NAME: &'static str;
    const N: usize;
    const H: usize;
    const D: usize;
    const A: usize;
    const K: usize;
    /// The functions H_msg, PRF, PRF_msg, F, H and T_ℓ.
    type Hash: SLHDSAHash;

    /// lg w: 4 for every parameter set of FIPS 205.
    const LG_W: usize = 4;
    /// w = 2^lg w.
    const W: u32 = 1 << Self::LG_W;
    /// h' = h / d.
    const HP: usize = Self::H / Self::D;
    /// len1 = ceil(8 n / lg w) (equation 5.2).
    const LEN1: usize = (8 * Self::N).div_ceil(Self::LG_W);
    /// len2 = floor(log2(len1 (w - 1)) / lg w) + 1 (equation 5.3), 3 for every parameter set.
    const LEN2: usize =
        ((usize::BITS - 1 - (Self::LEN1 * (Self::W as usize - 1)).leading_zeros()) as usize / Self::LG_W) + 1;
    /// len = len1 + len2 (equation 5.4).
    const LEN: usize = Self::LEN1 + Self::LEN2;
    /// The bytes of the message digest that select the FORS leaves: ceil(k a / 8).
    const MD_SIZE: usize = (Self::K * Self::A).div_ceil(8);
    /// The bytes that select the XMSS tree at the bottom: ceil((h - h') / 8).
    const TREE_SIZE: usize = (Self::H - Self::HP).div_ceil(8);
    /// The bytes that select the WOTS+ key: ceil(h' / 8).
    const LEAF_SIZE: usize = Self::HP.div_ceil(8);
    /// m, the bytes of the message digest.
    const M: usize = Self::MD_SIZE + Self::TREE_SIZE + Self::LEAF_SIZE;
    /// The bytes of a public key: 2 n.
    const PUBLIC_KEY_SIZE: usize = 2 * Self::N;
    /// The bytes of a private key: 4 n.
    const PRIVATE_KEY_SIZE: usize = 4 * Self::N;
    /// The bytes of a FORS signature: k (1 + a) n.
    const FORS_SIGNATURE_SIZE: usize = Self::K * (1 + Self::A) * Self::N;
    /// The bytes of an XMSS signature: (h' + len) n.
    const XMSS_SIGNATURE_SIZE: usize = (Self::HP + Self::LEN) * Self::N;
    /// The bytes of a signature: (1 + k (1 + a) + h + d len) n.
    const SIGNATURE_SIZE: usize = (1 + Self::K * (1 + Self::A) + Self::H + Self::D * Self::LEN) * Self::N;
}

/// Defines a parameter set of FIPS 205 table 2.
macro_rules! slhdsa_parameters {
    ($(#[$documentation:meta])* $name:ident, $text:literal, $hash:ty, $n:literal, $h:literal, $d:literal, $a:literal, $k:literal) => {
        $(#[$documentation])*
        // The name is that of the standard, its parts separated.
        #[allow(non_camel_case_types)]
        pub struct $name;

        impl SLHDSAParameters for $name {
            const NAME: &'static str = $text;
            const N: usize = $n;
            const H: usize = $h;
            const D: usize = $d;
            const A: usize = $a;
            const K: usize = $k;
            type Hash = $hash;
        }
    };
}

slhdsa_parameters!(
    /// SLH-DSA-SHA2-128s, of security category 1: n = 16, h = 63, d = 7, a = 12, k = 14.
    SLHDSA_SHA2_128s, "SLH-DSA-SHA2-128s", SLHDSASHA2Category1, 16, 63, 7, 12, 14
);
slhdsa_parameters!(
    /// SLH-DSA-SHAKE-128s, of security category 1: n = 16, h = 63, d = 7, a = 12, k = 14.
    SLHDSA_SHAKE_128s, "SLH-DSA-SHAKE-128s", SLHDSASHAKE, 16, 63, 7, 12, 14
);
slhdsa_parameters!(
    /// SLH-DSA-SHA2-128f, of security category 1: n = 16, h = 66, d = 22, a = 6, k = 33.
    SLHDSA_SHA2_128f, "SLH-DSA-SHA2-128f", SLHDSASHA2Category1, 16, 66, 22, 6, 33
);
slhdsa_parameters!(
    /// SLH-DSA-SHAKE-128f, of security category 1: n = 16, h = 66, d = 22, a = 6, k = 33.
    SLHDSA_SHAKE_128f, "SLH-DSA-SHAKE-128f", SLHDSASHAKE, 16, 66, 22, 6, 33
);
slhdsa_parameters!(
    /// SLH-DSA-SHA2-192s, of security category 3: n = 24, h = 63, d = 7, a = 14, k = 17.
    SLHDSA_SHA2_192s, "SLH-DSA-SHA2-192s", SLHDSASHA2Category3And5, 24, 63, 7, 14, 17
);
slhdsa_parameters!(
    /// SLH-DSA-SHAKE-192s, of security category 3: n = 24, h = 63, d = 7, a = 14, k = 17.
    SLHDSA_SHAKE_192s, "SLH-DSA-SHAKE-192s", SLHDSASHAKE, 24, 63, 7, 14, 17
);
slhdsa_parameters!(
    /// SLH-DSA-SHA2-192f, of security category 3: n = 24, h = 66, d = 22, a = 8, k = 33.
    SLHDSA_SHA2_192f, "SLH-DSA-SHA2-192f", SLHDSASHA2Category3And5, 24, 66, 22, 8, 33
);
slhdsa_parameters!(
    /// SLH-DSA-SHAKE-192f, of security category 3: n = 24, h = 66, d = 22, a = 8, k = 33.
    SLHDSA_SHAKE_192f, "SLH-DSA-SHAKE-192f", SLHDSASHAKE, 24, 66, 22, 8, 33
);
slhdsa_parameters!(
    /// SLH-DSA-SHA2-256s, of security category 5: n = 32, h = 64, d = 8, a = 14, k = 22.
    SLHDSA_SHA2_256s, "SLH-DSA-SHA2-256s", SLHDSASHA2Category3And5, 32, 64, 8, 14, 22
);
slhdsa_parameters!(
    /// SLH-DSA-SHAKE-256s, of security category 5: n = 32, h = 64, d = 8, a = 14, k = 22.
    SLHDSA_SHAKE_256s, "SLH-DSA-SHAKE-256s", SLHDSASHAKE, 32, 64, 8, 14, 22
);
slhdsa_parameters!(
    /// SLH-DSA-SHA2-256f, of security category 5: n = 32, h = 68, d = 17, a = 9, k = 35.
    SLHDSA_SHA2_256f, "SLH-DSA-SHA2-256f", SLHDSASHA2Category3And5, 32, 68, 17, 9, 35
);
slhdsa_parameters!(
    /// SLH-DSA-SHAKE-256f, of security category 5: n = 32, h = 68, d = 17, a = 9, k = 35.
    SLHDSA_SHAKE_256f, "SLH-DSA-SHAKE-256f", SLHDSASHAKE, 32, 68, 17, 9, 35
);
