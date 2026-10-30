use super::{LatticeRing, LatticeTables};

/// R_q of the ring of ML-DSA (FIPS 204 section 7.5): q = 8380417, n = 256 and ζ = 1753, a primitive 512-th root of unity; its NTT has 8 layers and leaves 256 residues of degree 0 (d = 1).
pub struct MLDSARing;

impl LatticeRing for MLDSARing {
    type Coefficient = u32;
    type Coefficients = [u32; 256];
    const Q: u32 = 8380417;
    const N: usize = 256;
    const ROOT: u32 = 1753;
    const LAYERS: u32 = 8;
    const ZETAS: &'static [u32] = &LatticeTables::zetas::<256>(8380417, 1753, 8);
    const GAMMAS: &'static [u32] = &LatticeTables::gammas::<256>(8380417, 1753, 8);
}
