use super::{LatticeRing, LatticeTables};

/// R_q of the ring of ML-KEM (FIPS 203 section 4.3): q = 3329, n = 256 and ζ = 17, a primitive 256-th root of unity; its NTT has 7 layers and leaves 128 residues of degree 1 (d = 2).
pub struct MLKEMRing;

impl LatticeRing for MLKEMRing {
    type Coefficient = u16;
    type Coefficients = [u16; 256];
    const Q: u32 = 3329;
    const N: usize = 256;
    const ROOT: u32 = 17;
    const LAYERS: u32 = 7;
    const ZETAS: &'static [u32] = &LatticeTables::zetas::<128>(3329, 17, 7);
    const GAMMAS: &'static [u32] = &LatticeTables::gammas::<128>(3329, 17, 7);
}
