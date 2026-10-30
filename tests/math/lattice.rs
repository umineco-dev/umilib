//! The rings of ML-KEM and ML-DSA: their tables against FIPS 203 appendix A
//! and FIPS 204 appendix B, the reduction against `%`, the NTT against the
//! product in Z_q[X]/(X^256 + 1) computed by the definition, and the bit
//! strings of FIPS 203 section 4.2.1.

use umilib::math::lattice::{LatticePacking, LatticeRing, LatticeTables, MLDSARing, MLKEMRing, Polynomial};

use crate::{Values, Vectors};

/// The tables of an appendix, in order: the integers between each `{` and
/// `}` that holds integers alone (the text also writes sets such as {0, ..., 127}).
fn tables(path: &str) -> Vec<Vec<i64>> {
    let text = Vectors::read(path);
    let mut tables = Vec::new();
    for part in text.split('{').skip(1) {
        let body = part.split('}').next().unwrap();
        let words: Vec<&str> = body.split([' ', ',', '\n']).filter(|word| !word.trim().is_empty()).collect();
        if let Ok(table) = words.iter().map(|word| word.trim().parse()).collect::<Result<Vec<i64>, _>>() {
            tables.push(table);
        }
    }
    tables
}

/// The table `values` modulo q.
fn modulo(values: &[i64], q: u32) -> Vec<u32> {
    values.iter().map(|value| value.rem_euclid(q as i64) as u32).collect()
}

#[test]
fn mlkem_tables_follow_fips_203_appendix_a() {
    let tables = tables("math/lattice/fips203-appendix-a.txt");
    assert_eq!(tables.len(), 2);
    assert_eq!(MLKEMRing::ZETAS, modulo(&tables[0], 3329).as_slice());
    assert_eq!(MLKEMRing::GAMMAS, modulo(&tables[1], 3329).as_slice());
    // 3303 = 128^-1 mod q (FIPS 203 algorithm 10 line 14).
    assert_eq!(MLKEMRing::INVERSE_SCALE, 3303);
    assert_eq!(MLKEMRing::FACTOR_DEGREE, 2);
}

#[test]
fn mldsa_zetas_follow_fips_204_appendix_b() {
    let tables = tables("math/lattice/fips204-appendix-b.txt");
    assert_eq!(tables.len(), 1);
    // zetas[0] is unused and printed as 0.
    assert_eq!(&MLDSARing::ZETAS[1..], &modulo(&tables[0], 8380417)[1..]);
    // 8347681 = 256^-1 mod q (FIPS 204 algorithm 42 line 21).
    assert_eq!(MLDSARing::INVERSE_SCALE, 8347681);
    assert_eq!(MLDSARing::FACTOR_DEGREE, 1);
}

#[test]
fn tables_are_powers_of_the_root() {
    assert_eq!(LatticeTables::bit_reverse(1, 7), 64);
    assert_eq!(LatticeTables::bit_reverse(0b1011, 8), 0b1101_0000);
    assert_eq!(LatticeTables::pow(17, 128, 3329), 3328);
    assert_eq!(LatticeTables::pow(1753, 256, 8380417), 8380416);
    assert_eq!(LatticeTables::inverse(17, 3329) * 17 % 3329, 1);
}

fn check_reduce<R: LatticeRing>() {
    let q = R::Q as u64;
    let mut values = Values::new(R::Q as u64);
    let edges = [0, 1, q - 1, q, q + 1, 2 * q - 1, 2 * q, q * q, (q - 1) * (q - 1), u64::MAX, u64::MAX - 1];
    for value in edges.into_iter().chain((0..10_000).map(|_| values.next_u64())) {
        assert_eq!(R::reduce(value) as u64, value % q, "{value}");
    }
    for _ in 0..10_000 {
        let (a, b) = ((values.next_u64() % q) as u32, (values.next_u64() % q) as u32);
        assert_eq!(R::add(a, b) as u64, (a as u64 + b as u64) % q);
        assert_eq!(R::sub(a, b) as u64, (a as u64 + q - b as u64) % q);
        assert_eq!(R::mul(a, b) as u64, a as u64 * b as u64 % q);
        assert_eq!(R::neg(a) as u64, (q - a as u64) % q);
    }
}

#[test]
fn reductions_agree_with_the_remainder() {
    check_reduce::<MLKEMRing>();
    check_reduce::<MLDSARing>();
}

/// A polynomial of random coefficients below q.
fn random<R: LatticeRing>(values: &mut Values) -> (Polynomial<R>, Vec<u64>) {
    let coefficients: Vec<u64> = (0..R::N).map(|_| values.next_u64() % R::Q as u64).collect();
    let as_u32: Vec<u32> = coefficients.iter().map(|value| *value as u32).collect();
    (Polynomial::from_values(&as_u32).unwrap(), coefficients)
}

/// f g in Z_q[X]/(X^n + 1) by the definition: X^n = -1.
fn negacyclic(f: &[u64], g: &[u64], q: u64) -> Vec<u64> {
    let n = f.len();
    let mut product = vec![0u64; n];
    for (i, a) in f.iter().enumerate() {
        for (j, b) in g.iter().enumerate() {
            let term = a * b % q;
            let k = (i + j) % n;
            product[k] = if i + j < n { (product[k] + term) % q } else { (product[k] + q - term) % q };
        }
    }
    product
}

fn check_ntt<R: LatticeRing>() {
    let mut values = Values::new(7 + R::Q as u64);
    for _ in 0..20 {
        let (f, f_values) = random::<R>(&mut values);
        let (g, g_values) = random::<R>(&mut values);
        assert_eq!(f.ntt().inverse_ntt(), f);
        let product = f.ntt().multiply_ntt(&g.ntt()).inverse_ntt();
        let expected = negacyclic(&f_values, &g_values, R::Q as u64);
        let got: Vec<u64> = (0..R::N).map(|index| product.get(index) as u64).collect();
        assert_eq!(got, expected);
        // The transform is linear.
        assert_eq!(f.add(&g).ntt(), f.ntt().add(&g.ntt()));
        assert_eq!(f.sub(&g).add(&g), f);
        assert_eq!(f.add(&f.neg()), Polynomial::zero());
    }
    // X × X^(n-1) = X^n = -1.
    let (mut x, mut last) = (Polynomial::<R>::zero(), Polynomial::<R>::zero());
    x.set(1, 1);
    last.set(R::N - 1, 1);
    let product = x.ntt().multiply_ntt(&last.ntt()).inverse_ntt();
    assert_eq!(product.get(0), R::Q - 1);
    assert!((1..R::N).all(|index| product.get(index) == 0));
}

#[test]
fn ntt_multiplies_in_the_ring() {
    check_ntt::<MLKEMRing>();
    check_ntt::<MLDSARing>();
}

#[test]
fn bit_strings_follow_fips_203_section_4_2_1() {
    // "the 8-bit string 11010001 corresponds to the byte 139".
    let mut packing = LatticePacking::new(1).unwrap();
    let mut byte = [0u8];
    packing.write(&[1, 1, 0, 1, 0, 0, 0, 1], &mut byte);
    assert_eq!(byte, [139]);
    assert_eq!(packing.position(), 8);
    // Integers are written from their least significant bit: 0x123 then 0x456 in 12 bits.
    let mut packing = LatticePacking::new(12).unwrap();
    let mut bytes = [0xFFu8; 3];
    packing.write(&[0x123, 0x456], &mut bytes);
    assert_eq!(bytes, [0x23, 0x61, 0x45]);
    let mut read = [0u32; 2];
    LatticePacking::new(12).unwrap().read(&bytes, &mut read);
    assert_eq!(read, [0x123, 0x456]);
    assert!(LatticePacking::new(0).is_err());
    assert!(LatticePacking::new(33).is_err());
    assert_eq!(LatticePacking::length(10, 256), 320);
}

#[test]
fn byte_encode_and_decode_follow_fips_203_algorithms_5_and_6() {
    let mut values = Values::new(5);
    for bits in 1..=12u32 {
        let limit = if bits == 12 { 3329 } else { 1 << bits };
        let coefficients: Vec<u32> = (0..256).map(|_| (values.next_u64() % limit) as u32).collect();
        let polynomial = Polynomial::<MLKEMRing>::from_values(&coefficients).unwrap();
        let mut bytes = vec![0u8; 32 * bits as usize];
        polynomial.write_bits(bits, &mut bytes).unwrap();
        // The bit i d + j of the output is the bit j of the coefficient i.
        for (index, value) in coefficients.iter().enumerate() {
            for bit in 0..bits as usize {
                let position = index * bits as usize + bit;
                assert_eq!((bytes[position / 8] >> (position % 8)) & 1, ((value >> bit) & 1) as u8);
            }
        }
        let (decoded, canonical) = Polynomial::<MLKEMRing>::read_bits(bits, &bytes).unwrap();
        assert_eq!(decoded, polynomial);
        assert!(canonical.into_bool());
        assert!(polynomial.write_bits(bits, &mut bytes[1..]).is_err());
    }
    // ByteDecode_12 reduces 12-bit values modulo q; such an encoding is not canonical.
    let (decoded, canonical) = Polynomial::<MLKEMRing>::read_bits(12, &[0xFF; 384]).unwrap();
    assert!(!canonical.into_bool());
    assert_eq!(decoded.get(0), 4095 - 3329);
    let mut almost = [0u8; 384];
    almost[0] = 0x00;
    almost[1] = 0x0D; // 3328 = 0xD00 in the first coefficient
    let (decoded, canonical) = Polynomial::<MLKEMRing>::read_bits(12, &almost).unwrap();
    assert!(canonical.into_bool());
    assert_eq!(decoded.get(0), 3328);
}

/// round(a / b) of FIPS 203 section 2.3 (⌈x⌋ = ⌊x + 1/2⌋), by integers.
fn rounded(numerator: u64, denominator: u64) -> u64 {
    (2 * numerator + denominator) / (2 * denominator)
}

#[test]
fn compression_follows_fips_203_equations_4_7_and_4_8() {
    let q = MLKEMRing::Q as u64;
    for bits in 1..12u32 {
        for x in 0..MLKEMRing::Q {
            let expected = rounded((x as u64) << bits, q) % (1 << bits);
            assert_eq!(MLKEMRing::compress(x, bits) as u64, expected, "Compress_{bits}({x})");
        }
        for y in 0..1u32 << bits {
            assert_eq!(
                MLKEMRing::decompress(y, bits) as u64,
                rounded(q * y as u64, 1 << bits),
                "Decompress_{bits}({y})"
            );
            // Decompression followed by compression preserves the input.
            assert_eq!(MLKEMRing::compress(MLKEMRing::decompress(y, bits), bits), y);
        }
    }
    for value in [0u64, 1, 3328, 3329, 3330, 1 << 40, (1 << 62) + 12345] {
        assert_eq!(MLKEMRing::quotient(value), value / 3329);
        assert_eq!(MLDSARing::quotient(value), value / 8380417);
    }
}
