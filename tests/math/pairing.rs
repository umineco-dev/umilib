//! Pairings against the test vectors of draft-irtf-cfrg-pairing-friendly-curves
//! appendix B (BLS12_381 and BN462) and the properties of a pairing
//! (bilinearity, non-degeneracy, values of order r) on every curve.

use umilib::math::ec::{AffinePoint, FieldElement, PrimeField, ProjectivePoint};
use umilib::math::pairing::{
    BLS12381, BN254, BN462, Fp2, Fp12, G2Affine, G2Projective, GT, Pairing, PairingCurve, SM9BN256, SM9BN256Field,
};

use super::ec_checks::ECChecks;
use crate::Vectors;

/// The values "name:" of a section of the draft, each "0x..." continued on
/// the following lines.
fn draft_value(section: &str, name: &str) -> Vec<u8> {
    let lines: Vec<&str> = section.lines().map(str::trim).collect();
    let index =
        lines.iter().position(|line| line.starts_with(&format!("{name}:"))).unwrap_or_else(|| panic!("no {name}"));
    let mut hex: String = lines[index][name.len() + 1..].trim().trim_start_matches("0x").to_owned();
    for line in &lines[index + 1..] {
        let line = line.trim_start_matches("0x");
        if line.is_empty() || !line.chars().all(|character| character.is_ascii_hexdigit()) {
            if hex.is_empty() && line.is_empty() {
                continue;
            }
            break;
        }
        hex.push_str(line);
    }
    let padded = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex };
    Vectors::hex(&padded)
}

fn element<C: PairingCurve>(bytes: &[u8]) -> FieldElement<C::Field> {
    let mut padded = vec![0u8; <C::Field as PrimeField>::BYTES - bytes.len()];
    padded.extend_from_slice(bytes);
    FieldElement::from_be_bytes(&padded).unwrap()
}

/// Appendix B: e(BP, BP') for the curve `C` named `name`.
fn check_vector<C: PairingCurve>(name: &str) {
    let text = Vectors::read("math/pairing/draft-irtf-cfrg-pairing-friendly-curves-11.txt");
    let start = text.find("\nAppendix B.  Test Vectors").unwrap();
    let appendix = &text[start..];
    let from = appendix.find(&format!("\n   {name}:")).unwrap();
    let to = appendix[from + 10..].find(":\n\n   Input x value").map_or(appendix.len(), |end| from + 10 + end);
    let section = &appendix[from..to];
    let value = |label: &str| element::<C>(&draft_value(section, label));
    let p = AffinePoint::<C::G1>::new(value("Input x value"), value("Input y value")).unwrap();
    assert_eq!(p, AffinePoint::generator());
    let q = G2Affine::<C>::new(
        Fp2::new(value("Input x'_0 value"), value("Input x'_1 value")),
        Fp2::new(value("Input y'_0 value"), value("Input y'_1 value")),
    )
    .unwrap();
    assert_eq!(q, G2Affine::generator());
    let expected: Vec<FieldElement<C::Field>> = (0..12).map(|index| value(&format!("e_{index}"))).collect();
    let result = Pairing::<C>::pairing(&p, &q).unwrap();
    assert_eq!(result.element().coefficients().to_vec(), expected, "{name}");
}

/// The properties of a pairing on the curve `C`.
fn check_properties<C: PairingCurve>(seed: u64) {
    ECChecks::new(seed).weierstrass::<C::G1>();
    let g1 = AffinePoint::<C::G1>::generator();
    let g2 = G2Affine::<C>::generator();
    assert!(g2.is_on_curve().into_bool());
    assert!(g2.is_in_subgroup().into_bool());
    let base = Pairing::<C>::pairing(&g1, &g2).unwrap();
    // Non-degenerate, of order r.
    assert!(!base.is_one().into_bool());
    assert!(base.pow(&FieldElement::one().neg()).mul(&base).is_one().into_bool());
    assert_eq!(base.invert().mul(&base), GT::one());
    // The identity pairs to 1.
    assert!(Pairing::<C>::pairing(&AffinePoint::identity(), &g2).unwrap().is_one().into_bool());
    assert!(Pairing::<C>::pairing(&g1, &G2Affine::identity()).unwrap().is_one().into_bool());
    // e([a]P, [b]Q) = e(P, Q)^(ab).
    let mut checks = ECChecks::new(seed + 1);
    let (a, b) = (checks.random_scalar::<C::Scalar>(), checks.random_scalar::<C::Scalar>());
    let p = ProjectivePoint::<C::G1>::generator().mul(&a).to_affine();
    let q = G2Projective::<C>::generator().mul(&b).to_affine();
    assert_eq!(Pairing::<C>::pairing(&p, &q).unwrap(), base.pow(&a.mul(&b)));
    assert_eq!(
        Pairing::<C>::pairing(&p, &g2).unwrap(),
        Pairing::<C>::pairing(&g1, &G2Projective::<C>::generator().mul(&a).to_affine()).unwrap()
    );
    // e(P, Q1 + Q2) = e(P, Q1) e(P, Q2).
    let q2 = G2Projective::<C>::generator().mul(&a).to_affine();
    let sum = q.to_projective().add(&q2.to_projective()).to_affine();
    assert_eq!(
        Pairing::<C>::pairing(&p, &sum).unwrap(),
        Pairing::<C>::pairing(&p, &q).unwrap().mul(&Pairing::<C>::pairing(&p, &q2).unwrap())
    );
    // G2: constant-time and public multiplications agree; r G2 = O; encodings round-trip.
    let value = b.value();
    assert_eq!(
        G2Projective::<C>::generator().mul_value(&value),
        G2Projective::<C>::generator().mul_value_vartime(&value)
    );
    let mut encoded = vec![0u8; G2Affine::<C>::encoded_length()];
    q.write_encoded(&mut encoded).unwrap();
    assert_eq!(G2Affine::<C>::from_encoded(&encoded).unwrap(), q);
    let mut gt = vec![0u8; GT::<C>::encoded_length()];
    base.write_bytes(&mut gt).unwrap();
    assert_eq!(Fp12::<C>::from_coefficients(&base.element().coefficients()), *base.element());
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn bls12_381() {
    check_vector::<BLS12381>("BLS12_381");
    check_properties::<BLS12381>(1);
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn bn462() {
    check_vector::<BN462>("BN462");
    check_properties::<BN462>(3);
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn bn254() {
    check_properties::<BN254>(5);
}

/// The curve of SM9, with its tower over u^2 = -2 and its M-type twist; its
/// pairing against GM/T 0044.5-2016 is in the tests of `crypto::ibs::sm9`.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn sm9_bn256() {
    check_properties::<SM9BN256>(7);
    // u^2 = -2 and w^6 = ξ = u.
    let u = Fp2::<SM9BN256Field>::new(FieldElement::zero(), FieldElement::one());
    assert_eq!(u.square(), Fp2::from_base(FieldElement::one().double().neg()));
    assert_eq!(u.mul(&u.invert().unwrap()), Fp2::one());
}
