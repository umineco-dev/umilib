//! Checks of elliptic curves shared by the test crates through `#[path]`:
//! the group laws, the orders of the generators and the encodings of SEC 1
//! and RFC 8032, which every curve of `umilib::math::ec` must satisfy, and
//! access to the values of RFCs.

#![allow(dead_code)]

use umilib::math::bigint::UnsignedInteger;
use umilib::math::ec::{
    AffinePoint, ECError, EdwardsCurve, EdwardsPoint, FieldElement, FieldValue, MontgomeryCurve, MontgomeryPoint,
    PrimeField, ProjectivePoint, WeierstrassCurve,
};
use umilib::math::modular::ModularArithmetic;

use super::{RFC, Vectors};

/// The checks, with a deterministic source of scalars (SplitMix64).
pub struct ECChecks {
    state: u64,
}

impl ECChecks {
    pub fn new(seed: u64) -> ECChecks {
        ECChecks { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    /// A scalar of random value below the order.
    pub fn random_scalar<F: PrimeField>(&mut self) -> FieldElement<F> {
        let bytes: Vec<u8> = (0..F::BYTES).map(|_| self.next_u64() as u8).collect();
        FieldElement::from_value_reduced(&FieldValue::<F>::from_be_bytes(&bytes).unwrap())
    }

    /// The element `number`.
    pub fn small<F: PrimeField>(number: u64) -> FieldElement<F> {
        FieldElement::from_value(&FieldValue::<F>::from_u64(number).unwrap()).unwrap()
    }

    /// The element of hexadecimal `hex` (of any number of digits), below the prime.
    pub fn element<F: PrimeField>(hex: &str) -> FieldElement<F> {
        let padded = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex.to_owned() };
        FieldElement::from_value(&FieldValue::<F>::from_be_bytes(&Vectors::hex(&padded)).unwrap()).unwrap()
    }

    /// The checks every short Weierstrass curve of prime order must pass.
    pub fn weierstrass<C: WeierstrassCurve>(&mut self) {
        let generator = ProjectivePoint::<C>::generator();
        let order = *<C::Scalar as PrimeField>::MODULUS.value();
        assert!(AffinePoint::<C>::generator().is_on_curve().into_bool());
        assert!(generator.mul_value(&order).is_identity().into_bool());
        assert!(generator.mul_value_vartime(&order).is_identity().into_bool());
        let order_minus_one = FieldElement::<C::Scalar>::one().neg();
        assert_eq!(generator.mul(&order_minus_one), generator.neg());
        assert!(!generator.is_identity().into_bool());

        let identity = ProjectivePoint::<C>::identity();
        assert!(identity.is_identity().into_bool());
        assert_eq!(identity.add(&identity), identity);
        assert_eq!(identity.double(), identity);
        assert_eq!(identity.to_affine(), AffinePoint::identity());
        assert_eq!(AffinePoint::<C>::identity().to_projective(), identity);

        // Small multiples by repeated addition.
        let mut multiple = identity;
        for number in 0..40u64 {
            let k = ECChecks::small::<C::Scalar>(number);
            assert_eq!(generator.mul(&k), multiple, "{number}");
            assert_eq!(generator.mul_vartime(&k), multiple, "{number}");
            multiple = multiple.add(&generator);
        }

        for _ in 0..6 {
            let (a, b) = (self.random_scalar::<C::Scalar>(), self.random_scalar::<C::Scalar>());
            let (p, q) = (generator.mul(&a), generator.mul(&b));
            assert!(p.to_affine().is_on_curve().into_bool());
            assert_eq!(p, generator.mul_vartime(&a));
            assert_eq!(p.add(&q), generator.mul(&a.add(&b)));
            assert_eq!(p.add(&q), q.add(&p));
            assert_eq!(p.sub(&q), generator.mul(&a.sub(&b)));
            assert_eq!(p.double(), p.add(&p));
            assert_eq!(p.double(), generator.mul(&a.double()));
            assert_eq!(p.add(&identity), p);
            assert_eq!(identity.add(&p), p);
            assert!(p.add(&p.neg()).is_identity().into_bool());
            assert_eq!(p.add(&q).add(&generator), p.add(&q.add(&generator)));
            assert_eq!(q.mul(&a), p.mul(&b));
            assert_eq!(q.mul(&a), generator.mul(&a.mul(&b)));
            assert_eq!(generator.mul_add_vartime(&a, &q, &b), p.add(&q.mul(&b)));
            assert_eq!(p.to_affine().to_projective(), p);
            assert_eq!(ProjectivePoint::from_affine(&p.to_affine()), p);
            // Equality holds whatever the projective representative.
            assert_eq!(p.add(&identity).to_affine(), p.to_affine());
            ECChecks::sec1(&p.to_affine());
        }
        ECChecks::sec1(&AffinePoint::<C>::generator());
        ECChecks::sec1_rejections::<C>();
    }
    /// The SEC1 encodings of `point` decode back to it.
    pub fn sec1<C: WeierstrassCurve>(point: &AffinePoint<C>) {
        for compressed in [false, true] {
            let mut encoded = vec![0; AffinePoint::<C>::encoded_length(compressed)];
            point.write_encoded(&mut encoded, compressed).unwrap();
            assert_eq!(encoded[0], if compressed { 2 | point.y().is_odd().bit() } else { 4 });
            let mut x = vec![0; <C::Field as PrimeField>::BYTES];
            point.x().write_be_bytes(&mut x).unwrap();
            assert_eq!(&encoded[1..1 + x.len()], &x[..]);
            assert_eq!(AffinePoint::<C>::from_encoded(&encoded).unwrap(), *point);
            let mut short = vec![0; encoded.len() - 1];
            assert_eq!(point.write_encoded(&mut short, compressed), Err(ECError::InvalidEncoding));
        }
    }
    /// SEC 1 section 2.3.4: what does not encode a point of the curve is refused.
    pub fn sec1_rejections<C: WeierstrassCurve>() {
        let bytes = <C::Field as PrimeField>::BYTES;
        let mut identity = [0xFFu8; 1];
        AffinePoint::<C>::identity().write_encoded(&mut identity, false).unwrap();
        assert_eq!(identity, [0]);
        assert!(AffinePoint::<C>::from_encoded(&[0]).unwrap().is_identity().into_bool());
        let mut long_identity = vec![0; 1 + bytes];
        assert_eq!(AffinePoint::<C>::identity().write_encoded(&mut long_identity, true), Err(ECError::InvalidEncoding));

        let generator = AffinePoint::<C>::generator();
        let mut uncompressed = vec![0; AffinePoint::<C>::encoded_length(false)];
        generator.write_encoded(&mut uncompressed, false).unwrap();
        let mut compressed = vec![0; AffinePoint::<C>::encoded_length(true)];
        generator.write_encoded(&mut compressed, true).unwrap();
        // Empty, truncated, extended, or with another first byte.
        for bad in [
            &[][..],
            &[0, 0][..],
            &uncompressed[..uncompressed.len() - 1],
            &compressed[..compressed.len() - 1],
            &[&uncompressed[..], &[0]].concat()[..],
            &[&compressed[..], &[0]].concat()[..],
        ] {
            assert_eq!(AffinePoint::<C>::from_encoded(bad), Err(ECError::InvalidEncoding), "{bad:02x?}");
        }
        for first in [0u8, 1, 2, 3, 5, 6, 7, 0x84] {
            let mut changed = uncompressed.clone();
            changed[0] = first;
            assert_eq!(AffinePoint::<C>::from_encoded(&changed), Err(ECError::InvalidEncoding));
        }
        for first in [0u8, 1, 4, 5, 0x82] {
            let mut changed = compressed.clone();
            changed[0] = first;
            assert_eq!(AffinePoint::<C>::from_encoded(&changed), Err(ECError::InvalidEncoding));
        }
        // A coordinate not below the prime: x + p does not fit, so use p itself.
        let mut prime = vec![0; bytes];
        <C::Field as PrimeField>::MODULUS.value().write_be_bytes(&mut prime).unwrap();
        let mut large_x = uncompressed.clone();
        large_x[1..1 + bytes].copy_from_slice(&prime);
        assert_eq!(AffinePoint::<C>::from_encoded(&large_x), Err(ECError::InvalidEncoding));
        let mut large_y = uncompressed.clone();
        large_y[1 + bytes..].copy_from_slice(&prime);
        assert_eq!(AffinePoint::<C>::from_encoded(&large_y), Err(ECError::InvalidEncoding));
        let mut large_compressed = compressed.clone();
        large_compressed[1..].copy_from_slice(&prime);
        assert_eq!(AffinePoint::<C>::from_encoded(&large_compressed), Err(ECError::InvalidEncoding));
        // y changed: not on the curve.
        let mut off_curve = uncompressed.clone();
        *off_curve.last_mut().unwrap() ^= 1;
        assert_eq!(AffinePoint::<C>::from_encoded(&off_curve), Err(ECError::NotOnCurve));
        assert_eq!(
            AffinePoint::<C>::new(*generator.x(), generator.y().add(&FieldElement::one())),
            Err(ECError::NotOnCurve)
        );
        // An x for which x^3 + ax + b is not a square has no point.
        let mut x = FieldElement::<C::Field>::zero();
        loop {
            let right = x.square().add(&C::A).mul(&x).add(&C::B);
            if !right.sqrt().1.into_bool() {
                break;
            }
            x = x.add(&FieldElement::one());
        }
        let mut no_point = compressed.clone();
        x.write_be_bytes(&mut no_point[1..]).unwrap();
        assert_eq!(AffinePoint::<C>::from_encoded(&no_point), Err(ECError::NotOnCurve));
    }
    /// The checks every twisted Edwards curve of the RFC 8032 shape must pass.
    pub fn edwards<C: EdwardsCurve>(&mut self) {
        let generator = EdwardsPoint::<C>::generator();
        let order = *<C::Scalar as PrimeField>::MODULUS.value();
        assert!(EdwardsPoint::<C>::is_on_curve(&C::GENERATOR_X, &C::GENERATOR_Y).into_bool());
        assert!(generator.mul_value(&order).is_identity().into_bool());
        assert!(generator.mul_value_vartime(&order).is_identity().into_bool());
        assert!(generator.is_in_subgroup().into_bool());
        assert!(!generator.is_identity().into_bool());
        assert_eq!(generator.mul(&FieldElement::one().neg()), generator.neg());

        let identity = EdwardsPoint::<C>::identity();
        assert!(identity.is_identity().into_bool());
        assert_eq!(identity.add(&identity), identity);
        assert_eq!(identity.to_affine(), (FieldElement::zero(), FieldElement::one()));

        let mut multiple = identity;
        for number in 0..40u64 {
            let k = ECChecks::small::<C::Scalar>(number);
            assert_eq!(generator.mul(&k), multiple, "{number}");
            assert_eq!(generator.mul_vartime(&k), multiple, "{number}");
            multiple = multiple.add(&generator);
        }
        let cofactor = ECChecks::small::<C::Scalar>(C::COFACTOR as u64);
        assert_eq!(generator.mul_by_cofactor(), generator.mul(&cofactor));

        for _ in 0..6 {
            let (a, b) = (self.random_scalar::<C::Scalar>(), self.random_scalar::<C::Scalar>());
            let (p, q) = (generator.mul(&a), generator.mul(&b));
            let (x, y) = p.to_affine();
            assert!(EdwardsPoint::<C>::is_on_curve(&x, &y).into_bool());
            assert_eq!(EdwardsPoint::from_affine(&x, &y).unwrap(), p);
            assert_eq!(p, generator.mul_vartime(&a));
            assert_eq!(p.add(&q), generator.mul(&a.add(&b)));
            assert_eq!(p.sub(&q), generator.mul(&a.sub(&b)));
            assert_eq!(p.double(), generator.mul(&a.double()));
            assert_eq!(p.add(&identity), p);
            assert!(p.add(&p.neg()).is_identity().into_bool());
            assert_eq!(p.add(&q).add(&generator), p.add(&q.add(&generator)));
            assert_eq!(q.mul(&a), generator.mul(&a.mul(&b)));
            assert_eq!(generator.mul_add_vartime(&a, &q, &b), p.add(&q.mul(&b)));
            let mut encoded = vec![0; C::ENCODED_BYTES];
            p.write_encoded(&mut encoded).unwrap();
            assert_eq!(EdwardsPoint::<C>::from_encoded(&encoded).unwrap(), p);
            // RFC 8032 section 5.1.2 / 5.2.2: y little-endian, the sign of x in the last bit.
            let mut y_bytes = vec![0; C::ENCODED_BYTES];
            y.write_le_bytes(&mut y_bytes[..<C::Field as PrimeField>::BYTES]).unwrap();
            *y_bytes.last_mut().unwrap() |= x.is_odd().bit() << 7;
            assert_eq!(encoded, y_bytes);
        }
        assert_eq!(
            EdwardsPoint::<C>::from_affine(&C::GENERATOR_X, &C::GENERATOR_Y.add(&FieldElement::one())),
            Err(ECError::NotOnCurve)
        );
        ECChecks::edwards_rejections::<C>();
    }
    /// RFC 8032 sections 5.1.3 and 5.2.3: what does not decode to a point is refused.
    pub fn edwards_rejections<C: EdwardsCurve>() {
        let length = C::ENCODED_BYTES;
        for size in [0, length - 1, length + 1] {
            assert_eq!(EdwardsPoint::<C>::from_encoded(&vec![0; size]), Err(ECError::InvalidEncoding));
            assert_eq!(EdwardsPoint::<C>::identity().write_encoded(&mut vec![0; size]), Err(ECError::InvalidEncoding));
        }
        // y = p (not below the prime), with either sign.
        let mut prime = vec![0; length];
        <C::Field as PrimeField>::MODULUS
            .value()
            .write_le_bytes(&mut prime[..<C::Field as PrimeField>::BYTES])
            .unwrap();
        assert_eq!(EdwardsPoint::<C>::from_encoded(&prime), Err(ECError::InvalidEncoding));
        prime[length - 1] |= 0x80;
        assert_eq!(EdwardsPoint::<C>::from_encoded(&prime), Err(ECError::InvalidEncoding));
        // The identity (0, 1): x = 0 with the sign 1 is refused.
        let mut identity = vec![0; length];
        EdwardsPoint::<C>::identity().write_encoded(&mut identity).unwrap();
        let mut expected = vec![0; length];
        expected[0] = 1;
        assert_eq!(identity, expected);
        assert!(EdwardsPoint::<C>::from_encoded(&identity).unwrap().is_identity().into_bool());
        identity[length - 1] |= 0x80;
        assert_eq!(EdwardsPoint::<C>::from_encoded(&identity), Err(ECError::InvalidEncoding));
        // A y with no x.
        let mut y = FieldElement::<C::Field>::zero();
        loop {
            let yy = y.square();
            let quotient = yy.sub(&FieldElement::one()).mul(&C::D.mul(&yy).sub(&C::A).invert().unwrap());
            if !quotient.sqrt().1.into_bool() {
                break;
            }
            y = y.add(&FieldElement::one());
        }
        let mut no_point = vec![0; length];
        y.write_le_bytes(&mut no_point[..<C::Field as PrimeField>::BYTES]).unwrap();
        assert_eq!(EdwardsPoint::<C>::from_encoded(&no_point), Err(ECError::NotOnCurve));
        // (0, -1) has order 2: on the curve, outside the subgroup.
        let order_two = EdwardsPoint::<C>::from_affine(&FieldElement::zero(), &FieldElement::one().neg()).unwrap();
        assert!(!order_two.is_in_subgroup().into_bool());
        assert!(order_two.double().is_identity().into_bool());
    }
    /// decodeScalar25519 and decodeScalar448 of RFC 7748 section 5.
    pub fn clamp(scalar: &[u8]) -> Vec<u8> {
        let mut scalar = scalar.to_vec();
        if scalar.len() == 32 {
            scalar[0] &= 248;
            scalar[31] &= 127;
            scalar[31] |= 64;
        } else {
            scalar[0] &= 252;
            scalar[55] |= 128;
        }
        scalar
    }
    /// The function X25519 or X448 of RFC 7748 section 5.
    pub fn ladder<C: MontgomeryCurve>(scalar: &[u8], u: &[u8]) -> Vec<u8> {
        let point = MontgomeryPoint::<C>::from_bytes(u).unwrap();
        let mut out = vec![0; <C::Field as PrimeField>::BYTES];
        point
            .mul_value(&FieldValue::<C::Field>::from_le_bytes(&ECChecks::clamp(scalar)).unwrap())
            .write_bytes(&mut out)
            .unwrap();
        out
    }

    /// RFC 7748 section 5.2 (the pairs and the iterations) and section 6 (the
    /// exchange) for the function `name`, X25519 or X448, in `section`, 6.1 or 6.2.
    pub fn rfc7748<C: MontgomeryCurve>(name: &str, section: &str, end: &str, iterations: bool) {
        let tests = RFC::section("math/ec/rfc7748.txt", "5.2.  Test Vectors", "6.  Diffie");
        let (pairs, iterated) = tests.split_at(tests.find("   The second type").unwrap());
        let both = |text: &str| {
            let (x25519, x448) = text.split_at(text.find("   X448:").unwrap());
            if name == "X25519" { x25519.to_owned() } else { x448.to_owned() }
        };
        let (pairs, iterated) = (both(pairs), both(iterated));
        let scalars = RFC::values(&pairs, "Input scalar:");
        let inputs = RFC::values(&pairs, "Input u-coordinate:");
        let outputs = RFC::values(&pairs, "Output u-coordinate:");
        assert_eq!((scalars.len(), inputs.len(), outputs.len()), (2, 2, 2));
        for ((scalar, u), expected) in scalars.iter().zip(&inputs).zip(&outputs) {
            assert_eq!(ECChecks::ladder::<C>(&Vectors::hex(scalar), &Vectors::hex(u)), Vectors::hex(expected));
        }

        // k = u = the base point, then k, u = X(k, u), k.
        let mut base = vec![0; <C::Field as PrimeField>::BYTES];
        C::BASE_U.write_le_bytes(&mut base).unwrap();
        let (mut k, mut u) = (base.clone(), base.clone());
        let counts: &[(usize, &str)] = if iterations {
            &[(1, "After one iteration:"), (1000, "After 1,000 iterations:")]
        } else {
            &[(1, "After one iteration:")]
        };
        let mut done = 0;
        for (count, label) in counts {
            while done < *count {
                let result = ECChecks::ladder::<C>(&k, &u);
                u = core::mem::replace(&mut k, result);
                done += 1;
            }
            assert_eq!(k, Vectors::hex(&RFC::value(&iterated, label)), "{name} {label}");
        }

        let exchange = RFC::section("math/ec/rfc7748.txt", section, end);
        let a = Vectors::hex(&RFC::value(&exchange, "Alice's private key, a:"));
        let b = Vectors::hex(&RFC::value(&exchange, "Bob's private key, b:"));
        let public_a = ECChecks::ladder::<C>(&a, &base);
        let public_b = ECChecks::ladder::<C>(&b, &base);
        assert_eq!(
            public_a,
            Vectors::hex(&RFC::value(&exchange, &format!("Alice's public key, {name}(a, {}):", base[0])))
        );
        assert_eq!(
            public_b,
            Vectors::hex(&RFC::value(&exchange, &format!("Bob's public key, {name}(b, {}):", base[0])))
        );
        let shared = Vectors::hex(&RFC::value(&exchange, "Their shared secret, K:"));
        assert_eq!(ECChecks::ladder::<C>(&a, &public_b), shared);
        assert_eq!(ECChecks::ladder::<C>(&b, &public_a), shared);
    }

    /// RFC 6979 appendix A.2: in the section from `start` to `end`, the
    /// public key U = xG, and r = x(kG) mod q for each of the ten nonces k.
    pub fn rfc6979<C: WeierstrassCurve>(start: &str, end: &str) {
        let section = RFC::section("math/ec/rfc6979.txt", start, end);
        let generator = ProjectivePoint::<C>::generator();
        let x = ECChecks::element::<C::Scalar>(&RFC::value_after(&section, "x = "));
        let public = generator.mul(&x).to_affine();
        assert_eq!(*public.x(), ECChecks::element::<C::Field>(&RFC::value_after(&section, "Ux = ")));
        assert_eq!(*public.y(), ECChecks::element::<C::Field>(&RFC::value_after(&section, "Uy = ")));
        let nonces = RFC::values_after(&section, "k = ");
        let rs = RFC::values_after(&section, "r = ");
        assert_eq!((nonces.len(), rs.len()), (10, 10));
        for (k, r) in nonces.iter().zip(&rs) {
            let point = generator.mul(&ECChecks::element::<C::Scalar>(k)).to_affine();
            let x = FieldValue::<C::Scalar>::from_be_bytes(&{
                let mut bytes = vec![0; <C::Field as PrimeField>::BYTES];
                point.x().write_be_bytes(&mut bytes).unwrap();
                bytes
            });
            let reduced = FieldElement::<C::Scalar>::from_value_reduced(&x.unwrap());
            assert_eq!(reduced, ECChecks::element::<C::Scalar>(r), "k = {k}");
        }
    }

    /// RFC 7027 appendix A: in the section from `start` to `end`, the key
    /// pairs of A and B and their shared point.
    pub fn rfc7027<C: WeierstrassCurve>(start: &str, end: &str) {
        let section = RFC::section("math/ec/rfc7027.txt", start, end);
        let value = |label: &str| RFC::value(&section, label);
        let point = |x: &str, y: &str| {
            AffinePoint::<C>::new(ECChecks::element(&value(x)), ECChecks::element(&value(y))).unwrap().to_projective()
        };
        let d_a = ECChecks::element::<C::Scalar>(&value("dA ="));
        let d_b = ECChecks::element::<C::Scalar>(&value("dB ="));
        let (q_a, q_b, z) = (point("x_qA =", "y_qA ="), point("x_qB =", "y_qB ="), point("x_Z =", "y_Z ="));
        let generator = ProjectivePoint::<C>::generator();
        assert_eq!(generator.mul(&d_a), q_a);
        assert_eq!(generator.mul(&d_b), q_b);
        assert_eq!(q_b.mul(&d_a), z);
        assert_eq!(q_a.mul(&d_b), z);
    }
}
