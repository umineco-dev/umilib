use alloc::vec;
use core::marker::PhantomData;

use super::DragonflyConfig;
use crate::crypto::CryptoError;
use crate::crypto::hmac::HMAC;
use crate::crypto::kbkdf::KBKDF;
use crate::hash::CryptographicDigest;
use crate::math::bigint::UnsignedInteger;
use crate::math::ec::{AffinePoint, FieldElement, FieldValue, PrimeField, WeierstrassCurve};
use crate::math::modular::ModularArithmetic;
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// The functions of Dragonfly on the curve `C` with the hash function `H`.
pub struct Dragonfly<C: WeierstrassCurve, H: CryptographicDigest + Default> {
    types: PhantomData<(C, H)>,
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> Dragonfly<C, H> {
    /// The label of the hunting and pecking (section 3.2).
    pub const HUNTING_LABEL: &'static [u8] = b"Dragonfly Hunting And Pecking";
    /// The label of the derivation of kck and mk (section 3.3).
    pub const DERIVATION_LABEL: &'static [u8] = b"Dragonfly Key Derivation";

    /// KDF-n(k, label): `out.len()` bytes of SP 800-108 counter mode with
    /// HMAC-`H` keyed with k on label || 0x00 || \[8 out.len()\]_32.
    pub fn kdf(key: &[u8], label: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let bits = u32::try_from(8 * out.len()).map_err(|_| CryptoError::InputLength { length: out.len() })?;
        let mut fixed = vec![0u8; label.len() + 5];
        fixed[..label.len()].copy_from_slice(label);
        fixed[label.len() + 1..].copy_from_slice(&bits.to_be_bytes());
        KBKDF::new(HMAC::<H>::new(key), 32)?.counter(&[], &fixed, out)
    }

    /// The password element of `password` shared by the peers `first` and
    /// `second` (section 3.2.1): for counter = 1, 2, ..., base = H(max || min
    /// || password || counter), seed = (KDF-n(base) mod (p - 1)) + 1 with
    /// n = len(p) + 64, until a seed is the x of a point and at least
    /// `config.iterations` rounds are done; y has the parity of the base.
    /// Every round costs the same. Fails with `InvalidParameter` if no point
    /// is found in 255 rounds.
    pub fn password_element(
        config: &DragonflyConfig,
        first: &[u8],
        second: &[u8],
        password: &[u8],
    ) -> Result<AffinePoint<C>, CryptoError> {
        let (maximum, minimum) = if first >= second { (first, second) } else { (second, first) };
        let size = <C::Field as PrimeField>::BYTES;
        let precision = <FieldValue<C::Field> as UnsignedInteger>::BYTES;
        let prime = *<C::Field as PrimeField>::MODULUS.value();
        let p_minus_1 = prime.wrapping_sub(&FieldValue::<C::Field>::ONE);
        let mut stretched = vec![0u8; size + 8];
        let mut found = Choice::FALSE;
        let mut x = FieldElement::<C::Field>::zero();
        let mut parity = Choice::FALSE;
        let mut counter: u32 = 1;
        while !found.into_bool() || counter <= config.iterations {
            if counter > 255 {
                return Err(CryptoError::InvalidParameter);
            }
            let mut hash = H::default();
            hash.update(maximum);
            hash.update(minimum);
            hash.update(password);
            hash.update(&[counter as u8]);
            let mut base = hash.finalize();
            Dragonfly::<C, H>::kdf(base.as_ref(), Dragonfly::<C, H>::HUNTING_LABEL, &mut stretched)?;
            // temp mod (p - 1), as the remainder of its high and low parts.
            let split = stretched.len().saturating_sub(precision);
            let high = FieldValue::<C::Field>::from_be_bytes(&stretched[..split])
                .map_err(|_| CryptoError::InvalidParameter)?;
            let low = FieldValue::<C::Field>::from_be_bytes(&stretched[split..])
                .map_err(|_| CryptoError::InvalidParameter)?;
            let mut seed = FieldValue::<C::Field>::rem_wide(&low, &high, &p_minus_1)
                .map_err(|_| CryptoError::InvalidParameter)?
                .wrapping_add(&FieldValue::<C::Field>::ONE);
            let candidate = FieldElement::<C::Field>::from_value_reduced(&seed);
            seed.zeroize();
            let (_, is_square) = candidate.square().add(&C::A).mul(&candidate).add(&C::B).sqrt();
            let take = is_square & !found;
            x = FieldElement::select(&x, &candidate, take);
            let base_parity = Choice::from_bit(base.as_ref()[H::OUTPUT_SIZE - 1] & 1);
            parity = Choice::select(&parity, &base_parity, take);
            found |= is_square;
            base.as_mut().zeroize();
            counter += 1;
        }
        stretched.zeroize();
        let (y, _) = x.square().add(&C::A).mul(&x).add(&C::B).sqrt();
        let y = FieldElement::select(&y.neg(), &y, y.is_odd().ct_eq(&parity));
        let point = AffinePoint::new(x, y).map_err(|_| CryptoError::InvalidParameter);
        x.zeroize();
        point
    }
}
