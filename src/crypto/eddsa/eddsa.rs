use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use super::EdDSACurve;
use crate::crypto::random::Random;
use crate::crypto::{CryptoError, SignatureScheme};
use crate::math::bigint::UnsignedInteger;
use crate::math::ec::{EdwardsPoint, FieldElement, FieldValue};
use crate::secret::Zeroize;

/// EdDSA on the curve `C` (RFC 8032 section 5).
pub struct EdDSA<C: EdDSACurve> {
    curve: PhantomData<C>,
}

/// A signing key of [`EdDSA`]: the secret key k of b bits and what is
/// derived from it (the scalar s, the prefix and the public key A), zeroized
/// when dropped.
pub struct EdDSASigningKey<C: EdDSACurve> {
    secret: Vec<u8>,
    scalar: FieldElement<C::Scalar>,
    prefix: Vec<u8>,
    verifying: EdDSAVerifyingKey<C>,
}

impl<C: EdDSACurve> EdDSASigningKey<C> {
    /// The key of the secret `secret` of [`EdwardsCurve::ENCODED_BYTES`](crate::math::ec::EdwardsCurve::ENCODED_BYTES)
    /// bytes (section 5.1.5 or 5.2.5): s from the pruned first half of
    /// H(k), the prefix from its second half, A = \[s\]B.
    pub fn new(secret: &[u8]) -> Result<EdDSASigningKey<C>, CryptoError> {
        if secret.len() != C::ENCODED_BYTES {
            return Err(CryptoError::InvalidKey);
        }
        let mut hash = vec![0u8; 2 * C::ENCODED_BYTES];
        C::hash(None, &[secret], &mut hash);
        let (half, prefix) = hash.split_at_mut(C::ENCODED_BYTES);
        C::prune(half);
        let scalar = FieldElement::<C::Scalar>::from_le_bytes_reduced(half);
        let verifying = EdDSAVerifyingKey::from_point(&EdwardsPoint::generator().mul(&scalar));
        let key = EdDSASigningKey { secret: secret.to_vec(), scalar, prefix: prefix.to_vec(), verifying };
        hash.zeroize();
        Ok(key)
    }

    /// The secret key k.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// The secret scalar s.
    pub fn scalar(&self) -> &FieldElement<C::Scalar> {
        &self.scalar
    }

    pub fn verifying_key(&self) -> &EdDSAVerifyingKey<C> {
        &self.verifying
    }
}

impl<C: EdDSACurve> Clone for EdDSASigningKey<C> {
    fn clone(&self) -> EdDSASigningKey<C> {
        EdDSASigningKey {
            secret: self.secret.clone(),
            scalar: self.scalar,
            prefix: self.prefix.clone(),
            verifying: self.verifying.clone(),
        }
    }
}

impl<C: EdDSACurve> Zeroize for EdDSASigningKey<C> {
    fn zeroize(&mut self) {
        self.secret.zeroize();
        self.scalar.zeroize();
        self.prefix.zeroize();
    }
}

impl<C: EdDSACurve> Drop for EdDSASigningKey<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the curve, not the key.
impl<C: EdDSACurve> fmt::Debug for EdDSASigningKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = core::any::type_name::<C>();
        write!(formatter, "EdDSASigningKey<{}>(..)", name.rsplit("::").next().unwrap_or(name))
    }
}

/// A verifying key of [`EdDSA`]: the point A with its encoding.
pub struct EdDSAVerifyingKey<C: EdDSACurve> {
    point: EdwardsPoint<C>,
    encoded: Vec<u8>,
}

impl<C: EdDSACurve> EdDSAVerifyingKey<C> {
    /// The key of the point `point`.
    pub fn from_point(point: &EdwardsPoint<C>) -> EdDSAVerifyingKey<C> {
        let mut encoded = vec![0u8; C::ENCODED_BYTES];
        // The buffer has the length of the encoding.
        let _ = point.write_encoded(&mut encoded);
        EdDSAVerifyingKey { point: *point, encoded }
    }

    /// The key of the encoding `bytes` (section 5.1.3 or 5.2.3); fails with
    /// `InvalidKey` for a length other than the encoding's or a value that
    /// does not decode to a point.
    pub fn from_encoded(bytes: &[u8]) -> Result<EdDSAVerifyingKey<C>, CryptoError> {
        let point = EdwardsPoint::from_encoded(bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(EdDSAVerifyingKey { point, encoded: bytes.to_vec() })
    }

    pub fn point(&self) -> &EdwardsPoint<C> {
        &self.point
    }

    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
}

impl<C: EdDSACurve> Clone for EdDSAVerifyingKey<C> {
    fn clone(&self) -> EdDSAVerifyingKey<C> {
        EdDSAVerifyingKey { point: self.point, encoded: self.encoded.clone() }
    }
}

impl<C: EdDSACurve> PartialEq for EdDSAVerifyingKey<C> {
    fn eq(&self, other: &EdDSAVerifyingKey<C>) -> bool {
        self.encoded == other.encoded
    }
}

impl<C: EdDSACurve> Eq for EdDSAVerifyingKey<C> {}

impl<C: EdDSACurve> fmt::Debug for EdDSAVerifyingKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "EdDSAVerifyingKey(")?;
        for byte in &self.encoded {
            write!(formatter, "{byte:02x}")?;
        }
        write!(formatter, ")")
    }
}

impl<C: EdDSACurve> EdDSA<C> {
    /// The longest context, in bytes.
    pub const MAXIMUM_CONTEXT: usize = 255;

    /// The domain of the pure variant.
    pub fn pure_domain() -> Option<(u8, &'static [u8])> {
        if C::PURE_DOMAIN { Some((0, b"")) } else { None }
    }

    /// The signature of `message` with the context `context` of at most 255
    /// bytes: Ed25519ctx (which RFC 8032 section 5.1 advises against with an
    /// empty context) or Ed448 with a context.
    pub fn sign_with_context(
        key: &EdDSASigningKey<C>,
        context: &[u8],
        message: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        EdDSA::<C>::check_context(context)?;
        EdDSA::<C>::sign_with_domain(key, Some((0, context)), message, out)
    }

    pub fn verify_with_context(
        key: &EdDSAVerifyingKey<C>,
        context: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        EdDSA::<C>::check_context(context)?;
        EdDSA::<C>::verify_with_domain(key, Some((0, context)), message, signature)
    }

    /// The signature of the prehash PH(`message`) with the context `context`
    /// of at most 255 bytes: Ed25519ph or Ed448ph.
    pub fn sign_prehashed(
        key: &EdDSASigningKey<C>,
        context: &[u8],
        message: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        EdDSA::<C>::check_context(context)?;
        let mut prehash = vec![0u8; C::PREHASH_BYTES];
        C::prehash(message, &mut prehash);
        EdDSA::<C>::sign_with_domain(key, Some((1, context)), &prehash, out)
    }

    pub fn verify_prehashed(
        key: &EdDSAVerifyingKey<C>,
        context: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        EdDSA::<C>::check_context(context)?;
        let mut prehash = vec![0u8; C::PREHASH_BYTES];
        C::prehash(message, &mut prehash);
        EdDSA::<C>::verify_with_domain(key, Some((1, context)), &prehash, signature)
    }

    /// Fails with `InvalidParameter` for a context of more than 255 bytes.
    pub fn check_context(context: &[u8]) -> Result<(), CryptoError> {
        if context.len() > EdDSA::<C>::MAXIMUM_CONTEXT {
            return Err(CryptoError::InvalidParameter);
        }
        Ok(())
    }

    /// Section 5.1.6 or 5.2.6 on `message` (M, or PH(M) for the prehash
    /// variants) with dom of `domain`: r = H(dom || prefix || M) mod L,
    /// R = \[r\]B, k = H(dom || R || A || M) mod L, S = (r + k s) mod L.
    pub fn sign_with_domain(
        key: &EdDSASigningKey<C>,
        domain: Option<(u8, &[u8])>,
        message: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let size = C::ENCODED_BYTES;
        let length = out.len();
        if length != 2 * size {
            return Err(CryptoError::InputLength { length });
        }
        let mut hash = vec![0u8; 2 * size];
        C::hash(domain, &[&key.prefix, message], &mut hash);
        let mut r = FieldElement::<C::Scalar>::from_le_bytes_reduced(&hash);
        let (encoded_r, encoded_s) = out.split_at_mut(size);
        let mut point = EdwardsPoint::<C>::generator().mul(&r);
        let written = point.write_encoded(encoded_r);
        point.zeroize();
        written.map_err(|_| CryptoError::InputLength { length })?;
        C::hash(domain, &[encoded_r, &key.verifying.encoded, message], &mut hash);
        let k = FieldElement::<C::Scalar>::from_le_bytes_reduced(&hash);
        let s = r.add(&k.mul(&key.scalar));
        r.zeroize();
        hash.zeroize();
        encoded_s.fill(0);
        let precision = <FieldValue<C::Scalar> as UnsignedInteger>::BYTES.min(size);
        s.write_le_bytes(&mut encoded_s[..precision]).map_err(|_| CryptoError::InputLength { length })
    }

    /// Section 5.1.7 or 5.2.7: R must decode, S must be below L, and
    /// \[2^c\]\[S\]B = \[2^c\]R + \[2^c\]\[k\]A with k = H(dom || R || A || M) mod L.
    pub fn verify_with_domain(
        key: &EdDSAVerifyingKey<C>,
        domain: Option<(u8, &[u8])>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let size = C::ENCODED_BYTES;
        if signature.len() != 2 * size {
            return Err(CryptoError::InvalidSignature);
        }
        let (encoded_r, encoded_s) = signature.split_at(size);
        let r = EdwardsPoint::<C>::from_encoded(encoded_r).map_err(|_| CryptoError::InvalidSignature)?;
        // S is little-endian; bytes beyond the precision must be zero.
        let value = FieldValue::<C::Scalar>::from_le_bytes(encoded_s).map_err(|_| CryptoError::InvalidSignature)?;
        let s = FieldElement::<C::Scalar>::from_value(&value).map_err(|_| CryptoError::InvalidSignature)?;
        let mut hash = vec![0u8; 2 * size];
        C::hash(domain, &[encoded_r, &key.encoded, message], &mut hash);
        let k = FieldElement::<C::Scalar>::from_le_bytes_reduced(&hash);
        // [S]B - [k]A - R, times the cofactor, must be the identity.
        let difference = EdwardsPoint::<C>::generator().mul_add_vartime(&s, &key.point, &k.neg()).sub(&r);
        if !difference.mul_by_cofactor().is_identity().into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }
}

impl<C: EdDSACurve> SignatureScheme for EdDSA<C> {
    type SigningKey = EdDSASigningKey<C>;
    type VerifyingKey = EdDSAVerifyingKey<C>;
    const SIGNING_KEY_SIZE: usize = C::ENCODED_BYTES;
    const VERIFYING_KEY_SIZE: usize = C::ENCODED_BYTES;
    /// R then S.
    const SIGNATURE_SIZE: usize = 2 * C::ENCODED_BYTES;

    /// [`EdDSA::SIGNING_KEY_SIZE`] random bytes (section 5.1.5 or 5.2.5).
    fn generate<R: Random>(random: &mut R) -> Result<EdDSASigningKey<C>, CryptoError> {
        let mut secret = vec![0u8; C::ENCODED_BYTES];
        let result = match random.fill(&mut secret) {
            Ok(()) => EdDSASigningKey::new(&secret),
            Err(_) => Err(CryptoError::RandomFailed),
        };
        secret.zeroize();
        result
    }

    fn signing_key_from_bytes(bytes: &[u8]) -> Result<EdDSASigningKey<C>, CryptoError> {
        EdDSASigningKey::new(bytes)
    }

    fn write_signing_key(key: &EdDSASigningKey<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != key.secret.len() {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        out.copy_from_slice(&key.secret);
        Ok(())
    }

    fn verifying_key(key: &EdDSASigningKey<C>) -> EdDSAVerifyingKey<C> {
        key.verifying.clone()
    }

    fn verifying_key_from_bytes(bytes: &[u8]) -> Result<EdDSAVerifyingKey<C>, CryptoError> {
        EdDSAVerifyingKey::from_encoded(bytes)
    }

    fn write_verifying_key(key: &EdDSAVerifyingKey<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != key.encoded.len() {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        out.copy_from_slice(&key.encoded);
        Ok(())
    }

    /// The pure variant: Ed25519, or Ed448 with an empty context.
    fn sign(key: &EdDSASigningKey<C>, message: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        EdDSA::<C>::sign_with_domain(key, EdDSA::<C>::pure_domain(), message, out)
    }

    fn verify(key: &EdDSAVerifyingKey<C>, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        EdDSA::<C>::verify_with_domain(key, EdDSA::<C>::pure_domain(), message, signature)
    }
}
