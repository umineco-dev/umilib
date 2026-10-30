use alloc::vec::Vec;

use super::{JWK, JWKCurve, JWKKey, JWSAlgorithm, JWTError};
use crate::auth::cert::key::{HashAlgorithm, PSSParameters, SignatureAlgorithm};
use crate::codec::asn1::Tag;
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::crypto::MAC;
use crate::crypto::hmac::HMAC;
use crate::crypto::random::Random;
use crate::hash::sha::v2::{SHA256, SHA384, SHA512};

impl JWSAlgorithm {
    /// The smallest RSA modulus the RSA algorithms accept, in bits (RFC 7518 §3.3, §3.5).
    pub const MINIMUM_RSA_BITS: usize = 2048;

    /// The curve the ECDSA algorithms require of the key (RFC 7518 §3.4, RFC 8812 §3.2).
    pub const fn curve(self) -> Option<JWKCurve> {
        match self {
            JWSAlgorithm::ES256 => Some(JWKCurve::P256),
            JWSAlgorithm::ES384 => Some(JWKCurve::P384),
            JWSAlgorithm::ES512 => Some(JWKCurve::P521),
            JWSAlgorithm::ES256K => Some(JWKCurve::Secp256k1),
            JWSAlgorithm::Ed25519 => Some(JWKCurve::Ed25519),
            JWSAlgorithm::Ed448 => Some(JWKCurve::Ed448),
            _ => None,
        }
    }

    /// The signature algorithm of the key module that computes the
    /// signature, for the asymmetric algorithms: RSASSA-PSS with MGF1 of
    /// the same hash and a salt of the size of the hash (RFC 7518 §3.5).
    pub fn signature_algorithm(self, key: &JWK) -> Result<SignatureAlgorithm, JWTError> {
        let hash = self.hash();
        Ok(match self {
            JWSAlgorithm::RS256 | JWSAlgorithm::RS384 | JWSAlgorithm::RS512 => {
                SignatureAlgorithm::RSAPKCS1v15(hash.ok_or(JWTError::UnknownAlgorithm)?)
            }
            JWSAlgorithm::PS256 | JWSAlgorithm::PS384 | JWSAlgorithm::PS512 => {
                let hash = hash.ok_or(JWTError::UnknownAlgorithm)?;
                let salt_length = hash.output_size() as u32;
                SignatureAlgorithm::RSAPSS(PSSParameters { hash, mask_hash: hash, salt_length })
            }
            JWSAlgorithm::ES256 | JWSAlgorithm::ES384 | JWSAlgorithm::ES512 | JWSAlgorithm::ES256K => {
                SignatureAlgorithm::ECDSA(hash.ok_or(JWTError::UnknownAlgorithm)?)
            }
            JWSAlgorithm::EdDSA => match &key.key {
                JWKKey::OKP { curve: JWKCurve::Ed25519, .. } => SignatureAlgorithm::Ed25519,
                JWKKey::OKP { curve: JWKCurve::Ed448, .. } => SignatureAlgorithm::Ed448,
                _ => return Err(JWTError::KeyMismatch),
            },
            JWSAlgorithm::Ed25519 => SignatureAlgorithm::Ed25519,
            JWSAlgorithm::Ed448 => SignatureAlgorithm::Ed448,
            JWSAlgorithm::MLDSA44 | JWSAlgorithm::MLDSA65 | JWSAlgorithm::MLDSA87 => {
                SignatureAlgorithm::MLDSA(self.mldsa().ok_or(JWTError::UnknownAlgorithm)?)
            }
            JWSAlgorithm::HS256 | JWSAlgorithm::HS384 | JWSAlgorithm::HS512 | JWSAlgorithm::None => {
                return Err(JWTError::KeyMismatch);
            }
        })
    }

    /// Checks that `key` fits the algorithm for `operation` ("sign" or
    /// "verify"): its type, curve and size, and its `alg`, `use` and
    /// `key_ops`; [`JWTError::KeyMismatch`] otherwise.
    pub fn check_key(self, key: &JWK, operation: &str) -> Result<(), JWTError> {
        if !key.allows(operation, self.name()) {
            return Err(JWTError::KeyMismatch);
        }
        let fits = match (self, &key.key) {
            (JWSAlgorithm::HS256 | JWSAlgorithm::HS384 | JWSAlgorithm::HS512, JWKKey::Oct { k }) => {
                // RFC 7518 §3.2: a key at least as long as the hash output.
                k.expose().len() >= self.hash().map_or(usize::MAX, HashAlgorithm::output_size)
            }
            (
                JWSAlgorithm::RS256
                | JWSAlgorithm::RS384
                | JWSAlgorithm::RS512
                | JWSAlgorithm::PS256
                | JWSAlgorithm::PS384
                | JWSAlgorithm::PS512,
                JWKKey::RSA { n, .. },
            ) => n
                .first()
                .is_some_and(|&first| n.len() * 8 - first.leading_zeros() as usize >= JWSAlgorithm::MINIMUM_RSA_BITS),
            (
                JWSAlgorithm::ES256 | JWSAlgorithm::ES384 | JWSAlgorithm::ES512 | JWSAlgorithm::ES256K,
                JWKKey::EC { curve, .. },
            ) => Some(*curve) == self.curve(),
            (JWSAlgorithm::EdDSA, JWKKey::OKP { curve, .. }) => matches!(curve, JWKCurve::Ed25519 | JWKCurve::Ed448),
            (JWSAlgorithm::Ed25519 | JWSAlgorithm::Ed448, JWKKey::OKP { curve, .. }) => Some(*curve) == self.curve(),
            (JWSAlgorithm::MLDSA44 | JWSAlgorithm::MLDSA65 | JWSAlgorithm::MLDSA87, JWKKey::AKP { .. }) => {
                key.algorithm.as_deref() == Some(self.name())
            }
            _ => false,
        };
        if fits { Ok(()) } else { Err(JWTError::KeyMismatch) }
    }

    /// The signature of the JWS Signing Input `input` under `key` (RFC 7515
    /// §5.1), drawing from `random` where the algorithm uses randomness;
    /// ECDSA signatures are R || S of the size of the curve (RFC 7518 §3.4).
    pub fn sign<R: Random>(self, key: &JWK, input: &[u8], random: &mut R) -> Result<Vec<u8>, JWTError> {
        self.check_key(key, "sign")?;
        if let JWKKey::Oct { k } = &key.key {
            return Ok(self.mac(k.expose(), input));
        }
        let algorithm = self.signature_algorithm(key)?;
        let signature = key.private_key()?.sign(&algorithm, input, random)?;
        match self.curve() {
            Some(curve) if !curve.is_okp() => JWSAlgorithm::raw_signature(&signature, curve.size()),
            _ => Ok(signature),
        }
    }

    /// Succeeds if `signature` is a signature of `input` under `key`;
    /// [`JWTError::Signature`] otherwise. HMAC tags are compared in
    /// constant time.
    pub fn verify(self, key: &JWK, input: &[u8], signature: &[u8]) -> Result<(), JWTError> {
        self.check_key(key, "verify")?;
        if let JWKKey::Oct { k } = &key.key {
            let valid = match self {
                JWSAlgorithm::HS256 => JWSAlgorithm::verify_mac(HMAC::<SHA256>::new(k.expose()), input, signature),
                JWSAlgorithm::HS384 => JWSAlgorithm::verify_mac(HMAC::<SHA384>::new(k.expose()), input, signature),
                _ => JWSAlgorithm::verify_mac(HMAC::<SHA512>::new(k.expose()), input, signature),
            };
            return if valid { Ok(()) } else { Err(JWTError::Signature) };
        }
        let algorithm = self.signature_algorithm(key)?;
        let encoded;
        let signature = match self.curve() {
            Some(curve) if !curve.is_okp() => {
                encoded = JWSAlgorithm::der_signature(signature, curve.size())?;
                &encoded[..]
            }
            _ => signature,
        };
        key.public_key()?.verify(&algorithm, input, signature).map_err(|_| JWTError::Signature)
    }

    /// Whether `tag` is the tag of `input` under the keyed `mac`, compared in constant time.
    pub fn verify_mac<M: MAC>(mut mac: M, input: &[u8], tag: &[u8]) -> bool {
        mac.update(input);
        mac.verify(tag)
    }

    /// The HMAC of `input` under `key` with the hash of the algorithm.
    pub fn mac(self, key: &[u8], input: &[u8]) -> Vec<u8> {
        match self {
            JWSAlgorithm::HS256 => HMAC::<SHA256>::mac(key, input).to_vec(),
            JWSAlgorithm::HS384 => HMAC::<SHA384>::mac(key, input).to_vec(),
            _ => HMAC::<SHA512>::mac(key, input).to_vec(),
        }
    }

    /// The JOSE form of an ECDSA signature, R || S each of `size` bytes, of
    /// the DER `Ecdsa-Sig-Value` `der` (RFC 7518 §3.4).
    pub fn raw_signature(der: &[u8], size: usize) -> Result<Vec<u8>, JWTError> {
        let invalid = |_| JWTError::Signature;
        let mut reader = DERReader::new(der);
        let mut sequence = reader.read_sequence().map_err(invalid)?;
        let mut raw = alloc::vec![0u8; 2 * size];
        for half in raw.chunks_mut(size) {
            let element = sequence.read_expected(Tag::INTEGER).map_err(invalid)?;
            let integer = element.as_integer().map_err(invalid)?;
            let magnitude = integer.magnitude().ok_or(JWTError::Signature)?;
            if magnitude.len() > size {
                return Err(JWTError::Signature);
            }
            half[size - magnitude.len()..].copy_from_slice(magnitude);
        }
        sequence.finish().map_err(invalid)?;
        reader.finish().map_err(invalid)?;
        Ok(raw)
    }

    /// The DER `Ecdsa-Sig-Value` of the JOSE ECDSA signature `raw`, which
    /// must be exactly R || S of `size` bytes each (RFC 7518 §3.4).
    pub fn der_signature(raw: &[u8], size: usize) -> Result<Vec<u8>, JWTError> {
        if raw.len() != 2 * size {
            return Err(JWTError::Signature);
        }
        let (r, s) = raw.split_at(size);
        let mut writer = DERWriter::new();
        writer
            .write_sequence(|sequence| {
                sequence.write_integer_unsigned(r);
                sequence.write_integer_unsigned(s);
                Ok(())
            })
            .map_err(|_| JWTError::Signature)?;
        Ok(writer.into_bytes())
    }
}
