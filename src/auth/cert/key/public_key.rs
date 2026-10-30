use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt;
use core::hash::{Hash, Hasher};

use super::{AlgorithmIdentifier, KeyAlgorithm, KeyError, SignatureAlgorithm};
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ASN1Error, BitString, Tag};
use crate::codec::pem::{PEMConfig, PEMDocument};

/// A `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7): the algorithm of a public
/// key and the key, borrowed from its encoding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub subject_public_key: BitString<'a>,
}

impl<'a> SubjectPublicKeyInfo<'a> {
    /// The label of a public key in PEM (RFC 7468 §13).
    pub const PEM_LABEL: &'static str = "PUBLIC KEY";

    /// Reads the next `SubjectPublicKeyInfo` of `reader`.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<SubjectPublicKeyInfo<'a>, ASN1Error> {
        let mut sequence = reader.read_sequence()?;
        let algorithm = AlgorithmIdentifier::decode(&mut sequence)?;
        let subject_public_key = sequence.read_with(Tag::BIT_STRING, |element| element.as_bit_string())?;
        sequence.finish()?;
        Ok(SubjectPublicKeyInfo { algorithm, subject_public_key })
    }

    /// The `SubjectPublicKeyInfo` of the DER encoding `bytes`.
    pub fn from_der(bytes: &'a [u8]) -> Result<SubjectPublicKeyInfo<'a>, ASN1Error> {
        let mut reader = DERReader::new(bytes);
        let info = SubjectPublicKeyInfo::decode(&mut reader)?;
        reader.finish()?;
        Ok(info)
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), ASN1Error> {
        writer.write_sequence(|sequence| {
            self.algorithm.encode(sequence)?;
            sequence.write_bit_string(&self.subject_public_key)
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, ASN1Error> {
        let mut writer = DERWriter::new();
        self.encode(&mut writer)?;
        Ok(writer.into_bytes())
    }

    pub fn into_owned(self) -> SubjectPublicKeyInfo<'static> {
        SubjectPublicKeyInfo {
            algorithm: self.algorithm.into_owned(),
            subject_public_key: self.subject_public_key.into_owned(),
        }
    }
}

/// The largest keys [`PublicKey`] accepts, which bound the work a key from
/// an untrusted source can cause (an RSA verification costs in the size of
/// the modulus and of the exponent). The defaults are those of OpenSSL: a
/// modulus of 16384 bits and an exponent of 64 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyLimits {
    pub maximum_rsa_bits: u32,
    pub maximum_rsa_exponent_bits: u32,
}

impl Default for KeyLimits {
    fn default() -> KeyLimits {
        KeyLimits { maximum_rsa_bits: 16384, maximum_rsa_exponent_bits: 64 }
    }
}

/// A public key of a known algorithm, validated: its algorithm and the
/// bytes of its `subjectPublicKey` (the DER `RSAPublicKey` of RSA keys,
/// the SEC 1 point of EC keys, the raw key of the others) and the key of
/// the crypto module they decode to, kept so that verifying does not decode
/// it again. Keys are equal when their algorithms and bytes are.
#[derive(Clone)]
pub struct PublicKey {
    algorithm: KeyAlgorithm,
    key: Vec<u8>,
    typed: Arc<dyn Any + Send + Sync>,
}

impl PublicKey {
    /// The key of `algorithm` and the bytes `key` of its `subjectPublicKey`,
    /// validated as its specification requires; fails with
    /// [`KeyError::InvalidKey`] if it is not a key of the algorithm, and with
    /// [`KeyError::Unsupported`] for an algorithm this build does not include.
    pub fn new(algorithm: KeyAlgorithm, key: &[u8]) -> Result<PublicKey, KeyError> {
        PublicKey::new_with_limits(algorithm, key, &KeyLimits::default())
    }

    /// [`PublicKey::new`] with the limits `limits` (an RSA key above them
    /// fails with [`KeyError::Limit`]).
    pub fn new_with_limits(algorithm: KeyAlgorithm, key: &[u8], limits: &KeyLimits) -> Result<PublicKey, KeyError> {
        let typed = PublicKey::decode(&algorithm, key)?;
        if let Some(rsa) = typed.downcast_ref::<crate::crypto::rsa::RSAPublicKey>()
            && (rsa.bits() > limits.maximum_rsa_bits || rsa.e().bit_length() > limits.maximum_rsa_exponent_bits)
        {
            return Err(KeyError::Limit);
        }
        Ok(PublicKey { algorithm, key: key.to_vec(), typed })
    }

    /// The key of the crypto module that `key` of `algorithm` decodes to,
    /// validated as its specification requires: `RSAPublicKey`,
    /// `ECDSAVerifyingKey<C>`, `EdDSAVerifyingKey<C>`, `XDHPublicKey<C>`,
    /// `MLDSAVerifyingKey<P>`, `SLHDSAVerifyingKey<P>` or
    /// `MLKEMEncapsulationKey<P>`.
    pub fn decode(algorithm: &KeyAlgorithm, key: &[u8]) -> Result<Arc<dyn Any + Send + Sync>, KeyError> {
        use crate::crypto::KeyAgreement;
        use crate::crypto::curve::curve448::Edwards448;
        use crate::crypto::curve::curve25519::Edwards25519;
        use crate::crypto::ecdsa::ECDSAVerifyingKey;
        use crate::crypto::eddsa::EdDSAVerifyingKey;
        use crate::crypto::rsa::RSAPublicKey;
        Ok(match algorithm {
            KeyAlgorithm::RSA | KeyAlgorithm::RSAPSS(_) => Arc::new(RSAPublicKey::from_pkcs1_der(key)?),
            KeyAlgorithm::EC(curve) => with_curve!(curve, C => {
                Ok::<Arc<dyn Any + Send + Sync>, KeyError>(Arc::new(ECDSAVerifyingKey::<C>::from_encoded(key)?))
            })?,
            KeyAlgorithm::Ed25519 => Arc::new(EdDSAVerifyingKey::<Edwards25519>::from_encoded(key)?),
            KeyAlgorithm::Ed448 => Arc::new(EdDSAVerifyingKey::<Edwards448>::from_encoded(key)?),
            // RFC 8410 §5: every string of the length is a key of X25519 or X448.
            KeyAlgorithm::X25519 => Arc::new(crate::crypto::ecdh::X25519::public_key_from_bytes(key)?),
            KeyAlgorithm::X448 => Arc::new(crate::crypto::ecdh::X448::public_key_from_bytes(key)?),
            KeyAlgorithm::MLDSA(set) => {
                with_mldsa!(set, P => Arc::new(crate::crypto::mldsa::MLDSAVerifyingKey::<P>::from_bytes(key)?))
            }
            KeyAlgorithm::SLHDSA(set) | KeyAlgorithm::HashSLHDSA(set) => {
                with_slhdsa!(set, P => Arc::new(crate::crypto::slhdsa::SLHDSAVerifyingKey::<P>::from_bytes(key)?))
            }
            KeyAlgorithm::MLKEM(set) => {
                with_mlkem!(set, P => Arc::new(crate::crypto::mlkem::MLKEMEncapsulationKey::<P>::from_bytes(key)?))
            }
        })
    }

    /// The point of an EC key in the uncompressed form of SEC 1 §2.3.3
    /// (0x04, x, y), whatever the form it was given in; fails with
    /// [`KeyError::Mismatch`] for a key of another algorithm.
    pub fn uncompressed_point(&self) -> Result<Vec<u8>, KeyError> {
        let KeyAlgorithm::EC(curve) = self.algorithm else { return Err(KeyError::Mismatch) };
        let mut out = alloc::vec![0u8; 1 + 2 * curve.field_size()];
        with_curve!(curve, C => {
            let key = self.typed::<crate::crypto::ecdsa::ECDSAVerifyingKey<C>>()?;
            key.write_encoded(&mut out, false).map_err(KeyError::from)
        })?;
        Ok(out)
    }

    /// The key of the crypto module (`T` must be the type of the algorithm,
    /// see [`PublicKey::decode`]; [`KeyError::Mismatch`] otherwise).
    pub fn typed<T: Any>(&self) -> Result<&T, KeyError> {
        self.typed.downcast_ref::<T>().ok_or(KeyError::Mismatch)
    }

    /// The key of a `SubjectPublicKeyInfo`, whose BIT STRING must have whole
    /// bytes, within the default [`KeyLimits`].
    pub fn from_info(info: &SubjectPublicKeyInfo<'_>) -> Result<PublicKey, KeyError> {
        PublicKey::from_info_with_limits(info, &KeyLimits::default())
    }

    /// [`PublicKey::from_info`] within `limits`.
    pub fn from_info_with_limits(info: &SubjectPublicKeyInfo<'_>, limits: &KeyLimits) -> Result<PublicKey, KeyError> {
        let algorithm = KeyAlgorithm::from_identifier(&info.algorithm)?;
        let key = info.subject_public_key.as_octets().ok_or(KeyError::InvalidKey)?;
        PublicKey::new_with_limits(algorithm, key, limits)
    }

    /// The key of the DER encoding of a `SubjectPublicKeyInfo`, within the default [`KeyLimits`].
    pub fn from_der(bytes: &[u8]) -> Result<PublicKey, KeyError> {
        PublicKey::from_info(&SubjectPublicKeyInfo::from_der(bytes)?)
    }

    /// The key of the PEM text of a `SubjectPublicKeyInfo` (label `PUBLIC KEY`).
    pub fn from_pem(text: &str) -> Result<PublicKey, KeyError> {
        let document = PEMDocument::decode(text.as_bytes(), PEMConfig::default())?;
        if document.label() != SubjectPublicKeyInfo::PEM_LABEL {
            return Err(KeyError::PEMLabel);
        }
        PublicKey::from_der(document.data())
    }

    pub fn algorithm(&self) -> &KeyAlgorithm {
        &self.algorithm
    }

    /// The bytes of the `subjectPublicKey`.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// The `SubjectPublicKeyInfo` of the key.
    pub fn info(&self) -> Result<SubjectPublicKeyInfo<'_>, KeyError> {
        Ok(SubjectPublicKeyInfo {
            algorithm: self.algorithm.identifier()?,
            subject_public_key: BitString::new(0, self.key.as_slice())?,
        })
    }

    /// The DER encoding of the `SubjectPublicKeyInfo`.
    pub fn to_der(&self) -> Result<Vec<u8>, KeyError> {
        Ok(self.info()?.to_der()?)
    }

    /// The PEM text of the `SubjectPublicKeyInfo`.
    pub fn to_pem(&self) -> Result<String, KeyError> {
        let document = PEMDocument::new(SubjectPublicKeyInfo::PEM_LABEL, self.to_der()?)?;
        Ok(document.encode())
    }

    /// Succeeds if `signature` is a signature of `message` under the key
    /// with `algorithm`; fails with [`KeyError::Mismatch`] if the key cannot
    /// make such signatures ([`KeyAlgorithm::signs`]) and with
    /// [`KeyError::InvalidSignature`] if the signature does not verify.
    ///
    /// The signature is in the form of the `signatureValue` of certificates:
    /// the DER `Ecdsa-Sig-Value` for ECDSA (RFC 5480 §2.2), the raw
    /// signature for the others. ML-DSA and SLH-DSA verify with the empty
    /// context, as RFC 9881 and RFC 9909 require.
    pub fn verify(&self, algorithm: &SignatureAlgorithm, message: &[u8], signature: &[u8]) -> Result<(), KeyError> {
        use crate::crypto::SignatureScheme;
        if !self.algorithm.signs(algorithm) {
            return Err(KeyError::Mismatch);
        }
        match (&self.algorithm, algorithm) {
            (_, SignatureAlgorithm::RSAPKCS1v15(hash)) => {
                let key = self.typed::<crate::crypto::rsa::RSAPublicKey>()?;
                with_digest!(hash, H => crate::crypto::rsa::RSAPKCS1v15::<H>::verify(key, message, signature)?, xof => {
                    return Err(KeyError::Parameters);
                })
            }
            (_, SignatureAlgorithm::RSAPSS(parameters)) => {
                let key = self.typed::<crate::crypto::rsa::RSAPublicKey>()?;
                let salt = parameters.salt_length as usize;
                with_digest!(parameters.hash, H => with_digest!(parameters.mask_hash, G => {
                    crate::crypto::rsa::RSAPSS::<H, G>::verify(key, message, signature, salt)?
                }, xof => return Err(KeyError::Parameters)), xof => return Err(KeyError::Parameters))
            }
            (KeyAlgorithm::EC(curve), SignatureAlgorithm::ECDSA(hash)) => {
                let mut digest = [0u8; 64];
                let length = hash.digest(message, &mut digest);
                with_curve!(curve, C => {
                    use crate::crypto::ecdsa::{ECDSA, ECDSASignature, ECDSAVerifyingKey};
                    let key = self.typed::<ECDSAVerifyingKey<C>>()?;
                    let signature = ECDSASignature::<C>::from_der(signature)?;
                    // The hash type of `ECDSA` does not take part in verifying a digest.
                    ECDSA::<C, crate::hash::sha::v2::SHA256>::verify_digest(key, &digest[..length], &signature)
                        .map_err(KeyError::from)
                })?
            }
            (_, SignatureAlgorithm::Ed25519) => {
                use crate::crypto::eddsa::{Ed25519, EdDSAVerifyingKey};
                let key = self.typed::<EdDSAVerifyingKey<crate::crypto::curve::curve25519::Edwards25519>>()?;
                Ed25519::verify(key, message, signature)?
            }
            (_, SignatureAlgorithm::Ed448) => {
                use crate::crypto::eddsa::{Ed448, EdDSAVerifyingKey};
                let key = self.typed::<EdDSAVerifyingKey<crate::crypto::curve::curve448::Edwards448>>()?;
                Ed448::verify(key, message, signature)?
            }
            (_, SignatureAlgorithm::MLDSA(set)) => with_mldsa!(set, P => {
                use crate::crypto::mldsa::{MLDSA, MLDSAVerifyingKey};
                let key = self.typed::<MLDSAVerifyingKey<P>>()?;
                MLDSA::<P>::verify_with_context(key, message, &[], signature)?
            }),
            (_, SignatureAlgorithm::SLHDSA(set)) => with_slhdsa!(set, P => {
                use crate::crypto::slhdsa::{SLHDSA, SLHDSAVerifyingKey};
                let key = self.typed::<SLHDSAVerifyingKey<P>>()?;
                SLHDSA::<P>::verify_with_context(key, message, &[], signature)?
            }),
            (_, SignatureAlgorithm::HashSLHDSA(set)) => with_slhdsa!(set, P => {
                use crate::crypto::slhdsa::{SLHDSA, SLHDSAVerifyingKey};
                use crate::auth::cert::key::HashAlgorithm;
                let key = self.typed::<SLHDSAVerifyingKey<P>>()?;
                match set.pre_hash() {
                    HashAlgorithm::SHA256 => SLHDSA::<P>::verify_pre_hash::<crate::hash::sha::v2::SHA256>(key, message, &[], signature)?,
                    HashAlgorithm::SHA512 => SLHDSA::<P>::verify_pre_hash::<crate::hash::sha::v2::SHA512>(key, message, &[], signature)?,
                    HashAlgorithm::SHAKE128 => SLHDSA::<P>::verify_pre_hash::<crate::hash::sha::v3::SHAKE128>(key, message, &[], signature)?,
                    _ => SLHDSA::<P>::verify_pre_hash::<crate::hash::sha::v3::SHAKE256>(key, message, &[], signature)?,
                }
            }),
            // `signs` refused every other pair.
            _ => return Err(KeyError::Mismatch),
        }
        Ok(())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.algorithm == other.algorithm && self.key == other.key
    }
}

impl Eq for PublicKey {}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.algorithm.hash(state);
        self.key.hash(state);
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PublicKey").field("algorithm", &self.algorithm).field("key", &self.key).finish()
    }
}
