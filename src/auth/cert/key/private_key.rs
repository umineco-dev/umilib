use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt;

use super::{KeyAlgorithm, KeyError, PublicKey, SignatureAlgorithm};
use crate::crypto::random::Random;

/// A private key of a known algorithm: the algorithm and the key of the
/// crypto module that implements it (`RSAPrivateKey`,
/// `ECDSASigningKey<P256>`, `EdDSASigningKey<Edwards25519>`,
/// `XDHPrivateKey<Curve25519>`, `MLDSASigningKey<MLDSA65>`,
/// `SLHDSASigningKey<SLHDSA_SHA2_128s>`, `MLKEMDecapsulationKey<MLKEM768>`,
/// ...), which zeroizes itself when dropped.
pub struct PrivateKey {
    algorithm: KeyAlgorithm,
    key: Box<dyn Any + Send + Sync>,
}

impl PrivateKey {
    /// The public exponent of the RSA keys [`PrivateKey::generate_rsa`] makes.
    pub const RSA_EXPONENT: u32 = 65537;

    /// The private key of `algorithm` and `key`, the key type of the crypto
    /// module for that algorithm; fails with [`KeyError::Mismatch`] for
    /// another type.
    pub fn from_key<T: Any + Send + Sync>(algorithm: KeyAlgorithm, key: T) -> Result<PrivateKey, KeyError> {
        let key = PrivateKey { algorithm, key: Box::new(key) };
        key.check_type()?;
        Ok(key)
    }

    /// The private key of `algorithm` and its boxed typed key; fails with
    /// [`KeyError::Mismatch`] if the key is not of the type of the algorithm.
    pub fn from_parts(algorithm: KeyAlgorithm, key: Box<dyn Any + Send + Sync>) -> Result<PrivateKey, KeyError> {
        let key = PrivateKey { algorithm, key };
        key.check_type()?;
        Ok(key)
    }

    /// Checks that the key is of the type of its algorithm.
    pub fn check_type(&self) -> Result<(), KeyError> {
        use crate::crypto::curve::curve448::{Curve448, Edwards448};
        use crate::crypto::curve::curve25519::{Curve25519, Edwards25519};
        let matches = match &self.algorithm {
            KeyAlgorithm::RSA | KeyAlgorithm::RSAPSS(_) => self.key.is::<crate::crypto::rsa::RSAPrivateKey>(),
            KeyAlgorithm::EC(curve) => {
                with_curve!(curve, C => Ok::<bool, KeyError>(self.key.is::<crate::crypto::ecdsa::ECDSASigningKey<C>>()))?
            }
            KeyAlgorithm::X25519 => self.key.is::<crate::crypto::ecdh::XDHPrivateKey<Curve25519>>(),
            KeyAlgorithm::X448 => self.key.is::<crate::crypto::ecdh::XDHPrivateKey<Curve448>>(),
            KeyAlgorithm::Ed25519 => self.key.is::<crate::crypto::eddsa::EdDSASigningKey<Edwards25519>>(),
            KeyAlgorithm::Ed448 => self.key.is::<crate::crypto::eddsa::EdDSASigningKey<Edwards448>>(),
            KeyAlgorithm::MLDSA(set) => {
                with_mldsa!(set, P => self.key.is::<crate::crypto::mldsa::MLDSASigningKey<P>>())
            }
            KeyAlgorithm::SLHDSA(set) | KeyAlgorithm::HashSLHDSA(set) => {
                with_slhdsa!(set, P => self.key.is::<crate::crypto::slhdsa::SLHDSASigningKey<P>>())
            }
            KeyAlgorithm::MLKEM(set) => {
                with_mlkem!(set, P => self.key.is::<crate::crypto::mlkem::MLKEMDecapsulationKey<P>>())
            }
        };
        if matches { Ok(()) } else { Err(KeyError::Mismatch) }
    }

    /// The typed key, of the type of the crypto module (`T` must be the
    /// type of the algorithm; `None` otherwise).
    pub fn key<T: Any>(&self) -> Option<&T> {
        self.key.downcast_ref::<T>()
    }

    /// The typed key, or [`KeyError::Mismatch`] (which `from_key` makes impossible).
    pub fn typed<T: Any>(&self) -> Result<&T, KeyError> {
        self.key::<T>().ok_or(KeyError::Mismatch)
    }

    pub fn algorithm(&self) -> &KeyAlgorithm {
        &self.algorithm
    }

    /// A new key of `algorithm` from the bytes of `random`. RSA keys need a
    /// size: [`PrivateKey::generate_rsa`].
    pub fn generate<R: Random>(algorithm: KeyAlgorithm, random: &mut R) -> Result<PrivateKey, KeyError> {
        use crate::crypto::curve::curve448::Edwards448;
        use crate::crypto::curve::curve25519::Edwards25519;
        use crate::crypto::{KeyAgreement, KeyEncapsulation, SignatureScheme};
        type Hash = crate::hash::sha::v2::SHA256;
        let key: Box<dyn Any + Send + Sync> = match &algorithm {
            KeyAlgorithm::RSA | KeyAlgorithm::RSAPSS(_) => return Err(KeyError::Parameters),
            KeyAlgorithm::EC(curve) => {
                with_curve!(curve, C => Ok::<Box<dyn Any + Send + Sync>, KeyError>(Box::new(crate::crypto::ecdsa::ECDSA::<C, Hash>::generate(random)?)))?
            }
            KeyAlgorithm::X25519 => Box::new(crate::crypto::ecdh::X25519::generate(random)?),
            KeyAlgorithm::X448 => Box::new(crate::crypto::ecdh::X448::generate(random)?),
            KeyAlgorithm::Ed25519 => Box::new(crate::crypto::eddsa::EdDSA::<Edwards25519>::generate(random)?),
            KeyAlgorithm::Ed448 => Box::new(crate::crypto::eddsa::EdDSA::<Edwards448>::generate(random)?),
            KeyAlgorithm::MLDSA(set) => {
                with_mldsa!(set, P => Box::new(crate::crypto::mldsa::MLDSA::<P>::generate(random)?))
            }
            KeyAlgorithm::SLHDSA(set) | KeyAlgorithm::HashSLHDSA(set) => {
                with_slhdsa!(set, P => Box::new(crate::crypto::slhdsa::SLHDSA::<P>::generate(random)?))
            }
            KeyAlgorithm::MLKEM(set) => {
                with_mlkem!(set, P => Box::new(crate::crypto::mlkem::MLKEM::<P>::generate(random)?))
            }
        };
        Ok(PrivateKey { algorithm, key })
    }

    /// A new RSA key of `bits` bits and the public exponent 65537, for
    /// `algorithm` (`RSA` or `RSAPSS`).
    pub fn generate_rsa<R: Random>(algorithm: KeyAlgorithm, bits: u32, random: &mut R) -> Result<PrivateKey, KeyError> {
        if !matches!(algorithm, KeyAlgorithm::RSA | KeyAlgorithm::RSAPSS(_)) {
            return Err(KeyError::Mismatch);
        }
        let exponent = crate::math::bigint::BoxedUint::from_u64(u64::from(PrivateKey::RSA_EXPONENT), 64)
            .map_err(|_| KeyError::Parameters)?;
        let key = crate::crypto::rsa::RSAPrivateKey::generate(bits, &exponent, random)?;
        Ok(PrivateKey { algorithm, key: Box::new(key) })
    }

    /// The public key of the private key.
    pub fn public_key(&self) -> Result<PublicKey, KeyError> {
        use crate::crypto::curve::curve448::Edwards448;
        use crate::crypto::curve::curve25519::Edwards25519;
        use crate::crypto::{KeyAgreement, KeyEncapsulation, SignatureScheme};
        let key: Vec<u8> = match &self.algorithm {
            KeyAlgorithm::RSA | KeyAlgorithm::RSAPSS(_) => {
                self.typed::<crate::crypto::rsa::RSAPrivateKey>()?.public_key().to_pkcs1_der()
            }
            KeyAlgorithm::EC(curve) => with_curve!(curve, C => {
                type Scheme = crate::crypto::ecdsa::ECDSA<C, crate::hash::sha::v2::SHA256>;
                let public = Scheme::verifying_key(self.typed::<crate::crypto::ecdsa::ECDSASigningKey<C>>()?);
                let mut out = vec![0u8; Scheme::VERIFYING_KEY_SIZE];
                public.write_encoded(&mut out, false)?;
                Ok::<Vec<u8>, KeyError>(out)
            })?,
            KeyAlgorithm::X25519 => {
                type Scheme = crate::crypto::ecdh::X25519;
                let public = Scheme::public_key(self.typed()?);
                let mut out = vec![0u8; Scheme::PUBLIC_KEY_SIZE];
                Scheme::write_public_key(&public, &mut out)?;
                out
            }
            KeyAlgorithm::X448 => {
                type Scheme = crate::crypto::ecdh::X448;
                let public = Scheme::public_key(self.typed()?);
                let mut out = vec![0u8; Scheme::PUBLIC_KEY_SIZE];
                Scheme::write_public_key(&public, &mut out)?;
                out
            }
            KeyAlgorithm::Ed25519 => {
                self.typed::<crate::crypto::eddsa::EdDSASigningKey<Edwards25519>>()?.verifying_key().encoded().to_vec()
            }
            KeyAlgorithm::Ed448 => {
                self.typed::<crate::crypto::eddsa::EdDSASigningKey<Edwards448>>()?.verifying_key().encoded().to_vec()
            }
            KeyAlgorithm::MLDSA(set) => with_mldsa!(set, P => {
                type Scheme = crate::crypto::mldsa::MLDSA<P>;
                let mut out = vec![0u8; Scheme::VERIFYING_KEY_SIZE];
                Scheme::write_verifying_key(&Scheme::verifying_key(self.typed()?), &mut out)?;
                out
            }),
            KeyAlgorithm::SLHDSA(set) | KeyAlgorithm::HashSLHDSA(set) => with_slhdsa!(set, P => {
                type Scheme = crate::crypto::slhdsa::SLHDSA<P>;
                let mut out = vec![0u8; Scheme::VERIFYING_KEY_SIZE];
                Scheme::write_verifying_key(&Scheme::verifying_key(self.typed()?), &mut out)?;
                out
            }),
            KeyAlgorithm::MLKEM(set) => with_mlkem!(set, P => {
                type Scheme = crate::crypto::mlkem::MLKEM<P>;
                let mut out = vec![0u8; Scheme::ENCAPSULATION_KEY_SIZE];
                Scheme::write_encapsulation_key(&Scheme::encapsulation_key(self.typed()?), &mut out)?;
                out
            }),
        };
        PublicKey::new(self.algorithm, &key)
    }

    /// The signature of `message` with `algorithm`, in the form of the
    /// `signatureValue` of certificates (see [`PublicKey::verify`]); fails
    /// with [`KeyError::Mismatch`] if the key cannot make such signatures.
    ///
    /// The signatures are hedged where the algorithm allows (`random` adds
    /// to the nonce of ECDSA, RFC 6979 §3.6, and is the randomness of
    /// ML-DSA and SLH-DSA); RSASSA-PSS draws its salt from `random`.
    pub fn sign<R: Random>(
        &self,
        algorithm: &SignatureAlgorithm,
        message: &[u8],
        random: &mut R,
    ) -> Result<Vec<u8>, KeyError> {
        use crate::crypto::SignatureScheme;
        if !self.algorithm.signs(algorithm) {
            return Err(KeyError::Mismatch);
        }
        Ok(match (&self.algorithm, algorithm) {
            (_, SignatureAlgorithm::RSAPKCS1v15(hash)) => {
                let key = self.typed::<crate::crypto::rsa::RSAPrivateKey>()?;
                with_digest!(hash, H => crate::crypto::rsa::RSAPKCS1v15::<H>::sign(key, message, random)?, xof => {
                    return Err(KeyError::Parameters);
                })
            }
            (_, SignatureAlgorithm::RSAPSS(parameters)) => {
                let key = self.typed::<crate::crypto::rsa::RSAPrivateKey>()?;
                let salt = parameters.salt_length as usize;
                with_digest!(parameters.hash, H => with_digest!(parameters.mask_hash, G => {
                    crate::crypto::rsa::RSAPSS::<H, G>::sign(key, message, salt, random)?
                }, xof => return Err(KeyError::Parameters)), xof => return Err(KeyError::Parameters))
            }
            (KeyAlgorithm::EC(curve), SignatureAlgorithm::ECDSA(hash)) => {
                let mut digest = [0u8; 64];
                let length = hash.digest(message, &mut digest);
                with_curve!(curve, C => {
                    type Scheme = crate::crypto::ecdsa::ECDSA<C, crate::hash::sha::v2::SHA256>;
                    let key = self.typed::<crate::crypto::ecdsa::ECDSASigningKey<C>>()?;
                    // The hash type of `ECDSA` does not take part in signing a digest.
                    Ok::<Vec<u8>, KeyError>(Scheme::sign_digest_hedged(key, &digest[..length], random)?.to_der())
                })?
            }
            (_, SignatureAlgorithm::Ed25519) => {
                type Scheme = crate::crypto::eddsa::Ed25519;
                let mut out = vec![0u8; Scheme::SIGNATURE_SIZE];
                Scheme::sign(self.typed()?, message, &mut out)?;
                out
            }
            (_, SignatureAlgorithm::Ed448) => {
                type Scheme = crate::crypto::eddsa::Ed448;
                let mut out = vec![0u8; Scheme::SIGNATURE_SIZE];
                Scheme::sign(self.typed()?, message, &mut out)?;
                out
            }
            (_, SignatureAlgorithm::MLDSA(set)) => with_mldsa!(set, P => {
                type Scheme = crate::crypto::mldsa::MLDSA<P>;
                let mut out = vec![0u8; Scheme::SIGNATURE_SIZE];
                Scheme::sign_with_context(self.typed()?, message, &[], random, &mut out)?;
                out
            }),
            (_, SignatureAlgorithm::SLHDSA(set)) => with_slhdsa!(set, P => {
                type Scheme = crate::crypto::slhdsa::SLHDSA<P>;
                let mut out = vec![0u8; Scheme::SIGNATURE_SIZE];
                Scheme::sign_with_context(self.typed()?, message, &[], random, &mut out)?;
                out
            }),
            (_, SignatureAlgorithm::HashSLHDSA(set)) => with_slhdsa!(set, P => {
                use crate::auth::cert::key::HashAlgorithm;
                type Scheme = crate::crypto::slhdsa::SLHDSA<P>;
                let mut out = vec![0u8; Scheme::SIGNATURE_SIZE];
                let key = self.typed()?;
                match set.pre_hash() {
                    HashAlgorithm::SHA256 => Scheme::sign_pre_hash::<crate::hash::sha::v2::SHA256, R>(key, message, &[], random, &mut out)?,
                    HashAlgorithm::SHA512 => Scheme::sign_pre_hash::<crate::hash::sha::v2::SHA512, R>(key, message, &[], random, &mut out)?,
                    HashAlgorithm::SHAKE128 => Scheme::sign_pre_hash::<crate::hash::sha::v3::SHAKE128, R>(key, message, &[], random, &mut out)?,
                    _ => Scheme::sign_pre_hash::<crate::hash::sha::v3::SHAKE256, R>(key, message, &[], random, &mut out)?,
                }
                out
            }),
            // `signs` refused every other pair.
            _ => return Err(KeyError::Mismatch),
        })
    }
}

impl fmt::Debug for PrivateKey {
    /// Prints the algorithm, not the key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PrivateKey").field("algorithm", &self.algorithm).finish_non_exhaustive()
    }
}
