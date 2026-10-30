use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;

use super::{AlgorithmIdentifier, KeyAlgorithm, KeyError, NamedCurve, PrivateKey};
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ASN1Error, BitString, Tag, TagClass};
use crate::codec::pem::{PEMConfig, PEMDocument};
use crate::secret::{ConstantTimeEq, Secret};

/// A `OneAsymmetricKey` (RFC 5958 §2, `PrivateKeyInfo` of PKCS #8 in its
/// version 1): the algorithm, the encoded private key, the attributes and,
/// in version 2, the public key; borrowed from its encoding. Its `Debug`
/// does not print the private key.
#[derive(Clone)]
pub struct PrivateKeyInfo<'a> {
    /// 0 (v1) or 1 (v2, which may hold the public key).
    pub version: u8,
    pub algorithm: AlgorithmIdentifier<'a>,
    /// The contents of the `privateKey` OCTET STRING.
    pub private_key: &'a [u8],
    /// The DER encoding of the `attributes` element (`[0] IMPLICIT SET OF Attribute`), if any.
    pub attributes: Option<&'a [u8]>,
    pub public_key: Option<BitString<'a>>,
}

impl<'a> PrivateKeyInfo<'a> {
    /// The label of a private key in PEM (RFC 7468 §10).
    pub const PEM_LABEL: &'static str = "PRIVATE KEY";

    /// Reads the next `OneAsymmetricKey` of `reader`; refuses versions
    /// other than v1 and v2, and a public key in a v1 key.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<PrivateKeyInfo<'a>, KeyError> {
        let mut sequence = reader.read_sequence()?;
        let version = sequence.read_integer()?.as_i128()?;
        let version = match version {
            0 => 0,
            1 => 1,
            _ => return Err(KeyError::Parameters),
        };
        let algorithm = AlgorithmIdentifier::decode(&mut sequence)?;
        let private_key = sequence.read_with(Tag::OCTET_STRING, |element| element.as_octet_string())?;
        let attributes =
            sequence.read_optional(Tag { class: TagClass::ContextSpecific, constructed: true, number: 0 })?;
        let public_key =
            sequence.read_optional(Tag { class: TagClass::ContextSpecific, constructed: false, number: 1 })?;
        sequence.finish()?;
        let public_key = public_key.map(|element| element.as_bit_string()).transpose()?;
        if public_key.is_some() && version == 0 {
            return Err(KeyError::Parameters);
        }
        Ok(PrivateKeyInfo {
            version,
            algorithm,
            private_key,
            attributes: attributes.map(|element| element.encoding),
            public_key,
        })
    }

    /// The `OneAsymmetricKey` of the DER encoding `bytes`.
    pub fn from_der(bytes: &'a [u8]) -> Result<PrivateKeyInfo<'a>, KeyError> {
        let mut reader = DERReader::new(bytes);
        let info = PrivateKeyInfo::decode(&mut reader)?;
        reader.finish()?;
        Ok(info)
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), ASN1Error> {
        writer.write_sequence(|sequence| {
            sequence.write_integer_i128(i128::from(self.version));
            self.algorithm.encode(sequence)?;
            sequence.write_octet_string(self.private_key);
            if let Some(attributes) = self.attributes {
                sequence.write_raw(attributes);
            }
            if let Some(public_key) = &self.public_key {
                let mut content = Vec::new();
                public_key.encode_content(&mut content);
                sequence
                    .write_element(Tag { class: TagClass::ContextSpecific, constructed: false, number: 1 }, &content);
            }
            Ok(())
        })
    }
}

/// The forms of an ML-DSA or ML-KEM private key that a CHOICE of RFC 9881
/// §6 or RFC 9935 §6 holds: the seed, the expanded key, or both. Its
/// `Debug` does not print them.
#[derive(Clone, Copy)]
pub struct SeedChoice<'a> {
    pub seed: Option<&'a [u8]>,
    pub expanded: Option<&'a [u8]>,
}

/// An `ECPrivateKey` (RFC 5915 §3): the private scalar of a fixed length,
/// the curve and the public point; borrowed from its encoding. Its `Debug`
/// does not print the scalar.
#[derive(Clone)]
pub struct ECPrivateKey<'a> {
    pub private_key: &'a [u8],
    pub curve: Option<NamedCurve>,
    pub public_key: Option<BitString<'a>>,
}

impl<'a> ECPrivateKey<'a> {
    /// The label of an `ECPrivateKey` in PEM (RFC 5915 §4).
    pub const PEM_LABEL: &'static str = "EC PRIVATE KEY";

    /// The `ECPrivateKey` of the DER encoding `bytes` (version 1).
    pub fn from_der(bytes: &'a [u8]) -> Result<ECPrivateKey<'a>, KeyError> {
        let mut reader = DERReader::new(bytes);
        let mut sequence = reader.read_sequence()?;
        reader.finish()?;
        if sequence.read_integer()?.as_i128()? != 1 {
            return Err(KeyError::Parameters);
        }
        let private_key = sequence.read_with(Tag::OCTET_STRING, |element| element.as_octet_string())?;
        let curve = match sequence.read_optional_explicit(0)? {
            Some(mut field) => {
                let oid = field.read_with(Tag::OBJECT_IDENTIFIER, |element| element.as_object_identifier())?;
                field.finish()?;
                Some(NamedCurve::from_oid(&oid).ok_or(KeyError::UnknownAlgorithm)?)
            }
            None => None,
        };
        let public_key = match sequence.read_optional_explicit(1)? {
            Some(mut field) => {
                let bits = field.read_with(Tag::BIT_STRING, |element| element.as_bit_string())?;
                field.finish()?;
                Some(bits)
            }
            None => None,
        };
        sequence.finish()?;
        Ok(ECPrivateKey { private_key, curve, public_key })
    }

    /// The DER encoding (version 1, with the curve, as RFC 5915 §3 requires).
    pub fn to_der(&self) -> Result<Secret<Vec<u8>>, KeyError> {
        let mut writer = DERWriter::new();
        writer.write_sequence(|sequence| {
            sequence.write_integer_i128(1);
            sequence.write_octet_string(self.private_key);
            if let Some(curve) = self.curve {
                sequence.write_explicit(0, |field| {
                    field.write_object_identifier(&curve.oid());
                    Ok(())
                })?;
            }
            if let Some(public_key) = &self.public_key {
                sequence.write_explicit(1, |field| field.write_bit_string(public_key))?;
            }
            Ok(())
        })?;
        Ok(Secret::new(writer.into_bytes()))
    }
}

impl PrivateKey {
    /// The key of a `OneAsymmetricKey` (PKCS #8) in BER (DER included), the
    /// encoding RFC 5958 §2 requires receivers to accept.
    pub fn from_pkcs8_ber(bytes: &[u8]) -> Result<PrivateKey, KeyError> {
        let der = Secret::new(crate::codec::asn1::ber::BERReader::to_der(bytes, DERReader::DEFAULT_MAXIMUM_DEPTH)?);
        PrivateKey::from_pkcs8_der(der.expose())
    }

    /// The key of the DER encoding of a `OneAsymmetricKey` (PKCS #8). A
    /// public key given with it must be that of the private key, and a
    /// private key given in two forms (RFC 9881, RFC 9935) must have
    /// matching forms; [`KeyError::Inconsistent`] otherwise.
    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<PrivateKey, KeyError> {
        let info = PrivateKeyInfo::from_der(bytes)?;
        let algorithm = KeyAlgorithm::from_identifier(&info.algorithm)?;
        let key = PrivateKey::decode_private_key(algorithm, info.private_key)?;
        if let Some(public_key) = &info.public_key {
            let given = super::PublicKey::new(algorithm, public_key.as_octets().ok_or(KeyError::InvalidKey)?)?;
            // An EC point may be given compressed: points are compared, not encodings.
            if !PrivateKey::same_point(&key.public_key()?, &given)? {
                return Err(KeyError::Inconsistent);
            }
        }
        Ok(key)
    }

    /// The DER encoding of the key as a `OneAsymmetricKey` v1 (PKCS #8).
    pub fn to_pkcs8_der(&self) -> Result<Secret<Vec<u8>>, KeyError> {
        let private_key = self.encode_private_key()?;
        let info = PrivateKeyInfo {
            version: 0,
            algorithm: self.algorithm().identifier()?,
            private_key: private_key.expose(),
            attributes: None,
            public_key: None,
        };
        let mut writer = DERWriter::new();
        info.encode(&mut writer)?;
        Ok(Secret::new(writer.into_bytes()))
    }

    /// The key of PEM text: a `PRIVATE KEY` (PKCS #8), an `RSA PRIVATE KEY`
    /// (PKCS #1) or an `EC PRIVATE KEY` (RFC 5915, with its curve).
    pub fn from_pem(text: &str) -> Result<PrivateKey, KeyError> {
        let document = PEMDocument::decode(text.as_bytes(), PEMConfig::default())?;
        let label = String::from(document.label());
        let data = Secret::new(document.into_data());
        PrivateKey::from_pem_document(&label, data.expose())
    }

    /// The key of the data of a PEM document of `label`.
    pub fn from_pem_document(label: &str, data: &[u8]) -> Result<PrivateKey, KeyError> {
        match label {
            PrivateKeyInfo::PEM_LABEL => PrivateKey::from_pkcs8_ber(data),
            "RSA PRIVATE KEY" => {
                PrivateKey::from_key(KeyAlgorithm::RSA, crate::crypto::rsa::RSAPrivateKey::from_pkcs1_der(data)?)
            }
            ECPrivateKey::PEM_LABEL => {
                let curve = ECPrivateKey::from_der(data)?.curve.ok_or(KeyError::Parameters)?;
                PrivateKey::decode_private_key(KeyAlgorithm::EC(curve), data)
            }
            _ => Err(KeyError::PEMLabel),
        }
    }

    /// The PEM text of the key as a `PRIVATE KEY` (PKCS #8).
    pub fn to_pem(&self) -> Result<Secret<String>, KeyError> {
        let der = self.to_pkcs8_der()?;
        let document = PEMDocument::new(PrivateKeyInfo::PEM_LABEL, der.expose().clone())?;
        Ok(Secret::new(document.encode()))
    }

    /// The key of `algorithm` of the contents of the `privateKey` field of
    /// a `OneAsymmetricKey`:
    /// - RSA: an `RSAPrivateKey` (RFC 8017 §A.1.2);
    /// - EC: an `ECPrivateKey` (RFC 5915), whose curve, if given, must be
    ///   that of `algorithm`;
    /// - X25519, X448, Ed25519, Ed448: a `CurvePrivateKey` OCTET STRING (RFC 8410 §7);
    /// - ML-DSA and ML-KEM: the CHOICE of a seed, an expanded key or both
    ///   (RFC 9881 §6, RFC 9935 §6), both forms checked against each other
    ///   (and an expanded ML-KEM key against its public key,
    ///   [`PrivateKey::check_mlkem_pair`]);
    /// - SLH-DSA: the raw key (RFC 9909 §6), checked against its root.
    pub fn decode_private_key(algorithm: KeyAlgorithm, bytes: &[u8]) -> Result<PrivateKey, KeyError> {
        use crate::crypto::curve::curve448::Edwards448;
        use crate::crypto::curve::curve25519::Edwards25519;
        use crate::crypto::{KeyAgreement, SignatureScheme};
        let key: Box<dyn Any + Send + Sync> = match &algorithm {
            KeyAlgorithm::RSA | KeyAlgorithm::RSAPSS(_) => {
                Box::new(crate::crypto::rsa::RSAPrivateKey::from_pkcs1_der(bytes)?)
            }
            KeyAlgorithm::EC(curve) => {
                let parsed = ECPrivateKey::from_der(bytes)?;
                if parsed.curve.is_some_and(|given| given != *curve) {
                    return Err(KeyError::Inconsistent);
                }
                if parsed.private_key.len() != curve.field_size() {
                    return Err(KeyError::InvalidKey);
                }
                let key: Box<dyn Any + Send + Sync> = with_curve!(curve, C => {
                    type Scheme = crate::crypto::ecdsa::ECDSA<C, crate::hash::sha::v2::SHA256>;
                    Ok::<Box<dyn Any + Send + Sync>, KeyError>(Box::new(Scheme::signing_key_from_bytes(parsed.private_key)?))
                })?;
                let key = PrivateKey::from_parts(algorithm, key)?;
                if let Some(public_key) = &parsed.public_key {
                    let given = public_key.as_octets().ok_or(KeyError::InvalidKey)?;
                    let derived = super::PublicKey::new(algorithm, given)?;
                    if !PrivateKey::same_point(&key.public_key()?, &derived)? {
                        return Err(KeyError::Inconsistent);
                    }
                }
                return Ok(key);
            }
            KeyAlgorithm::X25519 => {
                Box::new(crate::crypto::ecdh::X25519::private_key_from_bytes(PrivateKey::curve_private_key(bytes)?)?)
            }
            KeyAlgorithm::X448 => {
                Box::new(crate::crypto::ecdh::X448::private_key_from_bytes(PrivateKey::curve_private_key(bytes)?)?)
            }
            KeyAlgorithm::Ed25519 => Box::new(crate::crypto::eddsa::EdDSASigningKey::<Edwards25519>::new(
                PrivateKey::curve_private_key(bytes)?,
            )?),
            KeyAlgorithm::Ed448 => Box::new(crate::crypto::eddsa::EdDSASigningKey::<Edwards448>::new(
                PrivateKey::curve_private_key(bytes)?,
            )?),
            KeyAlgorithm::MLDSA(set) => with_mldsa!(set, P => {
                use crate::crypto::mldsa::{MLDSA, MLDSASigningKey};
                let choice = PrivateKey::seed_choice(bytes)?;
                let key = match (choice.seed, choice.expanded) {
                    (Some(seed), None) => MLDSA::<P>::signing_key_from_seed(seed)?,
                    (None, Some(expanded)) => MLDSASigningKey::<P>::from_bytes(expanded)?,
                    (Some(seed), Some(expanded)) => {
                        let key = MLDSA::<P>::signing_key_from_seed(seed)?;
                        let mut written = Secret::new(vec![0u8; expanded.len()]);
                        if expanded.len() != <MLDSA<P> as SignatureScheme>::SIGNING_KEY_SIZE {
                            return Err(KeyError::InvalidKey);
                        }
                        key.write_bytes(written.expose_mut());
                        if !written.expose().as_slice().ct_eq(expanded).into_bool() {
                            return Err(KeyError::Inconsistent);
                        }
                        key
                    }
                    (None, None) => return Err(KeyError::InvalidKey),
                };
                Box::new(key)
            }),
            KeyAlgorithm::MLKEM(set) => with_mlkem!(set, P => {
                use crate::crypto::mlkem::{MLKEM, MLKEMDecapsulationKey};
                let choice = PrivateKey::seed_choice(bytes)?;
                let key = match (choice.seed, choice.expanded) {
                    (Some(seed), None) => MLKEM::<P>::decapsulation_key_from_seed(seed)?,
                    (None, Some(expanded)) => {
                        let key = MLKEMDecapsulationKey::<P>::from_bytes(expanded)?;
                        PrivateKey::check_mlkem_pair(&key)?;
                        key
                    }
                    (Some(seed), Some(expanded)) => {
                        let key = MLKEM::<P>::decapsulation_key_from_seed(seed)?;
                        if expanded.len() != <MLKEM<P> as crate::crypto::KeyEncapsulation>::DECAPSULATION_KEY_SIZE {
                            return Err(KeyError::InvalidKey);
                        }
                        let mut written = Secret::new(vec![0u8; expanded.len()]);
                        key.write_bytes(written.expose_mut());
                        if !written.expose().as_slice().ct_eq(expanded).into_bool() {
                            return Err(KeyError::Inconsistent);
                        }
                        key
                    }
                    (None, None) => return Err(KeyError::InvalidKey),
                };
                Box::new(key)
            }),
            KeyAlgorithm::SLHDSA(set) | KeyAlgorithm::HashSLHDSA(set) => {
                with_slhdsa!(set, P => Box::new(crate::crypto::slhdsa::SLHDSA::<P>::signing_key_from_bytes(bytes)?))
            }
        };
        PrivateKey::from_parts(algorithm, key)
    }

    /// The contents of the `privateKey` field of the key's `OneAsymmetricKey`
    /// (see [`PrivateKey::decode_private_key`]). ML-DSA and ML-KEM keys are
    /// written as their seed when it is known, as RFC 9881 and RFC 9935
    /// recommend, and as their expanded key otherwise.
    pub fn encode_private_key(&self) -> Result<Secret<Vec<u8>>, KeyError> {
        use crate::crypto::curve::curve448::Edwards448;
        use crate::crypto::curve::curve25519::Edwards25519;
        use crate::crypto::{KeyAgreement, KeyEncapsulation, SignatureScheme};
        Ok(match self.algorithm() {
            KeyAlgorithm::RSA | KeyAlgorithm::RSAPSS(_) => {
                Secret::new(self.typed::<crate::crypto::rsa::RSAPrivateKey>()?.to_pkcs1_der()?)
            }
            KeyAlgorithm::EC(curve) => {
                let mut scalar = Secret::new(vec![0u8; curve.field_size()]);
                with_curve!(curve, C => {
                    type Scheme = crate::crypto::ecdsa::ECDSA<C, crate::hash::sha::v2::SHA256>;
                    Scheme::write_signing_key(self.typed()?, scalar.expose_mut()).map_err(KeyError::from)
                })?;
                let public_key = self.public_key()?;
                let point = BitString::new(0, public_key.key())?;
                ECPrivateKey { private_key: scalar.expose(), curve: Some(*curve), public_key: Some(point) }.to_der()?
            }
            KeyAlgorithm::X25519 => {
                let mut raw = Secret::new([0u8; 32]);
                crate::crypto::ecdh::X25519::write_private_key(self.typed()?, raw.expose_mut())?;
                PrivateKey::write_curve_private_key(raw.expose())
            }
            KeyAlgorithm::X448 => {
                let mut raw = Secret::new([0u8; 56]);
                crate::crypto::ecdh::X448::write_private_key(self.typed()?, raw.expose_mut())?;
                PrivateKey::write_curve_private_key(raw.expose())
            }
            KeyAlgorithm::Ed25519 => PrivateKey::write_curve_private_key(
                self.typed::<crate::crypto::eddsa::EdDSASigningKey<Edwards25519>>()?.secret(),
            ),
            KeyAlgorithm::Ed448 => PrivateKey::write_curve_private_key(
                self.typed::<crate::crypto::eddsa::EdDSASigningKey<Edwards448>>()?.secret(),
            ),
            KeyAlgorithm::MLDSA(set) => with_mldsa!(set, P => {
                use crate::crypto::mldsa::{MLDSA, MLDSASigningKey};
                let key = self.typed::<MLDSASigningKey<P>>()?;
                match key.seed() {
                    Some(seed) => PrivateKey::write_seed(seed),
                    None => {
                        let mut expanded = Secret::new(vec![0u8; <MLDSA<P> as SignatureScheme>::SIGNING_KEY_SIZE]);
                        key.write_bytes(expanded.expose_mut());
                        PrivateKey::write_expanded(expanded.expose())
                    }
                }
            }),
            KeyAlgorithm::MLKEM(set) => with_mlkem!(set, P => {
                use crate::crypto::mlkem::{MLKEM, MLKEMDecapsulationKey};
                let key = self.typed::<MLKEMDecapsulationKey<P>>()?;
                match key.seed() {
                    Some(seed) => PrivateKey::write_seed(seed),
                    None => {
                        let mut expanded = Secret::new(vec![0u8; MLKEM::<P>::DECAPSULATION_KEY_SIZE]);
                        key.write_bytes(expanded.expose_mut());
                        PrivateKey::write_expanded(expanded.expose())
                    }
                }
            }),
            KeyAlgorithm::SLHDSA(set) | KeyAlgorithm::HashSLHDSA(set) => with_slhdsa!(set, P => {
                type Scheme = crate::crypto::slhdsa::SLHDSA<P>;
                let mut raw = Secret::new(vec![0u8; Scheme::SIGNING_KEY_SIZE]);
                Scheme::write_signing_key(self.typed()?, raw.expose_mut())?;
                raw
            }),
        })
    }

    /// The private key of `algorithm` from its raw form, the form of the
    /// specification of the algorithm rather than of PKCS #8 (JOSE and COSE
    /// keys carry these): the scalar of an EC key (big-endian, of the size
    /// of the field), the private key of X25519, X448, Ed25519 and Ed448
    /// (RFC 7748, RFC 8032), the seed of an ML-DSA or ML-KEM key, the raw
    /// key of SLH-DSA. RSA keys have no single raw form
    /// ([`KeyError::Parameters`]): they are made from their components.
    pub fn from_raw(algorithm: KeyAlgorithm, raw: &[u8]) -> Result<PrivateKey, KeyError> {
        use crate::crypto::curve::curve448::Edwards448;
        use crate::crypto::curve::curve25519::Edwards25519;
        use crate::crypto::{KeyAgreement, SignatureScheme};
        let key: Box<dyn Any + Send + Sync> = match &algorithm {
            KeyAlgorithm::RSA | KeyAlgorithm::RSAPSS(_) => return Err(KeyError::Parameters),
            KeyAlgorithm::EC(curve) => {
                if raw.len() != curve.field_size() {
                    return Err(KeyError::InvalidKey);
                }
                with_curve!(curve, C => {
                    type Scheme = crate::crypto::ecdsa::ECDSA<C, crate::hash::sha::v2::SHA256>;
                    Ok::<Box<dyn Any + Send + Sync>, KeyError>(Box::new(Scheme::signing_key_from_bytes(raw)?))
                })?
            }
            KeyAlgorithm::X25519 => Box::new(crate::crypto::ecdh::X25519::private_key_from_bytes(raw)?),
            KeyAlgorithm::X448 => Box::new(crate::crypto::ecdh::X448::private_key_from_bytes(raw)?),
            KeyAlgorithm::Ed25519 => Box::new(crate::crypto::eddsa::EdDSASigningKey::<Edwards25519>::new(raw)?),
            KeyAlgorithm::Ed448 => Box::new(crate::crypto::eddsa::EdDSASigningKey::<Edwards448>::new(raw)?),
            KeyAlgorithm::MLDSA(set) => {
                with_mldsa!(set, P => Box::new(crate::crypto::mldsa::MLDSA::<P>::signing_key_from_seed(raw)?))
            }
            KeyAlgorithm::MLKEM(set) => {
                with_mlkem!(set, P => Box::new(crate::crypto::mlkem::MLKEM::<P>::decapsulation_key_from_seed(raw)?))
            }
            KeyAlgorithm::SLHDSA(set) | KeyAlgorithm::HashSLHDSA(set) => {
                with_slhdsa!(set, P => Box::new(crate::crypto::slhdsa::SLHDSA::<P>::signing_key_from_bytes(raw)?))
            }
        };
        PrivateKey::from_parts(algorithm, key)
    }

    /// The raw form of the key (see [`PrivateKey::from_raw`]); fails with
    /// [`KeyError::Parameters`] for RSA keys and for ML-DSA and ML-KEM keys
    /// whose seed is not known.
    pub fn raw(&self) -> Result<Secret<Vec<u8>>, KeyError> {
        use crate::crypto::curve::curve448::Edwards448;
        use crate::crypto::curve::curve25519::Edwards25519;
        use crate::crypto::{KeyAgreement, SignatureScheme};
        Ok(match self.algorithm() {
            KeyAlgorithm::RSA | KeyAlgorithm::RSAPSS(_) => return Err(KeyError::Parameters),
            KeyAlgorithm::EC(curve) => {
                let mut scalar = Secret::new(vec![0u8; curve.field_size()]);
                with_curve!(curve, C => {
                    type Scheme = crate::crypto::ecdsa::ECDSA<C, crate::hash::sha::v2::SHA256>;
                    Scheme::write_signing_key(self.typed()?, scalar.expose_mut()).map_err(KeyError::from)
                })?;
                scalar
            }
            KeyAlgorithm::X25519 => {
                let mut raw = Secret::new(vec![0u8; 32]);
                crate::crypto::ecdh::X25519::write_private_key(self.typed()?, raw.expose_mut())?;
                raw
            }
            KeyAlgorithm::X448 => {
                let mut raw = Secret::new(vec![0u8; 56]);
                crate::crypto::ecdh::X448::write_private_key(self.typed()?, raw.expose_mut())?;
                raw
            }
            KeyAlgorithm::Ed25519 => {
                Secret::new(self.typed::<crate::crypto::eddsa::EdDSASigningKey<Edwards25519>>()?.secret().to_vec())
            }
            KeyAlgorithm::Ed448 => {
                Secret::new(self.typed::<crate::crypto::eddsa::EdDSASigningKey<Edwards448>>()?.secret().to_vec())
            }
            KeyAlgorithm::MLDSA(set) => with_mldsa!(set, P => {
                let key = self.typed::<crate::crypto::mldsa::MLDSASigningKey<P>>()?;
                Secret::new(key.seed().ok_or(KeyError::Parameters)?.to_vec())
            }),
            KeyAlgorithm::MLKEM(set) => with_mlkem!(set, P => {
                let key = self.typed::<crate::crypto::mlkem::MLKEMDecapsulationKey<P>>()?;
                Secret::new(key.seed().ok_or(KeyError::Parameters)?.to_vec())
            }),
            KeyAlgorithm::SLHDSA(set) | KeyAlgorithm::HashSLHDSA(set) => with_slhdsa!(set, P => {
                type Scheme = crate::crypto::slhdsa::SLHDSA<P>;
                let mut raw = Secret::new(vec![0u8; Scheme::SIGNING_KEY_SIZE]);
                Scheme::write_signing_key(self.typed()?, raw.expose_mut())?;
                raw
            }),
        })
    }

    /// The pairwise consistency check of an ML-KEM key read from its
    /// expanded form (beyond the hash check of FIPS 203 §7.3, which
    /// `from_bytes` makes): a secret encapsulated to its public key (with
    /// fixed randomness, which a check needs no more than) must decapsulate
    /// to the same secret; [`KeyError::Inconsistent`] otherwise. It finds a
    /// private vector that does not belong to the public key (RFC 9935
    /// appendix C.4, second example).
    pub fn check_mlkem_pair<P: crate::crypto::mlkem::MLKEMParameters>(
        key: &crate::crypto::mlkem::MLKEMDecapsulationKey<P>,
    ) -> Result<(), KeyError> {
        use crate::crypto::mlkem::MLKEM;
        let message = [0x5A; 32];
        let mut ciphertext = vec![0u8; P::CIPHERTEXT_SIZE];
        let (mut sent, mut received) = (Secret::new([0u8; 32]), Secret::new([0u8; 32]));
        MLKEM::<P>::encapsulate_internal(key.encapsulation_key(), &message, &mut ciphertext, sent.expose_mut())?;
        MLKEM::<P>::decapsulate_internal(key, &ciphertext, received.expose_mut())?;
        if sent.expose().ct_eq(received.expose()).into_bool() { Ok(()) } else { Err(KeyError::Inconsistent) }
    }

    /// The raw key of a `CurvePrivateKey` (an OCTET STRING, RFC 8410 §7).
    pub fn curve_private_key(bytes: &[u8]) -> Result<&[u8], KeyError> {
        let mut reader = DERReader::new(bytes);
        let raw = reader.read_with(Tag::OCTET_STRING, |element| element.as_octet_string())?;
        reader.finish()?;
        Ok(raw)
    }

    /// The DER `CurvePrivateKey` of the raw key `raw`.
    pub fn write_curve_private_key(raw: &[u8]) -> Secret<Vec<u8>> {
        let mut writer = DERWriter::new();
        writer.write_octet_string(raw);
        Secret::new(writer.into_bytes())
    }

    /// The seed and the expanded key of the CHOICE of RFC 9881 §6 and
    /// RFC 9935 §6, told apart by their tags: `[0]` for the seed, OCTET
    /// STRING for the expanded key, SEQUENCE for both.
    pub fn seed_choice(bytes: &[u8]) -> Result<SeedChoice<'_>, KeyError> {
        let mut reader = DERReader::new(bytes);
        let element = reader.read_element()?;
        reader.finish()?;
        if element.tag == (Tag { class: TagClass::ContextSpecific, constructed: false, number: 0 }) {
            return Ok(SeedChoice { seed: Some(element.as_octet_string()?), expanded: None });
        }
        if element.tag == Tag::OCTET_STRING {
            return Ok(SeedChoice { seed: None, expanded: Some(element.as_octet_string()?) });
        }
        if element.tag == Tag::SEQUENCE {
            let mut sequence = reader.nested(&element)?;
            let seed = sequence.read_with(Tag::OCTET_STRING, |element| element.as_octet_string())?;
            let expanded = sequence.read_with(Tag::OCTET_STRING, |element| element.as_octet_string())?;
            sequence.finish()?;
            return Ok(SeedChoice { seed: Some(seed), expanded: Some(expanded) });
        }
        Err(KeyError::InvalidKey)
    }

    /// The `seed [0]` form of the CHOICE.
    pub fn write_seed(seed: &[u8]) -> Secret<Vec<u8>> {
        let mut writer = DERWriter::new();
        writer.write_element(Tag { class: TagClass::ContextSpecific, constructed: false, number: 0 }, seed);
        Secret::new(writer.into_bytes())
    }

    /// The `expandedKey` form of the CHOICE.
    pub fn write_expanded(expanded: &[u8]) -> Secret<Vec<u8>> {
        let mut writer = DERWriter::new();
        writer.write_octet_string(expanded);
        Secret::new(writer.into_bytes())
    }

    /// Whether two EC public keys are the same point (one may be compressed).
    pub fn same_point(first: &super::PublicKey, second: &super::PublicKey) -> Result<bool, KeyError> {
        if first.key() == second.key() {
            return Ok(true);
        }
        let KeyAlgorithm::EC(curve) = first.algorithm() else { return Ok(false) };
        with_curve!(curve, C => {
            use crate::crypto::ecdsa::ECDSAVerifyingKey;
            let a = ECDSAVerifyingKey::<C>::from_encoded(first.key())?;
            let b = ECDSAVerifyingKey::<C>::from_encoded(second.key())?;
            Ok(a.point() == b.point())
        })
    }
}

impl core::fmt::Debug for PrivateKeyInfo<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PrivateKeyInfo")
            .field("version", &self.version)
            .field("algorithm", &self.algorithm)
            .field("attributes", &self.attributes)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for SeedChoice<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SeedChoice")
            .field("seed", &self.seed.is_some())
            .field("expanded", &self.expanded.is_some())
            .finish()
    }
}

impl core::fmt::Debug for ECPrivateKey<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ECPrivateKey")
            .field("curve", &self.curve)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}
