use alloc::vec::Vec;

use super::{Base64URL, JOSEHeader, JWEAlgorithm, JWEConfig, JWEEncryption, JWK, JWKCurve, JWKKey, JWTError};
use crate::codec::json::JSONValue;
use crate::crypto::aes::{AES128, AES192, AES256};
use crate::crypto::concatkdf::ConcatKDF;
use crate::crypto::curve::p256::P256;
use crate::crypto::curve::p384::P384;
use crate::crypto::curve::p521::P521;
use crate::crypto::ecdh::{ECDH, X448, X25519};
use crate::crypto::mode::kw::KW;
use crate::crypto::pbkdf2::PBKDF2;
use crate::crypto::random::Random;
use crate::crypto::rsa::{RSAOAEP, RSAPrivateKey, RSAPublicKey};
use crate::crypto::{BlockCipher, KeyAgreement, KeyInit};
use crate::hash::sha::v1::SHA1;
use crate::hash::sha::v2::{SHA256, SHA384, SHA512};
use crate::secret::Secret;

/// The key management of one recipient of a JWE (RFC 7516 §5.1 steps 2 to
/// 8): the content encryption key, the JWE Encrypted Key, and the header
/// parameters the algorithm defines (`epk`, `iv`, `tag`, `p2s`, `p2c`),
/// which belong to the header of the recipient.
#[derive(Clone, Debug)]
pub struct JWEEncryptedKey {
    pub cek: Secret<Vec<u8>>,
    pub encrypted_key: Vec<u8>,
    pub parameters: JOSEHeader,
}

impl JWEAlgorithm {
    /// The shortest RSA modulus in bits (RFC 7518 §4.2, §4.3).
    pub const MINIMUM_RSA_BITS: usize = 2048;
    /// The PBES2 iteration count used when the header has no `p2c`
    /// (RFC 7518 §4.8.1.2 recommends at least 1000).
    pub const PBES2_COUNT: u32 = 600_000;
    pub const MINIMUM_PBES2_COUNT: u32 = 1000;
    /// The bytes of a generated PBES2 salt, and the fewest accepted
    /// (RFC 7518 §4.8.1.1: 8 or more).
    pub const PBES2_SALT_SIZE: usize = 16;
    pub const MINIMUM_PBES2_SALT_SIZE: usize = 8;
    /// The bytes of the IV and of the tag of AES-GCM key wrapping (RFC 7518 §4.7).
    pub const GCMKW_IV_SIZE: usize = 12;
    pub const GCMKW_TAG_SIZE: usize = 16;

    /// The key operations (RFC 7517 §4.3) of the sender and of the
    /// recipient: `wrapKey` and `unwrapKey` for the algorithms that encrypt
    /// the content encryption key, `deriveKey` for key agreement,
    /// `encrypt` and `decrypt` for direct encryption.
    pub const fn operations(self) -> (&'static str, &'static str) {
        match self {
            JWEAlgorithm::Dir => ("encrypt", "decrypt"),
            JWEAlgorithm::ECDHES
            | JWEAlgorithm::ECDHESA128KW
            | JWEAlgorithm::ECDHESA192KW
            | JWEAlgorithm::ECDHESA256KW => ("deriveKey", "deriveKey"),
            _ => ("wrapKey", "unwrapKey"),
        }
    }

    /// Fails with [`JWTError::KeyMismatch`] unless `key` may serve the
    /// algorithm with `encryption` for `operation`: its `alg`, `use` and
    /// `key_ops` allow it, and it is of the type and size the algorithm
    /// takes (RFC 7518 §4).
    pub fn check_key(self, key: &JWK, encryption: JWEEncryption, operation: &str) -> Result<(), JWTError> {
        // The key of direct encryption is the content encryption key: its
        // `alg` may name the content encryption algorithm (RFC 7520 §5.6).
        let name = match (self, key.algorithm.as_deref()) {
            (JWEAlgorithm::Dir, Some(own)) if own == encryption.name() => encryption.name(),
            _ => self.name(),
        };
        if !key.allows(operation, name) {
            return Err(JWTError::KeyMismatch);
        }
        let fits = match (self, &key.key) {
            (JWEAlgorithm::Dir, JWKKey::Oct { k }) => k.expose().len() == encryption.key_size(),
            (
                JWEAlgorithm::RSAOAEP | JWEAlgorithm::RSAOAEP256 | JWEAlgorithm::RSAOAEP384 | JWEAlgorithm::RSAOAEP512,
                JWKKey::RSA { n, .. },
            ) => n
                .first()
                .is_some_and(|&first| n.len() * 8 - first.leading_zeros() as usize >= JWEAlgorithm::MINIMUM_RSA_BITS),
            (
                JWEAlgorithm::ECDHES
                | JWEAlgorithm::ECDHESA128KW
                | JWEAlgorithm::ECDHESA192KW
                | JWEAlgorithm::ECDHESA256KW,
                JWKKey::EC { curve, .. } | JWKKey::OKP { curve, .. },
            ) => JWEAlgorithm::is_agreement_curve(*curve),
            (
                JWEAlgorithm::PBES2HS256A128KW | JWEAlgorithm::PBES2HS384A192KW | JWEAlgorithm::PBES2HS512A256KW,
                JWKKey::Oct { k },
            ) => !k.expose().is_empty(),
            (_, JWKKey::Oct { k }) => Some(k.expose().len()) == self.wrapping_key_size(),
            _ => false,
        };
        if fits { Ok(()) } else { Err(JWTError::KeyMismatch) }
    }

    /// Whether ECDH-ES works on `curve`: P-256, P-384 and P-521 (RFC 7518
    /// §4.6), X25519 and X448 (RFC 8037 §3.2).
    pub const fn is_agreement_curve(curve: JWKCurve) -> bool {
        matches!(curve, JWKCurve::P256 | JWKCurve::P384 | JWKCurve::P521 | JWKCurve::X25519 | JWKCurve::X448)
    }

    /// The key management of the sender for the recipient key `key`:
    /// `cek` is the content encryption key to encrypt, generated from
    /// `random` when `None`; the direct algorithms determine it themselves
    /// and take `None` only. `header` is the JOSE Header of the recipient,
    /// read for `apu` and `apv` (ECDH-ES) and `p2c` (PBES2).
    pub fn encrypt_key<R: Random>(
        self,
        key: &JWK,
        encryption: JWEEncryption,
        header: &JOSEHeader,
        cek: Option<&[u8]>,
        random: &mut R,
    ) -> Result<JWEEncryptedKey, JWTError> {
        self.check_key(key, encryption, self.operations().0)?;
        let mut parameters = JOSEHeader::new();
        let cek = match (self.is_direct(), cek) {
            (true, Some(_)) => return Err(JWTError::KeyMismatch),
            (true, None) => None,
            (false, Some(cek)) if cek.len() == encryption.key_size() => Some(Secret::new(cek.to_vec())),
            (false, Some(_)) => return Err(JWTError::KeyMismatch),
            (false, None) => {
                let mut cek = Secret::new(alloc::vec![0u8; encryption.key_size()]);
                random.fill(cek.expose_mut()).map_err(|_| crate::crypto::CryptoError::RandomFailed)?;
                Some(cek)
            }
        };
        let (cek, encrypted_key) = match (self, &key.key) {
            (JWEAlgorithm::Dir, JWKKey::Oct { k }) => (Secret::new(k.expose().clone()), Vec::new()),
            (JWEAlgorithm::A128KW | JWEAlgorithm::A192KW | JWEAlgorithm::A256KW, JWKKey::Oct { k }) => {
                let cek = cek.ok_or(JWTError::KeyMismatch)?;
                let wrapped = JWEAlgorithm::wrap(k.expose(), cek.expose())?;
                (cek, wrapped)
            }
            (JWEAlgorithm::A128GCMKW | JWEAlgorithm::A192GCMKW | JWEAlgorithm::A256GCMKW, JWKKey::Oct { k }) => {
                let cek = cek.ok_or(JWTError::KeyMismatch)?;
                let mut iv = [0u8; JWEAlgorithm::GCMKW_IV_SIZE];
                random.fill(&mut iv).map_err(|_| crate::crypto::CryptoError::RandomFailed)?;
                let (wrapped, tag) = JWEAlgorithm::encrypt_gcm(k.expose(), &iv, cek.expose())?;
                parameters.set_string("iv", &Base64URL::encode(&iv));
                parameters.set_string("tag", &Base64URL::encode(&tag));
                (cek, wrapped)
            }
            (
                JWEAlgorithm::PBES2HS256A128KW | JWEAlgorithm::PBES2HS384A192KW | JWEAlgorithm::PBES2HS512A256KW,
                JWKKey::Oct { k },
            ) => {
                let cek = cek.ok_or(JWTError::KeyMismatch)?;
                // A count in the header is kept; otherwise the default goes into the parameters.
                let count = match header.get("p2c") {
                    None => {
                        parameters.set("p2c", JSONValue::from(u64::from(JWEAlgorithm::PBES2_COUNT)));
                        JWEAlgorithm::PBES2_COUNT
                    }
                    Some(_) => JWEAlgorithm::pbes2_count(header, u32::MAX)?,
                };
                let mut salt = [0u8; JWEAlgorithm::PBES2_SALT_SIZE];
                random.fill(&mut salt).map_err(|_| crate::crypto::CryptoError::RandomFailed)?;
                let kek = self.pbes2_key(k.expose(), &salt, count)?;
                let wrapped = JWEAlgorithm::wrap(kek.expose(), cek.expose())?;
                parameters.set_string("p2s", &Base64URL::encode(&salt));
                (cek, wrapped)
            }
            (_, JWKKey::RSA { .. }) => {
                let cek = cek.ok_or(JWTError::KeyMismatch)?;
                let public = key.public_key()?;
                let wrapped = self.encrypt_rsa(public.typed::<RSAPublicKey>()?, cek.expose(), random)?;
                (cek, wrapped)
            }
            (_, JWKKey::EC { curve, .. } | JWKKey::OKP { curve, .. }) => {
                let (ephemeral, shared) =
                    JWEAlgorithm::agree_ephemeral(*curve, &JWEAlgorithm::agreement_public(key)?, random)?;
                parameters.set("epk", JSONValue::Object(JWEAlgorithm::agreement_jwk(*curve, &ephemeral)?.to_object()));
                let derived = self.derive(encryption, header, shared.expose())?;
                match cek {
                    None => (derived, Vec::new()),
                    Some(cek) => {
                        let wrapped = JWEAlgorithm::wrap(derived.expose(), cek.expose())?;
                        (cek, wrapped)
                    }
                }
            }
            _ => return Err(JWTError::KeyMismatch),
        };
        Ok(JWEEncryptedKey { cek, encrypted_key, parameters })
    }

    /// The key management of the recipient with its key `key` (RFC 7516
    /// §5.2 steps 9 to 11): the content encryption key of `encrypted_key`.
    /// `header` is the JOSE Header of the recipient (the union of the
    /// protected, the shared and the per-recipient headers). A key that
    /// does not fit fails with [`JWTError::KeyMismatch`], a malformed
    /// parameter with [`JWTError::Header`], and every failure to recover a
    /// key, wherever it comes from, with [`JWTError::Decryption`].
    pub fn decrypt_key<R: Random>(
        self,
        key: &JWK,
        encryption: JWEEncryption,
        header: &JOSEHeader,
        encrypted_key: &[u8],
        config: &JWEConfig,
        random: &mut R,
    ) -> Result<Secret<Vec<u8>>, JWTError> {
        self.check_key(key, encryption, self.operations().1)?;
        // RFC 7516 §5.2 step 10: no encrypted key for the direct algorithms.
        if self.is_direct() && !encrypted_key.is_empty() {
            return Err(JWTError::Decryption);
        }
        let cek = match (self, &key.key) {
            (JWEAlgorithm::Dir, JWKKey::Oct { k }) => Secret::new(k.expose().clone()),
            (JWEAlgorithm::A128KW | JWEAlgorithm::A192KW | JWEAlgorithm::A256KW, JWKKey::Oct { k }) => {
                JWEAlgorithm::unwrap(k.expose(), encrypted_key)?
            }
            (JWEAlgorithm::A128GCMKW | JWEAlgorithm::A192GCMKW | JWEAlgorithm::A256GCMKW, JWKKey::Oct { k }) => {
                let members = header.members();
                let iv = members.required_bytes("iv")?;
                let tag = members.required_bytes("tag")?;
                if iv.len() != JWEAlgorithm::GCMKW_IV_SIZE || tag.len() != JWEAlgorithm::GCMKW_TAG_SIZE {
                    return Err(JWTError::Header);
                }
                JWEAlgorithm::decrypt_gcm(k.expose(), &iv, encrypted_key, &tag)?
            }
            (
                JWEAlgorithm::PBES2HS256A128KW | JWEAlgorithm::PBES2HS384A192KW | JWEAlgorithm::PBES2HS512A256KW,
                JWKKey::Oct { k },
            ) => {
                let salt = header.members().required_bytes("p2s")?;
                if salt.len() < JWEAlgorithm::MINIMUM_PBES2_SALT_SIZE {
                    return Err(JWTError::Header);
                }
                let count = JWEAlgorithm::pbes2_count(header, config.maximum_pbes2_count)?;
                let kek = self.pbes2_key(k.expose(), &salt, count)?;
                JWEAlgorithm::unwrap(kek.expose(), encrypted_key)?
            }
            (_, JWKKey::RSA { .. }) => {
                let private = key.private_key()?;
                self.decrypt_rsa(private.typed::<RSAPrivateKey>()?, encrypted_key, random)?
            }
            (_, JWKKey::EC { curve, d: Some(d), .. } | JWKKey::OKP { curve, d: Some(d), .. }) => {
                let ephemeral = header.ephemeral_key()?.ok_or(JWTError::Header)?;
                let public = match &ephemeral.key {
                    JWKKey::EC { curve: other, .. } | JWKKey::OKP { curve: other, .. } if other == curve => {
                        JWEAlgorithm::agreement_public(&ephemeral)?
                    }
                    _ => return Err(JWTError::Header),
                };
                let shared = JWEAlgorithm::agree_static(*curve, d.expose(), &public)?;
                let derived = self.derive(encryption, header, shared.expose())?;
                if self.is_direct() { derived } else { JWEAlgorithm::unwrap(derived.expose(), encrypted_key)? }
            }
            _ => return Err(JWTError::KeyMismatch),
        };
        if cek.expose().len() != encryption.key_size() {
            return Err(JWTError::Decryption);
        }
        Ok(cek)
    }

    /// `cek` wrapped with AES Key Wrap (RFC 3394) under `kek` of 16, 24 or
    /// 32 bytes (RFC 7518 §4.4).
    pub fn wrap(kek: &[u8], cek: &[u8]) -> Result<Vec<u8>, JWTError> {
        match kek.len() {
            16 => JWEAlgorithm::wrap_with(AES128::new_from_slice(kek)?, cek),
            24 => JWEAlgorithm::wrap_with(AES192::new_from_slice(kek)?, cek),
            32 => JWEAlgorithm::wrap_with(AES256::new_from_slice(kek)?, cek),
            _ => Err(JWTError::KeyMismatch),
        }
    }

    pub fn unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Secret<Vec<u8>>, JWTError> {
        let unwrapped = match kek.len() {
            16 => JWEAlgorithm::unwrap_with(AES128::new_from_slice(kek)?, wrapped),
            24 => JWEAlgorithm::unwrap_with(AES192::new_from_slice(kek)?, wrapped),
            32 => JWEAlgorithm::unwrap_with(AES256::new_from_slice(kek)?, wrapped),
            _ => return Err(JWTError::KeyMismatch),
        };
        unwrapped.map_err(|_| JWTError::Decryption)
    }

    pub fn wrap_with<C: BlockCipher>(cipher: C, cek: &[u8]) -> Result<Vec<u8>, JWTError> {
        let mut out = alloc::vec![0u8; KW::<C>::wrapped_length(cek.len())?];
        KW::new(cipher)?.wrap(cek, &mut out)?;
        Ok(out)
    }

    pub fn unwrap_with<C: BlockCipher>(cipher: C, wrapped: &[u8]) -> Result<Secret<Vec<u8>>, JWTError> {
        let mut out = Secret::new(alloc::vec![0u8; wrapped.len().checked_sub(8).ok_or(JWTError::Decryption)?]);
        KW::new(cipher)?.unwrap(wrapped, out.expose_mut())?;
        Ok(out)
    }

    /// `cek` encrypted with AES-GCM under `kek` with `iv` and no additional
    /// data (RFC 7518 §4.7.1): the ciphertext and the tag.
    pub fn encrypt_gcm(kek: &[u8], iv: &[u8], cek: &[u8]) -> Result<(Vec<u8>, Vec<u8>), JWTError> {
        let encryption = match kek.len() {
            16 => JWEEncryption::A128GCM,
            24 => JWEEncryption::A192GCM,
            32 => JWEEncryption::A256GCM,
            _ => return Err(JWTError::KeyMismatch),
        };
        encryption.encrypt(kek, iv, &[], cek)
    }

    pub fn decrypt_gcm(kek: &[u8], iv: &[u8], wrapped: &[u8], tag: &[u8]) -> Result<Secret<Vec<u8>>, JWTError> {
        let encryption = match kek.len() {
            16 => JWEEncryption::A128GCM,
            24 => JWEEncryption::A192GCM,
            32 => JWEEncryption::A256GCM,
            _ => return Err(JWTError::KeyMismatch),
        };
        Ok(Secret::new(encryption.decrypt(kek, iv, &[], wrapped, tag)?))
    }

    /// `cek` encrypted with RSAES-OAEP (RFC 7518 §4.3): SHA-1 for
    /// `RSA-OAEP`, the hash of the name for the others, with MGF1 over the
    /// same hash and an empty label.
    pub fn encrypt_rsa<R: Random>(self, key: &RSAPublicKey, cek: &[u8], random: &mut R) -> Result<Vec<u8>, JWTError> {
        Ok(match self {
            JWEAlgorithm::RSAOAEP => RSAOAEP::<SHA1>::encrypt(key, cek, &[], random)?,
            JWEAlgorithm::RSAOAEP256 => RSAOAEP::<SHA256>::encrypt(key, cek, &[], random)?,
            JWEAlgorithm::RSAOAEP384 => RSAOAEP::<SHA384>::encrypt(key, cek, &[], random)?,
            JWEAlgorithm::RSAOAEP512 => RSAOAEP::<SHA512>::encrypt(key, cek, &[], random)?,
            _ => return Err(JWTError::KeyMismatch),
        })
    }

    pub fn decrypt_rsa<R: Random>(
        self,
        key: &RSAPrivateKey,
        wrapped: &[u8],
        random: &mut R,
    ) -> Result<Secret<Vec<u8>>, JWTError> {
        let cek = match self {
            JWEAlgorithm::RSAOAEP => RSAOAEP::<SHA1>::decrypt(key, wrapped, &[], random),
            JWEAlgorithm::RSAOAEP256 => RSAOAEP::<SHA256>::decrypt(key, wrapped, &[], random),
            JWEAlgorithm::RSAOAEP384 => RSAOAEP::<SHA384>::decrypt(key, wrapped, &[], random),
            JWEAlgorithm::RSAOAEP512 => RSAOAEP::<SHA512>::decrypt(key, wrapped, &[], random),
            _ => return Err(JWTError::KeyMismatch),
        };
        cek.map(Secret::new).map_err(|_| JWTError::Decryption)
    }

    /// The key of PBES2 (RFC 7518 §4.8.1.1): PBKDF2 with HMAC over the hash
    /// of the algorithm, of `password`, with the salt UTF8(alg) || 0x00 ||
    /// `salt`, `count` iterations and the size of the wrapping key.
    pub fn pbes2_key(self, password: &[u8], salt: &[u8], count: u32) -> Result<Secret<Vec<u8>>, JWTError> {
        let size = self.wrapping_key_size().ok_or(JWTError::KeyMismatch)?;
        let input = [self.name().as_bytes(), &[0], salt].concat();
        let mut key = Secret::new(alloc::vec![0u8; size]);
        match self {
            JWEAlgorithm::PBES2HS256A128KW => PBKDF2::<SHA256>::derive(password, &input, count, key.expose_mut())?,
            JWEAlgorithm::PBES2HS384A192KW => PBKDF2::<SHA384>::derive(password, &input, count, key.expose_mut())?,
            JWEAlgorithm::PBES2HS512A256KW => PBKDF2::<SHA512>::derive(password, &input, count, key.expose_mut())?,
            _ => return Err(JWTError::KeyMismatch),
        }
        Ok(key)
    }

    /// The `p2c` of `header`: an integer from [`JWEAlgorithm::MINIMUM_PBES2_COUNT`]
    /// to `maximum` (RFC 8725 §3.2 asks to bound it); [`JWTError::Header`] otherwise.
    pub fn pbes2_count(header: &JOSEHeader, maximum: u32) -> Result<u32, JWTError> {
        let count = header.get("p2c").and_then(JSONValue::as_number).ok_or(JWTError::Header)?;
        let count = count.as_u64().ok().and_then(|count| u32::try_from(count).ok()).ok_or(JWTError::Header)?;
        if !(JWEAlgorithm::MINIMUM_PBES2_COUNT..=maximum).contains(&count) {
            return Err(JWTError::Header);
        }
        Ok(count)
    }

    /// The key of ECDH-ES (RFC 7518 §4.6.2): the Concat KDF with SHA-256 of
    /// the shared secret `z`, with the OtherInfo of
    /// [`JWEAlgorithm::agreement_info`], of the size of the content
    /// encryption key (direct key agreement) or of the wrapping key.
    pub fn derive(self, encryption: JWEEncryption, header: &JOSEHeader, z: &[u8]) -> Result<Secret<Vec<u8>>, JWTError> {
        let size = if self.is_direct() {
            encryption.key_size()
        } else {
            self.wrapping_key_size().ok_or(JWTError::KeyMismatch)?
        };
        let info = self.agreement_info(encryption, header, size)?;
        let mut key = Secret::new(alloc::vec![0u8; size]);
        ConcatKDF::<crate::crypto::concatkdf::HashFunction<SHA256>>::hash().derive(z, &info, key.expose_mut())?;
        Ok(key)
    }

    /// The OtherInfo of ECDH-ES (RFC 7518 §4.6.2): AlgorithmID (the `enc`
    /// for direct key agreement, the `alg` otherwise), PartyUInfo (`apu`)
    /// and PartyVInfo (`apv`), each preceded by its length in 32 bits, and
    /// SuppPubInfo, the bits of the derived key in 32 bits.
    pub fn agreement_info(
        self,
        encryption: JWEEncryption,
        header: &JOSEHeader,
        size: usize,
    ) -> Result<Vec<u8>, JWTError> {
        let members = header.members();
        let algorithm = if self.is_direct() { encryption.name() } else { self.name() };
        let party_u = members.bytes("apu")?.unwrap_or_default();
        let party_v = members.bytes("apv")?.unwrap_or_default();
        let mut info = Vec::new();
        for field in [algorithm.as_bytes(), &party_u, &party_v] {
            let length = u32::try_from(field.len()).map_err(|_| JWTError::Header)?;
            info.extend_from_slice(&length.to_be_bytes());
            info.extend_from_slice(field);
        }
        let bits = u32::try_from(size * 8).map_err(|_| JWTError::KeyMismatch)?;
        info.extend_from_slice(&bits.to_be_bytes());
        Ok(info)
    }

    /// The public key of an `EC` or `OKP` key as its key agreement takes
    /// it: the uncompressed SEC 1 point, or the raw coordinate.
    pub fn agreement_public(key: &JWK) -> Result<Vec<u8>, JWTError> {
        match &key.key {
            JWKKey::EC { x, y, .. } => Ok([&[0x04][..], x, y].concat()),
            JWKKey::OKP { x, .. } => Ok(x.clone()),
            _ => Err(JWTError::KeyMismatch),
        }
    }

    /// The public JWK of `curve` with the public key `public` of its key agreement.
    pub fn agreement_jwk(curve: JWKCurve, public: &[u8]) -> Result<JWK, JWTError> {
        if curve.is_okp() {
            return Ok(JWK::new(JWKKey::OKP { curve, x: public.to_vec(), d: None }));
        }
        let point = public.get(1..).filter(|point| point.len() == 2 * curve.size()).ok_or(JWTError::KeyMismatch)?;
        let (x, y) = point.split_at(curve.size());
        Ok(JWK::new(JWKKey::EC { curve, x: x.to_vec(), y: y.to_vec(), d: None }))
    }

    /// A key pair generated on `curve` and its shared secret with `public`:
    /// the public key of the pair and the secret.
    pub fn agree_ephemeral<R: Random>(
        curve: JWKCurve,
        public: &[u8],
        random: &mut R,
    ) -> Result<(Vec<u8>, Secret<Vec<u8>>), JWTError> {
        match curve {
            JWKCurve::P256 => JWEAlgorithm::agree_ephemeral_with::<ECDH<P256>, R>(public, random),
            JWKCurve::P384 => JWEAlgorithm::agree_ephemeral_with::<ECDH<P384>, R>(public, random),
            JWKCurve::P521 => JWEAlgorithm::agree_ephemeral_with::<ECDH<P521>, R>(public, random),
            JWKCurve::X25519 => JWEAlgorithm::agree_ephemeral_with::<X25519, R>(public, random),
            JWKCurve::X448 => JWEAlgorithm::agree_ephemeral_with::<X448, R>(public, random),
            _ => Err(JWTError::KeyMismatch),
        }
    }

    /// The shared secret of the private key `private` (the `d` of the JWK)
    /// and the public key `public` on `curve`; [`JWTError::Decryption`] for
    /// a public key that is not valid or gives no secret.
    pub fn agree_static(curve: JWKCurve, private: &[u8], public: &[u8]) -> Result<Secret<Vec<u8>>, JWTError> {
        let shared = match curve {
            JWKCurve::P256 => JWEAlgorithm::agree_static_with::<ECDH<P256>>(private, public),
            JWKCurve::P384 => JWEAlgorithm::agree_static_with::<ECDH<P384>>(private, public),
            JWKCurve::P521 => JWEAlgorithm::agree_static_with::<ECDH<P521>>(private, public),
            JWKCurve::X25519 => JWEAlgorithm::agree_static_with::<X25519>(private, public),
            JWKCurve::X448 => JWEAlgorithm::agree_static_with::<X448>(private, public),
            _ => return Err(JWTError::KeyMismatch),
        };
        shared.map_err(|_| JWTError::Decryption)
    }

    pub fn agree_ephemeral_with<A: KeyAgreement, R: Random>(
        public: &[u8],
        random: &mut R,
    ) -> Result<(Vec<u8>, Secret<Vec<u8>>), JWTError> {
        let recipient = A::public_key_from_bytes(public)?;
        let private = A::generate(random)?;
        let mut ephemeral = alloc::vec![0u8; A::PUBLIC_KEY_SIZE];
        A::write_public_key(&A::public_key(&private), &mut ephemeral)?;
        let mut shared = Secret::new(alloc::vec![0u8; A::SHARED_SECRET_SIZE]);
        A::agree(&private, &recipient, shared.expose_mut())?;
        Ok((ephemeral, shared))
    }

    pub fn agree_static_with<A: KeyAgreement>(private: &[u8], public: &[u8]) -> Result<Secret<Vec<u8>>, JWTError> {
        let private = A::private_key_from_bytes(private)?;
        let public = A::public_key_from_bytes(public)?;
        let mut shared = Secret::new(alloc::vec![0u8; A::SHARED_SECRET_SIZE]);
        A::agree(&private, &public, shared.expose_mut())?;
        Ok(shared)
    }
}
