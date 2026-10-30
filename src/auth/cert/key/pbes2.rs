use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::{AlgorithmIdentifier, HashAlgorithm, KeyError, PrivateKey};
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ASN1Error, ObjectIdentifier, Tag};
use crate::codec::pem::{PEMConfig, PEMDocument};
use crate::crypto::random::Random;
use crate::secret::Secret;

/// A cipher of PBES2 (RFC 8018 §B.2, NIST CSOR): AES in CBC mode with the
/// padding of RFC 8018 §6.1.1 (that of PKCS #7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PBES2Cipher {
    AES128CBC,
    AES192CBC,
    AES256CBC,
}

impl PBES2Cipher {
    pub const ALL: [PBES2Cipher; 3] = [PBES2Cipher::AES128CBC, PBES2Cipher::AES192CBC, PBES2Cipher::AES256CBC];
    /// The bytes of the initialization vector (the parameters of the identifier).
    pub const IV_SIZE: usize = 16;

    pub const fn oid(self) -> ObjectIdentifier<'static> {
        ObjectIdentifier::from_static(match self {
            PBES2Cipher::AES128CBC => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02],
            PBES2Cipher::AES192CBC => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16],
            PBES2Cipher::AES256CBC => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A],
        })
    }

    pub fn from_oid(oid: &ObjectIdentifier<'_>) -> Option<PBES2Cipher> {
        PBES2Cipher::ALL.into_iter().find(|cipher| cipher.oid() == *oid)
    }

    pub const fn key_size(self) -> usize {
        match self {
            PBES2Cipher::AES128CBC => 16,
            PBES2Cipher::AES192CBC => 24,
            PBES2Cipher::AES256CBC => 32,
        }
    }

    /// Encrypts `data` in place (padded first) with `key` and `iv`.
    pub fn encrypt(self, key: &[u8], iv: &[u8; 16], data: &mut Vec<u8>) -> Result<(), KeyError> {
        use crate::crypto::mode::cbc::CBC;
        crate::crypto::mode::PKCS7::pad(data, 16)?;
        match self {
            PBES2Cipher::AES128CBC => {
                CBC::new(crate::crypto::aes::AES128::new(key.try_into().map_err(|_| KeyError::Parameters)?), iv)
                    .encrypt(data)?
            }
            PBES2Cipher::AES192CBC => {
                CBC::new(crate::crypto::aes::AES192::new(key.try_into().map_err(|_| KeyError::Parameters)?), iv)
                    .encrypt(data)?
            }
            PBES2Cipher::AES256CBC => {
                CBC::new(crate::crypto::aes::AES256::new(key.try_into().map_err(|_| KeyError::Parameters)?), iv)
                    .encrypt(data)?
            }
        }
        Ok(())
    }

    /// Decrypts `data` in place and removes its padding; fails with
    /// [`KeyError::Decryption`] if the padding is not valid.
    pub fn decrypt(self, key: &[u8], iv: &[u8; 16], data: &mut Vec<u8>) -> Result<(), KeyError> {
        use crate::crypto::mode::cbc::CBC;
        let decrypted = match self {
            PBES2Cipher::AES128CBC => {
                CBC::new(crate::crypto::aes::AES128::new(key.try_into().map_err(|_| KeyError::Parameters)?), iv)
                    .decrypt(data)
            }
            PBES2Cipher::AES192CBC => {
                CBC::new(crate::crypto::aes::AES192::new(key.try_into().map_err(|_| KeyError::Parameters)?), iv)
                    .decrypt(data)
            }
            PBES2Cipher::AES256CBC => {
                CBC::new(crate::crypto::aes::AES256::new(key.try_into().map_err(|_| KeyError::Parameters)?), iv)
                    .decrypt(data)
            }
        };
        decrypted.map_err(|_| KeyError::Decryption)?;
        crate::crypto::mode::PKCS7::unpad(data, 16).map_err(|_| KeyError::Decryption)
    }
}

/// The parameters of PBES2 with PBKDF2 (RFC 8018 §A.2, §A.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PBES2Parameters {
    /// The hash function of the HMAC of PBKDF2 (hmacWithSHA1 when absent).
    pub prf: HashAlgorithm,
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub cipher: PBES2Cipher,
    pub iv: [u8; 16],
}

impl PBES2Parameters {
    /// The identifier of PBES2.
    pub const OID: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D]);
    /// The identifier of PBKDF2.
    pub const PBKDF2_OID: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C]);
    /// The identifiers of the HMAC functions of PBKDF2 (RFC 8018 §B.1).
    pub const PRF_OIDS: [(HashAlgorithm, &'static [u8]); 7] = [
        (HashAlgorithm::SHA1, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07]),
        (HashAlgorithm::SHA224, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x08]),
        (HashAlgorithm::SHA256, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09]),
        (HashAlgorithm::SHA384, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0A]),
        (HashAlgorithm::SHA512, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B]),
        (HashAlgorithm::SHA512_224, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0C]),
        (HashAlgorithm::SHA512_256, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0D]),
    ];

    /// The parameters of the DER encoding `bytes` of `PBES2-params`. Only
    /// PBKDF2 with a salt given in place (`specified`) is supported; a
    /// `keyLength`, if given, must be the key size of the cipher.
    pub fn decode(bytes: &[u8]) -> Result<PBES2Parameters, KeyError> {
        let mut reader = DERReader::new(bytes);
        let mut sequence = reader.read_sequence()?;
        reader.finish()?;
        let kdf = AlgorithmIdentifier::decode(&mut sequence)?;
        let scheme = AlgorithmIdentifier::decode(&mut sequence)?;
        sequence.finish()?;
        if kdf.oid != PBES2Parameters::PBKDF2_OID {
            return Err(KeyError::UnknownAlgorithm);
        }
        let cipher = PBES2Cipher::from_oid(&scheme.oid).ok_or(KeyError::UnknownAlgorithm)?;
        let mut iv_reader = DERReader::new(scheme.parameters.as_deref().ok_or(KeyError::Parameters)?);
        let iv = iv_reader.read_with(Tag::OCTET_STRING, |element| element.as_octet_string())?;
        iv_reader.finish()?;
        let iv: [u8; 16] = iv.try_into().map_err(|_| KeyError::Parameters)?;
        let mut parameters = DERReader::new(kdf.parameters.as_deref().ok_or(KeyError::Parameters)?);
        let mut pbkdf2 = parameters.read_sequence()?;
        parameters.finish()?;
        // The salt is a CHOICE: `specified` (an OCTET STRING) or `otherSource`
        // (an AlgorithmIdentifier, a SEQUENCE), which RFC 8018 reserves.
        if pbkdf2.peek_tag() == Some(Tag::SEQUENCE) {
            return Err(KeyError::Unsupported);
        }
        let salt = pbkdf2.read_with(Tag::OCTET_STRING, |element| element.as_octet_string())?;
        let iterations = u32::try_from(pbkdf2.read_integer()?.as_u64()?).map_err(|_| KeyError::Parameters)?;
        if iterations == 0 {
            return Err(KeyError::Parameters);
        }
        if pbkdf2.peek_tag() == Some(Tag::INTEGER) {
            let length = pbkdf2.read_integer()?.as_u64()?;
            if length != cipher.key_size() as u64 {
                return Err(KeyError::Parameters);
            }
        }
        let mut prf = HashAlgorithm::SHA1;
        if !pbkdf2.is_empty() {
            let identifier = AlgorithmIdentifier::decode(&mut pbkdf2)?;
            if !identifier.has_null_or_absent_parameters() {
                return Err(KeyError::Parameters);
            }
            let found = PBES2Parameters::PRF_OIDS.iter().find(|(_, content)| identifier.oid.as_bytes() == *content);
            prf = found.map(|(hash, _)| *hash).ok_or(KeyError::UnknownAlgorithm)?;
        }
        pbkdf2.finish()?;
        Ok(PBES2Parameters { prf, salt: salt.to_vec(), iterations, cipher, iv })
    }

    /// The DER encoding of `PBES2-params` (the default PRF left out, no `keyLength`).
    pub fn encode(&self) -> Result<Vec<u8>, KeyError> {
        let prf = PBES2Parameters::PRF_OIDS.iter().find(|(hash, _)| *hash == self.prf).ok_or(KeyError::Parameters)?;
        let mut writer = DERWriter::new();
        writer.write_sequence(|sequence| {
            sequence.write_sequence(|kdf| {
                kdf.write_object_identifier(&PBES2Parameters::PBKDF2_OID);
                kdf.write_sequence(|parameters| {
                    parameters.write_octet_string(&self.salt);
                    parameters.write_integer_i128(i128::from(self.iterations));
                    if self.prf != HashAlgorithm::SHA1 {
                        AlgorithmIdentifier::null(ObjectIdentifier::from_static(prf.1)).encode(parameters)?;
                    }
                    Ok(())
                })
            })?;
            sequence.write_sequence(|scheme| {
                scheme.write_object_identifier(&self.cipher.oid());
                scheme.write_octet_string(&self.iv);
                Ok(())
            })
        })?;
        Ok(writer.into_bytes())
    }

    /// The key of the cipher derived from `password` with PBKDF2.
    pub fn derive_key(&self, password: &[u8]) -> Result<Secret<Vec<u8>>, KeyError> {
        let mut key = Secret::new(vec![0u8; self.cipher.key_size()]);
        with_digest!(self.prf, H => crate::crypto::pbkdf2::PBKDF2::<H>::derive(password, &self.salt, self.iterations, key.expose_mut())?, xof => {
            return Err(KeyError::Parameters);
        });
        Ok(key)
    }
}

/// The parameters of the encryption of private keys with PBES2: those
/// written (the PRF, the iterations, the salt length and the cipher) and
/// the most iterations accepted when decrypting, which bounds the work a
/// hostile file can cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PBES2Config {
    pub prf: HashAlgorithm,
    pub iterations: u32,
    pub salt_length: usize,
    pub cipher: PBES2Cipher,
    pub maximum_iterations: u32,
}

impl PBES2Config {
    /// The shortest salt written: 8 bytes (RFC 8018 §4.1).
    pub const MINIMUM_SALT_LENGTH: usize = 8;
    /// The longest salt written.
    pub const MAXIMUM_SALT_LENGTH: usize = 64;
    /// The fewest iterations written: 1000 (RFC 8018 §4.2).
    pub const MINIMUM_ITERATIONS: u32 = 1000;

    /// Fails with [`KeyError::Parameters`] unless the parameters may be
    /// written: a salt of 8 to 64 bytes and at least 1000 iterations.
    pub fn check(&self) -> Result<(), KeyError> {
        let salt = (PBES2Config::MINIMUM_SALT_LENGTH..=PBES2Config::MAXIMUM_SALT_LENGTH).contains(&self.salt_length);
        if salt && self.iterations >= PBES2Config::MINIMUM_ITERATIONS { Ok(()) } else { Err(KeyError::Parameters) }
    }
}

impl Default for PBES2Config {
    /// HMAC-SHA-256 with 600 000 iterations (the count OWASP recommends for
    /// PBKDF2-HMAC-SHA256), a salt of 16 bytes and AES-256-CBC; at most
    /// 10 000 000 iterations when decrypting.
    fn default() -> PBES2Config {
        PBES2Config {
            prf: HashAlgorithm::SHA256,
            iterations: 600_000,
            salt_length: 16,
            cipher: PBES2Cipher::AES256CBC,
            maximum_iterations: 10_000_000,
        }
    }
}

/// An `EncryptedPrivateKeyInfo` (RFC 5958 §3): the encryption algorithm and
/// the encrypted `OneAsymmetricKey`; borrowed from its encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedPrivateKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub encrypted_data: &'a [u8],
}

impl<'a> EncryptedPrivateKeyInfo<'a> {
    /// The label of an encrypted private key in PEM (RFC 7468 §11).
    pub const PEM_LABEL: &'static str = "ENCRYPTED PRIVATE KEY";

    pub fn from_der(bytes: &'a [u8]) -> Result<EncryptedPrivateKeyInfo<'a>, KeyError> {
        let mut reader = DERReader::new(bytes);
        let mut sequence = reader.read_sequence()?;
        reader.finish()?;
        let algorithm = AlgorithmIdentifier::decode(&mut sequence)?;
        let encrypted_data = sequence.read_with(Tag::OCTET_STRING, |element| element.as_octet_string())?;
        sequence.finish()?;
        Ok(EncryptedPrivateKeyInfo { algorithm, encrypted_data })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, ASN1Error> {
        let mut writer = DERWriter::new();
        writer.write_sequence(|sequence| {
            self.algorithm.encode(sequence)?;
            sequence.write_octet_string(self.encrypted_data);
            Ok(())
        })?;
        Ok(writer.into_bytes())
    }

    /// The DER `OneAsymmetricKey` decrypted with `password`; fails with
    /// [`KeyError::Decryption`] for a wrong password (or corrupted data) and
    /// with [`KeyError::Parameters`] for more iterations than `config` accepts.
    pub fn decrypt(&self, password: &[u8], config: &PBES2Config) -> Result<Secret<Vec<u8>>, KeyError> {
        if self.algorithm.oid != PBES2Parameters::OID {
            return Err(KeyError::UnknownAlgorithm);
        }
        let parameters = PBES2Parameters::decode(self.algorithm.parameters.as_deref().ok_or(KeyError::Parameters)?)?;
        if parameters.iterations > config.maximum_iterations {
            return Err(KeyError::Parameters);
        }
        let key = parameters.derive_key(password)?;
        let mut data = Secret::new(self.encrypted_data.to_vec());
        parameters.cipher.decrypt(key.expose(), &parameters.iv, data.expose_mut())?;
        Ok(data)
    }

    /// The DER `EncryptedPrivateKeyInfo` of `private_key_info` (a DER
    /// `OneAsymmetricKey`) encrypted with `password` and the parameters of
    /// `config`, with a salt and an IV from `random`.
    pub fn encrypt<R: Random>(
        private_key_info: &[u8],
        password: &[u8],
        config: &PBES2Config,
        random: &mut R,
    ) -> Result<Vec<u8>, KeyError> {
        config.check()?;
        let mut salt = vec![0u8; config.salt_length];
        let mut iv = [0u8; 16];
        random.fill(&mut salt).map_err(|_| KeyError::Crypto(crate::crypto::CryptoError::RandomFailed))?;
        random.fill(&mut iv).map_err(|_| KeyError::Crypto(crate::crypto::CryptoError::RandomFailed))?;
        let parameters =
            PBES2Parameters { prf: config.prf, salt, iterations: config.iterations, cipher: config.cipher, iv };
        let key = parameters.derive_key(password)?;
        // Room for the padding, so that padding never moves (and leaves behind) the plaintext.
        let mut data = Vec::with_capacity(private_key_info.len() + PBES2Cipher::IV_SIZE);
        data.extend_from_slice(private_key_info);
        let mut data = Secret::new(data);
        parameters.cipher.encrypt(key.expose(), &iv, data.expose_mut())?;
        let info = EncryptedPrivateKeyInfo {
            algorithm: AlgorithmIdentifier::new(PBES2Parameters::OID, Some(Cow::Owned(parameters.encode()?))),
            encrypted_data: data.expose(),
        };
        Ok(info.to_der()?)
    }
}

impl PrivateKey {
    /// The key of an `EncryptedPrivateKeyInfo` (PBES2) in BER (DER
    /// included), the encoding RFC 5958 §3 requires receivers to accept.
    pub fn from_encrypted_pkcs8_ber(
        bytes: &[u8],
        password: &[u8],
        config: &PBES2Config,
    ) -> Result<PrivateKey, KeyError> {
        let der = crate::codec::asn1::ber::BERReader::to_der(
            bytes,
            crate::codec::asn1::der::DERReader::DEFAULT_MAXIMUM_DEPTH,
        )?;
        PrivateKey::from_encrypted_pkcs8_der(&der, password, config)
    }

    /// The key of the DER encoding of an `EncryptedPrivateKeyInfo` (PBES2);
    /// the decrypted `OneAsymmetricKey` may be in BER.
    pub fn from_encrypted_pkcs8_der(
        bytes: &[u8],
        password: &[u8],
        config: &PBES2Config,
    ) -> Result<PrivateKey, KeyError> {
        let decrypted = EncryptedPrivateKeyInfo::from_der(bytes)?.decrypt(password, config)?;
        // Data that decrypts with a wrong password and a valid padding by chance is not a key.
        PrivateKey::from_pkcs8_ber(decrypted.expose()).map_err(|error| match error {
            KeyError::Encoding(_) => KeyError::Decryption,
            error => error,
        })
    }

    /// The DER `EncryptedPrivateKeyInfo` of the key (PBES2 with the parameters of `config`).
    pub fn to_encrypted_pkcs8_der<R: Random>(
        &self,
        password: &[u8],
        config: &PBES2Config,
        random: &mut R,
    ) -> Result<Vec<u8>, KeyError> {
        let info = self.to_pkcs8_der()?;
        EncryptedPrivateKeyInfo::encrypt(info.expose(), password, config, random)
    }

    /// The key of PEM text of an `ENCRYPTED PRIVATE KEY`.
    pub fn from_encrypted_pem(text: &str, password: &[u8], config: &PBES2Config) -> Result<PrivateKey, KeyError> {
        let document = PEMDocument::decode(text.as_bytes(), PEMConfig::default())?;
        if document.label() != EncryptedPrivateKeyInfo::PEM_LABEL {
            return Err(KeyError::PEMLabel);
        }
        PrivateKey::from_encrypted_pkcs8_ber(document.data(), password, config)
    }

    /// The PEM text of the key as an `ENCRYPTED PRIVATE KEY`.
    pub fn to_encrypted_pem<R: Random>(
        &self,
        password: &[u8],
        config: &PBES2Config,
        random: &mut R,
    ) -> Result<String, KeyError> {
        let der = self.to_encrypted_pkcs8_der(password, config, random)?;
        Ok(PEMDocument::new(EncryptedPrivateKeyInfo::PEM_LABEL, der)?.encode())
    }
}
