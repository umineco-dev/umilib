use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{Base64URL, JOSEHeader, JOSEMembers, JWEAlgorithm, JWEEncryption, JWK, JWTError};
use crate::codec::deflate::{DeflateCompressor, DeflateConfig, DeflateDecompressor, DeflateDecompressorConfig};
use crate::codec::json::{JSONConfig, JSONObject, JSONValue};
use crate::codec::{Compressor, Decompressor};
use crate::crypto::random::Random;
use crate::secret::Secret;

/// What decrypting a JWE accepts (RFC 8725 §3.1): the key management
/// algorithms, the content encryption algorithms, the critical header
/// parameters understood, the largest PBES2 iteration count (RFC 8725
/// §3.2), the most recipients a JWE may have (each may cost a key
/// derivation: the two bound the work of one decryption), and whether
/// compressed plaintexts (`zip`) are accepted, with the largest plaintext
/// they decompress to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JWEConfig {
    pub algorithms: Vec<JWEAlgorithm>,
    pub encryptions: Vec<JWEEncryption>,
    pub critical: Vec<String>,
    pub maximum_pbes2_count: u32,
    pub maximum_recipients: usize,
    pub compression: bool,
    pub maximum_decompressed: usize,
}

impl JWEConfig {
    pub const MAXIMUM_PBES2_COUNT: u32 = 1_000_000;
    pub const MAXIMUM_RECIPIENTS: usize = 16;
    pub const MAXIMUM_DECOMPRESSED: usize = 1 << 20;

    /// The configuration accepting `algorithms` and `encryptions`, no
    /// critical parameter and no compression.
    pub fn new(algorithms: &[JWEAlgorithm], encryptions: &[JWEEncryption]) -> JWEConfig {
        JWEConfig {
            algorithms: algorithms.to_vec(),
            encryptions: encryptions.to_vec(),
            critical: Vec::new(),
            maximum_pbes2_count: JWEConfig::MAXIMUM_PBES2_COUNT,
            maximum_recipients: JWEConfig::MAXIMUM_RECIPIENTS,
            compression: false,
            maximum_decompressed: JWEConfig::MAXIMUM_DECOMPRESSED,
        }
    }

    pub fn understood(&self) -> Vec<&str> {
        self.critical.iter().map(String::as_str).collect()
    }
}

/// One recipient of a JWE (RFC 7516 §7.2.1): its unprotected header and
/// its JWE Encrypted Key (empty for the direct algorithms).
#[derive(Clone, Debug, PartialEq)]
pub struct JWERecipient {
    pub header: Option<JOSEHeader>,
    pub encrypted_key: Vec<u8>,
}

/// A JWE (RFC 7516): the protected header as encoded and as decoded, the
/// shared unprotected header, the recipients, the JWE AAD, and the
/// encrypted content. The compact serialization holds one recipient and
/// only a protected header; the JSON serializations hold any number.
#[derive(Clone, Debug, PartialEq)]
pub struct JWE {
    /// The base64url text of the protected header; empty without one.
    pub protected: String,
    pub protected_header: JOSEHeader,
    pub unprotected: Option<JOSEHeader>,
    pub recipients: Vec<JWERecipient>,
    pub aad: Option<Vec<u8>>,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

impl JWE {
    /// The value of `zip` this module implements (RFC 7516 §4.1.3).
    pub const DEFLATE: &'static str = "DEF";

    /// The JOSE Header of `recipient` (RFC 7516 §7.2.1): the union of the
    /// protected, the shared unprotected and the per-recipient headers,
    /// which must not share a parameter.
    pub fn joined_header(&self, recipient: &JWERecipient) -> Result<JOSEHeader, JWTError> {
        let mut headers = alloc::vec![&self.protected_header];
        headers.extend(self.unprotected.as_ref());
        headers.extend(recipient.header.as_ref());
        JOSEHeader::union(&headers)
    }

    /// Checks the rules of the headers of `recipient`: disjoint headers,
    /// `crit` (with `understood`), and `zip` only in the protected header
    /// (RFC 7516 §4.1.3); the JOSE Header.
    pub fn check_headers(&self, recipient: &JWERecipient, understood: &[&str]) -> Result<JOSEHeader, JWTError> {
        let header = self.joined_header(recipient)?;
        let mut unprotected: Vec<&JOSEHeader> = self.unprotected.iter().collect();
        unprotected.extend(recipient.header.as_ref());
        JOSEHeader::check_critical(&self.protected_header, &unprotected, understood)?;
        if unprotected.iter().any(|header| header.get("zip").is_some()) {
            return Err(JWTError::Header);
        }
        Ok(header)
    }

    /// The Additional Authenticated Data of the content encryption (RFC
    /// 7516 §5.1 step 14): ASCII(protected), followed by '.' and the
    /// base64url JWE AAD when there is one.
    pub fn additional_data(&self) -> Vec<u8> {
        let mut data = self.protected.as_bytes().to_vec();
        if let Some(aad) = &self.aad {
            data.push(b'.');
            data.extend_from_slice(Base64URL::encode(aad).as_bytes());
        }
        data
    }

    /// The JWE of `plaintext` for `recipients`, each a key and its
    /// per-recipient header, with the headers `protected` and `unprotected`
    /// and the JWE AAD `aad` (RFC 7516 §5.1). Each JOSE Header must have
    /// the `alg` of its recipient and the `enc`, which all share; the direct
    /// algorithms take one recipient. `zip` of `DEF` in the protected header
    /// compresses the plaintext.
    ///
    /// The header parameters of the key management (`epk`, `iv`, `tag`,
    /// `p2s`, `p2c`) go into the protected header when the JWE has one
    /// recipient without a per-recipient header (as the compact
    /// serialization needs), and into the per-recipient header otherwise.
    pub fn encrypt<R: Random>(
        plaintext: &[u8],
        protected: &JOSEHeader,
        unprotected: Option<&JOSEHeader>,
        recipients: &[(&JWK, Option<JOSEHeader>)],
        aad: Option<&[u8]>,
        random: &mut R,
    ) -> Result<JWE, JWTError> {
        let mut jwe = JWE {
            protected: String::new(),
            protected_header: protected.clone(),
            unprotected: unprotected.cloned(),
            recipients: recipients
                .iter()
                .map(|(_, header)| JWERecipient { header: header.clone(), encrypted_key: Vec::new() })
                .collect(),
            aad: aad.map(<[u8]>::to_vec),
            iv: Vec::new(),
            ciphertext: Vec::new(),
            tag: Vec::new(),
        };
        let mut encryption = None;
        let mut algorithms = Vec::with_capacity(recipients.len());
        for recipient in &jwe.recipients {
            let listed = protected.critical()?.unwrap_or_default();
            let header = jwe.check_headers(recipient, &listed)?;
            let own = header.encryption()?;
            if encryption.is_some_and(|encryption| encryption != own) {
                return Err(JWTError::Header);
            }
            encryption = Some(own);
            algorithms.push((header.jwe_algorithm()?, header));
        }
        let encryption = encryption.ok_or(JWTError::Format)?;
        if algorithms.iter().any(|(algorithm, _)| algorithm.is_direct()) && recipients.len() != 1 {
            return Err(JWTError::Header);
        }
        let in_protected = recipients.len() == 1 && recipients[0].1.is_none();
        let mut cek: Option<Secret<Vec<u8>>> = None;
        for (index, ((key, _), (algorithm, header))) in recipients.iter().zip(&algorithms).enumerate() {
            let result = algorithm.encrypt_key(
                key,
                encryption,
                header,
                cek.as_ref().map(|cek| cek.expose().as_slice()),
                random,
            )?;
            let target = if in_protected {
                &mut jwe.protected_header
            } else {
                jwe.recipients[index].header.get_or_insert_with(JOSEHeader::new)
            };
            for (name, value) in result.parameters.parameters.iter() {
                if target.get(name).is_some() {
                    return Err(JWTError::Header);
                }
                target.set(name, value.clone());
            }
            jwe.recipients[index].encrypted_key = result.encrypted_key;
            cek.get_or_insert(result.cek);
        }
        // The parameters added must leave the headers disjoint.
        for recipient in &jwe.recipients {
            jwe.joined_header(recipient)?;
        }
        let cek = cek.ok_or(JWTError::Format)?;
        jwe.protected = if jwe.protected_header.is_empty() {
            String::new()
        } else {
            Base64URL::encode(jwe.protected_header.encode().as_bytes())
        };
        let compressed;
        let content = match jwe.protected_header.string("zip")? {
            None => plaintext,
            Some(JWE::DEFLATE) => {
                let mut compressor =
                    DeflateCompressor::new(DeflateConfig::default()).map_err(|_| JWTError::Compression)?;
                compressed = compressor.compress_to_vec(plaintext).map_err(|_| JWTError::Compression)?;
                &compressed
            }
            Some(_) => return Err(JWTError::Compression),
        };
        jwe.iv = alloc::vec![0u8; encryption.iv_size()];
        random.fill(&mut jwe.iv).map_err(|_| crate::crypto::CryptoError::RandomFailed)?;
        let (ciphertext, tag) = encryption.encrypt(cek.expose(), &jwe.iv, &jwe.additional_data(), content)?;
        jwe.ciphertext = ciphertext;
        jwe.tag = tag;
        Ok(jwe)
    }

    /// Decrypts the JWE with `key` (RFC 7516 §5.2): the plaintext and the
    /// recipient it was decrypted for, the first whose algorithms `config`
    /// allows and fit `key` and that decrypts. Fails with [`JWTError::Limit`]
    /// for more recipients than `config` accepts, with
    /// [`JWTError::AlgorithmNotAllowed`] if no recipient uses allowed
    /// algorithms, [`JWTError::KeyMismatch`] if none fits `key`, with the
    /// error of a header that breaks the rules, and with
    /// [`JWTError::Decryption`] otherwise, whatever failed.
    pub fn decrypt<R: Random>(
        &self,
        key: &JWK,
        config: &JWEConfig,
        random: &mut R,
    ) -> Result<(Vec<u8>, &JWERecipient), JWTError> {
        if self.recipients.len() > config.maximum_recipients {
            return Err(JWTError::Limit);
        }
        let understood = config.understood();
        let mut error = JWTError::AlgorithmNotAllowed;
        for recipient in &self.recipients {
            let header = self.check_headers(recipient, &understood)?;
            let (algorithm, encryption) = match (header.jwe_algorithm(), header.encryption()) {
                (Ok(algorithm), Ok(encryption)) => (algorithm, encryption),
                // An algorithm this module does not know is one no configuration allows.
                (Err(JWTError::UnknownAlgorithm), _) | (_, Err(JWTError::UnknownAlgorithm)) => continue,
                (Err(error), _) | (_, Err(error)) => return Err(error),
            };
            if !config.algorithms.contains(&algorithm) || !config.encryptions.contains(&encryption) {
                continue;
            }
            if algorithm.check_key(key, encryption, algorithm.operations().1).is_err() {
                if error == JWTError::AlgorithmNotAllowed {
                    error = JWTError::KeyMismatch;
                }
                continue;
            }
            let compressed = match header.string("zip")? {
                None => false,
                Some(JWE::DEFLATE) if config.compression => true,
                Some(_) => return Err(JWTError::Compression),
            };
            let cek = match algorithm.decrypt_key(key, encryption, &header, &recipient.encrypted_key, config, random) {
                Ok(cek) => cek,
                // RFC 7516 §11.5: a key that fails to decrypt continues as
                // a random one, so that the failure looks like any other.
                Err(JWTError::Decryption) if !algorithm.is_direct() => {
                    let mut cek = Secret::new(alloc::vec![0u8; encryption.key_size()]);
                    random.fill(cek.expose_mut()).map_err(|_| crate::crypto::CryptoError::RandomFailed)?;
                    cek
                }
                Err(JWTError::Decryption) => {
                    error = JWTError::Decryption;
                    continue;
                }
                Err(other) => return Err(other),
            };
            let Ok(content) =
                encryption.decrypt(cek.expose(), &self.iv, &self.additional_data(), &self.ciphertext, &self.tag)
            else {
                error = JWTError::Decryption;
                continue;
            };
            if !compressed {
                return Ok((content, recipient));
            }
            return Ok((JWE::decompress(&content, config.maximum_decompressed)?, recipient));
        }
        Err(error)
    }

    /// The Deflate stream `data` (RFC 1951), which must end where `data`
    /// does, decompressed to at most `limit` bytes.
    pub fn decompress(data: &[u8], limit: usize) -> Result<Vec<u8>, JWTError> {
        let mut decompressor =
            DeflateDecompressor::new(DeflateDecompressorConfig::default()).map_err(|_| JWTError::Compression)?;
        let mut input = data;
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let room = chunk.len().min((limit - out.len()).saturating_add(1));
            let progress = decompressor.decompress(input, &mut chunk[..room]).map_err(|_| JWTError::Compression)?;
            input = &input[progress.consumed..];
            out.extend_from_slice(&chunk[..progress.produced]);
            if out.len() > limit {
                return Err(JWTError::Compression);
            }
            if progress.finished {
                return if input.is_empty() { Ok(out) } else { Err(JWTError::Compression) };
            }
            if progress.consumed == 0 && progress.produced == 0 {
                return Err(JWTError::Compression);
            }
        }
    }

    /// The JWE of the compact serialization `text` (RFC 7516 §7.1):
    /// protected header, encrypted key, IV, ciphertext and tag, separated
    /// by `.`.
    pub fn from_compact(text: &str) -> Result<JWE, JWTError> {
        let mut parts = text.split('.');
        let (Some(protected), Some(encrypted_key), Some(iv), Some(ciphertext), Some(tag), None) =
            (parts.next(), parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JWTError::Format);
        };
        if protected.is_empty() {
            return Err(JWTError::Format);
        }
        Ok(JWE {
            protected: protected.to_string(),
            protected_header: JOSEHeader::decode(&Base64URL::decode(protected)?)?,
            unprotected: None,
            recipients: alloc::vec![JWERecipient { header: None, encrypted_key: Base64URL::decode(encrypted_key)? }],
            aad: None,
            iv: Base64URL::decode(iv)?,
            ciphertext: Base64URL::decode(ciphertext)?,
            tag: Base64URL::decode(tag)?,
        })
    }

    /// The compact serialization: one recipient, a protected header and no
    /// other header or JWE AAD (RFC 7516 §7.1).
    pub fn to_compact(&self) -> Result<String, JWTError> {
        let [recipient] = self.recipients.as_slice() else { return Err(JWTError::Format) };
        if self.protected.is_empty() || self.unprotected.is_some() || recipient.header.is_some() || self.aad.is_some() {
            return Err(JWTError::Format);
        }
        Ok(alloc::format!(
            "{}.{}.{}.{}.{}",
            self.protected,
            Base64URL::encode(&recipient.encrypted_key),
            Base64URL::encode(&self.iv),
            Base64URL::encode(&self.ciphertext),
            Base64URL::encode(&self.tag)
        ))
    }

    /// The JWE of a JSON serialization `text` (RFC 7516 §7.2): general,
    /// with `recipients`, or flattened, with the members of one recipient.
    pub fn from_json(text: &[u8]) -> Result<JWE, JWTError> {
        let value = JSONValue::decode(text, JSONConfig::default())?;
        let object = value.as_object().ok_or(JWTError::Format)?;
        let members = JOSEMembers::new(object, JWTError::Format);
        let protected = members.string("protected")?.unwrap_or_default();
        let protected_header =
            if protected.is_empty() { JOSEHeader::new() } else { JOSEHeader::decode(&Base64URL::decode(protected)?)? };
        let unprotected =
            members.object("unprotected")?.map(|parameters| JOSEHeader { parameters: parameters.clone() });
        let recipients = match object.get("recipients") {
            Some(list) => {
                if object.get("header").is_some() || object.get("encrypted_key").is_some() {
                    return Err(JWTError::Format);
                }
                let list = list.as_array().ok_or(JWTError::Format)?;
                if list.is_empty() {
                    return Err(JWTError::Format);
                }
                list.iter()
                    .map(|item| JWE::recipient_of(item.as_object().ok_or(JWTError::Format)?))
                    .collect::<Result<Vec<_>, _>>()?
            }
            None => alloc::vec![JWE::recipient_of(object)?],
        };
        Ok(JWE {
            protected: protected.to_string(),
            protected_header,
            unprotected,
            recipients,
            aad: members.bytes("aad")?,
            iv: members.bytes("iv")?.unwrap_or_default(),
            ciphertext: members.required_bytes("ciphertext")?,
            tag: members.bytes("tag")?.unwrap_or_default(),
        })
    }

    /// The recipient of the members `object` of a JSON serialization.
    pub fn recipient_of(object: &JSONObject) -> Result<JWERecipient, JWTError> {
        let members = JOSEMembers::new(object, JWTError::Format);
        Ok(JWERecipient {
            header: members.object("header")?.map(|parameters| JOSEHeader { parameters: parameters.clone() }),
            encrypted_key: members.bytes("encrypted_key")?.unwrap_or_default(),
        })
    }

    /// The members of one recipient in a JSON serialization.
    pub fn recipient_object(recipient: &JWERecipient, object: &mut JSONObject) {
        if let Some(header) = &recipient.header {
            object.insert(String::from("header"), JSONValue::Object(header.parameters.clone()));
        }
        if !recipient.encrypted_key.is_empty() {
            object
                .insert(String::from("encrypted_key"), JSONValue::String(Base64URL::encode(&recipient.encrypted_key)));
        }
    }

    /// The JSON object of a JSON serialization: general or `flattened` (one recipient).
    pub fn json_object(&self, flattened: bool) -> Result<JSONObject, JWTError> {
        let mut object = JSONObject::default();
        let put = |object: &mut JSONObject, name: &str, value: JSONValue| {
            object.insert(name.to_string(), value);
        };
        if !self.protected.is_empty() {
            put(&mut object, "protected", JSONValue::String(self.protected.clone()));
        }
        if let Some(unprotected) = &self.unprotected {
            put(&mut object, "unprotected", JSONValue::Object(unprotected.parameters.clone()));
        }
        if flattened {
            let [recipient] = self.recipients.as_slice() else { return Err(JWTError::Format) };
            JWE::recipient_object(recipient, &mut object);
        } else {
            let recipients = self
                .recipients
                .iter()
                .map(|recipient| {
                    let mut member = JSONObject::default();
                    JWE::recipient_object(recipient, &mut member);
                    JSONValue::Object(member)
                })
                .collect();
            put(&mut object, "recipients", JSONValue::Array(recipients));
        }
        if let Some(aad) = &self.aad {
            put(&mut object, "aad", JSONValue::String(Base64URL::encode(aad)));
        }
        if !self.iv.is_empty() {
            put(&mut object, "iv", JSONValue::String(Base64URL::encode(&self.iv)));
        }
        put(&mut object, "ciphertext", JSONValue::String(Base64URL::encode(&self.ciphertext)));
        if !self.tag.is_empty() {
            put(&mut object, "tag", JSONValue::String(Base64URL::encode(&self.tag)));
        }
        Ok(object)
    }

    /// The general JSON serialization (RFC 7516 §7.2.1).
    pub fn to_json(&self) -> Result<String, JWTError> {
        Ok(JSONValue::Object(self.json_object(false)?).encode())
    }

    /// The flattened JSON serialization of a JWE of one recipient (RFC 7516 §7.2.2).
    pub fn to_flattened_json(&self) -> Result<String, JWTError> {
        Ok(JSONValue::Object(self.json_object(true)?).encode())
    }
}
