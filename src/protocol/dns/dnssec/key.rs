use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;
use crate::crypto::SignatureScheme;
use crate::crypto::curve::curve448::Edwards448;
use crate::crypto::curve::curve25519::Edwards25519;
use crate::crypto::curve::p256::P256;
use crate::crypto::curve::p384::P384;
use crate::crypto::ecdsa::{ECDSA, ECDSASignature, ECDSASigningKey, ECDSAVerifyingKey};
use crate::crypto::eddsa::{Ed448, Ed25519, EdDSASigningKey, EdDSAVerifyingKey};
use crate::crypto::random::Random;
use crate::crypto::rsa::{RSAPKCS1v15, RSAPrivateKey, RSAPublicKey};
use crate::hash::Digest;
use crate::hash::sha::v1::SHA1;
use crate::hash::sha::v2::{SHA256, SHA384, SHA512};
use crate::math::bigint::BoxedUint;
use crate::secret::Zeroize;

use super::super::{DNSData, DNSError, DNSExtendedError};
use super::DNSSECAlgorithm;

/// The fields of a DNSKEY record (RFC 4034 §2.1), borrowed from its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DNSSECKey<'a> {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: DNSSECAlgorithm,
    pub public_key: &'a [u8],
}

impl<'a> DNSSECKey<'a> {
    /// The flag of a key that signs the zone's records (RFC 4034 §2.1.1).
    pub const ZONE: u16 = 0x0100;
    /// The flag of a key revoked as a trust anchor (RFC 5011 §3).
    pub const REVOKE: u16 = 0x0080;
    /// The flag of a key meant as a secure entry point (RFC 4034 §2.1.1, RFC 3757).
    pub const SECURE_ENTRY_POINT: u16 = 0x0001;
    /// The only protocol of a DNSKEY (RFC 4034 §2.1.2).
    pub const PROTOCOL: u8 = 3;

    /// The fields of a DNSKEY or CDNSKEY datum.
    pub fn from_data(data: &'a DNSData) -> Option<DNSSECKey<'a>> {
        match data {
            DNSData::DNSKEY { flags, protocol, algorithm, public_key } => Some(DNSSECKey {
                flags: *flags,
                protocol: *protocol,
                algorithm: DNSSECAlgorithm(*algorithm),
                public_key,
            }),
            _ => None,
        }
    }

    /// The RDATA of the key (RFC 4034 §2.1).
    pub fn rdata(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.public_key.len());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&[self.protocol, self.algorithm.0]);
        out.extend_from_slice(self.public_key);
        out
    }

    /// The key tag of RFC 4034 Appendix B: the sum of the RDATA as 16-bit
    /// words with the carry folded once, or, for RSA/MD5 (B.1), the second
    /// and third bytes from the end of the modulus.
    pub fn tag(&self) -> u16 {
        if self.algorithm == DNSSECAlgorithm::RSAMD5 {
            let length = self.public_key.len();
            return match length {
                3.. => u16::from_be_bytes([self.public_key[length - 3], self.public_key[length - 2]]),
                _ => 0,
            };
        }
        let mut sum: u32 = 0;
        for (index, byte) in self.rdata().iter().enumerate() {
            sum += if index & 1 == 0 { u32::from(*byte) << 8 } else { u32::from(*byte) };
        }
        sum += sum >> 16 & 0xFFFF;
        (sum & 0xFFFF) as u16
    }

    pub fn is_zone_key(&self) -> bool {
        self.flags & DNSSECKey::ZONE != 0
    }

    pub fn is_revoked(&self) -> bool {
        self.flags & DNSSECKey::REVOKE != 0
    }

    pub fn is_secure_entry_point(&self) -> bool {
        self.flags & DNSSECKey::SECURE_ENTRY_POINT != 0
    }
}

/// A public key of a DNSSEC algorithm, of the form of its DNSKEY: RSA of
/// RFC 3110 §2, ECDSA of RFC 6605 §4, EdDSA of RFC 8080 §3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DNSSECPublicKey {
    /// An RSA key of RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256 or RSASHA512.
    RSA(DNSSECAlgorithm, RSAPublicKey),
    ECDSAP256SHA256(ECDSAVerifyingKey<P256>),
    ECDSAP384SHA384(ECDSAVerifyingKey<P384>),
    ED25519(EdDSAVerifyingKey<Edwards25519>),
    ED448(EdDSAVerifyingKey<Edwards448>),
}

impl DNSSECPublicKey {
    /// The largest RSA modulus, in bits (RFC 3110 §2, RFC 5702 §2).
    pub const MAXIMUM_RSA_BITS: u32 = 4096;

    /// The key of the DNSKEY public key field `bytes` of `algorithm`. An
    /// RSA key has its exponent's length in one byte, or in two after a
    /// zero, then the exponent and the modulus, each without leading zeros
    /// (RFC 3110 §2), of 512 to 4096 bits (1024 for RSASHA512, RFC 5702 §2).
    pub fn decode(algorithm: DNSSECAlgorithm, bytes: &[u8]) -> Result<DNSSECPublicKey, DNSError> {
        let malformed = DNSError::Malformed("a public key not of its algorithm");
        match algorithm {
            DNSSECAlgorithm::RSASHA1
            | DNSSECAlgorithm::RSASHA1_NSEC3_SHA1
            | DNSSECAlgorithm::RSASHA256
            | DNSSECAlgorithm::RSASHA512 => {
                let (length, rest) = match bytes {
                    [0, high, low, rest @ ..] => (usize::from(u16::from_be_bytes([*high, *low])), rest),
                    [length, rest @ ..] => (usize::from(*length), rest),
                    [] => return Err(malformed),
                };
                if length == 0 || length >= rest.len() {
                    return Err(malformed);
                }
                let (exponent, modulus) = rest.split_at(length);
                if exponent[0] == 0 || modulus[0] == 0 {
                    return Err(malformed);
                }
                let bits = (modulus.len() * 8) as u32 - modulus[0].leading_zeros();
                let minimum = if algorithm == DNSSECAlgorithm::RSASHA512 { 1024 } else { 512 };
                if !(minimum..=DNSSECPublicKey::MAXIMUM_RSA_BITS).contains(&bits) || exponent.len() > modulus.len() {
                    return Err(malformed);
                }
                let integer =
                    |bytes: &[u8]| BoxedUint::from_be_bytes(bytes, (bytes.len() * 8) as u32).map_err(|_| malformed);
                let key = RSAPublicKey::new(&integer(modulus)?, &integer(exponent)?).map_err(|_| malformed)?;
                Ok(DNSSECPublicKey::RSA(algorithm, key))
            }
            DNSSECAlgorithm::ECDSAP256SHA256 => {
                Ok(DNSSECPublicKey::ECDSAP256SHA256(DNSSECPublicKey::point(bytes, 64).ok_or(malformed)?))
            }
            DNSSECAlgorithm::ECDSAP384SHA384 => {
                Ok(DNSSECPublicKey::ECDSAP384SHA384(DNSSECPublicKey::point(bytes, 96).ok_or(malformed)?))
            }
            DNSSECAlgorithm::ED25519 => {
                Ok(DNSSECPublicKey::ED25519(Ed25519::verifying_key_from_bytes(bytes).map_err(|_| malformed)?))
            }
            DNSSECAlgorithm::ED448 => {
                Ok(DNSSECPublicKey::ED448(Ed448::verifying_key_from_bytes(bytes).map_err(|_| malformed)?))
            }
            _ => Err(DNSError::Malformed("a key of an algorithm not implemented")),
        }
    }

    /// The point of the ECDSA key `bytes`: x then y, `length` bytes in all (RFC 6605 §4).
    pub fn point<C: crate::math::ec::WeierstrassCurve>(bytes: &[u8], length: usize) -> Option<ECDSAVerifyingKey<C>> {
        if bytes.len() != length {
            return None;
        }
        let mut encoded = Vec::with_capacity(length + 1);
        encoded.push(0x04);
        encoded.extend_from_slice(bytes);
        ECDSAVerifyingKey::from_encoded(&encoded).ok()
    }

    pub fn algorithm(&self) -> DNSSECAlgorithm {
        match self {
            DNSSECPublicKey::RSA(algorithm, _) => *algorithm,
            DNSSECPublicKey::ECDSAP256SHA256(_) => DNSSECAlgorithm::ECDSAP256SHA256,
            DNSSECPublicKey::ECDSAP384SHA384(_) => DNSSECAlgorithm::ECDSAP384SHA384,
            DNSSECPublicKey::ED25519(_) => DNSSECAlgorithm::ED25519,
            DNSSECPublicKey::ED448(_) => DNSSECAlgorithm::ED448,
        }
    }

    /// The size of the key: the bits of an RSA modulus or of the curve's field.
    pub fn bits(&self) -> u32 {
        match self {
            DNSSECPublicKey::RSA(_, key) => key.bits(),
            DNSSECPublicKey::ECDSAP256SHA256(_) => 256,
            DNSSECPublicKey::ECDSAP384SHA384(_) => 384,
            DNSSECPublicKey::ED25519(_) => 255,
            DNSSECPublicKey::ED448(_) => 448,
        }
    }

    /// The bits of an RSA key's public exponent; 0 for other keys.
    pub fn exponent_bits(&self) -> u32 {
        match self {
            DNSSECPublicKey::RSA(_, key) => key.e().bit_length(),
            _ => 0,
        }
    }

    /// The DNSKEY public key field of the key, as [`DNSSECPublicKey::decode`] reads it.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            DNSSECPublicKey::RSA(_, key) => {
                let exponent = DNSSECPublicKey::minimal(key.e().to_be_bytes());
                let modulus = DNSSECPublicKey::minimal(key.n().to_be_bytes());
                let mut out = Vec::with_capacity(3 + exponent.len() + modulus.len());
                match u8::try_from(exponent.len()) {
                    Ok(length) => out.push(length),
                    Err(_) => {
                        out.push(0);
                        out.extend_from_slice(&(exponent.len() as u16).to_be_bytes());
                    }
                }
                out.extend_from_slice(&exponent);
                out.extend_from_slice(&modulus);
                out
            }
            DNSSECPublicKey::ECDSAP256SHA256(key) => DNSSECPublicKey::coordinates::<P256, SHA256>(key),
            DNSSECPublicKey::ECDSAP384SHA384(key) => DNSSECPublicKey::coordinates::<P384, SHA384>(key),
            DNSSECPublicKey::ED25519(key) => key.encoded().to_vec(),
            DNSSECPublicKey::ED448(key) => key.encoded().to_vec(),
        }
    }

    /// `bytes` without its leading zeros.
    pub fn minimal(mut bytes: Vec<u8>) -> Vec<u8> {
        let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
        bytes.drain(..zeros);
        bytes
    }

    /// x then y of the ECDSA key `key` (RFC 6605 §4).
    pub fn coordinates<C: crate::math::ec::WeierstrassCurve, H: crate::hash::CryptographicDigest + Default>(
        key: &ECDSAVerifyingKey<C>,
    ) -> Vec<u8> {
        let mut encoded = alloc::vec![0u8; ECDSA::<C, H>::VERIFYING_KEY_SIZE];
        // The buffer has the size of the uncompressed encoding.
        let _ = key.write_encoded(&mut encoded, false);
        encoded.remove(0);
        encoded
    }

    /// Succeeds if `signature` is the key's signature of `data` (RFC 3110
    /// §3 and RFC 5702 §3: PKCS #1 v1.5; RFC 6605 §4: r then s; RFC 8080
    /// §4: pure EdDSA); fails with a bogus error otherwise.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), DNSError> {
        let valid = match self {
            DNSSECPublicKey::RSA(DNSSECAlgorithm::RSASHA256, key) => {
                RSAPKCS1v15::<SHA256>::verify(key, data, signature)
            }
            DNSSECPublicKey::RSA(DNSSECAlgorithm::RSASHA512, key) => {
                RSAPKCS1v15::<SHA512>::verify(key, data, signature)
            }
            DNSSECPublicKey::RSA(_, key) => RSAPKCS1v15::<SHA1>::verify(key, data, signature),
            DNSSECPublicKey::ECDSAP256SHA256(key) => ECDSA::<P256, SHA256>::verify(key, data, signature),
            DNSSECPublicKey::ECDSAP384SHA384(key) => ECDSA::<P384, SHA384>::verify(key, data, signature),
            DNSSECPublicKey::ED25519(key) => Ed25519::verify(key, data, signature),
            DNSSECPublicKey::ED448(key) => Ed448::verify(key, data, signature),
        };
        valid.map_err(|_| DNSError::Bogus {
            code: DNSExtendedError::DNSSEC_BOGUS,
            reason: "a signature that does not verify",
        })
    }
}

/// A private key of a DNSSEC algorithm, to sign zones.
#[derive(Debug)]
pub enum DNSSECPrivateKey {
    RSA(DNSSECAlgorithm, RSAPrivateKey),
    ECDSAP256SHA256(ECDSASigningKey<P256>),
    ECDSAP384SHA384(ECDSASigningKey<P384>),
    ED25519(EdDSASigningKey<Edwards25519>),
    ED448(EdDSASigningKey<Edwards448>),
}

impl DNSSECPrivateKey {
    /// The public exponent of generated RSA keys.
    pub const RSA_EXPONENT: u64 = 65537;

    /// A new key of `algorithm`; `bits` is the size of an RSA modulus and
    /// is not used by other algorithms.
    pub fn generate<R: Random>(
        algorithm: DNSSECAlgorithm,
        bits: u32,
        random: &mut R,
    ) -> Result<DNSSECPrivateKey, DNSError> {
        let failed = |_| DNSError::Config;
        match algorithm {
            DNSSECAlgorithm::RSASHA1
            | DNSSECAlgorithm::RSASHA1_NSEC3_SHA1
            | DNSSECAlgorithm::RSASHA256
            | DNSSECAlgorithm::RSASHA512 => {
                if bits > DNSSECPublicKey::MAXIMUM_RSA_BITS {
                    return Err(DNSError::Config);
                }
                let exponent = BoxedUint::from_u64(DNSSECPrivateKey::RSA_EXPONENT, 64).map_err(|_| DNSError::Config)?;
                Ok(DNSSECPrivateKey::RSA(algorithm, RSAPrivateKey::generate(bits, &exponent, random).map_err(failed)?))
            }
            DNSSECAlgorithm::ECDSAP256SHA256 => {
                Ok(DNSSECPrivateKey::ECDSAP256SHA256(ECDSA::<P256, SHA256>::generate(random).map_err(failed)?))
            }
            DNSSECAlgorithm::ECDSAP384SHA384 => {
                Ok(DNSSECPrivateKey::ECDSAP384SHA384(ECDSA::<P384, SHA384>::generate(random).map_err(failed)?))
            }
            DNSSECAlgorithm::ED25519 => Ok(DNSSECPrivateKey::ED25519(Ed25519::generate(random).map_err(failed)?)),
            DNSSECAlgorithm::ED448 => Ok(DNSSECPrivateKey::ED448(Ed448::generate(random).map_err(failed)?)),
            _ => Err(DNSError::Config),
        }
    }

    pub fn algorithm(&self) -> DNSSECAlgorithm {
        match self {
            DNSSECPrivateKey::RSA(algorithm, _) => *algorithm,
            DNSSECPrivateKey::ECDSAP256SHA256(_) => DNSSECAlgorithm::ECDSAP256SHA256,
            DNSSECPrivateKey::ECDSAP384SHA384(_) => DNSSECAlgorithm::ECDSAP384SHA384,
            DNSSECPrivateKey::ED25519(_) => DNSSECAlgorithm::ED25519,
            DNSSECPrivateKey::ED448(_) => DNSSECAlgorithm::ED448,
        }
    }

    pub fn public_key(&self) -> DNSSECPublicKey {
        match self {
            DNSSECPrivateKey::RSA(algorithm, key) => DNSSECPublicKey::RSA(*algorithm, key.public_key().clone()),
            DNSSECPrivateKey::ECDSAP256SHA256(key) => {
                DNSSECPublicKey::ECDSAP256SHA256(ECDSA::<P256, SHA256>::verifying_key(key))
            }
            DNSSECPrivateKey::ECDSAP384SHA384(key) => {
                DNSSECPublicKey::ECDSAP384SHA384(ECDSA::<P384, SHA384>::verifying_key(key))
            }
            DNSSECPrivateKey::ED25519(key) => DNSSECPublicKey::ED25519(key.verifying_key().clone()),
            DNSSECPrivateKey::ED448(key) => DNSSECPublicKey::ED448(key.verifying_key().clone()),
        }
    }

    /// The signature of `data`, of the form [`DNSSECPublicKey::verify`]
    /// checks. RSA is blinded by `random`; ECDSA's nonce is of RFC 6979
    /// with bytes of `random` added (§3.6); EdDSA does not use it.
    pub fn sign<R: Random>(&self, data: &[u8], random: &mut R) -> Result<Vec<u8>, DNSError> {
        let failed = |_| DNSError::State;
        match self {
            DNSSECPrivateKey::RSA(DNSSECAlgorithm::RSASHA256, key) => {
                RSAPKCS1v15::<SHA256>::sign(key, data, random).map_err(failed)
            }
            DNSSECPrivateKey::RSA(DNSSECAlgorithm::RSASHA512, key) => {
                RSAPKCS1v15::<SHA512>::sign(key, data, random).map_err(failed)
            }
            DNSSECPrivateKey::RSA(_, key) => RSAPKCS1v15::<SHA1>::sign(key, data, random).map_err(failed),
            DNSSECPrivateKey::ECDSAP256SHA256(key) => {
                let signature =
                    ECDSA::<P256, SHA256>::sign_digest_hedged(key, &SHA256::digest(data), random).map_err(failed)?;
                DNSSECPrivateKey::signature_bytes(&signature)
            }
            DNSSECPrivateKey::ECDSAP384SHA384(key) => {
                let signature =
                    ECDSA::<P384, SHA384>::sign_digest_hedged(key, &SHA384::digest(data), random).map_err(failed)?;
                DNSSECPrivateKey::signature_bytes(&signature)
            }
            DNSSECPrivateKey::ED25519(key) => {
                let mut out = alloc::vec![0u8; Ed25519::SIGNATURE_SIZE];
                Ed25519::sign(key, data, &mut out).map_err(failed)?;
                Ok(out)
            }
            DNSSECPrivateKey::ED448(key) => {
                let mut out = alloc::vec![0u8; Ed448::SIGNATURE_SIZE];
                Ed448::sign(key, data, &mut out).map_err(failed)?;
                Ok(out)
            }
        }
    }

    /// r then s of `signature` (RFC 6605 §4).
    pub fn signature_bytes<C: crate::math::ec::WeierstrassCurve>(
        signature: &ECDSASignature<C>,
    ) -> Result<Vec<u8>, DNSError> {
        let mut out = alloc::vec![0u8; ECDSASignature::<C>::BYTES];
        signature.write_bytes(&mut out).map_err(|_| DNSError::State)?;
        Ok(out)
    }

    /// The key of the text of the private key format v1.2 that BIND and
    /// the examples of RFC 5702 §6, RFC 6605 §6 and RFC 8080 §6 use: lines
    /// of a field, a colon and base64 (a line without a colon continues the
    /// one before). Fields this crate does not use are ignored.
    pub fn parse(text: &str) -> Result<DNSSECPrivateKey, DNSError> {
        let mut fields: Vec<(&str, String)> = Vec::new();
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            match line.split_once(':') {
                Some((name, value)) => fields.push((name.trim(), String::from(value.trim()))),
                None => match fields.last_mut() {
                    Some((_, value)) => value.push_str(line),
                    None => return Err(DNSError::Syntax("not a private key")),
                },
            }
        }
        let key = DNSSECPrivateKey::from_fields(&fields);
        for (_, value) in &mut fields {
            value.zeroize();
        }
        key
    }

    /// The key of the fields (name and base64 value) of the private key format.
    pub fn from_fields(fields: &[(&str, String)]) -> Result<DNSSECPrivateKey, DNSError> {
        let syntax = DNSError::Syntax("not a private key");
        let field =
            |name: &str| fields.iter().find(|(field, _)| field.eq_ignore_ascii_case(name)).map(|(_, value)| value);
        if !field("Private-key-format").is_some_and(|format| format.starts_with("v1.")) {
            return Err(syntax);
        }
        let number = field("Algorithm").and_then(|value| value.split_whitespace().next()).ok_or(syntax)?;
        let algorithm = DNSSECAlgorithm(number.parse().map_err(|_| syntax)?);
        let invalid = |_| DNSError::Syntax("a private key that is not valid");
        // The decoded bytes of a field, given to `read` and zeroed after.
        let decoded = |name: &str, read: &mut dyn FnMut(&[u8]) -> Result<(), DNSError>| {
            let mut bytes = Base64::STANDARD.decode(field(name).ok_or(syntax)?.as_bytes()).map_err(|_| syntax)?;
            let result = read(&bytes);
            bytes.zeroize();
            result
        };
        let integer = |name: &str| -> Result<BoxedUint, DNSError> {
            let mut value = None;
            decoded(name, &mut |bytes| {
                value = Some(BoxedUint::from_be_bytes(bytes, (bytes.len().max(1) * 8) as u32).map_err(|_| syntax)?);
                Ok(())
            })?;
            value.ok_or(syntax)
        };
        let signing = |read: &mut dyn FnMut(&[u8]) -> Result<(), DNSError>| decoded("PrivateKey", read);
        let mut key = None;
        match algorithm {
            DNSSECAlgorithm::RSASHA1
            | DNSSECAlgorithm::RSASHA1_NSEC3_SHA1
            | DNSSECAlgorithm::RSASHA256
            | DNSSECAlgorithm::RSASHA512 => {
                let public = RSAPublicKey::new(&integer("Modulus")?, &integer("PublicExponent")?).map_err(invalid)?;
                let private = RSAPrivateKey::from_components(
                    public,
                    &integer("PrivateExponent")?,
                    &integer("Prime1")?,
                    &integer("Prime2")?,
                    &integer("Exponent1")?,
                    &integer("Exponent2")?,
                    &integer("Coefficient")?,
                )
                .map_err(invalid)?;
                key = Some(DNSSECPrivateKey::RSA(algorithm, private));
            }
            DNSSECAlgorithm::ECDSAP256SHA256 => signing(&mut |bytes| {
                let private = ECDSA::<P256, SHA256>::signing_key_from_bytes(bytes).map_err(invalid)?;
                key = Some(DNSSECPrivateKey::ECDSAP256SHA256(private));
                Ok(())
            })?,
            DNSSECAlgorithm::ECDSAP384SHA384 => signing(&mut |bytes| {
                let private = ECDSA::<P384, SHA384>::signing_key_from_bytes(bytes).map_err(invalid)?;
                key = Some(DNSSECPrivateKey::ECDSAP384SHA384(private));
                Ok(())
            })?,
            DNSSECAlgorithm::ED25519 => signing(&mut |bytes| {
                key = Some(DNSSECPrivateKey::ED25519(Ed25519::signing_key_from_bytes(bytes).map_err(invalid)?));
                Ok(())
            })?,
            DNSSECAlgorithm::ED448 => signing(&mut |bytes| {
                key = Some(DNSSECPrivateKey::ED448(Ed448::signing_key_from_bytes(bytes).map_err(invalid)?));
                Ok(())
            })?,
            _ => return Err(DNSError::Syntax("a private key of an algorithm not implemented")),
        }
        key.ok_or(syntax)
    }

    /// The key in the text [`DNSSECPrivateKey::parse`] reads, one field a line.
    pub fn format(&self) -> String {
        let algorithm = self.algorithm();
        let mut out = String::from("Private-key-format: v1.2\n");
        let _ = writeln!(out, "Algorithm: {} ({})", algorithm.0, algorithm);
        let mut field = |name: &str, bytes: &[u8]| {
            let _ = writeln!(out, "{name}: {}", Base64::STANDARD.encode(bytes));
        };
        match self {
            DNSSECPrivateKey::RSA(_, key) => {
                // Each integer, without its leading zeros, is zeroed once written.
                let mut integer = |name: &str, value: &BoxedUint| {
                    let mut bytes = DNSSECPublicKey::minimal(value.to_be_bytes());
                    field(name, &bytes);
                    bytes.zeroize();
                };
                integer("Modulus", key.public_key().n());
                integer("PublicExponent", key.public_key().e());
                integer("PrivateExponent", key.d());
                if let Some(primes) = key.primes() {
                    integer("Prime1", primes.p());
                    integer("Prime2", primes.q());
                    integer("Exponent1", primes.dp());
                    integer("Exponent2", primes.dq());
                    integer("Coefficient", primes.q_inverse());
                }
            }
            DNSSECPrivateKey::ECDSAP256SHA256(key) => {
                let mut bytes = [0u8; 32];
                let _ = ECDSA::<P256, SHA256>::write_signing_key(key, &mut bytes);
                field("PrivateKey", &bytes);
                bytes.zeroize();
            }
            DNSSECPrivateKey::ECDSAP384SHA384(key) => {
                let mut bytes = [0u8; 48];
                let _ = ECDSA::<P384, SHA384>::write_signing_key(key, &mut bytes);
                field("PrivateKey", &bytes);
                bytes.zeroize();
            }
            DNSSECPrivateKey::ED25519(key) => field("PrivateKey", key.secret()),
            DNSSECPrivateKey::ED448(key) => field("PrivateKey", key.secret()),
        }
        out
    }
}
