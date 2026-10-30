use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::bytes::{Buffer, Reader, Writer};
use crate::crypto::random::Random;
use crate::secret::Secret;

use super::{
    TLSAlertDescription, TLSClientHello, TLSError, TLSExtension, TLSExtensionContext, TLSExtensionType, TLSServerNames,
    TLSTranscript, TLSVector,
};

/// A pair of an HPKE KDF and AEAD that encrypts ClientHellos:
/// `HpkeSymmetricCipherSuite` (RFC 9849 §4, RFC 9180 §7.2, §7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TLSECHCipherSuite {
    pub kdf_id: u16,
    pub aead_id: u16,
}

impl TLSECHCipherSuite {
    pub const HKDF_SHA256: u16 = 0x0001;
    pub const HKDF_SHA384: u16 = 0x0002;
    pub const HKDF_SHA512: u16 = 0x0003;
    pub const AES_128_GCM: u16 = 0x0001;
    pub const AES_256_GCM: u16 = 0x0002;
    pub const CHACHA20_POLY1305: u16 = 0x0003;
    /// The suite every implementation supports (RFC 9849 §9).
    pub const MANDATORY: TLSECHCipherSuite =
        TLSECHCipherSuite { kdf_id: TLSECHCipherSuite::HKDF_SHA256, aead_id: TLSECHCipherSuite::AES_128_GCM };

    /// Whether this crate implements the suite.
    pub fn is_supported(self) -> bool {
        (TLSECHCipherSuite::HKDF_SHA256..=TLSECHCipherSuite::HKDF_SHA512).contains(&self.kdf_id)
            && (TLSECHCipherSuite::AES_128_GCM..=TLSECHCipherSuite::CHACHA20_POLY1305).contains(&self.aead_id)
            && cfg!(umilib_feature = "crypto-hpke")
    }

    /// The length of the AEAD's tag: 16 for every AEAD supported.
    pub fn tag_length(self) -> usize {
        16
    }

    pub fn decode(reader: &mut Reader<'_>) -> Result<TLSECHCipherSuite, TLSError> {
        let kdf_id = reader.read_be().map_err(|_| TLSError::decode())?;
        let aead_id = reader.read_be().map_err(|_| TLSError::decode())?;
        Ok(TLSECHCipherSuite { kdf_id, aead_id })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        out.write_be(self.kdf_id)?;
        Ok(out.write_be(self.aead_id)?)
    }
}

/// An extension of an ECH configuration (RFC 9849 §4.2): one whose type has
/// the high bit set is mandatory, and a client that does not know it
/// ignores the configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLSECHConfigExtension {
    pub kind: u16,
    pub data: Vec<u8>,
}

impl TLSECHConfigExtension {
    pub fn is_mandatory(&self) -> bool {
        self.kind & 0x8000 != 0
    }
}

/// An ECH configuration: `ECHConfig` of version 0xfe0d (RFC 9849 §4), the
/// public key of a client-facing server and how to use it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLSECHConfig {
    pub config_id: u8,
    pub kem_id: u16,
    pub public_key: Vec<u8>,
    pub cipher_suites: Vec<TLSECHCipherSuite>,
    /// The longest name of the servers behind it, for padding; 0 if unknown.
    pub maximum_name_length: u8,
    /// The DNS name of the client-facing server.
    pub public_name: Vec<u8>,
    pub extensions: Vec<TLSECHConfigExtension>,
}

impl TLSECHConfig {
    /// The version of this specification, the code point of the extension.
    pub const VERSION: u16 = 0xFE0D;
    /// DHKEM(P-256, HKDF-SHA256), DHKEM(P-384, HKDF-SHA384),
    /// DHKEM(P-521, HKDF-SHA512), DHKEM(X25519, HKDF-SHA256) and
    /// DHKEM(X448, HKDF-SHA512) (RFC 9180 §7.1).
    pub const DHKEM_P256: u16 = 0x0010;
    pub const DHKEM_P384: u16 = 0x0011;
    pub const DHKEM_P521: u16 = 0x0012;
    pub const DHKEM_X25519: u16 = 0x0020;
    pub const DHKEM_X448: u16 = 0x0021;

    /// The configurations of an `ECHConfigList` (RFC 9849 §4) that are of
    /// version 0xfe0d, in order; those of other versions are skipped.
    pub fn decode_list(data: &[u8]) -> Result<Vec<TLSECHConfig>, TLSError> {
        let mut reader = Reader::new(data);
        let mut list = TLSVector::read_reader(&mut reader, 2, 4, 0xFFFF)?;
        TLSVector::finish(&reader)?;
        let mut configs = Vec::new();
        while !list.is_empty() {
            let version: u16 = list.read_be().map_err(|_| TLSError::decode())?;
            let contents = TLSVector::read(&mut list, 2, 0, 0xFFFF)?;
            if version == TLSECHConfig::VERSION {
                configs.push(TLSECHConfig::decode_contents(contents)?);
            }
        }
        Ok(configs)
    }

    pub fn encode_list(configs: &[TLSECHConfig], out: &mut impl Writer) -> Result<(), TLSError> {
        TLSVector::write_with(out, 2, 0xFFFF, |list| configs.iter().try_for_each(|config| config.encode(list)))
    }

    /// `ECHConfigContents`; duplicated extensions are `decode_error` (RFC 9849 §4.2).
    pub fn decode_contents(contents: &[u8]) -> Result<TLSECHConfig, TLSError> {
        let mut reader = Reader::new(contents);
        let config_id = reader.read_u8().map_err(|_| TLSError::decode())?;
        let kem_id = reader.read_be().map_err(|_| TLSError::decode())?;
        let public_key = TLSVector::read(&mut reader, 2, 1, 0xFFFF)?.to_vec();
        let mut list = TLSVector::read_reader(&mut reader, 2, 4, 0xFFFC)?;
        let mut cipher_suites = Vec::new();
        while !list.is_empty() {
            cipher_suites.push(TLSECHCipherSuite::decode(&mut list)?);
        }
        let maximum_name_length = reader.read_u8().map_err(|_| TLSError::decode())?;
        let public_name = TLSVector::read(&mut reader, 1, 1, 0xFF)?.to_vec();
        let mut list = TLSVector::read_reader(&mut reader, 2, 0, 0xFFFF)?;
        TLSVector::finish(&reader)?;
        let mut extensions: Vec<TLSECHConfigExtension> = Vec::new();
        while !list.is_empty() {
            let kind = list.read_be().map_err(|_| TLSError::decode())?;
            let data = TLSVector::read(&mut list, 2, 0, 0xFFFF)?.to_vec();
            extensions.push(TLSECHConfigExtension { kind, data });
        }
        if TLSVector::repeats(extensions.iter().map(|extension| extension.kind).collect()) {
            return Err(TLSError::decode());
        }
        Ok(TLSECHConfig { config_id, kem_id, public_key, cipher_suites, maximum_name_length, public_name, extensions })
    }

    /// The `ECHConfig`: version, length and contents.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        out.write_be(TLSECHConfig::VERSION)?;
        TLSVector::write_with(out, 2, 0xFFFF, |contents| {
            contents.write_u8(self.config_id)?;
            contents.write_be(self.kem_id)?;
            TLSVector::write(contents, 2, 0xFFFF, &self.public_key)?;
            TLSVector::write_with(contents, 2, 0xFFFC, |list| {
                self.cipher_suites.iter().try_for_each(|suite| suite.encode(list))
            })?;
            contents.write_u8(self.maximum_name_length)?;
            TLSVector::write(contents, 1, 0xFF, &self.public_name)?;
            TLSVector::write_with(contents, 2, 0xFFFF, |list| {
                for extension in &self.extensions {
                    list.write_be(extension.kind)?;
                    TLSVector::write(list, 2, 0xFFFF, &extension.data)?;
                }
                Ok(())
            })
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, TLSError> {
        let mut out = Buffer::new();
        self.encode(&mut out)?;
        Ok(out.into_vec())
    }

    /// The `info` of HPKE: "tls ech", a zero byte, and the ECHConfig (RFC 9849 §6.1).
    pub fn info(&self) -> Result<Vec<u8>, TLSError> {
        let mut info = b"tls ech\0".to_vec();
        self.encode(&mut info)?;
        Ok(info)
    }

    /// The first cipher suite this crate supports, if the configuration is
    /// one a client may use (RFC 9849 §6.1, §6.1.7, §4.2): a KEM this
    /// crate supports, no mandatory extension (none is known), and a
    /// public name that is a host name and cannot be read as an IPv4 address.
    pub fn usable_suite(&self) -> Option<TLSECHCipherSuite> {
        let usable = TLSECHConfig::supports_kem(self.kem_id)
            && !self.extensions.iter().any(TLSECHConfigExtension::is_mandatory)
            && TLSECHConfig::is_public_name(&self.public_name);
        self.cipher_suites.iter().copied().find(|suite| usable && suite.is_supported())
    }

    /// Whether `name` is a host name in preferred name syntax whose last
    /// label is not all digits nor "0x" and hexadecimal digits (RFC 9849 §6.1.7).
    pub fn is_public_name(name: &[u8]) -> bool {
        let labels: Vec<&[u8]> = name.split(|byte| *byte == b'.').collect();
        let ldh = labels.iter().all(|label| {
            (1..=63).contains(&label.len())
                && label.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
                && label.first() != Some(&b'-')
                && label.last() != Some(&b'-')
        });
        let last = labels.last().copied().unwrap_or(&[]);
        let numeric = last.iter().all(u8::is_ascii_digit)
            || ((last.starts_with(b"0x") || last.starts_with(b"0X")) && last[2..].iter().all(u8::is_ascii_hexdigit));
        ldh && !numeric
    }

    /// Whether this crate implements the KEM `kem_id`.
    pub fn supports_kem(kem_id: u16) -> bool {
        let compiled =
            matches!(kem_id, TLSECHConfig::DHKEM_P256 | TLSECHConfig::DHKEM_P384 | TLSECHConfig::DHKEM_X25519)
                || (kem_id == TLSECHConfig::DHKEM_P521 && cfg!(umilib_feature = "crypto-curve-p521"))
                || (kem_id == TLSECHConfig::DHKEM_X448 && cfg!(umilib_feature = "crypto-curve-curve448"));
        compiled && cfg!(umilib_feature = "crypto-hpke")
    }

    /// The public name as a string.
    pub fn public_name_string(&self) -> String {
        String::from_utf8_lossy(&self.public_name).to_ascii_lowercase()
    }
}

/// The `encrypted_client_hello` extension of a ClientHello (RFC 9849 §5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TLSECHClientHello {
    /// In ClientHelloOuter: the encrypted ClientHelloInner.
    Outer { cipher_suite: TLSECHCipherSuite, config_id: u8, enc: Vec<u8>, payload: Vec<u8> },
    /// In ClientHelloInner: empty.
    Inner,
}

impl TLSECHClientHello {
    pub const OUTER: u8 = 0;
    pub const INNER: u8 = 1;

    /// Fails with `illegal_parameter` for an unknown type (RFC 9849 §7).
    pub fn decode(data: &[u8]) -> Result<TLSECHClientHello, TLSError> {
        let mut reader = Reader::new(data);
        let hello = match reader.read_u8().map_err(|_| TLSError::decode())? {
            TLSECHClientHello::OUTER => {
                let cipher_suite = TLSECHCipherSuite::decode(&mut reader)?;
                let config_id = reader.read_u8().map_err(|_| TLSError::decode())?;
                let enc = TLSVector::read(&mut reader, 2, 0, 0xFFFF)?.to_vec();
                let payload = TLSVector::read(&mut reader, 2, 1, 0xFFFF)?.to_vec();
                TLSECHClientHello::Outer { cipher_suite, config_id, enc, payload }
            }
            TLSECHClientHello::INNER => TLSECHClientHello::Inner,
            _ => return Err(TLSError::illegal()),
        };
        TLSVector::finish(&reader)?;
        Ok(hello)
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        match self {
            TLSECHClientHello::Outer { cipher_suite, config_id, enc, payload } => {
                out.write_u8(TLSECHClientHello::OUTER)?;
                cipher_suite.encode(out)?;
                out.write_u8(*config_id)?;
                TLSVector::write(out, 2, 0xFFFF, enc)?;
                TLSVector::write(out, 2, 0xFFFF, payload)
            }
            TLSECHClientHello::Inner => Ok(out.write_u8(TLSECHClientHello::INNER)?),
        }
    }

    pub fn extension(&self) -> Result<TLSExtension, TLSError> {
        TLSExtension::with(TLSExtensionType::ENCRYPTED_CLIENT_HELLO, |data| self.encode(data))
    }
}

/// Whether a connection used ECH (RFC 9849).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum TLSECHStatus {
    #[default]
    NotOffered,
    /// A GREASE extension was sent: ECH was not offered (RFC 9849 §6.2).
    Grease,
    /// Offered; the server has not answered yet.
    Offered,
    /// The server used the ClientHelloInner.
    Accepted,
    /// The server used the ClientHelloOuter. A client fails with
    /// `ech_required` once the server proved it holds the public name,
    /// with the server's ECHConfigList to retry with, if it sent one
    /// (RFC 9849 §6.1.6).
    Rejected { retry_configs: Option<Vec<u8>> },
}

/// What seals the ClientHelloInners of one connection: an HPKE sender context.
pub trait TLSECHSealer: Send {
    fn seal(&mut self, associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TLSError>;
}

/// What opens the ClientHelloInners of one connection: an HPKE receiver context.
pub trait TLSECHOpener: Send {
    fn open(&mut self, associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, TLSError>;
}

/// The private key of an ECH configuration, which a client-facing server
/// holds (RFC 9849 §7.1). `retry` says whether the configuration is sent
/// to clients whose ECH was rejected (§6.1.6).
#[derive(Clone, Debug)]
pub struct TLSECHKey {
    pub config: TLSECHConfig,
    /// SerializePrivateKey of the KEM (RFC 9180 §7.1.2).
    pub private_key: Secret<Vec<u8>>,
    pub retry: bool,
}

/// A client's offer of ECH: the configuration and suite chosen, the HPKE
/// context, and the ClientHelloOuter, which the handshake continues with
/// if the server rejects ECH (RFC 9849 §6.1).
pub struct TLSECHOffer {
    pub config: TLSECHConfig,
    pub cipher_suite: TLSECHCipherSuite,
    pub sealer: Box<dyn TLSECHSealer>,
    /// The enc of the first ClientHelloOuter; empty in the second (§6.1.5).
    pub enc: Vec<u8>,
    /// The last ClientHelloOuter sent; its `encrypted_client_hello` is last.
    pub outer: TLSClientHello,
    /// The transcript of the ClientHelloOuters.
    pub transcript: TLSTranscript,
    /// Whether a HelloRetryRequest accepted ECH: the ServerHello must too (§6.1.5).
    pub accepted_retry: bool,
}

impl core::fmt::Debug for TLSECHOffer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("TLSECHOffer").field("config", &self.config).finish()
    }
}

/// A server's acceptance of ECH (RFC 9849 §7.1): the HPKE context, which
/// opens the second ClientHelloInner after a HelloRetryRequest (§7.1.1),
/// and what the second ClientHelloOuter must keep.
pub struct TLSECHAcceptance {
    pub opener: Box<dyn TLSECHOpener>,
    pub config_id: u8,
    pub cipher_suite: TLSECHCipherSuite,
}

impl core::fmt::Debug for TLSECHAcceptance {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TLSECHAcceptance")
            .field("config_id", &self.config_id)
            .field("cipher_suite", &self.cipher_suite)
            .finish()
    }
}

impl TLSECHAcceptance {
    /// The second ClientHelloInner of the second ClientHelloOuter `outer`
    /// (RFC 9849 §7.1.1): its `encrypted_client_hello` must be there
    /// (`missing_extension`), with the same suite and configuration and an
    /// empty enc (`illegal_parameter`), and open (`decrypt_error`).
    pub fn open_again(&mut self, outer: &TLSClientHello) -> Result<TLSClientHello, TLSError> {
        let extension = TLSECH::of(outer)?.ok_or(TLSError::Protocol(TLSAlertDescription::MISSING_EXTENSION))?;
        let TLSECHClientHello::Outer { cipher_suite, config_id, enc, payload } = extension else {
            return Err(TLSError::illegal());
        };
        if cipher_suite != self.cipher_suite || config_id != self.config_id || !enc.is_empty() {
            return Err(TLSError::illegal());
        }
        let encoded = self.opener.open(&TLSECH::outer_aad(outer)?, &payload)?;
        let inner = TLSECH::decode_inner(&encoded, outer)?;
        TLSECH::check_inner(&inner)?;
        Ok(inner)
    }
}

/// What ECH does to ClientHellos (RFC 9849 §5, §6.1, §7): the
/// EncodedClientHelloInner, the ClientHelloOuterAAD, and the confirmation
/// of acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TLSECH;

impl TLSECH {
    /// The EncodedClientHelloInner of `inner` (RFC 9849 §5.1): without its
    /// session ID, padded as §6.1.3 recommends (the server name to the
    /// configuration's maximum, then the whole to a multiple of 32).
    pub fn encode_inner(inner: &TLSClientHello, maximum_name_length: u8) -> Result<Vec<u8>, TLSError> {
        let mut hello = inner.clone();
        hello.legacy_session_id = Vec::new();
        let mut encoded = hello.to_bytes()?;
        let maximum = usize::from(maximum_name_length);
        let name = inner
            .extension(TLSExtensionType::SERVER_NAME)
            .map(TLSServerNames::decode)
            .transpose()?
            .and_then(|names| names.host_name().map(<[u8]>::len));
        let padding = match name {
            Some(length) => maximum.saturating_sub(length),
            None => maximum + 9,
        };
        encoded.resize(encoded.len() + padding, 0);
        let rounding = 31 - ((encoded.len() - 1) % 32);
        encoded.resize(encoded.len() + rounding, 0);
        Ok(encoded)
    }

    /// The ClientHelloInner of `encoded`, an EncodedClientHelloInner, with
    /// `outer`'s session ID and the extensions `ech_outer_extensions`
    /// refers to (RFC 9849 §5.1, Appendix A, in linear time). Fails with
    /// `illegal_parameter` for padding that is not zeros, a reference to an
    /// extension that `outer` lacks, repeats or puts out of order, or to
    /// `encrypted_client_hello`.
    pub fn decode_inner(encoded: &[u8], outer: &TLSClientHello) -> Result<TLSClientHello, TLSError> {
        let mut reader = Reader::new(encoded);
        let mut hello = TLSClientHello::read(&mut reader, false)?;
        if reader.read_rest().iter().any(|byte| *byte != 0) {
            return Err(TLSError::illegal());
        }
        let Some(position) =
            hello.extensions.iter().position(|extension| extension.kind == TLSExtensionType::ECH_OUTER_EXTENSIONS)
        else {
            hello.legacy_session_id = outer.legacy_session_id.clone();
            return TLSClientHello::decode(&hello.to_bytes()?);
        };
        let mut list = Reader::new(&hello.extensions[position].data);
        let kinds = TLSVector::read_u16s(&mut list, 1, 2, 0xFE)?;
        TLSVector::finish(&list)?;
        let mut cursor = outer.extensions.iter();
        let mut copied = Vec::with_capacity(kinds.len());
        for kind in kinds {
            if kind == TLSExtensionType::ENCRYPTED_CLIENT_HELLO.0 {
                return Err(TLSError::illegal());
            }
            let found = cursor.find(|extension| extension.kind.0 == kind).ok_or(TLSError::illegal())?;
            copied.push(found.clone());
        }
        hello.extensions.splice(position..=position, copied);
        hello.legacy_session_id = outer.legacy_session_id.clone();
        // Decoding again checks that no extension appears twice.
        TLSClientHello::decode(&hello.to_bytes()?)
    }

    /// The ClientHelloOuterAAD of `outer` (RFC 9849 §5.2): the ClientHello
    /// with the payload of its `encrypted_client_hello` replaced by zeros.
    pub fn outer_aad(outer: &TLSClientHello) -> Result<Vec<u8>, TLSError> {
        let mut aad = outer.clone();
        for extension in &mut aad.extensions {
            if extension.kind != TLSExtensionType::ENCRYPTED_CLIENT_HELLO {
                continue;
            }
            if let TLSECHClientHello::Outer { cipher_suite, config_id, enc, payload } =
                TLSECHClientHello::decode(&extension.data)?
            {
                let zeros = TLSECHClientHello::Outer { cipher_suite, config_id, enc, payload: vec![0; payload.len()] };
                *extension = zeros.extension()?;
            }
        }
        aad.to_bytes()
    }

    /// The `encrypted_client_hello` of a ClientHello, if any.
    pub fn of(hello: &TLSClientHello) -> Result<Option<TLSECHClientHello>, TLSError> {
        hello.extension(TLSExtensionType::ENCRYPTED_CLIENT_HELLO).map(TLSECHClientHello::decode).transpose()
    }

    /// Checks an `encrypted_client_hello` in EncryptedExtensions: a valid
    /// ECHConfigList (`decode_error` otherwise, RFC 9849 §6.1.6, §6.2.1).
    pub fn check_retry_configs(data: &[u8]) -> Result<(), TLSError> {
        TLSECHConfig::decode_list(data).map(|_| ())
    }

    /// The extension of retry configurations in EncryptedExtensions (RFC
    /// 9849 §7.1), of the keys marked `retry`; `None` without such keys.
    pub fn retry_extension(keys: &[TLSECHKey]) -> Result<Option<TLSExtension>, TLSError> {
        let configs: Vec<TLSECHConfig> = keys.iter().filter(|key| key.retry).map(|key| key.config.clone()).collect();
        if configs.is_empty() {
            return Ok(None);
        }
        TLSExtension::with(TLSExtensionType::ENCRYPTED_CLIENT_HELLO, |data| TLSECHConfig::encode_list(&configs, data))
            .map(Some)
    }

    /// Checks the type of ECH a ClientHelloInner must carry, and that it
    /// offers only TLS 1.3 or later (RFC 9849 §7.1: `illegal_parameter`).
    pub fn check_inner(inner: &TLSClientHello) -> Result<(), TLSError> {
        use super::{TLSSupportedVersions, TLSVersion};
        if TLSECH::of(inner)? != Some(TLSECHClientHello::Inner) {
            return Err(TLSError::illegal());
        }
        TLSExtension::check(&inner.extensions, TLSExtensionContext::ClientHello)?;
        let versions = inner.extension(TLSExtensionType::SUPPORTED_VERSIONS).ok_or(TLSError::illegal())?;
        let TLSSupportedVersions::Offered(versions) =
            TLSSupportedVersions::decode(versions, TLSExtensionContext::ClientHello)?
        else {
            return Err(TLSError::decode());
        };
        let old = versions.iter().any(|version| *version <= TLSVersion::TLS1_2 && !version.is_grease());
        if old { Err(TLSError::illegal()) } else { Ok(()) }
    }

    /// A GREASE `encrypted_client_hello` (RFC 9849 §6.2.1): a random
    /// config_id, the mandatory suite, the enc of a fresh X25519 key, and a
    /// random payload as long as one of `inner_length` bytes would be.
    pub fn grease<R: Random>(inner_length: usize, random: &mut R) -> Result<TLSExtension, TLSError> {
        let internal = |_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR);
        let mut config_id = [0u8; 1];
        random.fill(&mut config_id).map_err(internal)?;
        let (_, enc) = super::TLSKeyShareSecret::generate(super::TLSNamedGroup::X25519, random)?;
        let suite = TLSECHCipherSuite::MANDATORY;
        let length = inner_length + 31 - ((inner_length.max(1) - 1) % 32) + suite.tag_length();
        let mut payload = vec![0u8; length];
        random.fill(&mut payload).map_err(internal)?;
        TLSECHClientHello::Outer { cipher_suite: suite, config_id: config_id[0], enc, payload }.extension()
    }
}

#[cfg(umilib_feature = "protocol-tls-v1_3")]
impl TLSECH {
    pub const ACCEPT_LABEL: &'static [u8] = b"ech accept confirmation";
    pub const RETRY_LABEL: &'static [u8] = b"hrr ech accept confirmation";

    /// The confirmation of acceptance (RFC 9849 §7.2, §7.2.1):
    /// HKDF-Expand-Label(HKDF-Extract(0, ClientHelloInner.random), `label`,
    /// `transcript_hash`, 8) with the hash of the cipher suite.
    pub fn confirmation(
        hash: super::TLSHashAlgorithm,
        inner_random: &[u8; 32],
        label: &[u8],
        transcript_hash: &[u8],
    ) -> Result<[u8; 8], TLSError> {
        let schedule = super::v1_3::TLS13KeySchedule::new(hash);
        let secret = schedule.extract(&[], inner_random);
        let expanded = schedule.expand_label(secret.expose(), label, transcript_hash, 8)?;
        let mut confirmation = [0u8; 8];
        confirmation.copy_from_slice(expanded.expose());
        Ok(confirmation)
    }

    /// The confirmation a ServerHello `message` (header included) carries
    /// in its random's last 8 bytes, after the messages of `transcript`
    /// (RFC 9849 §7.2): computed with those bytes zero.
    pub fn server_hello_confirmation(
        transcript: &TLSTranscript,
        hash: super::TLSHashAlgorithm,
        inner_random: &[u8; 32],
        message: &[u8],
    ) -> Result<[u8; 8], TLSError> {
        // The random follows the header (4) and legacy_version (2).
        let mut zeroed = message.to_vec();
        zeroed.get_mut(30..38).ok_or(TLSError::decode())?.fill(0);
        let mut transcript = transcript.clone();
        transcript.select(hash);
        transcript.update(&zeroed);
        TLSECH::confirmation(hash, inner_random, TLSECH::ACCEPT_LABEL, &transcript.hash())
    }

    /// The confirmation of a HelloRetryRequest (RFC 9849 §7.2.1), whose
    /// `encrypted_client_hello` holds 8 bytes: over ClientHelloInner1's
    /// `message_hash` (the transcript `transcript` of it, restarted) and
    /// the HelloRetryRequest `retry` with those bytes zero.
    pub fn retry_confirmation(
        transcript: &TLSTranscript,
        hash: super::TLSHashAlgorithm,
        inner_random: &[u8; 32],
        retry: &super::TLSServerHello,
    ) -> Result<[u8; 8], TLSError> {
        let mut zeroed = retry.clone();
        for extension in &mut zeroed.extensions {
            if extension.kind == TLSExtensionType::ENCRYPTED_CLIENT_HELLO {
                extension.data = vec![0; 8];
            }
        }
        let message = super::TLSHandshake::new(super::TLSHandshakeType::SERVER_HELLO, zeroed.to_bytes()?).to_bytes()?;
        let mut transcript = transcript.clone();
        transcript.restart_after_retry(hash);
        transcript.update(&message);
        TLSECH::confirmation(hash, inner_random, TLSECH::RETRY_LABEL, &transcript.hash())
    }
}

/// HPKE for ECH, chosen at run time by the identifiers of RFC 9180 §7.
#[cfg(umilib_feature = "crypto-hpke")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TLSECHCipher;

#[cfg(umilib_feature = "crypto-hpke")]
impl<F: crate::crypto::hpke::HPKEKDF, A: crate::crypto::hpke::HPKEAEAD> TLSECHSealer
    for crate::crypto::hpke::HPKESenderContext<F, A>
where
    crate::crypto::hpke::HPKESenderContext<F, A>: Send,
{
    fn seal(&mut self, associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TLSError> {
        crate::crypto::hpke::HPKESenderContext::seal(self, associated, plaintext)
            .map_err(|_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR))
    }
}

#[cfg(umilib_feature = "crypto-hpke")]
impl<F: crate::crypto::hpke::HPKEKDF, A: crate::crypto::hpke::HPKEAEAD> TLSECHOpener
    for crate::crypto::hpke::HPKEReceiverContext<F, A>
where
    crate::crypto::hpke::HPKEReceiverContext<F, A>: Send,
{
    fn open(&mut self, associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, TLSError> {
        crate::crypto::hpke::HPKEReceiverContext::open(self, associated, ciphertext)
            .map_err(|_| TLSError::Protocol(TLSAlertDescription::DECRYPT_ERROR))
    }
}

/// Calls `$body` with the KEM type `$kem` of `$kem_id`, or evaluates `$none`.
#[cfg(umilib_feature = "crypto-hpke")]
macro_rules! ech_kem {
    ($kem_id:expr, $none:expr, |$kem:ident| $body:expr) => {{
        match $kem_id {
            #[cfg(umilib_feature = "crypto-curve-p256")]
            TLSECHConfig::DHKEM_P256 => {
                type $kem = crate::crypto::hpke::DHKEM<
                    crate::crypto::ecdh::ECDH<crate::crypto::curve::p256::P256>,
                    crate::hash::sha::v2::SHA256,
                >;
                $body
            }
            #[cfg(umilib_feature = "crypto-curve-p384")]
            TLSECHConfig::DHKEM_P384 => {
                type $kem = crate::crypto::hpke::DHKEM<
                    crate::crypto::ecdh::ECDH<crate::crypto::curve::p384::P384>,
                    crate::hash::sha::v2::SHA384,
                >;
                $body
            }
            #[cfg(umilib_feature = "crypto-curve-p521")]
            TLSECHConfig::DHKEM_P521 => {
                type $kem = crate::crypto::hpke::DHKEM<
                    crate::crypto::ecdh::ECDH<crate::crypto::curve::p521::P521>,
                    crate::hash::sha::v2::SHA512,
                >;
                $body
            }
            #[cfg(umilib_feature = "crypto-curve-curve25519")]
            TLSECHConfig::DHKEM_X25519 => {
                type $kem = crate::crypto::hpke::DHKEM<crate::crypto::ecdh::X25519, crate::hash::sha::v2::SHA256>;
                $body
            }
            #[cfg(umilib_feature = "crypto-curve-curve448")]
            TLSECHConfig::DHKEM_X448 => {
                type $kem = crate::crypto::hpke::DHKEM<crate::crypto::ecdh::X448, crate::hash::sha::v2::SHA512>;
                $body
            }
            _ => $none,
        }
    }};
}

/// Calls `$body` with the AEAD type `$aead` of `$aead_id`, or evaluates `$none`.
#[cfg(umilib_feature = "crypto-hpke")]
macro_rules! ech_aead {
    ($aead_id:expr, $none:expr, |$aead:ident| $body:expr) => {{
        match $aead_id {
            TLSECHCipherSuite::AES_128_GCM => {
                type $aead = crate::crypto::mode::gcm::GCM<crate::crypto::aes::AES128, 16>;
                $body
            }
            TLSECHCipherSuite::AES_256_GCM => {
                type $aead = crate::crypto::mode::gcm::GCM<crate::crypto::aes::AES256, 16>;
                $body
            }
            TLSECHCipherSuite::CHACHA20_POLY1305 => {
                type $aead = crate::crypto::chacha20poly1305::ChaCha20Poly1305;
                $body
            }
            _ => $none,
        }
    }};
}

/// Calls `$body` with the KDF type `$kdf` and the AEAD type `$aead` of
/// `$suite`, or evaluates `$none`.
#[cfg(umilib_feature = "crypto-hpke")]
macro_rules! ech_suite {
    ($suite:expr, $none:expr, |$kdf:ident, $aead:ident| $body:expr) => {{
        match $suite.kdf_id {
            TLSECHCipherSuite::HKDF_SHA256 => {
                type $kdf = crate::hash::sha::v2::SHA256;
                ech_aead!($suite.aead_id, $none, |$aead| $body)
            }
            TLSECHCipherSuite::HKDF_SHA384 => {
                type $kdf = crate::hash::sha::v2::SHA384;
                ech_aead!($suite.aead_id, $none, |$aead| $body)
            }
            TLSECHCipherSuite::HKDF_SHA512 => {
                type $kdf = crate::hash::sha::v2::SHA512;
                ech_aead!($suite.aead_id, $none, |$aead| $body)
            }
            _ => $none,
        }
    }};
}

#[cfg(umilib_feature = "crypto-hpke")]
impl TLSECHCipher {
    /// SetupBaseS for `config` with `suite` (RFC 9849 §6.1): enc and the sealer.
    pub fn setup_sender<R: Random>(
        config: &TLSECHConfig,
        suite: TLSECHCipherSuite,
        random: &mut R,
    ) -> Result<(Vec<u8>, Box<dyn TLSECHSealer>), TLSError> {
        use crate::crypto::hpke::{HPKE, HPKEKEM};
        let unsupported = TLSError::Config;
        let info = config.info()?;
        ech_kem!(config.kem_id, Err(unsupported), |K| {
            let public = K::deserialize_public_key(&config.public_key).map_err(|_| TLSError::Config)?;
            ech_suite!(suite, Err(unsupported), |F, A| {
                let (enc, context) = HPKE::<K, F, A>::setup_sender(&public, &info, None, None, random)
                    .map_err(|_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR))?;
                Ok((enc, Box::new(context) as Box<dyn TLSECHSealer>))
            })
        })
    }

    /// SetupBaseR with `key` for `enc` and `suite` (RFC 9849 §7.1); fails
    /// with `decrypt_error` when it cannot.
    pub fn setup_receiver(
        key: &TLSECHKey,
        suite: TLSECHCipherSuite,
        enc: &[u8],
    ) -> Result<Box<dyn TLSECHOpener>, TLSError> {
        use crate::crypto::hpke::{HPKE, HPKEKEM};
        let failure = TLSError::Protocol(TLSAlertDescription::DECRYPT_ERROR);
        let info = key.config.info()?;
        ech_kem!(key.config.kem_id, Err(failure), |K| {
            let private = K::deserialize_private_key(key.private_key.expose()).map_err(|_| failure)?;
            ech_suite!(suite, Err(failure), |F, A| {
                let context = HPKE::<K, F, A>::setup_receiver(enc, &private, &info, None, None).map_err(|_| failure)?;
                Ok(Box::new(context) as Box<dyn TLSECHOpener>)
            })
        })
    }

    /// A new key of `config`'s KEM (`public_key` is replaced) for a server.
    pub fn generate<R: Random>(mut config: TLSECHConfig, retry: bool, random: &mut R) -> Result<TLSECHKey, TLSError> {
        use crate::crypto::hpke::HPKEKEM;
        ech_kem!(config.kem_id, Err(TLSError::Config), |K| {
            let (private, public) = K::generate_key_pair(random).map_err(|_| TLSError::Config)?;
            config.public_key = K::serialize_public_key(&public);
            Ok(TLSECHKey { config, private_key: Secret::new(K::serialize_private_key(&private)), retry })
        })
    }
}

#[cfg(umilib_feature = "crypto-hpke")]
impl TLSECH {
    /// What a client-facing server makes of a first ClientHello (RFC 9849
    /// §7, §7.1): without `encrypted_client_hello`, nothing; with one of
    /// type inner, `illegal_parameter`; with one of type outer, the
    /// ClientHelloInner that a key of the configuration it names opens,
    /// checked, or nothing if none opens it (the session then says ECH was
    /// rejected).
    pub fn accept(
        keys: &[TLSECHKey],
        outer: &TLSClientHello,
        status: &mut TLSECHStatus,
    ) -> Result<Option<(TLSClientHello, TLSECHAcceptance)>, TLSError> {
        let Some(extension) = TLSECH::of(outer)? else { return Ok(None) };
        let TLSECHClientHello::Outer { cipher_suite, config_id, enc, payload } = extension else {
            return Err(TLSError::illegal());
        };
        *status = TLSECHStatus::Rejected { retry_configs: None };
        let aad = TLSECH::outer_aad(outer)?;
        let candidates = keys
            .iter()
            .filter(|key| key.config.config_id == config_id && key.config.cipher_suites.contains(&cipher_suite));
        for key in candidates {
            let Ok(mut opener) = TLSECHCipher::setup_receiver(key, cipher_suite, &enc) else { continue };
            let Ok(encoded) = opener.open(&aad, &payload) else { continue };
            let inner = TLSECH::decode_inner(&encoded, outer)?;
            TLSECH::check_inner(&inner)?;
            *status = TLSECHStatus::Accepted;
            return Ok(Some((inner, TLSECHAcceptance { opener, config_id, cipher_suite })));
        }
        Ok(None)
    }
}
