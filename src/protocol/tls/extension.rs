use alloc::vec::Vec;

use crate::bytes::{Buffer, Reader, Writer};

use super::{TLSError, TLSNamedGroup, TLSRecordHeader, TLSSignatureScheme, TLSVector, TLSVersion};

/// The type of an extension: `ExtensionType` (RFC 9846 §4.3 and the IANA
/// "TLS ExtensionType Values" registry). Unknown values are kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TLSExtensionType(pub u16);

impl TLSExtensionType {
    pub const SERVER_NAME: TLSExtensionType = TLSExtensionType(0);
    pub const STATUS_REQUEST: TLSExtensionType = TLSExtensionType(5);
    pub const SUPPORTED_GROUPS: TLSExtensionType = TLSExtensionType(10);
    /// TLS 1.2 (RFC 8422 §5.1.2).
    pub const EC_POINT_FORMATS: TLSExtensionType = TLSExtensionType(11);
    pub const SIGNATURE_ALGORITHMS: TLSExtensionType = TLSExtensionType(13);
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: TLSExtensionType = TLSExtensionType(16);
    pub const PADDING: TLSExtensionType = TLSExtensionType(21);
    /// TLS 1.2: "extended_main_secret" (RFC 7627, RFC 9846 Appendix D).
    pub const EXTENDED_MAIN_SECRET: TLSExtensionType = TLSExtensionType(23);
    pub const RECORD_SIZE_LIMIT: TLSExtensionType = TLSExtensionType(28);
    /// TLS 1.2 session tickets (RFC 5077): recognized, never offered.
    pub const SESSION_TICKET: TLSExtensionType = TLSExtensionType(35);
    pub const PRE_SHARED_KEY: TLSExtensionType = TLSExtensionType(41);
    pub const EARLY_DATA: TLSExtensionType = TLSExtensionType(42);
    pub const SUPPORTED_VERSIONS: TLSExtensionType = TLSExtensionType(43);
    pub const COOKIE: TLSExtensionType = TLSExtensionType(44);
    pub const PSK_KEY_EXCHANGE_MODES: TLSExtensionType = TLSExtensionType(45);
    pub const CERTIFICATE_AUTHORITIES: TLSExtensionType = TLSExtensionType(47);
    pub const OID_FILTERS: TLSExtensionType = TLSExtensionType(48);
    pub const POST_HANDSHAKE_AUTH: TLSExtensionType = TLSExtensionType(49);
    pub const SIGNATURE_ALGORITHMS_CERT: TLSExtensionType = TLSExtensionType(50);
    pub const KEY_SHARE: TLSExtensionType = TLSExtensionType(51);
    /// QUIC's transport parameters (RFC 9001 §8.2).
    pub const QUIC_TRANSPORT_PARAMETERS: TLSExtensionType = TLSExtensionType(57);
    pub const ECH_OUTER_EXTENSIONS: TLSExtensionType = TLSExtensionType(0xFD00);
    pub const ENCRYPTED_CLIENT_HELLO: TLSExtensionType = TLSExtensionType(0xFE0D);
    /// TLS 1.2 (RFC 5746).
    pub const RENEGOTIATION_INFO: TLSExtensionType = TLSExtensionType(0xFF01);

    /// The messages of TLS 1.3 that may carry the extension (RFC 9846 §4.3,
    /// Table 1), or `None` for an extension this crate does not recognize,
    /// which the receiver ignores.
    pub fn contexts(self) -> Option<&'static [TLSExtensionContext]> {
        use TLSExtensionContext::{
            Certificate as CT, CertificateRequest as CR, ClientHello as CH, EncryptedExtensions as EE,
            HelloRetryRequest as HRR, NewSessionTicket as NST, ServerHello as SH,
        };
        Some(match self {
            TLSExtensionType::SERVER_NAME => &[CH, EE, CR],
            TLSExtensionType::STATUS_REQUEST => &[CH, CR, CT],
            TLSExtensionType::SUPPORTED_GROUPS => &[CH, EE],
            TLSExtensionType::SIGNATURE_ALGORITHMS => &[CH, CR],
            TLSExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => &[CH, EE],
            TLSExtensionType::PADDING => &[CH],
            TLSExtensionType::RECORD_SIZE_LIMIT => &[CH, EE],
            TLSExtensionType::PRE_SHARED_KEY => &[CH, SH],
            TLSExtensionType::EARLY_DATA => &[CH, EE, NST],
            TLSExtensionType::SUPPORTED_VERSIONS => &[CH, SH, HRR],
            TLSExtensionType::COOKIE => &[CH, HRR],
            TLSExtensionType::PSK_KEY_EXCHANGE_MODES => &[CH],
            TLSExtensionType::CERTIFICATE_AUTHORITIES => &[CH, CR],
            TLSExtensionType::OID_FILTERS => &[CR],
            TLSExtensionType::POST_HANDSHAKE_AUTH => &[CH],
            TLSExtensionType::SIGNATURE_ALGORITHMS_CERT => &[CH, CR],
            TLSExtensionType::KEY_SHARE => &[CH, SH, HRR],
            TLSExtensionType::QUIC_TRANSPORT_PARAMETERS => &[CH, EE],
            TLSExtensionType::ECH_OUTER_EXTENSIONS => &[CH],
            TLSExtensionType::ENCRYPTED_CLIENT_HELLO => &[CH, HRR, EE],
            // TLS 1.2 only: allowed in the ClientHello, and nowhere in TLS 1.3.
            TLSExtensionType::EC_POINT_FORMATS
            | TLSExtensionType::EXTENDED_MAIN_SECRET
            | TLSExtensionType::SESSION_TICKET
            | TLSExtensionType::RENEGOTIATION_INFO => &[CH],
            _ => return None,
        })
    }

    /// Whether the value is a GREASE value (RFC 8701 §2).
    pub fn is_grease(self) -> bool {
        TLSVersion::grease(self.0)
    }
}

/// The message an extension block belongs to, which decides which
/// extensions it may hold and how some are read (RFC 9846 §4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLSExtensionContext {
    ClientHello,
    ServerHello,
    HelloRetryRequest,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    NewSessionTicket,
}

/// An extension as it was sent: its type and its bytes (RFC 9846 §4.3).
/// Typed values are read from `data` with the types of this module, so
/// that unknown extensions are kept byte for byte.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLSExtension {
    pub kind: TLSExtensionType,
    pub data: Vec<u8>,
}

impl TLSExtension {
    pub fn new(kind: TLSExtensionType, data: Vec<u8>) -> TLSExtension {
        TLSExtension { kind, data }
    }

    /// An extension of `kind` whose data `write` writes.
    pub fn with(
        kind: TLSExtensionType,
        write: impl FnOnce(&mut Buffer) -> Result<(), TLSError>,
    ) -> Result<TLSExtension, TLSError> {
        let mut data = Buffer::new();
        write(&mut data)?;
        Ok(TLSExtension { kind, data: data.into_vec() })
    }

    /// Reads an extension block `<minimum..2^16-1>`, refusing two extensions
    /// of one type with `illegal_parameter` (RFC 9846 §4.3).
    pub fn decode_list(reader: &mut Reader<'_>, minimum: usize) -> Result<Vec<TLSExtension>, TLSError> {
        let mut block = TLSVector::read_reader(reader, 2, minimum, 0xFFFF)?;
        let mut extensions: Vec<TLSExtension> = Vec::new();
        while !block.is_empty() {
            let kind = TLSExtensionType(block.read_be().map_err(|_| TLSError::decode())?);
            let data = TLSVector::read(&mut block, 2, 0, 0xFFFF)?;
            extensions.push(TLSExtension { kind, data: data.to_vec() });
        }
        if TLSVector::repeats(extensions.iter().map(|extension| extension.kind.0).collect()) {
            return Err(TLSError::illegal());
        }
        Ok(extensions)
    }

    pub fn encode_list(extensions: &[TLSExtension], out: &mut impl Writer) -> Result<(), TLSError> {
        TLSVector::write_with(out, 2, 0xFFFF, |block| {
            for extension in extensions {
                block.write_be(extension.kind.0)?;
                TLSVector::write(block, 2, 0xFFFF, &extension.data)?;
            }
            Ok(())
        })
    }

    /// The data of the extension of `kind` in `extensions`, if any.
    pub fn find(extensions: &[TLSExtension], kind: TLSExtensionType) -> Option<&[u8]> {
        extensions.iter().find(|extension| extension.kind == kind).map(|extension| extension.data.as_slice())
    }

    /// Checks the TLS 1.3 rules of an extension block of `context` (RFC 9846
    /// §4.3): every recognized extension must be allowed there
    /// (`illegal_parameter`), and `pre_shared_key` must come last in a
    /// ClientHello (`illegal_parameter`).
    pub fn check(extensions: &[TLSExtension], context: TLSExtensionContext) -> Result<(), TLSError> {
        for (index, extension) in extensions.iter().enumerate() {
            if extension.kind.contexts().is_some_and(|contexts| !contexts.contains(&context)) {
                return Err(TLSError::illegal());
            }
            if context == TLSExtensionContext::ClientHello
                && extension.kind == TLSExtensionType::PRE_SHARED_KEY
                && index + 1 != extensions.len()
            {
                return Err(TLSError::illegal());
            }
        }
        Ok(())
    }
}

/// The host names of `server_name` (RFC 6066 §3): a list of names, at
/// most one of each type, of which only `host_name` (0) is defined. In the
/// server's answer the extension is empty.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TLSServerNames {
    /// The host names (ASCII, without a trailing dot, never an address).
    pub host_names: Vec<Vec<u8>>,
}

impl TLSServerNames {
    pub const HOST_NAME: u8 = 0;

    pub fn decode(data: &[u8]) -> Result<TLSServerNames, TLSError> {
        let mut reader = Reader::new(data);
        let mut list = TLSVector::read_reader(&mut reader, 2, 1, 0xFFFF)?;
        TLSVector::finish(&reader)?;
        let mut host_names = Vec::new();
        while !list.is_empty() {
            let kind = list.read_u8().map_err(|_| TLSError::decode())?;
            if kind != TLSServerNames::HOST_NAME {
                return Err(TLSError::decode());
            }
            host_names.push(TLSVector::read(&mut list, 2, 1, 0xFFFF)?.to_vec());
        }
        // At most one name of each type (RFC 6066 §3).
        if host_names.len() > 1 {
            return Err(TLSError::illegal());
        }
        Ok(TLSServerNames { host_names })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        TLSVector::write_with(out, 2, 0xFFFF, |list| {
            for name in &self.host_names {
                list.write_u8(TLSServerNames::HOST_NAME)?;
                TLSVector::write(list, 2, 0xFFFF, name)?;
            }
            Ok(())
        })
    }

    /// The host name, if one was sent.
    pub fn host_name(&self) -> Option<&[u8]> {
        self.host_names.first().map(Vec::as_slice)
    }
}

/// `supported_groups`: `NamedGroupList` (RFC 9846 §4.3.7).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TLSSupportedGroups {
    pub groups: Vec<TLSNamedGroup>,
}

impl TLSSupportedGroups {
    pub fn decode(data: &[u8]) -> Result<TLSSupportedGroups, TLSError> {
        let mut reader = Reader::new(data);
        let groups = TLSVector::read_u16s(&mut reader, 2, 2, 0xFFFF)?.into_iter().map(TLSNamedGroup).collect();
        TLSVector::finish(&reader)?;
        Ok(TLSSupportedGroups { groups })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        let values: Vec<u16> = self.groups.iter().map(|group| group.0).collect();
        TLSVector::write_u16s(out, 2, 0xFFFF, &values)
    }
}

/// `ec_point_formats`: `ECPointFormatList` (RFC 8422 §5.1.2), which must
/// list the uncompressed format; TLS 1.2 only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TLSPointFormats {
    pub formats: Vec<u8>,
}

impl TLSPointFormats {
    pub const UNCOMPRESSED: u8 = 0;

    /// Fails with `illegal_parameter` if the list lacks the uncompressed format.
    pub fn decode(data: &[u8]) -> Result<TLSPointFormats, TLSError> {
        let mut reader = Reader::new(data);
        let formats = TLSVector::read(&mut reader, 1, 1, 0xFF)?.to_vec();
        TLSVector::finish(&reader)?;
        if !formats.contains(&TLSPointFormats::UNCOMPRESSED) {
            return Err(TLSError::illegal());
        }
        Ok(TLSPointFormats { formats })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        TLSVector::write(out, 1, 0xFF, &self.formats)
    }
}

/// `signature_algorithms` and `signature_algorithms_cert`:
/// `SignatureSchemeList` (RFC 9846 §4.3.3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TLSSignatureSchemes {
    pub schemes: Vec<TLSSignatureScheme>,
}

impl TLSSignatureSchemes {
    pub fn decode(data: &[u8]) -> Result<TLSSignatureSchemes, TLSError> {
        let mut reader = Reader::new(data);
        let schemes = TLSVector::read_u16s(&mut reader, 2, 2, 0xFFFE)?.into_iter().map(TLSSignatureScheme).collect();
        TLSVector::finish(&reader)?;
        Ok(TLSSignatureSchemes { schemes })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        let values: Vec<u16> = self.schemes.iter().map(|scheme| scheme.0).collect();
        TLSVector::write_u16s(out, 2, 0xFFFE, &values)
    }
}

/// `application_layer_protocol_negotiation`: `ProtocolNameList` (RFC 7301
/// §3.1). The server's answer holds exactly one name.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TLSProtocolNames {
    pub names: Vec<Vec<u8>>,
}

impl TLSProtocolNames {
    pub fn decode(data: &[u8]) -> Result<TLSProtocolNames, TLSError> {
        let mut reader = Reader::new(data);
        let mut list = TLSVector::read_reader(&mut reader, 2, 2, 0xFFFF)?;
        TLSVector::finish(&reader)?;
        let mut names = Vec::new();
        while !list.is_empty() {
            names.push(TLSVector::read(&mut list, 1, 1, 0xFF)?.to_vec());
        }
        Ok(TLSProtocolNames { names })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        TLSVector::write_with(out, 2, 0xFFFF, |list| {
            for name in &self.names {
                TLSVector::write(list, 1, 0xFF, name)?;
            }
            Ok(())
        })
    }

    /// The single name of a server's answer; fails with `decode_error`
    /// otherwise (RFC 7301 §3.1).
    pub fn selected(&self) -> Result<&[u8], TLSError> {
        match self.names.as_slice() {
            [name] => Ok(name),
            _ => Err(TLSError::decode()),
        }
    }
}

/// `supported_versions` (RFC 9846 §4.3.1): the client's list, or the
/// server's single version.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TLSSupportedVersions {
    Offered(Vec<TLSVersion>),
    Selected(TLSVersion),
}

impl TLSSupportedVersions {
    pub fn decode(data: &[u8], context: TLSExtensionContext) -> Result<TLSSupportedVersions, TLSError> {
        let mut reader = Reader::new(data);
        let versions = if context == TLSExtensionContext::ClientHello {
            TLSSupportedVersions::Offered(
                TLSVector::read_u16s(&mut reader, 1, 2, 254)?.into_iter().map(TLSVersion).collect(),
            )
        } else {
            TLSSupportedVersions::Selected(TLSVersion(reader.read_be().map_err(|_| TLSError::decode())?))
        };
        TLSVector::finish(&reader)?;
        Ok(versions)
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        match self {
            TLSSupportedVersions::Offered(versions) => {
                let values: Vec<u16> = versions.iter().map(|version| version.0).collect();
                TLSVector::write_u16s(out, 1, 254, &values)
            }
            TLSSupportedVersions::Selected(version) => Ok(out.write_be(version.0)?),
        }
    }
}

/// One share of `key_share`: `KeyShareEntry` (RFC 9846 §4.3.8).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLSKeyShareEntry {
    pub group: TLSNamedGroup,
    pub key_exchange: Vec<u8>,
}

impl TLSKeyShareEntry {
    pub fn decode(reader: &mut Reader<'_>) -> Result<TLSKeyShareEntry, TLSError> {
        let group = TLSNamedGroup(reader.read_be().map_err(|_| TLSError::decode())?);
        let key_exchange = TLSVector::read(reader, 2, 1, 0xFFFF)?.to_vec();
        Ok(TLSKeyShareEntry { group, key_exchange })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        out.write_be(self.group.0)?;
        TLSVector::write(out, 2, 0xFFFF, &self.key_exchange)
    }
}

/// `key_share` (RFC 9846 §4.3.8): the client's shares, the server's
/// share, or the group a HelloRetryRequest asks for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TLSKeyShare {
    /// At most one share per group (`illegal_parameter` otherwise).
    Client(Vec<TLSKeyShareEntry>),
    Server(TLSKeyShareEntry),
    Retry(TLSNamedGroup),
}

impl TLSKeyShare {
    pub fn decode(data: &[u8], context: TLSExtensionContext) -> Result<TLSKeyShare, TLSError> {
        let mut reader = Reader::new(data);
        let share = match context {
            TLSExtensionContext::ClientHello => {
                let mut list = TLSVector::read_reader(&mut reader, 2, 0, 0xFFFF)?;
                let mut entries: Vec<TLSKeyShareEntry> = Vec::new();
                while !list.is_empty() {
                    entries.push(TLSKeyShareEntry::decode(&mut list)?);
                }
                if TLSVector::repeats(entries.iter().map(|entry| entry.group.0).collect()) {
                    return Err(TLSError::illegal());
                }
                TLSKeyShare::Client(entries)
            }
            TLSExtensionContext::HelloRetryRequest => {
                TLSKeyShare::Retry(TLSNamedGroup(reader.read_be().map_err(|_| TLSError::decode())?))
            }
            _ => TLSKeyShare::Server(TLSKeyShareEntry::decode(&mut reader)?),
        };
        TLSVector::finish(&reader)?;
        Ok(share)
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        match self {
            TLSKeyShare::Client(entries) => {
                TLSVector::write_with(out, 2, 0xFFFF, |list| entries.iter().try_for_each(|entry| entry.encode(list)))
            }
            TLSKeyShare::Server(entry) => entry.encode(out),
            TLSKeyShare::Retry(group) => Ok(out.write_be(group.0)?),
        }
    }
}

/// A key exchange mode of PSKs: `PskKeyExchangeMode` (RFC 9846 §4.3.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TLSPSKMode(pub u8);

impl TLSPSKMode {
    /// PSK only: no forward secrecy.
    pub const PSK_KE: TLSPSKMode = TLSPSKMode(0);
    /// PSK with (EC)DHE.
    pub const PSK_DHE_KE: TLSPSKMode = TLSPSKMode(1);

    /// `psk_key_exchange_modes`: `ke_modes<1..255>`.
    pub fn decode_list(data: &[u8]) -> Result<Vec<TLSPSKMode>, TLSError> {
        let mut reader = Reader::new(data);
        let modes = TLSVector::read(&mut reader, 1, 1, 0xFF)?.iter().copied().map(TLSPSKMode).collect();
        TLSVector::finish(&reader)?;
        Ok(modes)
    }

    pub fn encode_list(modes: &[TLSPSKMode], out: &mut impl Writer) -> Result<(), TLSError> {
        let bytes: Vec<u8> = modes.iter().map(|mode| mode.0).collect();
        TLSVector::write(out, 1, 0xFF, &bytes)
    }
}

/// One identity of `pre_shared_key`: `PskIdentity` (RFC 9846 §4.3.11).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLSPSKIdentity {
    pub identity: Vec<u8>,
    pub obfuscated_ticket_age: u32,
}

/// `pre_shared_key` (RFC 9846 §4.3.11): the client's identities and
/// binders, or the index of the identity the server chose.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TLSPreSharedKey {
    /// As many binders as identities (`illegal_parameter` otherwise).
    Offered {
        identities: Vec<TLSPSKIdentity>,
        binders: Vec<Vec<u8>>,
    },
    Selected(u16),
}

impl TLSPreSharedKey {
    pub fn decode(data: &[u8], context: TLSExtensionContext) -> Result<TLSPreSharedKey, TLSError> {
        let mut reader = Reader::new(data);
        let value = if context == TLSExtensionContext::ClientHello {
            let mut list = TLSVector::read_reader(&mut reader, 2, 7, 0xFFFF)?;
            let mut identities = Vec::new();
            while !list.is_empty() {
                let identity = TLSVector::read(&mut list, 2, 1, 0xFFFF)?.to_vec();
                let obfuscated_ticket_age = list.read_be().map_err(|_| TLSError::decode())?;
                identities.push(TLSPSKIdentity { identity, obfuscated_ticket_age });
            }
            let mut list = TLSVector::read_reader(&mut reader, 2, 33, 0xFFFF)?;
            let mut binders = Vec::new();
            while !list.is_empty() {
                binders.push(TLSVector::read(&mut list, 1, 32, 0xFF)?.to_vec());
            }
            if binders.len() != identities.len() {
                return Err(TLSError::illegal());
            }
            TLSPreSharedKey::Offered { identities, binders }
        } else {
            TLSPreSharedKey::Selected(reader.read_be().map_err(|_| TLSError::decode())?)
        };
        TLSVector::finish(&reader)?;
        Ok(value)
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        match self {
            TLSPreSharedKey::Offered { identities, binders } => {
                TLSVector::write_with(out, 2, 0xFFFF, |list| {
                    for identity in identities {
                        TLSVector::write(list, 2, 0xFFFF, &identity.identity)?;
                        list.write_be(identity.obfuscated_ticket_age)?;
                    }
                    Ok(())
                })?;
                TLSPreSharedKey::encode_binders(binders, out)
            }
            TLSPreSharedKey::Selected(index) => Ok(out.write_be(*index)?),
        }
    }

    /// The binders list `<33..2^16-1>`, which follows the truncated
    /// ClientHello that the binders authenticate (RFC 9846 §4.3.11.2).
    pub fn encode_binders(binders: &[Vec<u8>], out: &mut impl Writer) -> Result<(), TLSError> {
        TLSVector::write_with(out, 2, 0xFFFF, |list| {
            binders.iter().try_for_each(|binder| TLSVector::write(list, 1, 0xFF, binder))
        })
    }

    /// The length of the binders list as written: what a truncated
    /// ClientHello leaves out.
    pub fn binders_length(binders: &[Vec<u8>]) -> usize {
        2 + binders.iter().map(|binder| 1 + binder.len()).sum::<usize>()
    }
}

/// An opaque vector extension: `cookie<1..2^16-1>` (RFC 9846 §4.3.2), or
/// `renegotiated_connection<0..255>` of `renegotiation_info` (RFC 5746 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TLSOpaqueExtension;

impl TLSOpaqueExtension {
    pub fn decode_cookie(data: &[u8]) -> Result<Vec<u8>, TLSError> {
        let mut reader = Reader::new(data);
        let cookie = TLSVector::read(&mut reader, 2, 1, 0xFFFF)?.to_vec();
        TLSVector::finish(&reader)?;
        Ok(cookie)
    }

    pub fn encode_cookie(cookie: &[u8], out: &mut impl Writer) -> Result<(), TLSError> {
        TLSVector::write(out, 2, 0xFFFF, cookie)
    }

    pub fn decode_renegotiation_info(data: &[u8]) -> Result<Vec<u8>, TLSError> {
        let mut reader = Reader::new(data);
        let info = TLSVector::read(&mut reader, 1, 0, 0xFF)?.to_vec();
        TLSVector::finish(&reader)?;
        Ok(info)
    }

    pub fn encode_renegotiation_info(info: &[u8], out: &mut impl Writer) -> Result<(), TLSError> {
        TLSVector::write(out, 1, 0xFF, info)
    }

    /// Fails with `decode_error` unless `data` is empty: the extensions with
    /// no content (`early_data` outside NewSessionTicket,
    /// `post_handshake_auth`, `extended_main_secret`, and the server's
    /// `server_name`).
    pub fn decode_empty(data: &[u8]) -> Result<(), TLSError> {
        if data.is_empty() { Ok(()) } else { Err(TLSError::decode()) }
    }
}

/// `certificate_authorities`: the distinguished names of the CAs the peer
/// trusts (RFC 9846 §4.3.4).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TLSCertificateAuthorities {
    /// DER `Name`s.
    pub names: Vec<Vec<u8>>,
}

impl TLSCertificateAuthorities {
    pub fn decode(data: &[u8]) -> Result<TLSCertificateAuthorities, TLSError> {
        let mut reader = Reader::new(data);
        let mut list = TLSVector::read_reader(&mut reader, 2, 3, 0xFFFF)?;
        TLSVector::finish(&reader)?;
        let mut names = Vec::new();
        while !list.is_empty() {
            names.push(TLSVector::read(&mut list, 2, 1, 0xFFFF)?.to_vec());
        }
        Ok(TLSCertificateAuthorities { names })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        TLSVector::write_with(out, 2, 0xFFFF, |list| {
            self.names.iter().try_for_each(|name| TLSVector::write(list, 2, 0xFFFF, name))
        })
    }
}

/// `record_size_limit` (RFC 8449 §4): the largest plaintext the sender
/// accepts in a record, at least 64.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TLSRecordSizeLimit(pub u16);

impl TLSRecordSizeLimit {
    pub const MINIMUM: u16 = 64;

    /// Fails with `illegal_parameter` below 64 (RFC 8449 §4).
    pub fn decode(data: &[u8]) -> Result<TLSRecordSizeLimit, TLSError> {
        let mut reader = Reader::new(data);
        let limit = reader.read_be::<u16>().map_err(|_| TLSError::decode())?;
        TLSVector::finish(&reader)?;
        if limit < TLSRecordSizeLimit::MINIMUM {
            return Err(TLSError::illegal());
        }
        Ok(TLSRecordSizeLimit(limit))
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        Ok(out.write_be(self.0)?)
    }

    /// The value that advertises `plaintext` bytes of plaintext in
    /// `version`: TLS 1.3 counts the content type as well (RFC 8449 §4).
    pub fn advertising(plaintext: u16, version: TLSVersion) -> TLSRecordSizeLimit {
        let plaintext = plaintext.min(TLSRecordHeader::MAXIMUM_PLAINTEXT as u16);
        if version == TLSVersion::TLS1_3 { TLSRecordSizeLimit(plaintext + 1) } else { TLSRecordSizeLimit(plaintext) }
    }

    /// The largest plaintext the value allows in `version`, never above
    /// what the version allows (RFC 8449 §4: a larger value is not used).
    pub fn plaintext(self, version: TLSVersion) -> usize {
        let value = self.0 as usize;
        let plaintext = if version == TLSVersion::TLS1_3 { value - 1 } else { value };
        plaintext.min(TLSRecordHeader::MAXIMUM_PLAINTEXT)
    }
}

/// `early_data` of a NewSessionTicket: the most early data the ticket
/// allows (RFC 9846 §4.3.10). In a ClientHello and EncryptedExtensions the
/// extension is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TLSEarlyDataIndication(pub u32);

impl TLSEarlyDataIndication {
    pub fn decode(data: &[u8]) -> Result<TLSEarlyDataIndication, TLSError> {
        let mut reader = Reader::new(data);
        let maximum = reader.read_be::<u32>().map_err(|_| TLSError::decode())?;
        TLSVector::finish(&reader)?;
        Ok(TLSEarlyDataIndication(maximum))
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        Ok(out.write_be(self.0)?)
    }
}

/// `status_request` (RFC 6066 §8): a client's request for an OCSP
/// response, or the response a certificate entry carries (RFC 9846
/// §4.5.1.1). Only the type `ocsp` (1) is defined.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TLSCertificateStatus {
    /// `OCSPStatusRequest`: the responder IDs and the request extensions,
    /// both DER, usually empty.
    Request { responder_ids: Vec<Vec<u8>>, extensions: Vec<u8> },
    /// A DER `OCSPResponse`.
    Response(Vec<u8>),
}

impl TLSCertificateStatus {
    pub const OCSP: u8 = 1;

    /// Reads a request (in a ClientHello or CertificateRequest) or a
    /// response (in a certificate entry, or TLS 1.2's CertificateStatus).
    pub fn decode(data: &[u8], response: bool) -> Result<TLSCertificateStatus, TLSError> {
        let mut reader = Reader::new(data);
        if reader.read_u8().map_err(|_| TLSError::decode())? != TLSCertificateStatus::OCSP {
            return Err(TLSError::decode());
        }
        let status = if response {
            TLSCertificateStatus::Response(TLSVector::read(&mut reader, 3, 1, 0xFF_FFFF)?.to_vec())
        } else {
            let mut list = TLSVector::read_reader(&mut reader, 2, 0, 0xFFFF)?;
            let mut responder_ids = Vec::new();
            while !list.is_empty() {
                responder_ids.push(TLSVector::read(&mut list, 2, 1, 0xFFFF)?.to_vec());
            }
            let extensions = TLSVector::read(&mut reader, 2, 0, 0xFFFF)?.to_vec();
            TLSCertificateStatus::Request { responder_ids, extensions }
        };
        TLSVector::finish(&reader)?;
        Ok(status)
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        out.write_u8(TLSCertificateStatus::OCSP)?;
        match self {
            TLSCertificateStatus::Request { responder_ids, extensions } => {
                TLSVector::write_with(out, 2, 0xFFFF, |list| {
                    responder_ids.iter().try_for_each(|id| TLSVector::write(list, 2, 0xFFFF, id))
                })?;
                TLSVector::write(out, 2, 0xFFFF, extensions)
            }
            TLSCertificateStatus::Response(response) => TLSVector::write(out, 3, 0xFF_FFFF, response),
        }
    }
}
