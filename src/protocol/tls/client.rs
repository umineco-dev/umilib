use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::auth::cert::path::ServiceIdentity;

use super::{
    TLSAlertDescription, TLSCertificateStatus, TLSCipherSuite, TLSClientConfig, TLSClientHello, TLSContentType,
    TLSContext, TLSECH, TLSECHCipherSuite, TLSECHClientHello, TLSECHConfig, TLSECHOffer, TLSECHStatus, TLSError,
    TLSExtension, TLSExtensionContext, TLSExtensionType, TLSHandshake, TLSHandshakeProtocol, TLSHandshakeType,
    TLSKeyShare, TLSKeyShareEntry, TLSKeyShareSecret, TLSMiddleboxCompatibility, TLSOpaqueExtension, TLSPSKMode,
    TLSPointFormats, TLSProtocolNames, TLSRecordSizeLimit, TLSServerHello, TLSServerNames, TLSSessionTicket,
    TLSSignatureSchemes, TLSSupportedGroups, TLSSupportedVersions, TLSTranscript, TLSVersion,
};

/// A client from its ClientHello to the server's ServerHello, which names
/// the version: the part of the handshake that every version shares. The
/// ClientHello offers every version configured at once (RFC 9846 §4.2.1,
/// Appendix E); a HelloRetryRequest (TLS 1.3) makes it send the
/// ClientHello again.
pub struct TLSClientStart {
    pub config: Arc<TLSClientConfig>,
    /// The name sent in `server_name`, if any.
    pub server_name: Option<String>,
    /// The identity the server's certificate must name.
    pub identity: Option<ServiceIdentity>,
    /// The last ClientHello sent.
    pub hello: TLSClientHello,
    pub transcript: TLSTranscript,
    /// The secrets of the key shares sent.
    pub shares: Vec<TLSKeyShareSecret>,
    /// The cipher suite and version of a HelloRetryRequest received, if any.
    pub retry: Option<(TLSCipherSuite, TLSVersion)>,
    /// Whether the dummy ChangeCipherSpec of the middlebox compatibility
    /// mode was sent (RFC 9846 Appendix E.4).
    pub sent_change_cipher_spec: bool,
    /// The name connected to, by which tickets are kept.
    pub name: Option<String>,
    /// The ticket offered for resumption, if any (TLS 1.3, RFC 9846 §4.6.1).
    pub resumption: Option<TLSSessionTicket>,
    /// How many more bytes of early data may be sent.
    pub early_data: usize,
    /// The offer of ECH while the server has not answered it (RFC 9849):
    /// `hello` and `transcript` are then those of the ClientHelloInner.
    pub ech: Option<Box<TLSECHOffer>>,
    /// Whether the server rejected ECH: the handshake authenticates the
    /// public name, and the session says so only once the server proved it
    /// holds it (RFC 9849 §6.1.6).
    pub ech_rejected: bool,
    /// The retry configurations of the server that rejected ECH, kept until then.
    pub ech_retry_configs: Option<Vec<u8>>,
}

impl TLSClientStart {
    /// Writes the ClientHello and returns the client waiting for the server.
    pub fn start(
        config: Arc<TLSClientConfig>,
        server_name: Option<&str>,
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        let (sni, identity) = TLSClientStart::names(server_name, config.send_server_name)?;
        let mut versions = TLSClientStart::versions(&config);
        // QUIC: TLS 1.3 only, without the middlebox compatibility mode (RFC 9001 §4.2, §8.4).
        let quic = context.layer.quic.as_ref().map(|quic| quic.transport_parameters.clone());
        if quic.is_some() {
            versions.retain(|version| *version == TLSVersion::TLS1_3);
        }
        let mut random = [0u8; 32];
        let internal = |_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR);
        context.random.fill(&mut random).map_err(internal)?;
        let legacy_session_id = if versions.contains(&TLSVersion::TLS1_3)
            && quic.is_none()
            && config.middlebox_compatibility == TLSMiddleboxCompatibility::On
        {
            let mut id = vec![0u8; 32];
            context.random.fill(&mut id).map_err(internal)?;
            id
        } else {
            Vec::new()
        };
        let mut shares = Vec::new();
        let mut entries = Vec::new();
        if versions.contains(&TLSVersion::TLS1_3) {
            for group in &config.key_share_groups {
                let (secret, key_exchange) = TLSKeyShareSecret::generate(*group, &mut &mut *context.random)?;
                shares.push(secret);
                entries.push(TLSKeyShareEntry { group: *group, key_exchange });
            }
        }
        let ech = TLSClientStart::choose_ech(&config, &versions);
        // A ClientHelloInner offers only TLS 1.3 (RFC 9849 §6.1).
        let inner_versions = if ech.is_some() { vec![TLSVersion::TLS1_3] } else { versions.clone() };
        let cipher_suites = TLSClientStart::suites(&config, &inner_versions);
        let name = server_name.map(|name| name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase());
        let resumption =
            TLSClientStart::resumption(&config, name.as_deref(), &inner_versions, &cipher_suites, context.session.time);
        let early = resumption.as_ref().is_some_and(|ticket| TLSClientStart::allows_early_data(&config, ticket));
        if let Some(ticket) = &resumption {
            context.session.application = ticket.state.application.clone();
        }
        let mut extensions =
            TLSClientStart::extensions(&config, &inner_versions, sni.as_deref(), entries.clone(), quic.as_deref())?;
        if early {
            extensions.push(TLSExtension::new(TLSExtensionType::EARLY_DATA, Vec::new()));
        }
        if ech.is_some() {
            extensions.push(TLSECHClientHello::Inner.extension()?);
        } else if config.ech_grease && versions.contains(&TLSVersion::TLS1_3) {
            // As long as a ClientHelloInner of these extensions would be (RFC 9849 §6.2.1).
            let length = 80 + extensions.iter().map(|extension| 4 + extension.data.len()).sum::<usize>();
            extensions.push(TLSECH::grease(length, &mut &mut *context.random)?);
            context.session.ech = TLSECHStatus::Grease;
        }
        #[cfg(umilib_feature = "protocol-tls-v1_3")]
        if let Some(ticket) = &resumption {
            extensions.push(super::v1_3::TLS13Resumption::offer(ticket, context.session.time)?);
        }
        let hello = TLSClientHello {
            legacy_version: TLSVersion::TLS1_2,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods: vec![0],
            extensions,
        };
        #[allow(unused_mut)]
        let mut offer = None;
        #[cfg(all(umilib_feature = "crypto-hpke", umilib_feature = "protocol-tls-v1_3"))]
        if let Some((ech_config, suite)) = ech {
            offer = Some(Box::new(TLSClientStart::offer_ech(
                &config, ech_config, suite, &versions, &hello, entries, context,
            )?));
        }
        #[cfg(not(all(umilib_feature = "crypto-hpke", umilib_feature = "protocol-tls-v1_3")))]
        let _ = (ech, entries);
        let mut start = TLSClientStart {
            config,
            server_name: sni,
            identity,
            hello,
            transcript: TLSTranscript::new(),
            shares,
            retry: None,
            sent_change_cipher_spec: false,
            name,
            resumption,
            early_data: 0,
            ech: offer,
            ech_rejected: false,
            ech_retry_configs: None,
        };
        // The record of an initial ClientHello says 0x0301 (RFC 9846 §5.1).
        context.layer.version = TLSVersion::TLS1_0;
        start.send_hello(context)?;
        context.layer.version = TLSVersion::TLS1_2;
        context.session.server_name = start.server_name.clone();
        #[cfg(umilib_feature = "protocol-tls-v1_3")]
        if early {
            start.offer_early_data(context)?;
        }
        Ok(Box::new(start))
    }

    /// Writes the ClientHello, with the binder of the PSK offered if any
    /// (RFC 9846 §4.3.11.2), and adds it to the transcript.
    pub fn send_hello(&mut self, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        #[allow(unused_mut)]
        let mut message = TLSHandshake::new(TLSHandshakeType::CLIENT_HELLO, self.hello.to_bytes()?).to_bytes()?;
        #[cfg(umilib_feature = "protocol-tls-v1_3")]
        if let Some(ticket) = &self.resumption {
            super::v1_3::TLS13Resumption::bind(&mut message, &ticket.state, &self.transcript)?;
            self.hello = TLSClientHello::decode(&message[4..])?;
        }
        self.transcript.update(&message);
        match &mut self.ech {
            Some(offer) => TLSClientStart::send_outer(&self.hello, offer, context),
            None => context.layer.write(TLSContentType::HANDSHAKE, &message),
        }
    }

    /// Writes the ClientHelloOuter of `offer` that carries `inner` (RFC
    /// 9849 §6.1.1): `encrypted_client_hello` is computed last, sealed over
    /// the ClientHelloOuterAAD, before `pre_shared_key` if any.
    pub fn send_outer(
        inner: &TLSClientHello,
        offer: &mut TLSECHOffer,
        context: &mut TLSContext<'_>,
    ) -> Result<(), TLSError> {
        let encoded = TLSECH::encode_inner(inner, offer.config.maximum_name_length)?;
        let mut outer = offer.outer.clone();
        outer.extensions.retain(|extension| extension.kind != TLSExtensionType::ENCRYPTED_CLIENT_HELLO);
        let position = outer
            .extensions
            .iter()
            .position(|extension| extension.kind == TLSExtensionType::PRE_SHARED_KEY)
            .unwrap_or(outer.extensions.len());
        let mut extension = TLSECHClientHello::Outer {
            cipher_suite: offer.cipher_suite,
            config_id: offer.config.config_id,
            enc: core::mem::take(&mut offer.enc),
            payload: vec![0; encoded.len() + offer.cipher_suite.tag_length()],
        };
        outer.extensions.insert(position, extension.extension()?);
        let payload = offer.sealer.seal(&outer.to_bytes()?, &encoded)?;
        if let TLSECHClientHello::Outer { payload: placeholder, .. } = &mut extension {
            *placeholder = payload;
        }
        outer.extensions[position] = extension.extension()?;
        let message = TLSHandshake::new(TLSHandshakeType::CLIENT_HELLO, outer.to_bytes()?).to_bytes()?;
        context.layer.write(TLSContentType::HANDSHAKE, &message)?;
        offer.transcript.update(&message);
        offer.outer = outer;
        Ok(())
    }

    /// The cipher suites to offer for `versions`.
    pub fn suites(config: &TLSClientConfig, versions: &[TLSVersion]) -> Vec<TLSCipherSuite> {
        config
            .config
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| suite.version().is_some_and(|version| versions.contains(&version)))
            .collect()
    }

    /// The ECH configuration to offer and its cipher suite: the first this
    /// crate can use (RFC 9849 §6.1), when TLS 1.3 is offered.
    pub fn choose_ech(config: &TLSClientConfig, versions: &[TLSVersion]) -> Option<(TLSECHConfig, TLSECHCipherSuite)> {
        if !versions.contains(&TLSVersion::TLS1_3) || !cfg!(umilib_feature = "crypto-hpke") {
            return None;
        }
        config.ech_configs.iter().find_map(|ech| ech.usable_suite().map(|suite| (ech.clone(), suite)))
    }

    /// The server rejected ECH (RFC 9849 §6.1.6): the handshake goes on
    /// with the ClientHelloOuter, authenticating the public name, and
    /// without the PSK of the inner one. The session's status stays
    /// `Offered` until [`TLSClientStart::end_rejected_ech`].
    pub fn reject_ech(&mut self, context: &mut TLSContext<'_>) {
        let Some(offer) = self.ech.take() else { return };
        let name = offer.config.public_name_string();
        self.hello = offer.outer;
        self.transcript = offer.transcript;
        self.identity = Some(ServiceIdentity::DNS(name.clone()));
        self.server_name = Some(name);
        self.resumption = None;
        context.session.server_name = self.server_name.clone();
        self.ech_rejected = true;
    }

    /// Fails a handshake whose ECH the server rejected, once the server
    /// proved it holds the public name: the session gets the retry
    /// configurations, and the connection fails with `ech_required` (RFC
    /// 9849 §6.1.6). Does nothing for another handshake.
    pub fn end_rejected_ech(&mut self, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        if !self.ech_rejected {
            return Ok(());
        }
        context.session.ech = TLSECHStatus::Rejected { retry_configs: self.ech_retry_configs.take() };
        Err(TLSError::Protocol(TLSAlertDescription::ECH_REQUIRED))
    }

    /// The `encrypted_client_hello` of a HelloRetryRequest to a client that
    /// sent GREASE: 8 bytes (`decode_error` otherwise), ignored (RFC 9849 §6.2.1).
    pub fn check_grease(&self, hello: &TLSServerHello) -> Result<(), TLSError> {
        match hello.extension(TLSExtensionType::ENCRYPTED_CLIENT_HELLO) {
            Some(data) if self.ech.is_none() && data.len() != 8 => Err(TLSError::decode()),
            _ => Ok(()),
        }
    }

    /// The ticket to offer for `name` at `time`, taken from the store: one
    /// of TLS 1.3, current, whose hash a suite offered has (RFC 9846 §4.6.1).
    pub fn resumption(
        config: &TLSClientConfig,
        name: Option<&str>,
        versions: &[TLSVersion],
        suites: &[TLSCipherSuite],
        time: i64,
    ) -> Option<TLSSessionTicket> {
        if !versions.contains(&TLSVersion::TLS1_3) || config.config.psk_modes.is_empty() {
            return None;
        }
        let ticket = config.sessions.as_ref()?.take(name?)?;
        let hash = ticket.state.cipher_suite.hash();
        let usable = ticket.state.version == TLSVersion::TLS1_3
            && ticket.state.is_current(time)
            && hash.is_some()
            && suites.iter().any(|suite| suite.version() == Some(TLSVersion::TLS1_3) && suite.hash() == hash);
        usable.then_some(ticket)
    }

    /// Whether to send early data with `ticket`: configured, allowed by the
    /// ticket, of a suite offered, and of the application protocol of the
    /// session, which the server must choose again (RFC 9846 §4.2.10).
    pub fn allows_early_data(config: &TLSClientConfig, ticket: &TLSSessionTicket) -> bool {
        config.early_data
            && ticket.state.maximum_early_data > 0
            && config.config.cipher_suites.contains(&ticket.state.cipher_suite)
            && ticket.state.protocol.as_ref().is_none_or(|protocol| config.config.protocols.contains(protocol))
    }

    /// Installs the keys of early data after the ClientHello, after the
    /// dummy ChangeCipherSpec in compatibility mode (RFC 9846 §7.1,
    /// Appendix E.4).
    #[cfg(umilib_feature = "protocol-tls-v1_3")]
    pub fn offer_early_data(&mut self, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let Some(ticket) = &self.resumption else { return Ok(()) };
        let suite = ticket.state.cipher_suite;
        let (Some(hash), Some(aead)) = (suite.hash(), suite.aead()) else { return Err(TLSError::illegal()) };
        let secret = super::v1_3::TLS13Resumption::early_traffic_secret(&ticket.state, &self.transcript)?;
        let schedule = super::v1_3::TLS13KeySchedule::new(hash);
        self.early_data = ticket.state.maximum_early_data as usize;
        self.send_change_cipher_spec(context)?;
        super::v1_3::TLS13Authentication::install(
            context.layer,
            super::TLSDirection::Writing,
            super::TLSEncryptionLevel::EarlyData,
            &schedule,
            aead,
            secret.expose(),
        )?;
        context.session.early_data = super::TLSEarlyData::Offered;
        Ok(())
    }

    /// The versions to offer: those configured that this crate supports.
    pub fn versions(config: &TLSClientConfig) -> Vec<TLSVersion> {
        config.config.versions.iter().copied().filter(|version| version.is_supported()).collect()
    }

    /// The highest of `versions`, which the ClientHello's values that
    /// depend on the version are written for.
    pub fn highest(versions: &[TLSVersion]) -> TLSVersion {
        versions.iter().copied().max().unwrap_or(TLSVersion::TLS1_2)
    }

    /// The server's `record_size_limit` (RFC 8449 §4): its limit applies to
    /// what this client sends, and this client's own, which the server has
    /// now seen, to what it receives, both as `version` counts them.
    pub fn limit_records(
        &self,
        data: &[u8],
        version: TLSVersion,
        context: &mut TLSContext<'_>,
    ) -> Result<(), TLSError> {
        let peer = TLSRecordSizeLimit::decode(data)?;
        let versions = TLSClientStart::versions(&self.config);
        let own =
            TLSRecordSizeLimit::advertising(self.config.config.record_size_limit, TLSClientStart::highest(&versions));
        context.layer.peer_limit = peer.0 as usize;
        context.layer.own_limit = own.plaintext(version);
        Ok(())
    }

    /// The name to send in `server_name` and the identity to check: a DNS
    /// name is both; an address is only the identity, as RFC 6066 §3
    /// forbids addresses in `server_name`. A trailing dot is removed.
    pub fn names(server_name: Option<&str>, send: bool) -> Result<(Option<String>, Option<ServiceIdentity>), TLSError> {
        let Some(name) = server_name else { return Ok((None, None)) };
        match name.parse::<core::net::IpAddr>() {
            Ok(core::net::IpAddr::V4(address)) => {
                return Ok((None, Some(ServiceIdentity::IPAddress(address.octets().to_vec()))));
            }
            Ok(core::net::IpAddr::V6(address)) => {
                return Ok((None, Some(ServiceIdentity::IPAddress(address.octets().to_vec()))));
            }
            Err(_) => {}
        }
        let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
        if name.is_empty() || name.len() > 253 || !name.is_ascii() {
            return Err(TLSError::Config);
        }
        Ok((send.then(|| name.clone()), Some(ServiceIdentity::DNS(name))))
    }

    /// The extensions of the ClientHello for `versions`.
    /// The extensions of a ClientHello offering `versions`, with QUIC's
    /// `transport_parameters` when QUIC carries it (RFC 9001 §8.2), and then
    /// neither `record_size_limit`, which limits records, nor
    /// `post_handshake_auth`, which QUIC forbids (RFC 9001 §4.4).
    pub fn extensions(
        config: &TLSClientConfig,
        versions: &[TLSVersion],
        server_name: Option<&str>,
        shares: Vec<TLSKeyShareEntry>,
        transport_parameters: Option<&[u8]>,
    ) -> Result<Vec<TLSExtension>, TLSError> {
        let mut extensions = Vec::new();
        if let Some(name) = server_name {
            let names = TLSServerNames { host_names: vec![name.as_bytes().to_vec()] };
            extensions.push(TLSExtension::with(TLSExtensionType::SERVER_NAME, |data| names.encode(data))?);
        }
        if config.request_certificate_status {
            let request = TLSCertificateStatus::Request { responder_ids: Vec::new(), extensions: Vec::new() };
            extensions.push(TLSExtension::with(TLSExtensionType::STATUS_REQUEST, |data| request.encode(data))?);
        }
        if versions.contains(&TLSVersion::TLS1_2) {
            // RFC 7627 (required here), RFC 5746 (signalling no renegotiation), RFC 8422 §5.1.2.
            extensions.push(TLSExtension::new(TLSExtensionType::EXTENDED_MAIN_SECRET, Vec::new()));
            extensions.push(TLSExtension::with(TLSExtensionType::RENEGOTIATION_INFO, |data| {
                TLSOpaqueExtension::encode_renegotiation_info(&[], data)
            })?);
            let formats = TLSPointFormats { formats: vec![TLSPointFormats::UNCOMPRESSED] };
            extensions.push(TLSExtension::with(TLSExtensionType::EC_POINT_FORMATS, |data| formats.encode(data))?);
        }
        let groups = TLSSupportedGroups {
            groups: config
                .config
                .groups
                .iter()
                .copied()
                .filter(|group| versions.iter().any(|version| group.usable_with(*version)))
                .collect(),
        };
        extensions.push(TLSExtension::with(TLSExtensionType::SUPPORTED_GROUPS, |data| groups.encode(data))?);
        let schemes = TLSSignatureSchemes { schemes: config.config.signature_schemes.clone() };
        extensions.push(TLSExtension::with(TLSExtensionType::SIGNATURE_ALGORITHMS, |data| schemes.encode(data))?);
        if !config.config.protocols.is_empty() {
            let protocols = TLSProtocolNames { names: config.config.protocols.clone() };
            extensions.push(TLSExtension::with(TLSExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION, |data| {
                protocols.encode(data)
            })?);
        }
        if transport_parameters.is_none() {
            let limit =
                TLSRecordSizeLimit::advertising(config.config.record_size_limit, TLSClientStart::highest(versions));
            extensions.push(TLSExtension::with(TLSExtensionType::RECORD_SIZE_LIMIT, |data| limit.encode(data))?);
        }
        let offered = TLSSupportedVersions::Offered(versions.to_vec());
        extensions.push(TLSExtension::with(TLSExtensionType::SUPPORTED_VERSIONS, |data| offered.encode(data))?);
        if versions.contains(&TLSVersion::TLS1_3) {
            if !config.config.psk_modes.is_empty() {
                extensions.push(TLSExtension::with(TLSExtensionType::PSK_KEY_EXCHANGE_MODES, |data| {
                    TLSPSKMode::encode_list(&config.config.psk_modes, data)
                })?);
            }
            if config.post_handshake_authentication && transport_parameters.is_none() {
                extensions.push(TLSExtension::new(TLSExtensionType::POST_HANDSHAKE_AUTH, Vec::new()));
            }
            let share = TLSKeyShare::Client(shares);
            extensions.push(TLSExtension::with(TLSExtensionType::KEY_SHARE, |data| share.encode(data))?);
        }
        if let Some(parameters) = transport_parameters {
            extensions.push(TLSExtension::new(TLSExtensionType::QUIC_TRANSPORT_PARAMETERS, parameters.to_vec()));
        }
        Ok(extensions)
    }

    /// The version of a ServerHello or HelloRetryRequest (RFC 9846 §4.3.1,
    /// Appendix E.1): that of `supported_versions`, which must be TLS 1.3
    /// and offered (`illegal_parameter`), or else `legacy_version`, which
    /// must be offered (`protocol_version`).
    pub fn version_of(&self, hello: &TLSServerHello) -> Result<TLSVersion, TLSError> {
        let offered = TLSClientStart::versions(&self.config);
        if let Some(data) = hello.extension(TLSExtensionType::SUPPORTED_VERSIONS) {
            let TLSSupportedVersions::Selected(version) =
                TLSSupportedVersions::decode(data, TLSExtensionContext::ServerHello)?
            else {
                return Err(TLSError::decode());
            };
            if version != TLSVersion::TLS1_3 || !offered.contains(&version) {
                return Err(TLSError::illegal());
            }
            return Ok(version);
        }
        if hello.is_retry() || hello.legacy_version != TLSVersion::TLS1_2 || !offered.contains(&TLSVersion::TLS1_2) {
            return Err(TLSError::Protocol(TLSAlertDescription::PROTOCOL_VERSION));
        }
        // A TLS 1.3 server that negotiates TLS 1.2 marks its random (RFC 9846 §4.2.3).
        let tail = &hello.random[24..];
        if offered.contains(&TLSVersion::TLS1_3)
            && (tail == TLSServerHello::DOWNGRADE_TLS1_2 || tail == TLSServerHello::DOWNGRADE_TLS1_1)
        {
            return Err(TLSError::illegal());
        }
        Ok(TLSVersion::TLS1_2)
    }

    /// Sends the dummy ChangeCipherSpec of the middlebox compatibility mode
    /// once, before the second flight (RFC 9846 Appendix E.4).
    pub fn send_change_cipher_spec(&mut self, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        if !self.sent_change_cipher_spec && !self.hello.legacy_session_id.is_empty() {
            context.layer.write_record(TLSContentType::CHANGE_CIPHER_SPEC, &[1])?;
            self.sent_change_cipher_spec = true;
        }
        Ok(())
    }

    /// A HelloRetryRequest (RFC 9846 §4.2.4): checks it as a ServerHello,
    /// then sends the ClientHello again with a share of the group asked for
    /// and the cookie, if any.
    #[cfg(umilib_feature = "protocol-tls-v1_3")]
    pub fn retry(
        mut self: Box<Self>,
        hello: TLSServerHello,
        bytes: &[u8],
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        if self.retry.is_some() {
            return Err(TLSError::unexpected());
        }
        let version = self.version_of(&hello)?;
        self.check_server_hello(&hello, TLSExtensionContext::HelloRetryRequest)?;
        let suite = hello.cipher_suite;
        let hash = suite.hash().ok_or(TLSError::illegal())?;
        let mut changed = false;
        // No early data after a HelloRetryRequest (RFC 9846 §4.2.10), and
        // no PSK of another hash than the suite's (§4.2.11).
        if context.session.early_data == super::TLSEarlyData::Offered {
            context.session.early_data = super::TLSEarlyData::Rejected;
            context.layer.unprotect_writing();
            self.early_data = 0;
        }
        if self.resumption.as_ref().is_some_and(|ticket| ticket.state.cipher_suite.hash() != Some(hash)) {
            self.resumption = None;
        }
        let resuming = self.resumption.is_some();
        let mut extensions: Vec<TLSExtension> = self
            .hello
            .extensions
            .iter()
            .filter(|extension| {
                extension.kind != TLSExtensionType::EARLY_DATA
                    && extension.kind != TLSExtensionType::COOKIE
                    && (extension.kind != TLSExtensionType::PRE_SHARED_KEY || resuming)
            })
            .cloned()
            .collect();
        if let Some(data) = hello.extension(TLSExtensionType::KEY_SHARE) {
            let TLSKeyShare::Retry(group) = TLSKeyShare::decode(data, TLSExtensionContext::HelloRetryRequest)? else {
                return Err(TLSError::decode());
            };
            // The group must be offered, without a share sent already (RFC 9846 §4.3.8).
            let offered = self.config.config.groups.contains(&group) && TLSKeyShareSecret::supports(group);
            if !offered || self.shares.iter().any(|share| share.group() == group) {
                return Err(TLSError::illegal());
            }
            let (secret, key_exchange) = TLSKeyShareSecret::generate(group, &mut &mut *context.random)?;
            self.shares = vec![secret];
            let share = TLSKeyShare::Client(vec![TLSKeyShareEntry { group, key_exchange }]);
            let data = {
                let mut data = crate::bytes::Buffer::new();
                share.encode(&mut data)?;
                data.into_vec()
            };
            if let Some(extension) =
                extensions.iter_mut().find(|extension| extension.kind == TLSExtensionType::KEY_SHARE)
            {
                extension.data = data;
            }
            changed = true;
        }
        if let Some(data) = hello.extension(TLSExtensionType::COOKIE) {
            let cookie = TLSOpaqueExtension::decode_cookie(data)?;
            let extension =
                TLSExtension::with(TLSExtensionType::COOKIE, |out| TLSOpaqueExtension::encode_cookie(&cookie, out))?;
            // Before pre_shared_key, which must stay last.
            let position = extensions.iter().position(|extension| extension.kind == TLSExtensionType::PRE_SHARED_KEY);
            extensions.insert(position.unwrap_or(extensions.len()), extension);
            changed = true;
        }
        if !changed {
            return Err(TLSError::illegal());
        }
        // ClientHello1 becomes a message_hash in the transcript (RFC 9846 §4.1).
        self.transcript.restart_after_retry(hash);
        self.transcript.update(bytes);
        self.retry = Some((suite, version));
        self.send_change_cipher_spec(context)?;
        self.hello.extensions = extensions;
        // The second ClientHelloOuter: the first with the new key share and no early data (RFC 9849 §6.1.5).
        let share = self.hello.extension(TLSExtensionType::KEY_SHARE).map(<[u8]>::to_vec);
        if let (Some(offer), Some(share)) = (&mut self.ech, share) {
            offer.outer.extensions.retain(|extension| extension.kind != TLSExtensionType::EARLY_DATA);
            for extension in &mut offer.outer.extensions {
                if extension.kind == TLSExtensionType::KEY_SHARE {
                    extension.data = share.clone();
                }
            }
        }
        self.send_hello(context)?;
        Ok(self)
    }

    /// The checks of RFC 9846 §4.2.3 and §4.3 common to ServerHello and
    /// HelloRetryRequest in TLS 1.3: the session ID echoed
    /// (`illegal_parameter`), a TLS 1.3 cipher suite offered
    /// (`illegal_parameter`), compression 0 (`illegal_parameter`), the
    /// extensions allowed (`illegal_parameter`) and offered
    /// (`unsupported_extension`; the cookie excepted).
    pub fn check_server_hello(&self, hello: &TLSServerHello, context: TLSExtensionContext) -> Result<(), TLSError> {
        if hello.legacy_session_id_echo != self.hello.legacy_session_id
            || hello.legacy_compression_method != 0
            || !self.hello.cipher_suites.contains(&hello.cipher_suite)
            || hello.cipher_suite.version() != Some(TLSVersion::TLS1_3)
        {
            return Err(TLSError::illegal());
        }
        if let Some((suite, _)) = self.retry
            && suite != hello.cipher_suite
        {
            return Err(TLSError::illegal());
        }
        TLSExtension::check(&hello.extensions, context)?;
        for extension in &hello.extensions {
            let offered = self.hello.extension(extension.kind).is_some();
            if !offered && extension.kind != TLSExtensionType::COOKIE {
                return Err(TLSError::Protocol(TLSAlertDescription::UNSUPPORTED_EXTENSION));
            }
        }
        Ok(())
    }

    /// The protocol the server chose (ALPN): one the client offered
    /// (RFC 7301 §3.2: `illegal_parameter` otherwise).
    pub fn protocol(&self, data: &[u8]) -> Result<Vec<u8>, TLSError> {
        let protocols = TLSProtocolNames::decode(data)?;
        let selected = protocols.selected()?;
        if self.config.config.protocols.iter().any(|protocol| protocol.as_slice() == selected) {
            Ok(selected.to_vec())
        } else {
            Err(TLSError::illegal())
        }
    }

    /// The server's name as a string, for the session.
    pub fn server_name_string(&self) -> Option<String> {
        self.server_name.as_ref().map(ToString::to_string)
    }
}

impl TLSHandshakeProtocol for TLSClientStart {
    /// Early data within what the ticket allows (RFC 9846 §4.2.10).
    fn send_early_data(&mut self, length: usize) -> Result<(), TLSError> {
        self.early_data = self.early_data.checked_sub(length).ok_or(TLSError::State)?;
        Ok(())
    }

    fn receive(
        #[allow(unused_mut)] mut self: Box<Self>,
        message: TLSHandshake,
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        // A HelloRequest of TLS 1.2 while negotiating is ignored (RFC 5246
        // §7.4.1.1); QUIC has TLS 1.3 only, which has none (RFC 9001 §4.2).
        if message.kind == TLSHandshakeType::HELLO_REQUEST && message.body.is_empty() && context.layer.quic.is_none() {
            context.layer.ignore()?;
            return Ok(self);
        }
        if message.kind != TLSHandshakeType::SERVER_HELLO {
            return Err(TLSError::unexpected());
        }
        let bytes = message.to_bytes()?;
        let hello = TLSServerHello::decode(&message.body)?;
        // In TLS 1.3 the ServerHello and a HelloRetryRequest come before a key
        // change: they end their record (RFC 9846 §5.1). TLS 1.2 may put the
        // server's whole flight in one record (RFC 5246 §6.2.1).
        if hello.is_retry() {
            context.layer.check_boundary()?;
        }
        #[cfg(all(umilib_feature = "crypto-hpke", umilib_feature = "protocol-tls-v1_3"))]
        if hello.is_retry() {
            self.accept_ech_retry(&hello, context)?;
        } else {
            self.accept_ech(&hello, &bytes, context)?;
        }
        if hello.is_retry() {
            self.check_grease(&hello)?;
        }
        #[cfg(umilib_feature = "protocol-tls-v1_3")]
        if hello.is_retry() {
            return self.retry(hello, &bytes, context);
        }
        let version = self.version_of(&hello)?;
        if let Some((_, retried)) = self.retry
            && retried != version
        {
            return Err(TLSError::illegal());
        }
        if version == TLSVersion::TLS1_3 {
            context.layer.check_boundary()?;
        }
        // A client that sent early data fails when the server chooses TLS 1.2 (RFC 9846 Appendix E.3).
        if version != TLSVersion::TLS1_3 && context.session.early_data == super::TLSEarlyData::Offered {
            return Err(TLSError::Protocol(TLSAlertDescription::PROTOCOL_VERSION));
        }
        context.session.version = Some(version);
        match version {
            #[cfg(umilib_feature = "protocol-tls-v1_3")]
            TLSVersion::TLS1_3 => super::v1_3::TLS13Client::from_server_hello(*self, hello, &bytes, context),
            #[cfg(umilib_feature = "protocol-tls-v1_2")]
            TLSVersion::TLS1_2 => super::v1_2::TLS12Client::from_server_hello(*self, hello, &bytes, context),
            _ => Err(TLSError::Protocol(TLSAlertDescription::PROTOCOL_VERSION)),
        }
    }

    /// The server's dummy ChangeCipherSpec, `0x01`, may follow its
    /// HelloRetryRequest; it is dropped (RFC 9846 §5: at any time after the
    /// first ClientHello was sent).
    fn receive_change_cipher_spec(
        self: Box<Self>,
        fragment: &[u8],
        _context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        if fragment == [1] { Ok(self) } else { Err(TLSError::unexpected()) }
    }

    fn is_established(&self) -> bool {
        false
    }

    fn export(&self, _label: &[u8], _context: Option<&[u8]>, _out: &mut [u8]) -> Result<(), TLSError> {
        Err(TLSError::State)
    }

    fn update_keys(&mut self, _request: bool, _context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        Err(TLSError::State)
    }
}

#[cfg(all(umilib_feature = "crypto-hpke", umilib_feature = "protocol-tls-v1_3"))]
impl TLSClientStart {
    /// The offer of ECH with `ech` and `suite` for the ClientHelloInner
    /// `inner` (RFC 9849 §6.1): the HPKE context, and the ClientHelloOuter
    /// for the public name with `versions`, the session ID of `inner`, a
    /// fresh random, `early_data` if `inner` has it, and a GREASE
    /// `pre_shared_key` if `inner` offers a PSK (§6.1.2). Neither the
    /// application protocols nor post-handshake authentication show in it
    /// (§10.5).
    pub fn offer_ech(
        config: &TLSClientConfig,
        ech: TLSECHConfig,
        suite: TLSECHCipherSuite,
        versions: &[TLSVersion],
        inner: &TLSClientHello,
        shares: Vec<TLSKeyShareEntry>,
        context: &mut TLSContext<'_>,
    ) -> Result<TLSECHOffer, TLSError> {
        let internal = |_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR);
        let (enc, sealer) = super::TLSECHCipher::setup_sender(&ech, suite, &mut &mut *context.random)?;
        let public_name = ech.public_name_string();
        let quic = context.layer.quic.as_ref().map(|quic| quic.transport_parameters.as_slice());
        let mut extensions = TLSClientStart::extensions(config, versions, Some(&public_name), shares, quic)?;
        extensions.retain(|extension| {
            extension.kind != TLSExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
                && extension.kind != TLSExtensionType::POST_HANDSHAKE_AUTH
        });
        if inner.extension(TLSExtensionType::EARLY_DATA).is_some() {
            extensions.push(TLSExtension::new(TLSExtensionType::EARLY_DATA, Vec::new()));
        }
        if let Some(data) = inner.extension(TLSExtensionType::PRE_SHARED_KEY) {
            let super::TLSPreSharedKey::Offered { identities, binders } =
                super::TLSPreSharedKey::decode(data, TLSExtensionContext::ClientHello)?
            else {
                return Err(TLSError::decode());
            };
            let mut random_bytes = |length: usize| -> Result<Vec<u8>, TLSError> {
                let mut bytes = vec![0u8; length];
                context.random.fill(&mut bytes).map_err(internal)?;
                Ok(bytes)
            };
            let mut grease = Vec::with_capacity(identities.len());
            for identity in &identities {
                let age = random_bytes(4)?;
                grease.push(super::TLSPSKIdentity {
                    identity: random_bytes(identity.identity.len())?,
                    obfuscated_ticket_age: u32::from_be_bytes([age[0], age[1], age[2], age[3]]),
                });
            }
            let binders = binders.iter().map(|binder| random_bytes(binder.len())).collect::<Result<_, _>>()?;
            let offered = super::TLSPreSharedKey::Offered { identities: grease, binders };
            extensions.push(TLSExtension::with(TLSExtensionType::PRE_SHARED_KEY, |out| offered.encode(out))?);
        }
        let mut random = [0u8; 32];
        context.random.fill(&mut random).map_err(internal)?;
        let outer = TLSClientHello {
            legacy_version: TLSVersion::TLS1_2,
            random,
            legacy_session_id: inner.legacy_session_id.clone(),
            cipher_suites: TLSClientStart::suites(config, versions),
            legacy_compression_methods: vec![0],
            extensions,
        };
        context.session.ech = TLSECHStatus::Offered;
        Ok(TLSECHOffer {
            config: ech,
            cipher_suite: suite,
            sealer,
            enc,
            outer,
            transcript: TLSTranscript::new(),
            accepted_retry: false,
        })
    }

    /// Whether the server accepted ECH with its ServerHello `hello`
    /// (`bytes`, header included): TLS 1.3, and the confirmation in the
    /// last 8 bytes of its random (RFC 9849 §6.1.4). After a
    /// HelloRetryRequest that accepted it, the ServerHello must too
    /// (`illegal_parameter`, §6.1.5).
    pub fn accept_ech(
        &mut self,
        hello: &TLSServerHello,
        bytes: &[u8],
        context: &mut TLSContext<'_>,
    ) -> Result<(), TLSError> {
        use crate::secret::ConstantTimeEq;
        let Some(offer) = &self.ech else { return Ok(()) };
        let accepted = match (self.version_of(hello), hello.cipher_suite.hash()) {
            (Ok(TLSVersion::TLS1_3), Some(hash)) => {
                let confirmation =
                    TLSECH::server_hello_confirmation(&self.transcript, hash, &self.hello.random, bytes)?;
                hello.random[24..].ct_eq(confirmation.as_slice()).into_bool()
            }
            _ => false,
        };
        if offer.accepted_retry && !accepted {
            return Err(TLSError::illegal());
        }
        if accepted {
            self.ech = None;
            context.session.ech = TLSECHStatus::Accepted;
        } else {
            self.reject_ech(context);
        }
        Ok(())
    }

    /// Whether the server accepted ECH with its HelloRetryRequest `hello`:
    /// an `encrypted_client_hello` of 8 bytes (`decode_error` otherwise)
    /// that is the confirmation (RFC 9849 §6.1.4).
    pub fn accept_ech_retry(&mut self, hello: &TLSServerHello, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        use crate::secret::ConstantTimeEq;
        if self.ech.is_none() {
            return Ok(());
        }
        let accepted = match hello.extension(TLSExtensionType::ENCRYPTED_CLIENT_HELLO) {
            Some(data) if data.len() != 8 => return Err(TLSError::decode()),
            Some(data) => {
                let hash = hello.cipher_suite.hash().ok_or(TLSError::illegal())?;
                let confirmation = TLSECH::retry_confirmation(&self.transcript, hash, &self.hello.random, hello)?;
                data.ct_eq(confirmation.as_slice()).into_bool()
            }
            None => false,
        };
        match (&mut self.ech, accepted) {
            (Some(offer), true) => offer.accepted_retry = true,
            _ => self.reject_ech(context),
        }
        Ok(())
    }
}
