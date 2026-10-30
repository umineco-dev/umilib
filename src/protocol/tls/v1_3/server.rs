use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::auth::cert::path::ServiceIdentity;
use crate::protocol::tls::{
    TLSAEAD, TLSAEADAlgorithm, TLSAlertDescription, TLSCertificateStatus, TLSCertifiedKey, TLSCipherSuite,
    TLSClientAuthentication, TLSClientHello, TLSContentType, TLSContext, TLSDirection, TLSECH, TLSECHAcceptance,
    TLSECHStatus, TLSEarlyData, TLSEarlyDataIndication, TLSEncryptionLevel, TLSError, TLSEvent, TLSExtension,
    TLSExtensionContext, TLSExtensionType, TLSHandshake, TLSHandshakeProtocol, TLSHandshakeType, TLSKeyShare,
    TLSKeyShareEntry, TLSKeyShareSecret, TLSNamedGroup, TLSPSKMode, TLSPreSharedKey, TLSProtocolNames, TLSQUIC,
    TLSRecordHeader, TLSRole, TLSServerConfig, TLSServerHello, TLSServerStart, TLSSessionState, TLSSignatureScheme,
    TLSSignatureSchemes, TLSSupportedGroups, TLSSupportedVersions, TLSTranscript, TLSVersion,
};
use crate::secret::{ConstantTimeEq, Secret};

use super::{
    TLS13Authentication, TLS13Authenticator, TLS13CertificateRequest, TLS13EncryptedExtensions, TLS13Established,
    TLS13KeySchedule, TLS13NewSessionTicket, TLS13PostHandshake, TLS13Resumption,
};

/// What a TLS 1.3 server waits for (RFC 9846 Appendix A.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLS13ServerState {
    /// The second ClientHello, after a HelloRetryRequest for the group.
    RetryClientHello(TLSNamedGroup),
    /// The client's early data and EndOfEarlyData, after accepting 0-RTT.
    EndOfEarlyData,
    Certificate,
    CertificateVerify,
    Finished,
}

/// What the server chose from a ClientHello (RFC 9846 §4.2.1). A client
/// that offers a PSK need not allow a key exchange or a certificate (§9.2).
#[derive(Clone)]
pub struct TLS13Selection {
    pub suite: TLSCipherSuite,
    /// The group of the key exchange, if there is one in common.
    pub group: Option<TLSNamedGroup>,
    /// The client's share of `group`, if it sent one.
    pub share: Option<Vec<u8>>,
    /// The certificate and the scheme it signs with, if one fits the client.
    pub certificate: Option<(Arc<TLSCertifiedKey>, TLSSignatureScheme)>,
    /// Whether the certificate was chosen for the name the client asked for.
    pub named: bool,
}

/// The PSK a server accepted from a ClientHello (RFC 9846 §4.2.11).
#[derive(Clone, Debug)]
pub struct TLS13PSKSelection {
    /// The index of the identity among those offered.
    pub index: u16,
    pub state: TLSSessionState,
    /// Its binder, which presents the ClientHello to anti-replay.
    pub binder: Vec<u8>,
    pub obfuscated_age: u32,
    pub mode: TLSPSKMode,
}

/// A TLS 1.3 server from the ClientHello to the client's Finished.
pub struct TLS13Server {
    pub config: Arc<TLSServerConfig>,
    pub state: TLS13ServerState,
    pub transcript: TLSTranscript,
    /// The first ClientHello, which a second one after a HelloRetryRequest must match.
    pub hello: TLSClientHello,
    pub suite: TLSCipherSuite,
    pub schedule: TLS13KeySchedule,
    pub aead: TLSAEADAlgorithm,
    pub client_handshake: Secret<Vec<u8>>,
    pub main: Secret<Vec<u8>>,
    pub client_application: Secret<Vec<u8>>,
    pub server_application: Secret<Vec<u8>>,
    pub exporter: Secret<Vec<u8>>,
    pub chain: Vec<Vec<u8>>,
    pub sent_change_cipher_spec: bool,
    /// Whether the handshake resumes a session: no certificates.
    pub resumed: bool,
    /// How many more bytes of early data are accepted.
    pub early_data: usize,
    /// This server's limit of records, which applies once early data ends.
    pub deferred_limit: Option<usize>,
    /// The acceptance of ECH, if the ClientHello is a ClientHelloInner (RFC 9849 §7).
    pub ech: Option<Box<TLSECHAcceptance>>,
}

impl TLS13Server {
    /// Takes a ClientHello that negotiates TLS 1.3: answers it with a
    /// HelloRetryRequest when no key share fits, and with the server's
    /// flight otherwise.
    pub fn from_client_hello(
        config: Arc<TLSServerConfig>,
        hello: TLSClientHello,
        bytes: &[u8],
        ech: Option<Box<TLSECHAcceptance>>,
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        TLS13Server::check(&hello)?;
        let selection = TLS13Server::select(&config, &hello, None)?;
        let hash = selection.suite.hash().ok_or(TLSError::illegal())?;
        let aead = selection.suite.aead().ok_or(TLSError::illegal())?;
        let mut transcript = TLSTranscript::new();
        transcript.select(hash);
        transcript.update(bytes);
        let mut server = TLS13Server {
            config,
            state: TLS13ServerState::Finished,
            transcript,
            hello,
            suite: selection.suite,
            schedule: TLS13KeySchedule::new(hash),
            aead,
            client_handshake: Secret::new(Vec::new()),
            main: Secret::new(Vec::new()),
            client_application: Secret::new(Vec::new()),
            server_application: Secret::new(Vec::new()),
            exporter: Secret::new(Vec::new()),
            chain: Vec::new(),
            sent_change_cipher_spec: false,
            resumed: false,
            early_data: 0,
            deferred_limit: None,
            ech,
        };
        let psk =
            TLS13Server::resume(&server.config, &server.hello, bytes, &TLSTranscript::new(), selection.suite, context)?;
        let failure = TLSError::Protocol(TLSAlertDescription::HANDSHAKE_FAILURE);
        if psk.is_none() && selection.certificate.is_none() {
            return Err(failure);
        }
        let dhe = psk.as_ref().is_none_or(|psk| psk.mode == TLSPSKMode::PSK_DHE_KE);
        if dhe && selection.share.is_none() {
            let group = selection.group.ok_or(failure)?;
            // The client's early data cannot be read now (RFC 9846 §4.2.10).
            if server.hello.extension(TLSExtensionType::EARLY_DATA).is_some() {
                context.layer.skippable = TLS13Server::skippable(&server.config, psk.as_ref());
            }
            server.send_retry(group, context)?;
            return Ok(Box::new(server));
        }
        let hello = server.hello.clone();
        server.respond(&hello, selection, psk, true, context)?;
        Ok(Box::new(server))
    }

    /// The PSK to resume with (RFC 9846 §4.2.11): the first identity whose
    /// ticket this server opens, of TLS 1.3, current, of the hash of
    /// `suite` and of the name asked for now, with a key exchange mode both
    /// allow. Its binder must verify over `prefix` (the messages before the
    /// ClientHello) and the ClientHello `message`: `decrypt_error` otherwise.
    /// A `pre_shared_key` without `psk_key_exchange_modes` is
    /// `missing_extension`.
    pub fn resume(
        config: &TLSServerConfig,
        hello: &TLSClientHello,
        message: &[u8],
        prefix: &TLSTranscript,
        suite: TLSCipherSuite,
        context: &mut TLSContext<'_>,
    ) -> Result<Option<TLS13PSKSelection>, TLSError> {
        let Some(data) = hello.extension(TLSExtensionType::PRE_SHARED_KEY) else { return Ok(None) };
        let TLSPreSharedKey::Offered { identities, binders } =
            TLSPreSharedKey::decode(data, TLSExtensionContext::ClientHello)?
        else {
            return Err(TLSError::decode());
        };
        let modes = hello
            .extension(TLSExtensionType::PSK_KEY_EXCHANGE_MODES)
            .ok_or(TLSError::Protocol(TLSAlertDescription::MISSING_EXTENSION))
            .and_then(TLSPSKMode::decode_list)?;
        let Some(ticketer) = &config.tickets else { return Ok(None) };
        let Some(mode) = config.config.psk_modes.iter().copied().find(|mode| modes.contains(mode)) else {
            return Ok(None);
        };
        let name = TLSServerStart::requested_name(hello)?;
        for (index, identity) in identities.iter().enumerate() {
            let Some(state) = ticketer.open(&identity.identity).and_then(|bytes| TLSSessionState::decode(&bytes).ok())
            else {
                continue;
            };
            // A server that requires client certificates resumes only sessions that had one.
            let authenticated = config.client_authentication != TLSClientAuthentication::Required
                || !state.peer_certificates.is_empty();
            let usable = state.version == TLSVersion::TLS1_3
                && state.cipher_suite.hash() == suite.hash()
                && state.is_current(context.session.time)
                && state.server_name == name
                && authenticated;
            if !usable {
                continue;
            }
            let length = TLSPreSharedKey::binders_length(&binders);
            let hash = TLS13Resumption::binder_hash(&state, prefix, message, length)?;
            let expected = TLS13Resumption::binder(&state, &hash)?;
            let binder = &binders[index];
            if binder.len() != expected.len() || !binder.ct_eq(expected.as_slice()).into_bool() {
                return Err(TLSError::Protocol(TLSAlertDescription::DECRYPT_ERROR));
            }
            return Ok(Some(TLS13PSKSelection {
                index: index as u16,
                state,
                binder: binder.clone(),
                obfuscated_age: identity.obfuscated_ticket_age,
                mode,
            }));
        }
        Ok(None)
    }

    /// How much refused early data is skipped (RFC 9846 §4.2.10): what this
    /// server allows, or what the ticket offered allowed if more (it may
    /// date from another configuration).
    pub fn skippable(config: &TLSServerConfig, psk: Option<&TLS13PSKSelection>) -> usize {
        let ticket = psk.map_or(0, |psk| psk.state.maximum_early_data);
        config.maximum_early_data.max(ticket) as usize
    }

    /// The checks of a TLS 1.3 ClientHello (RFC 9846 §4.2.2, §4.3):
    /// `legacy_version` 0x0303 (`protocol_version`), compression exactly
    /// null (`illegal_parameter`), and the extensions allowed there.
    pub fn check(hello: &TLSClientHello) -> Result<(), TLSError> {
        if hello.legacy_version != TLSVersion::TLS1_2 {
            return Err(TLSError::Protocol(TLSAlertDescription::PROTOCOL_VERSION));
        }
        if hello.legacy_compression_methods != [0] {
            return Err(TLSError::illegal());
        }
        TLSExtension::check(&hello.extensions, TLSExtensionContext::ClientHello)
    }

    /// The cipher suite, group and certificate for `hello` (RFC 9846
    /// §4.2.1). With `retry`, the group of a HelloRetryRequest, whose share
    /// the client must now have sent (`illegal_parameter`). Without a
    /// `pre_shared_key`, `supported_groups`, `key_share` and
    /// `signature_algorithms` are required (`missing_extension`, §9.2).
    pub fn select(
        config: &TLSServerConfig,
        hello: &TLSClientHello,
        retry: Option<TLSNamedGroup>,
    ) -> Result<TLS13Selection, TLSError> {
        let missing = TLSError::Protocol(TLSAlertDescription::MISSING_EXTENSION);
        let failure = TLSError::Protocol(TLSAlertDescription::HANDSHAKE_FAILURE);
        let usable = |suite: &TLSCipherSuite| {
            suite.version() == Some(TLSVersion::TLS1_3)
                && suite.aead().is_some_and(TLSAEAD::supports)
                && config.config.cipher_suites.contains(suite)
                && hello.cipher_suites.contains(suite)
        };
        let suite = if config.prefer_own_cipher_suites {
            config.config.cipher_suites.iter().copied().find(usable)
        } else {
            hello.cipher_suites.iter().copied().find(usable)
        }
        .ok_or(failure)?;
        let resuming = hello.extension(TLSExtensionType::PRE_SHARED_KEY).is_some();
        let required = |kind: TLSExtensionType| match hello.extension(kind) {
            Some(data) => Ok(Some(data)),
            None if resuming => Ok(None),
            None => Err(missing),
        };
        let groups = required(TLSExtensionType::SUPPORTED_GROUPS)?
            .map(TLSSupportedGroups::decode)
            .transpose()?
            .unwrap_or_default();
        let shares = match required(TLSExtensionType::KEY_SHARE)? {
            Some(data) => {
                let TLSKeyShare::Client(shares) = TLSKeyShare::decode(data, TLSExtensionContext::ClientHello)? else {
                    return Err(TLSError::decode());
                };
                shares
            }
            None => Vec::new(),
        };
        // A share must be of a group the client supports (RFC 9846 §4.3.8);
        // both lists are the peer's, so the check is not quadratic.
        let mut supported: Vec<u16> = groups.groups.iter().map(|group| group.0).collect();
        supported.sort_unstable();
        if shares.iter().any(|share| supported.binary_search(&share.group.0).is_err()) {
            return Err(TLSError::illegal());
        }
        let schemes = required(TLSExtensionType::SIGNATURE_ALGORITHMS)?
            .map(TLSSignatureSchemes::decode)
            .transpose()?
            .unwrap_or_default();
        let ours = |group: &TLSNamedGroup| {
            group.usable_with(TLSVersion::TLS1_3)
                && TLSKeyShareSecret::supports(*group)
                && groups.groups.contains(group)
        };
        let shared = |group: &TLSNamedGroup| {
            shares.iter().find(|share| share.group == *group).map(|share| share.key_exchange.clone())
        };
        let (group, share) = match retry {
            Some(group) => match shares.as_slice() {
                [only] if only.group == group => (Some(group), Some(only.key_exchange.clone())),
                _ => return Err(TLSError::illegal()),
            },
            None => match config
                .config
                .groups
                .iter()
                .filter(|group| ours(group))
                .find_map(|group| Some((*group, shared(group)?)))
            {
                Some((group, share)) => (Some(group), Some(share)),
                None => (config.config.groups.iter().copied().find(|group| ours(group)), None),
            },
        };
        let identity = TLSServerStart::requested_name(hello)?.map(ServiceIdentity::DNS);
        let fits = |key: &Arc<TLSCertifiedKey>| {
            key.scheme(&schemes.schemes, &config.config.signature_schemes, TLSVersion::TLS1_3)
                .map(|scheme| (key.clone(), scheme))
        };
        let named = identity
            .as_ref()
            .and_then(|identity| config.certificates.iter().filter(|key| key.names(identity)).find_map(fits));
        let (certificate, named) = match named {
            Some(chosen) => (Some(chosen), true),
            None => (config.certificates.iter().find_map(fits), false),
        };
        Ok(TLS13Selection { suite, group, share, certificate, named })
    }

    /// Sends the HelloRetryRequest for `group` (RFC 9846 §4.2.4), and the
    /// dummy ChangeCipherSpec after it in compatibility mode.
    pub fn send_retry(&mut self, group: TLSNamedGroup, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let versions = TLSSupportedVersions::Selected(TLSVersion::TLS1_3);
        let share = TLSKeyShare::Retry(group);
        let retry = TLSServerHello {
            legacy_version: TLSVersion::TLS1_2,
            random: TLSServerHello::RETRY_RANDOM,
            legacy_session_id_echo: self.hello.legacy_session_id.clone(),
            cipher_suite: self.suite,
            legacy_compression_method: 0,
            extensions: vec![
                TLSExtension::with(TLSExtensionType::SUPPORTED_VERSIONS, |data| versions.encode(data))?,
                TLSExtension::with(TLSExtensionType::KEY_SHARE, |data| share.encode(data))?,
            ],
        };
        // The confirmation of ECH, in an extension of its own (RFC 9849 §7.2.1).
        let mut retry = retry;
        if self.ech.is_some() {
            retry.extensions.push(TLSExtension::new(TLSExtensionType::ENCRYPTED_CLIENT_HELLO, vec![0; 8]));
            let confirmation =
                TLSECH::retry_confirmation(&self.transcript, self.schedule.hash, &self.hello.random, &retry)?;
            if let Some(extension) = retry.extensions.last_mut() {
                extension.data = confirmation.to_vec();
            }
        }
        let message = TLSHandshake::new(TLSHandshakeType::SERVER_HELLO, retry.to_bytes()?);
        self.transcript.restart_after_retry(self.schedule.hash);
        self.transcript.update(&context.layer.write_handshake(&message)?);
        self.send_change_cipher_spec(context)?;
        self.state = TLS13ServerState::RetryClientHello(group);
        Ok(())
    }

    /// The dummy ChangeCipherSpec after the server's first handshake
    /// message, when the client's session ID says it is in compatibility
    /// mode (RFC 9846 Appendix E.4).
    pub fn send_change_cipher_spec(&mut self, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        if !self.sent_change_cipher_spec && !self.hello.legacy_session_id.is_empty() {
            context.layer.write_record(TLSContentType::CHANGE_CIPHER_SPEC, &[1])?;
            self.sent_change_cipher_spec = true;
        }
        Ok(())
    }

    /// The server's flight: ServerHello, EncryptedExtensions, an optional
    /// CertificateRequest, Certificate, CertificateVerify and Finished
    /// (RFC 9846 §2), and the keys of every stage; with `psk`, a resumption
    /// without certificates (§2.2), which may accept early data when
    /// `first` (no HelloRetryRequest was sent, §4.2.10).
    pub fn respond(
        &mut self,
        hello: &TLSClientHello,
        selection: TLS13Selection,
        psk: Option<TLS13PSKSelection>,
        first: bool,
        context: &mut TLSContext<'_>,
    ) -> Result<(), TLSError> {
        let versions = TLSSupportedVersions::Selected(TLSVersion::TLS1_3);
        let mut extensions =
            vec![TLSExtension::with(TLSExtensionType::SUPPORTED_VERSIONS, |data| versions.encode(data))?];
        let dhe = psk.as_ref().is_none_or(|psk| psk.mode == TLSPSKMode::PSK_DHE_KE);
        let failure = TLSError::Protocol(TLSAlertDescription::HANDSHAKE_FAILURE);
        let shared = if dhe {
            let (Some(group), Some(share)) = (selection.group, selection.share.as_deref()) else { return Err(failure) };
            let (key_exchange, shared) = TLSKeyShareSecret::respond(group, share, &mut &mut *context.random)?;
            let share = TLSKeyShare::Server(TLSKeyShareEntry { group, key_exchange });
            extensions.push(TLSExtension::with(TLSExtensionType::KEY_SHARE, |data| share.encode(data))?);
            context.session.group = Some(group);
            shared
        } else {
            Secret::new(Vec::new())
        };
        if let Some(psk) = &psk {
            let selected = TLSPreSharedKey::Selected(psk.index);
            extensions.push(TLSExtension::with(TLSExtensionType::PRE_SHARED_KEY, |data| selected.encode(data))?);
        }
        // Early data: with the first PSK, of the same suite, fresh, enabled
        // on both sides; the protocol and replays are checked with the
        // EncryptedExtensions (RFC 9846 §4.2.10, §8).
        let offered_early = hello.extension(TLSExtensionType::EARLY_DATA).is_some();
        let early_candidate = psk.as_ref().filter(|psk| {
            offered_early
                && first
                && psk.index == 0
                && self.config.maximum_early_data > 0
                && psk.state.maximum_early_data > 0
                && psk.state.cipher_suite == self.suite
                && psk.state.is_fresh(psk.obfuscated_age, context.session.time, self.config.freshness_window)
        });
        let early_traffic = match early_candidate {
            Some(psk) => Some(TLS13Resumption::early_traffic_secret(&psk.state, &self.transcript)?),
            None => None,
        };
        let mut random = [0u8; 32];
        context.random.fill(&mut random).map_err(|_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR))?;
        let mut server_hello = TLSServerHello {
            legacy_version: TLSVersion::TLS1_2,
            random,
            legacy_session_id_echo: hello.legacy_session_id.clone(),
            cipher_suite: self.suite,
            legacy_compression_method: 0,
            extensions,
        };
        // The confirmation of ECH in the random's last 8 bytes (RFC 9849 §7.2).
        if self.ech.is_some() {
            let message = TLSHandshake::new(TLSHandshakeType::SERVER_HELLO, server_hello.to_bytes()?).to_bytes()?;
            let confirmation =
                TLSECH::server_hello_confirmation(&self.transcript, self.schedule.hash, &hello.random, &message)?;
            server_hello.random[24..].copy_from_slice(&confirmation);
        }
        let message = TLSHandshake::new(TLSHandshakeType::SERVER_HELLO, server_hello.to_bytes()?);
        self.transcript.update(&context.layer.write_handshake(&message)?);
        self.send_change_cipher_spec(context)?;
        let early = self.schedule.early_secret(psk.as_ref().map(|psk| psk.state.psk.expose().as_slice()));
        let handshake_secret = self.schedule.next_secret(early.expose(), shared.expose())?;
        let transcript_hash = self.transcript.hash();
        self.client_handshake =
            self.schedule.derive_secret(handshake_secret.expose(), b"c hs traffic", &transcript_hash)?;
        let server_handshake =
            self.schedule.derive_secret(handshake_secret.expose(), b"s hs traffic", &transcript_hash)?;
        let (schedule, aead) = (self.schedule, self.aead);
        TLS13Authentication::install(
            context.layer,
            TLSDirection::Writing,
            TLSEncryptionLevel::Handshake,
            &schedule,
            aead,
            server_handshake.expose(),
        )?;
        let secret = self.client_handshake.expose();
        TLS13Authentication::install(
            context.layer,
            TLSDirection::Reading,
            TLSEncryptionLevel::Handshake,
            &schedule,
            aead,
            secret,
        )?;
        context.session.cipher_suite = Some(self.suite);
        if let Some(psk) = &psk {
            self.resumed = true;
            context.session.resumed = true;
            context.session.peer_certificates = psk.state.peer_certificates.clone();
        }
        // The name is acknowledged when it chose the certificate (RFC 6066 §3).
        let named = selection.named && !self.resumed;
        let accepted = self.send_encrypted_extensions(hello, named, early_candidate, context)?;
        context.session.early_data = match (offered_early, accepted) {
            (false, _) => TLSEarlyData::NotOffered,
            (true, true) => TLSEarlyData::Accepted,
            (true, false) => TLSEarlyData::Rejected,
        };
        // A resumption authenticates with its PSK (RFC 9846 §4.3.2: no CertificateRequest either).
        let request = !self.resumed && self.config.client_authentication != TLSClientAuthentication::Off;
        if request {
            let schemes = TLSSignatureSchemes { schemes: self.config.config.signature_schemes.clone() };
            let request = TLS13CertificateRequest {
                context: Vec::new(),
                extensions: vec![TLSExtension::with(TLSExtensionType::SIGNATURE_ALGORITHMS, |data| {
                    schemes.encode(data)
                })?],
            };
            let message = TLSHandshake::with(TLSHandshakeType::CERTIFICATE_REQUEST, |body| request.encode(body))?;
            self.transcript.update(&context.layer.write_handshake(&message)?);
        }
        // A stapled OCSP response if the client asked for one (RFC 9846 §4.5.1.1, RFC 6066 §8).
        let status = match hello.extension(TLSExtensionType::STATUS_REQUEST) {
            Some(data) => matches!(TLSCertificateStatus::decode(data, false), Ok(TLSCertificateStatus::Request { .. })),
            None => false,
        };
        if !self.resumed {
            let (certificate, scheme) = selection.certificate.as_ref().ok_or(failure)?;
            TLS13Authentication::send(
                Some(certificate),
                Some(*scheme),
                &[],
                status,
                true,
                &mut self.transcript,
                context,
            )?;
        }
        TLS13Authentication::send_finished(&self.schedule, server_handshake.expose(), &mut self.transcript, context)?;
        self.main = self.schedule.next_secret(handshake_secret.expose(), &[])?;
        let transcript_hash = self.transcript.hash();
        self.client_application = self.schedule.derive_secret(self.main.expose(), b"c ap traffic", &transcript_hash)?;
        self.server_application = self.schedule.derive_secret(self.main.expose(), b"s ap traffic", &transcript_hash)?;
        self.exporter = self.schedule.derive_secret(self.main.expose(), b"exp master", &transcript_hash)?;
        let secret = self.server_application.expose();
        TLS13Authentication::install(
            context.layer,
            TLSDirection::Writing,
            TLSEncryptionLevel::Application,
            &schedule,
            aead,
            secret,
        )?;
        self.state = if request { TLS13ServerState::Certificate } else { TLS13ServerState::Finished };
        match early_traffic.filter(|_| accepted) {
            // QUIC reads early data from its own packets: no EndOfEarlyData (RFC 9001 §8.3).
            Some(secret) if context.layer.quic.is_some() => {
                TLS13Authentication::install(
                    context.layer,
                    TLSDirection::Reading,
                    TLSEncryptionLevel::EarlyData,
                    &schedule,
                    aead,
                    secret.expose(),
                )?;
            }
            Some(secret) => {
                TLS13Authentication::install(
                    context.layer,
                    TLSDirection::Reading,
                    TLSEncryptionLevel::EarlyData,
                    &schedule,
                    aead,
                    secret.expose(),
                )?;
                // As much as the ticket promised (RFC 9846 §4.6.1), in records the
                // client sized before it saw this server's record_size_limit.
                self.early_data = psk.as_ref().map_or(0, |psk| psk.state.maximum_early_data as usize);
                self.deferred_limit = Some(context.layer.own_limit);
                context.layer.own_limit = TLSRecordHeader::MAXIMUM_PLAINTEXT;
                self.state = TLS13ServerState::EndOfEarlyData;
            }
            // Refused early data is skipped: it does not decrypt (RFC 9846 §4.2.10).
            None if offered_early => context.layer.skippable = TLS13Server::skippable(&self.config, psk.as_ref()),
            None => {}
        }
        Ok(())
    }

    /// EncryptedExtensions: the protocol chosen (ALPN, RFC 7301 §3.2:
    /// `no_application_protocol` without one in common), the
    /// acknowledgment of `server_name` when it chose the certificate
    /// (RFC 6066 §3), `record_size_limit`, and `early_data` when the early
    /// data of `early` is accepted: of the session's protocol, and not a
    /// replay (RFC 9846 §4.2.10, §8). Returns whether it is.
    pub fn send_encrypted_extensions(
        &mut self,
        hello: &TLSClientHello,
        named: bool,
        early: Option<&TLS13PSKSelection>,
        context: &mut TLSContext<'_>,
    ) -> Result<bool, TLSError> {
        // The name asked for, acknowledged when it chose the certificate (RFC 6066 §3).
        context.session.server_name = TLSServerStart::requested_name(hello)?;
        let mut extensions = Vec::new();
        if named {
            extensions.push(TLSExtension::new(TLSExtensionType::SERVER_NAME, Vec::new()));
        }
        if let Some(data) = hello.extension(TLSExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
            && !self.config.config.protocols.is_empty()
        {
            let offered = TLSProtocolNames::decode(data)?;
            let protocol = self
                .config
                .config
                .protocols
                .iter()
                .find(|protocol| offered.names.contains(protocol))
                .ok_or(TLSError::Protocol(TLSAlertDescription::NO_APPLICATION_PROTOCOL))?;
            let selected = TLSProtocolNames { names: vec![protocol.clone()] };
            extensions.push(TLSExtension::with(TLSExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION, |out| {
                selected.encode(out)
            })?);
            context.session.protocol = Some(protocol.clone());
        }
        match &context.layer.quic {
            // QUIC: a protocol, and this end's transport parameters (RFC 9001 §8.1, §8.2).
            Some(quic) => {
                if context.session.protocol.is_none() {
                    return Err(TLSError::Protocol(TLSAlertDescription::NO_APPLICATION_PROTOCOL));
                }
                let parameters = quic.transport_parameters.clone();
                extensions.push(TLSExtension::new(TLSExtensionType::QUIC_TRANSPORT_PARAMETERS, parameters));
            }
            None => extensions.extend(TLSServerStart::limit_records(
                &self.config.config,
                hello,
                TLSVersion::TLS1_3,
                context,
            )?),
        }
        // The retry configurations, to a client whose ECH this server did not accept (RFC 9849 §7.1).
        if matches!(context.session.ech, TLSECHStatus::Rejected { .. }) {
            extensions.extend(TLSECH::retry_extension(&self.config.ech_keys)?);
        }
        let accepted = early.is_some_and(|psk| {
            psk.state.protocol == context.session.protocol
                && psk.state.application == context.session.application
                && self
                    .config
                    .anti_replay
                    .as_ref()
                    .is_some_and(|anti_replay| anti_replay.accept(&psk.binder, context.session.time))
        });
        if accepted {
            extensions.push(TLSExtension::new(TLSExtensionType::EARLY_DATA, Vec::new()));
        }
        let encrypted = TLS13EncryptedExtensions { extensions };
        let message = TLSHandshake::with(TLSHandshakeType::ENCRYPTED_EXTENSIONS, |body| encrypted.encode(body))?;
        self.transcript.update(&context.layer.write_handshake(&message)?);
        Ok(accepted)
    }

    /// The tickets sent after the handshake (RFC 9846 §4.6.1): `ticket_count`
    /// of them, each of its own nonce and PSK, when the server makes tickets
    /// and the client sent `psk_key_exchange_modes`.
    pub fn send_tickets(&self, resumption: &[u8], context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let Some(ticketer) = &self.config.tickets else { return Ok(()) };
        if self.hello.extension(TLSExtensionType::PSK_KEY_EXCHANGE_MODES).is_none() {
            return Ok(());
        }
        let internal = |_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR);
        let server_name = TLSServerStart::requested_name(&self.hello)?;
        // QUIC's sentinel stands for any amount: its own limits apply (RFC 9001 §4.6.1).
        let maximum_early_data = match self.config.maximum_early_data {
            0 => 0,
            _ if context.layer.quic.is_some() => TLSQUIC::EARLY_DATA,
            maximum => maximum,
        };
        for index in 0..self.config.ticket_count {
            let nonce = (index as u64).to_be_bytes().to_vec();
            let state = TLSSessionState {
                version: TLSVersion::TLS1_3,
                cipher_suite: self.suite,
                psk: self.schedule.resumption_psk(resumption, &nonce)?,
                time: context.session.time,
                lifetime: self.config.ticket_lifetime,
                age_add: context.random.next_u32().map_err(internal)?,
                maximum_early_data,
                protocol: context.session.protocol.clone(),
                server_name: server_name.clone(),
                peer_certificates: context.session.peer_certificates.clone(),
                application: context.session.application.clone(),
            };
            let mut bytes = Vec::new();
            state.encode(&mut bytes)?;
            let Some(ticket) = ticketer.seal(&bytes, &mut *context.random) else { return Ok(()) };
            let mut extensions = Vec::new();
            if maximum_early_data > 0 {
                let indication = TLSEarlyDataIndication(maximum_early_data);
                extensions.push(TLSExtension::with(TLSExtensionType::EARLY_DATA, |data| indication.encode(data))?);
            }
            let ticket =
                TLS13NewSessionTicket { lifetime: state.lifetime, age_add: state.age_add, nonce, ticket, extensions };
            context.layer.write_handshake(&TLSHandshake::with(TLSHandshakeType::NEW_SESSION_TICKET, |body| {
                ticket.encode(body)
            })?)?;
        }
        Ok(())
    }

    /// The client's Finished: the handshake completes (RFC 9846 §4.5.3).
    pub fn receive_finished(
        mut self: Box<Self>,
        message: &TLSHandshake,
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        TLS13Authentication::receive_finished(
            &self.schedule,
            self.client_handshake.expose(),
            &message.body,
            &self.transcript,
        )?;
        context.layer.check_boundary()?;
        self.transcript.update(&message.to_bytes()?);
        let resumption = self.schedule.derive_secret(self.main.expose(), b"res master", &self.transcript.hash())?;
        let secret = self.client_application.expose();
        TLS13Authentication::install(
            context.layer,
            TLSDirection::Reading,
            TLSEncryptionLevel::Application,
            &self.schedule,
            self.aead,
            secret,
        )?;
        context.events.push_back(TLSEvent::Connected);
        self.send_tickets(resumption.expose(), context)?;
        Ok(Box::new(TLS13Established {
            role: TLSRole::Server,
            schedule: self.schedule,
            aead: self.aead,
            sending: core::mem::take(&mut self.server_application),
            receiving: core::mem::take(&mut self.client_application),
            exporter: core::mem::take(&mut self.exporter),
            resumption,
            key_updates: 0,
            maximum_key_updates: self.config.config.maximum_key_updates,
            // QUIC has no post-handshake authentication (RFC 9001 §4.4).
            post_handshake: match &self.config.client_verifier {
                Some(verifier)
                    if self.hello.extension(TLSExtensionType::POST_HANDSHAKE_AUTH).is_some()
                        && context.layer.quic.is_none() =>
                {
                    TLS13PostHandshake::Server(Box::new(TLS13Authenticator {
                        verifier: verifier.clone(),
                        schemes: self.config.config.signature_schemes.clone(),
                        pending: None,
                    }))
                }
                _ => TLS13PostHandshake::Off,
            },
            transcript: self.transcript,
            sessions: None,
        }))
    }
}

impl TLSHandshakeProtocol for TLS13Server {
    fn receive(
        mut self: Box<Self>,
        message: TLSHandshake,
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        match (self.state, message.kind) {
            (TLS13ServerState::RetryClientHello(group), TLSHandshakeType::CLIENT_HELLO) => {
                context.layer.check_boundary()?;
                let mut hello = TLSClientHello::decode(&message.body)?;
                let mut bytes = message.to_bytes()?;
                // With ECH accepted, the second ClientHelloInner of the second ClientHelloOuter (RFC 9849 §7.1.1).
                if let Some(ech) = &mut self.ech {
                    hello = ech.open_again(&hello)?;
                    bytes = TLSHandshake::new(TLSHandshakeType::CLIENT_HELLO, hello.to_bytes()?).to_bytes()?;
                }
                TLS13Server::check(&hello)?;
                // The transport's rules again, and the same transport
                // parameters, which a second ClientHello may not change (RFC 9846 §4.1.2).
                let first = context.session.transport_parameters.clone();
                TLSServerStart::check_transport(&hello, TLSVersion::TLS1_3, context)?;
                if context.session.transport_parameters != first {
                    return Err(TLSError::illegal());
                }
                // The second ClientHello keeps the session ID and the suite,
                // and offers no early data (RFC 9846 §4.2.2, §4.2.4, §4.2.10).
                let selection = TLS13Server::select(&self.config, &hello, Some(group))?;
                if hello.legacy_session_id != self.hello.legacy_session_id
                    || selection.suite != self.suite
                    || hello.extension(TLSExtensionType::EARLY_DATA).is_some()
                {
                    return Err(TLSError::illegal());
                }
                // The early data of the first ClientHello came before this one.
                context.layer.skippable = 0;
                let psk = TLS13Server::resume(&self.config, &hello, &bytes, &self.transcript, self.suite, context)?;
                self.transcript.update(&bytes);
                self.respond(&hello, selection, psk, false, context)?;
                return Ok(self);
            }
            (TLS13ServerState::EndOfEarlyData, TLSHandshakeType::END_OF_EARLY_DATA) => {
                // It ends the early data and its keys (RFC 9846 §4.5).
                if !message.body.is_empty() {
                    return Err(TLSError::decode());
                }
                context.layer.check_boundary()?;
                let secret = self.client_handshake.expose();
                TLS13Authentication::install(
                    context.layer,
                    TLSDirection::Reading,
                    TLSEncryptionLevel::Handshake,
                    &self.schedule,
                    self.aead,
                    secret,
                )?;
                if let Some(limit) = self.deferred_limit.take() {
                    context.layer.own_limit = limit;
                }
                self.state = TLS13ServerState::Finished;
            }
            (TLS13ServerState::Certificate, TLSHandshakeType::CERTIFICATE) => {
                let verifier = self.config.client_verifier.clone().ok_or(TLSError::State)?;
                let chain = TLS13Authentication::receive_certificate(
                    &message.body,
                    &[],
                    false,
                    verifier.as_ref(),
                    None,
                    context.session.time,
                )?
                .chain;
                if chain.is_empty() && self.config.client_authentication == TLSClientAuthentication::Required {
                    return Err(TLSError::Protocol(TLSAlertDescription::CERTIFICATE_REQUIRED));
                }
                self.state =
                    if chain.is_empty() { TLS13ServerState::Finished } else { TLS13ServerState::CertificateVerify };
                context.session.peer_certificates = chain.clone();
                self.chain = chain;
            }
            (TLS13ServerState::CertificateVerify, TLSHandshakeType::CERTIFICATE_VERIFY) => {
                let scheme = TLS13Authentication::receive_verify(
                    &message.body,
                    &self.chain,
                    &self.config.config.signature_schemes,
                    false,
                    &self.transcript,
                )?;
                context.session.peer_signature_scheme = Some(scheme);
                self.state = TLS13ServerState::Finished;
            }
            (TLS13ServerState::Finished, TLSHandshakeType::FINISHED) => {
                return self.receive_finished(&message, context);
            }
            _ => return Err(TLSError::unexpected()),
        }
        self.transcript.update(&message.to_bytes()?);
        Ok(self)
    }

    /// The client's dummy ChangeCipherSpec, `0x01`, is dropped until its
    /// Finished (RFC 9846 §5).
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

    /// Early data, until EndOfEarlyData and within `maximum_early_data`
    /// (`unexpected_message` beyond, RFC 9846 §4.2.10).
    fn receive_early_data(&mut self, length: usize) -> Result<(), TLSError> {
        if self.state != TLS13ServerState::EndOfEarlyData {
            return Err(TLSError::unexpected());
        }
        self.early_data = self.early_data.checked_sub(length).ok_or(TLSError::unexpected())?;
        Ok(())
    }
}
