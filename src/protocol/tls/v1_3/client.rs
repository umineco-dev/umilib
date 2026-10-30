use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::protocol::tls::{
    TLSAEAD, TLSAEADAlgorithm, TLSAlertDescription, TLSClientStart, TLSContext, TLSDirection, TLSECH, TLSECHStatus,
    TLSEarlyData, TLSEncryptionLevel, TLSError, TLSEvent, TLSExtension, TLSExtensionContext, TLSExtensionType,
    TLSHandshake, TLSHandshakeProtocol, TLSHandshakeType, TLSKeyShare, TLSOpaqueExtension, TLSPSKMode, TLSPreSharedKey,
    TLSRole, TLSServerHello, TLSSignatureSchemes, TLSVersion,
};
use crate::secret::Secret;

use super::{
    TLS13Authentication, TLS13CertificateRequest, TLS13EncryptedExtensions, TLS13Established, TLS13KeySchedule,
    TLS13PostHandshake, TLS13ReceivedCertificate,
};

/// What a TLS 1.3 client waits for after the ServerHello (RFC 9846 Appendix A.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLS13ClientState {
    EncryptedExtensions,
    CertificateOrRequest,
    Certificate,
    CertificateVerify,
    Finished,
}

/// A TLS 1.3 client from the ServerHello to its own Finished (RFC 9846 §4).
pub struct TLS13Client {
    pub start: TLSClientStart,
    pub state: TLS13ClientState,
    pub schedule: TLS13KeySchedule,
    pub aead: TLSAEADAlgorithm,
    pub handshake_secret: Secret<Vec<u8>>,
    pub client_handshake: Secret<Vec<u8>>,
    pub server_handshake: Secret<Vec<u8>>,
    /// The CertificateRequest, if the server sent one.
    pub request: Option<TLS13CertificateRequest>,
    pub chain: Vec<Vec<u8>>,
    /// Whether the server accepted the PSK offered: no certificates follow.
    pub resumed: bool,
    /// Whether early data was offered with the ClientHello this ServerHello
    /// answers: its keys write until the server's Finished.
    pub early: bool,
}

impl TLS13Client {
    /// Takes the ServerHello of TLS 1.3 (RFC 9846 §4.2.3): checks it, agrees
    /// on the shared secret, and installs the handshake keys.
    pub fn from_server_hello(
        mut start: TLSClientStart,
        hello: TLSServerHello,
        bytes: &[u8],
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        if hello.legacy_version != TLSVersion::TLS1_2 {
            return Err(TLSError::Protocol(TLSAlertDescription::PROTOCOL_VERSION));
        }
        start.check_server_hello(&hello, TLSExtensionContext::ServerHello)?;
        let suite = hello.cipher_suite;
        let (Some(hash), Some(aead)) = (suite.hash(), suite.aead()) else { return Err(TLSError::illegal()) };
        if !TLSAEAD::supports(aead) {
            return Err(TLSError::illegal());
        }
        // The PSK the server chose: the one offered, of the suite's hash (RFC 9846 §4.2.11).
        let psk = match hello.extension(TLSExtensionType::PRE_SHARED_KEY) {
            Some(data) => {
                let TLSPreSharedKey::Selected(index) = TLSPreSharedKey::decode(data, TLSExtensionContext::ServerHello)?
                else {
                    return Err(TLSError::decode());
                };
                let ticket = start.resumption.as_ref().filter(|_| index == 0).ok_or(TLSError::illegal())?;
                if ticket.state.cipher_suite.hash() != Some(hash) {
                    return Err(TLSError::illegal());
                }
                Some(ticket.state.psk.clone())
            }
            None => None,
        };
        // The server's key share: required without a PSK (RFC 9846 §9.2), and
        // with one unless the client allowed psk_ke (§4.2.11).
        let shared = match hello.extension(TLSExtensionType::KEY_SHARE) {
            Some(data) => {
                let TLSKeyShare::Server(entry) = TLSKeyShare::decode(data, TLSExtensionContext::ServerHello)? else {
                    return Err(TLSError::decode());
                };
                let secret =
                    start.shares.iter().find(|share| share.group() == entry.group).ok_or(TLSError::illegal())?;
                context.session.group = Some(entry.group);
                secret.complete(&entry.key_exchange)?
            }
            None if psk.is_some() && start.config.config.psk_modes.contains(&TLSPSKMode::PSK_KE) => {
                Secret::new(Vec::new())
            }
            None if psk.is_some() => return Err(TLSError::illegal()),
            None => return Err(TLSError::Protocol(TLSAlertDescription::MISSING_EXTENSION)),
        };
        start.shares.clear();
        start.transcript.select(hash);
        start.transcript.update(bytes);
        let schedule = TLS13KeySchedule::new(hash);
        let early = schedule.early_secret(psk.as_ref().map(|psk| psk.expose().as_slice()));
        let handshake_secret = schedule.next_secret(early.expose(), shared.expose())?;
        let transcript_hash = start.transcript.hash();
        let client_handshake = schedule.derive_secret(handshake_secret.expose(), b"c hs traffic", &transcript_hash)?;
        let server_handshake = schedule.derive_secret(handshake_secret.expose(), b"s hs traffic", &transcript_hash)?;
        let layer = &mut *context.layer;
        TLS13Authentication::install(
            layer,
            TLSDirection::Reading,
            TLSEncryptionLevel::Handshake,
            &schedule,
            aead,
            server_handshake.expose(),
        )?;
        // Early data keeps its keys until the server's Finished (RFC 9846
        // §4.2.10); QUIC has its own packets for it (RFC 9001 §8.3).
        let early = context.session.early_data == TLSEarlyData::Offered;
        if !early || layer.quic.is_some() {
            TLS13Authentication::install(
                layer,
                TLSDirection::Writing,
                TLSEncryptionLevel::Handshake,
                &schedule,
                aead,
                client_handshake.expose(),
            )?;
        }
        context.session.cipher_suite = Some(suite);
        let resumed = psk.is_some();
        if let Some(ticket) = start.resumption.as_ref().filter(|_| resumed) {
            context.session.resumed = true;
            context.session.peer_certificates = ticket.state.peer_certificates.clone();
        }
        Ok(Box::new(TLS13Client {
            start,
            state: TLS13ClientState::EncryptedExtensions,
            schedule,
            aead,
            handshake_secret,
            client_handshake,
            server_handshake,
            request: None,
            chain: Vec::new(),
            resumed,
            early,
        }))
    }

    /// EncryptedExtensions (RFC 9846 §4.4.1): only extensions the client
    /// asked for (`unsupported_extension`) and allowed there (`illegal_parameter`).
    pub fn receive_encrypted_extensions(&mut self, body: &[u8], context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let extensions = TLS13EncryptedExtensions::decode(body)?;
        TLSExtension::check(&extensions.extensions, TLSExtensionContext::EncryptedExtensions)?;
        for extension in &extensions.extensions {
            if self.start.hello.extension(extension.kind).is_none() {
                return Err(TLSError::Protocol(TLSAlertDescription::UNSUPPORTED_EXTENSION));
            }
            match extension.kind {
                TLSExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                    context.session.protocol = Some(self.start.protocol(&extension.data)?);
                }
                TLSExtensionType::SERVER_NAME => TLSOpaqueExtension::decode_empty(&extension.data)?,
                TLSExtensionType::QUIC_TRANSPORT_PARAMETERS => {
                    context.session.transport_parameters = Some(extension.data.clone());
                }
                TLSExtensionType::RECORD_SIZE_LIMIT => {
                    self.start.limit_records(&extension.data, TLSVersion::TLS1_3, context)?;
                }
                // Retry configurations only when the server used the
                // ClientHelloOuter, or a GREASE one (RFC 9849 §5, §6.1.6, §6.2.1).
                TLSExtensionType::ENCRYPTED_CLIENT_HELLO => {
                    TLSECH::check_retry_configs(&extension.data)?;
                    match context.session.ech {
                        _ if self.start.ech_rejected => self.start.ech_retry_configs = Some(extension.data.clone()),
                        TLSECHStatus::Grease => {}
                        _ => return Err(TLSError::Protocol(TLSAlertDescription::UNSUPPORTED_EXTENSION)),
                    }
                }
                // Early data is accepted only with the first PSK, of the ticket's suite (RFC 9846 §4.2.10).
                TLSExtensionType::EARLY_DATA => {
                    TLSOpaqueExtension::decode_empty(&extension.data)?;
                    let suite = self.start.resumption.as_ref().map(|ticket| ticket.state.cipher_suite);
                    if !self.resumed || !self.early || suite != context.session.cipher_suite {
                        return Err(TLSError::illegal());
                    }
                    context.session.early_data = TLSEarlyData::Accepted;
                }
                _ => {}
            }
        }
        if context.session.early_data == TLSEarlyData::Offered {
            context.session.early_data = TLSEarlyData::Rejected;
        }
        // QUIC needs the server's transport parameters and a protocol (RFC 9001 §8.1, §8.2).
        if context.layer.quic.is_some() {
            if context.session.transport_parameters.is_none() {
                return Err(TLSError::Protocol(TLSAlertDescription::MISSING_EXTENSION));
            }
            if context.session.protocol.is_none() {
                return Err(TLSError::Protocol(TLSAlertDescription::NO_APPLICATION_PROTOCOL));
            }
        }
        Ok(())
    }

    /// CertificateRequest (RFC 9846 §4.4.2): an empty context in the
    /// handshake (`illegal_parameter`) and `signature_algorithms` (`missing_extension`).
    pub fn receive_request(&mut self, body: &[u8]) -> Result<(), TLSError> {
        let request = TLS13CertificateRequest::decode(body)?;
        if !request.context.is_empty() {
            return Err(TLSError::illegal());
        }
        TLSExtension::check(&request.extensions, TLSExtensionContext::CertificateRequest)?;
        if TLSExtension::find(&request.extensions, TLSExtensionType::SIGNATURE_ALGORITHMS).is_none() {
            return Err(TLSError::Protocol(TLSAlertDescription::MISSING_EXTENSION));
        }
        self.request = Some(request);
        Ok(())
    }

    /// The server's Finished: then the client's flight and the
    /// application keys (RFC 9846 §4.5.3, §7.1).
    pub fn receive_finished(
        mut self: Box<Self>,
        message: &TLSHandshake,
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        TLS13Authentication::receive_finished(
            &self.schedule,
            self.server_handshake.expose(),
            &message.body,
            &self.start.transcript,
        )?;
        // The Finished precedes a key change: it ends its record (RFC 9846 §5.1).
        context.layer.check_boundary()?;
        self.start.transcript.update(&message.to_bytes()?);
        let main = self.schedule.next_secret(self.handshake_secret.expose(), &[])?;
        let transcript_hash = self.start.transcript.hash();
        let client_application = self.schedule.derive_secret(main.expose(), b"c ap traffic", &transcript_hash)?;
        let server_application = self.schedule.derive_secret(main.expose(), b"s ap traffic", &transcript_hash)?;
        let exporter = self.schedule.derive_secret(main.expose(), b"exp master", &transcript_hash)?;
        let (schedule, aead) = (self.schedule, self.aead);
        TLS13Authentication::install(
            context.layer,
            TLSDirection::Reading,
            TLSEncryptionLevel::Application,
            &schedule,
            aead,
            server_application.expose(),
        )?;
        // EndOfEarlyData under the keys of early data, then the handshake's
        // (RFC 9846 §4.5); neither with QUIC (RFC 9001 §8.3).
        if self.early && context.layer.quic.is_none() {
            if context.session.early_data == TLSEarlyData::Accepted {
                let message = TLSHandshake::new(TLSHandshakeType::END_OF_EARLY_DATA, Vec::new());
                self.start.transcript.update(&context.layer.write_handshake(&message)?);
            }
            let secret = self.client_handshake.expose();
            TLS13Authentication::install(
                context.layer,
                TLSDirection::Writing,
                TLSEncryptionLevel::Handshake,
                &schedule,
                aead,
                secret,
            )?;
        }
        self.start.send_change_cipher_spec(context)?;
        if let Some(request) = &self.request {
            let schemes = TLSExtension::find(&request.extensions, TLSExtensionType::SIGNATURE_ALGORITHMS)
                .map(TLSSignatureSchemes::decode)
                .transpose()?
                .unwrap_or_default();
            // No certificate for the public name of a rejected ECH (RFC 9849 §6.1.7).
            let rejected = self.start.ech_rejected;
            let key = self.start.config.certificate.clone().filter(|_| !rejected);
            let scheme = key.as_ref().and_then(|key| {
                key.scheme(&schemes.schemes, &self.start.config.config.signature_schemes, TLSVersion::TLS1_3)
            });
            // Without a key that fits, an empty Certificate (RFC 9846 §4.4.2).
            let key = key.filter(|_| scheme.is_some());
            TLS13Authentication::send(key.as_deref(), scheme, &[], false, false, &mut self.start.transcript, context)?;
        }
        TLS13Authentication::send_finished(
            &self.schedule,
            self.client_handshake.expose(),
            &mut self.start.transcript,
            context,
        )?;
        let resumption = self.schedule.derive_secret(main.expose(), b"res master", &self.start.transcript.hash())?;
        TLS13Authentication::install(
            context.layer,
            TLSDirection::Writing,
            TLSEncryptionLevel::Application,
            &schedule,
            aead,
            client_application.expose(),
        )?;
        // A rejected ECH ends here, once the server proved it holds the public name (RFC 9849 §6.1.6).
        self.start.end_rejected_ech(context)?;
        context.events.push_back(TLSEvent::Connected);
        Ok(Box::new(TLS13Established {
            role: TLSRole::Client,
            schedule: self.schedule,
            aead: self.aead,
            sending: client_application,
            receiving: server_application,
            exporter,
            resumption,
            key_updates: 0,
            maximum_key_updates: self.start.config.config.maximum_key_updates,
            sessions: self
                .start
                .config
                .sessions
                .clone()
                .filter(|_| !self.start.config.config.psk_modes.is_empty())
                .zip(self.start.name.clone()),
            post_handshake: if self.start.config.post_handshake_authentication {
                TLS13PostHandshake::Client {
                    certificate: self.start.config.certificate.clone(),
                    schemes: self.start.config.config.signature_schemes.clone(),
                }
            } else {
                TLS13PostHandshake::Off
            },
            transcript: self.start.transcript,
        }))
    }
}

impl TLSHandshakeProtocol for TLS13Client {
    fn receive(
        mut self: Box<Self>,
        message: TLSHandshake,
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        match (self.state, message.kind) {
            (TLS13ClientState::EncryptedExtensions, TLSHandshakeType::ENCRYPTED_EXTENSIONS) => {
                self.receive_encrypted_extensions(&message.body, context)?;
                // A resumed session is authenticated by its PSK (RFC 9846 §2.2).
                self.state =
                    if self.resumed { TLS13ClientState::Finished } else { TLS13ClientState::CertificateOrRequest };
            }
            (TLS13ClientState::CertificateOrRequest, TLSHandshakeType::CERTIFICATE_REQUEST) => {
                self.receive_request(&message.body)?;
                self.state = TLS13ClientState::Certificate;
            }
            (TLS13ClientState::CertificateOrRequest | TLS13ClientState::Certificate, TLSHandshakeType::CERTIFICATE) => {
                let TLS13ReceivedCertificate { chain, status } = TLS13Authentication::receive_certificate(
                    &message.body,
                    &[],
                    self.start.config.request_certificate_status,
                    self.start.config.verifier.as_ref(),
                    self.start.identity.as_ref(),
                    context.session.time,
                )?;
                context.session.certificate_status = status;
                // A server's Certificate is never empty (RFC 9846 §4.5.1.3).
                if chain.is_empty() {
                    return Err(TLSError::decode());
                }
                context.session.peer_certificates = chain.clone();
                self.chain = chain;
                self.state = TLS13ClientState::CertificateVerify;
            }
            (TLS13ClientState::CertificateVerify, TLSHandshakeType::CERTIFICATE_VERIFY) => {
                let scheme = TLS13Authentication::receive_verify(
                    &message.body,
                    &self.chain,
                    &self.start.config.config.signature_schemes,
                    true,
                    &self.start.transcript,
                )?;
                context.session.peer_signature_scheme = Some(scheme);
                self.state = TLS13ClientState::Finished;
            }
            (TLS13ClientState::Finished, TLSHandshakeType::FINISHED) => {
                return self.receive_finished(&message, context);
            }
            _ => return Err(TLSError::unexpected()),
        }
        self.start.transcript.update(&message.to_bytes()?);
        Ok(self)
    }

    /// The peer's dummy ChangeCipherSpec, `0x01`, is dropped until the
    /// handshake completes (RFC 9846 §5).
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
