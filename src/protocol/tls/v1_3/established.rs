use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::protocol::tls::{
    TLSAEADAlgorithm, TLSAlertDescription, TLSCertificateVerifier, TLSCertifiedKey, TLSContext, TLSDirection,
    TLSEarlyDataIndication, TLSEncryptionLevel, TLSError, TLSEvent, TLSExtension, TLSExtensionContext,
    TLSExtensionType, TLSHandshake, TLSHandshakeProtocol, TLSHandshakeType, TLSQUIC, TLSRole, TLSSessionState,
    TLSSessionStore, TLSSessionTicket, TLSSignatureScheme, TLSSignatureSchemes, TLSTranscript, TLSVersion,
};
use crate::secret::Secret;

use super::{TLS13Authentication, TLS13CertificateRequest, TLS13KeySchedule, TLS13KeyUpdate, TLS13NewSessionTicket};

/// Post-handshake client authentication on an established connection
/// (RFC 9846 §4.6.2), which the client offers with `post_handshake_auth`.
pub enum TLS13PostHandshake {
    /// Not offered: a CertificateRequest is `unexpected_message`, and a
    /// server cannot ask.
    Off,
    /// A client that offered it, the certificate it answers with, and the
    /// signature schemes it signs with.
    Client { certificate: Option<Arc<TLSCertifiedKey>>, schemes: Vec<TLSSignatureScheme> },
    /// A server whose client offered it.
    /// Boxed: its transcript and pending request outweigh the other variants.
    Server(Box<TLS13Authenticator>),
}

/// What a server's post-handshake authentication checks the client with,
/// and the request it waits on the answer to, if any.
pub struct TLS13Authenticator {
    pub verifier: Arc<dyn TLSCertificateVerifier>,
    /// The schemes asked for and accepted.
    pub schemes: Vec<TLSSignatureScheme>,
    pub pending: Option<TLS13PendingRequest>,
}

/// What a server's CertificateRequest after the handshake waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLS13RequestState {
    Certificate,
    CertificateVerify,
    Finished,
}

/// A CertificateRequest sent after the handshake and its answer so far:
/// the transcript is the handshake's, then the request and the answer
/// (RFC 9846 §4.4).
pub struct TLS13PendingRequest {
    pub context: Vec<u8>,
    pub transcript: TLSTranscript,
    pub state: TLS13RequestState,
    pub chain: Vec<Vec<u8>>,
    pub scheme: Option<TLSSignatureScheme>,
}

/// A TLS 1.3 connection after its handshake (RFC 9846 §4.7): the traffic
/// secrets of both directions, which KeyUpdate replaces, and the secrets
/// of exporters and resumption.
pub struct TLS13Established {
    pub role: TLSRole,
    pub schedule: TLS13KeySchedule,
    pub aead: TLSAEADAlgorithm,
    /// The application traffic secret of what this end sends.
    pub sending: Secret<alloc::vec::Vec<u8>>,
    /// The application traffic secret of what this end receives.
    pub receiving: Secret<alloc::vec::Vec<u8>>,
    pub exporter: Secret<alloc::vec::Vec<u8>>,
    pub resumption: Secret<alloc::vec::Vec<u8>>,
    /// KeyUpdates received since the last application data.
    pub key_updates: u32,
    pub maximum_key_updates: u32,
    /// The transcript of the handshake, through the client's Finished,
    /// which post-handshake authentication continues.
    pub transcript: TLSTranscript,
    pub post_handshake: TLS13PostHandshake,
    /// A client's store of tickets and the name they are kept by, if it resumes.
    pub sessions: Option<(Arc<dyn TLSSessionStore>, String)>,
}

impl TLS13Established {
    /// Replaces the sending keys: the KeyUpdate goes out under the old ones (RFC 9846 §4.7.3).
    pub fn send_key_update(&mut self, request: bool, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        // QUIC updates its keys itself and forbids KeyUpdate (RFC 9001 §6).
        if context.layer.quic.is_some() {
            return Err(TLSError::State);
        }
        let update = TLS13KeyUpdate { request_update: request };
        context
            .layer
            .write_handshake(&TLSHandshake::with(TLSHandshakeType::KEY_UPDATE, |body| update.encode(body))?)?;
        self.sending = self.schedule.next_traffic_secret(self.sending.expose())?;
        let secret = self.sending.expose();
        TLS13Authentication::install(
            context.layer,
            TLSDirection::Writing,
            TLSEncryptionLevel::Application,
            &self.schedule,
            self.aead,
            secret,
        )?;
        Ok(())
    }

    /// A NewSessionTicket (RFC 9846 §4.6.1): kept in the store, with the PSK
    /// it stands for, unless its lifetime is 0.
    pub fn receive_ticket(&mut self, body: &[u8], context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let ticket = TLS13NewSessionTicket::decode(body)?;
        TLSExtension::check(&ticket.extensions, TLSExtensionContext::NewSessionTicket)?;
        let maximum_early_data = match TLSExtension::find(&ticket.extensions, TLSExtensionType::EARLY_DATA) {
            Some(data) => Some(TLSEarlyDataIndication::decode(data)?.0),
            None => None,
        };
        // QUIC allows only its sentinel when the extension is there (RFC 9001 §4.6.1).
        if context.layer.quic.is_some() && maximum_early_data.is_some_and(|maximum| maximum != TLSQUIC::EARLY_DATA) {
            return Err(TLSError::Transport);
        }
        let maximum_early_data = maximum_early_data.unwrap_or(0);
        let (Some((store, name)), Some(suite)) = (&self.sessions, context.session.cipher_suite) else { return Ok(()) };
        if ticket.lifetime == 0 {
            return Ok(());
        }
        let psk = self.schedule.resumption_psk(self.resumption.expose(), &ticket.nonce)?;
        let state = TLSSessionState {
            version: TLSVersion::TLS1_3,
            cipher_suite: suite,
            psk,
            time: context.session.time,
            lifetime: ticket.lifetime,
            age_add: ticket.age_add,
            maximum_early_data,
            protocol: context.session.protocol.clone(),
            server_name: context.session.server_name.clone(),
            peer_certificates: context.session.peer_certificates.clone(),
            application: context.session.application.clone(),
        };
        store.put(name, TLSSessionTicket { ticket: ticket.ticket, state });
        Ok(())
    }

    /// A client's answer to a CertificateRequest after the handshake (RFC
    /// 9846 §4.6.2): a context that is not empty (`illegal_parameter`),
    /// `signature_algorithms` (`missing_extension`); then its Certificate,
    /// CertificateVerify if it has a certificate that fits, and Finished
    /// keyed by its application traffic secret.
    pub fn answer_request(&mut self, message: &TLSHandshake, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let TLS13PostHandshake::Client { certificate: key, schemes: allowed } = &self.post_handshake else {
            return Err(TLSError::unexpected());
        };
        let request = TLS13CertificateRequest::decode(&message.body)?;
        if request.context.is_empty() {
            return Err(TLSError::illegal());
        }
        TLSExtension::check(&request.extensions, TLSExtensionContext::CertificateRequest)?;
        let schemes = TLSExtension::find(&request.extensions, TLSExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or(TLSError::Protocol(TLSAlertDescription::MISSING_EXTENSION))
            .and_then(TLSSignatureSchemes::decode)?;
        let scheme = key.as_ref().and_then(|key| key.scheme(&schemes.schemes, allowed, TLSVersion::TLS1_3));
        let key = key.clone().filter(|_| scheme.is_some());
        let mut transcript = self.transcript.clone();
        transcript.update(&message.to_bytes()?);
        TLS13Authentication::send(key.as_deref(), scheme, &request.context, false, false, &mut transcript, context)?;
        TLS13Authentication::send_finished(&self.schedule, self.sending.expose(), &mut transcript, context)
    }

    /// A server's CertificateRequest after the handshake, with a random
    /// context of 32 bytes; one at a time.
    pub fn send_request(&mut self, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let TLS13PostHandshake::Server(authenticator) = &mut self.post_handshake else { return Err(TLSError::State) };
        if authenticator.pending.is_some() {
            return Err(TLSError::State);
        }
        let mut request_context = vec![0u8; 32];
        context
            .random
            .fill(&mut request_context)
            .map_err(|_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR))?;
        let schemes = TLSSignatureSchemes { schemes: authenticator.schemes.clone() };
        let request = TLS13CertificateRequest {
            context: request_context.clone(),
            extensions: vec![TLSExtension::with(TLSExtensionType::SIGNATURE_ALGORITHMS, |data| schemes.encode(data))?],
        };
        let message = TLSHandshake::with(TLSHandshakeType::CERTIFICATE_REQUEST, |body| request.encode(body))?;
        let mut transcript = self.transcript.clone();
        transcript.update(&context.layer.write_handshake(&message)?);
        authenticator.pending = Some(TLS13PendingRequest {
            context: request_context,
            transcript,
            state: TLS13RequestState::Certificate,
            chain: Vec::new(),
            scheme: None,
        });
        Ok(())
    }

    /// A message of the client's answer to the server's request: its
    /// Certificate, CertificateVerify and Finished, checked as in the
    /// handshake; once complete, the session holds the client's chain
    /// (empty if it sent none) and [`TLSEvent::Authenticated`] is queued.
    pub fn receive_answer(&mut self, message: &TLSHandshake, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let TLS13PostHandshake::Server(authenticator) = &mut self.post_handshake else {
            return Err(TLSError::unexpected());
        };
        let Some(pending) = authenticator.pending.as_mut() else { return Err(TLSError::unexpected()) };
        match (pending.state, message.kind) {
            (TLS13RequestState::Certificate, TLSHandshakeType::CERTIFICATE) => {
                let chain = TLS13Authentication::receive_certificate(
                    &message.body,
                    &pending.context,
                    false,
                    authenticator.verifier.as_ref(),
                    None,
                    context.session.time,
                )?
                .chain;
                pending.state =
                    if chain.is_empty() { TLS13RequestState::Finished } else { TLS13RequestState::CertificateVerify };
                pending.chain = chain;
            }
            (TLS13RequestState::CertificateVerify, TLSHandshakeType::CERTIFICATE_VERIFY) => {
                pending.scheme = Some(TLS13Authentication::receive_verify(
                    &message.body,
                    &pending.chain,
                    &authenticator.schemes,
                    false,
                    &pending.transcript,
                )?);
                pending.state = TLS13RequestState::Finished;
            }
            (TLS13RequestState::Finished, TLSHandshakeType::FINISHED) => {
                TLS13Authentication::receive_finished(
                    &self.schedule,
                    self.receiving.expose(),
                    &message.body,
                    &pending.transcript,
                )?;
                let pending = authenticator.pending.take().ok_or(TLSError::State)?;
                context.session.peer_certificates = pending.chain;
                context.session.peer_signature_scheme = pending.scheme;
                context.events.push_back(TLSEvent::Authenticated);
                return Ok(());
            }
            _ => return Err(TLSError::unexpected()),
        }
        pending.transcript.update(&message.to_bytes()?);
        Ok(())
    }
}

impl TLSHandshakeProtocol for TLS13Established {
    /// The messages after the handshake: NewSessionTicket and
    /// CertificateRequest for a client, the answer to a CertificateRequest
    /// for a server, and KeyUpdate for both; anything else is
    /// `unexpected_message`.
    fn receive(
        mut self: Box<Self>,
        message: TLSHandshake,
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        match message.kind {
            // QUIC: a KeyUpdate is CRYPTO_ERROR 0x010a, unexpected_message (RFC 9001 §6).
            TLSHandshakeType::KEY_UPDATE if context.layer.quic.is_some() => Err(TLSError::unexpected()),
            TLSHandshakeType::KEY_UPDATE => {
                let update = TLS13KeyUpdate::decode(&message.body)?;
                // A KeyUpdate precedes a key change: it ends its record (RFC 9846 §5.1).
                context.layer.check_boundary()?;
                // A peer that only updates keys is cut off (RFC 9846 §4.7.3).
                self.key_updates += 1;
                if self.key_updates > self.maximum_key_updates {
                    return Err(TLSError::unexpected());
                }
                self.receiving = self.schedule.next_traffic_secret(self.receiving.expose())?;
                let secret = self.receiving.expose();
                TLS13Authentication::install(
                    context.layer,
                    TLSDirection::Reading,
                    TLSEncryptionLevel::Application,
                    &self.schedule,
                    self.aead,
                    secret,
                )?;
                // Nothing is sent after close_notify (RFC 9846 §6.1).
                if update.request_update && !context.layer.closed {
                    self.send_key_update(false, context)?;
                }
                Ok(self)
            }
            // QUIC forbids post-handshake authentication (RFC 9001 §4.4).
            TLSHandshakeType::CERTIFICATE_REQUEST if self.role == TLSRole::Client && context.layer.quic.is_some() => {
                Err(TLSError::Transport)
            }
            TLSHandshakeType::CERTIFICATE_REQUEST if self.role == TLSRole::Client => {
                self.answer_request(&message, context)?;
                Ok(self)
            }
            TLSHandshakeType::CERTIFICATE | TLSHandshakeType::CERTIFICATE_VERIFY | TLSHandshakeType::FINISHED
                if self.role == TLSRole::Server =>
            {
                self.receive_answer(&message, context)?;
                Ok(self)
            }
            // A client that does not resume ignores tickets (RFC 9846 §4.7.1); they must still decode.
            TLSHandshakeType::NEW_SESSION_TICKET if self.role == TLSRole::Client => {
                self.receive_ticket(&message.body, context)?;
                Ok(self)
            }
            _ => Err(TLSError::unexpected()),
        }
    }

    /// A ChangeCipherSpec after the handshake is `unexpected_message` (RFC 9846 §5).
    fn receive_change_cipher_spec(
        self: Box<Self>,
        _fragment: &[u8],
        _context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        Err(TLSError::unexpected())
    }

    fn is_established(&self) -> bool {
        true
    }

    fn export(&self, label: &[u8], context: Option<&[u8]>, out: &mut [u8]) -> Result<(), TLSError> {
        self.schedule.export(self.exporter.expose(), label, context.unwrap_or(&[]), out)
    }

    fn update_keys(&mut self, request: bool, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        self.send_key_update(request, context)
    }

    fn received_data(&mut self) {
        self.key_updates = 0;
    }

    fn request_certificate(&mut self, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        self.send_request(context)
    }
}
