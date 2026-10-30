use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::auth::cert::x509::Certificate;
use crate::protocol::tls::{
    TLSAEAD, TLSAlertDescription, TLSCertificateStatus, TLSCertificateVerify, TLSClientStart, TLSContentType,
    TLSContext, TLSError, TLSEvent, TLSExtensionType, TLSHandshake, TLSHandshakeProtocol, TLSHandshakeType,
    TLSKeyShareSecret, TLSOpaqueExtension, TLSPointFormats, TLSRecordProtector, TLSRole, TLSServerHello, TLSVersion,
};

use super::{
    TLS12Certificate, TLS12CertificateRequest, TLS12ClientKeyExchange, TLS12Established, TLS12Secrets,
    TLS12ServerKeyExchange,
};

/// What a TLS 1.2 client waits for (RFC 5246 §7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLS12ClientState {
    Certificate,
    /// After a Certificate, when the server acknowledged `status_request`:
    /// its CertificateStatus, which it may still leave out (RFC 6066 §8).
    StatusOrKeyExchange,
    ServerKeyExchange,
    RequestOrDone,
    Done,
    ChangeCipherSpec,
    Finished,
}

/// A TLS 1.2 client from the ServerHello to the server's Finished, with
/// the ECDHE key exchange (RFC 5246, RFC 8422).
pub struct TLS12Client {
    pub start: TLSClientStart,
    pub state: TLS12ClientState,
    pub server_hello: TLSServerHello,
    /// Every handshake message so far, which CertificateVerify signs (RFC 5246 §7.4.8).
    pub messages: Vec<u8>,
    pub extended: bool,
    /// Whether the server acknowledged `status_request` (RFC 6066 §8).
    pub status: bool,
    pub chain: Vec<Vec<u8>>,
    pub key_exchange: Option<TLS12ServerKeyExchange>,
    pub request: Option<TLS12CertificateRequest>,
    pub secrets: Option<TLS12Secrets>,
    /// The server's record protection, installed at its ChangeCipherSpec.
    pub pending_reader: Option<Box<dyn TLSRecordProtector>>,
}

impl TLS12Client {
    /// Takes the ServerHello of TLS 1.2: the suite offered, the secure
    /// renegotiation and the extended main secret acknowledged (RFC 9325
    /// §3.5), only the uncompressed point format (RFC 8422 §5.1.2), and
    /// only extensions that were offered.
    pub fn from_server_hello(
        mut start: TLSClientStart,
        hello: TLSServerHello,
        bytes: &[u8],
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        let suite = hello.cipher_suite;
        if !start.hello.cipher_suites.contains(&suite)
            || suite.version() != Some(TLSVersion::TLS1_2)
            || !suite.aead().is_some_and(TLSAEAD::supports)
            || hello.legacy_compression_method != 0
        {
            return Err(TLSError::illegal());
        }
        // An echo of a session ID the client did not offer for resumption.
        if !hello.legacy_session_id_echo.is_empty() && hello.legacy_session_id_echo == start.hello.legacy_session_id {
            return Err(TLSError::illegal());
        }
        for extension in &hello.extensions {
            if start.hello.extension(extension.kind).is_none() {
                return Err(TLSError::Protocol(TLSAlertDescription::UNSUPPORTED_EXTENSION));
            }
        }
        let failure = TLSError::Protocol(TLSAlertDescription::HANDSHAKE_FAILURE);
        let renegotiation = hello.extension(TLSExtensionType::RENEGOTIATION_INFO).ok_or(failure)?;
        if !TLSOpaqueExtension::decode_renegotiation_info(renegotiation)?.is_empty() {
            return Err(failure);
        }
        let extended = match hello.extension(TLSExtensionType::EXTENDED_MAIN_SECRET) {
            Some(data) => TLSOpaqueExtension::decode_empty(data).map(|_| true)?,
            None => false,
        };
        if !extended && start.config.config.require_extended_main_secret {
            return Err(failure);
        }
        if let Some(data) = hello.extension(TLSExtensionType::EC_POINT_FORMATS) {
            TLSPointFormats::decode(data)?;
        }
        if let Some(data) = hello.extension(TLSExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION) {
            context.session.protocol = Some(start.protocol(data)?);
        }
        let status = match hello.extension(TLSExtensionType::STATUS_REQUEST) {
            Some(data) => TLSOpaqueExtension::decode_empty(data).map(|_| true)?,
            None => false,
        };
        if let Some(data) = hello.extension(TLSExtensionType::RECORD_SIZE_LIMIT) {
            start.limit_records(data, TLSVersion::TLS1_2, context)?;
        }
        // The server acknowledges the name it chose the certificate for with an empty extension (RFC 6066 §3).
        if let Some(data) = hello.extension(TLSExtensionType::SERVER_NAME) {
            TLSOpaqueExtension::decode_empty(data)?;
        }
        let mut messages = start.transcript.buffered().unwrap_or(&[]).to_vec();
        messages.extend_from_slice(bytes);
        start.transcript.select(suite.hash().ok_or(TLSError::illegal())?);
        start.transcript.update(bytes);
        context.session.cipher_suite = Some(suite);
        Ok(Box::new(TLS12Client {
            start,
            state: TLS12ClientState::Certificate,
            server_hello: hello,
            messages,
            extended,
            status,
            chain: Vec::new(),
            key_exchange: None,
            request: None,
            secrets: None,
            pending_reader: None,
        }))
    }

    /// The server's Certificate: not empty, with a key of the suite's
    /// authentication (`unsupported_certificate`). The verifier checks it
    /// with [`TLS12Client::verify_chain`], once the stapled OCSP response
    /// has come or cannot come.
    pub fn receive_certificate(&mut self, body: &[u8], context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let chain = TLS12Certificate::decode(body)?.chain;
        let first = chain.first().ok_or(TLSError::decode())?;
        let key = Certificate::from_der(first)
            .and_then(|certificate| certificate.public_key())
            .map_err(|_| TLSError::Protocol(TLSAlertDescription::BAD_CERTIFICATE))?;
        let authentication = self.server_hello.cipher_suite.authentication().ok_or(TLSError::illegal())?;
        if !authentication.accepts(key.algorithm()) {
            return Err(TLSError::Protocol(TLSAlertDescription::UNSUPPORTED_CERTIFICATE));
        }
        context.session.peer_certificates = chain.clone();
        self.chain = chain;
        Ok(())
    }

    /// Checks the server's chain with the verifier, with the OCSP response
    /// of a CertificateStatus (RFC 6066 §8) if one came.
    pub fn verify_chain(&mut self, status: Option<Vec<u8>>, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        self.start
            .config
            .verifier
            .verify(&self.chain, self.start.identity.as_ref(), status.as_deref(), context.session.time)
            .map_err(TLSError::Protocol)?;
        context.session.certificate_status = status;
        Ok(())
    }

    /// ServerKeyExchange (RFC 8422 §5.4): a group the client offered
    /// (`illegal_parameter`), signed with a scheme it accepts
    /// (`illegal_parameter`) over both randoms and the parameters (`decrypt_error`).
    pub fn receive_key_exchange(&mut self, body: &[u8], context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let exchange = TLS12ServerKeyExchange::decode(body)?;
        let offered = self.start.config.config.groups.contains(&exchange.group)
            && exchange.group.usable_with(TLSVersion::TLS1_2)
            && TLSKeyShareSecret::supports(exchange.group);
        let scheme = exchange.signature.algorithm;
        if !offered || !self.start.config.config.signature_schemes.contains(&scheme) {
            return Err(TLSError::illegal());
        }
        let key = Certificate::from_der(&self.chain[0])
            .and_then(|certificate| certificate.public_key())
            .map_err(|_| TLSError::Protocol(TLSAlertDescription::BAD_CERTIFICATE))?;
        let parameters = TLS12ServerKeyExchange::parameters(exchange.group, &exchange.public)?;
        let signed = TLS12ServerKeyExchange::signed(&self.start.hello.random, &self.server_hello.random, &parameters);
        scheme.verify(&key, &signed, &exchange.signature.signature, TLSVersion::TLS1_2)?;
        context.session.peer_signature_scheme = Some(scheme);
        context.session.group = Some(exchange.group);
        self.key_exchange = Some(exchange);
        Ok(())
    }

    /// ServerHelloDone: the client's flight (RFC 5246 §7.3): its Certificate
    /// if asked, ClientKeyExchange, CertificateVerify if it sent a
    /// certificate, ChangeCipherSpec and Finished.
    pub fn send_flight(&mut self, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let exchange = self.key_exchange.take().ok_or(TLSError::unexpected())?;
        let mut client_key = None;
        if let Some(request) = &self.request {
            // A certificate of a type asked for, with a scheme asked for, or none (RFC 5246 §7.4.6).
            // No certificate for the public name of a rejected ECH (RFC 9849 §6.1.7).
            let rejected = self.start.ech_rejected;
            let key =
                self.start.config.certificate.clone().filter(|key| !rejected && request.accepts(key.key.algorithm()));
            let scheme = key.as_ref().and_then(|key| {
                key.scheme(&request.schemes, &self.start.config.config.signature_schemes, TLSVersion::TLS1_2)
            });
            let key = key.filter(|_| scheme.is_some());
            let certificate = TLS12Certificate { chain: key.as_ref().map(|key| key.chain.clone()).unwrap_or_default() };
            self.write(&TLSHandshake::with(TLSHandshakeType::CERTIFICATE, |body| certificate.encode(body))?, context)?;
            client_key = key.zip(scheme);
        }
        let (secret, public) = TLSKeyShareSecret::generate(exchange.group, &mut &mut *context.random)?;
        let preliminary = secret.complete(&exchange.public)?;
        let key_exchange = TLS12ClientKeyExchange { public };
        self.write(
            &TLSHandshake::with(TLSHandshakeType::CLIENT_KEY_EXCHANGE, |body| key_exchange.encode(body))?,
            context,
        )?;
        // The session hash ends with ClientKeyExchange (RFC 7627 §3).
        let session_hash = self.start.transcript.hash();
        let secrets = TLS12Secrets::new(
            self.server_hello.cipher_suite,
            preliminary.expose(),
            self.extended.then_some(session_hash.as_slice()),
            self.start.hello.random,
            self.server_hello.random,
        )?;
        if let Some((key, scheme)) = client_key {
            let signature = scheme.sign(&key.key, &self.messages, &mut &mut *context.random)?;
            let verify = TLSCertificateVerify { algorithm: scheme, signature };
            self.write(
                &TLSHandshake::with(TLSHandshakeType::CERTIFICATE_VERIFY, |body| verify.encode(body))?,
                context,
            )?;
        }
        let (writer, reader) = secrets.protections()?;
        context.layer.write_record(TLSContentType::CHANGE_CIPHER_SPEC, &[1])?;
        context.layer.writer = Some(writer);
        let finished = secrets.finished(true, &self.start.transcript);
        self.write(&TLSHandshake::new(TLSHandshakeType::FINISHED, finished), context)?;
        self.pending_reader = Some(reader);
        self.secrets = Some(secrets);
        Ok(())
    }

    /// Writes `message` and adds it to the transcript and the messages.
    pub fn write(&mut self, message: &TLSHandshake, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let bytes = context.layer.write_handshake(message)?;
        self.start.transcript.update(&bytes);
        self.messages.extend_from_slice(&bytes);
        Ok(())
    }
}

impl TLSHandshakeProtocol for TLS12Client {
    fn receive(
        mut self: Box<Self>,
        message: TLSHandshake,
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        // A HelloRequest during the handshake is ignored, and not part of it (RFC 5246 §7.4.1.1).
        if message.kind == TLSHandshakeType::HELLO_REQUEST && message.body.is_empty() {
            context.layer.ignore()?;
            return Ok(self);
        }
        match (self.state, message.kind) {
            (TLS12ClientState::Certificate, TLSHandshakeType::CERTIFICATE) => {
                self.receive_certificate(&message.body, context)?;
                if self.status {
                    self.state = TLS12ClientState::StatusOrKeyExchange;
                } else {
                    self.verify_chain(None, context)?;
                    self.state = TLS12ClientState::ServerKeyExchange;
                }
            }
            (TLS12ClientState::StatusOrKeyExchange, TLSHandshakeType::CERTIFICATE_STATUS) => {
                let TLSCertificateStatus::Response(response) = TLSCertificateStatus::decode(&message.body, true)?
                else {
                    return Err(TLSError::decode());
                };
                self.verify_chain(Some(response), context)?;
                self.state = TLS12ClientState::ServerKeyExchange;
            }
            (
                TLS12ClientState::StatusOrKeyExchange | TLS12ClientState::ServerKeyExchange,
                TLSHandshakeType::SERVER_KEY_EXCHANGE,
            ) => {
                if self.state == TLS12ClientState::StatusOrKeyExchange {
                    self.verify_chain(None, context)?;
                }
                self.receive_key_exchange(&message.body, context)?;
                self.state = TLS12ClientState::RequestOrDone;
            }
            (TLS12ClientState::RequestOrDone, TLSHandshakeType::CERTIFICATE_REQUEST) => {
                self.request = Some(TLS12CertificateRequest::decode(&message.body)?);
                self.state = TLS12ClientState::Done;
            }
            (TLS12ClientState::RequestOrDone | TLS12ClientState::Done, TLSHandshakeType::SERVER_HELLO_DONE) => {
                if !message.body.is_empty() {
                    return Err(TLSError::decode());
                }
                let bytes = message.to_bytes()?;
                self.start.transcript.update(&bytes);
                self.messages.extend_from_slice(&bytes);
                self.send_flight(context)?;
                self.state = TLS12ClientState::ChangeCipherSpec;
                return Ok(self);
            }
            (TLS12ClientState::Finished, TLSHandshakeType::FINISHED) => {
                let secrets = self.secrets.take().ok_or(TLSError::State)?;
                secrets.check_finished(false, &message.body, &self.start.transcript)?;
                // A rejected ECH ends here, once the server proved it holds the public name (RFC 9849 §6.1.6).
                self.start.end_rejected_ech(context)?;
                context.events.push_back(TLSEvent::Connected);
                return Ok(Box::new(TLS12Established {
                    role: TLSRole::Client,
                    prf: secrets.prf,
                    main: secrets.main,
                    client_random: secrets.client_random,
                    server_random: secrets.server_random,
                }));
            }
            _ => return Err(TLSError::unexpected()),
        }
        let bytes = message.to_bytes()?;
        self.start.transcript.update(&bytes);
        self.messages.extend_from_slice(&bytes);
        Ok(self)
    }

    /// The server's ChangeCipherSpec: `0x01`, at a record boundary, after
    /// the client's Finished; it installs the server's keys (RFC 5246 §7.1).
    fn receive_change_cipher_spec(
        mut self: Box<Self>,
        fragment: &[u8],
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        if fragment != [1] || self.state != TLS12ClientState::ChangeCipherSpec || !context.layer.handshake.is_empty() {
            return Err(TLSError::unexpected());
        }
        context.layer.reader = self.pending_reader.take();
        self.state = TLS12ClientState::Finished;
        Ok(self)
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
