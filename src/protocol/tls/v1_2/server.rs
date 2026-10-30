use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::auth::cert::key::KeyAlgorithm;
use crate::auth::cert::path::ServiceIdentity;
use crate::auth::cert::x509::Certificate;
use crate::protocol::tls::{
    TLSAEAD, TLSAlertDescription, TLSCertificateStatus, TLSCertificateVerify, TLSCertifiedKey, TLSCipherSuite,
    TLSClientAuthentication, TLSClientHello, TLSContentType, TLSContext, TLSError, TLSEvent, TLSExtension,
    TLSExtensionType, TLSHandshake, TLSHandshakeProtocol, TLSHandshakeType, TLSKeyShareSecret, TLSNamedGroup,
    TLSOpaqueExtension, TLSPointFormats, TLSProtocolNames, TLSRecordProtector, TLSRole, TLSServerConfig,
    TLSServerHello, TLSServerNames, TLSServerStart, TLSSignatureScheme, TLSSignatureSchemes, TLSSupportedGroups,
    TLSTranscript, TLSVersion,
};

use super::{
    TLS12Certificate, TLS12CertificateRequest, TLS12ClientKeyExchange, TLS12Established, TLS12Secrets,
    TLS12ServerKeyExchange,
};

/// What a TLS 1.2 server waits for (RFC 5246 §7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLS12ServerState {
    Certificate,
    ClientKeyExchange,
    CertificateVerify,
    ChangeCipherSpec,
    Finished,
}

/// What the server chose from a ClientHello of TLS 1.2.
#[derive(Clone)]
pub struct TLS12Selection {
    pub suite: TLSCipherSuite,
    pub group: TLSNamedGroup,
    pub certificate: Arc<TLSCertifiedKey>,
    pub scheme: TLSSignatureScheme,
    /// Whether the certificate was chosen for the name the client asked for.
    pub named: bool,
}

/// A TLS 1.2 server from the ClientHello to its Finished, with the ECDHE
/// key exchange (RFC 5246, RFC 8422).
pub struct TLS12Server {
    pub config: Arc<TLSServerConfig>,
    pub state: TLS12ServerState,
    pub suite: TLSCipherSuite,
    pub transcript: TLSTranscript,
    /// Every handshake message so far while a client certificate is asked
    /// for: what its CertificateVerify signs (RFC 5246 §7.4.8).
    pub messages: Vec<u8>,
    pub request: bool,
    pub extended: bool,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub share: Option<TLSKeyShareSecret>,
    pub chain: Vec<Vec<u8>>,
    pub secrets: Option<TLS12Secrets>,
    /// The server's record protection, installed with its ChangeCipherSpec.
    pub pending_writer: Option<Box<dyn TLSRecordProtector>>,
}

impl TLS12Server {
    /// Takes a ClientHello that negotiates TLS 1.2 and answers with the
    /// server's flight: ServerHello, Certificate, ServerKeyExchange, an
    /// optional CertificateRequest and ServerHelloDone.
    pub fn from_client_hello(
        config: Arc<TLSServerConfig>,
        hello: TLSClientHello,
        bytes: &[u8],
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        let extended = TLS12Server::check(&config, &hello)?;
        let selection = TLS12Server::select(&config, &hello)?;
        let hash = selection.suite.hash().ok_or(TLSError::illegal())?;
        let mut transcript = TLSTranscript::new();
        transcript.select(hash);
        transcript.update(bytes);
        let request = config.client_authentication != TLSClientAuthentication::Off;
        let mut server = TLS12Server {
            state: TLS12ServerState::ClientKeyExchange,
            suite: selection.suite,
            transcript,
            messages: if request { bytes.to_vec() } else { Vec::new() },
            request,
            extended,
            client_random: hello.random,
            server_random: [0; 32],
            share: None,
            chain: Vec::new(),
            secrets: None,
            pending_writer: None,
            config,
        };
        server.respond(&hello, selection, context)?;
        Ok(Box::new(server))
    }

    /// The checks of a TLS 1.2 ClientHello; returns whether it offers the
    /// extended main secret. A fallback to TLS 1.2 by a client that this
    /// server could serve TLS 1.3 fails with `inappropriate_fallback` (RFC
    /// 7507 §3); compression must offer null (RFC 5246 §7.4.1.2,
    /// `illegal_parameter`); secure renegotiation must be signalled, with
    /// an empty `renegotiation_info` (RFC 5746 §3.6, RFC 9325 §3.5); the
    /// extended main secret is required unless configured otherwise (RFC
    /// 7627 §5.3); and `ec_point_formats` must list the uncompressed format
    /// (RFC 8422 §5.1.2). Each fails with `handshake_failure` otherwise.
    pub fn check(config: &TLSServerConfig, hello: &TLSClientHello) -> Result<bool, TLSError> {
        let failure = TLSError::Protocol(TLSAlertDescription::HANDSHAKE_FAILURE);
        let newer = TLSVersion::TLS1_3.is_supported() && config.config.versions.contains(&TLSVersion::TLS1_3);
        if newer && hello.cipher_suites.contains(&TLSCipherSuite::TLS_FALLBACK_SCSV) {
            return Err(TLSError::Protocol(TLSAlertDescription::INAPPROPRIATE_FALLBACK));
        }
        if !hello.legacy_compression_methods.contains(&0) {
            return Err(TLSError::illegal());
        }
        match hello.extension(TLSExtensionType::RENEGOTIATION_INFO) {
            Some(data) if !TLSOpaqueExtension::decode_renegotiation_info(data)?.is_empty() => return Err(failure),
            Some(_) => {}
            None if hello.cipher_suites.contains(&TLSCipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV) => {}
            None => return Err(failure),
        }
        let extended = match hello.extension(TLSExtensionType::EXTENDED_MAIN_SECRET) {
            Some(data) => TLSOpaqueExtension::decode_empty(data).map(|_| true)?,
            None => false,
        };
        if !extended && config.config.require_extended_main_secret {
            return Err(failure);
        }
        if let Some(data) = hello.extension(TLSExtensionType::EC_POINT_FORMATS) {
            TLSPointFormats::decode(data)?;
        }
        Ok(extended)
    }

    /// The cipher suite, group and certificate for `hello`: the first suite
    /// (by the configured preference) with a group in common and a
    /// certificate whose key authenticates it, signs with a scheme the
    /// client accepts and, for ECDSA, lies on a curve the client supports
    /// (RFC 8422 §5.1.1). A client without `supported_groups` is taken to
    /// support secp256r1 (RFC 8422 §4); one without `signature_algorithms`
    /// accepts only SHA-1 (RFC 5246 §7.4.1.4.1), which is refused (RFC
    /// 9155). Fails with `handshake_failure`.
    pub fn select(config: &TLSServerConfig, hello: &TLSClientHello) -> Result<TLS12Selection, TLSError> {
        let failure = TLSError::Protocol(TLSAlertDescription::HANDSHAKE_FAILURE);
        let groups = match hello.extension(TLSExtensionType::SUPPORTED_GROUPS) {
            Some(data) => TLSSupportedGroups::decode(data)?.groups,
            None => vec![TLSNamedGroup::SECP256R1],
        };
        let schemes = match hello.extension(TLSExtensionType::SIGNATURE_ALGORITHMS) {
            Some(data) => TLSSignatureSchemes::decode(data)?.schemes,
            None => Vec::new(),
        };
        let group = config
            .config
            .groups
            .iter()
            .copied()
            .find(|group| {
                group.usable_with(TLSVersion::TLS1_2) && TLSKeyShareSecret::supports(*group) && groups.contains(group)
            })
            .ok_or(failure)?;
        let identity = hello
            .extension(TLSExtensionType::SERVER_NAME)
            .map(TLSServerNames::decode)
            .transpose()?
            .and_then(|names| names.host_name().map(<[u8]>::to_vec))
            .and_then(|name| String::from_utf8(name).ok())
            .map(|name| ServiceIdentity::DNS(name.to_ascii_lowercase()));
        let usable = |suite: &TLSCipherSuite| {
            suite.version() == Some(TLSVersion::TLS1_2)
                && suite.aead().is_some_and(TLSAEAD::supports)
                && config.config.cipher_suites.contains(suite)
                && hello.cipher_suites.contains(suite)
        };
        let suites: Vec<TLSCipherSuite> = if config.prefer_own_cipher_suites {
            config.config.cipher_suites.iter().copied().filter(usable).collect()
        } else {
            hello.cipher_suites.iter().copied().filter(usable).collect()
        };
        for suite in suites {
            let authentication = suite.authentication().ok_or(failure)?;
            let fits = |key: &Arc<TLSCertifiedKey>| {
                let algorithm = key.key.algorithm();
                let curve = match algorithm {
                    KeyAlgorithm::EC(curve) => {
                        TLSNamedGroup::of_curve(*curve).is_some_and(|curve| groups.contains(&curve))
                    }
                    _ => true,
                };
                if !authentication.accepts(algorithm) || !curve {
                    return None;
                }
                key.scheme(&schemes, &config.config.signature_schemes, TLSVersion::TLS1_2)
                    .map(|scheme| (key.clone(), scheme))
            };
            let named = identity
                .as_ref()
                .and_then(|identity| config.certificates.iter().filter(|key| key.names(identity)).find_map(fits));
            let chosen = match named {
                Some((key, scheme)) => Some((key, scheme, true)),
                None => config.certificates.iter().find_map(fits).map(|(key, scheme)| (key, scheme, false)),
            };
            if let Some((certificate, scheme, named)) = chosen {
                return Ok(TLS12Selection { suite, group, certificate, scheme, named });
            }
        }
        Err(failure)
    }

    /// The server's flight (RFC 5246 §7.3).
    pub fn respond(
        &mut self,
        hello: &TLSClientHello,
        selection: TLS12Selection,
        context: &mut TLSContext<'_>,
    ) -> Result<(), TLSError> {
        let internal = |_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR);
        context.random.fill(&mut self.server_random).map_err(internal)?;
        // A server that supports TLS 1.3 marks the random of TLS 1.2 (RFC 9846 §4.2.3).
        if TLSVersion::TLS1_3.is_supported() && self.config.config.versions.contains(&TLSVersion::TLS1_3) {
            self.server_random[24..].copy_from_slice(&TLSServerHello::DOWNGRADE_TLS1_2);
        }
        let mut extensions = vec![TLSExtension::with(TLSExtensionType::RENEGOTIATION_INFO, |data| {
            TLSOpaqueExtension::encode_renegotiation_info(&[], data)
        })?];
        if self.extended {
            extensions.push(TLSExtension::new(TLSExtensionType::EXTENDED_MAIN_SECRET, Vec::new()));
        }
        if hello.extension(TLSExtensionType::EC_POINT_FORMATS).is_some() {
            let formats = TLSPointFormats { formats: vec![TLSPointFormats::UNCOMPRESSED] };
            extensions.push(TLSExtension::with(TLSExtensionType::EC_POINT_FORMATS, |data| formats.encode(data))?);
        }
        // A stapled OCSP response if the client asked for one and there is one (RFC 6066 §8).
        let status = match hello.extension(TLSExtensionType::STATUS_REQUEST) {
            Some(data) => matches!(TLSCertificateStatus::decode(data, false), Ok(TLSCertificateStatus::Request { .. })),
            None => false,
        };
        let status = selection.certificate.ocsp.clone().filter(|_| status);
        if status.is_some() {
            extensions.push(TLSExtension::new(TLSExtensionType::STATUS_REQUEST, Vec::new()));
        }
        // The name asked for, acknowledged when it chose the certificate (RFC 6066 §3).
        context.session.server_name = TLSServerStart::requested_name(hello)?;
        if selection.named {
            extensions.push(TLSExtension::new(TLSExtensionType::SERVER_NAME, Vec::new()));
        }
        if let Some(protocol) = TLS12Server::protocol(&self.config, hello)? {
            let selected = TLSProtocolNames { names: vec![protocol.clone()] };
            extensions.push(TLSExtension::with(TLSExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION, |out| {
                selected.encode(out)
            })?);
            context.session.protocol = Some(protocol);
        }
        extensions.extend(TLSServerStart::limit_records(&self.config.config, hello, TLSVersion::TLS1_2, context)?);
        // An empty session ID: this server keeps no sessions to resume (RFC 5246 §7.4.1.3).
        let server_hello = TLSServerHello {
            legacy_version: TLSVersion::TLS1_2,
            random: self.server_random,
            legacy_session_id_echo: Vec::new(),
            cipher_suite: self.suite,
            legacy_compression_method: 0,
            extensions,
        };
        self.write(&TLSHandshake::new(TLSHandshakeType::SERVER_HELLO, server_hello.to_bytes()?), context)?;
        let certificate = TLS12Certificate { chain: selection.certificate.chain.clone() };
        self.write(&TLSHandshake::with(TLSHandshakeType::CERTIFICATE, |body| certificate.encode(body))?, context)?;
        if let Some(response) = status {
            let status = TLSCertificateStatus::Response(response);
            self.write(
                &TLSHandshake::with(TLSHandshakeType::CERTIFICATE_STATUS, |body| status.encode(body))?,
                context,
            )?;
        }
        let (share, public) = TLSKeyShareSecret::generate(selection.group, &mut &mut *context.random)?;
        let parameters = TLS12ServerKeyExchange::parameters(selection.group, &public)?;
        let signed = TLS12ServerKeyExchange::signed(&self.client_random, &self.server_random, &parameters);
        let signature = selection.scheme.sign(&selection.certificate.key, &signed, &mut &mut *context.random)?;
        let exchange = TLS12ServerKeyExchange {
            group: selection.group,
            public,
            signature: TLSCertificateVerify { algorithm: selection.scheme, signature },
        };
        self.write(&TLSHandshake::with(TLSHandshakeType::SERVER_KEY_EXCHANGE, |body| exchange.encode(body))?, context)?;
        self.share = Some(share);
        if self.request {
            let request = TLS12CertificateRequest {
                types: vec![TLS12CertificateRequest::RSA_SIGN, TLS12CertificateRequest::ECDSA_SIGN],
                schemes: self.config.config.signature_schemes.clone(),
                authorities: Vec::new(),
            };
            self.write(
                &TLSHandshake::with(TLSHandshakeType::CERTIFICATE_REQUEST, |body| request.encode(body))?,
                context,
            )?;
            self.state = TLS12ServerState::Certificate;
        }
        self.write(&TLSHandshake::new(TLSHandshakeType::SERVER_HELLO_DONE, Vec::new()), context)?;
        context.session.cipher_suite = Some(self.suite);
        context.session.group = Some(selection.group);
        Ok(())
    }

    /// The protocol chosen (ALPN): the server's most preferred one the
    /// client offers, `no_application_protocol` without one in common
    /// (RFC 7301 §3.2), or none if either side has none.
    pub fn protocol(config: &TLSServerConfig, hello: &TLSClientHello) -> Result<Option<Vec<u8>>, TLSError> {
        let Some(data) = hello.extension(TLSExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION) else {
            return Ok(None);
        };
        if config.config.protocols.is_empty() {
            return Ok(None);
        }
        let offered = TLSProtocolNames::decode(data)?;
        let protocol = config
            .config
            .protocols
            .iter()
            .find(|protocol| offered.names.contains(protocol))
            .ok_or(TLSError::Protocol(TLSAlertDescription::NO_APPLICATION_PROTOCOL))?;
        Ok(Some(protocol.clone()))
    }

    /// The client's Certificate: it may be empty unless one is required
    /// (`handshake_failure`, RFC 5246 §7.4.6).
    pub fn receive_certificate(&mut self, body: &[u8], context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let chain = TLS12Certificate::decode(body)?.chain;
        if chain.is_empty() {
            if self.config.client_authentication == TLSClientAuthentication::Required {
                return Err(TLSError::Protocol(TLSAlertDescription::HANDSHAKE_FAILURE));
            }
            return Ok(());
        }
        let verifier = self.config.client_verifier.clone().ok_or(TLSError::State)?;
        verifier.verify(&chain, None, None, context.session.time).map_err(TLSError::Protocol)?;
        context.session.peer_certificates = chain.clone();
        self.chain = chain;
        Ok(())
    }

    /// ClientKeyExchange: the preliminary secret, then the main secret
    /// with the session hash that ends with this message (RFC 7627 §3).
    pub fn receive_key_exchange(&mut self, message: &TLSHandshake) -> Result<(), TLSError> {
        let exchange = TLS12ClientKeyExchange::decode(&message.body)?;
        let share = self.share.take().ok_or(TLSError::State)?;
        let preliminary = share.complete(&exchange.public)?;
        self.record(&message.to_bytes()?);
        let session_hash = self.transcript.hash();
        let secrets = TLS12Secrets::new(
            self.suite,
            preliminary.expose(),
            self.extended.then_some(session_hash.as_slice()),
            self.client_random,
            self.server_random,
        )?;
        self.secrets = Some(secrets);
        Ok(())
    }

    /// CertificateVerify: a scheme this server asked for
    /// (`illegal_parameter`) that verifies over the messages so far
    /// (`decrypt_error`, RFC 5246 §7.4.8).
    pub fn receive_verify(&mut self, body: &[u8], context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let mut reader = crate::bytes::Reader::new(body);
        let verify = TLSCertificateVerify::decode(&mut reader)?;
        crate::protocol::tls::TLSVector::finish(&reader)?;
        if !self.config.config.signature_schemes.contains(&verify.algorithm) {
            return Err(TLSError::illegal());
        }
        let key = Certificate::from_der(&self.chain[0])
            .and_then(|certificate| certificate.public_key())
            .map_err(|_| TLSError::Protocol(TLSAlertDescription::BAD_CERTIFICATE))?;
        verify.algorithm.verify(&key, &self.messages, &verify.signature, TLSVersion::TLS1_2)?;
        context.session.peer_signature_scheme = Some(verify.algorithm);
        Ok(())
    }

    /// The client's Finished; the server answers with its ChangeCipherSpec
    /// and Finished, and the handshake completes.
    pub fn receive_finished(
        mut self: Box<Self>,
        message: &TLSHandshake,
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        let secrets = self.secrets.take().ok_or(TLSError::State)?;
        secrets.check_finished(true, &message.body, &self.transcript)?;
        context.layer.check_boundary()?;
        self.transcript.update(&message.to_bytes()?);
        context.layer.write_record(TLSContentType::CHANGE_CIPHER_SPEC, &[1])?;
        context.layer.writer = self.pending_writer.take();
        let finished = secrets.finished(false, &self.transcript);
        context.layer.write_handshake(&TLSHandshake::new(TLSHandshakeType::FINISHED, finished))?;
        context.events.push_back(TLSEvent::Connected);
        Ok(Box::new(TLS12Established {
            role: TLSRole::Server,
            prf: secrets.prf,
            main: secrets.main,
            client_random: secrets.client_random,
            server_random: secrets.server_random,
        }))
    }

    /// Writes `message` and records it.
    pub fn write(&mut self, message: &TLSHandshake, context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        let bytes = context.layer.write_handshake(message)?;
        self.record(&bytes);
        Ok(())
    }

    /// Adds a message to the transcript, and to the messages a client's
    /// CertificateVerify signs while one can come.
    pub fn record(&mut self, bytes: &[u8]) {
        self.transcript.update(bytes);
        if self.request && self.state != TLS12ServerState::ChangeCipherSpec {
            self.messages.extend_from_slice(bytes);
        }
    }
}

impl TLSHandshakeProtocol for TLS12Server {
    fn receive(
        mut self: Box<Self>,
        message: TLSHandshake,
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        match (self.state, message.kind) {
            (TLS12ServerState::Certificate, TLSHandshakeType::CERTIFICATE) => {
                self.receive_certificate(&message.body, context)?;
                self.record(&message.to_bytes()?);
                self.state = TLS12ServerState::ClientKeyExchange;
            }
            (TLS12ServerState::ClientKeyExchange, TLSHandshakeType::CLIENT_KEY_EXCHANGE) => {
                self.receive_key_exchange(&message)?;
                self.state = if self.chain.is_empty() {
                    TLS12ServerState::ChangeCipherSpec
                } else {
                    TLS12ServerState::CertificateVerify
                };
            }
            (TLS12ServerState::CertificateVerify, TLSHandshakeType::CERTIFICATE_VERIFY) => {
                self.receive_verify(&message.body, context)?;
                self.state = TLS12ServerState::ChangeCipherSpec;
                self.record(&message.to_bytes()?);
                self.messages = Vec::new();
            }
            (TLS12ServerState::Finished, TLSHandshakeType::FINISHED) => {
                return self.receive_finished(&message, context);
            }
            _ => return Err(TLSError::unexpected()),
        }
        Ok(self)
    }

    /// The client's ChangeCipherSpec: `0x01`, at a record boundary, after
    /// its key exchange (and CertificateVerify); it installs the client's
    /// keys (RFC 5246 §7.1).
    fn receive_change_cipher_spec(
        mut self: Box<Self>,
        fragment: &[u8],
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        if fragment != [1] || self.state != TLS12ServerState::ChangeCipherSpec || !context.layer.handshake.is_empty() {
            return Err(TLSError::unexpected());
        }
        let secrets = self.secrets.as_ref().ok_or(TLSError::State)?;
        let (reader, writer) = secrets.protections()?;
        context.layer.reader = Some(reader);
        self.pending_writer = Some(writer);
        self.state = TLS12ServerState::Finished;
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
