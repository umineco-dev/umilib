use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;

use super::{
    TLSAlertDescription, TLSClientHello, TLSConfig, TLSContext, TLSError, TLSExtension, TLSExtensionContext,
    TLSExtensionType, TLSHandshake, TLSHandshakeProtocol, TLSHandshakeType, TLSRecordSizeLimit, TLSServerConfig,
    TLSServerNames, TLSSupportedVersions, TLSVersion,
};

/// A server waiting for its first ClientHello, which decides the version
/// (RFC 9846 §4.3.1, Appendix E.2): the highest of `supported_versions`
/// that both support, or TLS 1.2 for a client without the extension.
pub struct TLSServerStart {
    pub config: Arc<TLSServerConfig>,
}

impl TLSServerStart {
    pub fn new(config: Arc<TLSServerConfig>) -> TLSServerStart {
        TLSServerStart { config }
    }

    /// The host name the client asks for (`server_name`), lowercase.
    pub fn requested_name(hello: &TLSClientHello) -> Result<Option<String>, TLSError> {
        Ok(hello
            .extension(TLSExtensionType::SERVER_NAME)
            .map(TLSServerNames::decode)
            .transpose()?
            .and_then(|names| names.host_name().map(<[u8]>::to_vec))
            .and_then(|name| String::from_utf8(name).ok())
            .map(|name| name.to_ascii_lowercase()))
    }

    /// The client's `record_size_limit` (RFC 8449 §4): its limit applies to
    /// what this server sends, and this server's own limit, in the
    /// extension returned to answer with, to what it receives.
    pub fn limit_records(
        config: &TLSConfig,
        hello: &TLSClientHello,
        version: TLSVersion,
        context: &mut TLSContext<'_>,
    ) -> Result<Option<TLSExtension>, TLSError> {
        let Some(data) = hello.extension(TLSExtensionType::RECORD_SIZE_LIMIT) else { return Ok(None) };
        let peer = TLSRecordSizeLimit::decode(data)?;
        let own = TLSRecordSizeLimit::advertising(config.record_size_limit, version);
        context.layer.peer_limit = peer.0 as usize;
        context.layer.own_limit = own.plaintext(version);
        Ok(Some(TLSExtension::with(TLSExtensionType::RECORD_SIZE_LIMIT, |out| own.encode(out))?))
    }

    /// The rules of the transport for `hello` and `version` (RFC 9001 §4.2,
    /// §8.2, §8.4): with QUIC, TLS 1.3 only (`protocol_version`), the
    /// client's transport parameters (`missing_extension`, kept in the
    /// session) and an empty session ID (PROTOCOL_VIOLATION); over records,
    /// no transport parameters (`unsupported_extension`).
    pub fn check_transport(
        hello: &TLSClientHello,
        version: TLSVersion,
        context: &mut TLSContext<'_>,
    ) -> Result<(), TLSError> {
        let parameters = hello.extension(TLSExtensionType::QUIC_TRANSPORT_PARAMETERS);
        if context.layer.quic.is_none() {
            return match parameters {
                Some(_) => Err(TLSError::Protocol(TLSAlertDescription::UNSUPPORTED_EXTENSION)),
                None => Ok(()),
            };
        }
        if version != TLSVersion::TLS1_3 {
            return Err(TLSError::Protocol(TLSAlertDescription::PROTOCOL_VERSION));
        }
        let parameters = parameters.ok_or(TLSError::Protocol(TLSAlertDescription::MISSING_EXTENSION))?;
        if !hello.legacy_session_id.is_empty() {
            return Err(TLSError::Transport);
        }
        context.session.transport_parameters = Some(parameters.to_vec());
        Ok(())
    }

    /// The version to negotiate with `hello`; fails with `protocol_version`
    /// if there is none in common.
    pub fn version(&self, hello: &TLSClientHello) -> Result<TLSVersion, TLSError> {
        let ours = |version: TLSVersion| version.is_supported() && self.config.config.versions.contains(&version);
        let version = match hello.extension(TLSExtensionType::SUPPORTED_VERSIONS) {
            // The server's preference among the versions the client lists; unknown ones are ignored.
            Some(data) => {
                let TLSSupportedVersions::Offered(offered) =
                    TLSSupportedVersions::decode(data, TLSExtensionContext::ClientHello)?
                else {
                    return Err(TLSError::decode());
                };
                self.config.config.versions.iter().copied().find(|version| ours(*version) && offered.contains(version))
            }
            // Without the extension, TLS 1.2 or nothing (RFC 9846 §4.3.1, RFC 8996).
            None => {
                (hello.legacy_version >= TLSVersion::TLS1_2 && ours(TLSVersion::TLS1_2)).then_some(TLSVersion::TLS1_2)
            }
        };
        version.ok_or(TLSError::Protocol(TLSAlertDescription::PROTOCOL_VERSION))
    }
}

impl TLSHandshakeProtocol for TLSServerStart {
    fn receive(
        self: Box<Self>,
        message: TLSHandshake,
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        if message.kind != TLSHandshakeType::CLIENT_HELLO {
            return Err(TLSError::unexpected());
        }
        // The ClientHello comes before a key change: it ends its record (RFC 9846 §5.1).
        context.layer.check_boundary()?;
        #[allow(unused_mut)]
        let mut bytes = message.to_bytes()?;
        #[allow(unused_mut)]
        let mut hello = TLSClientHello::decode(&message.body)?;
        // With ECH, the ClientHelloInner that the server's key opens is the one that counts (RFC 9849 §7.1).
        #[allow(unused_mut)]
        let mut ech: Option<alloc::boxed::Box<super::TLSECHAcceptance>> = None;
        // Only a server of TLS 1.3 accepts ECH, which offers no other version (RFC 9849 §6.1).
        #[cfg(umilib_feature = "crypto-hpke")]
        if TLSVersion::TLS1_3.is_supported()
            && self.config.config.versions.contains(&TLSVersion::TLS1_3)
            && let Some((inner, acceptance)) =
                super::TLSECH::accept(&self.config.ech_keys, &hello, &mut context.session.ech)?
        {
            bytes = TLSHandshake::new(TLSHandshakeType::CLIENT_HELLO, inner.to_bytes()?).to_bytes()?;
            hello = inner;
            ech = Some(alloc::boxed::Box::new(acceptance));
        }
        #[cfg(not(umilib_feature = "protocol-tls-v1_3"))]
        let _ = &ech;
        let version = self.version(&hello)?;
        TLSServerStart::check_transport(&hello, version, context)?;
        context.session.version = Some(version);
        match version {
            #[cfg(umilib_feature = "protocol-tls-v1_3")]
            TLSVersion::TLS1_3 => super::v1_3::TLS13Server::from_client_hello(self.config, hello, &bytes, ech, context),
            #[cfg(umilib_feature = "protocol-tls-v1_2")]
            TLSVersion::TLS1_2 => super::v1_2::TLS12Server::from_client_hello(self.config, hello, &bytes, context),
            _ => Err(TLSError::Protocol(TLSAlertDescription::PROTOCOL_VERSION)),
        }
    }

    /// No ChangeCipherSpec may come before the ClientHello.
    fn receive_change_cipher_spec(
        self: Box<Self>,
        _fragment: &[u8],
        _context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        Err(TLSError::unexpected())
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
