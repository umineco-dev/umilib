use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::protocol::tls::{
    TLSAlert, TLSAlertDescription, TLSAlertLevel, TLSContentType, TLSContext, TLSError, TLSHandshake,
    TLSHandshakeProtocol, TLSHandshakeType, TLSRole,
};
use crate::secret::Secret;

use super::TLS12PRF;

/// A TLS 1.2 connection after its handshake: what exporters need (RFC
/// 5705). Renegotiation is refused (RFC 5746 allows it to be): a
/// HelloRequest or a new ClientHello is answered with the warning
/// `no_renegotiation` (RFC 5246 §7.2.2).
pub struct TLS12Established {
    pub role: TLSRole,
    pub prf: TLS12PRF,
    pub main: Secret<Vec<u8>>,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
}

impl TLSHandshakeProtocol for TLS12Established {
    fn receive(
        self: Box<Self>,
        message: TLSHandshake,
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError> {
        let renegotiation = match self.role {
            TLSRole::Client => message.kind == TLSHandshakeType::HELLO_REQUEST && message.body.is_empty(),
            TLSRole::Server => message.kind == TLSHandshakeType::CLIENT_HELLO,
        };
        if !renegotiation {
            return Err(TLSError::unexpected());
        }
        let mut alert = Vec::new();
        TLSAlert { level: TLSAlertLevel::WARNING, description: TLSAlertDescription::NO_RENEGOTIATION }
            .encode(&mut alert)?;
        context.layer.write(TLSContentType::ALERT, &alert)?;
        Ok(self)
    }

    /// A ChangeCipherSpec after the handshake is `unexpected_message`.
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
        self.prf.export(self.main.expose(), label, context, &self.client_random, &self.server_random, out)
    }

    /// TLS 1.2 has no KeyUpdate.
    fn update_keys(&mut self, _request: bool, _context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        Err(TLSError::State)
    }
}
