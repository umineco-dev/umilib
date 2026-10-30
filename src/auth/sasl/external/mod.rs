//! EXTERNAL (RFC 4422 appendix A): the client asks the server to use the
//! credentials it established outside SASL (TLS client certificates, for
//! example); the one message is the authorization identity, if any.

use alloc::string::String;
use alloc::vec::Vec;

use super::SASLError;

/// The message of EXTERNAL (RFC 4422 appendix A.1): empty, or the
/// authorization identity the client asks to act as.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EXTERNALMessage {
    pub authzid: Option<String>,
}

impl EXTERNALMessage {
    pub fn new(authzid: Option<&str>) -> EXTERNALMessage {
        EXTERNALMessage { authzid: authzid.map(String::from) }
    }

    /// The UTF-8 of the authorization identity; fails with
    /// [`SASLError::Format`] for NUL, and [`SASLError::Length`] for an empty
    /// identity (absent is written as the empty message).
    pub fn encode(&self) -> Result<Vec<u8>, SASLError> {
        match &self.authzid {
            None => Ok(Vec::new()),
            Some(authzid) if authzid.is_empty() => Err(SASLError::Length),
            Some(authzid) if authzid.contains('\0') => Err(SASLError::Format),
            Some(authzid) => Ok(authzid.as_bytes().to_vec()),
        }
    }

    /// The message of `message`: UTF-8 without NUL; empty is no authorization identity.
    pub fn decode(message: &[u8]) -> Result<EXTERNALMessage, SASLError> {
        let text = core::str::from_utf8(message).map_err(|_| SASLError::Format)?;
        if text.contains('\0') {
            return Err(SASLError::Format);
        }
        Ok(EXTERNALMessage::new((!text.is_empty()).then_some(text)))
    }
}
