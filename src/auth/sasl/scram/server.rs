use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::super::{GS2ChannelBinding, GS2Header, SASLMechanism};
use super::{
    SCRAMAttribute, SCRAMClientFinal, SCRAMClientFirst, SCRAMCredentials, SCRAMError, SCRAMHash, SCRAMKeys,
    SCRAMServerError, SCRAMServerFinal, SCRAMServerFirst,
};
use crate::codec::stringprep::{StringPrepProfile, Unassigned};
use crate::secret::{ConstantTimeEq, Secret, Zeroize};

/// Where a server is in its exchange.
#[derive(Clone, Debug)]
pub enum SCRAMServerState {
    /// Before the client-first-message.
    Start,
    /// The client-first-message is read: the application looks up the
    /// credentials of `username` (prepared with SASLprep).
    Credentials { client_first: SCRAMClientFirst, username: String, header: String, bare: String },
    /// The server-first-message is sent; the identities of the client are kept.
    ClientFinal {
        username: String,
        authzid: Option<String>,
        header: String,
        binding_data: Vec<u8>,
        auth_prefix: String,
        nonce: String,
        stored_key: Secret<Vec<u8>>,
        server_key: Secret<Vec<u8>>,
    },
    /// The client proved it knows the password of `username`; the
    /// application checks that it may act as `authzid` (RFC 5802 §5).
    Done { username: String, authzid: Option<String> },
    /// A step failed: the server sends the error ([`SCRAMServer::reject`]).
    Failed,
}

/// The server of SCRAM over `H` (RFC 5802 §5), without I/O: the
/// application reads the client-first-message, looks up the credentials of
/// the user, and passes them on. `plus` tells whether the client chose the
/// `-PLUS` mechanism; the channel bindings are the types (with their data
/// for this channel) the server supports.
#[derive(Clone, Debug)]
pub struct SCRAMServer<H: SCRAMHash> {
    pub plus: bool,
    pub channel_bindings: Vec<(String, Vec<u8>)>,
    pub state: SCRAMServerState,
    pub hash: PhantomData<H>,
}

impl<H: SCRAMHash> SCRAMServer<H> {
    /// A server for the mechanism the client chose: with channel binding
    /// (`plus`, the `-PLUS` variant) or without.
    pub fn new(plus: bool) -> SCRAMServer<H> {
        SCRAMServer { plus, channel_bindings: Vec::new(), state: SCRAMServerState::Start, hash: PhantomData }
    }

    /// Adds a channel binding type the server supports, with its data for
    /// this channel (the `tls-exporter` value of the TLS connection, say).
    pub fn add_channel_binding(&mut self, name: &str, data: &[u8]) {
        self.channel_bindings.push((String::from(name), data.to_vec()));
    }

    pub fn mechanism(&self) -> SASLMechanism {
        if self.plus { H::PLUS_MECHANISM } else { H::MECHANISM }
    }

    /// Reads the client-first-message and returns it. The channel binding
    /// flag must agree with the mechanism and with what the server supports
    /// (RFC 5802 §6: `y` from a client of a server that supports channel
    /// binding is a downgrade), and the username must survive SASLprep.
    pub fn receive_client_first(&mut self, message: &[u8]) -> Result<&SCRAMClientFirst, SCRAMError> {
        if !matches!(self.state, SCRAMServerState::Start) {
            return Err(SCRAMError::State);
        }
        self.state = match self.client_first(message) {
            Ok(state) => state,
            Err(error) => return self.fail(error),
        };
        match &self.state {
            SCRAMServerState::Credentials { client_first, .. } => Ok(client_first),
            _ => Err(SCRAMError::State),
        }
    }

    pub fn client_first(&self, message: &[u8]) -> Result<SCRAMServerState, SCRAMError> {
        let client_first = SCRAMClientFirst::decode(message)?;
        let supported = !self.channel_bindings.is_empty();
        match (&client_first.header.channel_binding, self.plus) {
            (GS2ChannelBinding::Required(name), true) => {
                if !supported {
                    return Err(SCRAMError::Server(SCRAMServerError::ChannelBindingNotSupported));
                }
                if !self.channel_bindings.iter().any(|(own, _)| own == name) {
                    return Err(SCRAMError::Server(SCRAMServerError::UnsupportedChannelBindingType));
                }
            }
            (GS2ChannelBinding::Required(_), false) => {
                return Err(SCRAMError::Server(SCRAMServerError::ChannelBindingNotSupported));
            }
            (_, true) => return Err(SCRAMError::Server(SCRAMServerError::OtherError)),
            (GS2ChannelBinding::NotOffered, false) if supported => {
                return Err(SCRAMError::Server(SCRAMServerError::ServerDoesSupportChannelBinding));
            }
            (_, false) => {}
        }
        let username = StringPrepProfile::SASLPREP
            .prepare(&client_first.username, Unassigned::Allowed)
            .ok()
            .filter(|username| !username.is_empty())
            .ok_or(SCRAMError::Server(SCRAMServerError::InvalidUsernameEncoding))?;
        // The text as received goes into the AuthMessage and the channel binding (RFC 5802 §5.1).
        let text = core::str::from_utf8(message).map_err(|_| SCRAMError::Server(SCRAMServerError::InvalidEncoding))?;
        let (_, bare) = GS2Header::decode(text).map_err(|_| SCRAMError::Server(SCRAMServerError::InvalidEncoding))?;
        let header = String::from(&text[..text.len() - bare.len()]);
        Ok(SCRAMServerState::Credentials { client_first, username, header, bare: String::from(bare) })
    }

    /// The username the application looks up, prepared with SASLprep as a
    /// query, from the reading of the client-first-message to the end of a
    /// successful exchange (the authenticated identity).
    pub fn username(&self) -> Option<&str> {
        match &self.state {
            SCRAMServerState::Credentials { username, .. }
            | SCRAMServerState::ClientFinal { username, .. }
            | SCRAMServerState::Done { username, .. } => Some(username),
            _ => None,
        }
    }

    /// The authorization identity the client asks to act as (`a=`), if any,
    /// over the same steps as [`SCRAMServer::username`].
    pub fn authzid(&self) -> Option<&str> {
        match &self.state {
            SCRAMServerState::Credentials { client_first, .. } => client_first.header.authzid.as_deref(),
            SCRAMServerState::ClientFinal { authzid, .. } | SCRAMServerState::Done { authzid, .. } => {
                authzid.as_deref()
            }
            _ => None,
        }
    }

    /// The server-first-message for the user's `credentials`, with the
    /// server's part of the nonce `nonce` (see [`super::SCRAMNonce::random`]).
    pub fn server_first(&mut self, credentials: &SCRAMCredentials<H>, nonce: &str) -> Result<Vec<u8>, SCRAMError> {
        let SCRAMServerState::Credentials { client_first, username, header, bare } = &self.state else {
            return Err(SCRAMError::State);
        };
        if !SCRAMAttribute::is_printable(nonce) {
            return self.fail(SCRAMError::Format);
        }
        let full = alloc::format!("{}{nonce}", client_first.nonce);
        let server_first = SCRAMServerFirst {
            nonce: full.clone(),
            salt: credentials.salt.clone(),
            iterations: credentials.iterations,
            extensions: Vec::new(),
        };
        let encoded = match server_first.encode() {
            Ok(encoded) => encoded,
            Err(error) => return self.fail(error),
        };
        let binding_data = match &client_first.header.channel_binding {
            GS2ChannelBinding::Required(name) => self
                .channel_bindings
                .iter()
                .find(|(own, _)| own == name)
                .map(|(_, data)| data.clone())
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let auth_prefix = alloc::format!("{bare},{}", core::str::from_utf8(&encoded).map_err(|_| SCRAMError::Format)?);
        self.state = SCRAMServerState::ClientFinal {
            username: username.clone(),
            authzid: client_first.header.authzid.clone(),
            header: header.clone(),
            binding_data,
            auth_prefix,
            nonce: full,
            stored_key: credentials.stored_key.clone(),
            server_key: credentials.server_key.clone(),
        };
        Ok(encoded)
    }

    /// Reads the client-final-message and returns the server-final-message
    /// with the ServerSignature, if the channel binding, the nonce and the
    /// ClientProof are right (RFC 5802 §3, §6); the ClientKey is checked
    /// against StoredKey in constant time.
    pub fn receive_client_final(&mut self, message: &[u8]) -> Result<Vec<u8>, SCRAMError> {
        if !matches!(self.state, SCRAMServerState::ClientFinal { .. }) {
            return Err(SCRAMError::State);
        }
        match self.server_final(message) {
            Ok(final_message) => {
                if let SCRAMServerState::ClientFinal { username, authzid, .. } = &mut self.state {
                    let (username, authzid) = (core::mem::take(username), authzid.take());
                    self.state = SCRAMServerState::Done { username, authzid };
                }
                Ok(final_message)
            }
            Err(error) => self.fail(error),
        }
    }

    pub fn server_final(&self, message: &[u8]) -> Result<Vec<u8>, SCRAMError> {
        let SCRAMServerState::ClientFinal { header, binding_data, auth_prefix, nonce, stored_key, server_key, .. } =
            &self.state
        else {
            return Err(SCRAMError::State);
        };
        let client_final = SCRAMClientFinal::decode(message)?;
        let mut expected = header.as_bytes().to_vec();
        expected.extend_from_slice(binding_data);
        if client_final.channel_binding != expected {
            return Err(SCRAMError::Server(SCRAMServerError::ChannelBindingsDontMatch));
        }
        if client_final.nonce != *nonce {
            return Err(SCRAMError::Server(SCRAMServerError::OtherError));
        }
        let text = core::str::from_utf8(message).map_err(|_| SCRAMError::Server(SCRAMServerError::InvalidEncoding))?;
        let (without_proof, _) =
            text.rsplit_once(",p=").ok_or(SCRAMError::Server(SCRAMServerError::InvalidEncoding))?;
        let auth_message = alloc::format!("{auth_prefix},{without_proof}");
        let client_signature = SCRAMKeys::<H>::hmac(stored_key.expose(), auth_message.as_bytes());
        if client_final.proof.len() != H::OUTPUT_SIZE {
            return Err(SCRAMError::Server(SCRAMServerError::InvalidProof));
        }
        let client_key: Secret<Vec<u8>> = Secret::new(
            client_final
                .proof
                .iter()
                .zip(client_signature.expose())
                .map(|(proof, signature)| proof ^ signature)
                .collect(),
        );
        let mut digest = H::digest(client_key.expose());
        let valid = digest.as_ref().ct_eq(stored_key.expose().as_slice());
        digest.as_mut().zeroize();
        if !valid.into_bool() {
            return Err(SCRAMError::Server(SCRAMServerError::InvalidProof));
        }
        let server_signature = SCRAMKeys::<H>::hmac(server_key.expose(), auth_message.as_bytes());
        Ok(SCRAMServerFinal::Verifier(server_signature.expose().clone()).encode())
    }

    /// Ends the exchange with `error` and returns the server-final-message
    /// that reports it (RFC 5802 §5.1: the server may also end without one).
    pub fn reject(&mut self, error: SCRAMServerError) -> Vec<u8> {
        self.state = SCRAMServerState::Failed;
        SCRAMServerFinal::Error(error).encode()
    }

    /// Ends the exchange with `error`.
    pub fn fail<T>(&mut self, error: SCRAMError) -> Result<T, SCRAMError> {
        self.state = SCRAMServerState::Failed;
        Err(error)
    }
}
