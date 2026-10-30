use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::super::{GS2ChannelBinding, GS2Header};
use super::{
    SCRAMClientFinal, SCRAMClientFirst, SCRAMConfig, SCRAMError, SCRAMHash, SCRAMKeys, SCRAMServerFinal,
    SCRAMServerFirst,
};
use crate::codec::stringprep::{StringPrepProfile, Unassigned};
use crate::secret::{ConstantTimeEq, Secret};

/// What the client knows: the password, or a SaltedPassword kept from an
/// earlier exchange for its salt and iteration count (RFC 5802 §5.1).
#[derive(Clone, Debug)]
pub enum SCRAMSecret {
    Password(Secret<String>),
    SaltedPassword { salt: Vec<u8>, iterations: u32, salted_password: Secret<Vec<u8>> },
}

/// Where a client is in its exchange.
#[derive(Clone, Debug)]
pub enum SCRAMClientState {
    /// Before the client-first-message.
    Start,
    /// The client-first-message is sent; its bare part is kept for the AuthMessage.
    ServerFirst { client_first_bare: String },
    /// The client-final-message is sent; the ServerSignature to expect.
    ServerFinal { server_signature: Secret<Vec<u8>> },
    /// The server proved it knows the key.
    Done,
    /// A step failed; the exchange cannot go on.
    Failed,
}

/// The client of SCRAM over `H` (RFC 5802 §5), without I/O: each step
/// takes the message of the server and returns the message to send.
#[derive(Clone, Debug)]
pub struct SCRAMClient<H: SCRAMHash> {
    pub username: String,
    pub authzid: Option<String>,
    pub secret: SCRAMSecret,
    pub nonce: String,
    pub channel_binding: GS2ChannelBinding,
    pub channel_binding_data: Vec<u8>,
    pub config: SCRAMConfig,
    pub state: SCRAMClientState,
    /// The SaltedPassword of the exchange with its salt and iteration
    /// count, once the server-first-message is read.
    pub salted: Option<SCRAMSecret>,
    pub hash: PhantomData<H>,
}

impl<H: SCRAMHash> SCRAMClient<H> {
    /// The client of `username` with `secret` and the client nonce `nonce`
    /// (see [`super::SCRAMNonce::random`]), without channel binding (`n`)
    /// or authorization identity, with the default configuration.
    pub fn new(username: &str, secret: SCRAMSecret, nonce: &str) -> SCRAMClient<H> {
        SCRAMClient {
            username: String::from(username),
            authzid: None,
            secret,
            nonce: String::from(nonce),
            channel_binding: GS2ChannelBinding::Unsupported,
            channel_binding_data: Vec::new(),
            config: SCRAMConfig::default(),
            state: SCRAMClientState::Start,
            salted: None,
            hash: PhantomData,
        }
    }

    /// The name of the mechanism the client runs: the `-PLUS` variant
    /// exactly when it uses channel binding.
    pub fn mechanism(&self) -> super::super::SASLMechanism {
        match self.channel_binding {
            GS2ChannelBinding::Required(_) => H::PLUS_MECHANISM,
            _ => H::MECHANISM,
        }
    }

    /// The client-first-message. The username is prepared with SASLprep
    /// as a query (RFC 5802 §5.1); channel binding data must be present
    /// exactly when channel binding is used (RFC 5802 §7, `cbind-input`).
    pub fn client_first(&mut self) -> Result<Vec<u8>, SCRAMError> {
        if !matches!(self.state, SCRAMClientState::Start) {
            return Err(SCRAMError::State);
        }
        let binding = matches!(self.channel_binding, GS2ChannelBinding::Required(_));
        if binding == self.channel_binding_data.is_empty() {
            return self.fail(SCRAMError::Format);
        }
        let username = match StringPrepProfile::SASLPREP.prepare(&self.username, Unassigned::Allowed) {
            Ok(username) => username,
            Err(error) => return self.fail(SCRAMError::Prepare(error)),
        };
        let message = SCRAMClientFirst {
            header: GS2Header::new(self.channel_binding.clone(), self.authzid.as_deref()),
            username,
            nonce: self.nonce.clone(),
            extensions: Vec::new(),
        };
        let encoded = match (message.encode(), message.bare()) {
            (Ok(encoded), Ok(bare)) => {
                self.state = SCRAMClientState::ServerFirst { client_first_bare: bare };
                encoded
            }
            (Err(error), _) | (_, Err(error)) => return self.fail(error),
        };
        Ok(encoded)
    }

    /// Reads the server-first-message and returns the client-final-message
    /// with the ClientProof (RFC 5802 §3). The nonce of the server must
    /// begin with the client's and add to it, and the iteration count must
    /// be within the configuration.
    pub fn receive_server_first(&mut self, message: &[u8]) -> Result<Vec<u8>, SCRAMError> {
        let SCRAMClientState::ServerFirst { client_first_bare } = &self.state else { return Err(SCRAMError::State) };
        let client_first_bare = client_first_bare.clone();
        let result = self.client_final(&client_first_bare, message);
        match result {
            Ok((final_message, server_signature)) => {
                self.state = SCRAMClientState::ServerFinal { server_signature };
                Ok(final_message)
            }
            Err(error) => self.fail(error),
        }
    }

    /// The client-final-message for the server-first-message `message`, and
    /// the ServerSignature to expect.
    pub fn client_final(
        &mut self,
        client_first_bare: &str,
        message: &[u8],
    ) -> Result<(Vec<u8>, Secret<Vec<u8>>), SCRAMError> {
        let server_first = SCRAMServerFirst::decode(message)?;
        let extends = server_first.nonce.len() > self.nonce.len() && server_first.nonce.starts_with(&self.nonce);
        if !extends {
            return Err(SCRAMError::Nonce);
        }
        let iterations = server_first.iterations;
        if !(self.config.minimum_iterations..=self.config.maximum_iterations).contains(&iterations) {
            return Err(SCRAMError::Iterations);
        }
        let keys = match &self.secret {
            SCRAMSecret::Password(password) => {
                SCRAMKeys::<H>::from_password(password.expose(), &server_first.salt, iterations)?
            }
            SCRAMSecret::SaltedPassword { salt, iterations: cached, salted_password } => {
                if *salt != server_first.salt || *cached != iterations {
                    return Err(SCRAMError::Salt);
                }
                SCRAMKeys::from_salted_password(salted_password.clone())
            }
        };
        let header = GS2Header::new(self.channel_binding.clone(), self.authzid.as_deref());
        let mut binding_input = header.encode().map_err(|_| SCRAMError::Format)?.into_bytes();
        binding_input.extend_from_slice(&self.channel_binding_data);
        let mut client_final = SCRAMClientFinal {
            channel_binding: binding_input,
            nonce: server_first.nonce.clone(),
            extensions: Vec::new(),
            proof: Vec::new(),
        };
        let server_first_text = core::str::from_utf8(message).map_err(|_| SCRAMError::Format)?;
        let auth_message = alloc::format!("{client_first_bare},{server_first_text},{}", client_final.without_proof()?);
        let client_signature = SCRAMKeys::<H>::hmac(keys.stored_key.expose(), auth_message.as_bytes());
        client_final.proof = keys
            .client_key
            .expose()
            .iter()
            .zip(client_signature.expose())
            .map(|(key, signature)| key ^ signature)
            .collect();
        let server_signature = SCRAMKeys::<H>::hmac(keys.server_key.expose(), auth_message.as_bytes());
        let encoded = client_final.encode()?;
        self.salted = Some(SCRAMSecret::SaltedPassword {
            salt: server_first.salt,
            iterations,
            salted_password: keys.salted_password.clone(),
        });
        Ok((encoded, server_signature))
    }

    /// Reads the server-final-message: the exchange succeeds if it holds
    /// the ServerSignature, compared in constant time (RFC 5802 §5); an
    /// error of the server is [`SCRAMError::Server`].
    pub fn receive_server_final(&mut self, message: &[u8]) -> Result<(), SCRAMError> {
        let SCRAMClientState::ServerFinal { server_signature } = &self.state else { return Err(SCRAMError::State) };
        let verified = match SCRAMServerFinal::decode(message) {
            Ok(SCRAMServerFinal::Verifier(signature)) => {
                if signature.as_slice().ct_eq(server_signature.expose().as_slice()).into_bool() {
                    Ok(())
                } else {
                    Err(SCRAMError::ServerSignature)
                }
            }
            Ok(SCRAMServerFinal::Error(error)) => Err(SCRAMError::Server(error)),
            Err(error) => Err(error),
        };
        match verified {
            Ok(()) => {
                self.state = SCRAMClientState::Done;
                Ok(())
            }
            Err(error) => self.fail(error),
        }
    }

    /// The secret to keep for the next exchange with the same server: the
    /// SaltedPassword with its salt and iteration count, once the exchange
    /// succeeded (the server proved it knows the key).
    pub fn salted_secret(&self) -> Option<SCRAMSecret> {
        if !matches!(self.state, SCRAMClientState::Done) {
            return None;
        }
        self.salted.clone()
    }

    /// Ends the exchange with `error`.
    pub fn fail<T>(&mut self, error: SCRAMError) -> Result<T, SCRAMError> {
        self.state = SCRAMClientState::Failed;
        Err(error)
    }
}
