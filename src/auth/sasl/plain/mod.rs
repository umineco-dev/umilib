//! PLAIN (RFC 4616): one message from the client, the authorization
//! identity (optional), the authentication identity and the password,
//! separated by NUL. It sends the password in the clear: use it only over
//! a channel that protects it (TLS).

use alloc::string::String;
use alloc::vec::Vec;

use super::SASLError;
use crate::codec::stringprep::{StringPrepProfile, Unassigned};
use crate::secret::{ConstantTimeEq, Secret};

/// The message of PLAIN (RFC 4616 §2).
#[derive(Clone, Debug)]
pub struct PLAINMessage {
    pub authzid: Option<String>,
    pub authcid: String,
    pub password: Secret<String>,
}

impl PLAINMessage {
    pub fn new(authzid: Option<&str>, authcid: &str, password: &str) -> PLAINMessage {
        PLAINMessage {
            authzid: authzid.map(String::from),
            authcid: String::from(authcid),
            password: Secret::new(String::from(password)),
        }
    }

    /// `[authzid] NUL authcid NUL passwd`; fails with [`SASLError::Length`]
    /// for an empty authentication identity, password or present
    /// authorization identity, and with [`SASLError::Format`] for NUL in one.
    pub fn encode(&self) -> Result<Secret<Vec<u8>>, SASLError> {
        let authzid = self.authzid.as_deref().unwrap_or_default();
        for field in [self.authcid.as_str(), self.password.expose().as_str()] {
            PLAINMessage::check(field)?;
        }
        if self.authzid.is_some() {
            PLAINMessage::check(authzid)?;
        }
        let mut message = Vec::with_capacity(authzid.len() + self.authcid.len() + self.password.expose().len() + 2);
        message.extend_from_slice(authzid.as_bytes());
        message.push(0);
        message.extend_from_slice(self.authcid.as_bytes());
        message.push(0);
        message.extend_from_slice(self.password.expose().as_bytes());
        Ok(Secret::new(message))
    }

    /// The message of `message`: UTF-8 with exactly two NULs, a non-empty
    /// authentication identity and password; an empty authorization
    /// identity is absent. Fails with [`SASLError::Format`] or
    /// [`SASLError::Length`].
    pub fn decode(message: &[u8]) -> Result<PLAINMessage, SASLError> {
        let text = core::str::from_utf8(message).map_err(|_| SASLError::Format)?;
        let mut fields = text.split('\0');
        let (Some(authzid), Some(authcid), Some(password), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(SASLError::Format);
        };
        if authcid.is_empty() || password.is_empty() {
            return Err(SASLError::Length);
        }
        Ok(PLAINMessage::new((!authzid.is_empty()).then_some(authzid), authcid, password))
    }

    /// Fails unless `field` is `1*SAFE`: not empty, without NUL.
    pub fn check(field: &str) -> Result<(), SASLError> {
        if field.is_empty() {
            return Err(SASLError::Length);
        }
        if field.contains('\0') {
            return Err(SASLError::Format);
        }
        Ok(())
    }

    /// `text` prepared with SASLprep (RFC 4616 §2: presented strings as
    /// queries, the strings of the database as stored strings); fails with
    /// [`SASLError::Length`] for an empty result, since verification must
    /// then fail.
    pub fn prepare(text: &str, unassigned: Unassigned) -> Result<String, SASLError> {
        let prepared = StringPrepProfile::SASLPREP.prepare(text, unassigned)?;
        if prepared.is_empty() {
            return Err(SASLError::Length);
        }
        Ok(prepared)
    }

    /// The authentication identity prepared as a query: what the server
    /// looks up, and the authorization identity it derives when none is given.
    pub fn prepared_authcid(&self) -> Result<String, SASLError> {
        PLAINMessage::prepare(&self.authcid, Unassigned::Allowed)
    }

    /// Whether the password, prepared as a query, is `stored` (the password
    /// of the database) prepared as a stored string, compared in constant
    /// time; false if either preparation fails (RFC 4616 §2).
    pub fn verify_password(&self, stored: &str) -> bool {
        let (Ok(presented), Ok(stored)) = (
            PLAINMessage::prepare(self.password.expose(), Unassigned::Allowed).map(Secret::new),
            PLAINMessage::prepare(stored, Unassigned::Prohibited).map(Secret::new),
        ) else {
            return false;
        };
        presented.expose().as_bytes().ct_eq(stored.expose().as_bytes()).into_bool()
    }
}
