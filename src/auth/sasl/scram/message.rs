use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::super::GS2Header;
use super::{SCRAMError, SCRAMServerError};
use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;
use crate::crypto::random::Random;

/// An attribute of a SCRAM message (RFC 5802 §7, `attr-val`): a letter,
/// `=`, and a value of UTF-8 without NUL or `,`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SCRAMAttribute<'a> {
    pub name: char,
    pub value: &'a str,
}

impl<'a> SCRAMAttribute<'a> {
    /// The letters RFC 5802 defines: an extension may not use them.
    pub const DEFINED: [char; 10] = ['a', 'c', 'e', 'i', 'm', 'n', 'p', 'r', 's', 'v'];

    /// The attributes of `text`, separated by `,`; `None` unless each is a
    /// letter, `=` and a non-empty value without NUL.
    pub fn parse(text: &'a str) -> Option<Vec<SCRAMAttribute<'a>>> {
        text.split(',')
            .map(|part| {
                let mut characters = part.chars();
                let name = characters.next().filter(char::is_ascii_alphabetic)?;
                let value = characters.as_str().strip_prefix('=').filter(|value| !value.is_empty())?;
                if value.contains('\0') {
                    return None;
                }
                Some(SCRAMAttribute { name, value })
            })
            .collect()
    }

    /// The extensions after the attributes a message defines: attributes
    /// whose letters RFC 5802 does not define (RFC 5802 §7, `extensions`).
    pub fn extensions(attributes: &[SCRAMAttribute<'_>]) -> Option<Vec<(char, String)>> {
        attributes
            .iter()
            .map(|attribute| {
                (!SCRAMAttribute::DEFINED.contains(&attribute.name))
                    .then(|| (attribute.name, attribute.value.to_string()))
            })
            .collect()
    }

    /// Whether `text` is `printable` (RFC 5802 §7): ASCII from `!` to `~`
    /// except `,`, at least one character, as nonces are.
    pub fn is_printable(text: &str) -> bool {
        !text.is_empty() && text.bytes().all(|byte| (0x21..=0x7E).contains(&byte) && byte != b',')
    }

    /// `,x=value` for each extension.
    pub fn write_extensions(text: &mut String, extensions: &[(char, String)]) -> Result<(), SCRAMError> {
        for (name, value) in extensions {
            let valid = name.is_ascii_alphabetic()
                && !SCRAMAttribute::DEFINED.contains(name)
                && !value.is_empty()
                && !value.contains([',', '\0']);
            if !valid {
                return Err(SCRAMError::Format);
            }
            text.push(',');
            text.push(*name);
            text.push('=');
            text.push_str(value);
        }
        Ok(())
    }
}

/// The nonces of SCRAM (RFC 5802 §5.1, `r=`): random, different for each
/// exchange, `printable`.
pub struct SCRAMNonce;

impl SCRAMNonce {
    /// The random bytes of a nonce this module generates, in base64.
    pub const SIZE: usize = 24;

    /// A nonce of [`SCRAMNonce::SIZE`] random bytes in base64 (whose
    /// characters are all `printable`).
    pub fn random<R: Random>(random: &mut R) -> Result<String, SCRAMError> {
        let mut bytes = [0u8; SCRAMNonce::SIZE];
        random.fill(&mut bytes).map_err(|_| SCRAMError::Random)?;
        Ok(Base64::STANDARD.encode(&bytes))
    }
}

/// The client-first-message (RFC 5802 §7): the GS2 header, the username
/// (as sent, before escaping), the nonce of the client and extensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SCRAMClientFirst {
    pub header: GS2Header,
    pub username: String,
    pub nonce: String,
    pub extensions: Vec<(char, String)>,
}

impl SCRAMClientFirst {
    /// `client-first-message-bare`: `n=` the escaped username, `,r=` the
    /// nonce and the extensions.
    pub fn bare(&self) -> Result<String, SCRAMError> {
        if !SCRAMAttribute::is_printable(&self.nonce) {
            return Err(SCRAMError::Format);
        }
        let mut text = String::from("n=");
        text.push_str(&GS2Header::escape(&self.username).map_err(|_| SCRAMError::Format)?);
        text.push_str(",r=");
        text.push_str(&self.nonce);
        SCRAMAttribute::write_extensions(&mut text, &self.extensions)?;
        Ok(text)
    }

    /// The GS2 header (which SCRAM sends without the non-standard flag)
    /// followed by the bare message.
    pub fn encode(&self) -> Result<Vec<u8>, SCRAMError> {
        if self.header.nonstandard {
            return Err(SCRAMError::Format);
        }
        let mut text = self.header.encode().map_err(|_| SCRAMError::Format)?;
        text.push_str(&self.bare()?);
        Ok(text.into_bytes())
    }

    /// The message of `message`, as a server reads it: the errors are the
    /// values the server reports (`invalid-encoding`, `extensions-not-supported`
    /// for `m=`, `invalid-username-encoding` for a bad escape, RFC 5802 §5.1).
    pub fn decode(message: &[u8]) -> Result<SCRAMClientFirst, SCRAMError> {
        let invalid = SCRAMError::Server(SCRAMServerError::InvalidEncoding);
        let text = core::str::from_utf8(message).map_err(|_| invalid)?;
        let (header, bare) = GS2Header::decode(text).map_err(|_| invalid)?;
        // RFC 5802 §5: the message starts with n, y or p.
        if header.nonstandard {
            return Err(invalid);
        }
        let attributes = SCRAMAttribute::parse(bare).ok_or(invalid)?;
        if attributes.first().is_some_and(|attribute| attribute.name == 'm') {
            return Err(SCRAMError::Server(SCRAMServerError::ExtensionsNotSupported));
        }
        let [username, nonce, extensions @ ..] = attributes.as_slice() else { return Err(invalid) };
        if username.name != 'n' || nonce.name != 'r' || !SCRAMAttribute::is_printable(nonce.value) {
            return Err(invalid);
        }
        let username = GS2Header::unescape(username.value)
            .map_err(|_| SCRAMError::Server(SCRAMServerError::InvalidUsernameEncoding))?;
        let extensions = SCRAMAttribute::extensions(extensions).ok_or(invalid)?;
        Ok(SCRAMClientFirst { header, username, nonce: nonce.value.to_string(), extensions })
    }
}

/// The server-first-message (RFC 5802 §7): the nonce (the client's
/// followed by the server's), the salt, the iteration count and extensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SCRAMServerFirst {
    pub nonce: String,
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub extensions: Vec<(char, String)>,
}

impl SCRAMServerFirst {
    pub fn encode(&self) -> Result<Vec<u8>, SCRAMError> {
        if !SCRAMAttribute::is_printable(&self.nonce) || self.iterations == 0 || self.salt.is_empty() {
            return Err(SCRAMError::Format);
        }
        let mut text =
            alloc::format!("r={},s={},i={}", self.nonce, Base64::STANDARD.encode(&self.salt), self.iterations);
        SCRAMAttribute::write_extensions(&mut text, &self.extensions)?;
        Ok(text.into_bytes())
    }

    /// The message of `message`, as a client reads it; an iteration count
    /// beyond 32 bits is [`SCRAMError::Iterations`].
    pub fn decode(message: &[u8]) -> Result<SCRAMServerFirst, SCRAMError> {
        let text = core::str::from_utf8(message).map_err(|_| SCRAMError::Format)?;
        let attributes = SCRAMAttribute::parse(text).ok_or(SCRAMError::Format)?;
        if attributes.first().is_some_and(|attribute| attribute.name == 'm') {
            return Err(SCRAMError::Extension);
        }
        let [nonce, salt, iterations, extensions @ ..] = attributes.as_slice() else { return Err(SCRAMError::Format) };
        if nonce.name != 'r' || salt.name != 's' || iterations.name != 'i' || !SCRAMAttribute::is_printable(nonce.value)
        {
            return Err(SCRAMError::Format);
        }
        let salt = Base64::STANDARD.decode(salt.value.as_bytes()).map_err(|_| SCRAMError::Format)?;
        let iterations = SCRAMServerFirst::positive_number(iterations.value)?;
        let extensions = SCRAMAttribute::extensions(extensions).ok_or(SCRAMError::Format)?;
        Ok(SCRAMServerFirst { nonce: nonce.value.to_string(), salt, iterations, extensions })
    }

    /// The `posit-number` `text` (a digit 1 to 9, then digits).
    pub fn positive_number(text: &str) -> Result<u32, SCRAMError> {
        let digits = text.bytes().all(|byte| byte.is_ascii_digit());
        if !digits || text.starts_with('0') {
            return Err(SCRAMError::Format);
        }
        text.parse().map_err(|_| SCRAMError::Iterations)
    }
}

/// The client-final-message (RFC 5802 §7): the channel binding input (the
/// GS2 header and the channel binding data), the nonce, extensions and the
/// proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SCRAMClientFinal {
    pub channel_binding: Vec<u8>,
    pub nonce: String,
    pub extensions: Vec<(char, String)>,
    pub proof: Vec<u8>,
}

impl SCRAMClientFinal {
    /// `client-final-message-without-proof`, which the AuthMessage holds.
    pub fn without_proof(&self) -> Result<String, SCRAMError> {
        if !SCRAMAttribute::is_printable(&self.nonce) {
            return Err(SCRAMError::Format);
        }
        let mut text = alloc::format!("c={},r={}", Base64::STANDARD.encode(&self.channel_binding), self.nonce);
        SCRAMAttribute::write_extensions(&mut text, &self.extensions)?;
        Ok(text)
    }

    pub fn encode(&self) -> Result<Vec<u8>, SCRAMError> {
        let mut text = self.without_proof()?;
        text.push_str(",p=");
        text.push_str(&Base64::STANDARD.encode(&self.proof));
        Ok(text.into_bytes())
    }

    /// The message of `message`, as a server reads it (errors as the
    /// server reports them).
    pub fn decode(message: &[u8]) -> Result<SCRAMClientFinal, SCRAMError> {
        let invalid = SCRAMError::Server(SCRAMServerError::InvalidEncoding);
        let text = core::str::from_utf8(message).map_err(|_| invalid)?;
        let attributes = SCRAMAttribute::parse(text).ok_or(invalid)?;
        let [channel_binding, nonce, extensions @ .., proof] = attributes.as_slice() else { return Err(invalid) };
        if channel_binding.name != 'c' || nonce.name != 'r' || proof.name != 'p' {
            return Err(invalid);
        }
        if !SCRAMAttribute::is_printable(nonce.value) {
            return Err(invalid);
        }
        if extensions.iter().any(|attribute| attribute.name == 'm') {
            return Err(SCRAMError::Server(SCRAMServerError::ExtensionsNotSupported));
        }
        let base64 = |value: &str| Base64::STANDARD.decode(value.as_bytes()).map_err(|_| invalid);
        Ok(SCRAMClientFinal {
            channel_binding: base64(channel_binding.value)?,
            nonce: nonce.value.to_string(),
            extensions: SCRAMAttribute::extensions(extensions).ok_or(invalid)?,
            proof: base64(proof.value)?,
        })
    }
}

/// The server-final-message (RFC 5802 §7): the ServerSignature, or an
/// error. Extensions after it are ignored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SCRAMServerFinal {
    Verifier(Vec<u8>),
    Error(SCRAMServerError),
}

impl SCRAMServerFinal {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            SCRAMServerFinal::Verifier(signature) => alloc::format!("v={}", Base64::STANDARD.encode(signature)),
            SCRAMServerFinal::Error(error) => alloc::format!("e={}", error.name()),
        }
        .into_bytes()
    }

    /// The message of `message`, as a client reads it.
    pub fn decode(message: &[u8]) -> Result<SCRAMServerFinal, SCRAMError> {
        let text = core::str::from_utf8(message).map_err(|_| SCRAMError::Format)?;
        let attributes = SCRAMAttribute::parse(text).ok_or(SCRAMError::Format)?;
        let [first, extensions @ ..] = attributes.as_slice() else { return Err(SCRAMError::Format) };
        SCRAMAttribute::extensions(extensions).ok_or(SCRAMError::Format)?;
        match first.name {
            'v' => Ok(SCRAMServerFinal::Verifier(
                Base64::STANDARD.decode(first.value.as_bytes()).map_err(|_| SCRAMError::Format)?,
            )),
            'e' => Ok(SCRAMServerFinal::Error(SCRAMServerError::from_name(first.value))),
            _ => Err(SCRAMError::Format),
        }
    }
}
