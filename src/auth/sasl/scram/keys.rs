use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{SCRAMError, SCRAMHash};
use crate::codec::stringprep::{StringPrepProfile, Unassigned};
use crate::crypto::hmac::HMAC;
use crate::crypto::pbkdf2::PBKDF2;
use crate::secret::{Secret, Zeroize};

/// The keys of SCRAM (RFC 5802 §3) for a password, a salt and an
/// iteration count: SaltedPassword = Hi(Normalize(password), salt, i),
/// ClientKey = HMAC(SaltedPassword, "Client Key"), StoredKey = H(ClientKey)
/// and ServerKey = HMAC(SaltedPassword, "Server Key").
#[derive(Clone, Debug)]
pub struct SCRAMKeys<H: SCRAMHash> {
    pub salted_password: Secret<Vec<u8>>,
    pub client_key: Secret<Vec<u8>>,
    pub stored_key: Secret<Vec<u8>>,
    pub server_key: Secret<Vec<u8>>,
    pub hash: PhantomData<H>,
}

impl<H: SCRAMHash> SCRAMKeys<H> {
    /// The keys of `password`, prepared with SASLprep as a stored string
    /// (Normalize, RFC 5802 §2.2), with `salt` and `iterations` (at least one).
    pub fn from_password(password: &str, salt: &[u8], iterations: u32) -> Result<SCRAMKeys<H>, SCRAMError> {
        let password = Secret::new(SCRAMKeys::<H>::normalize(password)?);
        let mut salted = Secret::new(alloc::vec![0u8; H::OUTPUT_SIZE]);
        PBKDF2::<H>::derive(password.expose().as_bytes(), salt, iterations, salted.expose_mut())
            .map_err(|_| SCRAMError::Iterations)?;
        Ok(SCRAMKeys::from_salted_password(salted))
    }

    /// The keys of a SaltedPassword (which a client may keep to log in
    /// again without the cost of Hi, RFC 5802 §5.1).
    pub fn from_salted_password(salted_password: Secret<Vec<u8>>) -> SCRAMKeys<H> {
        let mac = |label: &[u8]| {
            let mut output = HMAC::<H>::mac(salted_password.expose(), label);
            let key = Secret::new(output.as_ref().to_vec());
            output.as_mut().zeroize();
            key
        };
        let client_key = mac(b"Client Key");
        let server_key = mac(b"Server Key");
        let mut digest = H::digest(client_key.expose());
        let stored_key = Secret::new(digest.as_ref().to_vec());
        digest.as_mut().zeroize();
        SCRAMKeys { salted_password, client_key, stored_key, server_key, hash: PhantomData }
    }

    /// Normalize (RFC 5802 §2.2): SASLprep of a stored string.
    pub fn normalize(password: &str) -> Result<String, SCRAMError> {
        Ok(StringPrepProfile::SASLPREP.prepare(password, Unassigned::Prohibited)?)
    }

    /// HMAC(key, message) over the hash of the mechanism.
    pub fn hmac(key: &[u8], message: &[u8]) -> Secret<Vec<u8>> {
        let mut output = HMAC::<H>::mac(key, message);
        let value = Secret::new(output.as_ref().to_vec());
        output.as_mut().zeroize();
        value
    }
}

/// What a server keeps for a user (RFC 5802 §3): the salt, the iteration
/// count, StoredKey and ServerKey; not the password.
#[derive(Clone, Debug)]
pub struct SCRAMCredentials<H: SCRAMHash> {
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub stored_key: Secret<Vec<u8>>,
    pub server_key: Secret<Vec<u8>>,
    pub hash: PhantomData<H>,
}

impl<H: SCRAMHash> SCRAMCredentials<H> {
    /// The credentials of `password` with `salt` (random, of
    /// [`SCRAMCredentials::SALT_SIZE`] bytes or more) and `iterations`.
    /// Fails with [`SCRAMError::Format`] for an empty salt, which the
    /// server-first-message cannot carry (RFC 5802 §7: a value has one
    /// character or more).
    pub fn new(password: &str, salt: &[u8], iterations: u32) -> Result<SCRAMCredentials<H>, SCRAMError> {
        if salt.is_empty() {
            return Err(SCRAMError::Format);
        }
        let keys = SCRAMKeys::<H>::from_password(password, salt, iterations)?;
        Ok(SCRAMCredentials::from_keys(&keys, salt, iterations))
    }

    /// The bytes of a salt this module generates.
    pub const SALT_SIZE: usize = 16;

    pub fn from_keys(keys: &SCRAMKeys<H>, salt: &[u8], iterations: u32) -> SCRAMCredentials<H> {
        SCRAMCredentials {
            salt: salt.to_vec(),
            iterations,
            stored_key: keys.stored_key.clone(),
            server_key: keys.server_key.clone(),
            hash: PhantomData,
        }
    }

    /// Credentials made of their parts, as read from storage; fails with
    /// [`SCRAMError::Format`] for keys of another size than the hash output,
    /// an empty salt or no iteration.
    pub fn from_parts(
        salt: &[u8],
        iterations: u32,
        stored_key: &[u8],
        server_key: &[u8],
    ) -> Result<SCRAMCredentials<H>, SCRAMError> {
        if stored_key.len() != H::OUTPUT_SIZE
            || server_key.len() != H::OUTPUT_SIZE
            || iterations == 0
            || salt.is_empty()
        {
            return Err(SCRAMError::Format);
        }
        Ok(SCRAMCredentials {
            salt: salt.to_vec(),
            iterations,
            stored_key: Secret::new(stored_key.to_vec()),
            server_key: Secret::new(server_key.to_vec()),
            hash: PhantomData,
        })
    }
}

/// The iteration counts a client accepts from a server: at least
/// `minimum_iterations` (RFC 5802 §5.1 and RFC 7677 §3 ask servers for 4096
/// or more) and at most `maximum_iterations`, which bounds the work a
/// server can make the client do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SCRAMConfig {
    pub minimum_iterations: u32,
    pub maximum_iterations: u32,
}

impl SCRAMConfig {
    pub const MINIMUM_ITERATIONS: u32 = 4096;
    pub const MAXIMUM_ITERATIONS: u32 = 1_000_000;
}

impl Default for SCRAMConfig {
    fn default() -> SCRAMConfig {
        SCRAMConfig {
            minimum_iterations: SCRAMConfig::MINIMUM_ITERATIONS,
            maximum_iterations: SCRAMConfig::MAXIMUM_ITERATIONS,
        }
    }
}
