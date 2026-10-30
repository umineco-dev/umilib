//! The C ABI of [`crate::auth::sasl::scram`].
//!
//! [`SCRAMClient<H>`], [`SCRAMServer<H>`] and [`SCRAMCredentials<H>`] are
//! exported as one type each, over the hash function whose C type is named
//! when they are created: `umilib_hash_sha_v1_SHA1` (SCRAM-SHA-1) or
//! `umilib_hash_sha_v2_SHA256` (SCRAM-SHA-256). A server error crosses as
//! its index in [`SCRAMServerError::ALL`].

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;

use super::SASLStatus;
use crate::auth::sasl::SASLMechanism;
use crate::auth::sasl::scram::{
    SCRAMClient, SCRAMConfig, SCRAMCredentials, SCRAMError, SCRAMNonce, SCRAMSecret, SCRAMServer, SCRAMServerError,
};
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};
use crate::hash::sha::v1::SHA1;
use crate::hash::sha::v2::SHA256;
use crate::secret::Secret;

/// The statuses of this module: one per server error of RFC 5802 §7 and
/// one per other variant of [`SCRAMError`].
pub struct SCRAMStatus;

impl SCRAMStatus {
    pub const INVALID_ENCODING: Status = Status::new(c"auth.sasl.scram", c"InvalidEncoding", c"invalid-encoding");
    pub const EXTENSIONS_NOT_SUPPORTED: Status =
        Status::new(c"auth.sasl.scram", c"ExtensionsNotSupported", c"extensions-not-supported");
    pub const INVALID_PROOF: Status = Status::new(c"auth.sasl.scram", c"InvalidProof", c"invalid-proof");
    pub const CHANNEL_BINDINGS_DONT_MATCH: Status =
        Status::new(c"auth.sasl.scram", c"ChannelBindingsDontMatch", c"channel-bindings-dont-match");
    pub const SERVER_DOES_SUPPORT_CHANNEL_BINDING: Status =
        Status::new(c"auth.sasl.scram", c"ServerDoesSupportChannelBinding", c"server-does-support-channel-binding");
    pub const CHANNEL_BINDING_NOT_SUPPORTED: Status =
        Status::new(c"auth.sasl.scram", c"ChannelBindingNotSupported", c"channel-binding-not-supported");
    pub const UNSUPPORTED_CHANNEL_BINDING_TYPE: Status =
        Status::new(c"auth.sasl.scram", c"UnsupportedChannelBindingType", c"unsupported-channel-binding-type");
    pub const UNKNOWN_USER: Status = Status::new(c"auth.sasl.scram", c"UnknownUser", c"unknown-user");
    pub const INVALID_USERNAME_ENCODING: Status =
        Status::new(c"auth.sasl.scram", c"InvalidUsernameEncoding", c"invalid-username-encoding");
    pub const NO_RESOURCES: Status = Status::new(c"auth.sasl.scram", c"NoResources", c"no-resources");
    pub const OTHER_ERROR: Status = Status::new(c"auth.sasl.scram", c"OtherError", c"other-error");
    pub const FORMAT: Status = Status::new(c"auth.sasl.scram", c"Format", c"malformed SCRAM message");
    pub const EXTENSION: Status =
        Status::new(c"auth.sasl.scram", c"Extension", c"unsupported mandatory SCRAM extension");
    pub const NONCE: Status =
        Status::new(c"auth.sasl.scram", c"Nonce", c"the server nonce does not extend the client nonce");
    pub const ITERATIONS: Status =
        Status::new(c"auth.sasl.scram", c"Iterations", c"iteration count outside the configuration");
    pub const SERVER_SIGNATURE: Status =
        Status::new(c"auth.sasl.scram", c"ServerSignature", c"the server signature does not verify");
    pub const SALT: Status =
        Status::new(c"auth.sasl.scram", c"Salt", c"the cached salted password is for another salt");
    pub const RANDOM: Status = Status::new(c"auth.sasl.scram", c"Random", c"the random source failed");
    pub const STATE: Status = Status::new(c"auth.sasl.scram", c"State", c"SCRAM step out of order");

    /// The server error at `index` of [`SCRAMServerError::ALL`]; InvalidArgument past it.
    pub fn server_error_at(index: u8) -> Result<SCRAMServerError, &'static Status> {
        SCRAMServerError::ALL.get(index as usize).copied().ok_or(&Status::INVALID_ARGUMENT)
    }

    pub fn server_error(error: SCRAMServerError) -> &'static Status {
        match error {
            SCRAMServerError::InvalidEncoding => &SCRAMStatus::INVALID_ENCODING,
            SCRAMServerError::ExtensionsNotSupported => &SCRAMStatus::EXTENSIONS_NOT_SUPPORTED,
            SCRAMServerError::InvalidProof => &SCRAMStatus::INVALID_PROOF,
            SCRAMServerError::ChannelBindingsDontMatch => &SCRAMStatus::CHANNEL_BINDINGS_DONT_MATCH,
            SCRAMServerError::ServerDoesSupportChannelBinding => &SCRAMStatus::SERVER_DOES_SUPPORT_CHANNEL_BINDING,
            SCRAMServerError::ChannelBindingNotSupported => &SCRAMStatus::CHANNEL_BINDING_NOT_SUPPORTED,
            SCRAMServerError::UnsupportedChannelBindingType => &SCRAMStatus::UNSUPPORTED_CHANNEL_BINDING_TYPE,
            SCRAMServerError::UnknownUser => &SCRAMStatus::UNKNOWN_USER,
            SCRAMServerError::InvalidUsernameEncoding => &SCRAMStatus::INVALID_USERNAME_ENCODING,
            SCRAMServerError::NoResources => &SCRAMStatus::NO_RESOURCES,
            SCRAMServerError::OtherError => &SCRAMStatus::OTHER_ERROR,
        }
    }
}

impl ToStatus for SCRAMError {
    fn to_status(&self) -> &'static Status {
        match self {
            SCRAMError::Server(error) => SCRAMStatus::server_error(*error),
            SCRAMError::Format => &SCRAMStatus::FORMAT,
            SCRAMError::Extension => &SCRAMStatus::EXTENSION,
            SCRAMError::Nonce => &SCRAMStatus::NONCE,
            SCRAMError::Iterations => &SCRAMStatus::ITERATIONS,
            SCRAMError::ServerSignature => &SCRAMStatus::SERVER_SIGNATURE,
            SCRAMError::Salt => &SCRAMStatus::SALT,
            SCRAMError::Prepare(error) => error.to_status(),
            SCRAMError::Random => &SCRAMStatus::RANDOM,
            SCRAMError::State => &SCRAMStatus::STATE,
        }
    }
}

/// Calls `$body` with `$inner` bound to the value of every variant of
/// `$value`, an enum of this module over SHA-1 and SHA-256.
macro_rules! scram_dispatch {
    ($kind:ident, $value:expr, $inner:ident => $body:expr) => {
        match $value {
            $kind::SHA1($inner) => $body,
            $kind::SHA256($inner) => $body,
        }
    };
}

/// [`SCRAMClient`] over SHA-1 or SHA-256.
#[derive(Clone, Debug)]
pub enum SCRAMClientChoice {
    SHA1(SCRAMClient<SHA1>),
    SHA256(SCRAMClient<SHA256>),
}

/// [`SCRAMServer`] over SHA-1 or SHA-256.
#[derive(Clone, Debug)]
pub enum SCRAMServerChoice {
    SHA1(SCRAMServer<SHA1>),
    SHA256(SCRAMServer<SHA256>),
}

/// [`SCRAMCredentials`] over SHA-1 or SHA-256.
#[derive(Clone, Debug)]
pub enum SCRAMCredentialsChoice {
    SHA1(SCRAMCredentials<SHA1>),
    SHA256(SCRAMCredentials<SHA256>),
}

impl SCRAMClientChoice {
    pub fn new(
        hash: &str,
        username: &str,
        secret: SCRAMSecret,
        nonce: &str,
    ) -> Result<SCRAMClientChoice, &'static Status> {
        match hash {
            SCRAMHashName::SHA1 => Ok(SCRAMClientChoice::SHA1(SCRAMClient::new(username, secret, nonce))),
            SCRAMHashName::SHA256 => Ok(SCRAMClientChoice::SHA256(SCRAMClient::new(username, secret, nonce))),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

impl SCRAMServerChoice {
    pub fn new(hash: &str, plus: bool) -> Result<SCRAMServerChoice, &'static Status> {
        match hash {
            SCRAMHashName::SHA1 => Ok(SCRAMServerChoice::SHA1(SCRAMServer::new(plus))),
            SCRAMHashName::SHA256 => Ok(SCRAMServerChoice::SHA256(SCRAMServer::new(plus))),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

impl SCRAMCredentialsChoice {
    pub fn new(
        hash: &str,
        password: &str,
        salt: &[u8],
        iterations: u32,
    ) -> Result<SCRAMCredentialsChoice, &'static Status> {
        let status = |error: SCRAMError| error.to_status();
        match hash {
            SCRAMHashName::SHA1 => {
                SCRAMCredentials::new(password, salt, iterations).map(SCRAMCredentialsChoice::SHA1).map_err(status)
            }
            SCRAMHashName::SHA256 => {
                SCRAMCredentials::new(password, salt, iterations).map(SCRAMCredentialsChoice::SHA256).map_err(status)
            }
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    pub fn from_parts(
        hash: &str,
        salt: &[u8],
        iterations: u32,
        stored_key: &[u8],
        server_key: &[u8],
    ) -> Result<SCRAMCredentialsChoice, &'static Status> {
        let status = |error: SCRAMError| error.to_status();
        match hash {
            SCRAMHashName::SHA1 => SCRAMCredentials::from_parts(salt, iterations, stored_key, server_key)
                .map(SCRAMCredentialsChoice::SHA1)
                .map_err(status),
            SCRAMHashName::SHA256 => SCRAMCredentials::from_parts(salt, iterations, stored_key, server_key)
                .map(SCRAMCredentialsChoice::SHA256)
                .map_err(status),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

/// The C type names of the hash functions of SCRAM.
pub struct SCRAMHashName;

impl SCRAMHashName {
    pub const SHA1: &'static str = "umilib_hash_sha_v1_SHA1";
    pub const SHA256: &'static str = "umilib_hash_sha_v2_SHA256";
}

impl Value for SCRAMClientChoice {
    const TYPE: Type = Type::Named("umilib_auth_sasl_scram_SCRAMClient");
}

impl Value for SCRAMServerChoice {
    const TYPE: Type = Type::Named("umilib_auth_sasl_scram_SCRAMServer");
}

impl Value for SCRAMCredentialsChoice {
    const TYPE: Type = Type::Named("umilib_auth_sasl_scram_SCRAMCredentials");
}

crate::ffi_functions! {
    /// Writes a nonce of random bytes drawn from `random` in base64 into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_nonce_random(random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a generator of the named type and a writable buffer.
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let nonce = SCRAMNonce::random(&mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, nonce) }
        })())
    }

    /// Writes the value of `e=` of the server error at `index` into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_server_error_name(index: u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let error = SCRAMStatus::server_error_at(index)?;
            // SAFETY: the caller passes a writable buffer.
            unsafe { Pointer::write_text(out, String::from(error.name())) }
        })())
    }

    /// Writes the client over the hash function named by `hash` for the username at `username`, the
    /// password at `password` and the client nonce at `nonce` (all UTF-8) into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_client_new(hash: *const u8, hash_length: usize, username: *const u8, username_length: usize, password: *const u8, password_length: usize, nonce: *const u8, nonce_length: usize, out: *mut *mut SCRAMClientChoice) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let username = unsafe { Pointer::text(username, username_length) }?;
            let password = unsafe { Pointer::text(password, password_length) }?;
            let nonce = unsafe { Pointer::text(nonce, nonce_length) }?;
            let secret = SCRAMSecret::Password(Secret::new(String::from(password)));
            unsafe { Pointer::write_handle(out, SCRAMClientChoice::new(hash, username, secret, nonce)?) }
        })())
    }

    /// Writes the client of a SaltedPassword kept from an earlier exchange (with its salt and
    /// iteration count) into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_client_from_salted_password(hash: *const u8, hash_length: usize, username: *const u8, username_length: usize, salt: *const u8, salt_length: usize, iterations: u32, salted_password: *const u8, salted_password_length: usize, nonce: *const u8, nonce_length: usize, out: *mut *mut SCRAMClientChoice) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let username = unsafe { Pointer::text(username, username_length) }?;
            let salt = unsafe { Pointer::slice(salt, salt_length) }?;
            let salted_password = unsafe { Pointer::slice(salted_password, salted_password_length) }?;
            let nonce = unsafe { Pointer::text(nonce, nonce_length) }?;
            let secret = SCRAMSecret::SaltedPassword { salt: salt.to_vec(), iterations, salted_password: Secret::new(salted_password.to_vec()) };
            unsafe { Pointer::write_handle(out, SCRAMClientChoice::new(hash, username, secret, nonce)?) }
        })())
    }

    /// Sets the authorization identity to the UTF-8 text at `authzid`, or none for null.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_client_set_authzid(client: *mut SCRAMClientChoice, authzid: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and null or readable text.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let authzid = unsafe { Pointer::optional_text(authzid, length) }?.map(String::from);
            scram_dispatch!(SCRAMClientChoice, client, inner => inner.authzid = authzid);
            Ok(())
        })())
    }

    /// Sets the channel binding flag `kind` (0 `n`, 1 `y`, 2 `p` with the type's name at `name`)
    /// and its data at `data` (present exactly for 2).
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_client_set_channel_binding(client: *mut SCRAMClientChoice, kind: u8, name: *const u8, name_length: usize, data: *const u8, data_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, null or readable text, and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let name = unsafe { Pointer::optional_text(name, name_length) }?;
            let data = unsafe { Pointer::slice(data, data_length) }?;
            let binding = SASLStatus::channel_binding(kind, name)?;
            scram_dispatch!(SCRAMClientChoice, client, inner => {
                inner.channel_binding = binding;
                inner.channel_binding_data = data.to_vec();
            });
            Ok(())
        })())
    }

    /// Sets the iteration counts the client accepts.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_client_set_iterations(client: *mut SCRAMClientChoice, minimum: u32, maximum: u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let config = SCRAMConfig { minimum_iterations: minimum, maximum_iterations: maximum };
            scram_dispatch!(SCRAMClientChoice, client, inner => inner.config = config);
            Ok(())
        })())
    }

    /// Writes the index of the mechanism the client runs (the `-PLUS` variant with channel binding) into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_client_mechanism(client: *const SCRAMClientChoice, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            let mechanism = scram_dispatch!(SCRAMClientChoice, client, inner => inner.mechanism());
            unsafe { Pointer::write(out, SASLMechanism::ALL.iter().position(|own| *own == mechanism).unwrap_or_default() as u8) }
        })())
    }

    /// Writes the client-first-message into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_client_client_first(client: *mut SCRAMClientChoice, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let message = scram_dispatch!(SCRAMClientChoice, client, inner => inner.client_first()).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(message)) }
        })())
    }

    /// Reads the server-first-message at `message` and writes the client-final-message into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_client_receive_server_first(client: *mut SCRAMClientChoice, message: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable buffer.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let message = unsafe { Pointer::slice(message, length) }?;
            let reply = scram_dispatch!(SCRAMClientChoice, client, inner => inner.receive_server_first(message)).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(reply)) }
        })())
    }

    /// Reads the server-final-message at `message`: succeeds if the server proved it knows the key.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_client_receive_server_final(client: *mut SCRAMClientChoice, message: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let message = unsafe { Pointer::slice(message, length) }?;
            scram_dispatch!(SCRAMClientChoice, client, inner => inner.receive_server_final(message)).map_err(|error| error.to_status())
        })())
    }

    /// Writes whether the exchange succeeded into `out_has` and, if so, the salt into `out_salt`,
    /// the iteration count into `out_iterations` and the SaltedPassword into `out`, to keep.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_client_salted_secret(client: *const SCRAMClientChoice, out_has: *mut bool, out_salt: *mut Buffer, out_iterations: *mut u32, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let client = unsafe { Pointer::reference(client) }?;
            let secret = scram_dispatch!(SCRAMClientChoice, client, inner => inner.salted_secret());
            let (salt, iterations, salted) = match secret {
                Some(SCRAMSecret::SaltedPassword { salt, iterations, salted_password }) => (salt, iterations, salted_password.expose().clone()),
                _ => (Vec::new(), 0, Vec::new()),
            };
            unsafe { Pointer::write(out_has, !salted.is_empty()) }?;
            unsafe { Pointer::write(out_salt, Buffer::from_vec(salt)) }?;
            unsafe { Pointer::write(out_iterations, iterations) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(salted)) }
        })())
    }

    /// Writes a copy of `client` into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_client_clone(client: *const SCRAMClientChoice, out: *mut *mut SCRAMClientChoice) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write_handle(out, client.clone()) }
        })())
    }

    /// Releases a client, zeroizing its secrets. Does nothing if `client` is null.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_client_free(client: *mut SCRAMClientChoice) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(client) }
    }

    /// Writes the server over the hash function named by `hash`, for the `-PLUS` mechanism if `plus`, into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_server_new(hash: *const u8, hash_length: usize, plus: bool, out: *mut *mut SCRAMServerChoice) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            unsafe { Pointer::write_handle(out, SCRAMServerChoice::new(hash, plus)?) }
        })())
    }

    /// Adds the channel binding type named by the UTF-8 text at `name` with its data at `data`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_server_add_channel_binding(server: *mut SCRAMServerChoice, name: *const u8, name_length: usize, data: *const u8, data_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            let data = unsafe { Pointer::slice(data, data_length) }?;
            scram_dispatch!(SCRAMServerChoice, server, inner => inner.add_channel_binding(name, data));
            Ok(())
        })())
    }

    /// Reads the client-first-message at `message`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_server_receive_client_first(server: *mut SCRAMServerChoice, message: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let message = unsafe { Pointer::slice(message, length) }?;
            scram_dispatch!(SCRAMServerChoice, server, inner => inner.receive_client_first(message).map(|_| ())).map_err(|error| error.to_status())
        })())
    }

    /// Writes the username (prepared with SASLprep), once the client-first-message is read, into `out_has` and `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_server_username(server: *const SCRAMServerChoice, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            let username = scram_dispatch!(SCRAMServerChoice, server, inner => inner.username().map(String::from));
            unsafe { Pointer::write_optional_text(out_has, out, username.as_deref()) }
        })())
    }

    /// Writes the authorization identity of the client-first-message, if any, into `out_has` and `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_server_authzid(server: *const SCRAMServerChoice, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            let authzid = scram_dispatch!(SCRAMServerChoice, server, inner => inner.authzid().map(String::from));
            unsafe { Pointer::write_optional_text(out_has, out, authzid.as_deref()) }
        })())
    }

    /// Writes the server-first-message for the user's `credentials` (of the same hash function) and
    /// the server's part of the nonce at `nonce` into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_server_server_first(server: *mut SCRAMServerChoice, credentials: *const SCRAMCredentialsChoice, nonce: *const u8, nonce_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, readable text and a writable buffer.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let credentials = unsafe { Pointer::reference(credentials) }?;
            let nonce = unsafe { Pointer::text(nonce, nonce_length) }?;
            let message = match (server, credentials) {
                (SCRAMServerChoice::SHA1(server), SCRAMCredentialsChoice::SHA1(credentials)) => server.server_first(credentials, nonce),
                (SCRAMServerChoice::SHA256(server), SCRAMCredentialsChoice::SHA256(credentials)) => server.server_first(credentials, nonce),
                _ => return Err(&Status::INVALID_ARGUMENT),
            }
            .map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(message)) }
        })())
    }

    /// Reads the client-final-message at `message` and writes the server-final-message into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_server_receive_client_final(server: *mut SCRAMServerChoice, message: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable buffer.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let message = unsafe { Pointer::slice(message, length) }?;
            let reply = scram_dispatch!(SCRAMServerChoice, server, inner => inner.receive_client_final(message)).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(reply)) }
        })())
    }

    /// Ends the exchange with the server error at `index` and writes the server-final-message that reports it into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_server_reject(server: *mut SCRAMServerChoice, index: u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let error = SCRAMStatus::server_error_at(index)?;
            let message = scram_dispatch!(SCRAMServerChoice, server, inner => inner.reject(error));
            unsafe { Pointer::write(out, Buffer::from_vec(message)) }
        })())
    }

    /// Writes a copy of `server` into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_server_clone(server: *const SCRAMServerChoice, out: *mut *mut SCRAMServerChoice) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write_handle(out, server.clone()) }
        })())
    }

    /// Releases a server, zeroizing its keys. Does nothing if `server` is null.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_server_free(server: *mut SCRAMServerChoice) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(server) }
    }

    /// Writes the credentials of the password at `password` with the salt at `salt` and `iterations`
    /// over the hash function named by `hash` into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_credentials_new(hash: *const u8, hash_length: usize, password: *const u8, password_length: usize, salt: *const u8, salt_length: usize, iterations: u32, out: *mut *mut SCRAMCredentialsChoice) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let password = unsafe { Pointer::text(password, password_length) }?;
            let salt = unsafe { Pointer::slice(salt, salt_length) }?;
            unsafe { Pointer::write_handle(out, SCRAMCredentialsChoice::new(hash, password, salt, iterations)?) }
        })())
    }

    /// Writes the credentials of their stored parts into `out`; fails with Format for keys of another size than the hash output.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_credentials_from_parts(hash: *const u8, hash_length: usize, salt: *const u8, salt_length: usize, iterations: u32, stored_key: *const u8, stored_key_length: usize, server_key: *const u8, server_key_length: usize, out: *mut *mut SCRAMCredentialsChoice) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let salt = unsafe { Pointer::slice(salt, salt_length) }?;
            let stored_key = unsafe { Pointer::slice(stored_key, stored_key_length) }?;
            let server_key = unsafe { Pointer::slice(server_key, server_key_length) }?;
            unsafe { Pointer::write_handle(out, SCRAMCredentialsChoice::from_parts(hash, salt, iterations, stored_key, server_key)?) }
        })())
    }

    /// Writes the salt into `out_salt`, the iteration count into `out_iterations`, StoredKey into
    /// `out_stored_key` and ServerKey into `out_server_key`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_credentials_parts(credentials: *const SCRAMCredentialsChoice, out_salt: *mut Buffer, out_iterations: *mut u32, out_stored_key: *mut Buffer, out_server_key: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let credentials = unsafe { Pointer::reference(credentials) }?;
            let (salt, iterations, stored, server) = scram_dispatch!(SCRAMCredentialsChoice, credentials, inner => (
                inner.salt.clone(), inner.iterations, inner.stored_key.expose().clone(), inner.server_key.expose().clone()
            ));
            unsafe { Pointer::write(out_salt, Buffer::from_vec(salt)) }?;
            unsafe { Pointer::write(out_iterations, iterations) }?;
            unsafe { Pointer::write(out_stored_key, Buffer::from_vec(stored)) }?;
            unsafe { Pointer::write(out_server_key, Buffer::from_vec(server)) }
        })())
    }

    /// Writes a copy of `credentials` into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_credentials_clone(credentials: *const SCRAMCredentialsChoice, out: *mut *mut SCRAMCredentialsChoice) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let credentials = unsafe { Pointer::reference(credentials) }?;
            unsafe { Pointer::write_handle(out, credentials.clone()) }
        })())
    }

    /// Releases credentials, zeroizing ServerKey. Does nothing if `credentials` is null.
    pub unsafe extern "C" fn umilib_auth_sasl_scram_scram_credentials_free(credentials: *mut SCRAMCredentialsChoice) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(credentials) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "scram",
    definitions: &[
        Definition::Opaque {
            name: "umilib_auth_sasl_scram_SCRAMClient",
            documentation: " The client of SCRAM (RFC 5802) over SHA-1 or SHA-256.",
        },
        Definition::Opaque {
            name: "umilib_auth_sasl_scram_SCRAMServer",
            documentation: " The server of SCRAM (RFC 5802) over SHA-1 or SHA-256.",
        },
        Definition::Opaque {
            name: "umilib_auth_sasl_scram_SCRAMCredentials",
            documentation: " What a SCRAM server keeps for a user.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
