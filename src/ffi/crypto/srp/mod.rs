//! The C ABI of [`crate::crypto::srp`].
//!
//! The group is named by the C type name of its type
//! (`umilib_crypto_srp_SRP1024` to `umilib_crypto_srp_SRP8192`) and the hash
//! function by one of [`ffi_standard_digests!`](crate::ffi_standard_digests)
//! (`umilib_hash_sha_v1_SHA1` for RFC 5054). [`SRPClient`] and [`SRPServer`]
//! are the handles `umilib_crypto_srp_SRPClient` and
//! `umilib_crypto_srp_SRPServer`; integers are big-endian.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::CryptoError;
use crate::crypto::srp::{SRP, SRPClient, SRPGroup, SRPServer};
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};
use crate::hash::CryptographicDigest;

/// A client of any group and hash function: [`SRPClient`] chosen at run time.
pub trait SRPClientState {
    fn public_value(&self) -> Vec<u8>;

    fn premaster_secret(
        &self,
        identity: &[u8],
        password: &[u8],
        salt: &[u8],
        server_public: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

impl<G: SRPGroup, H: CryptographicDigest + Default> SRPClientState for SRPClient<G, H> {
    fn public_value(&self) -> Vec<u8> {
        SRPClient::public_value(self)
    }

    fn premaster_secret(
        &self,
        identity: &[u8],
        password: &[u8],
        salt: &[u8],
        server_public: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        SRPClient::premaster_secret(self, identity, password, salt, server_public)
    }
}

/// A server of any group and hash function: [`SRPServer`] chosen at run time.
pub trait SRPServerState {
    fn public_value(&self) -> Vec<u8>;

    fn premaster_secret(&self, client_public: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

impl<G: SRPGroup, H: CryptographicDigest + Default> SRPServerState for SRPServer<G, H> {
    fn public_value(&self) -> Vec<u8> {
        SRPServer::public_value(self)
    }

    fn premaster_secret(&self, client_public: &[u8]) -> Result<Vec<u8>, CryptoError> {
        SRPServer::premaster_secret(self, client_public)
    }
}

impl Value for Box<dyn SRPClientState> {
    const TYPE: Type = Type::Named("umilib_crypto_srp_SRPClient");
}

impl Value for Box<dyn SRPServerState> {
    const TYPE: Type = Type::Named("umilib_crypto_srp_SRPServer");
}

/// An operation on a group and hash function chosen at run time, called by [`SRPSuite::call`].
pub trait SRPCall {
    type Output;

    fn call<G: SRPGroup, H: CryptographicDigest + Default + 'static>(self) -> Result<Self::Output, CryptoError>;
}

/// The secret exponent of a party: random or given.
pub enum SRPSecret<'a> {
    Random(RandomSource<'a>),
    Given(&'a [u8]),
}

/// [`SRP::verifier`] of the user.
pub struct SRPVerifier<'a> {
    pub salt: &'a [u8],
    pub identity: &'a [u8],
    pub password: &'a [u8],
}

impl SRPCall for SRPVerifier<'_> {
    type Output = Vec<u8>;

    fn call<G: SRPGroup, H: CryptographicDigest + Default + 'static>(self) -> Result<Vec<u8>, CryptoError> {
        SRP::<G, H>::verifier(self.salt, self.identity, self.password)
    }
}

/// A client of the secret.
pub struct SRPClientNew<'a> {
    pub secret: SRPSecret<'a>,
}

impl SRPCall for SRPClientNew<'_> {
    type Output = Box<dyn SRPClientState>;

    fn call<G: SRPGroup, H: CryptographicDigest + Default + 'static>(self) -> Result<Self::Output, CryptoError> {
        let client = match self.secret {
            SRPSecret::Random(mut random) => SRPClient::<G, H>::generate(&mut random)?,
            SRPSecret::Given(secret) => SRPClient::<G, H>::new(secret)?,
        };
        Ok(Box::new(client))
    }
}

/// A server of the verifier and the secret.
pub struct SRPServerNew<'a> {
    pub verifier: &'a [u8],
    pub secret: SRPSecret<'a>,
}

impl SRPCall for SRPServerNew<'_> {
    type Output = Box<dyn SRPServerState>;

    fn call<G: SRPGroup, H: CryptographicDigest + Default + 'static>(self) -> Result<Self::Output, CryptoError> {
        let server = match self.secret {
            SRPSecret::Random(mut random) => SRPServer::<G, H>::generate(self.verifier, &mut random)?,
            SRPSecret::Given(secret) => SRPServer::<G, H>::new(self.verifier, secret)?,
        };
        Ok(Box::new(server))
    }
}

/// A group and a hash function by the C type names of their types.
pub struct SRPSuite<'a> {
    pub group: &'a str,
    pub hash: &'a str,
}

impl SRPSuite<'_> {
    /// Calls `call` with the group and the hash function; fails with InvalidArgument if either is unknown.
    pub fn call<V: SRPCall>(&self, call: V) -> Result<V::Output, &'static Status> {
        use crate::crypto::srp::{SRP1024, SRP1536, SRP2048, SRP3072, SRP4096, SRP6144, SRP8192};
        match self.group {
            "umilib_crypto_srp_SRP1024" => self.with_group::<SRP1024, V>(call),
            "umilib_crypto_srp_SRP1536" => self.with_group::<SRP1536, V>(call),
            "umilib_crypto_srp_SRP2048" => self.with_group::<SRP2048, V>(call),
            "umilib_crypto_srp_SRP3072" => self.with_group::<SRP3072, V>(call),
            "umilib_crypto_srp_SRP4096" => self.with_group::<SRP4096, V>(call),
            "umilib_crypto_srp_SRP6144" => self.with_group::<SRP6144, V>(call),
            "umilib_crypto_srp_SRP8192" => self.with_group::<SRP8192, V>(call),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

/// Defines [`SRPSuite::with_group`] over the hash functions of the registry.
macro_rules! srp_hashes {
    ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
        impl SRPSuite<'_> {
            /// [`SRPSuite::call`] with the group `G` chosen.
            pub fn with_group<G: SRPGroup, V: SRPCall>(&self, call: V) -> Result<V::Output, &'static Status> {
                match self.hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => call.call::<G, $type>().map_err(|error| error.to_status()),
                    )*
                    _ => Err(&Status::INVALID_ARGUMENT),
                }
            }
        }
    };
}

crate::ffi_standard_digests!(srp_hashes);

crate::ffi_functions! {
    /// Writes the verifier v = g^x % N of the user `identity` with `password` and `salt` (RFC 5054 section
    /// 2.4), without leading zeros, into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_srp_srp_verifier(group: *const u8, group_length: usize, hash: *const u8, hash_length: usize, salt: *const u8, salt_length: usize, identity: *const u8, identity_length: usize, password: *const u8, password_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable buffer.
            let suite = SRPSuite { group: unsafe { Pointer::text(group, group_length) }?, hash: unsafe { Pointer::text(hash, hash_length) }? };
            let call = SRPVerifier {
                salt: unsafe { Pointer::slice(salt, salt_length) }?,
                identity: unsafe { Pointer::slice(identity, identity_length) }?,
                password: unsafe { Pointer::slice(password, password_length) }?,
            };
            let verifier = suite.call(call)?;
            unsafe { Pointer::write(out, Buffer::from_vec(verifier)) }
        })())
    }

    /// Creates the client of the secret exponent a; fails with InvalidKey for a = 0 or more bytes than N.
    pub unsafe extern "C" fn umilib_crypto_srp_srp_client_new(group: *const u8, group_length: usize, hash: *const u8, hash_length: usize, secret: *const u8, secret_length: usize, out: *mut *mut Box<dyn SRPClientState>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let suite = SRPSuite { group: unsafe { Pointer::text(group, group_length) }?, hash: unsafe { Pointer::text(hash, hash_length) }? };
            let secret = SRPSecret::Given(unsafe { Pointer::slice(secret, secret_length) }?);
            let client = suite.call(SRPClientNew { secret })?;
            unsafe { Pointer::write_handle(out, client) }
        })())
    }

    /// Creates a client with a random exponent from the generator handle `random` of the type named by
    /// `random_type`.
    pub unsafe extern "C" fn umilib_crypto_srp_srp_client_generate(group: *const u8, group_length: usize, hash: *const u8, hash_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut Box<dyn SRPClientState>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text, a live generator of the named type and a writable pointer.
            let suite = SRPSuite { group: unsafe { Pointer::text(group, group_length) }?, hash: unsafe { Pointer::text(hash, hash_length) }? };
            let secret = SRPSecret::Random(unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?);
            let client = suite.call(SRPClientNew { secret })?;
            unsafe { Pointer::write_handle(out, client) }
        })())
    }

    /// Releases the client, zeroizing its secret. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_crypto_srp_srp_client_free(client: *mut Box<dyn SRPClientState>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(client) }
    }

    /// Writes A, as the client sends it (without leading zeros), into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_srp_srp_client_public_value(client: *const Box<dyn SRPClientState>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(client.public_value())) }
        })())
    }

    /// Writes the premaster secret of section 2.6 for the user `identity` with `password` and the salt and B
    /// of the server into a new buffer; fails with InvalidKey for B % N = 0 or u = 0.
    pub unsafe extern "C" fn umilib_crypto_srp_srp_client_premaster_secret(client: *const Box<dyn SRPClientState>, identity: *const u8, identity_length: usize, password: *const u8, password_length: usize, salt: *const u8, salt_length: usize, server_public: *const u8, server_public_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable buffer.
            let client = unsafe { Pointer::reference(client) }?;
            let identity = unsafe { Pointer::slice(identity, identity_length) }?;
            let password = unsafe { Pointer::slice(password, password_length) }?;
            let salt = unsafe { Pointer::slice(salt, salt_length) }?;
            let server_public = unsafe { Pointer::slice(server_public, server_public_length) }?;
            let secret = client.premaster_secret(identity, password, salt, server_public).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(secret)) }
        })())
    }

    /// Creates the server of the verifier and the secret exponent b; fails with InvalidKey for b = 0, v % N
    /// = 0 or values longer than N.
    pub unsafe extern "C" fn umilib_crypto_srp_srp_server_new(group: *const u8, group_length: usize, hash: *const u8, hash_length: usize, verifier: *const u8, verifier_length: usize, secret: *const u8, secret_length: usize, out: *mut *mut Box<dyn SRPServerState>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let suite = SRPSuite { group: unsafe { Pointer::text(group, group_length) }?, hash: unsafe { Pointer::text(hash, hash_length) }? };
            let verifier = unsafe { Pointer::slice(verifier, verifier_length) }?;
            let secret = SRPSecret::Given(unsafe { Pointer::slice(secret, secret_length) }?);
            let server = suite.call(SRPServerNew { verifier, secret })?;
            unsafe { Pointer::write_handle(out, server) }
        })())
    }

    /// Creates a server of the verifier with a random exponent from the generator handle `random` of the type
    /// named by `random_type`.
    pub unsafe extern "C" fn umilib_crypto_srp_srp_server_generate(group: *const u8, group_length: usize, hash: *const u8, hash_length: usize, verifier: *const u8, verifier_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut Box<dyn SRPServerState>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes, a live generator of the named type and a
            // writable pointer.
            let suite = SRPSuite { group: unsafe { Pointer::text(group, group_length) }?, hash: unsafe { Pointer::text(hash, hash_length) }? };
            let verifier = unsafe { Pointer::slice(verifier, verifier_length) }?;
            let secret = SRPSecret::Random(unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?);
            let server = suite.call(SRPServerNew { verifier, secret })?;
            unsafe { Pointer::write_handle(out, server) }
        })())
    }

    /// Releases the server, zeroizing its secret. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_crypto_srp_srp_server_free(server: *mut Box<dyn SRPServerState>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(server) }
    }

    /// Writes B, as the server sends it (without leading zeros), into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_srp_srp_server_public_value(server: *const Box<dyn SRPServerState>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(server.public_value())) }
        })())
    }

    /// Writes the premaster secret of section 2.6 for the client's A into a new buffer; fails with InvalidKey
    /// for A % N = 0 or u = 0.
    pub unsafe extern "C" fn umilib_crypto_srp_srp_server_premaster_secret(server: *const Box<dyn SRPServerState>, client_public: *const u8, client_public_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable buffer.
            let server = unsafe { Pointer::reference(server) }?;
            let client_public = unsafe { Pointer::slice(client_public, client_public_length) }?;
            let secret = server.premaster_secret(client_public).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(secret)) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "srp",
    definitions: &[
        Definition::Opaque {
            name: "umilib_crypto_srp_SRPClient",
            documentation: " The client of SRP (RFC 5054), of any group and hash function, with its secret exponent.",
        },
        Definition::Opaque {
            name: "umilib_crypto_srp_SRPServer",
            documentation: " The server of SRP (RFC 5054), of any group and hash function, with its verifier and secret exponent.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
