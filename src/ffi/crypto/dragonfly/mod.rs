//! The C ABI of [`crate::crypto::dragonfly`].
//!
//! A [`DragonflyPeer<C, H>`](crate::crypto::dragonfly::DragonflyPeer) is the
//! handle `umilib_crypto_dragonfly_DragonflyPeer`, created on the curve and
//! with the hash function named by the C type names of
//! [`ffi_weierstrass_curves!`](crate::ffi_weierstrass_curves) and
//! [`ffi_standard_digests!`](crate::ffi_standard_digests). Commits are
//! scalar || element (uncompressed), as [`DragonflyCommit`] encodes them.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::CryptoError;
use crate::crypto::dragonfly::{DragonflyCommit, DragonflyConfig, DragonflyPeer};
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::hash::CryptographicDigest;
use crate::math::ec::WeierstrassCurve;

/// A peer of any curve and hash function: [`DragonflyPeer`] chosen at run time.
pub trait DragonflyState {
    /// The encoding of the peer's own commit.
    fn commit(&self) -> Vec<u8>;

    /// [`DragonflyPeer::process`] of the encoded commit of the other peer: the own confirm.
    fn process(&mut self, commit: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// [`DragonflyPeer::finish`]: the master key.
    fn finish(&self, confirm: &[u8]) -> Result<&[u8], CryptoError>;
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> DragonflyState for DragonflyPeer<C, H> {
    fn commit(&self) -> Vec<u8> {
        DragonflyPeer::commit(self).to_bytes()
    }

    fn process(&mut self, commit: &[u8]) -> Result<Vec<u8>, CryptoError> {
        DragonflyPeer::process(self, DragonflyCommit::from_bytes(commit)?)
    }

    fn finish(&self, confirm: &[u8]) -> Result<&[u8], CryptoError> {
        DragonflyPeer::finish(self, confirm)
    }
}

impl Value for DragonflyConfig {
    const TYPE: Type = Type::Named("umilib_crypto_dragonfly_DragonflyConfig");
}

impl Value for Box<dyn DragonflyState> {
    const TYPE: Type = Type::Named("umilib_crypto_dragonfly_DragonflyPeer");
}

/// The arguments of [`DragonflyPeer::new`].
pub struct DragonflyPeerNew<'a> {
    pub config: &'a DragonflyConfig,
    pub identity: &'a [u8],
    pub peer_identity: &'a [u8],
    pub password: &'a [u8],
    pub random: RandomSource<'a>,
}

impl DragonflyPeerNew<'_> {
    /// The peer on `C` with `H`.
    pub fn call<C: WeierstrassCurve, H: CryptographicDigest + Default + 'static>(
        mut self,
    ) -> Result<Box<dyn DragonflyState>, CryptoError> {
        let peer = DragonflyPeer::<C, H>::new(
            self.config,
            self.identity,
            self.peer_identity,
            self.password,
            &mut self.random,
        )?;
        Ok(Box::new(peer))
    }
}

/// Defines [`DragonflyPeerNew::dispatch`] over the curves of the registry.
macro_rules! dragonfly_curves {
    ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
        // The registry may enable no curve, leaving the arguments unused.
        #[allow(unused_variables)]
        impl DragonflyPeerNew<'_> {
            /// The peer on the curve named `curve` with the hash function named `hash`; fails with
            /// InvalidArgument if either is unknown.
            pub fn dispatch(self, curve: &str, hash: &str) -> Result<Box<dyn DragonflyState>, &'static Status> {
                match curve {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => self.with_curve::<$type>(hash),
                    )*
                    _ => Err(&Status::INVALID_ARGUMENT),
                }
            }
        }
    };
}

/// Defines [`DragonflyPeerNew::with_curve`] over the hash functions of the registry.
macro_rules! dragonfly_hashes {
    ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
        // The registry may enable no hash function, leaving the arguments unused.
        #[allow(unused_variables, dead_code)]
        impl DragonflyPeerNew<'_> {
            /// The peer on `C` with the hash function named `hash`; fails with InvalidArgument if it is unknown.
            pub fn with_curve<C: WeierstrassCurve>(self, hash: &str) -> Result<Box<dyn DragonflyState>, &'static Status> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => self.call::<C, $type>().map_err(|error| ToStatus::to_status(&error)),
                    )*
                    _ => Err(&Status::INVALID_ARGUMENT),
                }
            }
        }
    };
}

crate::ffi_weierstrass_curves!(dragonfly_curves);
crate::ffi_standard_digests!(dragonfly_hashes);

crate::ffi_functions! {
    /// The default parameters: 40 rounds of hunting and pecking.
    pub unsafe extern "C" fn umilib_crypto_dragonfly_dragonfly_config_default() -> DragonflyConfig {
        DragonflyConfig::default()
    }

    /// Creates the peer `identity` of an exchange with `peer_identity` over the shared `password` (section
    /// 3.3), on the curve named by `curve` with the hash function named by `hash`, its secrets drawn from the
    /// generator handle `random` of the type named by `random_type`. Fails with InvalidParameter when no
    /// password element is found within the rounds of `config`.
    pub unsafe extern "C" fn umilib_crypto_dragonfly_dragonfly_peer_new(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, config: *const DragonflyConfig, identity: *const u8, identity_length: usize, peer_identity: *const u8, peer_identity_length: usize, password: *const u8, password_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut Box<dyn DragonflyState>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text, a readable configuration, readable bytes, a live
            // generator of the named type and a writable pointer.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let call = DragonflyPeerNew {
                config: unsafe { Pointer::reference(config) }?,
                identity: unsafe { Pointer::slice(identity, identity_length) }?,
                peer_identity: unsafe { Pointer::slice(peer_identity, peer_identity_length) }?,
                password: unsafe { Pointer::slice(password, password_length) }?,
                random: unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?,
            };
            let peer = call.dispatch(curve, hash)?;
            unsafe { Pointer::write_handle(out, peer) }
        })())
    }

    /// Releases the peer, zeroizing its secrets. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_crypto_dragonfly_dragonfly_peer_free(peer: *mut Box<dyn DragonflyState>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(peer) }
    }

    /// Writes the peer's commit, to send to the other peer, into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_dragonfly_dragonfly_peer_commit(peer: *const Box<dyn DragonflyState>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let peer = unsafe { Pointer::reference(peer) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(peer.commit())) }
        })())
    }

    /// Processes the commit of the other peer (section 3.4) and writes the peer's confirm, to send to the
    /// other peer, into a new buffer. Fails with InvalidKey for a commit that is invalid or a reflection of
    /// the peer's own.
    pub unsafe extern "C" fn umilib_crypto_dragonfly_dragonfly_peer_process(peer: *mut Box<dyn DragonflyState>, commit: *const u8, commit_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable buffer.
            let peer = unsafe { Pointer::reference_mut(peer) }?;
            let commit = unsafe { Pointer::slice(commit, commit_length) }?;
            let confirm = peer.process(commit).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(confirm)) }
        })())
    }

    /// Checks the confirm of the other peer and writes the master key into a new buffer. Fails with
    /// AuthenticationFailed for a wrong confirm and InvalidParameter before
    /// [`umilib_crypto_dragonfly_dragonfly_peer_process`].
    pub unsafe extern "C" fn umilib_crypto_dragonfly_dragonfly_peer_finish(peer: *const Box<dyn DragonflyState>, confirm: *const u8, confirm_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable buffer.
            let peer = unsafe { Pointer::reference(peer) }?;
            let confirm = unsafe { Pointer::slice(confirm, confirm_length) }?;
            let key = peer.finish(confirm).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(key.to_vec())) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "dragonfly",
    definitions: &[
        Definition::Structure {
            name: "umilib_crypto_dragonfly_DragonflyConfig",
            documentation: " The parameters of a Dragonfly exchange.",
            fields: &[Parameter { name: "iterations", value: <u32 as Value>::TYPE }],
        },
        Definition::Opaque {
            name: "umilib_crypto_dragonfly_DragonflyPeer",
            documentation: " A peer of a Dragonfly exchange (RFC 7664), of any curve and hash function.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
