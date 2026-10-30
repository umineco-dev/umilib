//! The C ABI of [`crate::crypto::sm2`].
//!
//! The schemes are exported with the parameters GB/T 32918 recommends, the
//! curve of SM2 and SM3, which C names `umilib_crypto_curve_sm2_SM2` and
//! `umilib_hash_sm3_SM3`: [`SM2DSA`](crate::crypto::sm2::SM2DSA)
//! (`umilib_crypto_sm2_sm2dsa_*`, with the functions of
//! [`SignatureScheme`](crate::crypto::SignatureScheme) for the default
//! identity and `_sign_with_identity`/`_verify_with_identity`),
//! [`SM2PKE`](crate::crypto::sm2::SM2PKE) (`umilib_crypto_sm2_sm2pke_*`,
//! the order of the ciphertext 0 for C1C3C2 and 1 for C1C2C3) and
//! [`SM2KEP`] as an opaque handle
//! (`umilib_crypto_sm2_sm2kep_*`, the role 0 for the initiator and 1 for the
//! responder). Keys are those of `SM2DSA`: the private key big-endian, the
//! public key the uncompressed point.

use crate::crypto::curve::sm2::SM2;
use crate::crypto::sm2::{SM2CiphertextOrder, SM2KEP, SM2PrivateKey, SM2PublicKey, SM2Role};
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus, Type, Value};
use crate::hash::sm3::SM3;

/// The names of the only parameters exported.
pub struct SM2Names;

impl SM2Names {
    pub const CURVE: &'static str = "umilib_crypto_curve_sm2_SM2";
    pub const HASH: &'static str = "umilib_hash_sm3_SM3";

    /// Fails with InvalidArgument unless the names are those of the curve of SM2 and of SM3.
    pub fn check(curve: &str, hash: &str) -> Result<(), &'static Status> {
        if curve != SM2Names::CURVE || hash != SM2Names::HASH {
            return Err(&Status::INVALID_ARGUMENT);
        }
        Ok(())
    }

    /// The order of a ciphertext: 0 for C1C3C2, 1 for C1C2C3.
    pub fn order(value: u8) -> Result<SM2CiphertextOrder, &'static Status> {
        match value {
            0 => Ok(SM2CiphertextOrder::C1C3C2),
            1 => Ok(SM2CiphertextOrder::C1C2C3),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

/// [`SM2DSA`](crate::crypto::sm2::SM2DSA).
pub mod sm2dsa {
    use super::SM2Names;
    use crate::crypto::curve::sm2::SM2;
    use crate::crypto::sm2::{SM2DSA, SM2PrivateKey, SM2PublicKey, SM2Signature};
    use crate::ffi::crypto::SignatureSchemeCall;
    use crate::ffi::{Pointer, Status, ToStatus};
    use crate::hash::sm3::SM3;

    /// Calls `call` with `SM2DSA<SM2, SM3>` for those names; `None` for others.
    pub fn scheme<V: SignatureSchemeCall>(names: (&str, &str), call: V) -> Option<V::Output> {
        SM2Names::check(names.0, names.1).ok()?;
        Some(call.call::<SM2DSA<SM2, SM3>>())
    }

    crate::ffi_signature_scheme!(
        "umilib_crypto_sm2_sm2dsa",
        "SM2DSA on the curve named by `curve` with the hash function named by `hash`",
        [curve curve_length, hash hash_length]
    );

    crate::ffi_exports! {
        const IDENTITIES;
        /// Writes the signature (r || s) of the message by the signer of the private key and the identity into
        /// `out` of 64 bytes.
        pub unsafe extern "C" fn sign_with_identity = "umilib_crypto_sm2_sm2dsa_sign_with_identity"; (curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, key: *const u8, key_length: usize, identity: *const u8, identity_length: usize, message: *const u8, message_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes and writable bytes.
                let inputs = [(curve, curve_length), (hash, hash_length), (key, key_length), (identity, identity_length), (message, message_length)];
                Pointer::check_ranges(&inputs, &[(out, out_length)])?;
                SM2Names::check(unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?)?;
                let key = SM2PrivateKey::<SM2>::from_bytes(unsafe { Pointer::slice(key, key_length) }?).map_err(|error| error.to_status())?;
                let identity = unsafe { Pointer::slice(identity, identity_length) }?;
                let message = unsafe { Pointer::slice(message, message_length) }?;
                let out = unsafe { Pointer::slice_mut(out, out_length) }?;
                let signature = SM2DSA::<SM2, SM3>::sign(&key, identity, message).map_err(|error| error.to_status())?;
                signature.write_bytes(out).map_err(|error| error.to_status())
            })())
        }

        /// Succeeds if the signature (r || s) is one of the message by the signer of the public key and the
        /// identity; fails with InvalidSignature otherwise.
        pub unsafe extern "C" fn verify_with_identity = "umilib_crypto_sm2_sm2dsa_verify_with_identity"; (curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, key: *const u8, key_length: usize, identity: *const u8, identity_length: usize, message: *const u8, message_length: usize, signature: *const u8, signature_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes.
                SM2Names::check(unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?)?;
                let key = SM2PublicKey::<SM2>::from_encoded(unsafe { Pointer::slice(key, key_length) }?).map_err(|error| error.to_status())?;
                let identity = unsafe { Pointer::slice(identity, identity_length) }?;
                let message = unsafe { Pointer::slice(message, message_length) }?;
                let signature = SM2Signature::<SM2>::from_bytes(unsafe { Pointer::slice(signature, signature_length) }?)
                    .map_err(|error| error.to_status())?;
                SM2DSA::<SM2, SM3>::verify(&key, identity, message, &signature).map_err(|error| error.to_status())
            })())
        }
    }

    /// The DER encoding of signatures (`SM2Signature` of GM/T 0009-2012 section 7.3, a SEQUENCE of r and s).
    #[cfg(umilib_feature = "codec-asn1-der")]
    pub mod der {
        use super::SM2Names;
        use crate::crypto::curve::sm2::SM2;
        use crate::crypto::sm2::SM2Signature;
        use crate::ffi::{Buffer, Pointer, Status, ToStatus};

        crate::ffi_functions! {
            /// Writes the signature r || s of the DER encoding into a new buffer; fails with InvalidSignature for
            /// another encoding or values out of range.
            pub unsafe extern "C" fn umilib_crypto_sm2_sm2dsa_signature_from_der(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, der: *const u8, der_length: usize, out: *mut Buffer) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes and a writable buffer.
                    SM2Names::check(unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?)?;
                    let signature = SM2Signature::<SM2>::from_der(unsafe { Pointer::slice(der, der_length) }?)
                        .map_err(|error| error.to_status())?;
                    let mut bytes = alloc::vec![0u8; 64];
                    signature.write_bytes(&mut bytes).map_err(|error| error.to_status())?;
                    unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
                })())
            }

            /// Writes the DER encoding of the signature r || s into a new buffer.
            pub unsafe extern "C" fn umilib_crypto_sm2_sm2dsa_signature_to_der(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, signature: *const u8, signature_length: usize, out: *mut Buffer) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes and a writable buffer.
                    SM2Names::check(unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?)?;
                    let signature = SM2Signature::<SM2>::from_bytes(unsafe { Pointer::slice(signature, signature_length) }?)
                        .map_err(|error| error.to_status())?;
                    unsafe { Pointer::write(out, Buffer::from_vec(signature.to_der())) }
                })())
            }
        }
    }

    #[cfg(umilib_feature = "codec-asn1-der")]
    pub const ENCODINGS: &[crate::ffi::Function] = der::FUNCTIONS;
    #[cfg(not(umilib_feature = "codec-asn1-der"))]
    pub const ENCODINGS: &[crate::ffi::Function] = &[];
}

impl Value for SM2KEP<SM2, SM3> {
    const TYPE: Type = Type::Named("umilib_crypto_sm2_SM2KEP");
}

crate::ffi_exports! {
    const FUNCTIONS;
    /// The bytes a ciphertext of SM2PKE adds to its message: C1 (65) and C3 (32).
    pub unsafe extern "C" fn sm2pke_overhead = "umilib_crypto_sm2_sm2pke_overhead"; () -> usize {
        crate::crypto::sm2::SM2PKE::<SM2, SM3>::OVERHEAD
    }

    /// Writes the encryption of the message for the public key, in the order `order`, with the k of the
    /// generator handle `random` of the type named by `random_type`, into `out` of the length of the
    /// message plus the overhead.
    pub unsafe extern "C" fn sm2pke_encrypt = "umilib_crypto_sm2_sm2pke_encrypt"; (curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, key: *const u8, key_length: usize, message: *const u8, message_length: usize, order: u8, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes, a live generator of the named type and writable bytes.
            let inputs = [(curve, curve_length), (hash, hash_length), (key, key_length), (message, message_length), (random_type, random_type_length)];
            Pointer::check_ranges(&inputs, &[(out, out_length)])?;
            SM2Names::check(unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?)?;
            let key = SM2PublicKey::<SM2>::from_encoded(unsafe { Pointer::slice(key, key_length) }?).map_err(|error| error.to_status())?;
            let message = unsafe { Pointer::slice(message, message_length) }?;
            let mut random = unsafe { crate::ffi::crypto::random::RandomSource::from_handle(random, random_type, random_type_length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            if out.len() != message.len() + crate::crypto::sm2::SM2PKE::<SM2, SM3>::OVERHEAD {
                return Err(&Status::INVALID_ARGUMENT);
            }
            let ciphertext = crate::crypto::sm2::SM2PKE::<SM2, SM3>::encrypt(&key, message, SM2Names::order(order)?, &mut random)
                .map_err(|error| error.to_status())?;
            out.copy_from_slice(&ciphertext);
            Ok(())
        })())
    }

    /// Writes the message of the ciphertext in the order `order` for the private key into `out` of the
    /// length of the ciphertext minus the overhead; fails with DecryptionFailed for any invalid ciphertext.
    pub unsafe extern "C" fn sm2pke_decrypt = "umilib_crypto_sm2_sm2pke_decrypt"; (curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, key: *const u8, key_length: usize, ciphertext: *const u8, ciphertext_length: usize, order: u8, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and writable bytes.
            let inputs = [(curve, curve_length), (hash, hash_length), (key, key_length), (ciphertext, ciphertext_length)];
            Pointer::check_ranges(&inputs, &[(out, out_length)])?;
            SM2Names::check(unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?)?;
            let key = SM2PrivateKey::<SM2>::from_bytes(unsafe { Pointer::slice(key, key_length) }?).map_err(|error| error.to_status())?;
            let ciphertext = unsafe { Pointer::slice(ciphertext, ciphertext_length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            let mut message = crate::crypto::sm2::SM2PKE::<SM2, SM3>::decrypt(&key, ciphertext, SM2Names::order(order)?)
                .map_err(|error| error.to_status())?;
            let result = if out.len() == message.len() {
                out.copy_from_slice(&message);
                Ok(())
            } else {
                Err(&Status::INVALID_ARGUMENT)
            };
            crate::secret::Zeroize::zeroize(&mut message);
            result
        })())
    }

    /// Creates one side of the key exchange, of the role (0 initiator, 1 responder), the private key, the
    /// identity and the ephemeral private key.
    pub unsafe extern "C" fn sm2kep_new = "umilib_crypto_sm2_sm2kep_new"; (role: u8, key: *const u8, key_length: usize, identity: *const u8, identity_length: usize, ephemeral: *const u8, ephemeral_length: usize, out: *mut *mut SM2KEP<SM2, SM3>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let role = match role { 0 => SM2Role::Initiator, 1 => SM2Role::Responder, _ => return Err(&Status::INVALID_ARGUMENT) };
            let key = SM2PrivateKey::<SM2>::from_bytes(unsafe { Pointer::slice(key, key_length) }?).map_err(|error| error.to_status())?;
            let ephemeral = SM2PrivateKey::<SM2>::from_bytes(unsafe { Pointer::slice(ephemeral, ephemeral_length) }?).map_err(|error| error.to_status())?;
            let identity = unsafe { Pointer::slice(identity, identity_length) }?;
            let side = SM2KEP::<SM2, SM3>::new(role, key, identity, ephemeral).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, side) }
        })())
    }

    /// Creates one side of the key exchange with an ephemeral key of the generator handle `random`.
    pub unsafe extern "C" fn sm2kep_generate = "umilib_crypto_sm2_sm2kep_generate"; (role: u8, key: *const u8, key_length: usize, identity: *const u8, identity_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut SM2KEP<SM2, SM3>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes, a live generator of the named type and a writable pointer.
            let role = match role { 0 => SM2Role::Initiator, 1 => SM2Role::Responder, _ => return Err(&Status::INVALID_ARGUMENT) };
            let key = SM2PrivateKey::<SM2>::from_bytes(unsafe { Pointer::slice(key, key_length) }?).map_err(|error| error.to_status())?;
            let identity = unsafe { Pointer::slice(identity, identity_length) }?;
            let mut random = unsafe { crate::ffi::crypto::random::RandomSource::from_handle(random, random_type, random_type_length) }?;
            let side = SM2KEP::<SM2, SM3>::generate(role, key, identity, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, side) }
        })())
    }

    /// Releases the side of the key exchange, zeroizing its keys. Does nothing if it is null.
    pub unsafe extern "C" fn sm2kep_free = "umilib_crypto_sm2_sm2kep_free"; (side: *mut SM2KEP<SM2, SM3>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(side) }
    }

    /// Writes the ephemeral public key R to send into `out` of 65 bytes (the uncompressed point).
    pub unsafe extern "C" fn sm2kep_ephemeral_public_key = "umilib_crypto_sm2_sm2kep_ephemeral_public_key"; (side: *const SM2KEP<SM2, SM3>, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable bytes.
            let side = unsafe { Pointer::reference(side) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            let encoded = side.ephemeral_public_key().to_encoded();
            if out.len() != encoded.len() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            out.copy_from_slice(&encoded);
            Ok(())
        })())
    }

    /// Writes the shared key with the peer of the public key, the identity and the ephemeral public key
    /// into `key_out`, and the confirmations S_B (0x02) into `responder` and S_A (0x03) into
    /// `initiator` (32 bytes each); fails with InvalidKey if the shared point is the identity.
    pub unsafe extern "C" fn sm2kep_agree = "umilib_crypto_sm2_sm2kep_agree"; (side: *const SM2KEP<SM2, SM3>, peer: *const u8, peer_length: usize, peer_identity: *const u8, peer_identity_length: usize, peer_ephemeral: *const u8, peer_ephemeral_length: usize, key_out: *mut u8, key_out_length: usize, responder: *mut u8, responder_length: usize, initiator: *mut u8, initiator_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and writable bytes.
            let inputs = [(peer, peer_length), (peer_identity, peer_identity_length), (peer_ephemeral, peer_ephemeral_length)];
            let outputs = [(key_out.cast_const(), key_out_length), (responder.cast_const(), responder_length), (initiator.cast_const(), initiator_length)];
            Pointer::check_ranges(&inputs, &outputs)?;
            let side = unsafe { Pointer::reference(side) }?;
            let peer = SM2PublicKey::<SM2>::from_encoded(unsafe { Pointer::slice(peer, peer_length) }?).map_err(|error| error.to_status())?;
            let peer_ephemeral = SM2PublicKey::<SM2>::from_encoded(unsafe { Pointer::slice(peer_ephemeral, peer_ephemeral_length) }?)
                .map_err(|error| error.to_status())?;
            let peer_identity = unsafe { Pointer::slice(peer_identity, peer_identity_length) }?;
            let key_out = unsafe { Pointer::slice_mut(key_out, key_out_length) }?;
            let responder = unsafe { Pointer::slice_mut(responder, responder_length) }?;
            let initiator = unsafe { Pointer::slice_mut(initiator, initiator_length) }?;
            if responder.len() != 32 || initiator.len() != 32 {
                return Err(&Status::INVALID_ARGUMENT);
            }
            let confirmation = side.agree(&peer, peer_identity, &peer_ephemeral, key_out).map_err(|error| error.to_status())?;
            responder.copy_from_slice(confirmation.responder());
            initiator.copy_from_slice(confirmation.initiator());
            Ok(())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "sm2",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_sm2_SM2KEP",
        documentation: " One side of the key exchange of SM2 (GB/T 32918.3) on the curve of SM2 with SM3.",
    }],
    functions: &Function::concat::<
        { sm2dsa::FUNCTIONS.len() + sm2dsa::IDENTITIES.len() + sm2dsa::ENCODINGS.len() + FUNCTIONS.len() },
    >(&[sm2dsa::FUNCTIONS, sm2dsa::IDENTITIES, sm2dsa::ENCODINGS, FUNCTIONS]),
    modules: &[],
};
