//! The C ABI of [`crate::crypto::hpke`].
//!
//! A suite is chosen by the identifiers of RFC 9180 section 7: kem_id
//! (`kem`), kdf_id (`kdf`) and aead_id (`aead`), those of the
//! [`HPKEKEM::ID`], [`HPKEKDF::ID`] and [`HPKEAEAD::ID`] of the types:
//!
//! - KEMs: 0x0010 DHKEM(P-256, HKDF-SHA256), 0x0011 DHKEM(P-384,
//!   HKDF-SHA384), 0x0012 DHKEM(P-521, HKDF-SHA512), 0x0020 DHKEM(X25519,
//!   HKDF-SHA256), 0x0021 DHKEM(X448, HKDF-SHA512);
//! - KDFs: 0x0001 HKDF-SHA256, 0x0002 HKDF-SHA384, 0x0003 HKDF-SHA512;
//! - AEADs: 0x0001 AES-128-GCM, 0x0002 AES-256-GCM, 0x0003
//!   ChaCha20Poly1305, 0xFFFF export-only;
//!
//! each available with the features of its parts; other identifiers fail
//! with InvalidArgument. Keys are the encodings of SerializePrivateKey and
//! SerializePublicKey (section 7.1). The pre-shared key is absent when both
//! it and its identifier are empty, and the sender's key (auth modes) when
//! it is empty. Contexts are the handles
//! `umilib_crypto_hpke_HPKESenderContext` and
//! `umilib_crypto_hpke_HPKEReceiverContext`.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::CryptoError;
use crate::crypto::hpke::{HPKE, HPKEAEAD, HPKEKDF, HPKEKEM, HPKEReceiverContext, HPKESenderContext};
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};
use crate::secret::Zeroize;

/// A sender's context of any suite: [`HPKESenderContext`] chosen at run time.
pub trait HPKESenderState {
    /// The sequence number of the next message.
    fn sequence(&self) -> u64;

    fn seal(&mut self, associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    fn export(&self, context: &[u8], out: &mut [u8]) -> Result<(), CryptoError>;
}

impl<F: HPKEKDF, A: HPKEAEAD> HPKESenderState for HPKESenderContext<F, A> {
    fn sequence(&self) -> u64 {
        self.context().sequence()
    }

    fn seal(&mut self, associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        HPKESenderContext::seal(self, associated, plaintext)
    }

    fn export(&self, context: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        HPKESenderContext::export(self, context, out)
    }
}

/// A receiver's context of any suite: [`HPKEReceiverContext`] chosen at run time.
pub trait HPKEReceiverState {
    /// The sequence number of the next message.
    fn sequence(&self) -> u64;

    fn open(&mut self, associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    fn export(&self, context: &[u8], out: &mut [u8]) -> Result<(), CryptoError>;
}

impl<F: HPKEKDF, A: HPKEAEAD> HPKEReceiverState for HPKEReceiverContext<F, A> {
    fn sequence(&self) -> u64 {
        self.context().sequence()
    }

    fn open(&mut self, associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        HPKEReceiverContext::open(self, associated, ciphertext)
    }

    fn export(&self, context: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        HPKEReceiverContext::export(self, context, out)
    }
}

impl Value for Box<dyn HPKESenderState> {
    const TYPE: Type = Type::Named("umilib_crypto_hpke_HPKESenderContext");
}

impl Value for Box<dyn HPKEReceiverState> {
    const TYPE: Type = Type::Named("umilib_crypto_hpke_HPKEReceiverContext");
}

/// An operation on a KEM chosen at run time, called by [`HPKESuite::call_kem`].
pub trait HPKEKEMCall {
    type Output;

    fn call<K: HPKEKEM>(self) -> Self::Output;
}

/// An operation on a suite chosen at run time, called by [`HPKESuite::call`].
pub trait HPKECall {
    type Output;

    fn call<K: HPKEKEM, F: HPKEKDF + 'static, A: HPKEAEAD + 'static>(self) -> Self::Output;
}

/// A suite by its identifiers of RFC 9180 section 7.
#[derive(Clone, Copy, Debug)]
pub struct HPKESuite {
    pub kem: u16,
    pub kdf: u16,
    pub aead: u16,
}

// A suite of identifiers whose features are disabled leaves the arguments unused.
#[allow(unused_variables)]
impl HPKESuite {
    /// Calls `call` with the KEM of the identifier `kem`; fails with InvalidArgument if it is unknown.
    pub fn call_kem<V: HPKEKEMCall>(kem: u16, call: V) -> Result<V::Output, &'static Status> {
        match kem {
            #[cfg(all(umilib_feature = "crypto-curve-p256", umilib_feature = "hash-sha-v2"))]
            0x0010 => Ok(call.call::<crate::crypto::hpke::DHKEM<
                crate::crypto::ecdh::ECDH<crate::crypto::curve::p256::P256>,
                crate::hash::sha::v2::SHA256,
            >>()),
            #[cfg(all(umilib_feature = "crypto-curve-p384", umilib_feature = "hash-sha-v2"))]
            0x0011 => Ok(call.call::<crate::crypto::hpke::DHKEM<
                crate::crypto::ecdh::ECDH<crate::crypto::curve::p384::P384>,
                crate::hash::sha::v2::SHA384,
            >>()),
            #[cfg(all(umilib_feature = "crypto-curve-p521", umilib_feature = "hash-sha-v2"))]
            0x0012 => Ok(call.call::<crate::crypto::hpke::DHKEM<
                crate::crypto::ecdh::ECDH<crate::crypto::curve::p521::P521>,
                crate::hash::sha::v2::SHA512,
            >>()),
            #[cfg(all(umilib_feature = "crypto-curve-curve25519", umilib_feature = "hash-sha-v2"))]
            0x0020 => {
                Ok(call.call::<crate::crypto::hpke::DHKEM<crate::crypto::ecdh::X25519, crate::hash::sha::v2::SHA256>>())
            }
            #[cfg(all(umilib_feature = "crypto-curve-curve448", umilib_feature = "hash-sha-v2"))]
            0x0021 => {
                Ok(call.call::<crate::crypto::hpke::DHKEM<crate::crypto::ecdh::X448, crate::hash::sha::v2::SHA512>>())
            }
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    /// Calls `call` with the suite; fails with InvalidArgument for an identifier that is unknown.
    pub fn call<V: HPKECall>(self, call: V) -> Result<V::Output, &'static Status> {
        HPKESuite::call_kem(self.kem, HPKESuiteKEM { suite: self, call })?
    }

    /// [`HPKESuite::call`] with the KEM `K` chosen.
    pub fn call_with_kem<K: HPKEKEM, V: HPKECall>(self, call: V) -> Result<V::Output, &'static Status> {
        match self.kdf {
            #[cfg(umilib_feature = "hash-sha-v2")]
            0x0001 => self.call_with_kdf::<K, crate::hash::sha::v2::SHA256, V>(call),
            #[cfg(umilib_feature = "hash-sha-v2")]
            0x0002 => self.call_with_kdf::<K, crate::hash::sha::v2::SHA384, V>(call),
            #[cfg(umilib_feature = "hash-sha-v2")]
            0x0003 => self.call_with_kdf::<K, crate::hash::sha::v2::SHA512, V>(call),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    /// [`HPKESuite::call`] with the KEM `K` and the KDF `F` chosen.
    pub fn call_with_kdf<K: HPKEKEM, F: HPKEKDF + 'static, V: HPKECall>(
        self,
        call: V,
    ) -> Result<V::Output, &'static Status> {
        use crate::crypto::hpke::HPKEExportOnly;
        match self.aead {
            #[cfg(all(umilib_feature = "crypto-mode-gcm", umilib_feature = "crypto-aes"))]
            0x0001 => Ok(call.call::<K, F, crate::crypto::mode::gcm::GCM<crate::crypto::aes::AES128, 16>>()),
            #[cfg(all(umilib_feature = "crypto-mode-gcm", umilib_feature = "crypto-aes"))]
            0x0002 => Ok(call.call::<K, F, crate::crypto::mode::gcm::GCM<crate::crypto::aes::AES256, 16>>()),
            #[cfg(umilib_feature = "crypto-chacha20poly1305")]
            0x0003 => Ok(call.call::<K, F, crate::crypto::chacha20poly1305::ChaCha20Poly1305>()),
            0xFFFF => Ok(call.call::<K, F, HPKEExportOnly>()),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

/// The step of [`HPKESuite::call`] from the KEM to the KDF and AEAD.
pub struct HPKESuiteKEM<V: HPKECall> {
    pub suite: HPKESuite,
    pub call: V,
}

impl<V: HPKECall> HPKEKEMCall for HPKESuiteKEM<V> {
    type Output = Result<V::Output, &'static Status>;

    fn call<K: HPKEKEM>(self) -> Self::Output {
        self.suite.call_with_kem::<K, V>(self.call)
    }
}

/// The sizes in bytes of the KEM: Nenc, Npk and Nsk.
pub struct HPKESizes;

impl HPKEKEMCall for HPKESizes {
    type Output = [usize; 3];

    fn call<K: HPKEKEM>(self) -> [usize; 3] {
        [K::ENCAPSULATED_SIZE, K::PUBLIC_KEY_SIZE, K::PRIVATE_KEY_SIZE]
    }
}

/// The source of a key pair of the KEM.
pub enum HPKEKeySource<'a> {
    /// GenerateKeyPair() from the generator.
    Random(RandomSource<'a>),
    /// DeriveKeyPair(ikm).
    Derive(&'a [u8]),
    /// The pair of the encoded private key.
    Private(&'a [u8]),
}

impl HPKEKeySource<'_> {
    /// The pair of keys of `K`.
    pub fn key_pair<K: HPKEKEM>(self) -> Result<(K::PrivateKey, K::PublicKey), CryptoError> {
        match self {
            HPKEKeySource::Random(mut random) => K::generate_key_pair(&mut random),
            HPKEKeySource::Derive(ikm) => K::derive_key_pair(ikm),
            HPKEKeySource::Private(bytes) => {
                let key = K::deserialize_private_key(bytes)?;
                let public_key = K::public_key(&key);
                Ok((key, public_key))
            }
        }
    }
}

/// Writes the encodings of a key pair into `private_key` (unless it is `None`) and `public_key`.
pub struct HPKEKeyPair<'a> {
    pub source: HPKEKeySource<'a>,
    pub private_key: Option<&'a mut [u8]>,
    pub public_key: &'a mut [u8],
}

impl HPKEKEMCall for HPKEKeyPair<'_> {
    type Output = Result<(), CryptoError>;

    fn call<K: HPKEKEM>(self) -> Result<(), CryptoError> {
        let (private_key, public_key) = self.source.key_pair::<K>()?;
        HPKEKeyPair::copy(&K::serialize_public_key(&public_key), self.public_key)?;
        if let Some(out) = self.private_key {
            let mut bytes = K::serialize_private_key(&private_key);
            let result = HPKEKeyPair::copy(&bytes, out);
            bytes.zeroize();
            result?;
        }
        Ok(())
    }
}

impl HPKEKeyPair<'_> {
    /// Copies `bytes` into `out` of their length; fails with InputLength otherwise.
    pub fn copy(bytes: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != bytes.len() {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        out.copy_from_slice(bytes);
        Ok(())
    }
}

/// DeserializePrivateKey of the encoded `private_key`.
pub struct HPKECheckPrivate<'a> {
    pub private_key: &'a [u8],
}

impl HPKEKEMCall for HPKECheckPrivate<'_> {
    type Output = Result<(), CryptoError>;

    fn call<K: HPKEKEM>(self) -> Result<(), CryptoError> {
        K::deserialize_private_key(self.private_key).map(|_| ())
    }
}

/// DeserializePublicKey of the encoded `public_key`, with its validation.
pub struct HPKECheckPublic<'a> {
    pub public_key: &'a [u8],
}

impl HPKEKEMCall for HPKECheckPublic<'_> {
    type Output = Result<(), CryptoError>;

    fn call<K: HPKEKEM>(self) -> Result<(), CryptoError> {
        K::deserialize_public_key(self.public_key).map(|_| ())
    }
}

/// The inputs of a setup common to both parties (section 5.1).
pub struct HPKEInputs<'a> {
    pub info: &'a [u8],
    /// The pre-shared key and its identifier, or `None`.
    pub psk: Option<(&'a [u8], &'a [u8])>,
    /// The encoded key of the sender (private for the sender, public for the receiver), or `None`.
    pub sender: Option<&'a [u8]>,
}

impl<'a> HPKEInputs<'a> {
    /// The inputs of the C ABI: a pre-shared key and a sender's key are absent when empty.
    pub fn new(info: &'a [u8], psk: &'a [u8], psk_id: &'a [u8], sender: &'a [u8]) -> HPKEInputs<'a> {
        let psk = (!psk.is_empty() || !psk_id.is_empty()).then_some((psk, psk_id));
        HPKEInputs { info, psk, sender: (!sender.is_empty()).then_some(sender) }
    }
}

/// SetupS of the mode of the inputs (section 5.1) for the encoded public key
/// `recipient`, with the ephemeral key of `ephemeral`: writes enc into
/// `encapsulated` of Nenc bytes and gives the context.
pub struct HPKESetupSender<'a> {
    pub recipient: &'a [u8],
    pub inputs: HPKEInputs<'a>,
    pub ephemeral: HPKEKeySource<'a>,
    pub encapsulated: &'a mut [u8],
}

impl HPKECall for HPKESetupSender<'_> {
    type Output = Result<Box<dyn HPKESenderState>, CryptoError>;

    fn call<K: HPKEKEM, F: HPKEKDF + 'static, A: HPKEAEAD + 'static>(self) -> Self::Output {
        let recipient = K::deserialize_public_key(self.recipient)?;
        let sender = self.inputs.sender.map(K::deserialize_private_key).transpose()?;
        let (ephemeral, _) = self.ephemeral.key_pair::<K>()?;
        let (encapsulated, context) = HPKE::<K, F, A>::setup_sender_with_ephemeral(
            &recipient,
            self.inputs.info,
            self.inputs.psk,
            sender.as_ref(),
            &ephemeral,
        )?;
        HPKEKeyPair::copy(&encapsulated, self.encapsulated)?;
        Ok(Box::new(context))
    }
}

/// SetupR of the mode of the inputs (section 5.1) for the enc `encapsulated`
/// and the encoded private key `recipient`.
pub struct HPKESetupReceiver<'a> {
    pub encapsulated: &'a [u8],
    pub recipient: &'a [u8],
    pub inputs: HPKEInputs<'a>,
}

impl HPKECall for HPKESetupReceiver<'_> {
    type Output = Result<Box<dyn HPKEReceiverState>, CryptoError>;

    fn call<K: HPKEKEM, F: HPKEKDF + 'static, A: HPKEAEAD + 'static>(self) -> Self::Output {
        let recipient = K::deserialize_private_key(self.recipient)?;
        let sender = self.inputs.sender.map(K::deserialize_public_key).transpose()?;
        let context = HPKE::<K, F, A>::setup_receiver(
            self.encapsulated,
            &recipient,
            self.inputs.info,
            self.inputs.psk,
            sender.as_ref(),
        )?;
        Ok(Box::new(context))
    }
}

crate::ffi_functions! {
    /// Writes Nenc, Npk and Nsk, the sizes in bytes of an enc, a public key and a private key of the KEM `kem`,
    /// into `sizes` (three elements).
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_sizes(kem: u16, sizes: *mut usize) -> *const Status {
        Status::from_result((|| {
            let values = HPKESuite::call_kem(kem, HPKESizes)?;
            // SAFETY: the caller passes three writable elements.
            let out = unsafe { Pointer::slice_of_mut(sizes, 3) }?;
            out.copy_from_slice(&values);
            Ok(())
        })())
    }

    /// GenerateKeyPair() of the KEM `kem` from the generator handle `random` of the type named by
    /// `random_type`: writes the private key into `private_key` of Nsk bytes and the public key into `public_key` of
    /// Npk bytes.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_generate_key_pair(kem: u16, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, private_key: *mut u8, private_key_length: usize, public_key: *mut u8, public_key_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(random_type, random_type_length)], &[(private_key.cast_const(), private_key_length), (public_key.cast_const(), public_key_length)])?;
            // SAFETY: the caller passes a live generator of the named type and writable bytes.
            let random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let private_key = unsafe { Pointer::slice_mut(private_key, private_key_length) }?;
            let public_key = unsafe { Pointer::slice_mut(public_key, public_key_length) }?;
            let call = HPKEKeyPair { source: HPKEKeySource::Random(random), private_key: Some(private_key), public_key };
            HPKESuite::call_kem(kem, call)?.map_err(|error| error.to_status())
        })())
    }

    /// DeriveKeyPair(ikm) of the KEM `kem` (section 7.1.3): writes the private key into `private_key` of Nsk
    /// bytes and the public key into `public_key` of Npk bytes.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_derive_key_pair(kem: u16, ikm: *const u8, ikm_length: usize, private_key: *mut u8, private_key_length: usize, public_key: *mut u8, public_key_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(ikm, ikm_length)], &[(private_key.cast_const(), private_key_length), (public_key.cast_const(), public_key_length)])?;
            // SAFETY: the caller passes readable bytes and writable bytes.
            let ikm = unsafe { Pointer::slice(ikm, ikm_length) }?;
            let private_key = unsafe { Pointer::slice_mut(private_key, private_key_length) }?;
            let public_key = unsafe { Pointer::slice_mut(public_key, public_key_length) }?;
            let call = HPKEKeyPair { source: HPKEKeySource::Derive(ikm), private_key: Some(private_key), public_key };
            HPKESuite::call_kem(kem, call)?.map_err(|error| error.to_status())
        })())
    }

    /// Succeeds if the private key is one of the KEM `kem` (DeserializePrivateKey of section 7.1.2); fails with
    /// InvalidKey otherwise.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_check_private_key(kem: u16, private_key: *const u8, private_key_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes.
            let private_key = unsafe { Pointer::slice(private_key, private_key_length) }?;
            HPKESuite::call_kem(kem, HPKECheckPrivate { private_key })?.map_err(|error| error.to_status())
        })())
    }

    /// Succeeds if the public key is one of the KEM `kem` (DeserializePublicKey and the validation of
    /// section 7.1.4); fails with InvalidKey otherwise.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_check_public_key(kem: u16, public_key: *const u8, public_key_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes.
            let public_key = unsafe { Pointer::slice(public_key, public_key_length) }?;
            HPKESuite::call_kem(kem, HPKECheckPublic { public_key })?.map_err(|error| error.to_status())
        })())
    }

    /// Writes the public key of the private key of the KEM `kem` into `out` of Npk bytes.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_public_key(kem: u16, private_key: *const u8, private_key_length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(private_key, private_key_length)], &[(out.cast_const(), out_length)])?;
            // SAFETY: the caller passes readable bytes and writable bytes.
            let private_key = unsafe { Pointer::slice(private_key, private_key_length) }?;
            let public_key = unsafe { Pointer::slice_mut(out, out_length) }?;
            let call = HPKEKeyPair { source: HPKEKeySource::Private(private_key), private_key: None, public_key };
            HPKESuite::call_kem(kem, call)?.map_err(|error| error.to_status())
        })())
    }

    /// SetupBaseS, SetupPSKS, SetupAuthS or SetupAuthPSKS (section 5.1) of the suite for the public key
    /// `recipient`, with an ephemeral key from the generator handle `random` of the type named by
    /// `random_type`: writes enc into `encapsulated` of Nenc bytes and creates the sender's context.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_setup_sender(kem: u16, kdf: u16, aead: u16, recipient: *const u8, recipient_length: usize, info: *const u8, info_length: usize, psk: *const u8, psk_length: usize, psk_id: *const u8, psk_id_length: usize, sender: *const u8, sender_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, encapsulated: *mut u8, encapsulated_length: usize, out: *mut *mut Box<dyn HPKESenderState>) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(recipient, recipient_length), (info, info_length), (psk, psk_length), (psk_id, psk_id_length), (sender, sender_length), (random_type, random_type_length)], &[(encapsulated.cast_const(), encapsulated_length)])?;
            // SAFETY: the caller passes readable bytes, a live generator of the named type, writable bytes and
            // a writable pointer.
            let random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let call = HPKESetupSender {
                recipient: unsafe { Pointer::slice(recipient, recipient_length) }?,
                inputs: HPKEInputs::new(
                    unsafe { Pointer::slice(info, info_length) }?,
                    unsafe { Pointer::slice(psk, psk_length) }?,
                    unsafe { Pointer::slice(psk_id, psk_id_length) }?,
                    unsafe { Pointer::slice(sender, sender_length) }?,
                ),
                ephemeral: HPKEKeySource::Random(random),
                encapsulated: unsafe { Pointer::slice_mut(encapsulated, encapsulated_length) }?,
            };
            let context = HPKESuite { kem, kdf, aead }.call(call)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, context) }
        })())
    }

    /// [`umilib_crypto_hpke_hpke_setup_sender`] with the encoded ephemeral private key `ephemeral` (as
    /// DeriveKeyPair(ikmE) gives it in the test vectors of RFC 9180 appendix A). The key must be fresh and
    /// secret.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_setup_sender_with_ephemeral(kem: u16, kdf: u16, aead: u16, recipient: *const u8, recipient_length: usize, info: *const u8, info_length: usize, psk: *const u8, psk_length: usize, psk_id: *const u8, psk_id_length: usize, sender: *const u8, sender_length: usize, ephemeral: *const u8, ephemeral_length: usize, encapsulated: *mut u8, encapsulated_length: usize, out: *mut *mut Box<dyn HPKESenderState>) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(recipient, recipient_length), (info, info_length), (psk, psk_length), (psk_id, psk_id_length), (sender, sender_length), (ephemeral, ephemeral_length)], &[(encapsulated.cast_const(), encapsulated_length)])?;
            // SAFETY: the caller passes readable bytes, writable bytes and a writable pointer.
            let call = HPKESetupSender {
                recipient: unsafe { Pointer::slice(recipient, recipient_length) }?,
                inputs: HPKEInputs::new(
                    unsafe { Pointer::slice(info, info_length) }?,
                    unsafe { Pointer::slice(psk, psk_length) }?,
                    unsafe { Pointer::slice(psk_id, psk_id_length) }?,
                    unsafe { Pointer::slice(sender, sender_length) }?,
                ),
                ephemeral: HPKEKeySource::Private(unsafe { Pointer::slice(ephemeral, ephemeral_length) }?),
                encapsulated: unsafe { Pointer::slice_mut(encapsulated, encapsulated_length) }?,
            };
            let context = HPKESuite { kem, kdf, aead }.call(call)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, context) }
        })())
    }

    /// SetupBaseR, SetupPSKR, SetupAuthR or SetupAuthPSKR (section 5.1) of the suite for the enc
    /// `encapsulated` and the private key `recipient` (with the sender's public key in the auth modes):
    /// creates the receiver's context.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_setup_receiver(kem: u16, kdf: u16, aead: u16, encapsulated: *const u8, encapsulated_length: usize, recipient: *const u8, recipient_length: usize, info: *const u8, info_length: usize, psk: *const u8, psk_length: usize, psk_id: *const u8, psk_id_length: usize, sender: *const u8, sender_length: usize, out: *mut *mut Box<dyn HPKEReceiverState>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let call = HPKESetupReceiver {
                encapsulated: unsafe { Pointer::slice(encapsulated, encapsulated_length) }?,
                recipient: unsafe { Pointer::slice(recipient, recipient_length) }?,
                inputs: HPKEInputs::new(
                    unsafe { Pointer::slice(info, info_length) }?,
                    unsafe { Pointer::slice(psk, psk_length) }?,
                    unsafe { Pointer::slice(psk_id, psk_id_length) }?,
                    unsafe { Pointer::slice(sender, sender_length) }?,
                ),
            };
            let context = HPKESuite { kem, kdf, aead }.call(call)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, context) }
        })())
    }

    /// Releases the sender's context, zeroizing its secrets. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_sender_context_free(context: *mut Box<dyn HPKESenderState>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(context) }
    }

    /// Writes the sequence number of the next message into `out`.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_sender_context_sequence(context: *const Box<dyn HPKESenderState>, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable element.
            let context = unsafe { Pointer::reference(context) }?;
            unsafe { Pointer::write(out, context.sequence()) }
        })())
    }

    /// ContextS.Seal(aad, pt) (section 5.2): writes the ciphertext with its tag into a new buffer. Fails with
    /// InvalidParameter for the export-only AEAD and LimitExceeded after the last sequence number.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_sender_context_seal(context: *mut Box<dyn HPKESenderState>, associated: *const u8, associated_length: usize, plaintext: *const u8, plaintext_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable buffer.
            let context = unsafe { Pointer::reference_mut(context) }?;
            let associated = unsafe { Pointer::slice(associated, associated_length) }?;
            let plaintext = unsafe { Pointer::slice(plaintext, plaintext_length) }?;
            let ciphertext = context.seal(associated, plaintext).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(ciphertext)) }
        })())
    }

    /// Context.Export(exporter_context, L) (section 5.3) into `out` of L bytes.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_sender_context_export(context: *const Box<dyn HPKESenderState>, exporter_context: *const u8, exporter_context_length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(exporter_context, exporter_context_length)], &[(out.cast_const(), out_length)])?;
            // SAFETY: the caller passes a valid handle, readable bytes and writable bytes.
            let context = unsafe { Pointer::reference(context) }?;
            let exporter_context = unsafe { Pointer::slice(exporter_context, exporter_context_length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            context.export(exporter_context, out).map_err(|error| error.to_status())
        })())
    }

    /// Releases the receiver's context, zeroizing its secrets. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_receiver_context_free(context: *mut Box<dyn HPKEReceiverState>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(context) }
    }

    /// Writes the sequence number of the next message into `out`.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_receiver_context_sequence(context: *const Box<dyn HPKEReceiverState>, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable element.
            let context = unsafe { Pointer::reference(context) }?;
            unsafe { Pointer::write(out, context.sequence()) }
        })())
    }

    /// ContextR.Open(aad, ct) (section 5.2): writes the plaintext into a new buffer. Fails with
    /// AuthenticationFailed unless the ciphertext authenticates at the next sequence number, which then does
    /// not advance.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_receiver_context_open(context: *mut Box<dyn HPKEReceiverState>, associated: *const u8, associated_length: usize, ciphertext: *const u8, ciphertext_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable buffer.
            let context = unsafe { Pointer::reference_mut(context) }?;
            let associated = unsafe { Pointer::slice(associated, associated_length) }?;
            let ciphertext = unsafe { Pointer::slice(ciphertext, ciphertext_length) }?;
            let plaintext = context.open(associated, ciphertext).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(plaintext)) }
        })())
    }

    /// Context.Export(exporter_context, L) (section 5.3) into `out` of L bytes.
    pub unsafe extern "C" fn umilib_crypto_hpke_hpke_receiver_context_export(context: *const Box<dyn HPKEReceiverState>, exporter_context: *const u8, exporter_context_length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(exporter_context, exporter_context_length)], &[(out.cast_const(), out_length)])?;
            // SAFETY: the caller passes a valid handle, readable bytes and writable bytes.
            let context = unsafe { Pointer::reference(context) }?;
            let exporter_context = unsafe { Pointer::slice(exporter_context, exporter_context_length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            context.export(exporter_context, out).map_err(|error| error.to_status())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "hpke",
    definitions: &[
        Definition::Opaque {
            name: "umilib_crypto_hpke_HPKESenderContext",
            documentation: " The context of a sender of HPKE (RFC 9180 section 5.2), of any suite: it seals and exports.",
        },
        Definition::Opaque {
            name: "umilib_crypto_hpke_HPKEReceiverContext",
            documentation: " The context of a receiver of HPKE (RFC 9180 section 5.2), of any suite: it opens and exports.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
