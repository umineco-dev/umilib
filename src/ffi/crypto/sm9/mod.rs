//! The C ABI of [`crate::crypto::sm9`].
//!
//! The schemes are exported on the pairing-friendly curves of
//! [`ffi_pairing_curves!`](crate::ffi_pairing_curves) with the hash
//! functions of [`ffi_standard_digests!`](crate::ffi_standard_digests) and
//! SM3, and [`SM9PKE`] with [`SM9StreamCipher`] or [`SM9BlockCipher`] over a
//! block cipher of [`ffi_block_ciphers!`](crate::ffi_block_ciphers), each
//! named by its C type name ([`SM9Registry`]); GM/T 0044 specifies
//! `umilib_math_pairing_SM9BN256` with `umilib_hash_sm3_SM3`, and annex D
//! uses `umilib_crypto_sm4_SM4`. The master key
//! ([`SM9EncryptMasterKey`]), the keys of the users
//! ([`SM9EncryptUserKey`]) and the sides of the key exchange ([`SM9KEP`])
//! are the handles `umilib_crypto_sm9_SM9EncryptMasterKey`,
//! `umilib_crypto_sm9_SM9EncryptUserKey` and `umilib_crypto_sm9_SM9KEP`,
//! which keep their curve; the functions that take a key name the hash
//! function (and the cipher) as Rust names their types. Scalars are
//! big-endian of the bytes of the order, points of G_1 x || y and points of
//! G_2 04 || x || y ([`SM9Encoding`]); the role of the key exchange is 0 for
//! the initiator and 1 for the responder.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::crypto::CryptoError;
#[cfg(umilib_feature = "crypto-mode-cbc")]
use crate::crypto::sm9::SM9BlockCipher;
use crate::crypto::sm9::{
    SM9Cipher, SM9Encoding, SM9EncryptMasterKey, SM9EncryptUserKey, SM9KEM, SM9KEP, SM9PKE, SM9Role, SM9StreamCipher,
};
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};
use crate::hash::CryptographicDigest;
use crate::math::ec::{FieldElement, PrimeField};
use crate::math::pairing::PairingCurve;
use crate::secret::Zeroize;

/// An operation on a curve chosen at run time.
pub trait SM9CurveCall {
    type Output;

    fn call<C: PairingCurve + 'static>(self) -> Self::Output;
}

/// An operation on the curve `C` with a hash function chosen at run time.
pub trait SM9HashCall<C: PairingCurve> {
    type Output;

    fn call<H: CryptographicDigest + Default + 'static>(self) -> Self::Output;
}

/// An operation on a curve and a hash function chosen at run time.
pub trait SM9Call {
    type Output;

    fn call<C: PairingCurve + 'static, H: CryptographicDigest + Default + 'static>(self) -> Self::Output;
}

/// An operation with a cipher of [`SM9PKE`] chosen at run time.
pub trait SM9CipherCall {
    type Output;

    fn call<E: SM9Cipher>(self) -> Self::Output;
}

/// The curves, hash functions and ciphers of the C ABI, by their C type
/// names; each function gives `None` for a name that is unknown or not enabled.
pub struct SM9Registry;

/// Defines [`SM9Registry::curve`] over the curves of the registry.
macro_rules! sm9_curves {
    ($($variant:ident => $type:path, $name:literal;)*) => {
        impl SM9Registry {
            /// Calls `call` with the curve named `name`.
            pub fn curve<V: SM9CurveCall>(name: &str, call: V) -> Option<V::Output> {
                match name {
                    $($name => Some(call.call::<$type>()),)*
                    _ => None,
                }
            }
        }
    };
}

/// Defines [`SM9Registry::hash`] over the hash functions of the registry.
macro_rules! sm9_hashes {
    ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
        impl SM9Registry {
            /// Calls `call` with the hash function named `name`.
            // The registry may enable no hash function, leaving the arguments unused.
            #[allow(unused_variables)]
            pub fn hash<C: PairingCurve, V: SM9HashCall<C>>(name: &str, call: V) -> Option<V::Output> {
                match name {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some(call.call::<$type>()),
                    )*
                    // The hash function GM/T 0044 specifies, beside those of the registry.
                    #[cfg(umilib_feature = "hash-sm3")]
                    "umilib_hash_sm3_SM3" => Some(call.call::<crate::hash::sm3::SM3>()),
                    _ => None,
                }
            }
        }
    };
}

/// Defines [`SM9Registry::cipher`] over the block ciphers of the registry.
macro_rules! sm9_ciphers {
    ([16] $($feature:literal $variant:ident => $type:path, $name:literal;)* [8] $($feature8:literal $variant8:ident => $type8:path, $name8:literal;)*) => {
        impl SM9Registry {
            /// The C type name of [`SM9StreamCipher`].
            pub const STREAM_CIPHER: &'static str = "umilib_crypto_sm9_SM9StreamCipher";

            /// Calls `call` with [`SM9StreamCipher`] for [`SM9Registry::STREAM_CIPHER`], or with
            /// [`SM9BlockCipher`] over the block cipher named `name`.
            pub fn cipher<V: SM9CipherCall>(name: &str, call: V) -> Option<V::Output> {
                match name {
                    SM9Registry::STREAM_CIPHER => Some(call.call::<SM9StreamCipher>()),
                    $(
                        #[cfg(all(umilib_feature = "crypto-mode-cbc", umilib_feature = $feature))]
                        $name => Some(call.call::<SM9BlockCipher<$type>>()),
                    )*
                    $(
                        #[cfg(all(umilib_feature = "crypto-mode-cbc", umilib_feature = $feature8))]
                        $name8 => Some(call.call::<SM9BlockCipher<$type8>>()),
                    )*
                    _ => None,
                }
            }
        }
    };
}

crate::ffi_pairing_curves!(sm9_curves);
crate::ffi_standard_digests!(sm9_hashes);
crate::ffi_block_ciphers!(sm9_ciphers);

impl SM9Registry {
    /// Calls `call` with the curve named `curve` and the hash function named `hash`.
    pub fn scheme<V: SM9Call>(curve: &str, hash: &str, call: V) -> Option<V::Output> {
        SM9Registry::curve(curve, SM9WithHash { hash, call }).flatten()
    }
}

/// The step of [`SM9Registry::scheme`] from the curve to the hash function.
pub struct SM9WithHash<'a, V> {
    hash: &'a str,
    call: V,
}

impl<V: SM9Call> SM9CurveCall for SM9WithHash<'_, V> {
    type Output = Option<V::Output>;

    fn call<C: PairingCurve + 'static>(self) -> Option<V::Output> {
        SM9Registry::hash::<C, _>(self.hash, SM9OnCurve { call: self.call, curve: PhantomData::<C> })
    }
}

/// The step of [`SM9Registry::scheme`] with the curve `C` chosen.
pub struct SM9OnCurve<C, V> {
    call: V,
    curve: PhantomData<C>,
}

impl<C: PairingCurve + 'static, V: SM9Call> SM9HashCall<C> for SM9OnCurve<C, V> {
    type Output = V::Output;

    fn call<H: CryptographicDigest + Default + 'static>(self) -> V::Output {
        self.call.call::<C, H>()
    }
}

/// The random r of an operation: drawn from a generator, or given.
pub enum SM9Ephemeral<'a> {
    Random(RandomSource<'a>),
    Given(&'a [u8]),
}

impl SM9Ephemeral<'_> {
    /// r given, in \[1, N - 1\]; fails with `InvalidKey` otherwise.
    pub fn scalar<C: PairingCurve>(bytes: &[u8]) -> Result<FieldElement<C::Scalar>, CryptoError> {
        let scalar = FieldElement::from_be_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?;
        if scalar.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(scalar)
    }
}

/// A master key on a curve chosen at run time: [`SM9EncryptMasterKey`].
pub trait SM9MasterState {
    /// ke, big-endian.
    fn secret(&self) -> Vec<u8>;

    /// Ppub-e, x || y.
    fn public_key(&self) -> Vec<u8>;

    /// The key of `identity` and `hid` with H1 of the hash function named `hash`.
    fn extract(&self, hash: &str, identity: &[u8], hid: u8) -> Option<Result<Box<dyn SM9UserState>, CryptoError>>;
}

/// A user's key on a curve chosen at run time: [`SM9EncryptUserKey`].
pub trait SM9UserState {
    fn identity(&self) -> &[u8];

    fn hid(&self) -> u8;

    /// de, 04 || x || y.
    fn key(&self) -> Vec<u8>;

    /// Ppub-e, x || y.
    fn master(&self) -> Vec<u8>;

    /// A side of the key exchange with the hash function named `hash`.
    fn exchange(
        &self,
        hash: &str,
        role: SM9Role,
        peer_identity: &[u8],
        ephemeral: SM9Ephemeral<'_>,
    ) -> Option<Result<Box<dyn SM9KEPState>, CryptoError>>;

    /// K of the encapsulation C (x || y) into `out`, with the hash function named `hash`.
    fn decapsulate(&self, hash: &str, encapsulated: &[u8], out: &mut [u8]) -> Option<Result<(), CryptoError>>;

    /// The message of `ciphertext`, with the hash function named `hash` and the cipher named `cipher`.
    fn decrypt(&self, hash: &str, cipher: &str, ciphertext: &[u8]) -> Option<Result<Vec<u8>, CryptoError>>;
}

/// A side of the key exchange on a curve and with a hash function chosen at run time: [`SM9KEP`].
pub trait SM9KEPState {
    /// R, x || y.
    fn ephemeral_public_key(&self) -> Vec<u8>;

    /// The bytes of a confirmation: those of the hash function.
    fn confirmation_size(&self) -> usize;

    /// SK of the other side's R (x || y) into `out`, and the confirmations S_B and S_A into `responder` and
    /// `initiator`, of [`SM9KEPState::confirmation_size`] bytes.
    fn agree(
        &self,
        peer_ephemeral: &[u8],
        out: &mut [u8],
        responder: &mut [u8],
        initiator: &mut [u8],
    ) -> Result<(), CryptoError>;
}

/// The master key on the curve `C`.
pub struct SM9Master<C: PairingCurve> {
    pub key: SM9EncryptMasterKey<C>,
}

/// A user's key on the curve `C`.
pub struct SM9User<C: PairingCurve> {
    pub key: SM9EncryptUserKey<C>,
}

/// A side of the key exchange on the curve `C` with the hash function `H`.
pub struct SM9Side<C: PairingCurve, H: CryptographicDigest + Default> {
    pub side: SM9KEP<C, H>,
}

impl<C: PairingCurve + 'static> SM9MasterState for SM9Master<C> {
    fn secret(&self) -> Vec<u8> {
        let mut out = vec![0u8; <C::Scalar as PrimeField>::BYTES];
        // The buffer has the bytes of the scalars.
        let _ = self.key.secret().write_be_bytes(&mut out);
        out
    }

    fn public_key(&self) -> Vec<u8> {
        // Ppub-e = [ke]P1 with ke in [1, N - 1] is never the identity.
        SM9Encoding::<C>::g1(self.key.public_key()).unwrap_or_default()
    }

    fn extract(&self, hash: &str, identity: &[u8], hid: u8) -> Option<Result<Box<dyn SM9UserState>, CryptoError>> {
        SM9Registry::hash::<C, _>(hash, SM9Extract { key: &self.key, identity, hid })
    }
}

/// [`SM9EncryptMasterKey::extract`] with the hash function chosen at run time.
pub struct SM9Extract<'a, C: PairingCurve> {
    key: &'a SM9EncryptMasterKey<C>,
    identity: &'a [u8],
    hid: u8,
}

impl<C: PairingCurve + 'static> SM9HashCall<C> for SM9Extract<'_, C> {
    type Output = Result<Box<dyn SM9UserState>, CryptoError>;

    fn call<H: CryptographicDigest + Default + 'static>(self) -> Self::Output {
        let key = self.key.extract::<H>(self.identity, self.hid)?;
        Ok(Box::new(SM9User { key }))
    }
}

impl<C: PairingCurve + 'static> SM9UserState for SM9User<C> {
    fn identity(&self) -> &[u8] {
        self.key.identity()
    }

    fn hid(&self) -> u8 {
        self.key.hid()
    }

    fn key(&self) -> Vec<u8> {
        // de = [t2]P2 with t2 in [1, N - 1] is never the identity.
        SM9Encoding::<C>::g2(self.key.key()).unwrap_or_default()
    }

    fn master(&self) -> Vec<u8> {
        SM9Encoding::<C>::g1(self.key.master()).unwrap_or_default()
    }

    fn exchange(
        &self,
        hash: &str,
        role: SM9Role,
        peer_identity: &[u8],
        ephemeral: SM9Ephemeral<'_>,
    ) -> Option<Result<Box<dyn SM9KEPState>, CryptoError>> {
        SM9Registry::hash::<C, _>(hash, SM9Exchange { key: &self.key, role, peer_identity, ephemeral })
    }

    fn decapsulate(&self, hash: &str, encapsulated: &[u8], out: &mut [u8]) -> Option<Result<(), CryptoError>> {
        SM9Registry::hash::<C, _>(hash, SM9Decapsulate { key: &self.key, encapsulated, out })
    }

    fn decrypt(&self, hash: &str, cipher: &str, ciphertext: &[u8]) -> Option<Result<Vec<u8>, CryptoError>> {
        SM9Registry::hash::<C, _>(hash, SM9Decrypt { key: &self.key, cipher, ciphertext }).flatten()
    }
}

/// [`SM9KEP::new`] and [`SM9KEP::generate`] with the hash function chosen at run time.
pub struct SM9Exchange<'a, C: PairingCurve> {
    key: &'a SM9EncryptUserKey<C>,
    role: SM9Role,
    peer_identity: &'a [u8],
    ephemeral: SM9Ephemeral<'a>,
}

impl<C: PairingCurve + 'static> SM9HashCall<C> for SM9Exchange<'_, C> {
    type Output = Result<Box<dyn SM9KEPState>, CryptoError>;

    fn call<H: CryptographicDigest + Default + 'static>(self) -> Self::Output {
        let key = SM9EncryptUserKey::new(self.key.identity(), self.key.hid(), *self.key.key(), *self.key.master());
        let side = match self.ephemeral {
            SM9Ephemeral::Random(mut random) => {
                SM9KEP::<C, H>::generate(self.role, key, self.peer_identity, &mut random)?
            }
            SM9Ephemeral::Given(bytes) => {
                let mut scalar = SM9Ephemeral::scalar::<C>(bytes)?;
                let side = SM9KEP::<C, H>::new(self.role, key, self.peer_identity, scalar);
                scalar.zeroize();
                side?
            }
        };
        Ok(Box::new(SM9Side { side }))
    }
}

/// [`SM9KEM::decapsulate`] with the hash function chosen at run time.
pub struct SM9Decapsulate<'a, C: PairingCurve> {
    key: &'a SM9EncryptUserKey<C>,
    encapsulated: &'a [u8],
    out: &'a mut [u8],
}

impl<C: PairingCurve + 'static> SM9HashCall<C> for SM9Decapsulate<'_, C> {
    type Output = Result<(), CryptoError>;

    fn call<H: CryptographicDigest + Default + 'static>(self) -> Self::Output {
        let encapsulated = SM9Encoding::<C>::g1_from_bytes(self.encapsulated)?;
        SM9KEM::<C, H>::decapsulate(self.key, &encapsulated, self.out)
    }
}

/// [`SM9PKE::decrypt`] with the hash function and the cipher chosen at run time.
pub struct SM9Decrypt<'a, C: PairingCurve> {
    key: &'a SM9EncryptUserKey<C>,
    cipher: &'a str,
    ciphertext: &'a [u8],
}

impl<C: PairingCurve + 'static> SM9HashCall<C> for SM9Decrypt<'_, C> {
    type Output = Option<Result<Vec<u8>, CryptoError>>;

    fn call<H: CryptographicDigest + Default + 'static>(self) -> Self::Output {
        let call = SM9DecryptWith::<C, H> { key: self.key, ciphertext: self.ciphertext, hash: PhantomData };
        SM9Registry::cipher(self.cipher, call)
    }
}

/// The step of [`SM9Decrypt`] with the hash function `H` chosen.
pub struct SM9DecryptWith<'a, C: PairingCurve, H> {
    key: &'a SM9EncryptUserKey<C>,
    ciphertext: &'a [u8],
    hash: PhantomData<H>,
}

impl<C: PairingCurve, H: CryptographicDigest + Default> SM9CipherCall for SM9DecryptWith<'_, C, H> {
    type Output = Result<Vec<u8>, CryptoError>;

    fn call<E: SM9Cipher>(self) -> Self::Output {
        SM9PKE::<C, H, E>::decrypt(self.key, self.ciphertext)
    }
}

impl<C: PairingCurve + 'static, H: CryptographicDigest + Default + 'static> SM9KEPState for SM9Side<C, H> {
    fn ephemeral_public_key(&self) -> Vec<u8> {
        // R = [r]Q with r in [1, N - 1] and Q of order N is never the identity.
        SM9Encoding::<C>::g1(self.side.ephemeral_public_key()).unwrap_or_default()
    }

    fn confirmation_size(&self) -> usize {
        H::OUTPUT_SIZE
    }

    fn agree(
        &self,
        peer_ephemeral: &[u8],
        out: &mut [u8],
        responder: &mut [u8],
        initiator: &mut [u8],
    ) -> Result<(), CryptoError> {
        if responder.len() != H::OUTPUT_SIZE || initiator.len() != H::OUTPUT_SIZE {
            return Err(CryptoError::InputLength { length: responder.len().max(initiator.len()) });
        }
        let peer = SM9Encoding::<C>::g1_from_bytes(peer_ephemeral)?;
        let confirmation = self.side.agree(&peer, out)?;
        responder.copy_from_slice(confirmation.responder());
        initiator.copy_from_slice(confirmation.initiator());
        Ok(())
    }
}

impl Value for Box<dyn SM9MasterState> {
    const TYPE: Type = Type::Named("umilib_crypto_sm9_SM9EncryptMasterKey");
}

impl Value for Box<dyn SM9UserState> {
    const TYPE: Type = Type::Named("umilib_crypto_sm9_SM9EncryptUserKey");
}

impl Value for Box<dyn SM9KEPState> {
    const TYPE: Type = Type::Named("umilib_crypto_sm9_SM9KEP");
}

/// The sizes in bytes of a scalar (ke, r), a point of G_1 (x || y), a point
/// of G_2 (04 || x || y) and an output of the hash function (C3, S_A, S_B).
pub struct SM9Sizes;

impl SM9Call for SM9Sizes {
    type Output = [usize; 4];

    fn call<C: PairingCurve + 'static, H: CryptographicDigest + Default + 'static>(self) -> [usize; 4] {
        [<C::Scalar as PrimeField>::BYTES, SM9Encoding::<C>::g1_length(), SM9Encoding::<C>::g2_length(), H::OUTPUT_SIZE]
    }
}

/// The master key from a generator, or of a given ke.
pub enum SM9MasterNew<'a> {
    Random(RandomSource<'a>),
    Secret(&'a [u8]),
}

impl SM9CurveCall for SM9MasterNew<'_> {
    type Output = Result<Box<dyn SM9MasterState>, CryptoError>;

    fn call<C: PairingCurve + 'static>(self) -> Self::Output {
        let key = match self {
            SM9MasterNew::Random(mut random) => SM9EncryptMasterKey::<C>::generate(&mut random)?,
            SM9MasterNew::Secret(bytes) => {
                let mut secret = FieldElement::from_be_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?;
                let key = SM9EncryptMasterKey::new(secret);
                secret.zeroize();
                key?
            }
        };
        Ok(Box::new(SM9Master { key }))
    }
}

/// [`SM9EncryptUserKey::new`] of encoded de and Ppub-e.
pub struct SM9UserNew<'a> {
    pub identity: &'a [u8],
    pub hid: u8,
    pub key: &'a [u8],
    pub master: &'a [u8],
}

impl SM9CurveCall for SM9UserNew<'_> {
    type Output = Result<Box<dyn SM9UserState>, CryptoError>;

    fn call<C: PairingCurve + 'static>(self) -> Self::Output {
        let key = SM9Encoding::<C>::g2_from_bytes(self.key)?;
        let master = SM9Encoding::<C>::g1_from_bytes(self.master)?;
        Ok(Box::new(SM9User { key: SM9EncryptUserKey::new(self.identity, self.hid, key, master) }))
    }
}

/// [`SM9KEM::encapsulate`] and [`SM9KEM::encapsulate_with_ephemeral`]: K into
/// `out` and C (x || y) into `encapsulated`.
pub struct SM9Encapsulate<'a> {
    pub master: &'a [u8],
    pub identity: &'a [u8],
    pub hid: u8,
    pub ephemeral: SM9Ephemeral<'a>,
    pub out: &'a mut [u8],
    pub encapsulated: &'a mut [u8],
}

impl SM9Call for SM9Encapsulate<'_> {
    type Output = Result<(), CryptoError>;

    fn call<C: PairingCurve + 'static, H: CryptographicDigest + Default + 'static>(self) -> Self::Output {
        if self.encapsulated.len() != SM9Encoding::<C>::g1_length() {
            return Err(CryptoError::InputLength { length: self.encapsulated.len() });
        }
        let master = SM9Encoding::<C>::g1_from_bytes(self.master)?;
        let point = match self.ephemeral {
            SM9Ephemeral::Random(mut random) => {
                SM9KEM::<C, H>::encapsulate(&master, self.identity, self.hid, self.out, &mut random)?
            }
            SM9Ephemeral::Given(bytes) => {
                let mut scalar = SM9Ephemeral::scalar::<C>(bytes)?;
                let point =
                    SM9KEM::<C, H>::encapsulate_with_ephemeral(&master, self.identity, self.hid, &scalar, self.out);
                scalar.zeroize();
                point?
            }
        };
        self.encapsulated.copy_from_slice(&SM9Encoding::<C>::g1(&point)?);
        Ok(())
    }
}

/// [`SM9PKE::encrypt`] and [`SM9PKE::encrypt_with_ephemeral`] with the cipher named `cipher`.
pub struct SM9Encrypt<'a> {
    pub cipher: &'a str,
    pub master: &'a [u8],
    pub identity: &'a [u8],
    pub hid: u8,
    pub message: &'a [u8],
    pub ephemeral: SM9Ephemeral<'a>,
}

impl SM9Call for SM9Encrypt<'_> {
    type Output = Option<Result<Vec<u8>, CryptoError>>;

    fn call<C: PairingCurve + 'static, H: CryptographicDigest + Default + 'static>(self) -> Self::Output {
        let cipher = self.cipher;
        SM9Registry::cipher(cipher, SM9EncryptWith::<C, H> { encrypt: self, types: PhantomData })
    }
}

/// The step of [`SM9Encrypt`] with the curve `C` and the hash function `H` chosen.
pub struct SM9EncryptWith<'a, C, H> {
    encrypt: SM9Encrypt<'a>,
    types: PhantomData<(C, H)>,
}

impl<C: PairingCurve, H: CryptographicDigest + Default> SM9CipherCall for SM9EncryptWith<'_, C, H> {
    type Output = Result<Vec<u8>, CryptoError>;

    fn call<E: SM9Cipher>(self) -> Self::Output {
        let SM9Encrypt { master, identity, hid, message, ephemeral, .. } = self.encrypt;
        let master = SM9Encoding::<C>::g1_from_bytes(master)?;
        match ephemeral {
            SM9Ephemeral::Random(mut random) => {
                SM9PKE::<C, H, E>::encrypt(&master, identity, hid, message, &mut random)
            }
            SM9Ephemeral::Given(bytes) => {
                let mut scalar = SM9Ephemeral::scalar::<C>(bytes)?;
                let ciphertext = SM9PKE::<C, H, E>::encrypt_with_ephemeral(&master, identity, hid, message, &scalar);
                scalar.zeroize();
                ciphertext
            }
        }
    }
}

/// The role of the C ABI: 0 for the initiator, 1 for the responder.
pub struct SM9Roles;

impl SM9Roles {
    pub fn role(value: u8) -> Result<SM9Role, &'static Status> {
        match value {
            0 => Ok(SM9Role::Initiator),
            1 => Ok(SM9Role::Responder),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

crate::ffi_functions! {
    /// Writes the sizes in bytes of a scalar (ke, r), a point of G_1 (x || y: Ppub-e, R, C), a point of G_2
    /// (04 || x || y: de) and an output of the hash function (C3, S_A, S_B) on the curve named by `curve` with
    /// the hash function named by `hash` into `sizes` (four elements).
    pub unsafe extern "C" fn umilib_crypto_sm9_sizes(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, sizes: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(curve, curve_length), (hash, hash_length)], &[(sizes.cast_const().cast(), 4 * core::mem::size_of::<usize>())])?;
            // SAFETY: the caller passes readable text and four writable elements.
            let (curve, hash) = (unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?);
            let values = SM9Registry::scheme(curve, hash, SM9Sizes).ok_or(&Status::INVALID_ARGUMENT)?;
            let out = unsafe { Pointer::slice_of_mut(sizes, 4) }?;
            out.copy_from_slice(&values);
            Ok(())
        })())
    }

    /// Creates the master key of ke (big-endian, 1 ≤ ke < N) on the curve named by `curve`; fails with
    /// InvalidKey otherwise.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9_encrypt_master_key_new(curve: *const u8, curve_length: usize, secret: *const u8, secret_length: usize, out: *mut *mut Box<dyn SM9MasterState>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let call = SM9MasterNew::Secret(unsafe { Pointer::slice(secret, secret_length) }?);
            let key = SM9Registry::curve(curve, call).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Creates a master key on the curve named by `curve` with ke drawn from the generator handle `random`,
    /// whose C type is named by `random_type`.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9_encrypt_master_key_generate(curve: *const u8, curve_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut Box<dyn SM9MasterState>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text, a live generator of the named type and a writable pointer.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let key = SM9Registry::curve(curve, SM9MasterNew::Random(random)).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Releases the master key, zeroizing ke. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9_encrypt_master_key_free(key: *mut Box<dyn SM9MasterState>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(key) }
    }

    /// Writes ke into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9_encrypt_master_key_secret(key: *const Box<dyn SM9MasterState>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(key.secret())) }
        })())
    }

    /// Writes Ppub-e (x || y) into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9_encrypt_master_key_public_key(key: *const Box<dyn SM9MasterState>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(key.public_key())) }
        })())
    }

    /// Creates the key of `identity` and the identifier `hid` with H1 of the hash function named by `hash`;
    /// fails with InvalidParameter if t1 = 0, when the master key must be generated again.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9_encrypt_master_key_extract(key: *const Box<dyn SM9MasterState>, hash: *const u8, hash_length: usize, identity: *const u8, identity_length: usize, hid: u8, out: *mut *mut Box<dyn SM9UserState>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and bytes and a writable pointer.
            let key = unsafe { Pointer::reference(key) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let identity = unsafe { Pointer::slice(identity, identity_length) }?;
            let user = key.extract(hash, identity, hid).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, user) }
        })())
    }

    /// Creates the key de (04 || x || y) of `identity` and `hid` under Ppub-e `master` (x || y) on the curve
    /// named by `curve`; fails with InvalidKey unless both are points of their groups other than the identity.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9_encrypt_user_key_new(curve: *const u8, curve_length: usize, identity: *const u8, identity_length: usize, hid: u8, key: *const u8, key_length: usize, master: *const u8, master_length: usize, out: *mut *mut Box<dyn SM9UserState>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let call = SM9UserNew {
                identity: unsafe { Pointer::slice(identity, identity_length) }?,
                hid,
                key: unsafe { Pointer::slice(key, key_length) }?,
                master: unsafe { Pointer::slice(master, master_length) }?,
            };
            let user = SM9Registry::curve(curve, call).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, user) }
        })())
    }

    /// Releases the key, zeroizing de. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9_encrypt_user_key_free(key: *mut Box<dyn SM9UserState>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(key) }
    }

    /// Writes the identity of the key into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9_encrypt_user_key_identity(key: *const Box<dyn SM9UserState>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(key.identity().to_vec())) }
        })())
    }

    /// The identifier hid of the key.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9_encrypt_user_key_hid(key: *const Box<dyn SM9UserState>, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable byte.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, key.hid()) }
        })())
    }

    /// Writes de (04 || x || y) into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9_encrypt_user_key_key(key: *const Box<dyn SM9UserState>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(key.key())) }
        })())
    }

    /// Writes Ppub-e (x || y) of the key into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9_encrypt_user_key_master(key: *const Box<dyn SM9UserState>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(key.master())) }
        })())
    }

    /// Creates the side of `role` for the user of `key` with the user `peer_identity`, the hash function named
    /// by `hash` and r (big-endian, 1 ≤ r < N) `ephemeral`, which must be secret, random and used once.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9kep_new(key: *const Box<dyn SM9UserState>, hash: *const u8, hash_length: usize, role: u8, peer_identity: *const u8, peer_identity_length: usize, ephemeral: *const u8, ephemeral_length: usize, out: *mut *mut Box<dyn SM9KEPState>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and bytes and a writable pointer.
            let key = unsafe { Pointer::reference(key) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let peer_identity = unsafe { Pointer::slice(peer_identity, peer_identity_length) }?;
            let ephemeral = SM9Ephemeral::Given(unsafe { Pointer::slice(ephemeral, ephemeral_length) }?);
            let side = key.exchange(hash, SM9Roles::role(role)?, peer_identity, ephemeral).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, side) }
        })())
    }

    /// Creates the side of `role` with r drawn from the generator handle `random` of the type named by
    /// `random_type`.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9kep_generate(key: *const Box<dyn SM9UserState>, hash: *const u8, hash_length: usize, role: u8, peer_identity: *const u8, peer_identity_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut Box<dyn SM9KEPState>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and bytes, a live generator of the named
            // type and a writable pointer.
            let key = unsafe { Pointer::reference(key) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let peer_identity = unsafe { Pointer::slice(peer_identity, peer_identity_length) }?;
            let random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let side = key.exchange(hash, SM9Roles::role(role)?, peer_identity, SM9Ephemeral::Random(random)).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, side) }
        })())
    }

    /// Releases the side, zeroizing r and the key. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9kep_free(side: *mut Box<dyn SM9KEPState>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(side) }
    }

    /// Writes R (x || y), which the side sends to the other, into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9kep_ephemeral_public_key(side: *const Box<dyn SM9KEPState>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let side = unsafe { Pointer::reference(side) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(side.ephemeral_public_key())) }
        })())
    }

    /// Writes SK of the other side's R (x || y) into `key_out` (klen / 8 bytes) and the confirmations S_B into
    /// `responder` and S_A into `initiator` (each of the bytes of the hash function); fails with InvalidKey
    /// unless R is a point of G_1 other than the identity.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9kep_agree(side: *const Box<dyn SM9KEPState>, peer_ephemeral: *const u8, peer_ephemeral_length: usize, key_out: *mut u8, key_out_length: usize, responder: *mut u8, responder_length: usize, initiator: *mut u8, initiator_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and writable bytes.
            let outputs = [(key_out.cast_const(), key_out_length), (responder.cast_const(), responder_length), (initiator.cast_const(), initiator_length)];
            Pointer::check_ranges(&[(peer_ephemeral, peer_ephemeral_length)], &outputs)?;
            let side = unsafe { Pointer::reference(side) }?;
            let peer_ephemeral = unsafe { Pointer::slice(peer_ephemeral, peer_ephemeral_length) }?;
            let key_out = unsafe { Pointer::slice_mut(key_out, key_out_length) }?;
            let responder = unsafe { Pointer::slice_mut(responder, responder_length) }?;
            let initiator = unsafe { Pointer::slice_mut(initiator, initiator_length) }?;
            side.agree(peer_ephemeral, key_out, responder, initiator).map_err(|error| error.to_status())
        })())
    }

    /// Writes K for `identity` and `hid` under Ppub-e `master` (x || y) into `key_out` (klen / 8 bytes, not
    /// empty) and C (x || y) into `encapsulated`, on the curve named by `curve` with the hash function named
    /// by `hash` and r drawn from the generator handle `random` of the type named by `random_type`.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9kem_encapsulate(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, master: *const u8, master_length: usize, identity: *const u8, identity_length: usize, hid: u8, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, key_out: *mut u8, key_out_length: usize, encapsulated: *mut u8, encapsulated_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes, a live generator of the named type and writable
            // bytes.
            let inputs = [(curve, curve_length), (hash, hash_length), (master, master_length), (identity, identity_length), (random_type, random_type_length)];
            Pointer::check_ranges(&inputs, &[(key_out.cast_const(), key_out_length), (encapsulated.cast_const(), encapsulated_length)])?;
            let (curve, hash) = (unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?);
            let call = SM9Encapsulate {
                master: unsafe { Pointer::slice(master, master_length) }?,
                identity: unsafe { Pointer::slice(identity, identity_length) }?,
                hid,
                ephemeral: SM9Ephemeral::Random(unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?),
                out: unsafe { Pointer::slice_mut(key_out, key_out_length) }?,
                encapsulated: unsafe { Pointer::slice_mut(encapsulated, encapsulated_length) }?,
            };
            SM9Registry::scheme(curve, hash, call).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
        })())
    }

    /// The encapsulation with r (big-endian, 1 ≤ r < N) `ephemeral`, which must be secret, random and used
    /// once; fails with InvalidParameter if K is zero, when another r is needed.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9kem_encapsulate_with_ephemeral(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, master: *const u8, master_length: usize, identity: *const u8, identity_length: usize, hid: u8, ephemeral: *const u8, ephemeral_length: usize, key_out: *mut u8, key_out_length: usize, encapsulated: *mut u8, encapsulated_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and writable bytes.
            let inputs = [(curve, curve_length), (hash, hash_length), (master, master_length), (identity, identity_length), (ephemeral, ephemeral_length)];
            Pointer::check_ranges(&inputs, &[(key_out.cast_const(), key_out_length), (encapsulated.cast_const(), encapsulated_length)])?;
            let (curve, hash) = (unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?);
            let call = SM9Encapsulate {
                master: unsafe { Pointer::slice(master, master_length) }?,
                identity: unsafe { Pointer::slice(identity, identity_length) }?,
                hid,
                ephemeral: SM9Ephemeral::Given(unsafe { Pointer::slice(ephemeral, ephemeral_length) }?),
                out: unsafe { Pointer::slice_mut(key_out, key_out_length) }?,
                encapsulated: unsafe { Pointer::slice_mut(encapsulated, encapsulated_length) }?,
            };
            SM9Registry::scheme(curve, hash, call).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
        })())
    }

    /// Writes K of C (x || y) `encapsulated` for `key` into `key_out` (klen / 8 bytes, not empty), with the
    /// hash function named by `hash`; fails with InvalidKey unless C is a point of G_1 other than the identity
    /// and with DecryptionFailed if K is zero.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9kem_decapsulate(key: *const Box<dyn SM9UserState>, hash: *const u8, hash_length: usize, encapsulated: *const u8, encapsulated_length: usize, key_out: *mut u8, key_out_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and bytes and writable bytes.
            Pointer::check_ranges(&[(hash, hash_length), (encapsulated, encapsulated_length)], &[(key_out.cast_const(), key_out_length)])?;
            let key = unsafe { Pointer::reference(key) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let encapsulated = unsafe { Pointer::slice(encapsulated, encapsulated_length) }?;
            let out = unsafe { Pointer::slice_mut(key_out, key_out_length) }?;
            key.decapsulate(hash, encapsulated, out).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
        })())
    }

    /// Writes the ciphertext C1 || C3 || C2 of `message` for `identity` and `hid` under Ppub-e `master`
    /// (x || y) into a new buffer, on the curve named by `curve` with the hash function named by `hash`, the
    /// cipher named by `cipher` (`umilib_crypto_sm9_SM9StreamCipher` or a block cipher in CBC mode) and r
    /// drawn from the generator handle `random` of the type named by `random_type`.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9pke_encrypt(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, cipher: *const u8, cipher_length: usize, master: *const u8, master_length: usize, identity: *const u8, identity_length: usize, hid: u8, message: *const u8, message_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes, a live generator of the named type and a
            // writable buffer.
            let (curve, hash) = (unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?);
            let call = SM9Encrypt {
                cipher: unsafe { Pointer::text(cipher, cipher_length) }?,
                master: unsafe { Pointer::slice(master, master_length) }?,
                identity: unsafe { Pointer::slice(identity, identity_length) }?,
                hid,
                message: unsafe { Pointer::slice(message, message_length) }?,
                ephemeral: SM9Ephemeral::Random(unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?),
            };
            let ciphertext = SM9Registry::scheme(curve, hash, call).flatten().ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(ciphertext)) }
        })())
    }

    /// The encryption with r (big-endian, 1 ≤ r < N) `ephemeral`, which must be secret, random and used once;
    /// fails with InvalidParameter if K1 is zero, when another r is needed.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9pke_encrypt_with_ephemeral(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, cipher: *const u8, cipher_length: usize, master: *const u8, master_length: usize, identity: *const u8, identity_length: usize, hid: u8, message: *const u8, message_length: usize, ephemeral: *const u8, ephemeral_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable buffer.
            let (curve, hash) = (unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?);
            let call = SM9Encrypt {
                cipher: unsafe { Pointer::text(cipher, cipher_length) }?,
                master: unsafe { Pointer::slice(master, master_length) }?,
                identity: unsafe { Pointer::slice(identity, identity_length) }?,
                hid,
                message: unsafe { Pointer::slice(message, message_length) }?,
                ephemeral: SM9Ephemeral::Given(unsafe { Pointer::slice(ephemeral, ephemeral_length) }?),
            };
            let ciphertext = SM9Registry::scheme(curve, hash, call).flatten().ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(ciphertext)) }
        })())
    }

    /// Writes the message of `ciphertext` for `key` into a new buffer, with the hash function named by `hash`
    /// and the cipher named by `cipher`; fails with DecryptionFailed for every invalid ciphertext.
    pub unsafe extern "C" fn umilib_crypto_sm9_sm9pke_decrypt(key: *const Box<dyn SM9UserState>, hash: *const u8, hash_length: usize, cipher: *const u8, cipher_length: usize, ciphertext: *const u8, ciphertext_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and bytes and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let ciphertext = unsafe { Pointer::slice(ciphertext, ciphertext_length) }?;
            let message = key.decrypt(hash, cipher, ciphertext).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(message)) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "sm9",
    definitions: &[
        Definition::Opaque {
            name: "umilib_crypto_sm9_SM9EncryptMasterKey",
            documentation: " The encryption master key of a KGC of SM9 (ke and Ppub-e), which keeps its curve.",
        },
        Definition::Opaque {
            name: "umilib_crypto_sm9_SM9EncryptUserKey",
            documentation: " The encryption key of a user of SM9 (its identity, hid, de and Ppub-e), which keeps its curve.",
        },
        Definition::Opaque {
            name: "umilib_crypto_sm9_SM9KEP",
            documentation: " One side of the key exchange of SM9 (GM/T 0044.3), which keeps its curve and hash function.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
