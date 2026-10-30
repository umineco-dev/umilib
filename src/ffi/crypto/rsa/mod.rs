//! The C ABI of [`crate::crypto::rsa`].
//!
//! [`RSAPublicKey`] and [`RSAPrivateKey`] are opaque handles; integers are
//! big-endian bytes. The schemes take the hash function by the C type name
//! of its type, among those of
//! [`ffi_standard_digests!`](crate::ffi_standard_digests), and PSS and OAEP
//! the hash function of MGF1 by name too: the same one, or SHA-1. The
//! private operations take a generator handle `random` of the type named by
//! `random_type` for their blinding (and salts and seeds).

use alloc::vec::Vec;

use crate::crypto::CryptoError;
use crate::crypto::rsa::{PKCS1Digest, RSAOAEP, RSAPKCS1v15, RSAPSS, RSAPrivateKey, RSAPublicKey};
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::math::bigint::BigEndianInteger;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for RSAPublicKey {
    const TYPE: Type = Type::Named("umilib_crypto_rsa_RSAPublicKey");
}

impl Value for RSAPrivateKey {
    const TYPE: Type = Type::Named("umilib_crypto_rsa_RSAPrivateKey");
}

/// An operation of the C ABI generic over the hash function `H` and the
/// hash function `G` of MGF1.
pub trait RSACall {
    type Output;

    fn call<H: PKCS1Digest, G: PKCS1Digest>(self) -> Self::Output;
}

/// The choice of the hash functions by their names.
pub struct RSADigests;

/// Defines [`RSADigests::dispatch`] over the hash functions of the registry.
macro_rules! rsa_digests {
    ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
        // The registry may enable no hash function, leaving the arguments unused.
        #[allow(unused_variables)]
        impl RSADigests {
            /// Calls `call` with the hash function named `hash` and that of MGF1 named `mgf` (the same
            /// name or SHA-1); fails with InvalidArgument for other names.
            pub fn dispatch<V: RSACall>(hash: &str, mgf: &str, call: V) -> Result<V::Output, &'static Status> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => RSADigests::with_mgf::<$type, V>(hash, mgf, call),
                    )*
                    _ => Err(&Status::INVALID_ARGUMENT),
                }
            }
        }
    };
}

crate::ffi_standard_digests!(rsa_digests);

impl RSADigests {
    /// Calls `call` with `H` and the hash function of MGF1, `H` itself or SHA-1.
    pub fn with_mgf<H: PKCS1Digest, V: RSACall>(hash: &str, mgf: &str, call: V) -> Result<V::Output, &'static Status> {
        if mgf == hash {
            return Ok(call.call::<H, H>());
        }
        #[cfg(umilib_feature = "hash-sha-v1")]
        if mgf == "umilib_hash_sha_v1_SHA1" {
            return Ok(call.call::<H, crate::hash::sha::v1::SHA1>());
        }
        Err(&Status::INVALID_ARGUMENT)
    }
}

/// RSASSA-PKCS1-v1_5 and RSASSA-PSS signing into `out`.
pub struct RSASign<'a> {
    pub key: &'a RSAPrivateKey,
    pub message: &'a [u8],
    pub random: RandomSource<'a>,
    /// `None` for PKCS #1 v1.5, the salt length for PSS.
    pub salt: Option<usize>,
    pub out: &'a mut [u8],
}

impl RSACall for RSASign<'_> {
    type Output = Result<(), CryptoError>;

    fn call<H: PKCS1Digest, G: PKCS1Digest>(mut self) -> Result<(), CryptoError> {
        let signature = match self.salt {
            None => RSAPKCS1v15::<H>::sign(self.key, self.message, &mut self.random)?,
            Some(salt) => RSAPSS::<H, G>::sign(self.key, self.message, salt, &mut self.random)?,
        };
        if self.out.len() != signature.len() {
            return Err(CryptoError::InputLength { length: self.out.len() });
        }
        self.out.copy_from_slice(&signature);
        Ok(())
    }
}

/// RSASSA-PKCS1-v1_5 and RSASSA-PSS verification.
pub struct RSAVerify<'a> {
    pub key: &'a RSAPublicKey,
    pub message: &'a [u8],
    pub signature: &'a [u8],
    pub salt: Option<usize>,
}

impl RSACall for RSAVerify<'_> {
    type Output = Result<(), CryptoError>;

    fn call<H: PKCS1Digest, G: PKCS1Digest>(self) -> Result<(), CryptoError> {
        match self.salt {
            None => RSAPKCS1v15::<H>::verify(self.key, self.message, self.signature),
            Some(salt) => RSAPSS::<H, G>::verify(self.key, self.message, self.signature, salt),
        }
    }
}

/// RSAES-OAEP encryption into `out`.
pub struct RSAEncrypt<'a> {
    pub key: &'a RSAPublicKey,
    pub message: &'a [u8],
    pub label: &'a [u8],
    pub random: RandomSource<'a>,
    pub out: &'a mut [u8],
}

impl RSACall for RSAEncrypt<'_> {
    type Output = Result<(), CryptoError>;

    fn call<H: PKCS1Digest, G: PKCS1Digest>(mut self) -> Result<(), CryptoError> {
        let ciphertext = RSAOAEP::<H, G>::encrypt(self.key, self.message, self.label, &mut self.random)?;
        if self.out.len() != ciphertext.len() {
            return Err(CryptoError::InputLength { length: self.out.len() });
        }
        self.out.copy_from_slice(&ciphertext);
        Ok(())
    }
}

/// RSAES-OAEP decryption.
pub struct RSADecrypt<'a> {
    pub key: &'a RSAPrivateKey,
    pub ciphertext: &'a [u8],
    pub label: &'a [u8],
    pub random: RandomSource<'a>,
}

impl RSACall for RSADecrypt<'_> {
    type Output = Result<Vec<u8>, CryptoError>;

    fn call<H: PKCS1Digest, G: PKCS1Digest>(mut self) -> Result<Vec<u8>, CryptoError> {
        RSAOAEP::<H, G>::decrypt(self.key, self.ciphertext, self.label, &mut self.random)
    }
}

crate::ffi_functions! {
    /// Creates the public key (n, e) of the big-endian integers; fails with InvalidKey unless n is odd and
    /// e odd with 3 ≤ e < n.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_public_key_new(n: *const u8, n_length: usize, e: *const u8, e_length: usize, out: *mut *mut RSAPublicKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let n = BigEndianInteger::integer(unsafe { Pointer::slice(n, n_length) }?)?;
            let e = BigEndianInteger::integer(unsafe { Pointer::slice(e, e_length) }?)?;
            let key = RSAPublicKey::new(&n, &e).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Releases the public key. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_public_key_free(key: *mut RSAPublicKey) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(key) }
    }

    /// The bytes of n: the length of signatures and ciphertexts.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_public_key_size(key: *const RSAPublicKey, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable element.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, key.size()) }
        })())
    }

    /// Writes n big-endian without leading zeros into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_public_key_n(key: *const RSAPublicKey, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(BigEndianInteger::bytes(key.n()))) }
        })())
    }

    /// Writes e big-endian without leading zeros into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_public_key_e(key: *const RSAPublicKey, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(BigEndianInteger::bytes(key.e()))) }
        })())
    }

    /// Creates the private key of the big-endian n, e and d, without its primes; fails with InvalidKey
    /// unless d inverts e.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_private_key_new(n: *const u8, n_length: usize, e: *const u8, e_length: usize, d: *const u8, d_length: usize, out: *mut *mut RSAPrivateKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let n = BigEndianInteger::integer(unsafe { Pointer::slice(n, n_length) }?)?;
            let e = BigEndianInteger::integer(unsafe { Pointer::slice(e, e_length) }?)?;
            let mut d = BigEndianInteger::integer(unsafe { Pointer::slice(d, d_length) }?)?;
            let public = RSAPublicKey::new(&n, &e).map_err(|error| error.to_status())?;
            let key = RSAPrivateKey::new(public, &d).map_err(|error| error.to_status());
            crate::secret::Zeroize::zeroize(&mut d);
            unsafe { Pointer::write_handle(out, key?) }
        })())
    }

    /// Creates the private key of the primes p and q and the public exponent e, with d = e^-1 mod
    /// lcm(p - 1, q - 1).
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_private_key_from_primes(p: *const u8, p_length: usize, q: *const u8, q_length: usize, e: *const u8, e_length: usize, out: *mut *mut RSAPrivateKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let mut p = BigEndianInteger::integer(unsafe { Pointer::slice(p, p_length) }?)?;
            let mut q = BigEndianInteger::integer(unsafe { Pointer::slice(q, q_length) }?)?;
            let e = BigEndianInteger::integer(unsafe { Pointer::slice(e, e_length) }?)?;
            let key = RSAPrivateKey::from_primes(&p, &q, &e).map_err(|error| error.to_status());
            crate::secret::Zeroize::zeroize(&mut p);
            crate::secret::Zeroize::zeroize(&mut q);
            unsafe { Pointer::write_handle(out, key?) }
        })())
    }

    /// Generates a private key of `bits` bits (at least 2048, even) with the public exponent e (odd,
    /// 2^16 < e < 2^256), from the generator handle `random` of the type named by `random_type`.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_private_key_generate(bits: u32, e: *const u8, e_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut RSAPrivateKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes, a live generator of the named type and a writable pointer.
            let e = BigEndianInteger::integer(unsafe { Pointer::slice(e, e_length) }?)?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let key = RSAPrivateKey::generate(bits, &e, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Releases the private key, zeroizing it. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_private_key_free(key: *mut RSAPrivateKey) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(key) }
    }

    /// Writes the private exponent d big-endian, without leading zeros, into a new buffer, which zeroizes it
    /// when it is released.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_private_key_d(key: *const RSAPrivateKey, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(BigEndianInteger::bytes(key.d()))) }
        })())
    }

    /// Creates a copy of the public key of the private key.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_private_key_public_key(key: *const RSAPrivateKey, out: *mut *mut RSAPublicKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write_handle(out, key.public_key().clone()) }
        })())
    }

    /// Writes the RSASSA-PKCS1-v1_5 signature of the message with the hash function named by `hash` into
    /// `out` of the size of the key.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_pkcs1v15_sign(key: *const RSAPrivateKey, hash: *const u8, hash_length: usize, message: *const u8, message_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(hash, hash_length), (message, message_length), (random_type, random_type_length)], &[(out.cast_const(), out_length)])?;
            // SAFETY: the caller passes a valid handle, readable text and bytes, a live generator and writable bytes.
            let key = unsafe { Pointer::reference(key) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let message = unsafe { Pointer::slice(message, message_length) }?;
            let random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            RSADigests::dispatch(hash, hash, RSASign { key, message, random, salt: None, out })?.map_err(|error| error.to_status())
        })())
    }

    /// Succeeds if the signature is the RSASSA-PKCS1-v1_5 signature of the message with the hash function
    /// named by `hash`; fails with InvalidSignature otherwise.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_pkcs1v15_verify(key: *const RSAPublicKey, hash: *const u8, hash_length: usize, message: *const u8, message_length: usize, signature: *const u8, signature_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text and bytes.
            let key = unsafe { Pointer::reference(key) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let message = unsafe { Pointer::slice(message, message_length) }?;
            let signature = unsafe { Pointer::slice(signature, signature_length) }?;
            RSADigests::dispatch(hash, hash, RSAVerify { key, message, signature, salt: None })?.map_err(|error| error.to_status())
        })())
    }

    /// Writes the RSASSA-PSS signature of the message with the hash functions named by `hash` and `mgf` and
    /// a random salt of `salt_length` bytes into `out` of the size of the key.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_pss_sign(key: *const RSAPrivateKey, hash: *const u8, hash_length: usize, mgf: *const u8, mgf_length: usize, salt_length: usize, message: *const u8, message_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(hash, hash_length), (mgf, mgf_length), (message, message_length), (random_type, random_type_length)], &[(out.cast_const(), out_length)])?;
            // SAFETY: the caller passes a valid handle, readable text and bytes, a live generator and writable bytes.
            let key = unsafe { Pointer::reference(key) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let mgf = unsafe { Pointer::text(mgf, mgf_length) }?;
            let message = unsafe { Pointer::slice(message, message_length) }?;
            let random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            RSADigests::dispatch(hash, mgf, RSASign { key, message, random, salt: Some(salt_length), out })?.map_err(|error| error.to_status())
        })())
    }

    /// Succeeds if the signature is an RSASSA-PSS signature of the message with the hash functions named by
    /// `hash` and `mgf` and a salt of `salt_length` bytes; fails with InvalidSignature otherwise.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_pss_verify(key: *const RSAPublicKey, hash: *const u8, hash_length: usize, mgf: *const u8, mgf_length: usize, salt_length: usize, message: *const u8, message_length: usize, signature: *const u8, signature_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text and bytes.
            let key = unsafe { Pointer::reference(key) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let mgf = unsafe { Pointer::text(mgf, mgf_length) }?;
            let message = unsafe { Pointer::slice(message, message_length) }?;
            let signature = unsafe { Pointer::slice(signature, signature_length) }?;
            RSADigests::dispatch(hash, mgf, RSAVerify { key, message, signature, salt: Some(salt_length) })?.map_err(|error| error.to_status())
        })())
    }

    /// Writes the RSAES-OAEP encryption of the message with the label and the hash functions named by
    /// `hash` and `mgf` into `out` of the size of the key; fails with InputLength for a message too long.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_oaep_encrypt(key: *const RSAPublicKey, hash: *const u8, hash_length: usize, mgf: *const u8, mgf_length: usize, label: *const u8, label_length: usize, message: *const u8, message_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(hash, hash_length), (mgf, mgf_length), (label, label_length), (message, message_length), (random_type, random_type_length)], &[(out.cast_const(), out_length)])?;
            // SAFETY: the caller passes a valid handle, readable text and bytes, a live generator and writable bytes.
            let key = unsafe { Pointer::reference(key) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let mgf = unsafe { Pointer::text(mgf, mgf_length) }?;
            let label = unsafe { Pointer::slice(label, label_length) }?;
            let message = unsafe { Pointer::slice(message, message_length) }?;
            let random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            RSADigests::dispatch(hash, mgf, RSAEncrypt { key, message, label, random, out })?.map_err(|error| error.to_status())
        })())
    }

    /// Writes the message of the RSAES-OAEP ciphertext with the label and the hash functions named by `hash`
    /// and `mgf` into a new buffer; fails with DecryptionFailed alike for every invalid ciphertext.
    pub unsafe extern "C" fn umilib_crypto_rsa_rsa_oaep_decrypt(key: *const RSAPrivateKey, hash: *const u8, hash_length: usize, mgf: *const u8, mgf_length: usize, label: *const u8, label_length: usize, ciphertext: *const u8, ciphertext_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and bytes, a live generator and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let mgf = unsafe { Pointer::text(mgf, mgf_length) }?;
            let label = unsafe { Pointer::slice(label, label_length) }?;
            let ciphertext = unsafe { Pointer::slice(ciphertext, ciphertext_length) }?;
            let random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let message = RSADigests::dispatch(hash, mgf, RSADecrypt { key, ciphertext, label, random })?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(message)) }
        })())
    }
}

/// The PKCS #1 DER encodings of the keys.
#[cfg(umilib_feature = "codec-asn1-der")]
pub mod pkcs1 {
    use super::{RSAPrivateKey, RSAPublicKey};
    use crate::ffi::{Buffer, Pointer, Status, ToStatus};

    crate::ffi_functions! {
        /// Creates the public key of the PKCS #1 `RSAPublicKey` in DER.
        pub unsafe extern "C" fn umilib_crypto_rsa_rsa_public_key_from_pkcs1_der(der: *const u8, der_length: usize, out: *mut *mut RSAPublicKey) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable bytes and a writable pointer.
                let key = RSAPublicKey::from_pkcs1_der(unsafe { Pointer::slice(der, der_length) }?).map_err(|error| error.to_status())?;
                unsafe { Pointer::write_handle(out, key) }
            })())
        }

        /// Writes the PKCS #1 `RSAPublicKey` in DER into a new buffer.
        pub unsafe extern "C" fn umilib_crypto_rsa_rsa_public_key_to_pkcs1_der(key: *const RSAPublicKey, out: *mut Buffer) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes a valid handle and a writable buffer.
                let key = unsafe { Pointer::reference(key) }?;
                unsafe { Pointer::write(out, Buffer::from_vec(key.to_pkcs1_der())) }
            })())
        }

        /// Creates the private key of the PKCS #1 `RSAPrivateKey` (version 0) in DER.
        pub unsafe extern "C" fn umilib_crypto_rsa_rsa_private_key_from_pkcs1_der(der: *const u8, der_length: usize, out: *mut *mut RSAPrivateKey) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable bytes and a writable pointer.
                let key = RSAPrivateKey::from_pkcs1_der(unsafe { Pointer::slice(der, der_length) }?).map_err(|error| error.to_status())?;
                unsafe { Pointer::write_handle(out, key) }
            })())
        }

        /// Writes the PKCS #1 `RSAPrivateKey` in DER into a new buffer; fails with InvalidKey for a key
        /// without its primes.
        pub unsafe extern "C" fn umilib_crypto_rsa_rsa_private_key_to_pkcs1_der(key: *const RSAPrivateKey, out: *mut Buffer) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes a valid handle and a writable buffer.
                let key = unsafe { Pointer::reference(key) }?;
                let der = key.to_pkcs1_der().map_err(|error| error.to_status())?;
                unsafe { Pointer::write(out, Buffer::from_vec(der)) }
            })())
        }
    }
}

#[cfg(umilib_feature = "codec-asn1-der")]
const ENCODINGS: &[crate::ffi::Function] = pkcs1::FUNCTIONS;
#[cfg(not(umilib_feature = "codec-asn1-der"))]
const ENCODINGS: &[crate::ffi::Function] = &[];

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "rsa",
    definitions: &[
        Definition::Opaque {
            name: "umilib_crypto_rsa_RSAPublicKey",
            documentation: " An RSA public key (n, e) of RFC 8017 section 3.1.",
        },
        Definition::Opaque {
            name: "umilib_crypto_rsa_RSAPrivateKey",
            documentation: " An RSA private key of RFC 8017 section 3.2, with its primes when they are known.",
        },
    ],
    functions: &crate::ffi::Function::concat::<{ FUNCTIONS.len() + ENCODINGS.len() }>(&[FUNCTIONS, ENCODINGS]),
    modules: &[],
};
