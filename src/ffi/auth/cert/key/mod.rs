//! The C ABI of [`crate::auth::cert::key`].
//!
//! Hash functions, curves and parameter sets are numbers: their indices in
//! [`HashAlgorithm::ALL`], [`NamedCurve::ALL`], [`MLDSAParameterSet::ALL`],
//! [`SLHDSAParameterSet::ALL`], [`MLKEMParameterSet::ALL`] and
//! [`PBES2Cipher::ALL`]. Signature and key algorithms are handles, made by
//! one function per kind or from the DER of an `AlgorithmIdentifier`.
//! Functions that draw random bytes take a generator of
//! [`crate::ffi::crypto::random`] (`random` and `random_type`).

use core::ffi::c_void;

use crate::auth::cert::key::{
    AlgorithmIdentifier, HashAlgorithm, KeyAlgorithm, KeyError, MLDSAParameterSet, MLKEMParameterSet, NamedCurve,
    PBES2Cipher, PBES2Config, PSSParameters, PrivateKey, PublicKey, SLHDSAParameterSet, SignatureAlgorithm,
};
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};

/// The statuses of this module, one per variant of [`KeyError`] (a crypto error keeps its own).
pub struct KeyStatus;

impl KeyStatus {
    pub const ENCODING: Status = Status::new(c"auth.cert.key", c"Encoding", c"the DER encoding is malformed");
    pub const PEM: Status = Status::new(c"auth.cert.key", c"PEM", c"the PEM text is malformed");
    pub const PEM_LABEL: Status =
        Status::new(c"auth.cert.key", c"PEMLabel", c"a PEM document of another label than expected");
    pub const UNKNOWN_ALGORITHM: Status = Status::new(c"auth.cert.key", c"UnknownAlgorithm", c"unknown algorithm");
    pub const UNSUPPORTED: Status =
        Status::new(c"auth.cert.key", c"Unsupported", c"the algorithm is not included in this build");
    pub const PARAMETERS: Status = Status::new(c"auth.cert.key", c"Parameters", c"invalid algorithm parameters");
    pub const INVALID_KEY: Status = Status::new(c"auth.cert.key", c"InvalidKey", c"invalid key");
    pub const LIMIT: Status = Status::new(c"auth.cert.key", c"Limit", c"the key is larger than the limits accept");
    pub const INCONSISTENT: Status =
        Status::new(c"auth.cert.key", c"Inconsistent", c"the parts of the key do not match");
    pub const MISMATCH: Status =
        Status::new(c"auth.cert.key", c"Mismatch", c"the algorithm cannot be used with the key");
    pub const INVALID_SIGNATURE: Status = Status::new(c"auth.cert.key", c"InvalidSignature", c"invalid signature");
    pub const DECRYPTION: Status = Status::new(c"auth.cert.key", c"Decryption", c"wrong password or corrupted data");

    /// The value of `ALL[index]`; InvalidArgument for an index past it.
    pub fn index<T: Copy>(all: &[T], index: u8) -> Result<T, &'static Status> {
        all.get(index as usize).copied().ok_or(&Status::INVALID_ARGUMENT)
    }
}

impl ToStatus for KeyError {
    fn to_status(&self) -> &'static Status {
        match *self {
            KeyError::Encoding(_) => &KeyStatus::ENCODING,
            KeyError::PEM(_) => &KeyStatus::PEM,
            KeyError::PEMLabel => &KeyStatus::PEM_LABEL,
            KeyError::UnknownAlgorithm => &KeyStatus::UNKNOWN_ALGORITHM,
            KeyError::Unsupported => &KeyStatus::UNSUPPORTED,
            KeyError::Parameters => &KeyStatus::PARAMETERS,
            KeyError::InvalidKey => &KeyStatus::INVALID_KEY,
            KeyError::Limit => &KeyStatus::LIMIT,
            KeyError::Inconsistent => &KeyStatus::INCONSISTENT,
            KeyError::Mismatch => &KeyStatus::MISMATCH,
            KeyError::InvalidSignature => &KeyStatus::INVALID_SIGNATURE,
            KeyError::Decryption => &KeyStatus::DECRYPTION,
            KeyError::Crypto(error) => error.to_status(),
        }
    }
}

/// The parameters of PBES2 as C passes them (see [`PBES2Config`]).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FFIPBES2Config {
    /// The index of the hash function of the PRF.
    pub prf: u8,
    /// The index of the cipher.
    pub cipher: u8,
    pub iterations: u32,
    pub salt_length: u32,
    pub maximum_iterations: u32,
}

impl FFIPBES2Config {
    pub fn decode(&self) -> Result<PBES2Config, &'static Status> {
        Ok(PBES2Config {
            prf: KeyStatus::index(&HashAlgorithm::ALL, self.prf)?,
            cipher: KeyStatus::index(&PBES2Cipher::ALL, self.cipher)?,
            iterations: self.iterations,
            salt_length: self.salt_length as usize,
            maximum_iterations: self.maximum_iterations,
        })
    }
}

impl Value for FFIPBES2Config {
    const TYPE: Type = Type::Named("umilib_auth_cert_key_PBES2Config");
}

impl Value for SignatureAlgorithm {
    const TYPE: Type = Type::Named("umilib_auth_cert_key_SignatureAlgorithm");
}

impl Value for KeyAlgorithm {
    const TYPE: Type = Type::Named("umilib_auth_cert_key_KeyAlgorithm");
}

impl Value for PublicKey {
    const TYPE: Type = Type::Named("umilib_auth_cert_key_PublicKey");
}

impl Value for PrivateKey {
    const TYPE: Type = Type::Named("umilib_auth_cert_key_PrivateKey");
}

crate::ffi_functions! {
    const FUNCTIONS;

    /// Writes the bytes of the digest of the hash function `hash` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_hash_algorithm_output_size(hash: u8, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            let hash = KeyStatus::index(&HashAlgorithm::ALL, hash)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, hash.output_size()) }
        })())
    }

    /// Writes the signature algorithm RSASSA-PKCS1-v1_5 with the hash function `hash` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_signature_algorithm_rsa_pkcs1v15(hash: u8, out: *mut *mut SignatureAlgorithm) -> *const Status {
        Status::from_result((|| {
            let hash = KeyStatus::index(&HashAlgorithm::ALL, hash)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, SignatureAlgorithm::RSAPKCS1v15(hash)) }
        })())
    }

    /// Writes the signature algorithm RSASSA-PSS with the hash functions `hash` and `mask_hash` (of MGF1)
    /// and a salt of `salt_length` bytes into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_signature_algorithm_rsa_pss(hash: u8, mask_hash: u8, salt_length: u32, out: *mut *mut SignatureAlgorithm) -> *const Status {
        Status::from_result((|| {
            let hash = KeyStatus::index(&HashAlgorithm::ALL, hash)?;
            let mask_hash = KeyStatus::index(&HashAlgorithm::ALL, mask_hash)?;
            let algorithm = SignatureAlgorithm::RSAPSS(PSSParameters { hash, mask_hash, salt_length });
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, algorithm) }
        })())
    }

    /// Writes the signature algorithm ECDSA with the hash function `hash` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_signature_algorithm_ecdsa(hash: u8, out: *mut *mut SignatureAlgorithm) -> *const Status {
        Status::from_result((|| {
            let hash = KeyStatus::index(&HashAlgorithm::ALL, hash)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, SignatureAlgorithm::ECDSA(hash)) }
        })())
    }

    /// Writes the signature algorithm Ed25519 into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_signature_algorithm_ed25519(out: *mut *mut SignatureAlgorithm) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, SignatureAlgorithm::Ed25519) })
    }

    /// Writes the signature algorithm Ed448 into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_signature_algorithm_ed448(out: *mut *mut SignatureAlgorithm) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, SignatureAlgorithm::Ed448) })
    }

    /// Writes the signature algorithm ML-DSA of the parameter set `set` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_signature_algorithm_mldsa(set: u8, out: *mut *mut SignatureAlgorithm) -> *const Status {
        Status::from_result((|| {
            let set = KeyStatus::index(&MLDSAParameterSet::ALL, set)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, SignatureAlgorithm::MLDSA(set)) }
        })())
    }

    /// Writes the signature algorithm SLH-DSA (pure, or HashSLH-DSA if `pre_hash`) of the parameter set `set` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_signature_algorithm_slhdsa(set: u8, pre_hash: bool, out: *mut *mut SignatureAlgorithm) -> *const Status {
        Status::from_result((|| {
            let set = KeyStatus::index(&SLHDSAParameterSet::ALL, set)?;
            let algorithm = if pre_hash { SignatureAlgorithm::HashSLHDSA(set) } else { SignatureAlgorithm::SLHDSA(set) };
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, algorithm) }
        })())
    }

    /// Writes the signature algorithm of the DER `AlgorithmIdentifier` of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_signature_algorithm_from_der(data: *const u8, length: usize, out: *mut *mut SignatureAlgorithm) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let identifier = AlgorithmIdentifier::from_der(data).map_err(|error| KeyError::from(error).to_status())?;
            let algorithm = SignatureAlgorithm::from_identifier(&identifier).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, algorithm) }
        })())
    }

    /// Writes the DER `AlgorithmIdentifier` of the signature algorithm into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_signature_algorithm_to_der(algorithm: *const SignatureAlgorithm, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let algorithm = unsafe { Pointer::reference(algorithm) }?;
            let der = algorithm.identifier().and_then(|identifier| Ok(identifier.to_der()?)).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Releases a signature algorithm. Does nothing if `algorithm` is null.
    pub unsafe extern "C" fn umilib_auth_cert_key_signature_algorithm_free(algorithm: *mut SignatureAlgorithm) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(algorithm) }
    }

    /// Writes the key algorithm `kind` into `out`: 0 RSA, 1 RSASSA-PSS (without parameters), 2 EC (on
    /// the curve `parameter`), 3 X25519, 4 X448, 5 Ed25519, 6 Ed448, 7 ML-DSA, 8 SLH-DSA, 9 HashSLH-DSA
    /// and 10 ML-KEM (of the parameter set `parameter`).
    pub unsafe extern "C" fn umilib_auth_cert_key_key_algorithm_new(kind: u8, parameter: u8, out: *mut *mut KeyAlgorithm) -> *const Status {
        Status::from_result((|| {
            let algorithm = match kind {
                0 => KeyAlgorithm::RSA,
                1 => KeyAlgorithm::RSAPSS(None),
                2 => KeyAlgorithm::EC(KeyStatus::index(&NamedCurve::ALL, parameter)?),
                3 => KeyAlgorithm::X25519,
                4 => KeyAlgorithm::X448,
                5 => KeyAlgorithm::Ed25519,
                6 => KeyAlgorithm::Ed448,
                7 => KeyAlgorithm::MLDSA(KeyStatus::index(&MLDSAParameterSet::ALL, parameter)?),
                8 => KeyAlgorithm::SLHDSA(KeyStatus::index(&SLHDSAParameterSet::ALL, parameter)?),
                9 => KeyAlgorithm::HashSLHDSA(KeyStatus::index(&SLHDSAParameterSet::ALL, parameter)?),
                10 => KeyAlgorithm::MLKEM(KeyStatus::index(&MLKEMParameterSet::ALL, parameter)?),
                _ => return Err(&Status::INVALID_ARGUMENT),
            };
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, algorithm) }
        })())
    }

    /// Writes the key algorithm RSASSA-PSS restricted to the parameters of `signature` (an RSASSA-PSS
    /// signature algorithm) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_key_algorithm_rsa_pss(signature: *const SignatureAlgorithm, out: *mut *mut KeyAlgorithm) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let SignatureAlgorithm::RSAPSS(parameters) = *unsafe { Pointer::reference(signature) }? else {
                return Err(&Status::INVALID_ARGUMENT);
            };
            unsafe { Pointer::write_handle(out, KeyAlgorithm::RSAPSS(Some(parameters))) }
        })())
    }

    /// Writes the key algorithm of the DER `AlgorithmIdentifier` of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_key_algorithm_from_der(data: *const u8, length: usize, out: *mut *mut KeyAlgorithm) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let identifier = AlgorithmIdentifier::from_der(data).map_err(|error| KeyError::from(error).to_status())?;
            let algorithm = KeyAlgorithm::from_identifier(&identifier).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, algorithm) }
        })())
    }

    /// Writes the DER `AlgorithmIdentifier` of the key algorithm into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_key_algorithm_to_der(algorithm: *const KeyAlgorithm, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let algorithm = unsafe { Pointer::reference(algorithm) }?;
            let der = algorithm.identifier().and_then(|identifier| Ok(identifier.to_der()?)).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Writes whether a key of `algorithm` makes signatures of `signature` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_key_algorithm_signs(algorithm: *const KeyAlgorithm, signature: *const SignatureAlgorithm, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let algorithm = unsafe { Pointer::reference(algorithm) }?;
            let signature = unsafe { Pointer::reference(signature) }?;
            unsafe { Pointer::write(out, algorithm.signs(signature)) }
        })())
    }

    /// Releases a key algorithm. Does nothing if `algorithm` is null.
    pub unsafe extern "C" fn umilib_auth_cert_key_key_algorithm_free(algorithm: *mut KeyAlgorithm) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(algorithm) }
    }

    /// Writes the public key of the DER `SubjectPublicKeyInfo` of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_public_key_from_der(data: *const u8, length: usize, out: *mut *mut PublicKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let key = PublicKey::from_der(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Writes the public key of the PEM text (`PUBLIC KEY`) of `length` bytes at `text` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_public_key_from_pem(text: *const u8, length: usize, out: *mut *mut PublicKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let key = PublicKey::from_pem(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Writes the DER `SubjectPublicKeyInfo` of the key into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_public_key_to_der(key: *const PublicKey, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let der = key.to_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Writes the PEM text (`PUBLIC KEY`) of the key into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_public_key_to_pem(key: *const PublicKey, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let pem = key.to_pem().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(pem.into_bytes())) }
        })())
    }

    /// Writes the bytes of the key's `subjectPublicKey` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_public_key_key(key: *const PublicKey, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(key.key().to_vec())) }
        })())
    }

    /// Writes the algorithm of the key into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_public_key_algorithm(key: *const PublicKey, out: *mut *mut KeyAlgorithm) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write_handle(out, *key.algorithm()) }
        })())
    }

    /// Succeeds if the `signature_length` bytes at `signature` are a signature of the `length` bytes at
    /// `message` with `algorithm` under the key; fails with InvalidSignature, or Mismatch if the key
    /// does not make such signatures.
    pub unsafe extern "C" fn umilib_auth_cert_key_public_key_verify(key: *const PublicKey, algorithm: *const SignatureAlgorithm, message: *const u8, length: usize, signature: *const u8, signature_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and readable bytes.
            let key = unsafe { Pointer::reference(key) }?;
            let algorithm = unsafe { Pointer::reference(algorithm) }?;
            let message = unsafe { Pointer::slice(message, length) }?;
            let signature = unsafe { Pointer::slice(signature, signature_length) }?;
            key.verify(algorithm, message, signature).map_err(|error| error.to_status())
        })())
    }

    /// Releases a public key. Does nothing if `key` is null.
    pub unsafe extern "C" fn umilib_auth_cert_key_public_key_free(key: *mut PublicKey) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(key) }
    }

    /// Writes a new key of `algorithm` (not RSA) drawn from the generator `random` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_generate(algorithm: *const KeyAlgorithm, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut PrivateKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, a generator of the named type and a writable pointer.
            let algorithm = unsafe { Pointer::reference(algorithm) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let key = PrivateKey::generate(*algorithm, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Writes a new RSA key of `bits` bits for `algorithm` (RSA or RSASSA-PSS) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_generate_rsa(algorithm: *const KeyAlgorithm, bits: u32, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut PrivateKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: as for `_generate`.
            let algorithm = unsafe { Pointer::reference(algorithm) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let key = PrivateKey::generate_rsa(*algorithm, bits, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Writes the key of the DER `OneAsymmetricKey` (PKCS #8) of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_from_pkcs8_der(data: *const u8, length: usize, out: *mut *mut PrivateKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let key = PrivateKey::from_pkcs8_der(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Writes the key of the `OneAsymmetricKey` (PKCS #8) in BER (DER included, as RFC 5958 requires
    /// receivers to accept) of `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_from_pkcs8_ber(data: *const u8, length: usize, out: *mut *mut PrivateKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let key = PrivateKey::from_pkcs8_ber(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Writes the key of the `EncryptedPrivateKeyInfo` in BER (DER included) of `length` bytes at
    /// `data`, decrypted as in `_from_encrypted_pkcs8_der`, into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_from_encrypted_pkcs8_ber(data: *const u8, length: usize, password: *const u8, password_length: usize, config: FFIPBES2Config, out: *mut *mut PrivateKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let password = unsafe { Pointer::slice(password, password_length) }?;
            let key = PrivateKey::from_encrypted_pkcs8_ber(data, password, &config.decode()?).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Writes the key of PEM text (`PRIVATE KEY`, `RSA PRIVATE KEY` or `EC PRIVATE KEY`) of `length`
    /// bytes at `text` into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_from_pem(text: *const u8, length: usize, out: *mut *mut PrivateKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let key = PrivateKey::from_pem(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Writes the key of the DER `EncryptedPrivateKeyInfo` of `length` bytes at `data`, decrypted with
    /// the `password_length` bytes at `password` and the limits of `config`, into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_from_encrypted_pkcs8_der(data: *const u8, length: usize, password: *const u8, password_length: usize, config: FFIPBES2Config, out: *mut *mut PrivateKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let password = unsafe { Pointer::slice(password, password_length) }?;
            let key = PrivateKey::from_encrypted_pkcs8_der(data, password, &config.decode()?).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Writes the key of PEM text of an `ENCRYPTED PRIVATE KEY`, decrypted as in
    /// `_from_encrypted_pkcs8_der`, into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_from_encrypted_pem(text: *const u8, length: usize, password: *const u8, password_length: usize, config: FFIPBES2Config, out: *mut *mut PrivateKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let password = unsafe { Pointer::slice(password, password_length) }?;
            let key = PrivateKey::from_encrypted_pem(text, password, &config.decode()?).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Writes the DER `OneAsymmetricKey` (PKCS #8) of the key into `out` (zeroized by `umilib_ffi_buffer_free`).
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_to_pkcs8_der(key: *const PrivateKey, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let der = key.to_pkcs8_der().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der.expose().clone())) }
        })())
    }

    /// Writes the PEM text (`PRIVATE KEY`) of the key into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_to_pem(key: *const PrivateKey, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let pem = key.to_pem().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(pem.expose().clone().into_bytes())) }
        })())
    }

    /// Writes the DER `EncryptedPrivateKeyInfo` of the key, encrypted with the `password_length` bytes
    /// at `password` and the parameters of `config` (a salt and an IV from `random`), into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_to_encrypted_pkcs8_der(key: *const PrivateKey, password: *const u8, password_length: usize, config: FFIPBES2Config, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes, a generator of the named type and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let password = unsafe { Pointer::slice(password, password_length) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let der = key.to_encrypted_pkcs8_der(password, &config.decode()?, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Writes the public key of the key into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_public_key(key: *const PrivateKey, out: *mut *mut PublicKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let key = unsafe { Pointer::reference(key) }?;
            let public = key.public_key().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, public) }
        })())
    }

    /// Writes the algorithm of the key into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_algorithm(key: *const PrivateKey, out: *mut *mut KeyAlgorithm) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write_handle(out, *key.algorithm()) }
        })())
    }

    /// Writes the signature of the `length` bytes at `message` with `algorithm` (drawing from `random`
    /// where the algorithm uses random bytes) into `out`; fails with Mismatch if the key does not make
    /// such signatures.
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_sign(key: *const PrivateKey, algorithm: *const SignatureAlgorithm, message: *const u8, length: usize, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, readable bytes, a generator of the named type and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let algorithm = unsafe { Pointer::reference(algorithm) }?;
            let message = unsafe { Pointer::slice(message, length) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let signature = key.sign(algorithm, message, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(signature)) }
        })())
    }

    /// Releases a private key, zeroizing it. Does nothing if `key` is null.
    pub unsafe extern "C" fn umilib_auth_cert_key_private_key_free(key: *mut PrivateKey) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(key) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "key",
    definitions: &[
        Definition::Opaque {
            name: "umilib_auth_cert_key_SignatureAlgorithm",
            documentation: " A signature algorithm and its parameters.",
        },
        Definition::Opaque {
            name: "umilib_auth_cert_key_KeyAlgorithm",
            documentation: " The algorithm of a key and its parameters.",
        },
        Definition::Opaque {
            name: "umilib_auth_cert_key_PublicKey",
            documentation: " A validated public key and its algorithm.",
        },
        Definition::Opaque {
            name: "umilib_auth_cert_key_PrivateKey",
            documentation: " A private key and its algorithm.",
        },
        Definition::Structure {
            name: "umilib_auth_cert_key_PBES2Config",
            documentation: " The parameters of PBES2: the indices of the PRF's hash function and of the cipher, the iterations, the salt length and the most iterations accepted when decrypting.",
            fields: &[
                Parameter { name: "prf", value: <u8 as Value>::TYPE },
                Parameter { name: "cipher", value: <u8 as Value>::TYPE },
                Parameter { name: "iterations", value: <u32 as Value>::TYPE },
                Parameter { name: "salt_length", value: <u32 as Value>::TYPE },
                Parameter { name: "maximum_iterations", value: <u32 as Value>::TYPE },
            ],
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
