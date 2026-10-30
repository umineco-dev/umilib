//! The C ABI of [`crate::crypto::scrypt`].

use crate::crypto::scrypt::Scrypt;
use crate::ffi::{Definition, Module, Pointer, Status, ToStatus, Type, U128, Value};

impl Value for Scrypt {
    const TYPE: Type = Type::Named("umilib_crypto_scrypt_Scrypt");
}

crate::ffi_functions! {
    /// Creates scrypt with the cost N (a power of two above 1, below 2^(16r)), the block size r and the
    /// parallelization p (r × p < 2^30); fails with InvalidParameter otherwise.
    pub unsafe extern "C" fn umilib_crypto_scrypt_scrypt_new(n: u64, r: u32, p: u32, out: *mut *mut Scrypt) -> *const Status {
        Status::from_result((|| {
            let scrypt = Scrypt::new(n, r, p).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, scrypt) }
        })())
    }

    /// Releases the parameters. Does nothing if `scrypt` is null.
    pub unsafe extern "C" fn umilib_crypto_scrypt_scrypt_free(scrypt: *mut Scrypt) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(scrypt) }
    }

    /// Writes a copy of `scrypt` into `out`.
    pub unsafe extern "C" fn umilib_crypto_scrypt_scrypt_clone(scrypt: *const Scrypt, out: *mut *mut Scrypt) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let scrypt = unsafe { Pointer::reference(scrypt) }?;
            unsafe { Pointer::write_handle(out, *scrypt) }
        })())
    }

    /// Writes N into `out`.
    pub unsafe extern "C" fn umilib_crypto_scrypt_scrypt_n(scrypt: *const Scrypt, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let scrypt = unsafe { Pointer::reference(scrypt) }?;
            unsafe { Pointer::write(out, scrypt.n()) }
        })())
    }

    /// Writes r into `out`.
    pub unsafe extern "C" fn umilib_crypto_scrypt_scrypt_r(scrypt: *const Scrypt, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let scrypt = unsafe { Pointer::reference(scrypt) }?;
            unsafe { Pointer::write(out, scrypt.r()) }
        })())
    }

    /// Writes p into `out`.
    pub unsafe extern "C" fn umilib_crypto_scrypt_scrypt_p(scrypt: *const Scrypt, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let scrypt = unsafe { Pointer::reference(scrypt) }?;
            unsafe { Pointer::write(out, scrypt.p()) }
        })())
    }

    /// Writes the bytes of memory a derivation allocates, 128 × r × (N + p), into `out`; a caller should
    /// bound it before deriving with parameters it did not choose.
    pub unsafe extern "C" fn umilib_crypto_scrypt_scrypt_memory(scrypt: *const Scrypt, out: *mut U128) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let scrypt = unsafe { Pointer::reference(scrypt) }?;
            unsafe { Pointer::write(out, U128::from(scrypt.memory())) }
        })())
    }

    /// Fills the `length` bytes at `out` with scrypt (RFC 7914) of the password and the salt, which must
    /// not overlap `out`; fails with Allocation if the memory cannot be allocated.
    pub unsafe extern "C" fn umilib_crypto_scrypt_scrypt_derive(scrypt: *const Scrypt, password: *const u8, password_length: usize, salt: *const u8, salt_length: usize, out: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(password, password_length, out, length)?;
            Pointer::check_disjoint(salt, salt_length, out, length)?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable byte range.
            let scrypt = unsafe { Pointer::reference(scrypt) }?;
            let password = unsafe { Pointer::slice(password, password_length) }?;
            let salt = unsafe { Pointer::slice(salt, salt_length) }?;
            let out = unsafe { Pointer::slice_mut(out, length) }?;
            scrypt.derive(password, salt, out).map_err(|error| error.to_status())
        })())
    }

    /// Applies the Salsa20/8 core (RFC 7914 section 3) to the 16 little-endian words at `block`.
    pub unsafe extern "C" fn umilib_crypto_scrypt_scrypt_salsa20_8(block: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes 16 writable words.
            let block: &mut [u32; 16] = unsafe { Pointer::slice_of_mut(block, 16) }?.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            Scrypt::salsa20_8(block);
            Ok(())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "scrypt",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_scrypt_Scrypt",
        documentation: " The parameters N, r and p of scrypt (RFC 7914), checked when they are created.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
