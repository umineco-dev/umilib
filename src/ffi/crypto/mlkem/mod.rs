//! The C ABI of [`crate::crypto::mlkem`].
//!
//! [`MLKEM<P>`](crate::crypto::mlkem::MLKEM) is exported once
//! (`umilib_crypto_mlkem_mlkem_*`) for the parameter sets named by the C type
//! names `umilib_crypto_mlkem_MLKEM512`, `umilib_crypto_mlkem_MLKEM768` and
//! `umilib_crypto_mlkem_MLKEM1024`: the functions of
//! [`KeyEncapsulation`](crate::crypto::KeyEncapsulation) on the encodings of
//! FIPS 203, `_decapsulation_key_from_seed` (the decapsulation key of the seed d || z) and
//! `_encapsulate_internal` (ML-KEM.Encaps_internal with m, for testing).

use crate::ffi::Module;

/// [`MLKEM`](crate::crypto::mlkem::MLKEM).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod mlkem {
    use crate::crypto::KeyEncapsulation;
    use crate::crypto::mlkem::{MLKEM, MLKEM512, MLKEM768, MLKEM1024, MLKEMParameters};
    use crate::ffi::crypto::KeyEncapsulationCall;
    use crate::ffi::{Pointer, Status, ToStatus};

    /// An operation on a parameter set of ML-KEM chosen at run time.
    pub trait MLKEMCall {
        type Output;

        fn call<P: MLKEMParameters>(self) -> Self::Output;
    }

    /// Calls `call` with the parameter set named `name`; `None` if it is unknown.
    pub fn parameters<V: MLKEMCall>(name: &str, call: V) -> Option<V::Output> {
        match name {
            "umilib_crypto_mlkem_MLKEM512" => Some(call.call::<MLKEM512>()),
            "umilib_crypto_mlkem_MLKEM768" => Some(call.call::<MLKEM768>()),
            "umilib_crypto_mlkem_MLKEM1024" => Some(call.call::<MLKEM1024>()),
            _ => None,
        }
    }

    /// The step of [`scheme`] from the parameter set to `MLKEM<P>`.
    pub struct MLKEMScheme<V> {
        call: V,
    }

    impl<V: KeyEncapsulationCall> MLKEMCall for MLKEMScheme<V> {
        type Output = V::Output;

        fn call<P: MLKEMParameters>(self) -> V::Output {
            self.call.call::<MLKEM<P>>()
        }
    }

    /// Calls `call` with `MLKEM<P>` for the parameter set named `names.0`; `None` if it is unknown.
    pub fn scheme<V: KeyEncapsulationCall>(names: (&str,), call: V) -> Option<V::Output> {
        parameters(names.0, MLKEMScheme { call })
    }

    crate::ffi_key_encapsulation!("umilib_crypto_mlkem_mlkem", "ML-KEM with the parameter set named by `parameters`", [parameters parameters_length]);

    /// Writes the decapsulation key of the seed d || z into `out`.
    pub struct MLKEMExpandSeed<'a> {
        pub seed: &'a [u8],
        pub out: &'a mut [u8],
    }

    impl MLKEMCall for MLKEMExpandSeed<'_> {
        type Output = Result<(), &'static Status>;

        fn call<P: MLKEMParameters>(self) -> Self::Output {
            let key = MLKEM::<P>::decapsulation_key_from_seed(self.seed).map_err(|error| error.to_status())?;
            MLKEM::<P>::write_decapsulation_key(&key, self.out).map_err(|error| error.to_status())
        }
    }

    /// ML-KEM.Encaps_internal with m.
    pub struct MLKEMEncapsulateInternal<'a> {
        pub key: &'a [u8],
        pub message: &'a [u8],
        pub ciphertext: &'a mut [u8],
        pub shared: &'a mut [u8],
    }

    impl MLKEMCall for MLKEMEncapsulateInternal<'_> {
        type Output = Result<(), &'static Status>;

        fn call<P: MLKEMParameters>(self) -> Self::Output {
            let key = MLKEM::<P>::encapsulation_key_from_bytes(self.key).map_err(|error| error.to_status())?;
            let message: &[u8; 32] = self.message.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            MLKEM::<P>::encapsulate_internal(&key, message, self.ciphertext, self.shared)
                .map_err(|error| error.to_status())
        }
    }

    crate::ffi_exports! {
        const INTERNAL;
        /// Writes the decapsulation key of the seed d || z (64 bytes, FIPS 203 section 3.3) into `out` of the
        /// size of a decapsulation key.
        pub unsafe extern "C" fn decapsulation_key_from_seed = "umilib_crypto_mlkem_mlkem_decapsulation_key_from_seed"; (parameters: *const u8, parameters_length: usize, seed: *const u8, seed_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes and writable bytes.
                Pointer::check_ranges(&[(parameters, parameters_length), (seed, seed_length)], &[(out, out_length)])?;
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let seed = unsafe { Pointer::slice(seed, seed_length) }?;
                let out = unsafe { Pointer::slice_mut(out, out_length) }?;
                self::parameters(name, MLKEMExpandSeed { seed, out }).ok_or(&Status::INVALID_ARGUMENT)?
            })())
        }

        /// ML-KEM.Encaps_internal (FIPS 203 algorithm 17) with the 32 bytes of m, for testing: the ciphertext
        /// into `ciphertext` and the shared secret into `shared`.
        pub unsafe extern "C" fn encapsulate_internal = "umilib_crypto_mlkem_mlkem_encapsulate_internal"; (parameters: *const u8, parameters_length: usize, key: *const u8, key_length: usize, message: *const u8, message_length: usize, ciphertext: *mut u8, ciphertext_length: usize, shared: *mut u8, shared_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes and writable bytes.
                let inputs = [(parameters, parameters_length), (key, key_length), (message, message_length)];
                Pointer::check_ranges(&inputs, &[(ciphertext, ciphertext_length), (shared, shared_length)])?;
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let call = MLKEMEncapsulateInternal {
                    key: unsafe { Pointer::slice(key, key_length) }?,
                    message: unsafe { Pointer::slice(message, message_length) }?,
                    ciphertext: unsafe { Pointer::slice_mut(ciphertext, ciphertext_length) }?,
                    shared: unsafe { Pointer::slice_mut(shared, shared_length) }?,
                };
                self::parameters(name, call).ok_or(&Status::INVALID_ARGUMENT)?
            })())
        }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "mlkem",
    definitions: &[],
    functions: &crate::ffi::Function::concat::<{ mlkem::FUNCTIONS.len() + mlkem::INTERNAL.len() }>(&[
        mlkem::FUNCTIONS,
        mlkem::INTERNAL,
    ]),
    modules: &[],
};
