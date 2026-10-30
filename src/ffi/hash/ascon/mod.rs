//! The C ABI of [`crate::hash::ascon`].

use crate::ffi::{Module, Pointer, Status, ToStatus};
use crate::hash::ascon::{AsconCXOF128, AsconPermutation};

/// [`AsconHash256`](crate::hash::ascon::AsconHash256).
pub mod ascon_hash256 {
    crate::ffi_digest!(default crate::hash::ascon::AsconHash256, "umilib_hash_ascon_ascon_hash256", "umilib_hash_ascon_AsconHash256", "Ascon-Hash256 (SP 800-232).");
}

/// [`AsconReader`](crate::hash::ascon::AsconReader), the reader of Ascon-XOF128 and Ascon-CXOF128.
pub mod ascon_reader {
    crate::ffi_xof_reader!(
        crate::hash::ascon::AsconReader,
        "umilib_hash_ascon_ascon_reader",
        "umilib_hash_ascon_AsconReader",
        "The output of Ascon-XOF128 or Ascon-CXOF128."
    );
}

/// [`AsconXOF128`](crate::hash::ascon::AsconXOF128).
pub mod ascon_xof128 {
    crate::ffi_extendable_output!(default crate::hash::ascon::AsconXOF128, "umilib_hash_ascon_ascon_xof128", "umilib_hash_ascon_AsconXOF128", "Ascon-XOF128 (SP 800-232).");
}

/// [`AsconCXOF128`].
pub mod ascon_cxof128 {
    use super::{AsconCXOF128, Pointer, Status, ToStatus};

    crate::ffi_extendable_output!(keyed crate::hash::ascon::AsconCXOF128, "umilib_hash_ascon_ascon_cxof128", "umilib_hash_ascon_AsconCXOF128", "Ascon-CXOF128 (SP 800-232): Ascon-XOF128 with a customization string.");

    crate::ffi_functions! {
        const CONSTRUCTORS;
        /// Creates Ascon-CXOF128 with the customization string of `length` bytes (at most 256) at
        /// `customization`; fails with InvalidParameter if it is longer.
        pub unsafe extern "C" fn umilib_hash_ascon_ascon_cxof128_new(customization: *const u8, length: usize, out: *mut *mut AsconCXOF128) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable bytes and a writable pointer.
                let customization = unsafe { Pointer::slice(customization, length) }?;
                let state = AsconCXOF128::new(customization).map_err(|error| error.to_status())?;
                unsafe { Pointer::write_handle(out, state) }
            })())
        }
    }

    /// The functions exported by this module, in declaration order.
    pub const FUNCTIONS: &[crate::ffi::Function] =
        &crate::ffi::Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() }>(&[CONSTRUCTORS, COMMON]);
}

crate::ffi_functions! {
    const PERMUTATION;
    /// Applies Ascon-p\[`rounds`\] (1 to 16 rounds) to the 5 words at `state` (S0 to S4); fails with
    /// InvalidArgument for another number of rounds.
    pub unsafe extern "C" fn umilib_hash_ascon_ascon_permutation_permute(state: *mut u64, rounds: usize) -> *const Status {
        Status::from_result((|| {
            if !(1..=AsconPermutation::MAXIMUM_ROUNDS).contains(&rounds) {
                return Err(&Status::INVALID_ARGUMENT);
            }
            // SAFETY: the caller passes 5 writable words.
            let words: &mut [u64; 5] = unsafe { Pointer::slice_of_mut(state, 5) }?.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            let mut permutation = AsconPermutation::from_words(*words);
            permutation.permute(rounds);
            *words = *permutation.words();
            Ok(())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ascon",
    definitions: &[
        ascon_hash256::DEFINITION,
        ascon_reader::DEFINITION,
        ascon_xof128::DEFINITION,
        ascon_cxof128::DEFINITION,
    ],
    functions: &crate::ffi::Function::concat::<
        {
            ascon_hash256::FUNCTIONS.len()
                + ascon_reader::FUNCTIONS.len()
                + ascon_xof128::FUNCTIONS.len()
                + ascon_cxof128::FUNCTIONS.len()
                + PERMUTATION.len()
        },
    >(&[
        ascon_hash256::FUNCTIONS,
        ascon_reader::FUNCTIONS,
        ascon_xof128::FUNCTIONS,
        ascon_cxof128::FUNCTIONS,
        PERMUTATION,
    ]),
    modules: &[],
};
