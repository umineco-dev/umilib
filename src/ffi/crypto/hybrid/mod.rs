//! The C ABI of [`crate::crypto::hybrid`].
//!
//! [`HybridKEM<P>`](crate::crypto::hybrid::HybridKEM) is exported once
//! (`umilib_crypto_hybrid_hybrid_kem_*`) for the groups of RFC 10024 named by
//! the C type names `umilib_crypto_hybrid_X25519MLKEM768`,
//! `umilib_crypto_hybrid_SecP256r1MLKEM768` and
//! `umilib_crypto_hybrid_SecP384r1MLKEM1024`: the functions of
//! [`KeyEncapsulation`](crate::crypto::KeyEncapsulation), whose encapsulation
//! key is the client's share and whose ciphertext is the server's share.

use crate::ffi::Module;

/// [`HybridKEM`](crate::crypto::hybrid::HybridKEM).
pub mod hybrid_kem {
    use crate::crypto::hybrid::{HybridKEM, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519MLKEM768};
    use crate::ffi::crypto::KeyEncapsulationCall;
    use crate::ffi::{Pointer, Status};

    /// Calls `call` with `HybridKEM<P>` for the group named `names.0`; `None` if it is unknown.
    pub fn scheme<V: KeyEncapsulationCall>(names: (&str,), call: V) -> Option<V::Output> {
        match names.0 {
            "umilib_crypto_hybrid_X25519MLKEM768" => Some(call.call::<HybridKEM<X25519MLKEM768>>()),
            "umilib_crypto_hybrid_SecP256r1MLKEM768" => Some(call.call::<HybridKEM<SecP256r1MLKEM768>>()),
            "umilib_crypto_hybrid_SecP384r1MLKEM1024" => Some(call.call::<HybridKEM<SecP384r1MLKEM1024>>()),
            _ => None,
        }
    }

    crate::ffi_key_encapsulation!("umilib_crypto_hybrid_hybrid_kem", "the hybrid group named by `group`", [group group_length]);
}

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "hybrid", definitions: &[], functions: hybrid_kem::FUNCTIONS, modules: &[] };
