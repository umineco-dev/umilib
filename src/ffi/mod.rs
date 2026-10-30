//! The C ABI of every enabled module.
//!
//! `umilib::ffi::a::b` exports the C functions of `umilib::a::b` and is
//! compiled when both `ffi` and the feature of `a::b` are enabled. The
//! [`Manifest`] describes every exported type and function; `include/` and the
//! bindings in `port/` are derived from it.
//!
//! Conventions shared by every exported function (see `docs/ffi.md`):
//! - Functions are named `umilib_<module path>_<type>_<method>` in
//!   `snake_case`; C types are named `umilib_<module path>_<RustType>`, keeping
//!   the Rust spelling, so a type never collides with a function.
//! - Fallible functions return `const umilib_ffi_Status*`, null on success,
//!   and write results through `out` pointers only on success.
//! - Byte input is a `(const uint8_t* data, size_t length)` pair and text is
//!   UTF-8 in the same form; neither needs to outlive the call unless stated.
//! - Byte output is an [`Buffer`] released with `umilib_ffi_buffer_free`.
//! - Objects are opaque handles created by `*_new` and released by `*_free`.
//! - Pointers must be valid for the access the function performs; this is the
//!   safety contract of every `unsafe` function in this module tree.

#![allow(clippy::missing_safety_doc)]

mod buffer;
mod c_header;
mod functions;
mod integer;
mod manifest;
mod module;
mod pointer;
mod status;
mod value;

pub use buffer::Buffer;
pub use c_header::CHeader;
pub use integer::{Char, I128, U128};
pub use manifest::{Manifest, umilib_version};
pub use module::{Definition, Function, Module, Parameter};
pub use pointer::Pointer;
pub use status::{Status, ToStatus};
pub use value::{Type, Value};

#[cfg(umilib_feature = "auth")]
pub mod auth;
#[cfg(umilib_feature = "bytes")]
pub mod bytes;
#[cfg(umilib_feature = "calendar")]
pub mod calendar;
#[cfg(umilib_feature = "codec")]
pub mod codec;
#[cfg(umilib_feature = "crypto")]
pub mod crypto;
#[cfg(any(umilib_feature = "hash", umilib_feature = "crypto-hmac"))]
pub mod hash;
#[cfg(umilib_feature = "math")]
pub mod math;
#[cfg(umilib_feature = "platform")]
pub mod platform;
#[cfg(umilib_feature = "protocol")]
pub mod protocol;
#[cfg(umilib_feature = "runtime")]
pub mod runtime;
#[cfg(umilib_feature = "secret")]
pub mod secret;
#[cfg(umilib_feature = "service")]
pub mod service;

impl Value for Char {
    const TYPE: Type = Type::Char;
}

impl Value for Status {
    const TYPE: Type = Type::Named("umilib_ffi_Status");
}

impl Value for Buffer {
    const TYPE: Type = Type::Named("umilib_ffi_Buffer");
}

impl Value for U128 {
    const TYPE: Type = Type::Named("umilib_ffi_U128");
}

impl Value for I128 {
    const TYPE: Type = Type::Named("umilib_ffi_I128");
}

crate::ffi_functions! {
    /// Overwrites the bytes owned by `buffer` with zeros, releases them and resets it to empty.
    /// Does nothing if `buffer` is null or already empty.
    pub unsafe extern "C" fn umilib_ffi_buffer_free(buffer: *mut Buffer) {
        // SAFETY: the caller passes null or a buffer filled by umilib.
        if let Ok(buffer) = unsafe { Pointer::reference_mut(buffer) } {
            // SAFETY: the caller does not modify the fields of a buffer.
            unsafe { buffer.release() };
        }
    }

    /// Writes the manifest of this build, as UTF-8 JSON, into `out`.
    pub unsafe extern "C" fn umilib_ffi_manifest(out: *mut Buffer) -> *const Status {
        let json = Manifest::json(&Manifest::ROOT);
        // SAFETY: the caller passes a writable `umilib_ffi_Buffer`.
        Status::from_result(unsafe { Pointer::write(out, Buffer::from_vec(json.into_bytes())) })
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ffi",
    definitions: &[
        Definition::Structure {
            name: "umilib_ffi_Status",
            documentation: " The error returned by a fallible function; success is a null pointer.\n \
                            Every string is static and NUL-terminated.",
            fields: &[
                Parameter { name: "domain", value: <*const Char as Value>::TYPE },
                Parameter { name: "name", value: <*const Char as Value>::TYPE },
                Parameter { name: "message", value: <*const Char as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_ffi_Buffer",
            documentation: " Bytes owned by umilib; release them with umilib_ffi_buffer_free, which\n \
                            overwrites them with zeros. Do not modify the fields.",
            fields: &[
                Parameter { name: "data", value: <*mut u8 as Value>::TYPE },
                Parameter { name: "length", value: Type::USize },
                Parameter { name: "capacity", value: Type::USize },
            ],
        },
        Definition::Structure {
            name: "umilib_ffi_U128",
            documentation: " An unsigned 128-bit integer: (high << 64) | low.",
            fields: &[Parameter { name: "high", value: Type::U64 }, Parameter { name: "low", value: Type::U64 }],
        },
        Definition::Structure {
            name: "umilib_ffi_I128",
            documentation: " A signed 128-bit integer in two's complement: (high << 64) | low.",
            fields: &[Parameter { name: "high", value: Type::I64 }, Parameter { name: "low", value: Type::U64 }],
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
