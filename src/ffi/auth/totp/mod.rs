//! The C ABI of [`crate::auth::totp`].
//!
//! [`HOTP<H>`](crate::auth::totp::HOTP) and [`TOTP<H>`](crate::auth::totp::TOTP)
//! are exported as one type each for every hash function of
//! [`ffi_digest_algorithms!`](crate::ffi_digest_algorithms), chosen by the C
//! type name of the hash type when they are created.

use crate::auth::totp::{OTPCode, OTPError, TOTPConfig};
use crate::ffi::{Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};

/// The statuses of this module.
pub struct TOTPStatus;

impl TOTPStatus {
    pub const KEY_TOO_SHORT: Status = Status::new(c"auth.totp", c"KeyTooShort", c"the key is shorter than 128 bits");
    pub const DIGITS: Status = Status::new(c"auth.totp", c"Digits", c"a password has 6 to 10 digits");
    pub const PERIOD: Status = Status::new(c"auth.totp", c"Period", c"the time step is zero seconds");
    pub const TIME: Status = Status::new(c"auth.totp", c"Time", c"the time is before the origin of the time steps");
    pub const HASH: Status = Status::new(c"auth.totp", c"Hash", c"the hash function's output is shorter than 19 bytes");
}

impl ToStatus for OTPError {
    fn to_status(&self) -> &'static Status {
        match *self {
            OTPError::KeyTooShort => &TOTPStatus::KEY_TOO_SHORT,
            OTPError::Digits => &TOTPStatus::DIGITS,
            OTPError::Period => &TOTPStatus::PERIOD,
            OTPError::Time => &TOTPStatus::TIME,
            OTPError::Hash => &TOTPStatus::HASH,
        }
    }
}

/// The parameters of a TOTP generator, as C passes them.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FFITOTPConfig {
    pub digits: u32,
    pub period: u64,
    pub origin: u64,
}

impl From<FFITOTPConfig> for TOTPConfig {
    fn from(config: FFITOTPConfig) -> TOTPConfig {
        TOTPConfig { digits: config.digits, period: config.period, origin: config.origin }
    }
}

impl Value for FFITOTPConfig {
    const TYPE: Type = Type::Named("umilib_auth_totp_TOTPConfig");
}

/// Defines [`HOTPState`] and [`TOTPState`] over the hash functions of the registry.
macro_rules! otp_states {
    ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
        /// [`HOTP<H>`](crate::auth::totp::HOTP) for any hash function `H` of the registry.
        #[derive(Clone, Debug)]
        // The enum lives behind a handle: boxing the variants would add an allocation.
        #[allow(clippy::large_enum_variant)]
        pub enum HOTPState {
            $(
                #[cfg(umilib_feature = $feature)]
                $variant(crate::auth::totp::HOTP<$type>),
            )*
        }

        /// [`TOTP<H>`](crate::auth::totp::TOTP) for any hash function `H` of the registry.
        #[derive(Clone, Debug)]
        #[allow(clippy::large_enum_variant)]
        pub enum TOTPState {
            $(
                #[cfg(umilib_feature = $feature)]
                $variant(crate::auth::totp::TOTP<$type>),
            )*
        }

        // The enums are empty when no algorithm of the registry is enabled, leaving the arguments unused.
        #[allow(unused_variables, unreachable_code)]
        impl HOTPState {
            /// HOTP of `key` and `digits` over the hash function whose C type is named `hash`;
            /// `None` if it is unknown or not enabled.
            pub fn new(hash: &str, key: &[u8], digits: u32) -> Option<Result<HOTPState, OTPError>> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some(crate::auth::totp::HOTP::<$type>::new(key, digits).map(HOTPState::$variant)),
                    )*
                    _ => None,
                }
            }

            pub fn generate(&self, counter: u64) -> Result<OTPCode, OTPError> {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        HOTPState::$variant(ref hotp) => hotp.generate(counter),
                    )*
                }
            }

            pub fn verify(&self, code: &[u8], counter: u64, look_ahead: u64) -> Option<u64> {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        HOTPState::$variant(ref hotp) => hotp.verify(code, counter, look_ahead),
                    )*
                }
            }
        }

        #[allow(unused_variables, unreachable_code)]
        impl TOTPState {
            /// TOTP of `key` and `config` over the hash function whose C type is named `hash`;
            /// `None` if it is unknown or not enabled.
            pub fn new(hash: &str, key: &[u8], config: &TOTPConfig) -> Option<Result<TOTPState, OTPError>> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some(crate::auth::totp::TOTP::<$type>::new(key, config).map(TOTPState::$variant)),
                    )*
                    _ => None,
                }
            }

            pub fn generate(&self, time: u64) -> Result<OTPCode, OTPError> {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        TOTPState::$variant(ref totp) => totp.generate(time),
                    )*
                }
            }

            pub fn verify(&self, code: &[u8], time: u64, behind: u64, ahead: u64) -> Result<Option<u64>, OTPError> {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        TOTPState::$variant(ref totp) => totp.verify(code, time, behind, ahead),
                    )*
                }
            }

            pub fn counter(&self, time: u64) -> Result<u64, OTPError> {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        TOTPState::$variant(ref totp) => totp.counter(time),
                    )*
                }
            }
        }
    };
}

crate::ffi_digest_algorithms!(otp_states);

impl Value for HOTPState {
    const TYPE: Type = Type::Named("umilib_auth_totp_HOTP");
}

impl Value for TOTPState {
    const TYPE: Type = Type::Named("umilib_auth_totp_TOTP");
}

impl OTPCode {
    /// Writes the ASCII digits of the password into the `length` bytes at
    /// `out` (at least the digits) and the number of digits into `written`.
    ///
    /// # Safety
    /// As [`Pointer::slice_mut`] and [`Pointer::write`].
    pub unsafe fn write_ascii(&self, out: *mut u8, length: usize, written: *mut usize) -> Result<(), &'static Status> {
        let digits = self.digits() as usize;
        Pointer::check_range(written, 1)?;
        // SAFETY: the caller's promise.
        let out = unsafe { Pointer::slice_mut(out, length) }?;
        let target = out.get_mut(..digits).ok_or(&Status::INVALID_ARGUMENT)?;
        target.copy_from_slice(&self.to_ascii()[..digits]);
        unsafe { Pointer::write(written, digits) }
    }
}

crate::ffi_functions! {
    const FUNCTIONS;

    /// Writes an HOTP generator of the `key_length` bytes at `key` and passwords of `digits` digits
    /// over the hash function whose C type is named by the UTF-8 text at `hash` (such as
    /// `umilib_hash_sha_v1_SHA1`) into `out`; fails with InvalidArgument if that hash function is
    /// unknown or not enabled, and with KeyTooShort, Digits or Hash.
    pub unsafe extern "C" fn umilib_auth_totp_hotp_new(hash: *const u8, hash_length: usize, key: *const u8, key_length: usize, digits: u32, out: *mut *mut HOTPState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let hotp = HOTPState::new(hash, key, digits).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, hotp) }
        })())
    }

    /// Releases a generator, zeroizing its key. Does nothing if `hotp` is null.
    pub unsafe extern "C" fn umilib_auth_totp_hotp_free(hotp: *mut HOTPState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(hotp) }
    }

    /// Writes the ASCII digits of the password of `counter` into the `length` bytes at `out` (at
    /// least 10 are always enough) and their number into `written`.
    pub unsafe extern "C" fn umilib_auth_totp_hotp_generate(hotp: *const HOTPState, counter: u64, out: *mut u8, length: usize, written: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, a writable byte range and a writable pointer.
            let hotp = unsafe { Pointer::reference(hotp) }?;
            let code = hotp.generate(counter).map_err(|error| error.to_status())?;
            unsafe { code.write_ascii(out, length, written) }
        })())
    }

    /// Writes whether the `length` ASCII digits at `code` are the password of a counter from
    /// `counter` to `counter + look_ahead` into `found`, and that counter into `matched`.
    pub unsafe extern "C" fn umilib_auth_totp_hotp_verify(hotp: *const HOTPState, code: *const u8, length: usize, counter: u64, look_ahead: u64, found: *mut bool, matched: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and writable pointers.
            let hotp = unsafe { Pointer::reference(hotp) }?;
            let code = unsafe { Pointer::slice(code, length) }?;
            Pointer::check_range(found, 1)?;
            Pointer::check_range(matched, 1)?;
            let result = hotp.verify(code, counter, look_ahead);
            unsafe { Pointer::write(found, result.is_some()) }?;
            unsafe { Pointer::write(matched, result.unwrap_or(0)) }
        })())
    }

    /// Writes a TOTP generator of the `key_length` bytes at `key` and the parameters `config` over
    /// the hash function named as in `umilib_auth_totp_hotp_new` into `out`; fails as it does, and
    /// with Period.
    pub unsafe extern "C" fn umilib_auth_totp_totp_new(hash: *const u8, hash_length: usize, key: *const u8, key_length: usize, config: FFITOTPConfig, out: *mut *mut TOTPState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let totp = TOTPState::new(hash, key, &config.into()).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, totp) }
        })())
    }

    /// Releases a generator, zeroizing its key. Does nothing if `totp` is null.
    pub unsafe extern "C" fn umilib_auth_totp_totp_free(totp: *mut TOTPState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(totp) }
    }

    /// Writes the time step of `time` (seconds of the Unix epoch) into `out`; fails with Time.
    pub unsafe extern "C" fn umilib_auth_totp_totp_counter(totp: *const TOTPState, time: u64, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let totp = unsafe { Pointer::reference(totp) }?;
            Pointer::check_range(out, 1)?;
            let counter = totp.counter(time).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, counter) }
        })())
    }

    /// Writes the ASCII digits of the password at `time` into the `length` bytes at `out` and their
    /// number into `written`; fails with Time.
    pub unsafe extern "C" fn umilib_auth_totp_totp_generate(totp: *const TOTPState, time: u64, out: *mut u8, length: usize, written: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, a writable byte range and a writable pointer.
            let totp = unsafe { Pointer::reference(totp) }?;
            let code = totp.generate(time).map_err(|error| error.to_status())?;
            unsafe { code.write_ascii(out, length, written) }
        })())
    }

    /// Writes whether the `length` ASCII digits at `code` are the password of a time step from
    /// `behind` steps before that of `time` to `ahead` steps after it into `found`, and that step
    /// into `matched`; fails with Time.
    pub unsafe extern "C" fn umilib_auth_totp_totp_verify(totp: *const TOTPState, code: *const u8, length: usize, time: u64, behind: u64, ahead: u64, found: *mut bool, matched: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and writable pointers.
            let totp = unsafe { Pointer::reference(totp) }?;
            let code = unsafe { Pointer::slice(code, length) }?;
            Pointer::check_range(found, 1)?;
            Pointer::check_range(matched, 1)?;
            let result = totp.verify(code, time, behind, ahead).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(found, result.is_some()) }?;
            unsafe { Pointer::write(matched, result.unwrap_or(0)) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "totp",
    definitions: &[
        Definition::Opaque { name: "umilib_auth_totp_HOTP", documentation: " An HOTP generator (RFC 4226)." },
        Definition::Opaque { name: "umilib_auth_totp_TOTP", documentation: " A TOTP generator (RFC 6238)." },
        Definition::Structure {
            name: "umilib_auth_totp_TOTPConfig",
            documentation: " The digits of a password, the time step in seconds and its origin (seconds of the Unix epoch).",
            fields: &[
                Parameter { name: "digits", value: <u32 as Value>::TYPE },
                Parameter { name: "period", value: <u64 as Value>::TYPE },
                Parameter { name: "origin", value: <u64 as Value>::TYPE },
            ],
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
