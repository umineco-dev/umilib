use core::ffi::CStr;

use super::Char;

/// The outcome of a fallible FFI function.
///
/// Fallible functions return `const umilib_ffi_Status*`: a null pointer on
/// success, otherwise a pointer to a static `Status` that describes the error.
/// `domain` is the module path of the error type (for example `bytes`) and
/// `name` is the error variant (for example `UnexpectedEnd`). Every string is
/// static and NUL-terminated; the caller never frees a status.
#[repr(C)]
#[derive(Debug)]
pub struct Status {
    domain: *const Char,
    name: *const Char,
    message: *const Char,
}

// SAFETY: a `Status` only points to immutable static strings.
unsafe impl Sync for Status {}

impl Status {
    /// A required pointer argument was null.
    pub const NULL_POINTER: Status = Status::new(c"ffi", c"NullPointer", c"a required pointer argument is null");
    /// An argument is outside the range the function accepts.
    pub const INVALID_ARGUMENT: Status = Status::new(c"ffi", c"InvalidArgument", c"an argument is out of range");
    /// A string argument is not valid UTF-8.
    pub const INVALID_UTF8: Status = Status::new(c"ffi", c"InvalidUTF8", c"a string argument is not valid UTF-8");

    /// Creates a status from static strings.
    pub const fn new(domain: &'static CStr, name: &'static CStr, message: &'static CStr) -> Status {
        Status { domain: domain.as_ptr().cast(), name: name.as_ptr().cast(), message: message.as_ptr().cast() }
    }

    /// Converts a result into the value returned to C: null on success.
    pub fn from_result(result: Result<(), &'static Status>) -> *const Status {
        match result {
            Ok(()) => core::ptr::null(),
            Err(status) => status,
        }
    }

    /// The module path of the error type.
    pub fn domain(&self) -> &'static CStr {
        // SAFETY: the fields are private and only set by `Status::new` from
        // static NUL-terminated strings.
        unsafe { CStr::from_ptr(self.domain.cast()) }
    }

    /// The error variant.
    pub fn name(&self) -> &'static CStr {
        // SAFETY: see `Status::domain`.
        unsafe { CStr::from_ptr(self.name.cast()) }
    }

    /// A human-readable description of the error.
    pub fn message(&self) -> &'static CStr {
        // SAFETY: see `Status::domain`.
        unsafe { CStr::from_ptr(self.message.cast()) }
    }
}

/// An error type that can be reported across the FFI boundary.
pub trait ToStatus {
    /// The static status describing this error.
    fn to_status(&self) -> &'static Status;
}

impl ToStatus for &'static Status {
    fn to_status(&self) -> &'static Status {
        self
    }
}
