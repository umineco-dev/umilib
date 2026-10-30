//! The C ABI of [`crate::platform::native`]: the system's random bytes and its name.

use crate::ffi::{Char, Module, Pointer, Status};

/// The statuses of this module.
pub struct NativeStatus;

impl NativeStatus {
    pub const UNSUPPORTED: Status =
        Status::new(c"platform", c"Unsupported", c"the operating system has no native layer");
    pub const RANDOM: Status = Status::new(c"platform", c"Random", c"the system's random generator failed");
}

crate::ffi_functions! {
    const FUNCTIONS;

    /// Fills the `length` bytes at `data` with the system's random bytes.
    pub unsafe extern "C" fn umilib_platform_native_random_fill(data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes writable bytes.
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
            {
                crate::platform::native::Random::new().fill(data).map_err(|_| &NativeStatus::RANDOM)
            }
            #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
            {
                let _ = data;
                Err(&NativeStatus::UNSUPPORTED)
            }
        })())
    }

    /// Writes the name of the operating system ("linux", "android", "darwin", "windows" or "other"),
    /// a static NUL-terminated string, into `out`.
    pub unsafe extern "C" fn umilib_platform_native_system_name(out: *mut *const Char) -> *const Status {
        let name: &'static core::ffi::CStr = match crate::platform::native::System::NAME.as_bytes() {
            b"linux" => c"linux",
            b"android" => c"android",
            b"darwin" => c"darwin",
            b"windows" => c"windows",
            _ => c"other",
        };
        // SAFETY: the caller passes a writable pointer; the string is static.
        Status::from_result(unsafe { Pointer::write(out, name.as_ptr().cast::<Char>()) })
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "native", definitions: &[], functions: FUNCTIONS, modules: &[] };
