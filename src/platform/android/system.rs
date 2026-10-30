use core::ffi::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::string::String;

unsafe extern "C" {
    /// `__system_property_get` of `sys/system_properties.h` (in every NDK).
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> c_int;
}

/// The system properties of Android.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AndroidSystem;

impl AndroidSystem {
    /// The most bytes of a property value, with its NUL (`PROP_VALUE_MAX`).
    pub const PROPERTY_VALUE_MAXIMUM: usize = 92;

    /// The value of the property `name` (such as `ro.build.version.release`),
    /// `None` if it is not set (or empty).
    pub fn property(name: &str) -> Option<String> {
        let name = CString::new(name).ok()?;
        let mut value = [0 as c_char; AndroidSystem::PROPERTY_VALUE_MAXIMUM];
        // SAFETY: a NUL-terminated name and a buffer of PROP_VALUE_MAX bytes, as the function requires.
        let length = unsafe { __system_property_get(name.as_ptr(), value.as_mut_ptr()) };
        if length <= 0 {
            return None;
        }
        // SAFETY: the function wrote a NUL-terminated value into the buffer.
        let value = unsafe { CStr::from_ptr(value.as_ptr()) };
        Some(value.to_string_lossy().into_owned())
    }

    /// The API level of the system (`ro.build.version.sdk`).
    pub fn api_level() -> Option<u32> {
        AndroidSystem::property("ro.build.version.sdk")?.trim().parse().ok()
    }
}
