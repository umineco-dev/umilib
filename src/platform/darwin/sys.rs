//! The Darwin functions and constants the Darwin layer uses, declared from
//! the headers of the macOS SDK (`sys/event.h`, `sys/random.h`).

use core::ffi::{c_int, c_void};

/// `struct kevent`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct KEvent {
    pub ident: usize,
    pub filter: i16,
    pub flags: u16,
    pub fflags: u32,
    pub data: isize,
    pub udata: *mut c_void,
}

impl Default for KEvent {
    fn default() -> KEvent {
        KEvent { ident: 0, filter: 0, flags: 0, fflags: 0, data: 0, udata: core::ptr::null_mut() }
    }
}

/// `struct timespec`.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct TimeSpec {
    pub seconds: i64,
    pub nanoseconds: i64,
}

unsafe extern "C" {
    pub fn kqueue() -> c_int;
    pub fn kevent(
        queue: c_int,
        changes: *const KEvent,
        change_count: c_int,
        events: *mut KEvent,
        event_count: c_int,
        timeout: *const TimeSpec,
    ) -> c_int;
    pub fn getentropy(buffer: *mut c_void, length: usize) -> c_int;
}

/// The constants of the declarations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Darwin;

impl Darwin {
    pub const EVFILT_READ: i16 = -1;
    pub const EVFILT_WRITE: i16 = -2;
    pub const EVFILT_USER: i16 = -10;
    pub const EV_ADD: u16 = 0x0001;
    pub const EV_DELETE: u16 = 0x0002;
    pub const EV_ENABLE: u16 = 0x0004;
    pub const EV_ONESHOT: u16 = 0x0010;
    pub const EV_CLEAR: u16 = 0x0020;
    pub const EV_RECEIPT: u16 = 0x0040;
    pub const EV_ERROR: u16 = 0x4000;
    pub const EV_EOF: u16 = 0x8000;
    pub const NOTE_TRIGGER: u32 = 0x0100_0000;
    pub const EINTR: i32 = 4;
    pub const ENOENT: i32 = 2;
    /// The most bytes one `getentropy` call gives.
    pub const ENTROPY_MAXIMUM: usize = 256;
}
