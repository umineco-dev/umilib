//! The C ABI of [`crate::protocol::icmp`].
//!
//! A message crosses as the structure of its first eight bytes but the
//! checksum ([`FFIICMPHeader`]) and its body, the bytes after them. An
//! extension structure crosses as its bytes, its objects read by index.

#[cfg(umilib_feature = "protocol-icmp-v4")]
pub mod v4;
#[cfg(umilib_feature = "protocol-icmp-v6")]
pub mod v6;

use core::time::Duration;

use crate::bytes::Buffer as Bytes;
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::icmp::{ICMPError, ICMPExtensionObject, ICMPExtensions, ICMPRateLimitConfig, ICMPRateLimiter};
use crate::runtime::Instant;

/// The statuses of this module, one per variant of [`ICMPError`] that is not
/// another module's.
pub struct ICMPStatus;

impl ICMPStatus {
    pub const LENGTH: Status =
        Status::new(c"protocol.icmp", c"Length", c"the ICMP message is shorter than its fields say");
    pub const CHECKSUM: Status = Status::new(c"protocol.icmp", c"Checksum", c"the ICMP checksum is wrong");
    pub const VERSION: Status =
        Status::new(c"protocol.icmp", c"Version", c"the ICMP extension structure is not of version 2");
    pub const INVALID: Status =
        Status::new(c"protocol.icmp", c"Invalid", c"the ICMP message fails the validity checks of its type");
    pub const LIMIT: Status = Status::new(c"protocol.icmp", c"Limit", c"the neighbor cache is full");

    /// Writes what `write` writes into a new buffer at `out`.
    ///
    /// # Safety
    /// As [`Pointer::write`].
    pub unsafe fn write_bytes(
        out: *mut Buffer,
        write: impl FnOnce(&mut Bytes) -> Result<(), ICMPError>,
    ) -> Result<(), &'static Status> {
        Pointer::check_range(out, 1)?;
        let mut bytes = Bytes::new();
        write(&mut bytes).map_err(|error| error.to_status())?;
        // SAFETY: the caller's promise.
        unsafe { Pointer::write(out, Buffer::from_vec(bytes.into_vec())) }
    }
}

impl ToStatus for ICMPError {
    fn to_status(&self) -> &'static Status {
        match self {
            ICMPError::Length => &ICMPStatus::LENGTH,
            ICMPError::Checksum => &ICMPStatus::CHECKSUM,
            ICMPError::Version => &ICMPStatus::VERSION,
            ICMPError::Invalid => &ICMPStatus::INVALID,
            ICMPError::Limit => &ICMPStatus::LIMIT,
            ICMPError::Write(error) => error.to_status(),
        }
    }
}

/// The first eight bytes of an ICMP or ICMPv6 message but the checksum: the
/// type, the code and the four bytes whose meaning depends on the type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FFIICMPHeader {
    pub kind: u8,
    pub code: u8,
    pub rest: [u8; 4],
}

impl Value for FFIICMPHeader {
    const TYPE: Type = Type::Named("umilib_protocol_icmp_ICMPHeader");
}

impl Value for ICMPRateLimiter {
    const TYPE: Type = Type::Named("umilib_protocol_icmp_ICMPRateLimiter");
}

crate::ffi_functions! {
    /// Checks the extension structure of the `length` bytes at `bytes` (version 2, the checksum if
    /// one was sent, the objects) and writes its checksum as received into `out`; fails with Version,
    /// Checksum or Length.
    pub unsafe extern "C" fn umilib_protocol_icmp_icmp_extensions_decode(bytes: *const u8, length: usize, out: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let extensions = ICMPExtensions::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, extensions.checksum) }
        })())
    }

    /// Writes whether the extension structure of the `length` bytes at `bytes` has an object at
    /// `index` into `out_found`, its class and sub-type into `out_class` and `out_kind`, and its
    /// payload into `out`; fails as `umilib_protocol_icmp_icmp_extensions_decode` does.
    pub unsafe extern "C" fn umilib_protocol_icmp_icmp_extensions_get(bytes: *const u8, length: usize, index: usize, out_found: *mut bool, out_class: *mut u8, out_kind: *mut u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(bytes, length)],
                &[Pointer::range(out_found, 1), Pointer::range(out_class, 1), Pointer::range(out_kind, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            for pointer in [out_class, out_kind] {
                Pointer::check_range(pointer, 1)?;
            }
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let extensions = ICMPExtensions::decode(bytes).map_err(|error| error.to_status())?;
            let object = extensions.iter().nth(index).transpose().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_found, object.is_some()) }?;
            unsafe { Pointer::write(out_class, object.map_or(0, |object| object.class)) }?;
            unsafe { Pointer::write(out_kind, object.map_or(0, |object| object.kind)) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(object.map(|object| object.payload.to_vec()).unwrap_or_default())) }
        })())
    }

    /// Writes an object of the class `object_class`, the sub-type `kind` and the `length` bytes of
    /// payload at `payload` into `out`; fails with Length unless the object is a multiple of 4 bytes.
    pub unsafe extern "C" fn umilib_protocol_icmp_icmp_extension_object_encode(object_class: u8, kind: u8, payload: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let payload = unsafe { Pointer::slice(payload, length) }?;
            unsafe { ICMPStatus::write_bytes(out, |bytes| ICMPExtensionObject { class: object_class, kind, payload }.encode(bytes)) }
        })())
    }

    /// Checks that the `length` bytes of encoded objects at `objects` are one or more objects of whole
    /// 32-bit words (RFC 4884 §7, §8); fails with Length.
    pub unsafe extern "C" fn umilib_protocol_icmp_icmp_extensions_check(objects: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes.
            let objects = unsafe { Pointer::slice(objects, length) }?;
            ICMPExtensions { checksum: 0, objects }.check().map_err(|error| error.to_status())
        })())
    }

    /// Checks that `word` is the word of a version of ICMP, 4 or 8 (RFC 4884 §4); fails with Invalid.
    pub unsafe extern "C" fn umilib_protocol_icmp_icmp_extensions_check_word(word: usize) -> *const Status {
        Status::from_result(ICMPExtensions::check_word(word).map_err(|error| error.to_status()))
    }

    /// Writes the extension structure of the `length` bytes of encoded objects at `objects` into `out`;
    /// fails with Length unless they are one or more objects of whole 32-bit words.
    pub unsafe extern "C" fn umilib_protocol_icmp_icmp_extensions_encode(objects: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let objects = unsafe { Pointer::slice(objects, length) }?;
            unsafe { ICMPStatus::write_bytes(out, |bytes| ICMPExtensions { checksum: 0, objects }.encode(bytes)) }
        })())
    }

    /// Writes the body of an extended error message (the `original_length` bytes of the original
    /// datagram at `original`, padded to a multiple of `word` bytes and to 128, then the structure of
    /// the `objects_length` bytes of objects at `objects`) into `out` and its length attribute into
    /// `out_attribute`; fails with Invalid unless `word` is 4 or 8, and with Length if the attribute
    /// does not fit 8 bits or the objects are not one or more of whole 32-bit words.
    pub unsafe extern "C" fn umilib_protocol_icmp_icmp_extensions_encode_body(objects: *const u8, objects_length: usize, original: *const u8, original_length: usize, word: usize, out_attribute: *mut u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(objects, objects_length), Pointer::range(original, original_length)],
                &[Pointer::range(out_attribute, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let objects = unsafe { Pointer::slice(objects, objects_length) }?;
            let original = unsafe { Pointer::slice(original, original_length) }?;
            Pointer::check_range(out_attribute, 1)?;
            let mut attribute = 0;
            unsafe {
                ICMPStatus::write_bytes(out, |bytes| {
                    attribute = ICMPExtensions { checksum: 0, objects }.encode_body(original, word, bytes)?;
                    Ok(())
                })
            }?;
            unsafe { Pointer::write(out_attribute, attribute) }
        })())
    }

    /// Splits the `length` bytes of body at `body` of an error message whose length attribute is
    /// `attribute` words of `word` bytes: writes the length of the original datagram into
    /// `out_original` and whether an extension structure follows it into `out_found`; fails with
    /// Invalid unless `word` is 4 or 8, and with Length, Version or Checksum if the body or the
    /// structure is malformed.
    pub unsafe extern "C" fn umilib_protocol_icmp_icmp_extensions_split_body(body: *const u8, length: usize, attribute: u8, word: usize, out_original: *mut usize, out_found: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(body, length)],
                &[Pointer::range(out_original, 1), Pointer::range(out_found, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let body = unsafe { Pointer::slice(body, length) }?;
            Pointer::check_range(out_original, 1)?;
            Pointer::check_range(out_found, 1)?;
            let (original, extensions) = ICMPExtensions::split_body(body, attribute, word).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_original, original.len()) }?;
            unsafe { Pointer::write(out_found, extensions.is_some()) }
        })())
    }

    /// Writes a full token bucket of `burst` tokens, one added every `interval` nanoseconds, at
    /// `now` into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_icmp_rate_limiter_new(burst: u32, interval: u64, now: u64, out: *mut *mut ICMPRateLimiter) -> *const Status {
        let config = ICMPRateLimitConfig { burst, interval: Duration::from_nanos(interval) };
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, ICMPRateLimiter::new(config, Instant::from_nanos(now))) })
    }

    /// Releases a bucket. Does nothing if `limiter` is null.
    pub unsafe extern "C" fn umilib_protocol_icmp_icmp_rate_limiter_free(limiter: *mut ICMPRateLimiter) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(limiter) }
    }

    /// Writes whether a message may be sent at `now` into `out`, taking its token if so.
    pub unsafe extern "C" fn umilib_protocol_icmp_icmp_rate_limiter_allow(limiter: *mut ICMPRateLimiter, now: u64, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let limiter = unsafe { Pointer::reference_mut(limiter) }?;
            Pointer::check_range(out, 1)?;
            let allowed = limiter.allow(Instant::from_nanos(now));
            unsafe { Pointer::write(out, allowed) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "icmp",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_icmp_ICMPHeader",
            documentation: " The first eight bytes of an ICMP or ICMPv6 message but the checksum.",
            fields: &[
                Parameter { name: "kind", value: <u8 as Value>::TYPE },
                Parameter { name: "code", value: <u8 as Value>::TYPE },
                Parameter { name: "rest", value: <[u8; 4] as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_icmp_ICMPRateLimiter",
            documentation: " The token bucket that limits the error messages a node originates.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[
        #[cfg(umilib_feature = "protocol-icmp-v4")]
        v4::MODULE,
        #[cfg(umilib_feature = "protocol-icmp-v6")]
        v6::MODULE,
    ],
};
