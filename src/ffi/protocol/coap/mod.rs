//! The C ABI of [`crate::protocol::coap`].
//!
//! A message, its options, an endpoint, the observers of a server, a
//! receiver of a block-wise transfer, a link, a list of links and a rule are
//! handles. A message's type crosses as the number of its bits (0
//! Confirmable, 1 Non-confirmable, 2 Acknowledgement, 3 Reset), its code as
//! its byte, an option's number as its `u16`; a block, the configuration of
//! an endpoint, the definition of an option and an event are structures. The
//! peers of an endpoint are the endpoints of the ip module. Times are
//! nanoseconds of the caller's monotonic clock (`now`), durations of the
//! configuration milliseconds. The functions that draw randomness (Message
//! IDs, tokens, the timeouts of retransmission) take a generator of the
//! crypto.random module by its handle and the C name of its type (`random`
//! and `random_type`), as the functions that generate keys take it.

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::time::Duration;

use crate::ffi::crypto::random::RandomSource;
use crate::ffi::protocol::ip::FFIIPEndpoint;
use crate::ffi::{Buffer, Char, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::coap::{
    CoAPBlock, CoAPBlockwise, CoAPCode, CoAPConfig, CoAPEndpoint, CoAPError, CoAPEvent, CoAPLink, CoAPMessage,
    CoAPObservers, CoAPOptionFormat, CoAPOptionNumber, CoAPOptions, CoAPRule, CoAPType,
};
use crate::runtime::Instant;
use crate::service::Rule;

/// The statuses of this module, one per variant of [`CoAPError`].
pub struct CoAPStatus;

impl CoAPStatus {
    pub const MALFORMED: Status =
        Status::new(c"protocol.coap", c"Malformed", c"not a CoAP message: a message format error");
    pub const OPTION: Status =
        Status::new(c"protocol.coap", c"Option", c"a CoAP option of a value its definition does not allow");
    pub const TOO_LARGE: Status = Status::new(c"protocol.coap", c"TooLarge", c"a CoAP message larger than it may be");
    pub const STATE: Status = Status::new(c"protocol.coap", c"State", c"not possible in this state");
    pub const CONFIG: Status = Status::new(c"protocol.coap", c"Config", c"the CoAP configuration cannot work");
    pub const RANDOM: Status = Status::new(c"protocol.coap", c"Random", c"the source of randomness failed");

    /// The type of the bits `bits` (RFC 7252 §3); fails with InvalidArgument above 3.
    pub fn kind(bits: u8) -> Result<CoAPType, &'static Status> {
        match bits {
            0..=3 => Ok(CoAPType::from_bits(bits)),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    /// The number of `format`, as [`FFICoAPOptionDefinition`] carries it.
    pub fn format(format: CoAPOptionFormat) -> u8 {
        match format {
            CoAPOptionFormat::Empty => 0,
            CoAPOptionFormat::Opaque => 1,
            CoAPOptionFormat::Uint => 2,
            CoAPOptionFormat::String => 3,
        }
    }
}

impl ToStatus for CoAPError {
    fn to_status(&self) -> &'static Status {
        match self {
            CoAPError::Malformed(_) => &CoAPStatus::MALFORMED,
            CoAPError::Option(_) => &CoAPStatus::OPTION,
            CoAPError::TooLarge => &CoAPStatus::TOO_LARGE,
            CoAPError::State => &CoAPStatus::STATE,
            CoAPError::Config => &CoAPStatus::CONFIG,
            CoAPError::Random => &CoAPStatus::RANDOM,
        }
    }
}

/// A [`CoAPBlock`] (RFC 7959 §2.2): its number, whether more follow, and
/// its size as SZX, 2^(SZX + 4) bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFICoAPBlock {
    pub number: u32,
    pub more: bool,
    pub exponent: u8,
}

impl FFICoAPBlock {
    pub fn of(block: &CoAPBlock) -> FFICoAPBlock {
        FFICoAPBlock { number: block.number, more: block.more, exponent: block.exponent }
    }

    /// The block; fails with Option for a number of more than 20 bits or an
    /// SZX of 7, which is reserved (§2.2).
    pub fn block(&self) -> Result<CoAPBlock, &'static Status> {
        if self.number > CoAPBlock::MAXIMUM_NUMBER || self.exponent > 6 {
            return Err(&CoAPStatus::OPTION);
        }
        Ok(CoAPBlock { number: self.number, more: self.more, exponent: self.exponent })
    }
}

/// The definition of a known option (RFC 7252 table 4): its format (0
/// empty, 1 opaque, 2 uint, 3 string), least and greatest length, and
/// whether it may repeat.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFICoAPOptionDefinition {
    pub format: u8,
    pub least: usize,
    pub greatest: usize,
    pub repeatable: bool,
}

/// A [`CoAPConfig`]: the transmission parameters (RFC 7252 §4.8) and the
/// limits of an endpoint; durations in milliseconds, ACK_RANDOM_FACTOR in
/// thousandths.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFICoAPConfig {
    pub ack_timeout: u64,
    pub ack_random_factor: u32,
    pub max_retransmit: u32,
    pub nstart: usize,
    pub exchange_lifetime: u64,
    pub non_lifetime: u64,
    pub ack_delay: u64,
    pub maximum_token: usize,
    pub maximum_seen: usize,
    pub maximum_incoming: usize,
}

impl FFICoAPConfig {
    pub fn of(config: &CoAPConfig) -> FFICoAPConfig {
        FFICoAPConfig {
            ack_timeout: config.ack_timeout.as_millis() as u64,
            ack_random_factor: config.ack_random_factor,
            max_retransmit: config.max_retransmit,
            nstart: config.nstart,
            exchange_lifetime: config.exchange_lifetime.as_millis() as u64,
            non_lifetime: config.non_lifetime.as_millis() as u64,
            ack_delay: config.ack_delay.as_millis() as u64,
            maximum_token: config.maximum_token,
            maximum_seen: config.maximum_seen,
            maximum_incoming: config.maximum_incoming,
        }
    }

    pub fn config(&self) -> CoAPConfig {
        CoAPConfig {
            ack_timeout: Duration::from_millis(self.ack_timeout),
            ack_random_factor: self.ack_random_factor,
            max_retransmit: self.max_retransmit,
            nstart: self.nstart,
            exchange_lifetime: Duration::from_millis(self.exchange_lifetime),
            non_lifetime: Duration::from_millis(self.non_lifetime),
            ack_delay: Duration::from_millis(self.ack_delay),
            maximum_token: self.maximum_token,
            maximum_seen: self.maximum_seen,
            maximum_incoming: self.maximum_incoming,
        }
    }
}

/// A [`CoAPEvent`]: `kind` the number of its variant (0 Request, 1
/// Response, 2 Timeout, 3 Reset), with the handle it names — `exchange` of
/// a Request, `request` of a Response, `message` of a Timeout or a Reset —
/// and the `peer` of a Request. The message of a Request or a Response is a
/// handle beside it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFICoAPEvent {
    pub kind: u8,
    pub exchange: u64,
    pub request: u64,
    pub message: u64,
    pub peer: FFIIPEndpoint,
}

impl FFICoAPEvent {
    /// The structure of `event` and its message, if it has one.
    pub fn of(event: CoAPEvent) -> (FFICoAPEvent, Option<CoAPMessage>) {
        let mut out = FFICoAPEvent::default();
        let message = match event {
            CoAPEvent::Request { exchange, peer, message } => {
                (out.kind, out.exchange, out.peer) = (0, exchange, FFIIPEndpoint::of(&peer));
                Some(message)
            }
            CoAPEvent::Response { request, message } => {
                (out.kind, out.request) = (1, request);
                Some(message)
            }
            CoAPEvent::Timeout { message } => {
                (out.kind, out.message) = (2, message);
                None
            }
            CoAPEvent::Reset { message } => {
                (out.kind, out.message) = (3, message);
                None
            }
        };
        (out, message)
    }

    /// The event of the structure with `message` as the message of a
    /// Request or a Response; fails with InvalidArgument for another kind,
    /// and with the ip module's Length for the peer of a Request.
    pub fn event(&self, message: CoAPMessage) -> Result<CoAPEvent, &'static Status> {
        match self.kind {
            0 => Ok(CoAPEvent::Request { exchange: self.exchange, peer: self.peer.endpoint()?, message }),
            1 => Ok(CoAPEvent::Response { request: self.request, message }),
            2 => Ok(CoAPEvent::Timeout { message: self.message }),
            3 => Ok(CoAPEvent::Reset { message: self.message }),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

impl Value for FFICoAPBlock {
    const TYPE: Type = Type::Named("umilib_protocol_coap_CoAPBlock");
}

impl Value for FFICoAPOptionDefinition {
    const TYPE: Type = Type::Named("umilib_protocol_coap_CoAPOptionDefinition");
}

impl Value for FFICoAPConfig {
    const TYPE: Type = Type::Named("umilib_protocol_coap_CoAPConfig");
}

impl Value for FFICoAPEvent {
    const TYPE: Type = Type::Named("umilib_protocol_coap_CoAPEvent");
}

impl Value for CoAPOptions {
    const TYPE: Type = Type::Named("umilib_protocol_coap_CoAPOptions");
}

impl Value for CoAPMessage {
    const TYPE: Type = Type::Named("umilib_protocol_coap_CoAPMessage");
}

impl Value for CoAPEndpoint {
    const TYPE: Type = Type::Named("umilib_protocol_coap_CoAPEndpoint");
}

impl Value for CoAPObservers {
    const TYPE: Type = Type::Named("umilib_protocol_coap_CoAPObservers");
}

impl Value for CoAPBlockwise {
    const TYPE: Type = Type::Named("umilib_protocol_coap_CoAPBlockwise");
}

impl Value for CoAPLink {
    const TYPE: Type = Type::Named("umilib_protocol_coap_CoAPLink");
}

impl Value for Vec<CoAPLink> {
    const TYPE: Type = Type::Named("umilib_protocol_coap_CoAPLinks");
}

impl Value for CoAPRule {
    const TYPE: Type = Type::Named("umilib_protocol_coap_CoAPRule");
}

crate::ffi_functions! {
    /// Writes whether the option `number` is critical, so that an endpoint that does not know it
    /// cannot ignore it (RFC 7252 §5.4.1), into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_option_number_is_critical(number: u16, out: *mut bool) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, CoAPOptionNumber(number).is_critical()) })
    }

    /// Writes whether the option `number` is unsafe to forward by a proxy that does not know it
    /// (RFC 7252 §5.4.2) into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_option_number_is_unsafe(number: u16, out: *mut bool) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, CoAPOptionNumber(number).is_unsafe()) })
    }

    /// Writes whether the option `number` is not part of the cache key (RFC 7252 §5.4.2, §5.4.6) into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_option_number_is_no_cache_key(number: u16, out: *mut bool) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, CoAPOptionNumber(number).is_no_cache_key()) })
    }

    /// Writes the definition of the option `number` into `out` and whether it is a known option into
    /// `out_found` (RFC 7252 table 4, RFC 7641 §2, RFC 7959 tables 1 and 2).
    pub unsafe extern "C" fn umilib_protocol_coap_coap_option_number_definition(number: u16, out_found: *mut bool, out: *mut FFICoAPOptionDefinition) -> *const Status {
        let definition = CoAPOptionNumber(number).definition().map(|(format, least, greatest, repeatable)| {
            FFICoAPOptionDefinition { format: CoAPStatus::format(format), least, greatest, repeatable }
        });
        // SAFETY: the caller passes writable pointers.
        Status::from_result(unsafe { Pointer::write_optional(definition, out_found, out) })
    }

    /// Writes an empty set of options into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_new(out: *mut *mut CoAPOptions) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, CoAPOptions::new()) })
    }

    /// Writes a copy of the options into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_clone(options: *const CoAPOptions, out: *mut *mut CoAPOptions) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let options = unsafe { Pointer::reference(options) }?;
            unsafe { Pointer::write_handle(out, options.clone()) }
        })())
    }

    /// Releases a set of options. Does nothing if `options` is null.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_free(options: *mut CoAPOptions) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(options) }
    }

    /// Writes the number of options into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_count(options: *const CoAPOptions, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let options = unsafe { Pointer::reference(options) }?;
            unsafe { Pointer::write(out, options.entries.len()) }
        })())
    }

    /// Writes the number of the option `index`, in the order of the numbers and repeated ones in the
    /// order given (RFC 7252 §3.1, §5.4.5), into `out_number` and its value into `out`; fails with
    /// InvalidArgument past the end.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_entry(options: *const CoAPOptions, index: usize, out_number: *mut u16, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let options = unsafe { Pointer::reference(options) }?;
            Pointer::check_range(out_number, 1)?;
            Pointer::check_range(out, 1)?;
            let (number, value) = options.entries.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out_number, number.0) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(value.clone())) }
        })())
    }

    /// Adds the option `number` of the `length` bytes at `value` after those of its number and before
    /// greater ones.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_push(options: *mut CoAPOptions, number: u16, value: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let options = unsafe { Pointer::reference_mut(options) }?;
            let value = unsafe { Pointer::slice(value, length) }?;
            options.push(CoAPOptionNumber(number), value.to_vec());
            Ok(())
        })())
    }

    /// Sets the one option `number` to the `length` bytes at `value`, replacing those there are.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_set(options: *mut CoAPOptions, number: u16, value: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let options = unsafe { Pointer::reference_mut(options) }?;
            let value = unsafe { Pointer::slice(value, length) }?;
            options.set(CoAPOptionNumber(number), value.to_vec());
            Ok(())
        })())
    }

    /// Removes every option `number`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_remove(options: *mut CoAPOptions, number: u16) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(options) }?.remove(CoAPOptionNumber(number));
            Ok(())
        })())
    }

    /// Writes the value of the first option `number` into `out` and whether there is one into `out_found`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_get(options: *const CoAPOptions, number: u16, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let options = unsafe { Pointer::reference(options) }?;
            unsafe { Pointer::write_optional(options.get(CoAPOptionNumber(number)).map(|value| Buffer::from_vec(value.to_vec())), out_found, out) }
        })())
    }

    /// Writes whether there is an option `number` into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_contains(options: *const CoAPOptions, number: u16, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let options = unsafe { Pointer::reference(options) }?;
            unsafe { Pointer::write(out, options.contains(CoAPOptionNumber(number))) }
        })())
    }

    /// Writes the uint of the first option `number` (RFC 7252 §3.2) into `out` and whether there is
    /// one of at most 4 bytes into `out_found`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_uint(options: *const CoAPOptions, number: u16, out_found: *mut bool, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let options = unsafe { Pointer::reference(options) }?;
            unsafe { Pointer::write_optional(options.uint(CoAPOptionNumber(number)), out_found, out) }
        })())
    }

    /// Sets the one option `number` to the uint `value`, without leading zeros (RFC 7252 §3.2).
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_set_uint(options: *mut CoAPOptions, number: u16, value: u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(options) }?.set_uint(CoAPOptionNumber(number), value);
            Ok(())
        })())
    }

    /// Writes the bytes of the uint `value`, without leading zeros (RFC 7252 §3.2), into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_uint_bytes(value: u32, out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, Buffer::from_vec(CoAPOptions::uint_bytes(value))) })
    }

    /// Writes the uint of the `length` bytes at `bytes` into `out` and whether they are at most 4
    /// into `out_found` (RFC 7252 §3.2).
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_uint_of(bytes: *const u8, length: usize, out_found: *mut bool, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(bytes, length)],
                &[Pointer::range(out_found, 1), Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            unsafe { Pointer::write_optional(CoAPOptions::uint_of(bytes), out_found, out) }
        })())
    }

    /// Writes whether an option makes the message one to reject (RFC 7252 §5.4.1, §5.4.3, §5.4.5) —
    /// a critical option unknown, of a value its definition does not allow, or repeated though it may
    /// not be — into `out_found` and the number of the first such into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_check(options: *const CoAPOptions, out_found: *mut bool, out: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let options = unsafe { Pointer::reference(options) }?;
            let rejected = options.check().err().map(|number| number.0);
            unsafe { Pointer::write_optional(rejected, out_found, out) }
        })())
    }

    /// Writes the options without the elective ones to ignore — unknown, of a value out of their
    /// definition, or repeated beyond the first (RFC 7252 §5.4.1, §5.4.5) — into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_usable(options: *const CoAPOptions, out: *mut *mut CoAPOptions) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let options = unsafe { Pointer::reference(options) }?;
            unsafe { Pointer::write_handle(out, options.usable()) }
        })())
    }

    /// Sets the Uri-Path options of the UTF-8 text at `path` ("/a/b") and the Uri-Query options of
    /// the UTF-8 text at `query` ("x=1&y", none if null), as RFC 7252 §6.4 splits a URI.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_set_uri(options: *mut CoAPOptions, path: *const u8, path_length: usize, query: *const u8, query_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let options = unsafe { Pointer::reference_mut(options) }?;
            let path = unsafe { Pointer::text(path, path_length) }?;
            let query = unsafe { Pointer::optional_text(query, query_length) }?;
            options.set_uri(path, query);
            Ok(())
        })())
    }

    /// Writes the Content-Format (RFC 7252 §5.10.3) into `out` and whether there is one into `out_found`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_content_format(options: *const CoAPOptions, out_found: *mut bool, out: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let options = unsafe { Pointer::reference(options) }?;
            let format = options.content_format().map(|format| format.0);
            unsafe { Pointer::write_optional(format, out_found, out) }
        })())
    }

    /// Writes the Max-Age in seconds, 60 without the option (RFC 7252 §5.10.5), into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_max_age(options: *const CoAPOptions, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let options = unsafe { Pointer::reference(options) }?;
            unsafe { Pointer::write(out, options.max_age()) }
        })())
    }

    /// Writes the Observe value, of 24 bits (RFC 7641 §2), into `out` and whether there is one into `out_found`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_observe(options: *const CoAPOptions, out_found: *mut bool, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let options = unsafe { Pointer::reference(options) }?;
            unsafe { Pointer::write_optional(options.observe(), out_found, out) }
        })())
    }

    /// Writes the block of the option `number` (Block1 or Block2, RFC 7959 §2.2) into `out` and
    /// whether there is one into `out_found`; fails with Option for a value longer than 3 bytes or of
    /// the reserved SZX 7.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_options_block(options: *const CoAPOptions, number: u16, out_found: *mut bool, out: *mut FFICoAPBlock) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let options = unsafe { Pointer::reference(options) }?;
            let block = options.block(CoAPOptionNumber(number)).transpose().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_optional(block.as_ref().map(FFICoAPBlock::of), out_found, out) }
        })())
    }

    /// Writes the block `number` of `size` bytes (16 to 1024 in powers of 2), with more after it if
    /// `more`, into `out`; fails with Option for another size or a number of more than 20 bits.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_block_new(number: u32, more: bool, size: usize, out: *mut FFICoAPBlock) -> *const Status {
        Status::from_result((|| {
            let block = CoAPBlock::new(number, more, size).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, FFICoAPBlock::of(&block)) }
        })())
    }

    /// Reads the block of the option value of `length` bytes at `value` into `out`; fails with Option
    /// for a value longer than 3 bytes or of the reserved SZX 7 (RFC 7959 §2.2).
    pub unsafe extern "C" fn umilib_protocol_coap_coap_block_decode(value: *const u8, length: usize, out: *mut FFICoAPBlock) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(value, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let value = unsafe { Pointer::slice(value, length) }?;
            let block = CoAPBlock::decode(value).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, FFICoAPBlock::of(&block)) }
        })())
    }

    /// Writes the option value of the block `block` into `out`; fails with Option for a block that is not one.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_block_encode(block: FFICoAPBlock, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let block = block.block()?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, Buffer::from_vec(block.encode())) }
        })())
    }

    /// Writes the size of the block in bytes into `out`; fails with Option for a block that is not one.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_block_size(block: FFICoAPBlock, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            let block = block.block()?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, block.size()) }
        })())
    }

    /// Writes the offset of the block in the whole body (RFC 7959 §2.2) into `out`; fails with Option
    /// for a block that is not one.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_block_offset(block: FFICoAPBlock, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            let block = block.block()?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, block.offset()) }
        })())
    }

    /// Writes whether the body of `length` bytes at `body` has the block `block` (RFC 7959 §2.4) into
    /// `out_found`, the length of its bytes, which start at the block's offset, into `out_length`, and
    /// whether more follow into `out_more`; fails with Option for a block that is not one.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_block_slice(block: FFICoAPBlock, body: *const u8, length: usize, out_found: *mut bool, out_length: *mut usize, out_more: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(body, length)],
                &[Pointer::range(out_found, 1), Pointer::range(out_length, 1), Pointer::range(out_more, 1)],
            )?;
            let block = block.block()?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let body = unsafe { Pointer::slice(body, length) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_length, 1)?;
            Pointer::check_range(out_more, 1)?;
            let slice = block.slice(body);
            let (length, more) = slice.map_or((0, false), |(bytes, more)| (bytes.len(), more));
            unsafe { Pointer::write(out_found, slice.is_some()) }?;
            unsafe { Pointer::write(out_length, length) }?;
            unsafe { Pointer::write(out_more, more) }
        })())
    }

    /// Writes a message of the type `kind`, the code `code` and the Message ID `id`, without token,
    /// options or payload, into `out`; fails with InvalidArgument for a type above 3.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_new(kind: u8, code: u8, id: u16, out: *mut *mut CoAPMessage) -> *const Status {
        Status::from_result((|| {
            let kind = CoAPStatus::kind(kind)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, CoAPMessage::new(kind, CoAPCode(code), id)) }
        })())
    }

    /// Writes the empty message of the type `kind` and the Message ID `id`, an ACK or a RST (RFC 7252
    /// §4.1, §4.2), into `out`; fails with InvalidArgument for a type above 3.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_empty(kind: u8, id: u16, out: *mut *mut CoAPMessage) -> *const Status {
        Status::from_result((|| {
            let kind = CoAPStatus::kind(kind)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, CoAPMessage::empty(kind, id)) }
        })())
    }

    /// Writes a copy of the message into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_clone(message: *const CoAPMessage, out: *mut *mut CoAPMessage) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write_handle(out, message.clone()) }
        })())
    }

    /// Releases a message. Does nothing if `message` is null.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_free(message: *mut CoAPMessage) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(message) }
    }

    /// Reads the message of the `length` bytes at `bytes` (RFC 7252 §3, RFC 8974 §2.1) into `out`;
    /// fails with Malformed for a message format error: another version, a token length of 15, an
    /// option of delta or length 15, a payload marker without payload, or an empty message with a
    /// token, options or payload (RFC 7252 §4.1).
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_decode(bytes: *const u8, length: usize, out: *mut *mut CoAPMessage) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            Pointer::check_range(out, 1)?;
            let message = CoAPMessage::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, message) }
        })())
    }

    /// Writes the bytes of the message (RFC 7252 §3) into `out`; fails with TooLarge for a token or an
    /// option value above its largest length.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_encode(message: *const CoAPMessage, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            Pointer::check_range(out, 1)?;
            let bytes = message.encode().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }

    /// Writes whether the `length` bytes at `bytes` have a header of version 1 into `out_found`, and
    /// its type and Message ID into `out_kind` and `out_id`: what a message that cannot be read
    /// otherwise is rejected by (RFC 7252 §4.2, §4.3).
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_header(bytes: *const u8, length: usize, out_found: *mut bool, out_kind: *mut u8, out_id: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(bytes, length)],
                &[Pointer::range(out_found, 1), Pointer::range(out_kind, 1), Pointer::range(out_id, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out_id, 1)?;
            let header = CoAPMessage::header(bytes);
            let (kind, id) = header.map_or((0, 0), |(kind, id)| (kind.bits(), id));
            unsafe { Pointer::write(out_found, header.is_some()) }?;
            unsafe { Pointer::write(out_kind, kind) }?;
            unsafe { Pointer::write(out_id, id) }
        })())
    }

    /// Writes the type of the message, as its bits, into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_kind(message: *const CoAPMessage, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write(out, message.kind.bits()) }
        })())
    }

    /// Sets the type of the message to the bits `kind`; fails with InvalidArgument above 3.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_set_kind(message: *mut CoAPMessage, kind: u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let message = unsafe { Pointer::reference_mut(message) }?;
            message.kind = CoAPStatus::kind(kind)?;
            Ok(())
        })())
    }

    /// Writes the code of the message into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_code(message: *const CoAPMessage, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write(out, message.code.0) }
        })())
    }

    /// Sets the code of the message.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_set_code(message: *mut CoAPMessage, code: u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(message) }?.code = CoAPCode(code);
            Ok(())
        })())
    }

    /// Writes the Message ID of the message into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_id(message: *const CoAPMessage, out: *mut u16) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write(out, message.id) }
        })())
    }

    /// Sets the Message ID of the message.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_set_id(message: *mut CoAPMessage, id: u16) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(message) }?.id = id;
            Ok(())
        })())
    }

    /// Writes the token of the message into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_token(message: *const CoAPMessage, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(message.token.clone())) }
        })())
    }

    /// Sets the token of the message to the `length` bytes at `token`, of up to 65804 bytes (RFC 8974
    /// §2.1), which encoding checks.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_set_token(message: *mut CoAPMessage, token: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let message = unsafe { Pointer::reference_mut(message) }?;
            message.token = unsafe { Pointer::slice(token, length) }?.to_vec();
            Ok(())
        })())
    }

    /// Writes a copy of the options of the message into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_options(message: *const CoAPMessage, out: *mut *mut CoAPOptions) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write_handle(out, message.options.clone()) }
        })())
    }

    /// Sets the options of the message to a copy of `options`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_set_options(message: *mut CoAPMessage, options: *const CoAPOptions) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let options = unsafe { Pointer::reference(options) }?.clone();
            unsafe { Pointer::reference_mut(message) }?.options = options;
            Ok(())
        })())
    }

    /// Writes the payload of the message into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_payload(message: *const CoAPMessage, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(message.payload.clone())) }
        })())
    }

    /// Sets the payload of the message to the `length` bytes at `payload`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_message_set_payload(message: *mut CoAPMessage, payload: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let message = unsafe { Pointer::reference_mut(message) }?;
            message.payload = unsafe { Pointer::slice(payload, length) }?.to_vec();
            Ok(())
        })())
    }

    /// Writes the default configuration (RFC 7252 §4.8, and tokens of up to 8 bytes) into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_config_default(out: *mut FFICoAPConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFICoAPConfig::of(&CoAPConfig::default())) })
    }

    /// Writes an endpoint of the configuration at `config`, its first Message ID drawn from `random`
    /// (RFC 7252 §4.4), into `out`; fails with Config for a zero ACK_TIMEOUT, an ACK_RANDOM_FACTOR
    /// below 1000 or a zero NSTART, and with Random if `random` fails.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_endpoint_new(config: *const FFICoAPConfig, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut CoAPEndpoint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure, a generator of the named type and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?.config();
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            Pointer::check_range(out, 1)?;
            let endpoint = CoAPEndpoint::new(config, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, endpoint) }
        })())
    }

    /// Releases an endpoint. Does nothing if `endpoint` is null.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_endpoint_free(endpoint: *mut CoAPEndpoint) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(endpoint) }
    }

    /// Sends the request `message` (Confirmable or Non-confirmable, a token of 8 random bytes if it
    /// has none) to `peer` at `now`; it waits while NSTART interactions with the peer are outstanding
    /// (RFC 7252 §4.7). Writes the handle its response and notifications come with into `out`; fails
    /// with State for a message that is not such a request, TooLarge, and Random.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_endpoint_request(endpoint: *mut CoAPEndpoint, peer: *const FFIIPEndpoint, message: *const CoAPMessage, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(peer, 1), Pointer::range(random_type, random_type_length)],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes valid handles and structure, a generator of the named type and a writable pointer.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let peer = unsafe { Pointer::reference(peer) }?.endpoint()?;
            let message = unsafe { Pointer::reference(message) }?.clone();
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            Pointer::check_range(out, 1)?;
            let handle = endpoint.request(peer, message, Instant::from_nanos(now), &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, handle) }
        })())
    }

    /// Takes the datagram of `length` bytes at `bytes` from `peer` at `now`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_endpoint_receive(endpoint: *mut CoAPEndpoint, peer: *const FFIIPEndpoint, bytes: *const u8, length: usize, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and structure, readable bytes and a generator of the named type.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let peer = unsafe { Pointer::reference(peer) }?.endpoint()?;
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            endpoint.receive(peer, bytes, Instant::from_nanos(now), &mut random);
            Ok(())
        })())
    }

    /// Answers the request `exchange` with the code, options and payload of `response` at `now`:
    /// piggybacked in the ACK of a Confirmable request not yet acknowledged (RFC 7252 §5.2.1), else
    /// separately, Confirmable for a Confirmable request (§5.2.2) and Non-confirmable for a
    /// Non-confirmable one. Fails with State for an exchange that is not awaiting its answer.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_endpoint_respond(endpoint: *mut CoAPEndpoint, exchange: u64, response: *const CoAPMessage, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a generator of the named type.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let response = unsafe { Pointer::reference(response) }?.clone();
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            endpoint.respond(exchange, response, Instant::from_nanos(now), &mut random).map_err(|error| error.to_status())
        })())
    }

    /// Does not answer the request `exchange` (RFC 7967, or a multicast request, RFC 7252 §8.2): it is
    /// forgotten, and a Confirmable request not yet acknowledged is acknowledged by an empty ACK.
    /// Fails with State for an exchange not awaiting its answer.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_endpoint_ignore(endpoint: *mut CoAPEndpoint, exchange: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(endpoint) }?.ignore(exchange).map_err(|error| error.to_status())
        })())
    }

    /// Sends the notification `message` (a response with Observe, of the observer's token) of an
    /// observation to `peer` at `now` (RFC 7641 §4.2); writes its handle, to learn of a RST or a
    /// timeout, which end the observation (§3.6, §4.5), into `out`. Fails with State for a message
    /// that is not such a response.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_endpoint_notify(endpoint: *mut CoAPEndpoint, peer: *const FFIIPEndpoint, message: *const CoAPMessage, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(peer, 1), Pointer::range(random_type, random_type_length)],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes valid handles and structure, a generator of the named type and a writable pointer.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let peer = unsafe { Pointer::reference(peer) }?.endpoint()?;
            let message = unsafe { Pointer::reference(message) }?.clone();
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            Pointer::check_range(out, 1)?;
            let handle = endpoint.notify(peer, message, Instant::from_nanos(now), &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, handle) }
        })())
    }

    /// Stops awaiting the request `handle` at `now`: its observation is forgotten, so that its
    /// notifications are rejected (RFC 7641 §3.6), and what waited for it may go.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_endpoint_cancel(endpoint: *mut CoAPEndpoint, handle: u64, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(endpoint) }?.cancel(handle, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes whether a timer is set into `out_found` and when it fires (nanoseconds) into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_endpoint_poll_timeout(endpoint: *const CoAPEndpoint, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let endpoint = unsafe { Pointer::reference(endpoint) }?;
            let timeout = endpoint.poll_timeout().map(Instant::as_nanos);
            unsafe { Pointer::write_optional(timeout, out_found, out) }
        })())
    }

    /// Does what is due at `now`: retransmissions, doubling the timeout up to MAX_RETRANSMIT (RFC 7252
    /// §4.2); the end of what is not answered; the empty ACK of a request not yet answered (§5.2.2).
    pub unsafe extern "C" fn umilib_protocol_coap_coap_endpoint_expire(endpoint: *mut CoAPEndpoint, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(endpoint) }?.expire(Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes the next datagram to send into `out` and its peer into `out_peer`, and whether there was
    /// one into `out_found`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_endpoint_transmit(endpoint: *mut CoAPEndpoint, out_found: *mut bool, out_peer: *mut FFIIPEndpoint, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out_peer, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_peer, 1)?;
            Pointer::check_range(out, 1)?;
            let transmission = endpoint.transmit();
            unsafe { Pointer::write(out_found, transmission.is_some()) }?;
            let (peer, bytes) = transmission.map_or((FFIIPEndpoint::default(), Vec::new()), |transmission| {
                (FFIIPEndpoint::of(&transmission.peer), transmission.message)
            });
            unsafe { Pointer::write(out_peer, peer) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }

    /// Writes whether an event is pending into `out_found`, the event into `out`, and the message of a
    /// Request or a Response into `out_message` (null for another event).
    pub unsafe extern "C" fn umilib_protocol_coap_coap_endpoint_poll_event(endpoint: *mut CoAPEndpoint, out_found: *mut bool, out: *mut FFICoAPEvent, out_message: *mut *mut CoAPMessage) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_message, 1)?;
            let event = endpoint.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let (structure, message) = event.map_or((FFICoAPEvent::default(), None), FFICoAPEvent::of);
            unsafe { Pointer::write(out, structure) }?;
            match message {
                Some(message) => unsafe { Pointer::write_handle(out_message, message) },
                None => unsafe { Pointer::write(out_message, core::ptr::null_mut()) },
            }
        })())
    }

    /// Writes whether a notification of the Observe value `value` received at `now` (nanoseconds) was
    /// sent after the freshest one, of `freshest` received at `at`, into `out` (RFC 7641 §3.4).
    pub unsafe extern "C" fn umilib_protocol_coap_coap_endpoint_is_fresher(freshest: u32, at: u64, value: u32, now: u64, out: *mut bool) -> *const Status {
        let fresher = CoAPEndpoint::is_fresher(freshest, Instant::from_nanos(at), value, Instant::from_nanos(now));
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, fresher) })
    }

    /// Writes the observers of a server, of none yet, into `out`: a Confirmable notification at least
    /// once a day (RFC 7641 §4.5), and at most 1024 observers.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_observers_new(out: *mut *mut CoAPObservers) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, CoAPObservers::default()) })
    }

    /// Releases the observers. Does nothing if `observers` is null.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_observers_free(observers: *mut CoAPObservers) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(observers) }
    }

    /// Writes how often, at least, a notification is Confirmable (RFC 7641 §4.5), in milliseconds, into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_observers_confirm_interval(observers: *const CoAPObservers, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let observers = unsafe { Pointer::reference(observers) }?;
            unsafe { Pointer::write(out, observers.confirm_interval.as_millis() as u64) }
        })())
    }

    /// Sets how often, at least, a notification is Confirmable, in milliseconds.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_observers_set_confirm_interval(observers: *mut CoAPObservers, interval: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(observers) }?.confirm_interval = Duration::from_millis(interval);
            Ok(())
        })())
    }

    /// Writes the most observers kept into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_observers_maximum(observers: *const CoAPObservers, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let observers = unsafe { Pointer::reference(observers) }?;
            unsafe { Pointer::write(out, observers.maximum) }
        })())
    }

    /// Sets the most observers kept.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_observers_set_maximum(observers: *mut CoAPObservers, maximum: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(observers) }?.maximum = maximum;
            Ok(())
        })())
    }

    /// Writes the number of observers into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_observers_count(observers: *const CoAPObservers, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let observers = unsafe { Pointer::reference(observers) }?;
            unsafe { Pointer::write(out, observers.observers.len()) }
        })())
    }

    /// Writes the peer of the observer `index` into `out_peer` and its token into `out_token`; fails
    /// with InvalidArgument past the end.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_observers_observer(observers: *const CoAPObservers, index: usize, out_peer: *mut FFIIPEndpoint, out_token: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let observers = unsafe { Pointer::reference(observers) }?;
            Pointer::check_range(out_peer, 1)?;
            Pointer::check_range(out_token, 1)?;
            let observer = observers.observers.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out_peer, FFIIPEndpoint::of(&observer.peer)) }?;
            unsafe { Pointer::write(out_token, Buffer::from_vec(observer.token.clone())) }
        })())
    }

    /// Takes the GET or FETCH request `request` of `peer` at `now`: with Observe 0 the client observes
    /// the resource (an observer of the same peer and token replaced, RFC 7641 §4.1); with Observe 1
    /// it stops (§3.6). Writes whether the response is to carry Observe into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_observers_register(observers: *mut CoAPObservers, peer: *const FFIIPEndpoint, request: *const CoAPMessage, now: u64, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(peer, 1)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes valid handles and structure and a writable pointer.
            let observers = unsafe { Pointer::reference_mut(observers) }?;
            let peer = unsafe { Pointer::reference(peer) }?.endpoint()?;
            let request = unsafe { Pointer::reference(request) }?;
            Pointer::check_range(out, 1)?;
            let observing = observers.register(peer, request, Instant::from_nanos(now));
            unsafe { Pointer::write(out, observing) }
        })())
    }

    /// Writes the next Observe value, of 24 bits and strictly increasing (RFC 7641 §4.4), into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_observers_next_value(observers: *mut CoAPObservers, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let observers = unsafe { Pointer::reference_mut(observers) }?;
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write(out, observers.next_value()) }
        })())
    }

    /// Sends, through `endpoint` at `now`, the state of the resource at the path of the `count`
    /// NUL-terminated UTF-8 segments at `path` to its observers (RFC 7641 §4.2): `response` with each
    /// one's token and the next Observe value, Confirmable if `confirmable` or if the observer has not
    /// had a Confirmable one for the interval. A response of another class than 2 has no Observe, and
    /// ends the observations.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_observers_notify(observers: *mut CoAPObservers, endpoint: *mut CoAPEndpoint, path: *const *const Char, count: usize, response: *const CoAPMessage, confirmable: bool, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, NUL-terminated strings and a generator of the named type.
            let observers = unsafe { Pointer::reference_mut(observers) }?;
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let path: Vec<String> = unsafe { Pointer::strings(path, count) }?;
            let response = unsafe { Pointer::reference(response) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            observers
                .notify(endpoint, &path, response, confirmable, Instant::from_nanos(now), &mut random)
                .map_err(|error| error.to_status())
        })())
    }

    /// Takes the event at `event` of the endpoint: a notification rejected (Reset) or not
    /// acknowledged (Timeout) ends its observation (RFC 7641 §3.6, §4.5). Writes whether it was one
    /// into `out`; fails with InvalidArgument for a kind above 3.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_observers_handle(observers: *mut CoAPObservers, event: *const FFICoAPEvent, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(event, 1)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and structure and a writable pointer.
            let observers = unsafe { Pointer::reference_mut(observers) }?;
            let event = unsafe { Pointer::reference(event) }?.event(CoAPMessage::empty(CoAPType::Acknowledgement, 0))?;
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write(out, observers.handle(&event)) }
        })())
    }

    /// Sets the block of the body of `length` bytes at `body` that `request` asks for in its Block2
    /// (its number, at most `size` bytes), or the first, as the payload of `response` with its Block2
    /// option, if the body is larger than a block or a block was asked for (RFC 7959 §2.4); and Size2
    /// if the request has it (§4). Fails with Option for a block past the end, which is 4.02, or a
    /// size that is not one of a block.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_blockwise_respond(request: *const CoAPMessage, body: *const u8, length: usize, size: usize, response: *mut CoAPMessage) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and readable bytes. `request` and `response`
            // may be one handle: the request is copied, and its reference ends, before the
            // response is borrowed mutably.
            let request = unsafe { Pointer::reference(request) }?.clone();
            let body = unsafe { Pointer::slice(body, length) }?;
            let response = unsafe { Pointer::reference_mut(response) }?;
            let mut changed = response.clone();
            CoAPBlockwise::respond(&request, body, size, &mut changed).map_err(|error| error.to_status())?;
            *response = changed;
            Ok(())
        })())
    }

    /// Writes a receiver of a body of at most `maximum` bytes, block by block (RFC 7959 §2.4), into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_blockwise_new(maximum: usize, out: *mut *mut CoAPBlockwise) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, CoAPBlockwise::new(maximum)) })
    }

    /// Releases a receiver. Does nothing if `blockwise` is null.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_blockwise_free(blockwise: *mut CoAPBlockwise) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(blockwise) }
    }

    /// Takes the block `block` of the payload of `length` bytes at `payload`, of the message's ETag of
    /// `etag_length` bytes at `etag` (none if null): in order, each but the last of the full size and
    /// of the same ETag (RFC 7959 §2.4, §2.5). Writes whether the body is whole into `out`; fails with
    /// State for a block out of order or of another ETag, Malformed for one not of its size before
    /// the last, TooLarge past the maximum, and Option for a block that is not one.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_blockwise_receive(blockwise: *mut CoAPBlockwise, block: FFICoAPBlock, payload: *const u8, length: usize, etag: *const u8, etag_length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(payload, length), Pointer::range(etag, etag_length)],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let blockwise = unsafe { Pointer::reference_mut(blockwise) }?;
            let block = block.block()?;
            let payload = unsafe { Pointer::slice(payload, length) }?;
            let etag = match etag.is_null() {
                true => None,
                false => Some(unsafe { Pointer::slice(etag, etag_length) }?),
            };
            Pointer::check_range(out, 1)?;
            let whole = blockwise.receive(block, payload, etag).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, whole) }
        })())
    }

    /// Writes the options of the request for the next block into `out`: `options` with Block2 of the
    /// next number and `size` bytes, without Observe (RFC 7959 §2.4); fails with Option for a size
    /// that is not one of a block.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_blockwise_next_request(blockwise: *const CoAPBlockwise, options: *const CoAPOptions, size: usize, out: *mut *mut CoAPOptions) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let blockwise = unsafe { Pointer::reference(blockwise) }?;
            let options = unsafe { Pointer::reference(options) }?;
            Pointer::check_range(out, 1)?;
            let next = blockwise.next_request(options, size).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, next) }
        })())
    }

    /// Writes the body received so far into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_blockwise_body(blockwise: *const CoAPBlockwise, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let blockwise = unsafe { Pointer::reference(blockwise) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(blockwise.body.clone())) }
        })())
    }

    /// Writes a link to the UTF-8 text at `target`, without attributes (RFC 6690 §2), into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_link_new(target: *const u8, length: usize, out: *mut *mut CoAPLink) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let target = unsafe { Pointer::text(target, length) }?;
            unsafe { Pointer::write_handle(out, CoAPLink::new(target)) }
        })())
    }

    /// Writes a copy of the link into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_link_clone(link: *const CoAPLink, out: *mut *mut CoAPLink) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let link = unsafe { Pointer::reference(link) }?;
            unsafe { Pointer::write_handle(out, link.clone()) }
        })())
    }

    /// Releases a link. Does nothing if `link` is null.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_link_free(link: *mut CoAPLink) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(link) }
    }

    /// Adds the attribute of the UTF-8 text at `name` and that at `value` (none if null) to the link.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_link_with(link: *mut CoAPLink, name: *const u8, name_length: usize, value: *const u8, value_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let link = unsafe { Pointer::reference_mut(link) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            let value = unsafe { Pointer::optional_text(value, value_length) }?;
            *link = core::mem::take(link).with(name, value);
            Ok(())
        })())
    }

    /// Writes the target of the link into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_link_target(link: *const CoAPLink, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let link = unsafe { Pointer::reference(link) }?;
            unsafe { Pointer::write_text(out, link.target.clone()) }
        })())
    }

    /// Writes whether the link has an attribute of the UTF-8 text at `name` (in any case) into
    /// `out_found`, whether the first has a value into `out_has_value`, and its value into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_link_attribute(link: *const CoAPLink, name: *const u8, length: usize, out_found: *mut bool, out_has_value: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(name, length)],
                &[Pointer::range(out_found, 1), Pointer::range(out_has_value, 1)],
            )?;
            // SAFETY: the caller passes a valid handle, readable text and writable pointers.
            let link = unsafe { Pointer::reference(link) }?;
            let name = unsafe { Pointer::text(name, length) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_has_value, 1)?;
            Pointer::check_range(out, 1)?;
            let attribute = link.attribute(name);
            unsafe { Pointer::write(out_found, attribute.is_some()) }?;
            unsafe { Pointer::write_optional_text(out_has_value, out, attribute.flatten()) }
        })())
    }

    /// Writes the number of attributes of the link into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_link_attribute_count(link: *const CoAPLink, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let link = unsafe { Pointer::reference(link) }?;
            unsafe { Pointer::write(out, link.attributes.len()) }
        })())
    }

    /// Writes the name of the attribute `index` of the link into `out_name`, whether it has a value
    /// into `out_has_value`, and its value into `out_value`; fails with InvalidArgument past the end.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_link_attribute_entry(link: *const CoAPLink, index: usize, out_name: *mut Buffer, out_has_value: *mut bool, out_value: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let link = unsafe { Pointer::reference(link) }?;
            Pointer::check_range(out_name, 1)?;
            Pointer::check_range(out_has_value, 1)?;
            Pointer::check_range(out_value, 1)?;
            let (name, value) = link.attributes.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_text(out_name, name.clone()) }?;
            unsafe { Pointer::write_optional_text(out_has_value, out_value, value.as_deref()) }
        })())
    }

    /// Reads the links of the UTF-8 text at `text` (`<target>;name=value;name="quoted",...`, RFC
    /// 6690 §2) into `out`; fails with Malformed for text not of the link format.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_link_parse(text: *const u8, length: usize, out: *mut *mut Vec<CoAPLink>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            Pointer::check_range(out, 1)?;
            let links = CoAPLink::parse(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, links) }
        })())
    }

    /// Writes the text of the links (RFC 6690 §2), values quoted unless they are tokens, into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_link_format(links: *const Vec<CoAPLink>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let links = unsafe { Pointer::reference(links) }?;
            unsafe { Pointer::write_text(out, CoAPLink::format(links)) }
        })())
    }

    /// Writes an empty list of links into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_links_new(out: *mut *mut Vec<CoAPLink>) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, Vec::<CoAPLink>::new()) })
    }

    /// Releases a list of links. Does nothing if `links` is null.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_links_free(links: *mut Vec<CoAPLink>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(links) }
    }

    /// Appends a copy of `link` to the list.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_links_push(links: *mut Vec<CoAPLink>, link: *const CoAPLink) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let link = unsafe { Pointer::reference(link) }?.clone();
            unsafe { Pointer::reference_mut(links) }?.push(link);
            Ok(())
        })())
    }

    /// Writes the number of links into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_links_count(links: *const Vec<CoAPLink>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let links = unsafe { Pointer::reference(links) }?;
            unsafe { Pointer::write(out, links.len()) }
        })())
    }

    /// Writes a copy of the link `index` into `out`; fails with InvalidArgument past the end.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_links_get(links: *const Vec<CoAPLink>, index: usize, out: *mut *mut CoAPLink) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let links = unsafe { Pointer::reference(links) }?;
            let link = links.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, link.clone()) }
        })())
    }

    /// Writes a rule of the requests of paths at or below the UTF-8 text at `path` ("/sensors/temp"),
    /// of any method, into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_rule_new(path: *const u8, length: usize, out: *mut *mut CoAPRule) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let path = unsafe { Pointer::text(path, length) }?;
            unsafe { Pointer::write_handle(out, CoAPRule::new(path)) }
        })())
    }

    /// Releases a rule. Does nothing if `rule` is null.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_rule_free(rule: *mut CoAPRule) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(rule) }
    }

    /// Limits the rule to the requests of the method (the code) `method`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_rule_with_method(rule: *mut CoAPRule, method: u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let rule = unsafe { Pointer::reference_mut(rule) }?;
            *rule = core::mem::take(rule).with_method(CoAPCode(method));
            Ok(())
        })())
    }

    /// Writes whether the rule matches `message`, a request of the rule's path or below it and of its
    /// method if it has one, into `out`.
    pub unsafe extern "C" fn umilib_protocol_coap_coap_rule_matches(rule: *const CoAPRule, message: *const CoAPMessage, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let rule = unsafe { Pointer::reference(rule) }?;
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write(out, rule.matches(message)) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "coap",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_coap_CoAPBlock",
            documentation: " A Block1 or Block2 option (RFC 7959 §2.2): the block's number, whether more\n \
                            follow, and its size as SZX, 2^(SZX + 4) bytes.",
            fields: &[
                Parameter { name: "number", value: <u32 as Value>::TYPE },
                Parameter { name: "more", value: <bool as Value>::TYPE },
                Parameter { name: "exponent", value: <u8 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_coap_CoAPOptionDefinition",
            documentation: " The definition of a known CoAP option (RFC 7252 table 4): its format (0 empty,\n \
                            1 opaque, 2 uint, 3 string), least and greatest length, and whether it may repeat.",
            fields: &[
                Parameter { name: "format", value: <u8 as Value>::TYPE },
                Parameter { name: "least", value: <usize as Value>::TYPE },
                Parameter { name: "greatest", value: <usize as Value>::TYPE },
                Parameter { name: "repeatable", value: <bool as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_coap_CoAPConfig",
            documentation: " The transmission parameters (RFC 7252 §4.8) and the limits of a CoAP endpoint;\n \
                            durations in milliseconds, ACK_RANDOM_FACTOR in thousandths.",
            fields: &[
                Parameter { name: "ack_timeout", value: <u64 as Value>::TYPE },
                Parameter { name: "ack_random_factor", value: <u32 as Value>::TYPE },
                Parameter { name: "max_retransmit", value: <u32 as Value>::TYPE },
                Parameter { name: "nstart", value: <usize as Value>::TYPE },
                Parameter { name: "exchange_lifetime", value: <u64 as Value>::TYPE },
                Parameter { name: "non_lifetime", value: <u64 as Value>::TYPE },
                Parameter { name: "ack_delay", value: <u64 as Value>::TYPE },
                Parameter { name: "maximum_token", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_seen", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_incoming", value: <usize as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_coap_CoAPEvent",
            documentation: " An event of a CoAP endpoint: its kind (0 Request, 1 Response, 2 Timeout,\n \
                            3 Reset), the handle it names, and the peer of a Request.",
            fields: &[
                Parameter { name: "kind", value: <u8 as Value>::TYPE },
                Parameter { name: "exchange", value: <u64 as Value>::TYPE },
                Parameter { name: "request", value: <u64 as Value>::TYPE },
                Parameter { name: "message", value: <u64 as Value>::TYPE },
                Parameter { name: "peer", value: <FFIIPEndpoint as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_coap_CoAPOptions",
            documentation: " The options of a CoAP message, in the order of their numbers (RFC 7252 §3.1).",
        },
        Definition::Opaque {
            name: "umilib_protocol_coap_CoAPMessage",
            documentation: " A CoAP message (RFC 7252 §3): type, code, Message ID, token, options and payload.",
        },
        Definition::Opaque {
            name: "umilib_protocol_coap_CoAPEndpoint",
            documentation: " A CoAP endpoint without I/O, client and server (RFC 7252).",
        },
        Definition::Opaque {
            name: "umilib_protocol_coap_CoAPObservers",
            documentation: " The observers of a CoAP server's resources (RFC 7641 §4).",
        },
        Definition::Opaque {
            name: "umilib_protocol_coap_CoAPBlockwise",
            documentation: " The receiver of a body transferred block by block (RFC 7959).",
        },
        Definition::Opaque {
            name: "umilib_protocol_coap_CoAPLink",
            documentation: " A link of the CoRE Link Format (RFC 6690 §2): its target and attributes.",
        },
        Definition::Opaque {
            name: "umilib_protocol_coap_CoAPLinks",
            documentation: " A list of links of the CoRE Link Format.",
        },
        Definition::Opaque {
            name: "umilib_protocol_coap_CoAPRule",
            documentation: " A rule that routes CoAP requests by their path and, if given, their method.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
