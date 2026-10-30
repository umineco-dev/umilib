//! The C ABI of [`crate::protocol::ip::v4`].
//!
//! Headers and options are structures; data is given back as the offset and
//! length of its part of the caller's bytes. The fragmenter keeps a copy of
//! the data it cuts; the reassembler is a handle, and an abandoned datagram
//! is a handle of its own. Instants and durations are nanoseconds.

use alloc::vec::Vec;
use core::time::Duration;

use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::ip::v4::{
    IPv4Error, IPv4Fragmenter, IPv4Header, IPv4OptionKind, IPv4Options, IPv4Reassembler, IPv4Reassembly,
    IPv4ReassemblyConfig, IPv4ReassemblyKey,
};
use crate::protocol::ip::{IPProtocol, IPv4Address};
use crate::runtime::Instant;

/// The statuses of this module, one per variant of [`IPv4Error`] that is not
/// another module's.
pub struct IPv4Status;

impl IPv4Status {
    pub const VERSION: Status = Status::new(c"protocol.ip.v4", c"Version", c"the packet is not of IP version 4");
    pub const LENGTH: Status =
        Status::new(c"protocol.ip.v4", c"Length", c"the lengths of the packet are not consistent");
    pub const CHECKSUM: Status = Status::new(c"protocol.ip.v4", c"Checksum", c"the header checksum is wrong");
    pub const OPTION: Status = Status::new(c"protocol.ip.v4", c"Option", c"the options are malformed");
    pub const FRAGMENT: Status =
        Status::new(c"protocol.ip.v4", c"Fragment", c"the datagram cannot be fragmented to fit the MTU");
    pub const LIMIT: Status =
        Status::new(c"protocol.ip.v4", c"Limit", c"the fragment does not fit the reassembly limits");
    pub const EXPIRED: Status =
        Status::new(c"protocol.ip.v4", c"Expired", c"the reassembly deadline of the datagram is past");
}

impl ToStatus for IPv4Error {
    fn to_status(&self) -> &'static Status {
        match self {
            IPv4Error::Version => &IPv4Status::VERSION,
            IPv4Error::Length => &IPv4Status::LENGTH,
            IPv4Error::Checksum => &IPv4Status::CHECKSUM,
            IPv4Error::Option => &IPv4Status::OPTION,
            IPv4Error::Fragment => &IPv4Status::FRAGMENT,
            IPv4Error::Reassembly(error) => error.to_status(),
            IPv4Error::Limit => &IPv4Status::LIMIT,
            IPv4Error::Expired => &IPv4Status::EXPIRED,
            IPv4Error::Write(error) => error.to_status(),
        }
    }
}

/// The C form of an [`IPv4ReassemblyConfig`], the timeout in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FFIIPv4ReassemblyConfig {
    pub timeout: u64,
    pub maximum_length: usize,
    pub maximum_datagrams: usize,
    pub maximum_buffered: usize,
}

impl From<FFIIPv4ReassemblyConfig> for IPv4ReassemblyConfig {
    fn from(config: FFIIPv4ReassemblyConfig) -> IPv4ReassemblyConfig {
        IPv4ReassemblyConfig {
            timeout: Duration::from_nanos(config.timeout),
            maximum_length: config.maximum_length,
            maximum_datagrams: config.maximum_datagrams,
            maximum_buffered: config.maximum_buffered,
        }
    }
}

impl From<IPv4ReassemblyConfig> for FFIIPv4ReassemblyConfig {
    fn from(config: IPv4ReassemblyConfig) -> FFIIPv4ReassemblyConfig {
        FFIIPv4ReassemblyConfig {
            timeout: u64::try_from(config.timeout.as_nanos()).unwrap_or(u64::MAX),
            maximum_length: config.maximum_length,
            maximum_datagrams: config.maximum_datagrams,
            maximum_buffered: config.maximum_buffered,
        }
    }
}

/// An [`IPv4Fragmenter`] that owns the data it cuts.
#[derive(Clone, Debug)]
pub struct FFIIPv4Fragmenter {
    pub header: IPv4Header,
    pub payload: Vec<u8>,
    pub mtu: usize,
    pub position: usize,
    pub done: bool,
}

impl Value for IPv4Header {
    const TYPE: Type = Type::Named("umilib_protocol_ip_v4_IPv4Header");
}

impl Value for IPv4Options {
    const TYPE: Type = Type::Named("umilib_protocol_ip_v4_IPv4Options");
}

impl Value for FFIIPv4ReassemblyConfig {
    const TYPE: Type = Type::Named("umilib_protocol_ip_v4_IPv4ReassemblyConfig");
}

impl Value for IPv4ReassemblyKey {
    const TYPE: Type = Type::Named("umilib_protocol_ip_v4_IPv4ReassemblyKey");
}

impl Value for FFIIPv4Fragmenter {
    const TYPE: Type = Type::Named("umilib_protocol_ip_v4_IPv4Fragmenter");
}

impl Value for IPv4Reassembler {
    const TYPE: Type = Type::Named("umilib_protocol_ip_v4_IPv4Reassembler");
}

impl Value for IPv4Reassembly {
    const TYPE: Type = Type::Named("umilib_protocol_ip_v4_IPv4Reassembly");
}

crate::ffi_functions! {
    /// Writes the header of a datagram of `payload_length` bytes of `protocol` without options into
    /// `out`; fails with Length beyond 65,535 bytes.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_header_new(source: IPv4Address, destination: IPv4Address, protocol: u8, payload_length: usize, out: *mut IPv4Header) -> *const Status {
        Status::from_result((|| {
            let header = IPv4Header::new(source, destination, IPProtocol(protocol), payload_length).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, header) }
        })())
    }

    /// Reads the header at the start of the `length` bytes at `bytes` into `out` and the offset and
    /// length of its data into `out_offset` and `out_length`; fails with Version, Length, Checksum or Option.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_header_decode(bytes: *const u8, length: usize, out: *mut IPv4Header, out_offset: *mut usize, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(bytes, length)],
                &[Pointer::range(out, 1), Pointer::range(out_offset, 1), Pointer::range(out_length, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            Pointer::check_range(out_offset, 1)?;
            Pointer::check_range(out_length, 1)?;
            let (header, payload) = IPv4Header::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, header) }?;
            unsafe { Pointer::write(out_offset, header.header_length()) }?;
            unsafe { Pointer::write(out_length, payload.len()) }
        })())
    }

    /// Reads the header at the start of the `length` bytes at `bytes`, whose data may be cut short
    /// (as an ICMP error quotes it), into `out` and the offset and length of the data present into
    /// `out_offset` and `out_length`; fails with Version, Length, Checksum or Option.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_header_decode_truncated(bytes: *const u8, length: usize, out: *mut IPv4Header, out_offset: *mut usize, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(bytes, length)],
                &[Pointer::range(out, 1), Pointer::range(out_offset, 1), Pointer::range(out_length, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            Pointer::check_range(out_offset, 1)?;
            Pointer::check_range(out_length, 1)?;
            let (header, data) = IPv4Header::decode_truncated(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, header) }?;
            unsafe { Pointer::write(out_offset, header.header_length()) }?;
            unsafe { Pointer::write(out_length, data.len()) }
        })())
    }

    /// Writes the bytes of the header, with its checksum, into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_header_encode(header: *const IPv4Header, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure and a writable buffer.
            let header = unsafe { Pointer::reference(header) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(header.to_bytes()[..header.header_length()].to_vec())) }
        })())
    }

    /// The length of the header with its padded options.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_header_header_length(header: IPv4Header) -> usize {
        header.header_length()
    }

    /// The total length less the header.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_header_payload_length(header: IPv4Header) -> usize {
        header.payload_length()
    }

    /// Whether the packet is a fragment of a larger datagram.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_header_is_fragment(header: IPv4Header) -> bool {
        header.is_fragment()
    }

    /// Sets the total length of `header` for `length` bytes of data; fails with Length.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_header_set_payload_length(header: *mut IPv4Header, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure.
            let header = unsafe { Pointer::reference_mut(header) }?;
            header.set_payload_length(length).map_err(|error| error.to_status())
        })())
    }

    /// Reads the options of the `length` bytes at `bytes` (the header after its 20 fixed bytes)
    /// into `out`; fails with Option.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_options_decode(bytes: *const u8, length: usize, out: *mut IPv4Options) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let options = IPv4Options::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, options) }
        })())
    }

    /// Appends an option of `kind` with the `length` bytes of data at `data`; fails with Option.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_options_push(options: *mut IPv4Options, kind: u8, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(options, 1)])?;
            // SAFETY: the caller passes a valid structure and readable bytes.
            let options = unsafe { Pointer::reference_mut(options) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            options.push(IPv4OptionKind(kind), data).map_err(|error| error.to_status())
        })())
    }

    /// Writes whether there is an option at `index` (counting neither padding nor No Operation)
    /// into `out_found`, its kind into `out_kind` and its data into `out`; fails with Option for a
    /// malformed option before it.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_options_get(options: *const IPv4Options, index: usize, out_found: *mut bool, out_kind: *mut u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(options, 1)],
                &[Pointer::range(out_found, 1), Pointer::range(out_kind, 1)],
            )?;
            // SAFETY: the caller passes a valid structure and writable pointers.
            let options = unsafe { Pointer::reference(options) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out, 1)?;
            let option = options.iter().nth(index).transpose().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_found, option.is_some()) }?;
            unsafe { Pointer::write(out_kind, option.map_or(0, |option| option.kind.0)) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(option.map(|option| option.data.to_vec()).unwrap_or_default())) }
        })())
    }

    /// The options copied into every fragment but the first.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_options_copied(options: IPv4Options) -> IPv4Options {
        options.copied()
    }

    /// The length of the options padded to a multiple of 4.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_options_padded_length(options: IPv4Options) -> usize {
        options.padded_length()
    }

    /// Whether an option of `kind` is copied into every fragment.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_option_kind_is_copied(kind: u8) -> bool {
        IPv4OptionKind(kind).is_copied()
    }

    /// The class of an option of `kind`: 0 for control, 2 for debugging and measurement.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_option_kind_class(kind: u8) -> u8 {
        IPv4OptionKind(kind).class()
    }

    /// The number of an option of `kind`.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_option_kind_number(kind: u8) -> u8 {
        IPv4OptionKind(kind).number()
    }

    /// Writes a fragmenter of a copy of the `length` bytes of data at `payload` after `header` for
    /// `mtu` into `out`; fails with Fragment or Length.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_fragmenter_new(header: *const IPv4Header, payload: *const u8, length: usize, mtu: usize, out: *mut *mut FFIIPv4Fragmenter) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure, readable bytes and a writable pointer.
            let header = unsafe { Pointer::reference(header) }?;
            let payload = unsafe { Pointer::slice(payload, length) }?;
            IPv4Fragmenter::new(*header, payload, mtu).map_err(|error| error.to_status())?;
            let fragmenter = FFIIPv4Fragmenter { header: *header, payload: payload.to_vec(), mtu, position: 0, done: false };
            unsafe { Pointer::write_handle(out, fragmenter) }
        })())
    }

    /// Releases a fragmenter. Does nothing if `fragmenter` is null.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_fragmenter_free(fragmenter: *mut FFIIPv4Fragmenter) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(fragmenter) }
    }

    /// Writes whether there is a next fragment into `out_found`, its header into `out` and the
    /// offset and length of its part of the data into `out_offset` and `out_length`.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_fragmenter_next(fragmenter: *mut FFIIPv4Fragmenter, out_found: *mut bool, out: *mut IPv4Header, out_offset: *mut usize, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[
                    Pointer::range(out_found, 1),
                    Pointer::range(out, 1),
                    Pointer::range(out_offset, 1),
                    Pointer::range(out_length, 1),
                ],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let state = unsafe { Pointer::reference_mut(fragmenter) }?;
            for pointer in [out_offset, out_length] {
                Pointer::check_range(pointer, 1)?;
            }
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let mut fragmenter = IPv4Fragmenter {
                header: state.header,
                payload: &state.payload,
                mtu: state.mtu,
                position: state.position,
                done: state.done,
            };
            let start = fragmenter.position;
            let next = fragmenter.next();
            (state.position, state.done) = (fragmenter.position, fragmenter.done);
            unsafe { Pointer::write(out_found, next.is_some()) }?;
            if let Some((header, data)) = next {
                unsafe { Pointer::write(out, header) }?;
                unsafe { Pointer::write(out_offset, start) }?;
                unsafe { Pointer::write(out_length, data.len()) }?;
            }
            Ok(())
        })())
    }

    /// Writes the default limits of a reassembler into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_reassembly_config_default(out: *mut FFIIPv4ReassemblyConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, IPv4ReassemblyConfig::default().into()) })
    }

    /// Writes a reassembler with the limits `config` into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_reassembler_new(config: FFIIPv4ReassemblyConfig, out: *mut *mut IPv4Reassembler) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, IPv4Reassembler::new(config.into())) })
    }

    /// Releases a reassembler. Does nothing if `reassembler` is null.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_reassembler_free(reassembler: *mut IPv4Reassembler) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(reassembler) }
    }

    /// Adds the fragment of `header` and the `length` bytes of data at `payload`, received at `now`,
    /// and writes whether it completes a datagram into `out_complete`, and that datagram's header and
    /// data into `out` and `out_data`; fails with Length, Limit, Overlap (the datagram is discarded)
    /// or the Length of `protocol.ip`.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_reassembler_receive(reassembler: *mut IPv4Reassembler, header: *const IPv4Header, payload: *const u8, length: usize, now: u64, out_complete: *mut bool, out: *mut IPv4Header, out_data: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(header, 1), Pointer::range(payload, length)],
                &[Pointer::range(out_complete, 1), Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes a valid handle and structure, readable bytes and writable pointers.
            let reassembler = unsafe { Pointer::reference_mut(reassembler) }?;
            let header = unsafe { Pointer::reference(header) }?;
            let payload = unsafe { Pointer::slice(payload, length) }?;
            Pointer::check_range(out_complete, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_data, 1)?;
            let result = reassembler.receive(header, payload, Instant::from_nanos(now)).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_complete, result.is_some()) }?;
            if let Some((header, data)) = result {
                unsafe { Pointer::write(out, header) }?;
                unsafe { Pointer::write(out_data, Buffer::from_vec(data)) }?;
            }
            Ok(())
        })())
    }

    /// Writes whether a datagram is being reassembled into `out_found` and the earliest deadline into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_reassembler_poll_timeout(reassembler: *const IPv4Reassembler, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reassembler = unsafe { Pointer::reference(reassembler) }?;
            let deadline = reassembler.poll_timeout();
            unsafe { Pointer::write(out_found, deadline.is_some()) }?;
            unsafe { Pointer::write(out, deadline.map_or(0, Instant::as_nanos)) }
        })())
    }

    /// Removes a datagram whose deadline is at or before `now` and writes whether there was one into
    /// `out_found`, its key into `out_key` and it into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_reassembler_expire(reassembler: *mut IPv4Reassembler, now: u64, out_found: *mut bool, out_key: *mut IPv4ReassemblyKey, out: *mut *mut IPv4Reassembly) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out_key, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reassembler = unsafe { Pointer::reference_mut(reassembler) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_key, 1)?;
            Pointer::check_range(out, 1)?;
            let expired = reassembler.expire(Instant::from_nanos(now));
            unsafe { Pointer::write(out_found, expired.is_some()) }?;
            if let Some((key, reassembly)) = expired {
                unsafe { Pointer::write(out_key, key) }?;
                unsafe { Pointer::write_handle(out, reassembly) }?;
            }
            Ok(())
        })())
    }

    /// Writes whether fragments of the datagram overlapped (RFC 5722) into `out`: it then has no
    /// first fragment, and no ICMP message is sent for it.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_reassembly_abandoned(reassembly: *const IPv4Reassembly, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reassembly = unsafe { Pointer::reference(reassembly) }?;
            unsafe { Pointer::write(out, reassembly.abandoned) }
        })())
    }

    /// Releases a datagram given back by expire. Does nothing if `reassembly` is null.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_reassembly_free(reassembly: *mut IPv4Reassembly) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(reassembly) }
    }

    /// Writes whether the first fragment was received into `out_found`, its header into `out` and
    /// the data received (zeros between the fragments) into `out_data`.
    pub unsafe extern "C" fn umilib_protocol_ip_v4_ipv4_reassembly_first(reassembly: *const IPv4Reassembly, out_found: *mut bool, out: *mut IPv4Header, out_data: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reassembly = unsafe { Pointer::reference(reassembly) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_data, 1)?;
            unsafe { Pointer::write(out_found, reassembly.first.is_some()) }?;
            if let Some(first) = reassembly.first {
                unsafe { Pointer::write(out, first) }?;
            }
            unsafe { Pointer::write(out_data, Buffer::from_vec(reassembly.buffer.data.clone())) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v4",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_ip_v4_IPv4Options",
            documentation: " The options of a header: the bytes after its fixed 20 bytes, at most 40.",
            fields: &[
                Parameter { name: "bytes", value: <[u8; 40] as Value>::TYPE },
                Parameter { name: "length", value: <u8 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_ip_v4_IPv4Header",
            documentation: " The header of an IPv4 packet (RFC 791 §3.1), without its checksum.",
            fields: &[
                Parameter { name: "dscp", value: <u8 as Value>::TYPE },
                Parameter { name: "ecn", value: <u8 as Value>::TYPE },
                Parameter { name: "total_length", value: <u16 as Value>::TYPE },
                Parameter { name: "identification", value: <u16 as Value>::TYPE },
                Parameter { name: "dont_fragment", value: <bool as Value>::TYPE },
                Parameter { name: "more_fragments", value: <bool as Value>::TYPE },
                Parameter { name: "fragment_offset", value: <u16 as Value>::TYPE },
                Parameter { name: "time_to_live", value: <u8 as Value>::TYPE },
                Parameter { name: "protocol", value: <u8 as Value>::TYPE },
                Parameter { name: "source", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "destination", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "options", value: <IPv4Options as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_ip_v4_IPv4ReassemblyConfig",
            documentation: " The limits of a reassembler; the timeout in nanoseconds.",
            fields: &[
                Parameter { name: "timeout", value: <u64 as Value>::TYPE },
                Parameter { name: "maximum_length", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_datagrams", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_buffered", value: <usize as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_ip_v4_IPv4ReassemblyKey",
            documentation: " What identifies the fragments of one datagram.",
            fields: &[
                Parameter { name: "source", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "destination", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "protocol", value: <u8 as Value>::TYPE },
                Parameter { name: "identification", value: <u16 as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_ip_v4_IPv4Fragmenter",
            documentation: " The fragments of a datagram that fit an MTU.",
        },
        Definition::Opaque {
            name: "umilib_protocol_ip_v4_IPv4Reassembler",
            documentation: " The reassembly of IPv4 datagrams from their fragments.",
        },
        Definition::Opaque {
            name: "umilib_protocol_ip_v4_IPv4Reassembly",
            documentation: " A datagram given back by the reassembler at its deadline.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
