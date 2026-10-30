//! The C ABI of [`crate::protocol::dhcp`].
//!
//! A DUID is an [`FFIDHCPDUID`] of its fixed fields beside its variable
//! bytes. The messages of both versions are structures of their headers
//! beside their options, which cross as the bytes of their wire format.
//! Clients and servers are handles; instants cross as nanoseconds of the
//! caller's monotonic clock (`now`), durations as milliseconds, with
//! [`DHCPStatus::INFINITY`] for infinity. The functions that draw
//! randomness (transaction IDs and the jitter of retransmissions) take a
//! generator of the crypto.random module by its handle and the C name of its
//! type (`random` and `random_type`), as the functions that generate keys take it.

#[cfg(umilib_feature = "protocol-dhcp-v4")]
pub mod v4;
#[cfg(umilib_feature = "protocol-dhcp-v6")]
pub mod v6;

use alloc::vec::Vec;
use core::time::Duration;

use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::dhcp::{DHCPDUID, DHCPError};

/// The statuses of this module, one per variant of [`DHCPError`], and the
/// helpers of the modules of both versions.
pub struct DHCPStatus;

impl DHCPStatus {
    pub const MALFORMED: Status =
        Status::new(c"protocol.dhcp", c"Malformed", c"the bytes are not a valid DHCP message or option");
    pub const TOO_LARGE: Status =
        Status::new(c"protocol.dhcp", c"TooLarge", c"the DHCP message or option is too large");
    pub const STATE: Status = Status::new(c"protocol.dhcp", c"State", c"not possible in the DHCP client's state");
    pub const CONFIG: Status = Status::new(c"protocol.dhcp", c"Config", c"the DHCP configuration cannot work");
    pub const RANDOM: Status = Status::new(c"protocol.dhcp", c"Random", c"the source of randomness failed");
    /// The milliseconds of an infinite duration, and the nanoseconds of an instant that never comes.
    pub const INFINITY: u64 = u64::MAX;

    /// The `length` bytes at `data`, or none if `data` is null.
    ///
    /// # Safety
    /// As [`Pointer::slice`].
    pub unsafe fn optional<'a>(data: *const u8, length: usize) -> Result<Option<&'a [u8]>, &'static Status> {
        if data.is_null() {
            return Ok(None);
        }
        // SAFETY: the caller's promise; `data` is non-null.
        Ok(Some(unsafe { Pointer::slice(data, length) }?))
    }

    /// The milliseconds of `duration`; [`DHCPStatus::INFINITY`] for none.
    pub fn milliseconds(duration: Option<Duration>) -> u64 {
        duration.map_or(DHCPStatus::INFINITY, |duration| {
            duration.as_millis().min(u128::from(DHCPStatus::INFINITY - 1)) as u64
        })
    }

    /// The duration of `milliseconds`; none for [`DHCPStatus::INFINITY`].
    pub fn duration(milliseconds: u64) -> Option<Duration> {
        (milliseconds != DHCPStatus::INFINITY).then(|| Duration::from_millis(milliseconds))
    }
}

impl ToStatus for DHCPError {
    fn to_status(&self) -> &'static Status {
        match self {
            DHCPError::Malformed(_) => &DHCPStatus::MALFORMED,
            DHCPError::TooLarge => &DHCPStatus::TOO_LARGE,
            DHCPError::State => &DHCPStatus::STATE,
            DHCPError::Config => &DHCPStatus::CONFIG,
            DHCPError::Random => &DHCPStatus::RANDOM,
        }
    }
}

/// A [`DHCPDUID`] but its variable bytes: `kind` its type (1 DUID-LLT, 2
/// DUID-EN, 3 DUID-LL, 4 DUID-UUID, any other a type kept as it is), the
/// `hardware` type of DUID-LLT and DUID-LL, the `time` of DUID-LLT and the
/// `enterprise` number of DUID-EN; the fields a type has not are zero. The
/// link-layer address, the identifier, the 16 bytes of the UUID or the data
/// of another type are beside it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPDUID {
    pub kind: u16,
    pub hardware: u16,
    pub time: u32,
    pub enterprise: u32,
}

impl FFIDHCPDUID {
    /// The structure of `duid` and its variable bytes.
    pub fn of(duid: &DHCPDUID) -> (FFIDHCPDUID, Vec<u8>) {
        let mut out = FFIDHCPDUID::default();
        let data = match duid {
            DHCPDUID::LLT { hardware, time, address } => {
                (out.kind, out.hardware, out.time) = (1, *hardware, *time);
                address.clone()
            }
            DHCPDUID::EN { enterprise, identifier } => {
                (out.kind, out.enterprise) = (2, *enterprise);
                identifier.clone()
            }
            DHCPDUID::LL { hardware, address } => {
                (out.kind, out.hardware) = (3, *hardware);
                address.clone()
            }
            DHCPDUID::UUID(uuid) => {
                out.kind = 4;
                uuid.to_vec()
            }
            DHCPDUID::Other { kind, data } => {
                out.kind = *kind;
                data.clone()
            }
        };
        (out, data)
    }

    /// The DUID of the structure and `data`; fails with Malformed for a UUID
    /// of other than 16 bytes.
    pub fn duid(&self, data: &[u8]) -> Result<DHCPDUID, &'static Status> {
        let duid = match self.kind {
            1 => DHCPDUID::LLT { hardware: self.hardware, time: self.time, address: data.to_vec() },
            2 => DHCPDUID::EN { enterprise: self.enterprise, identifier: data.to_vec() },
            3 => DHCPDUID::LL { hardware: self.hardware, address: data.to_vec() },
            4 => DHCPDUID::UUID(data.try_into().map_err(|_| &DHCPStatus::MALFORMED)?),
            kind => DHCPDUID::Other { kind, data: data.to_vec() },
        };
        Ok(duid)
    }
}

impl Value for FFIDHCPDUID {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_DHCPDUID");
}

crate::ffi_functions! {
    /// Reads the DUID of the `length` bytes at `bytes` (RFC 9915 §11) into `out` and its variable bytes
    /// into `out_data`; fails with Malformed for one of fewer than 3 or more than 130 bytes, or of a
    /// known type shorter than its fixed fields.
    pub unsafe extern "C" fn umilib_protocol_dhcp_dhcp_duid_decode(bytes: *const u8, length: usize, out: *mut FFIDHCPDUID, out_data: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_data, 1)?;
            let duid = DHCPDUID::decode(bytes).map_err(|error| error.to_status())?;
            let (structure, data) = FFIDHCPDUID::of(&duid);
            unsafe { Pointer::write(out, structure) }?;
            unsafe { Pointer::write(out_data, Buffer::from_vec(data)) }
        })())
    }

    /// Writes the DUID of `duid` and the `length` bytes at `data` into `out`; fails with Malformed
    /// without variable bytes, for a UUID of other than 16 bytes, or for more than 130 bytes in all
    /// (RFC 9915 §11.1).
    pub unsafe extern "C" fn umilib_protocol_dhcp_dhcp_duid_encode(duid: FFIDHCPDUID, data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out, 1)?;
            let bytes = duid.duid(data)?.encode().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }

    /// The time of a DUID-LLT made at `unix` seconds since 1970: the seconds since 2000-01-01 UTC,
    /// modulo 2^32 (RFC 9915 §11.2).
    pub unsafe extern "C" fn umilib_protocol_dhcp_dhcp_duid_time(unix: u64) -> u32 {
        DHCPDUID::time(unix)
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "dhcp",
    definitions: &[Definition::Structure {
        name: "umilib_protocol_dhcp_DHCPDUID",
        documentation: " A DHCP Unique Identifier (RFC 9915 §11) but its variable bytes: kind 1 DUID-LLT, 2 DUID-EN,\n \
                        3 DUID-LL, 4 DUID-UUID, any other a type kept as it is; the fields a type has not are zero.",
        fields: &[
            Parameter { name: "kind", value: <u16 as Value>::TYPE },
            Parameter { name: "hardware", value: <u16 as Value>::TYPE },
            Parameter { name: "time", value: <u32 as Value>::TYPE },
            Parameter { name: "enterprise", value: <u32 as Value>::TYPE },
        ],
    }],
    functions: FUNCTIONS,
    modules: &[
        #[cfg(umilib_feature = "protocol-dhcp-v4")]
        v4::MODULE,
        #[cfg(umilib_feature = "protocol-dhcp-v6")]
        v6::MODULE,
    ],
};
