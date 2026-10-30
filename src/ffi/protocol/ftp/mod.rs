//! The C ABI of [`crate::protocol::ftp`].
//!
//! Commands cross it as their lines on the wire without their CRLF, replies
//! as their lines with their CRLFs. A data address is
//! [`FFIFTPDataAddress`]. The configurations are structures (times in
//! nanoseconds); the texts and lists of a server's configuration are given
//! beside its structure. An event is the number of its variant and its
//! contents: of a client, 0 Greeting (its reply), 1 Preliminary and 2 Reply
//! (the command and the reply), 3 StartTLS, 4 ClearCommandChannel, 5 Closed
//! (its error, or null); of a server, 0 Command, 1 StartTLS,
//! 2 ClearCommandChannel, 3 Closed. Times are nanoseconds of the caller's
//! monotonic clock.

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use crate::ffi::{Buffer, Char, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::ftp::{
    FTPClient, FTPClientEvent, FTPCommand, FTPConfig, FTPDataAddress, FTPError, FTPFacts, FTPFeatures, FTPReply,
    FTPReplyReader, FTPServer, FTPServerConfig, FTPServerEvent, FTPTime,
};
use crate::protocol::ip::IPAddress;
use crate::runtime::Instant;

/// The statuses of [`FTPError`], one per variant.
pub struct FTPStatus;

impl FTPStatus {
    pub const SYNTAX: Status = Status::new(c"protocol.ftp", c"Syntax", c"text not of the grammar of FTP");
    pub const TOO_LONG: Status =
        Status::new(c"protocol.ftp", c"TooLong", c"a line longer than the configuration takes");
    pub const STATE: Status = Status::new(c"protocol.ftp", c"State", c"not in this state, or of a feature not listed");
    pub const TIMEOUT: Status = Status::new(c"protocol.ftp", c"Timeout", c"no reply in time");
    pub const CLOSED: Status = Status::new(c"protocol.ftp", c"Closed", c"the connection is closed");

    /// The reply of its text on the wire: its lines, each with its CRLF.
    pub fn reply_of(wire: &[u8]) -> Result<FTPReply, &'static Status> {
        let mut reader = FTPReplyReader::new();
        let mut lines = wire.split(|byte| *byte == b'\n').peekable();
        while let Some(line) = lines.next() {
            if line.is_empty() && lines.peek().is_none() {
                break;
            }
            let line = line.strip_suffix(b"\r").ok_or(&FTPStatus::SYNTAX)?;
            if let Some(reply) = reader.push(line, usize::MAX).map_err(|error| error.to_status())? {
                reply.check().map_err(|error| error.to_status())?;
                return match lines.all(|rest| rest.is_empty()) {
                    true => Ok(reply),
                    false => Err(&FTPStatus::SYNTAX),
                };
            }
        }
        Err(&FTPStatus::SYNTAX)
    }

    pub fn wire_of(reply: &FTPReply) -> Vec<u8> {
        let mut out = Vec::new();
        reply.encode(&mut out);
        out
    }

    /// The command line of `command`, without its CRLF.
    pub fn line_of(command: &FTPCommand) -> Result<Vec<u8>, &'static Status> {
        let mut out = Vec::new();
        command.encode(&mut out).map_err(|error| error.to_status())?;
        out.truncate(out.len() - 2);
        Ok(out)
    }

    pub fn command_of(line: &[u8]) -> Result<FTPCommand, &'static Status> {
        FTPCommand::parse(line).map_err(|error| error.to_status())
    }
}

impl ToStatus for FTPError {
    fn to_status(&self) -> &'static Status {
        match self {
            FTPError::Syntax { .. } => &FTPStatus::SYNTAX,
            FTPError::TooLong { .. } => &FTPStatus::TOO_LONG,
            FTPError::State { .. } => &FTPStatus::STATE,
            FTPError::Timeout => &FTPStatus::TIMEOUT,
            FTPError::Closed => &FTPStatus::CLOSED,
        }
    }
}

/// An [`FTPDataAddress`] in the C ABI: the first `length` (4 or 16) of `octets` are the host, and a
/// `length` of 0 is no host (the reply to EPSV).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIFTPDataAddress {
    pub octets: [u8; 16],
    pub length: u8,
    pub port: u16,
}

impl FFIFTPDataAddress {
    pub fn of(address: &FTPDataAddress) -> FFIFTPDataAddress {
        let mut out = FFIFTPDataAddress { port: address.port, ..FFIFTPDataAddress::default() };
        if let Some(host) = &address.host {
            let octets = host.octets();
            out.octets[..octets.len()].copy_from_slice(octets);
            out.length = octets.len() as u8;
        }
        out
    }

    pub fn address(&self) -> Result<FTPDataAddress, &'static Status> {
        let host = match self.length {
            0 => None,
            length => {
                let octets = self.octets.get(..usize::from(length)).ok_or(&Status::INVALID_ARGUMENT)?;
                Some(IPAddress::from_octets(octets).map_err(|_| &Status::INVALID_ARGUMENT)?)
            }
        };
        Ok(FTPDataAddress { host, port: self.port })
    }
}

/// [`FTPConfig`] in the C ABI: the times in nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIFTPConfig {
    pub maximum_line: usize,
    pub maximum_reply_lines: usize,
    pub maximum_buffered: usize,
    pub reply_timeout: u64,
    pub idle_timeout: u64,
}

impl FFIFTPConfig {
    pub fn of(config: &FTPConfig) -> FFIFTPConfig {
        let nanoseconds = |duration: Duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        FFIFTPConfig {
            maximum_line: config.maximum_line,
            maximum_reply_lines: config.maximum_reply_lines,
            maximum_buffered: config.maximum_buffered,
            reply_timeout: nanoseconds(config.reply_timeout),
            idle_timeout: nanoseconds(config.idle_timeout),
        }
    }

    pub fn config(&self) -> FTPConfig {
        FTPConfig {
            maximum_line: self.maximum_line,
            maximum_reply_lines: self.maximum_reply_lines,
            maximum_buffered: self.maximum_buffered,
            reply_timeout: Duration::from_nanos(self.reply_timeout),
            idle_timeout: Duration::from_nanos(self.idle_timeout),
        }
    }
}

/// The scalar fields of [`FTPServerConfig`] in the C ABI; its texts and lists are given beside it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIFTPServerConfig {
    pub tls: bool,
    pub require_tls: bool,
    pub require_protection: bool,
    pub allow_ccc: bool,
    pub allow_foreign_data: bool,
    pub size: bool,
    pub mdtm: bool,
    pub rest_stream: bool,
    pub utf8: bool,
    pub host: bool,
}

impl FFIFTPServerConfig {
    pub fn of(config: &FTPServerConfig) -> FFIFTPServerConfig {
        FFIFTPServerConfig {
            tls: config.tls,
            require_tls: config.require_tls,
            require_protection: config.require_protection,
            allow_ccc: config.allow_ccc,
            allow_foreign_data: config.allow_foreign_data,
            size: config.size,
            mdtm: config.mdtm,
            rest_stream: config.rest_stream,
            utf8: config.utf8,
            host: config.host,
        }
    }

    pub fn config(
        &self,
        system: String,
        mlst_facts: Vec<String>,
        features: Vec<String>,
        commands: Vec<String>,
    ) -> FTPServerConfig {
        FTPServerConfig {
            system,
            tls: self.tls,
            require_tls: self.require_tls,
            require_protection: self.require_protection,
            allow_ccc: self.allow_ccc,
            allow_foreign_data: self.allow_foreign_data,
            size: self.size,
            mdtm: self.mdtm,
            rest_stream: self.rest_stream,
            mlst_facts,
            utf8: self.utf8,
            host: self.host,
            features,
            commands,
        }
    }
}

/// The contents of an event, as the C ABI gives them.
#[derive(Clone, Debug, Default)]
pub struct FFIFTPEvent {
    pub kind: u8,
    pub command: Vec<u8>,
    pub reply: Vec<u8>,
    pub error: Option<&'static Status>,
}

impl FFIFTPEvent {
    pub fn of_client(event: FTPClientEvent) -> FFIFTPEvent {
        let mut out = FFIFTPEvent::default();
        let line = |command: &FTPCommand| FTPStatus::line_of(command).unwrap_or_default();
        match event {
            FTPClientEvent::Greeting(reply) => out.reply = FTPStatus::wire_of(&reply),
            FTPClientEvent::Preliminary { command, reply } => {
                out.kind = 1;
                out.command = line(&command);
                out.reply = FTPStatus::wire_of(&reply);
            }
            FTPClientEvent::Reply { command, reply } => {
                out.kind = 2;
                out.command = line(&command);
                out.reply = FTPStatus::wire_of(&reply);
            }
            FTPClientEvent::StartTLS => out.kind = 3,
            FTPClientEvent::ClearCommandChannel => out.kind = 4,
            FTPClientEvent::Closed { error } => {
                out.kind = 5;
                out.error = error.map(|error| error.to_status());
            }
        }
        out
    }

    pub fn of_server(event: FTPServerEvent) -> FFIFTPEvent {
        let mut out = FFIFTPEvent::default();
        match event {
            FTPServerEvent::Command(command) => out.command = FTPStatus::line_of(&command).unwrap_or_default(),
            FTPServerEvent::StartTLS => out.kind = 1,
            FTPServerEvent::ClearCommandChannel => out.kind = 2,
            FTPServerEvent::Closed { error } => {
                out.kind = 3;
                out.error = error.map(|error| error.to_status());
            }
        }
        out
    }

    /// Writes the event's contents into the outputs.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn write(
        self,
        out_kind: *mut u8,
        out_command: *mut Buffer,
        out_reply: *mut Buffer,
        out_error: *mut *const Status,
    ) -> Result<(), &'static Status> {
        Pointer::check_range(out_kind, 1)?;
        Pointer::check_range(out_command, 1)?;
        Pointer::check_range(out_reply, 1)?;
        Pointer::check_range(out_error, 1)?;
        // SAFETY: guaranteed by the caller; the ranges were checked.
        unsafe { Pointer::write(out_kind, self.kind) }?;
        unsafe { Pointer::write(out_error, self.error.map_or(core::ptr::null(), |error| error as *const Status)) }?;
        unsafe { Pointer::write(out_command, Buffer::from_vec(self.command)) }?;
        unsafe { Pointer::write(out_reply, Buffer::from_vec(self.reply)) }
    }
}

impl Value for FFIFTPDataAddress {
    const TYPE: Type = Type::Named("umilib_protocol_ftp_FTPDataAddress");
}

impl Value for FFIFTPConfig {
    const TYPE: Type = Type::Named("umilib_protocol_ftp_FTPConfig");
}

impl Value for FFIFTPServerConfig {
    const TYPE: Type = Type::Named("umilib_protocol_ftp_FTPServerConfig");
}

impl Value for FTPClient {
    const TYPE: Type = Type::Named("umilib_protocol_ftp_FTPClient");
}

impl Value for FTPServer {
    const TYPE: Type = Type::Named("umilib_protocol_ftp_FTPServer");
}

crate::ffi_functions! {
    /// Writes the default configuration into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_config_default(out: *mut FFIFTPConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFIFTPConfig::of(&FTPConfig::default())) })
    }

    /// Writes the default scalar fields of a server's configuration into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_config_default(out: *mut FFIFTPServerConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFIFTPServerConfig::of(&FTPServerConfig::default())) })
    }

    /// Writes the command line of the line at `line`, as this crate writes it, into `out`, and whether
    /// the command transfers data on a data connection into `out_transfers`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_command_normalize(line: *const u8, length: usize, out_transfers: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(line, length)], &[Pointer::range(out_transfers, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let command = FTPStatus::command_of(unsafe { Pointer::slice(line, length) }?)?;
            Pointer::check_range(out_transfers, 1)?;
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write(out_transfers, command.transfers()) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(FTPStatus::line_of(&command)?)) }
        })())
    }

    /// Writes the code of the reply of the text at `wire` into `out_code` and its lines, joined by LF,
    /// into `out_lines` (RFC 959 §4.2).
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_reply_decode(wire: *const u8, length: usize, out_code: *mut u16, out_lines: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(wire, length)], &[Pointer::range(out_code, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let reply = FTPStatus::reply_of(unsafe { Pointer::slice(wire, length) }?)?;
            Pointer::check_range(out_code, 1)?;
            Pointer::check_range(out_lines, 1)?;
            unsafe { Pointer::write(out_code, reply.code) }?;
            unsafe { Pointer::write(out_lines, Buffer::from_vec(reply.lines.join(&b'\n'))) }
        })())
    }

    /// Writes the text on the wire of the reply of `code` and the lines at `lines` (joined by LF) into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_reply_encode(code: u16, lines: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let lines = unsafe { Pointer::slice(lines, length) }?;
            Pointer::check_range(out, 1)?;
            let reply = FTPReply { code, lines: lines.split(|byte| *byte == b'\n').map(<[u8]>::to_vec).collect() };
            reply.check().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(FTPStatus::wire_of(&reply))) }
        })())
    }

    /// Writes whether the reply at `wire` names a pathname (of PWD and MKD, RFC 959 Appendix II) into
    /// `out_found` and the pathname into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_reply_pathname(wire: *const u8, length: usize, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(wire, length)], &[Pointer::range(out_found, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let reply = FTPStatus::reply_of(unsafe { Pointer::slice(wire, length) }?)?;
            let pathname = reply.pathname().map(|pathname| Buffer::from_vec(pathname.into_bytes()));
            unsafe { Pointer::write_optional(pathname, out_found, out) }
        })())
    }

    /// Writes the 257 reply of the pathname at `pathname` and the text at `text` into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_reply_with_pathname(pathname: *const u8, pathname_length: usize, text: *const u8, text_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let pathname = unsafe { Pointer::text(pathname, pathname_length) }?;
            let text = unsafe { Pointer::text(text, text_length) }?;
            Pointer::check_range(out, 1)?;
            let reply = FTPReply::with_pathname(pathname, text);
            reply.check().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(FTPStatus::wire_of(&reply))) }
        })())
    }

    /// Writes the features of the reply to FEAT at `wire`, a line each of a name in upper case and its
    /// parameters, joined by LF, into `out` (RFC 2389 §3.2).
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_features_decode(wire: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let reply = FTPStatus::reply_of(unsafe { Pointer::slice(wire, length) }?)?;
            Pointer::check_range(out, 1)?;
            let features = FTPFeatures::from_reply(&reply).map_err(|error| error.to_status())?;
            let lines: Vec<Vec<u8>> = features.entries.iter().map(|feature| feature.line()[1..].to_vec()).collect();
            unsafe { Pointer::write(out, Buffer::from_vec(lines.join(&b'\n'))) }
        })())
    }

    /// Writes the address of the argument of PORT at `text` (RFC 959 §4.1.2) into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_data_address_parse_port(text: *const u8, length: usize, out: *mut FFIFTPDataAddress) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(text, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable pointer.
            let address = FTPDataAddress::parse_port(unsafe { Pointer::text(text, length) }?).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, FFIFTPDataAddress::of(&address)) }
        })())
    }

    /// Writes the argument of PORT of the IPv4 address `address` into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_data_address_format_port(address: FFIFTPDataAddress, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let text = address.address()?.format_port().map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_text(out, text) }
        })())
    }

    /// Writes the address of the argument of EPRT at `text` (RFC 2428 §2) into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_data_address_parse_eprt(text: *const u8, length: usize, out: *mut FFIFTPDataAddress) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(text, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable pointer.
            let address = FTPDataAddress::parse_eprt(unsafe { Pointer::text(text, length) }?).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, FFIFTPDataAddress::of(&address)) }
        })())
    }

    /// Writes the argument of EPRT of `address` into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_data_address_format_eprt(address: FFIFTPDataAddress, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let text = address.address()?.format_eprt().map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_text(out, text) }
        })())
    }

    /// Writes the address of the 227 reply to PASV at `wire` into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_data_address_from_pasv(wire: *const u8, length: usize, out: *mut FFIFTPDataAddress) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(wire, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let reply = FTPStatus::reply_of(unsafe { Pointer::slice(wire, length) }?)?;
            let address = FTPDataAddress::from_pasv(&reply).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, FFIFTPDataAddress::of(&address)) }
        })())
    }

    /// Writes the 227 reply to PASV of the IPv4 address `address` into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_data_address_pasv_reply(address: FFIFTPDataAddress, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let reply = address.address()?.pasv_reply().map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, Buffer::from_vec(FTPStatus::wire_of(&reply))) }
        })())
    }

    /// Writes the address (a port, no host) of the 229 reply to EPSV at `wire` into `out` (RFC 2428 §3).
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_data_address_from_epsv(wire: *const u8, length: usize, out: *mut FFIFTPDataAddress) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(wire, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let reply = FTPStatus::reply_of(unsafe { Pointer::slice(wire, length) }?)?;
            let address = FTPDataAddress::from_epsv(&reply).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, FFIFTPDataAddress::of(&address)) }
        })())
    }

    /// Writes the 229 reply to EPSV of the port of `address` into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_data_address_epsv_reply(address: FFIFTPDataAddress, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let reply = address.address()?.epsv_reply();
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, Buffer::from_vec(FTPStatus::wire_of(&reply))) }
        })())
    }

    /// Writes the seconds since 1970 and the nanoseconds of the time-val at `text` (RFC 3659 §2.3) into the outputs.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_time_parse(text: *const u8, length: usize, out_seconds: *mut i64, out_nanoseconds: *mut u32) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(text, length)],
                &[Pointer::range(out_seconds, 1), Pointer::range(out_nanoseconds, 1)],
            )?;
            // SAFETY: the caller passes readable text and writable pointers.
            let time = FTPTime::parse(unsafe { Pointer::text(text, length) }?).map_err(|error| error.to_status())?;
            Pointer::check_range(out_seconds, 1)?;
            Pointer::check_range(out_nanoseconds, 1)?;
            unsafe { Pointer::write(out_seconds, time.seconds) }?;
            unsafe { Pointer::write(out_nanoseconds, time.nanoseconds) }
        })())
    }

    /// Writes the time-val of `seconds` since 1970 and `nanoseconds` into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_time_format(seconds: i64, nanoseconds: u32, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            if nanoseconds >= 1_000_000_000 {
                return Err(&Status::INVALID_ARGUMENT);
            }
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_text(out, alloc::format!("{}", FTPTime::new(seconds, nanoseconds))) }
        })())
    }

    /// Writes the entry of facts of the line at `line` (of MLSD, RFC 3659 §7.2), as this crate writes
    /// it, its fact names in lower case, into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_facts_normalize(line: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let facts = FTPFacts::parse(unsafe { Pointer::text(line, length) }?).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, alloc::format!("{facts}")) }
        })())
    }

    /// Writes a client of a new control connection into `out`; `secure` if it is TLS from its start.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_client_new(config: FFIFTPConfig, secure: bool, now: u64, out: *mut *mut FTPClient) -> *const Status {
        Status::from_result((|| {
            let client = FTPClient::new(config.config(), secure, Instant::from_nanos(now)).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, client) }
        })())
    }

    /// Takes the `length` bytes at `data` the server sent.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_client_receive(client: *mut FTPClient, data: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            client.receive(data, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Queues the command of the line at `line`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_client_send(client: *mut FTPClient, line: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let command = FTPStatus::command_of(unsafe { Pointer::slice(line, length) }?)?;
            client.send(command, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Writes what is to be sent into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_client_transmit(client: *mut FTPClient, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let client = unsafe { Pointer::reference_mut(client) }?;
            Pointer::check_range(out, 1)?;
            let mut data = Vec::new();
            client.transmit(&mut data);
            unsafe { Pointer::write(out, Buffer::from_vec(data)) }
        })())
    }

    /// Writes whether an event is pending into `out_found` and its contents into the outputs.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_client_poll_event(client: *mut FTPClient, out_found: *mut bool, out_kind: *mut u8, out_command: *mut Buffer, out_reply: *mut Buffer, out_error: *mut *const Status) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[Pointer::range(out_found, 1), Pointer::range(out_kind, 1), Pointer::range(out_error, 1)],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let client = unsafe { Pointer::reference_mut(client) }?;
            // Every output is checked before the event is taken, so that none is lost.
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out_command, 1)?;
            Pointer::check_range(out_reply, 1)?;
            Pointer::check_range(out_error, 1)?;
            let event = client.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let event = event.map(FFIFTPEvent::of_client).unwrap_or_default();
            unsafe { event.write(out_kind, out_command, out_reply, out_error) }
        })())
    }

    /// Writes whether the client waits for a reply into `out_found` and when it times out into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_client_poll_timeout(client: *const FTPClient, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write_optional(client.poll_timeout().map(Instant::as_nanos), out_found, out) }
        })())
    }

    /// Times out what waits past `now`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_client_expire(client: *mut FTPClient, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(client) }?.expire(Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes whether the connection is open into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_client_is_open(client: *const FTPClient, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write(out, client.is_open()) }
        })())
    }

    /// Writes whether the server listed the feature of the name at `name` (RFC 2389) into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_client_has_feature(client: *const FTPClient, name: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(name, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable text and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            let name = unsafe { Pointer::text(name, length) }?;
            unsafe { Pointer::write(out, client.has_feature(name)) }
        })())
    }

    /// Releases a client. Does nothing if `client` is null.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_client_free(client: *mut FTPClient) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(client) }
    }

    /// Writes a server of a new control connection from the host of the `peer_length` (4 or 16)
    /// octets at `peer` into `out`: of `config`, the scalar fields of `server`, the system's type at
    /// `system`, and the arrays of MLST facts, other features and extension commands.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_new(config: FFIFTPConfig, server: FFIFTPServerConfig, system: *const u8, system_length: usize, facts: *const *const Char, fact_count: usize, features: *const *const Char, feature_count: usize, commands: *const *const Char, command_count: usize, peer: *const u8, peer_length: usize, secure: bool, out: *mut *mut FTPServer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and octets, arrays of strings and a writable pointer.
            let system = String::from(unsafe { Pointer::text(system, system_length) }?);
            let facts = unsafe { Pointer::strings(facts, fact_count) }?;
            let features = unsafe { Pointer::strings(features, feature_count) }?;
            let commands = unsafe { Pointer::strings(commands, command_count) }?;
            let peer = IPAddress::from_octets(unsafe { Pointer::slice(peer, peer_length) }?).map_err(|_| &Status::INVALID_ARGUMENT)?;
            let server_config = server.config(system, facts, features, commands);
            let server = FTPServer::new(config.config(), server_config, peer, secure).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, server) }
        })())
    }

    /// Sends the greeting of the reply at `wire`: 220, or 421 (RFC 959 §5.4).
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_greet(server: *mut FTPServer, wire: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let reply = FTPStatus::reply_of(unsafe { Pointer::slice(wire, length) }?)?;
            server.greet(reply, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Writes the reply to FEAT the server would send now into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_features(server: *const FTPServer, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(FTPStatus::wire_of(&server.features().reply()))) }
        })())
    }

    /// Writes whether the server takes more input now into `out`: false while what it holds of
    /// the client (pipelined commands not yet answered) reaches `maximum_buffered`, so that a
    /// peer cannot make it hold more; stop reading from the connection until it is true again.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_wants_receive(server: *const FTPServer, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, server.wants_receive()) }
        })())
    }

    /// Takes the `length` bytes at `data` the client sent.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_receive(server: *mut FTPServer, data: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            server.receive(unsafe { Pointer::slice(data, length) }?, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Answers the command told with the reply at `wire`: of a transfer, a preliminary reply (1xx)
    /// and then its final one.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_reply(server: *mut FTPServer, wire: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let reply = FTPStatus::reply_of(unsafe { Pointer::slice(wire, length) }?)?;
            server.reply(reply, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Closes the connection with 421 and the text at `text`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_shutdown(server: *mut FTPServer, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let server = unsafe { Pointer::reference_mut(server) }?;
            server.shutdown(unsafe { Pointer::text(text, length) }?);
            Ok(())
        })())
    }

    /// Writes what is to be sent into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_transmit(server: *mut FTPServer, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference_mut(server) }?;
            Pointer::check_range(out, 1)?;
            let mut data = Vec::new();
            server.transmit(&mut data);
            unsafe { Pointer::write(out, Buffer::from_vec(data)) }
        })())
    }

    /// Writes whether an event is pending into `out_found` and its contents into the outputs.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_poll_event(server: *mut FTPServer, out_found: *mut bool, out_kind: *mut u8, out_command: *mut Buffer, out_reply: *mut Buffer, out_error: *mut *const Status) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[Pointer::range(out_found, 1), Pointer::range(out_kind, 1), Pointer::range(out_error, 1)],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let server = unsafe { Pointer::reference_mut(server) }?;
            // Every output is checked before the event is taken, so that none is lost.
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out_command, 1)?;
            Pointer::check_range(out_reply, 1)?;
            Pointer::check_range(out_error, 1)?;
            let event = server.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let event = event.map(FFIFTPEvent::of_server).unwrap_or_default();
            unsafe { event.write(out_kind, out_command, out_reply, out_error) }
        })())
    }

    /// Writes whether the server waits for a command into `out_found` and until when into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_poll_timeout(server: *const FTPServer, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write_optional(server.poll_timeout().map(Instant::as_nanos), out_found, out) }
        })())
    }

    /// Closes the connection with 421 if the client was idle past its time.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_expire(server: *mut FTPServer, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(server) }?.expire(Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes whether the connection is open into `out`.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_is_open(server: *const FTPServer, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, server.is_open()) }
        })())
    }

    /// Writes what the session set into the outputs: whether a user is logged in, the
    /// representation type of TYPE (`A N`, `I` or `L 8`), the mode of MODE and the structure of
    /// STRU (as ASCII letters), the protection of data connections of PROT (`C` or `P`, RFC 4217
    /// §9), and whether a REST marker is set for the next transfer and the marker.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_session(server: *const FTPServer, out_logged_in: *mut bool, out_representation: *mut Buffer, out_mode: *mut u8, out_structure: *mut u8, out_protection: *mut u8, out_has_restart: *mut bool, out_restart: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[
                    Pointer::range(out_logged_in, 1),
                    Pointer::range(out_mode, 1),
                    Pointer::range(out_structure, 1),
                    Pointer::range(out_protection, 1),
                    Pointer::range(out_has_restart, 1),
                ],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            Pointer::check_range(out_logged_in, 1)?;
            Pointer::check_range(out_representation, 1)?;
            Pointer::check_range(out_mode, 1)?;
            Pointer::check_range(out_structure, 1)?;
            Pointer::check_range(out_protection, 1)?;
            Pointer::check_range(out_has_restart, 1)?;
            Pointer::check_range(out_restart, 1)?;
            let letter = |value: char| u8::try_from(value).unwrap_or(b'?');
            unsafe { Pointer::write(out_logged_in, server.logged_in) }?;
            unsafe { Pointer::write(out_mode, letter(server.mode)) }?;
            unsafe { Pointer::write(out_structure, letter(server.structure)) }?;
            unsafe { Pointer::write(out_protection, letter(server.protection)) }?;
            unsafe { Pointer::write_text(out_representation, server.representation.clone()) }?;
            let restart = server.restart.clone().map(|marker| Buffer::from_vec(marker.into_bytes()));
            unsafe { Pointer::write_optional(restart, out_has_restart, out_restart) }
        })())
    }

    /// Releases a server. Does nothing if `server` is null.
    pub unsafe extern "C" fn umilib_protocol_ftp_ftp_server_free(server: *mut FTPServer) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(server) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ftp",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_ftp_FTPDataAddress",
            documentation: " The address of a data connection: the first `length` (4 or 16) octets the host, none if 0.",
            fields: &[
                Parameter { name: "octets", value: <[u8; 16] as Value>::TYPE },
                Parameter { name: "length", value: Type::U8 },
                Parameter { name: "port", value: Type::U16 },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_ftp_FTPConfig",
            documentation: " The limits and times (nanoseconds) of an FTP control connection.",
            fields: &[
                Parameter { name: "maximum_line", value: Type::USize },
                Parameter { name: "maximum_reply_lines", value: Type::USize },
                Parameter { name: "maximum_buffered", value: Type::USize },
                Parameter { name: "reply_timeout", value: Type::U64 },
                Parameter { name: "idle_timeout", value: Type::U64 },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_ftp_FTPServerConfig",
            documentation: " The scalar fields of an FTP server's configuration.",
            fields: &[
                Parameter { name: "tls", value: Type::Bool },
                Parameter { name: "require_tls", value: Type::Bool },
                Parameter { name: "require_protection", value: Type::Bool },
                Parameter { name: "allow_ccc", value: Type::Bool },
                Parameter { name: "allow_foreign_data", value: Type::Bool },
                Parameter { name: "size", value: Type::Bool },
                Parameter { name: "mdtm", value: Type::Bool },
                Parameter { name: "rest_stream", value: Type::Bool },
                Parameter { name: "utf8", value: Type::Bool },
                Parameter { name: "host", value: Type::Bool },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_ftp_FTPClient",
            documentation: " An FTP client of the control connection, without I/O.",
        },
        Definition::Opaque {
            name: "umilib_protocol_ftp_FTPServer",
            documentation: " An FTP server of the control connection, without I/O.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
