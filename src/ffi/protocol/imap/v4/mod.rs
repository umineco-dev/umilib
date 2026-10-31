//! The C ABI of [`crate::protocol::imap::v4`].
//!
//! Commands and responses cross it as their logical lines on the wire
//! (RFC 9051 §2.2): a line with its literals in it (`{n}`, CRLF and the
//! octets), without the last CRLF, and mailbox names of UTF-8 as IMAP4rev2
//! writes them; the client and the server write them to the other side as
//! the session needs (modified UTF-7 for IMAP4rev1). A command given to a
//! client is its body, without a tag. Conditions are numbered 0 OK, 1 NO,
//! 2 BAD, 3 PREAUTH, 4 BYE, and states 0 Not Authenticated, 1 Authenticated,
//! 2 Selected, 3 Logout. An event is the number of its variant and its
//! contents: of a client, 0 Greeting and 1 Untagged (the response),
//! 2 Completed (the command and its tagged response), 3 AuthenticateChallenge
//! (the tag and the data), 4 Idling (the tag), 5 StartTLS, 6 Closed (its
//! error, or null); of a server, 0 Command (the command), 1
//! AuthenticateResponse (the tag and the data), 2 AuthenticateCancelled and
//! 3 IdleDone (the tag), 4 StartTLS, 5 Closed. Times are nanoseconds of the
//! caller's monotonic clock.

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use crate::codec::mail::{MIMEEntity, MailConfig, MailFields};
use crate::ffi::{Buffer, Char, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::imap::v4::{
    IMAPBody, IMAPClient, IMAPClientEvent, IMAPCommand, IMAPCommandBody, IMAPCondition, IMAPConfig, IMAPDateTime,
    IMAPEnvelope, IMAPError, IMAPLiteralMode, IMAPMailbox, IMAPReader, IMAPResponse, IMAPResponseCode, IMAPSection,
    IMAPSequenceSet, IMAPServer, IMAPServerConfig, IMAPServerEvent, IMAPState, IMAPWriter,
};
use crate::runtime::Instant;

/// The statuses of [`IMAPError`], one per variant.
pub struct IMAPStatus;

impl IMAPStatus {
    pub const SYNTAX: Status = Status::new(c"protocol.imap.v4", c"Syntax", c"text not of the grammar of RFC 9051");
    pub const TOO_LONG: Status = Status::new(
        c"protocol.imap.v4",
        c"TooLong",
        c"a line, a literal or a command longer than the configuration takes",
    );
    pub const STATE: Status =
        Status::new(c"protocol.imap.v4", c"State", c"not in this state, or of a capability not announced");
    pub const TIMEOUT: Status = Status::new(c"protocol.imap.v4", c"Timeout", c"no response in time");
    pub const CLOSED: Status = Status::new(c"protocol.imap.v4", c"Closed", c"the connection is closed");
    pub const UNKNOWN_VALUE: Status = Status::new(c"protocol.imap.v4", c"UnknownValue", c"a number of no condition");

    /// The depth of lists the text at the boundary may have.
    pub const MAXIMUM_DEPTH: usize = 64;

    /// The logical line of what `write` writes, without its last CRLF.
    pub fn line(write: impl FnOnce(&mut IMAPWriter)) -> Vec<u8> {
        let mut writer = IMAPWriter::new(IMAPLiteralMode::Server, true);
        write(&mut writer);
        let mut out = writer.out;
        if out.ends_with(b"\r\n") {
            out.truncate(out.len() - 2);
        }
        out
    }

    pub fn command_line(command: &IMAPCommand) -> Vec<u8> {
        IMAPStatus::line(|writer| command.write(writer))
    }

    pub fn response_line(response: &IMAPResponse) -> Vec<u8> {
        IMAPStatus::line(|writer| response.write(writer))
    }

    pub fn command_of(line: &[u8]) -> Result<IMAPCommand, &'static Status> {
        IMAPCommand::parse(line, true, IMAPStatus::MAXIMUM_DEPTH).map_err(|error| error.to_status())
    }

    /// The body of a command given without its tag.
    pub fn body_of(line: &[u8]) -> Result<IMAPCommandBody, &'static Status> {
        let tagged = [&b"X "[..], line].concat();
        Ok(IMAPStatus::command_of(&tagged)?.body)
    }

    pub fn response_of(line: &[u8]) -> Result<IMAPResponse, &'static Status> {
        let response = IMAPResponse::parse(line, true, IMAPStatus::MAXIMUM_DEPTH).map_err(|error| error.to_status())?;
        response.check().map_err(|error| error.to_status())?;
        Ok(response)
    }

    /// The response code of its text, its brackets included; none if empty.
    pub fn code_of(text: &[u8]) -> Result<Option<IMAPResponseCode>, &'static Status> {
        if text.is_empty() {
            return Ok(None);
        }
        let mut reader = IMAPReader::new(text, IMAPStatus::MAXIMUM_DEPTH);
        let code = IMAPResponseCode::read(&mut reader).map_err(|error| error.to_status())?;
        reader.end().map_err(|error| error.to_status())?;
        Ok(Some(code))
    }

    pub fn code_line(code: &IMAPResponseCode) -> Vec<u8> {
        IMAPStatus::line(|writer| code.write(writer))
    }

    pub fn condition_of(number: u8) -> Result<IMAPCondition, &'static Status> {
        match number {
            0 => Ok(IMAPCondition::OK),
            1 => Ok(IMAPCondition::NO),
            2 => Ok(IMAPCondition::BAD),
            3 => Ok(IMAPCondition::PREAUTH),
            4 => Ok(IMAPCondition::BYE),
            _ => Err(&IMAPStatus::UNKNOWN_VALUE),
        }
    }

    pub fn condition_number(condition: IMAPCondition) -> u8 {
        match condition {
            IMAPCondition::OK => 0,
            IMAPCondition::NO => 1,
            IMAPCondition::BAD => 2,
            IMAPCondition::PREAUTH => 3,
            IMAPCondition::BYE => 4,
        }
    }

    pub fn state_number(state: IMAPState) -> u8 {
        match state {
            IMAPState::NotAuthenticated => 0,
            IMAPState::Authenticated => 1,
            IMAPState::Selected => 2,
            IMAPState::Logout => 3,
        }
    }

    /// The entity of the message at `message`, of `config`.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn entity<'a>(
        message: *const u8,
        length: usize,
        config: &MailConfig,
    ) -> Result<(&'a [u8], MIMEEntity), &'static Status> {
        // SAFETY: guaranteed by the caller.
        let text = unsafe { Pointer::slice(message, length) }?;
        let entity = MIMEEntity::decode(text, config).map_err(|error| error.to_status())?;
        Ok((text, entity))
    }
}

impl ToStatus for IMAPError {
    fn to_status(&self) -> &'static Status {
        match self {
            IMAPError::Syntax { .. } => &IMAPStatus::SYNTAX,
            IMAPError::TooLong { .. } => &IMAPStatus::TOO_LONG,
            IMAPError::State { .. } => &IMAPStatus::STATE,
            IMAPError::Timeout => &IMAPStatus::TIMEOUT,
            IMAPError::Closed => &IMAPStatus::CLOSED,
        }
    }
}

/// [`IMAPConfig`] in the C ABI: the times in nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIIMAPConfig {
    pub maximum_line: usize,
    pub maximum_literal: u64,
    pub maximum_command: u64,
    pub maximum_depth: usize,
    pub maximum_buffered: usize,
    pub command_timeout: u64,
    pub autologout: u64,
    pub login_timeout: u64,
    pub passwords_require_tls: bool,
}

impl FFIIMAPConfig {
    pub fn of(config: &IMAPConfig) -> FFIIMAPConfig {
        let nanoseconds = |duration: Duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        FFIIMAPConfig {
            maximum_line: config.maximum_line,
            maximum_literal: config.maximum_literal,
            maximum_command: config.maximum_command,
            maximum_depth: config.maximum_depth,
            maximum_buffered: config.maximum_buffered,
            command_timeout: nanoseconds(config.command_timeout),
            autologout: nanoseconds(config.autologout),
            login_timeout: nanoseconds(config.login_timeout),
            passwords_require_tls: config.passwords_require_tls,
        }
    }

    pub fn config(&self) -> IMAPConfig {
        IMAPConfig {
            maximum_line: self.maximum_line,
            maximum_literal: self.maximum_literal,
            maximum_command: self.maximum_command,
            maximum_depth: self.maximum_depth,
            maximum_buffered: self.maximum_buffered,
            command_timeout: Duration::from_nanos(self.command_timeout),
            autologout: Duration::from_nanos(self.autologout),
            login_timeout: Duration::from_nanos(self.login_timeout),
            passwords_require_tls: self.passwords_require_tls,
        }
    }
}

/// The scalar fields of [`IMAPServerConfig`] in the C ABI; its lists are given beside it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIIMAPServerConfig {
    pub rev1: bool,
    pub starttls: bool,
    pub passwords_require_tls: bool,
    pub literal_plus: bool,
}

impl FFIIMAPServerConfig {
    pub fn of(config: &IMAPServerConfig) -> FFIIMAPServerConfig {
        FFIIMAPServerConfig {
            rev1: config.rev1,
            starttls: config.starttls,
            passwords_require_tls: config.passwords_require_tls,
            literal_plus: config.literal_plus,
        }
    }

    pub fn config(
        &self,
        mechanisms: Vec<String>,
        plaintext: Vec<String>,
        capabilities: Vec<String>,
        commands: Vec<String>,
    ) -> IMAPServerConfig {
        IMAPServerConfig {
            rev1: self.rev1,
            starttls: self.starttls,
            auth_mechanisms: mechanisms,
            plaintext_mechanisms: plaintext,
            passwords_require_tls: self.passwords_require_tls,
            literal_plus: self.literal_plus,
            capabilities,
            commands,
        }
    }
}

/// The contents of an event, as the C ABI gives them.
#[derive(Clone, Debug, Default)]
pub struct FFIIMAPEvent {
    pub kind: u8,
    pub tag: String,
    pub command: Vec<u8>,
    pub response: Vec<u8>,
    pub data: Vec<u8>,
    pub error: Option<&'static Status>,
}

impl FFIIMAPEvent {
    pub fn of_client(event: IMAPClientEvent) -> FFIIMAPEvent {
        let mut out = FFIIMAPEvent::default();
        match event {
            IMAPClientEvent::Greeting(response) => out.response = IMAPStatus::response_line(&response),
            IMAPClientEvent::Untagged(response) => {
                out.kind = 1;
                out.response = IMAPStatus::response_line(&response);
            }
            IMAPClientEvent::Completed { command, condition, code, text } => {
                out.kind = 2;
                out.response = IMAPStatus::response_line(&IMAPResponse::tagged(&command.tag, condition, code, &text));
                out.command = IMAPStatus::command_line(&command);
                out.tag = command.tag;
            }
            IMAPClientEvent::AuthenticateChallenge { tag, data } => {
                out.kind = 3;
                out.tag = tag;
                out.data = data;
            }
            IMAPClientEvent::Idling { tag } => {
                out.kind = 4;
                out.tag = tag;
            }
            IMAPClientEvent::StartTLS => out.kind = 5,
            IMAPClientEvent::Closed { error } => {
                out.kind = 6;
                out.error = error.map(|error| error.to_status());
            }
        }
        out
    }

    pub fn of_server(event: IMAPServerEvent) -> FFIIMAPEvent {
        let mut out = FFIIMAPEvent::default();
        match event {
            IMAPServerEvent::Command(command) => {
                out.command = IMAPStatus::command_line(&command);
                out.tag = command.tag;
            }
            IMAPServerEvent::AuthenticateResponse { tag, data } => {
                out.kind = 1;
                out.tag = tag;
                out.data = data;
            }
            IMAPServerEvent::AuthenticateCancelled { tag } => {
                out.kind = 2;
                out.tag = tag;
            }
            IMAPServerEvent::IdleDone { tag } => {
                out.kind = 3;
                out.tag = tag;
            }
            IMAPServerEvent::StartTLS => out.kind = 4,
            IMAPServerEvent::Closed { error } => {
                out.kind = 5;
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
        out_tag: *mut Buffer,
        out_command: *mut Buffer,
        out_response: *mut Buffer,
        out_data: *mut Buffer,
        out_error: *mut *const Status,
    ) -> Result<(), &'static Status> {
        Pointer::check_range(out_kind, 1)?;
        Pointer::check_range(out_tag, 1)?;
        Pointer::check_range(out_command, 1)?;
        Pointer::check_range(out_response, 1)?;
        Pointer::check_range(out_data, 1)?;
        Pointer::check_range(out_error, 1)?;
        // SAFETY: guaranteed by the caller; the ranges were checked.
        unsafe { Pointer::write(out_kind, self.kind) }?;
        unsafe { Pointer::write(out_error, self.error.map_or(core::ptr::null(), |error| error as *const Status)) }?;
        unsafe { Pointer::write_text(out_tag, self.tag) }?;
        unsafe { Pointer::write(out_command, Buffer::from_vec(self.command)) }?;
        unsafe { Pointer::write(out_response, Buffer::from_vec(self.response)) }?;
        unsafe { Pointer::write(out_data, Buffer::from_vec(self.data)) }
    }
}

impl Value for FFIIMAPConfig {
    const TYPE: Type = Type::Named("umilib_protocol_imap_v4_IMAPConfig");
}

impl Value for FFIIMAPServerConfig {
    const TYPE: Type = Type::Named("umilib_protocol_imap_v4_IMAPServerConfig");
}

impl Value for IMAPClient {
    const TYPE: Type = Type::Named("umilib_protocol_imap_v4_IMAPClient");
}

impl Value for IMAPServer {
    const TYPE: Type = Type::Named("umilib_protocol_imap_v4_IMAPServer");
}

crate::ffi_functions! {
    /// Writes the default configuration (the timers of RFC 9051 §5.4) into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_config_default(out: *mut FFIIMAPConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFIIMAPConfig::of(&IMAPConfig::default())) })
    }

    /// Writes the default scalar fields of a server's configuration into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_config_default(out: *mut FFIIMAPServerConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFIIMAPServerConfig::of(&IMAPServerConfig::default())) })
    }

    /// Writes the logical line of the command at `line` (a tag and a command), as this crate writes
    /// it, into `out`, its name (in upper case; `UID` and the command after it for one of UIDs) into
    /// `out_name` and its tag into `out_tag`; fails for a line that is not a command.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_command_normalize(line: *const u8, length: usize, out_tag: *mut Buffer, out_name: *mut Buffer, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and writable pointers.
            let line = unsafe { Pointer::slice(line, length) }?;
            Pointer::check_range(out_tag, 1)?;
            Pointer::check_range(out_name, 1)?;
            Pointer::check_range(out, 1)?;
            let command = IMAPStatus::command_of(line)?;
            unsafe { Pointer::write_text(out_name, String::from(command.body.name())) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(IMAPStatus::command_line(&command))) }?;
            unsafe { Pointer::write_text(out_tag, command.tag) }
        })())
    }

    /// Writes the logical line of the response at `line`, as this crate writes it, into `out`; fails
    /// for a line that is not a response.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_response_normalize(line: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let response = IMAPStatus::response_of(unsafe { Pointer::slice(line, length) }?)?;
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write(out, Buffer::from_vec(IMAPStatus::response_line(&response))) }
        })())
    }

    /// Writes whether the response at `line` is a status response (RFC 9051 §7.1) into `out_status`,
    /// and then whether it is tagged into `out_tagged`, its tag into `out_tag`, its condition into
    /// `out_condition`, its response code (brackets included; empty if none) into `out_code` and its
    /// text into `out_text`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_response_status(line: *const u8, length: usize, out_status: *mut bool, out_tagged: *mut bool, out_tag: *mut Buffer, out_condition: *mut u8, out_code: *mut Buffer, out_text: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(line, length)],
                &[Pointer::range(out_status, 1), Pointer::range(out_tagged, 1), Pointer::range(out_condition, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let response = IMAPStatus::response_of(unsafe { Pointer::slice(line, length) }?)?;
            for out in [out_tag, out_code, out_text] {
                Pointer::check_range(out, 1)?;
            }
            Pointer::check_range(out_status, 1)?;
            Pointer::check_range(out_tagged, 1)?;
            Pointer::check_range(out_condition, 1)?;
            let (status, tag, condition, code, text) = match response {
                IMAPResponse::Status { tag, condition, code, text } => (true, tag, condition, code, text),
                _ => (false, None, IMAPCondition::OK, None, String::new()),
            };
            unsafe { Pointer::write(out_status, status) }?;
            unsafe { Pointer::write(out_tagged, tag.is_some()) }?;
            unsafe { Pointer::write(out_condition, IMAPStatus::condition_number(condition)) }?;
            unsafe { Pointer::write_text(out_tag, tag.unwrap_or_default()) }?;
            unsafe { Pointer::write(out_code, Buffer::from_vec(code.as_ref().map(IMAPStatus::code_line).unwrap_or_default())) }?;
            unsafe { Pointer::write_text(out_text, text) }
        })())
    }

    /// Writes the logical line of the status response of the tag at `tag` (untagged if none), the
    /// condition `condition`, the response code at `code` (brackets included; none if empty) and
    /// the text at `text` into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_response_status_encode(tag: *const u8, tag_length: usize, condition: u8, code: *const u8, code_length: usize, text: *const u8, text_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let tag = unsafe { Pointer::optional_text(tag, tag_length) }?.map(String::from);
            let code = IMAPStatus::code_of(unsafe { Pointer::slice(code, code_length) }?)?;
            let text = String::from(unsafe { Pointer::text(text, text_length) }?);
            Pointer::check_range(out, 1)?;
            let response = IMAPResponse::Status { tag, condition: IMAPStatus::condition_of(condition)?, code, text };
            response.check().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(IMAPStatus::response_line(&response))) }
        })())
    }

    /// Writes the mailbox name of the UTF-8 text at `text` in modified UTF-7 (RFC 3501 §5.1.3) into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_mailbox_encode_modified_utf7(text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            unsafe { Pointer::write_text(out, IMAPMailbox::encode_modified_utf7(text)) }
        })())
    }

    /// Writes the UTF-8 text of the mailbox name in modified UTF-7 at `name` into `out`; fails for
    /// one that is not of modified UTF-7.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_mailbox_decode_modified_utf7(name: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let name = unsafe { Pointer::slice(name, length) }?;
            Pointer::check_range(out, 1)?;
            let text = IMAPMailbox::decode_modified_utf7(name).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, text) }
        })())
    }

    /// Writes the sequence set at `text` (RFC 9051 §9), as this crate writes it, into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_sequence_set_normalize(text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            Pointer::check_range(out, 1)?;
            let set = IMAPSequenceSet::parse(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, alloc::format!("{set}")) }
        })())
    }

    /// Writes the ranges of the sequence set at `text` when `last` is the highest number (`*`), in
    /// order and merged, as `a:b` or `a` joined by `,`, into `out`; empty for `$`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_sequence_set_resolve(text: *const u8, length: usize, last: u32, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            Pointer::check_range(out, 1)?;
            let set = IMAPSequenceSet::parse(text).map_err(|error| error.to_status())?;
            let ranges: Vec<String> = set
                .resolve(last)
                .iter()
                .map(|range| match range.start() == range.end() {
                    true => alloc::format!("{}", range.start()),
                    false => alloc::format!("{}:{}", range.start(), range.end()),
                })
                .collect();
            unsafe { Pointer::write_text(out, ranges.join(",")) }
        })())
    }

    /// Writes whether `number` is of the sequence set at `text` when `last` is the highest number into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_sequence_set_contains(text: *const u8, length: usize, number: u32, last: u32, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(text, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            let set = IMAPSequenceSet::parse(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, set.contains(number, last)) }
        })())
    }

    /// Writes the seconds since 1970 and the offset in minutes of the date-time at `text` (RFC 9051
    /// §9 `date-time`, with its quotes) into the outputs.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_date_time_parse(text: *const u8, length: usize, out_seconds: *mut i64, out_offset: *mut i16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(text, length)],
                &[Pointer::range(out_seconds, 1), Pointer::range(out_offset, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let text = unsafe { Pointer::slice(text, length) }?;
            Pointer::check_range(out_seconds, 1)?;
            Pointer::check_range(out_offset, 1)?;
            let mut reader = IMAPReader::new(text, IMAPStatus::MAXIMUM_DEPTH);
            let date = IMAPDateTime::read(&mut reader).map_err(|error| error.to_status())?;
            reader.end().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_seconds, date.seconds) }?;
            unsafe { Pointer::write(out_offset, date.offset) }
        })())
    }

    /// Writes the date-time of `seconds` since 1970 at the offset `offset` in minutes, with its
    /// quotes, into `out`; `InvalidArgument` for a date-time of a year outside 0000 to 9999 or a
    /// zone beyond 99 hours, which the syntax cannot write.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_date_time_format(seconds: i64, offset: i16, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let date = IMAPDateTime::new(seconds, offset);
            if !date.is_valid() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_text(out, alloc::format!("{date}")) }
        })())
    }

    /// Writes the ENVELOPE (RFC 9051 §7.5.2) of the message at `message`, of `config`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_envelope_of_message(message: *const u8, length: usize, config: MailConfig, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let message = unsafe { Pointer::slice(message, length) }?;
            Pointer::check_range(out, 1)?;
            let (fields, _) = MailFields::decode(message, &config).map_err(|error| error.to_status())?;
            let envelope = IMAPEnvelope::from_fields(&fields);
            unsafe { Pointer::write(out, Buffer::from_vec(IMAPStatus::line(|writer| envelope.write(writer)))) }
        })())
    }

    /// Writes the BODYSTRUCTURE (RFC 9051 §7.5.2) of the message at `message`, of `config`, into
    /// `out`; without extension data (BODY) unless `extensible`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_body_of_message(message: *const u8, length: usize, config: MailConfig, extensible: bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let (text, entity) = unsafe { IMAPStatus::entity(message, length, &config) }?;
            Pointer::check_range(out, 1)?;
            let body = IMAPBody::from_entity(&entity, text, extensible);
            unsafe { Pointer::write(out, Buffer::from_vec(IMAPStatus::line(|writer| body.write(writer)))) }
        })())
    }

    /// Writes whether the message at `message`, of `config`, has the section at `section` (RFC 9051
    /// §6.4.5, with its brackets: `[1.HEADER]`) into `out_found`, and its octets into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_section_extract(section: *const u8, section_length: usize, message: *const u8, length: usize, config: MailConfig, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(section, section_length), Pointer::range(message, length)],
                &[Pointer::range(out_found, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let section = unsafe { Pointer::slice(section, section_length) }?;
            let (text, entity) = unsafe { IMAPStatus::entity(message, length, &config) }?;
            let mut reader = IMAPReader::new(section, IMAPStatus::MAXIMUM_DEPTH);
            let section = IMAPSection::read(&mut reader, false).map_err(|error| error.to_status())?;
            reader.end().map_err(|error| error.to_status())?;
            let data = section.extract(&entity, text).map(Buffer::from_vec);
            unsafe { Pointer::write_optional(data, out_found, out) }
        })())
    }

    /// Writes a client of a new connection into `out`: `secure` if it is TLS from its start (RFC
    /// 8314), its tags the text at `prefix` and a number.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_new(config: FFIIMAPConfig, secure: bool, prefix: *const u8, prefix_length: usize, now: u64, out: *mut *mut IMAPClient) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let prefix = unsafe { Pointer::text(prefix, prefix_length) }?;
            let client = IMAPClient::new(config.config(), secure, prefix, Instant::from_nanos(now)).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, client) }
        })())
    }

    /// Takes the `length` bytes at `data` the server sent.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_receive(client: *mut IMAPClient, data: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            client.receive(data, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Queues the command of the body at `body` (a command without its tag) and writes its tag into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_send(client: *mut IMAPClient, body: *const u8, length: usize, now: u64, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let body = IMAPStatus::body_of(unsafe { Pointer::slice(body, length) }?)?;
            Pointer::check_range(out, 1)?;
            let tag = client.send(body, Instant::from_nanos(now)).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, tag) }
        })())
    }

    /// Queues the command of the body at `body` with the tag at `tag`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_send_with_tag(client: *mut IMAPClient, tag: *const u8, tag_length: usize, body: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let tag = unsafe { Pointer::text(tag, tag_length) }?;
            let body = IMAPStatus::body_of(unsafe { Pointer::slice(body, length) }?)?;
            client.send_with_tag(tag, body, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Answers an AUTHENTICATE challenge with the bytes at `response`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_authenticate_respond(client: *mut IMAPClient, response: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let response = unsafe { Pointer::slice(response, length) }?;
            client.authenticate_respond(response, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Cancels an AUTHENTICATE exchange with `*` (RFC 9051 §6.2.2).
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_authenticate_cancel(client: *mut IMAPClient, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let client = unsafe { Pointer::reference_mut(client) }?;
            client.authenticate_cancel(Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Ends IDLE with DONE (RFC 9051 §6.3.13).
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_idle_done(client: *mut IMAPClient, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let client = unsafe { Pointer::reference_mut(client) }?;
            client.idle_done(Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Takes the `count` capabilities at `capabilities` as those the server announced.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_learn_capabilities(client: *mut IMAPClient, capabilities: *const *const Char, count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and an array of strings.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let capabilities = unsafe { Pointer::strings(capabilities, count) }?;
            client.learn_capabilities(&capabilities);
            Ok(())
        })())
    }

    /// Writes whether the server announced the capability at `capability` into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_has_capability(client: *const IMAPClient, capability: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(capability, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable text and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            let capability = unsafe { Pointer::text(capability, length) }?;
            unsafe { Pointer::write(out, client.has_capability(capability)) }
        })())
    }

    /// Writes the session's state into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_state(client: *const IMAPClient, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write(out, IMAPStatus::state_number(client.state)) }
        })())
    }

    /// Writes what is to be sent into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_transmit(client: *mut IMAPClient, out: *mut Buffer) -> *const Status {
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
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_poll_event(client: *mut IMAPClient, out_found: *mut bool, out_kind: *mut u8, out_tag: *mut Buffer, out_command: *mut Buffer, out_response: *mut Buffer, out_data: *mut Buffer, out_error: *mut *const Status) -> *const Status {
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
            Pointer::check_range(out_tag, 1)?;
            Pointer::check_range(out_command, 1)?;
            Pointer::check_range(out_response, 1)?;
            Pointer::check_range(out_data, 1)?;
            Pointer::check_range(out_error, 1)?;
            let event = client.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let event = event.map(FFIIMAPEvent::of_client).unwrap_or_default();
            unsafe { event.write(out_kind, out_tag, out_command, out_response, out_data, out_error) }
        })())
    }

    /// Writes whether the client waits for a response into `out_found` and when it times out into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_poll_timeout(client: *const IMAPClient, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write_optional(client.poll_timeout().map(Instant::as_nanos), out_found, out) }
        })())
    }

    /// Times out what waits past `now`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_expire(client: *mut IMAPClient, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(client) }?.expire(Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes whether the connection is open into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_is_open(client: *const IMAPClient, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write(out, client.is_open()) }
        })())
    }

    /// Releases a client. Does nothing if `client` is null.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_client_free(client: *mut IMAPClient) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(client) }
    }

    /// Writes a server of a new connection into `out`: of `config`, the scalar fields of `server`,
    /// and the arrays of SASL mechanisms, plaintext mechanisms, other capabilities and extension commands.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_new(config: FFIIMAPConfig, server: FFIIMAPServerConfig, mechanisms: *const *const Char, mechanism_count: usize, plaintext: *const *const Char, plaintext_count: usize, capabilities: *const *const Char, capability_count: usize, commands: *const *const Char, command_count: usize, secure: bool, out: *mut *mut IMAPServer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes arrays of strings and a writable pointer.
            let mechanisms = unsafe { Pointer::strings(mechanisms, mechanism_count) }?;
            let plaintext = unsafe { Pointer::strings(plaintext, plaintext_count) }?;
            let capabilities = unsafe { Pointer::strings(capabilities, capability_count) }?;
            let commands = unsafe { Pointer::strings(commands, command_count) }?;
            let server_config = server.config(mechanisms, plaintext, capabilities, commands);
            let server = IMAPServer::new(config.config(), server_config, secure).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, server) }
        })())
    }

    /// Sends the greeting of `condition` (OK, PREAUTH or BYE) and the text at `text`, with the
    /// capabilities (RFC 9051 §7.1).
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_greet(server: *mut IMAPServer, condition: u8, text: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let text = unsafe { Pointer::text(text, length) }?;
            server.greet(IMAPStatus::condition_of(condition)?, text, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Writes the capabilities the server announces now, joined by spaces, into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_capabilities(server: *const IMAPServer, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write_text(out, server.capabilities().join(" ")) }
        })())
    }

    /// Writes whether passwords sent as they are are taken now (RFC 9051 §6.2.3) into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_passwords_taken(server: *const IMAPServer, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, server.passwords_taken()) }
        })())
    }

    /// Writes whether IMAP4rev2 is in use (the server offers it alone, or the client enabled it)
    /// into `out`: SEARCH is answered with ESEARCH and RECENT is not sent then.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_rev2(server: *const IMAPServer, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, server.rev2) }
        })())
    }

    /// Writes the session's state into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_state(server: *const IMAPServer, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, IMAPStatus::state_number(server.state)) }
        })())
    }

    /// Writes whether the server takes more input now into `out`: false while what it holds of
    /// the client (pipelined commands not yet answered) reaches `maximum_buffered`, so that a
    /// peer cannot make it hold more; stop reading from the connection until it is true again.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_wants_receive(server: *const IMAPServer, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, server.wants_receive()) }
        })())
    }

    /// Takes the `length` bytes at `data` the client sent.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_receive(server: *mut IMAPServer, data: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            server.receive(unsafe { Pointer::slice(data, length) }?, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Sends the untagged response at `line` of the command told.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_respond(server: *mut IMAPServer, line: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let response = IMAPStatus::response_of(unsafe { Pointer::slice(line, length) }?)?;
            server.respond(&response).map_err(|error| error.to_status())
        })())
    }

    /// Completes the command told with its tagged response of `condition` (OK, NO or BAD), the response
    /// code at `code` (brackets included; none if empty) and the text at `text` (RFC 9051 §7.1).
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_complete(server: *mut IMAPServer, condition: u8, code: *const u8, code_length: usize, text: *const u8, text_length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let code = IMAPStatus::code_of(unsafe { Pointer::slice(code, code_length) }?)?;
            let text = unsafe { Pointer::text(text, text_length) }?;
            server.complete(IMAPStatus::condition_of(condition)?, code, text, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Sends the bytes at `challenge` as a challenge of the AUTHENTICATE told.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_authenticate_challenge(server: *mut IMAPServer, challenge: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let challenge = unsafe { Pointer::slice(challenge, length) }?;
            server.authenticate_challenge(challenge, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Accepts the IDLE told with a continuation request of the text at `text` (RFC 9051 §6.3.13).
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_idle(server: *mut IMAPServer, text: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let text = unsafe { Pointer::text(text, length) }?;
            server.idle(text, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Closes the connection with an untagged BYE of the text at `text` (RFC 9051 §7.1.5).
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_shutdown(server: *mut IMAPServer, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let server = unsafe { Pointer::reference_mut(server) }?;
            server.shutdown(unsafe { Pointer::text(text, length) }?).map_err(|error| error.to_status())
        })())
    }

    /// Writes what is to be sent into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_transmit(server: *mut IMAPServer, out: *mut Buffer) -> *const Status {
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
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_poll_event(server: *mut IMAPServer, out_found: *mut bool, out_kind: *mut u8, out_tag: *mut Buffer, out_command: *mut Buffer, out_response: *mut Buffer, out_data: *mut Buffer, out_error: *mut *const Status) -> *const Status {
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
            Pointer::check_range(out_tag, 1)?;
            Pointer::check_range(out_command, 1)?;
            Pointer::check_range(out_response, 1)?;
            Pointer::check_range(out_data, 1)?;
            Pointer::check_range(out_error, 1)?;
            let event = server.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let event = event.map(FFIIMAPEvent::of_server).unwrap_or_default();
            unsafe { event.write(out_kind, out_tag, out_command, out_response, out_data, out_error) }
        })())
    }

    /// Writes whether the server waits for the client into `out_found` and until when (the
    /// autologout timer, RFC 9051 §5.4) into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_poll_timeout(server: *const IMAPServer, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write_optional(server.poll_timeout().map(Instant::as_nanos), out_found, out) }
        })())
    }

    /// Closes the connection with BYE if the client was silent past its time.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_expire(server: *mut IMAPServer, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(server) }?.expire(Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes whether the connection is open into `out`.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_is_open(server: *const IMAPServer, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, server.is_open()) }
        })())
    }

    /// Releases a server. Does nothing if `server` is null.
    pub unsafe extern "C" fn umilib_protocol_imap_v4_imap_server_free(server: *mut IMAPServer) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(server) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v4",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_imap_v4_IMAPConfig",
            documentation: " The limits and times (nanoseconds) of an IMAP connection.",
            fields: &[
                Parameter { name: "maximum_line", value: Type::USize },
                Parameter { name: "maximum_literal", value: Type::U64 },
                Parameter { name: "maximum_command", value: Type::U64 },
                Parameter { name: "maximum_depth", value: Type::USize },
                Parameter { name: "maximum_buffered", value: Type::USize },
                Parameter { name: "command_timeout", value: Type::U64 },
                Parameter { name: "autologout", value: Type::U64 },
                Parameter { name: "login_timeout", value: Type::U64 },
                Parameter { name: "passwords_require_tls", value: Type::Bool },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_imap_v4_IMAPServerConfig",
            documentation: " The scalar fields of an IMAP server's configuration.",
            fields: &[
                Parameter { name: "rev1", value: Type::Bool },
                Parameter { name: "starttls", value: Type::Bool },
                Parameter { name: "passwords_require_tls", value: Type::Bool },
                Parameter { name: "literal_plus", value: Type::Bool },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_imap_v4_IMAPClient",
            documentation: " An IMAP client without I/O.",
        },
        Definition::Opaque {
            name: "umilib_protocol_imap_v4_IMAPServer",
            documentation: " An IMAP server without I/O.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
