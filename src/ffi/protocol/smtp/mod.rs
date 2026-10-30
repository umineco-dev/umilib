//! The C ABI of [`crate::protocol::smtp`].
//!
//! Commands and replies cross it as their text on the wire: a command
//! line without its CRLF, a reply of its lines with their CRLFs. The
//! configurations are structures (times in nanoseconds), the lists of a
//! server's configuration (its mechanisms, the plaintext ones, the
//! commands of its extensions) arrays of text. An event is the number of
//! its variant and its contents: of a client, 0 Greeting, 1 Reply (its
//! command), 2 DataReply, 3 AuthChallenge (its data), 4 StartTLS, 5 Closed
//! (its error, or null); of a server, 0 Command, 1 Data, 2 DataEnd (`last`),
//! 3 DataRejected (its error), 4 AuthResponse, 5 AuthCancelled, 6 Reset,
//! 7 StartTLS, 8 Closed, 9 AuthFailed. Times are nanoseconds of the caller's monotonic clock.

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use crate::ffi::{Buffer, Char, Definition, Function, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::smtp::{
    SMTPClient, SMTPClientEvent, SMTPCommand, SMTPConfig, SMTPData, SMTPDataReader, SMTPEnhancedStatus, SMTPError,
    SMTPExtensions, SMTPMailbox, SMTPReply, SMTPReplyReader, SMTPServer, SMTPServerConfig, SMTPServerEvent, SMTPXText,
};
use crate::runtime::Instant;

#[cfg(umilib_feature = "protocol-dns")]
pub mod route;

/// The functions of the choice of mail hosts, of MX records.
#[cfg(umilib_feature = "protocol-dns")]
pub const ROUTE: &[Function] = route::FUNCTIONS;
#[cfg(not(umilib_feature = "protocol-dns"))]
pub const ROUTE: &[Function] = &[];

/// The statuses of [`SMTPError`], one per variant.
pub struct SMTPStatus;

impl SMTPStatus {
    pub const SYNTAX: Status = Status::new(c"protocol.smtp", c"Syntax", c"text not of the grammar of SMTP");
    pub const TOO_LONG: Status =
        Status::new(c"protocol.smtp", c"TooLong", c"a line longer than the configuration takes");
    pub const TOO_LARGE: Status = Status::new(c"protocol.smtp", c"TooLarge", c"a message larger than is taken");
    pub const STATE: Status =
        Status::new(c"protocol.smtp", c"State", c"not in this state, or of an extension not advertised");
    pub const CONTENT: Status = Status::new(c"protocol.smtp", c"Content", c"a message not of its body type");
    pub const TIMEOUT: Status = Status::new(c"protocol.smtp", c"Timeout", c"no reply in time");
    pub const CLOSED: Status = Status::new(c"protocol.smtp", c"Closed", c"the connection is closed");
    pub const NO_MAIL: Status = Status::new(c"protocol.smtp", c"NoMail", c"the domain takes no mail");

    /// The reply of its text on the wire: its lines, each with its CRLF.
    pub fn reply_of(wire: &[u8], maximum_lines: usize) -> Result<SMTPReply, &'static Status> {
        let mut reader = SMTPReplyReader::new();
        let mut lines = wire.split(|byte| *byte == b'\n').peekable();
        while let Some(line) = lines.next() {
            if line.is_empty() && lines.peek().is_none() {
                break;
            }
            let line = line.strip_suffix(b"\r").ok_or(&SMTPStatus::SYNTAX)?;
            if let Some(reply) = reader.push(line, maximum_lines).map_err(|error| error.to_status())? {
                return match lines.all(|rest| rest.is_empty()) {
                    true => Ok(reply),
                    false => Err(&SMTPStatus::SYNTAX),
                };
            }
        }
        Err(&SMTPStatus::SYNTAX)
    }

    /// The text on the wire of `reply`.
    pub fn wire_of(reply: &SMTPReply) -> Vec<u8> {
        let mut out = Vec::new();
        reply.encode(&mut out);
        out
    }

    /// The command line of `command`.
    pub fn line_of(command: &SMTPCommand) -> Vec<u8> {
        alloc::format!("{command}").into_bytes()
    }
}

impl ToStatus for SMTPError {
    fn to_status(&self) -> &'static Status {
        match self {
            SMTPError::Syntax { .. } => &SMTPStatus::SYNTAX,
            SMTPError::TooLong { .. } => &SMTPStatus::TOO_LONG,
            SMTPError::TooLarge { .. } => &SMTPStatus::TOO_LARGE,
            SMTPError::State { .. } => &SMTPStatus::STATE,
            SMTPError::Content { .. } => &SMTPStatus::CONTENT,
            SMTPError::Timeout => &SMTPStatus::TIMEOUT,
            SMTPError::Closed => &SMTPStatus::CLOSED,
            SMTPError::NoMail => &SMTPStatus::NO_MAIL,
        }
    }
}

/// [`SMTPConfig`] in the C ABI: the times in nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFISMTPConfig {
    pub maximum_command_line: usize,
    pub maximum_reply_line: usize,
    pub maximum_reply_lines: usize,
    pub maximum_text_line: usize,
    pub maximum_auth_line: usize,
    pub maximum_buffered: usize,
    pub greeting_timeout: u64,
    pub command_timeout: u64,
    pub data_initiation_timeout: u64,
    pub data_termination_timeout: u64,
    pub server_timeout: u64,
    pub passwords_require_tls: bool,
}

impl FFISMTPConfig {
    pub fn of(config: &SMTPConfig) -> FFISMTPConfig {
        let nanoseconds = |duration: Duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        FFISMTPConfig {
            maximum_command_line: config.maximum_command_line,
            maximum_reply_line: config.maximum_reply_line,
            maximum_reply_lines: config.maximum_reply_lines,
            maximum_text_line: config.maximum_text_line,
            maximum_auth_line: config.maximum_auth_line,
            maximum_buffered: config.maximum_buffered,
            greeting_timeout: nanoseconds(config.greeting_timeout),
            command_timeout: nanoseconds(config.command_timeout),
            data_initiation_timeout: nanoseconds(config.data_initiation_timeout),
            data_termination_timeout: nanoseconds(config.data_termination_timeout),
            server_timeout: nanoseconds(config.server_timeout),
            passwords_require_tls: config.passwords_require_tls,
        }
    }

    pub fn config(&self) -> SMTPConfig {
        SMTPConfig {
            maximum_command_line: self.maximum_command_line,
            maximum_reply_line: self.maximum_reply_line,
            maximum_reply_lines: self.maximum_reply_lines,
            maximum_text_line: self.maximum_text_line,
            maximum_auth_line: self.maximum_auth_line,
            maximum_buffered: self.maximum_buffered,
            greeting_timeout: Duration::from_nanos(self.greeting_timeout),
            command_timeout: Duration::from_nanos(self.command_timeout),
            data_initiation_timeout: Duration::from_nanos(self.data_initiation_timeout),
            data_termination_timeout: Duration::from_nanos(self.data_termination_timeout),
            server_timeout: Duration::from_nanos(self.server_timeout),
            passwords_require_tls: self.passwords_require_tls,
        }
    }
}

/// The scalar fields of [`SMTPServerConfig`] in the C ABI; its domain and lists are given beside it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFISMTPServerConfig {
    pub maximum_message_size: u64,
    pub maximum_recipients: usize,
    pub pipelining: bool,
    pub eight_bit_mime: bool,
    pub smtputf8: bool,
    pub chunking: bool,
    pub binary_mime: bool,
    pub dsn: bool,
    pub enhanced_status_codes: bool,
    pub starttls: bool,
    pub passwords_require_tls: bool,
    pub requires_tls: bool,
    pub requires_auth: bool,
}

impl FFISMTPServerConfig {
    pub fn of(config: &SMTPServerConfig) -> FFISMTPServerConfig {
        FFISMTPServerConfig {
            maximum_message_size: config.maximum_message_size,
            maximum_recipients: config.maximum_recipients,
            pipelining: config.pipelining,
            eight_bit_mime: config.eight_bit_mime,
            smtputf8: config.smtputf8,
            chunking: config.chunking,
            binary_mime: config.binary_mime,
            dsn: config.dsn,
            enhanced_status_codes: config.enhanced_status_codes,
            starttls: config.starttls,
            passwords_require_tls: config.passwords_require_tls,
            requires_tls: config.requires_tls,
            requires_auth: config.requires_auth,
        }
    }

    pub fn config(
        &self,
        domain: String,
        mechanisms: Vec<String>,
        plaintext: Vec<String>,
        commands: Vec<String>,
    ) -> SMTPServerConfig {
        SMTPServerConfig {
            domain,
            maximum_message_size: self.maximum_message_size,
            maximum_recipients: self.maximum_recipients,
            pipelining: self.pipelining,
            eight_bit_mime: self.eight_bit_mime,
            smtputf8: self.smtputf8,
            chunking: self.chunking,
            binary_mime: self.binary_mime,
            dsn: self.dsn,
            enhanced_status_codes: self.enhanced_status_codes,
            starttls: self.starttls,
            auth_mechanisms: mechanisms,
            plaintext_mechanisms: plaintext,
            passwords_require_tls: self.passwords_require_tls,
            requires_tls: self.requires_tls,
            requires_auth: self.requires_auth,
            commands,
        }
    }
}

/// The contents of an event, as the C ABI gives them.
#[derive(Clone, Debug, Default)]
pub struct FFISMTPEvent {
    pub kind: u8,
    pub command: Vec<u8>,
    pub reply: Vec<u8>,
    pub data: Vec<u8>,
    pub last: bool,
    pub error: Option<&'static Status>,
}

impl FFISMTPEvent {
    pub fn of_client(event: SMTPClientEvent) -> FFISMTPEvent {
        let mut out = FFISMTPEvent::default();
        match event {
            SMTPClientEvent::Greeting(reply) => out.reply = SMTPStatus::wire_of(&reply),
            SMTPClientEvent::Reply { command, reply } => {
                out.kind = 1;
                out.command = SMTPStatus::line_of(&command);
                out.reply = SMTPStatus::wire_of(&reply);
            }
            SMTPClientEvent::DataReply(reply) => {
                out.kind = 2;
                out.reply = SMTPStatus::wire_of(&reply);
            }
            SMTPClientEvent::AuthChallenge(data) => {
                out.kind = 3;
                out.data = data;
            }
            SMTPClientEvent::StartTLS => out.kind = 4,
            SMTPClientEvent::Closed { error } => {
                out.kind = 5;
                out.error = error.map(|error| error.to_status());
            }
        }
        out
    }

    pub fn of_server(event: SMTPServerEvent) -> FFISMTPEvent {
        let mut out = FFISMTPEvent::default();
        match event {
            SMTPServerEvent::Command(command) => out.command = SMTPStatus::line_of(&command),
            SMTPServerEvent::Data(data) => {
                out.kind = 1;
                out.data = data;
            }
            SMTPServerEvent::DataEnd { last } => {
                out.kind = 2;
                out.last = last;
            }
            SMTPServerEvent::DataRejected(error) => {
                out.kind = 3;
                out.error = Some(error.to_status());
            }
            SMTPServerEvent::AuthResponse(data) => {
                out.kind = 4;
                out.data = data;
            }
            SMTPServerEvent::AuthCancelled => out.kind = 5,
            SMTPServerEvent::Reset => out.kind = 6,
            SMTPServerEvent::StartTLS => out.kind = 7,
            SMTPServerEvent::Closed { error } => {
                out.kind = 8;
                out.error = error.map(|error| error.to_status());
            }
            SMTPServerEvent::AuthFailed => out.kind = 9,
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
        out_data: *mut Buffer,
        out_last: *mut bool,
        out_error: *mut *const Status,
    ) -> Result<(), &'static Status> {
        Pointer::check_range(out_kind, 1)?;
        Pointer::check_range(out_command, 1)?;
        Pointer::check_range(out_reply, 1)?;
        Pointer::check_range(out_data, 1)?;
        Pointer::check_range(out_last, 1)?;
        Pointer::check_range(out_error, 1)?;
        // SAFETY: guaranteed by the caller; the ranges were checked.
        unsafe { Pointer::write(out_kind, self.kind) }?;
        unsafe { Pointer::write(out_last, self.last) }?;
        unsafe { Pointer::write(out_error, self.error.map_or(core::ptr::null(), |error| error as *const Status)) }?;
        unsafe { Pointer::write(out_command, Buffer::from_vec(self.command)) }?;
        unsafe { Pointer::write(out_reply, Buffer::from_vec(self.reply)) }?;
        unsafe { Pointer::write(out_data, Buffer::from_vec(self.data)) }
    }
}

impl Value for FFISMTPConfig {
    const TYPE: Type = Type::Named("umilib_protocol_smtp_SMTPConfig");
}

impl Value for FFISMTPServerConfig {
    const TYPE: Type = Type::Named("umilib_protocol_smtp_SMTPServerConfig");
}

impl Value for SMTPClient {
    const TYPE: Type = Type::Named("umilib_protocol_smtp_SMTPClient");
}

impl Value for SMTPServer {
    const TYPE: Type = Type::Named("umilib_protocol_smtp_SMTPServer");
}

impl Value for SMTPDataReader {
    const TYPE: Type = Type::Named("umilib_protocol_smtp_SMTPDataReader");
}

crate::ffi_functions! {
    /// Writes the default configuration (the minimums and times of RFC 5321 §4.5.3) into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_config_default(out: *mut FFISMTPConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFISMTPConfig::of(&SMTPConfig::default())) })
    }

    /// Writes the default scalar fields of a server's configuration into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_config_default(out: *mut FFISMTPServerConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFISMTPServerConfig::of(&SMTPServerConfig::default())) })
    }

    /// Writes the command line of the line at `line`, as this crate writes it, into `out`; fails for a
    /// line that is not a command (UTF-8 taken where `utf8`, RFC 6531).
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_command_normalize(line: *const u8, length: usize, utf8: bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let line = unsafe { Pointer::slice(line, length) }?;
            Pointer::check_range(out, 1)?;
            let command = SMTPCommand::parse(line, utf8).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(SMTPStatus::line_of(&command))) }
        })())
    }

    /// Writes the code of the reply of the text at `wire` into `out_code` and its lines, joined by LF,
    /// into `out_lines`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_reply_decode(wire: *const u8, length: usize, out_code: *mut u16, out_lines: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(wire, length)], &[Pointer::range(out_code, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let wire = unsafe { Pointer::slice(wire, length) }?;
            Pointer::check_range(out_code, 1)?;
            Pointer::check_range(out_lines, 1)?;
            let reply = SMTPStatus::reply_of(wire, usize::MAX)?;
            unsafe { Pointer::write(out_code, reply.code) }?;
            unsafe { Pointer::write(out_lines, Buffer::from_vec(reply.lines.join(&b'\n'))) }
        })())
    }

    /// Writes the text on the wire of the reply of `code` and the lines at `lines` (joined by LF) into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_reply_encode(code: u16, lines: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let lines = unsafe { Pointer::slice(lines, length) }?;
            Pointer::check_range(out, 1)?;
            let reply = SMTPReply { code, lines: lines.split(|byte| *byte == b'\n').map(<[u8]>::to_vec).collect() };
            reply.check().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(SMTPStatus::wire_of(&reply))) }
        })())
    }

    /// Writes whether the first line of the reply text at `wire` begins with an enhanced status code of
    /// its class into `out_found`, and the code's class, subject and detail into the outputs (RFC 2034).
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_reply_status(wire: *const u8, length: usize, out_found: *mut bool, out_class: *mut u8, out_subject: *mut u16, out_detail: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(wire, length)],
                &[
                    Pointer::range(out_found, 1),
                    Pointer::range(out_class, 1),
                    Pointer::range(out_subject, 1),
                    Pointer::range(out_detail, 1),
                ],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let wire = unsafe { Pointer::slice(wire, length) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_class, 1)?;
            Pointer::check_range(out_subject, 1)?;
            Pointer::check_range(out_detail, 1)?;
            let status = SMTPStatus::reply_of(wire, usize::MAX)?.status();
            let status = status.unwrap_or(SMTPEnhancedStatus::new(0, 0, 0));
            unsafe { Pointer::write(out_class, status.class) }?;
            unsafe { Pointer::write(out_subject, status.subject) }?;
            unsafe { Pointer::write(out_detail, status.detail) }?;
            unsafe { Pointer::write(out_found, status.class != 0) }
        })())
    }

    /// Writes the greeting of the reply to EHLO at `wire` into `out_greeting` and its extensions, each
    /// a line of a keyword and its parameters, joined by LF, into `out_entries`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_extensions_decode(wire: *const u8, length: usize, out_greeting: *mut Buffer, out_entries: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and writable pointers.
            let wire = unsafe { Pointer::slice(wire, length) }?;
            Pointer::check_range(out_greeting, 1)?;
            Pointer::check_range(out_entries, 1)?;
            let extensions = SMTPExtensions::from_reply(&SMTPStatus::reply_of(wire, usize::MAX)?).map_err(|error| error.to_status())?;
            let entries: Vec<Vec<u8>> = extensions.entries.iter().map(|extension| extension.line()).collect();
            unsafe { Pointer::write_text(out_greeting, extensions.greeting) }?;
            unsafe { Pointer::write(out_entries, Buffer::from_vec(entries.join(&b'\n'))) }
        })())
    }

    /// Writes the local part and the domain of the mailbox at `text` into the outputs (RFC 5321 §4.1.2).
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_mailbox_parse(text: *const u8, length: usize, utf8: bool, out_local: *mut Buffer, out_domain: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and writable pointers.
            let text = unsafe { Pointer::slice(text, length) }?;
            Pointer::check_range(out_local, 1)?;
            Pointer::check_range(out_domain, 1)?;
            let mailbox = SMTPMailbox::parse(text, utf8).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out_local, mailbox.local) }?;
            unsafe { Pointer::write_text(out_domain, mailbox.domain) }
        })())
    }

    /// Writes the mailbox of the local part at `local` and the domain at `domain` as it is written into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_mailbox_format(local: *const u8, local_length: usize, domain: *const u8, domain_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let local = unsafe { Pointer::text(local, local_length) }?;
            let domain = unsafe { Pointer::text(domain, domain_length) }?;
            unsafe { Pointer::write_text(out, alloc::format!("{}", SMTPMailbox::new(local, domain))) }
        })())
    }

    /// Writes the xtext of the bytes at `data` into `out` (RFC 3461 §4).
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_xtext_encode(data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            unsafe { Pointer::write_text(out, SMTPXText::encode(data)) }
        })())
    }

    /// Writes the bytes of the xtext at `text` into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_xtext_decode(text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            Pointer::check_range(out, 1)?;
            let data = SMTPXText::decode(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(data)) }
        })())
    }

    /// Writes the message at `message` as mail data (RFC 5321 §4.5.2) into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_data_encode(message: *const u8, length: usize, maximum_line: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let message = unsafe { Pointer::slice(message, length) }?;
            Pointer::check_range(out, 1)?;
            let mut data = Vec::new();
            SMTPData::encode(message, maximum_line, &mut data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(data)) }
        })())
    }

    /// Writes a reader of mail data of at most `maximum_size` octets delivered and lines of at most
    /// `maximum_line` into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_data_reader_new(maximum_size: u64, maximum_line: usize, out: *mut *mut SMTPDataReader) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, SMTPDataReader::new(maximum_size, maximum_line)) })
    }

    /// Reads the bytes at `input` to the end of the data: writes the octets read into `out_read`, the
    /// data into `out`, and whether the data ended into `out_end`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_data_reader_read(reader: *mut SMTPDataReader, input: *const u8, length: usize, out_read: *mut usize, out: *mut Buffer, out_end: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(input, length)],
                &[Pointer::range(out_read, 1), Pointer::range(out_end, 1)],
            )?;
            // SAFETY: the caller passes a valid handle, readable bytes and writable pointers.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            let input = unsafe { Pointer::slice(input, length) }?;
            Pointer::check_range(out_read, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_end, 1)?;
            let mut data = Vec::new();
            let read = reader.read(input, &mut data);
            unsafe { Pointer::write(out_read, read) }?;
            unsafe { Pointer::write(out_end, reader.is_end()) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(data)) }
        })())
    }

    /// Writes whether the end of the data was read into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_data_reader_is_end(reader: *const SMTPDataReader, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write(out, reader.is_end()) }
        })())
    }

    /// Writes the error of the data read into `out` (null if it is of the data SMTP takes).
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_data_reader_error(reader: *const SMTPDataReader, out: *mut *const Status) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            let error = reader.error().map_or(core::ptr::null(), |error| error.to_status() as *const Status);
            unsafe { Pointer::write(out, error) }
        })())
    }

    /// Releases a reader of mail data. Does nothing if `reader` is null.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_data_reader_free(reader: *mut SMTPDataReader) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(reader) }
    }

    /// Writes a client of a new connection into `out`; `secure` if it is TLS from its start.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_client_new(config: FFISMTPConfig, secure: bool, now: u64, out: *mut *mut SMTPClient) -> *const Status {
        Status::from_result((|| {
            let client = SMTPClient::new(config.config(), secure, Instant::from_nanos(now)).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, client) }
        })())
    }

    /// Takes the `length` bytes at `data` the server sent.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_client_receive(client: *mut SMTPClient, data: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            client.receive(data, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Queues the command of the line at `line` (UTF-8 taken where `utf8`).
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_client_send(client: *mut SMTPClient, line: *const u8, length: usize, utf8: bool, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let line = unsafe { Pointer::slice(line, length) }?;
            let command = SMTPCommand::parse(line, utf8).map_err(|error| error.to_status())?;
            client.send(command, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Sends the message at `message` after the server's 354 to DATA.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_client_send_data(client: *mut SMTPClient, message: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let message = unsafe { Pointer::slice(message, length) }?;
            client.send_data(message, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Sends the bytes at `data` as a chunk of BDAT, the last if `last` (RFC 3030).
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_client_send_chunk(client: *mut SMTPClient, data: *const u8, length: usize, last: bool, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            client.send_chunk(data, last, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Answers an AUTH challenge with the bytes at `response`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_client_auth_respond(client: *mut SMTPClient, response: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let response = unsafe { Pointer::slice(response, length) }?;
            client.auth_respond(response, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Cancels an AUTH exchange.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_client_auth_cancel(client: *mut SMTPClient, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let client = unsafe { Pointer::reference_mut(client) }?;
            client.auth_cancel(Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Writes what is to be sent into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_client_transmit(client: *mut SMTPClient, out: *mut Buffer) -> *const Status {
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
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_client_poll_event(client: *mut SMTPClient, out_found: *mut bool, out_kind: *mut u8, out_command: *mut Buffer, out_reply: *mut Buffer, out_data: *mut Buffer, out_last: *mut bool, out_error: *mut *const Status) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[
                    Pointer::range(out_found, 1),
                    Pointer::range(out_kind, 1),
                    Pointer::range(out_last, 1),
                    Pointer::range(out_error, 1),
                ],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let client = unsafe { Pointer::reference_mut(client) }?;
            // Every output is checked before the event is taken, so that none is lost.
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out_command, 1)?;
            Pointer::check_range(out_reply, 1)?;
            Pointer::check_range(out_data, 1)?;
            Pointer::check_range(out_last, 1)?;
            Pointer::check_range(out_error, 1)?;
            let event = client.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let event = event.map(FFISMTPEvent::of_client).unwrap_or_default();
            unsafe { event.write(out_kind, out_command, out_reply, out_data, out_last, out_error) }
        })())
    }

    /// Writes whether the client waits for anything into `out_found` and when it times out into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_client_poll_timeout(client: *const SMTPClient, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write_optional(client.poll_timeout().map(Instant::as_nanos), out_found, out) }
        })())
    }

    /// Times out what waits past `now`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_client_expire(client: *mut SMTPClient, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(client) }?.expire(Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes whether the connection is open into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_client_is_open(client: *const SMTPClient, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write(out, client.is_open()) }
        })())
    }

    /// Writes whether the server advertised the extension of the UTF-8 keyword at `keyword` into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_client_has_extension(client: *const SMTPClient, keyword: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(keyword, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            let keyword = unsafe { Pointer::text(keyword, length) }?;
            unsafe { Pointer::write(out, client.has_extension(keyword)) }
        })())
    }

    /// Releases a client. Does nothing if `client` is null.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_client_free(client: *mut SMTPClient) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(client) }
    }

    /// Writes a server of a new connection into `out`: of `config`, the scalar fields of `server`, the
    /// domain at `domain`, and the arrays of mechanisms, plaintext mechanisms and extension commands.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_new(config: FFISMTPConfig, server: FFISMTPServerConfig, domain: *const u8, domain_length: usize, mechanisms: *const *const Char, mechanism_count: usize, plaintext: *const *const Char, plaintext_count: usize, commands: *const *const Char, command_count: usize, secure: bool, out: *mut *mut SMTPServer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text, arrays of strings and a writable pointer.
            let domain = String::from(unsafe { Pointer::text(domain, domain_length) }?);
            let mechanisms = unsafe { Pointer::strings(mechanisms, mechanism_count) }?;
            let plaintext = unsafe { Pointer::strings(plaintext, plaintext_count) }?;
            let commands = unsafe { Pointer::strings(commands, command_count) }?;
            let server_config = server.config(domain, mechanisms, plaintext, commands);
            let server = SMTPServer::new(config.config(), server_config, secure).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, server) }
        })())
    }

    /// Sends the greeting of the reply text at `wire`: 220, or 554.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_greet(server: *mut SMTPServer, wire: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let reply = SMTPStatus::reply_of(unsafe { Pointer::slice(wire, length) }?, usize::MAX)?;
            server.greet(reply, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Writes the server's greeting of its domain into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_greeting(server: *const SMTPServer, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(SMTPStatus::wire_of(&server.greeting()))) }
        })())
    }

    /// Writes whether the server takes more input now into `out`: false while what it holds of
    /// the client (pipelined commands not yet answered) reaches `maximum_buffered`, so that a
    /// peer cannot make it hold more; stop reading from the connection until it is true again.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_wants_receive(server: *const SMTPServer, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, server.wants_receive()) }
        })())
    }

    /// Takes the `length` bytes at `data` the client sent.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_receive(server: *mut SMTPServer, data: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            server.receive(unsafe { Pointer::slice(data, length) }?, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Answers the command told with the reply text at `wire`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_reply(server: *mut SMTPServer, wire: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let reply = SMTPStatus::reply_of(unsafe { Pointer::slice(wire, length) }?, usize::MAX)?;
            server.reply(reply, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Sends the bytes at `challenge` as a challenge of the AUTH exchange told.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_auth_challenge(server: *mut SMTPServer, challenge: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let challenge = unsafe { Pointer::slice(challenge, length) }?;
            server.auth_challenge(challenge, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Writes the reply to EHLO the server would send now (its extensions) into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_extensions(server: *const SMTPServer, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(SMTPStatus::wire_of(&server.extensions().reply()))) }
        })())
    }

    /// Closes the connection with 421 and the UTF-8 text at `text`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_shutdown(server: *mut SMTPServer, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let server = unsafe { Pointer::reference_mut(server) }?;
            server.shutdown(unsafe { Pointer::text(text, length) }?);
            Ok(())
        })())
    }

    /// Writes what is to be sent into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_transmit(server: *mut SMTPServer, out: *mut Buffer) -> *const Status {
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
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_poll_event(server: *mut SMTPServer, out_found: *mut bool, out_kind: *mut u8, out_command: *mut Buffer, out_reply: *mut Buffer, out_data: *mut Buffer, out_last: *mut bool, out_error: *mut *const Status) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[
                    Pointer::range(out_found, 1),
                    Pointer::range(out_kind, 1),
                    Pointer::range(out_last, 1),
                    Pointer::range(out_error, 1),
                ],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let server = unsafe { Pointer::reference_mut(server) }?;
            // Every output is checked before the event is taken, so that none is lost.
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out_command, 1)?;
            Pointer::check_range(out_reply, 1)?;
            Pointer::check_range(out_data, 1)?;
            Pointer::check_range(out_last, 1)?;
            Pointer::check_range(out_error, 1)?;
            let event = server.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let event = event.map(FFISMTPEvent::of_server).unwrap_or_default();
            unsafe { event.write(out_kind, out_command, out_reply, out_data, out_last, out_error) }
        })())
    }

    /// Writes whether the server waits for the client into `out_found` and until when into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_poll_timeout(server: *const SMTPServer, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write_optional(server.poll_timeout().map(Instant::as_nanos), out_found, out) }
        })())
    }

    /// Closes the connection with 421 if the client was silent past its time.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_expire(server: *mut SMTPServer, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(server) }?.expire(Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes whether the connection is open into `out`.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_is_open(server: *const SMTPServer, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, server.is_open()) }
        })())
    }

    /// Releases a server. Does nothing if `server` is null.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_server_free(server: *mut SMTPServer) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(server) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "smtp",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_smtp_SMTPConfig",
            documentation: " The limits and times (nanoseconds) of an SMTP connection.",
            fields: &[
                Parameter { name: "maximum_command_line", value: Type::USize },
                Parameter { name: "maximum_reply_line", value: Type::USize },
                Parameter { name: "maximum_reply_lines", value: Type::USize },
                Parameter { name: "maximum_text_line", value: Type::USize },
                Parameter { name: "maximum_auth_line", value: Type::USize },
                Parameter { name: "maximum_buffered", value: Type::USize },
                Parameter { name: "greeting_timeout", value: Type::U64 },
                Parameter { name: "command_timeout", value: Type::U64 },
                Parameter { name: "data_initiation_timeout", value: Type::U64 },
                Parameter { name: "data_termination_timeout", value: Type::U64 },
                Parameter { name: "server_timeout", value: Type::U64 },
                Parameter { name: "passwords_require_tls", value: Type::Bool },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_smtp_SMTPServerConfig",
            documentation: " The scalar fields of an SMTP server's configuration.",
            fields: &[
                Parameter { name: "maximum_message_size", value: Type::U64 },
                Parameter { name: "maximum_recipients", value: Type::USize },
                Parameter { name: "pipelining", value: Type::Bool },
                Parameter { name: "eight_bit_mime", value: Type::Bool },
                Parameter { name: "smtputf8", value: Type::Bool },
                Parameter { name: "chunking", value: Type::Bool },
                Parameter { name: "binary_mime", value: Type::Bool },
                Parameter { name: "dsn", value: Type::Bool },
                Parameter { name: "enhanced_status_codes", value: Type::Bool },
                Parameter { name: "starttls", value: Type::Bool },
                Parameter { name: "passwords_require_tls", value: Type::Bool },
                Parameter { name: "requires_tls", value: Type::Bool },
                Parameter { name: "requires_auth", value: Type::Bool },
            ],
        },
        Definition::Opaque { name: "umilib_protocol_smtp_SMTPClient", documentation: " An SMTP client without I/O." },
        Definition::Opaque { name: "umilib_protocol_smtp_SMTPServer", documentation: " An SMTP server without I/O." },
        Definition::Opaque {
            name: "umilib_protocol_smtp_SMTPDataReader",
            documentation: " A reader of the mail data of DATA.",
        },
    ],
    functions: &Function::concat::<{ FUNCTIONS.len() + ROUTE.len() }>(&[FUNCTIONS, ROUTE]),
    modules: &[],
};
