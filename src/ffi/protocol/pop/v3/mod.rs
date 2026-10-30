//! The C ABI of [`crate::protocol::pop::v3`].
//!
//! Commands and status lines cross it as their lines on the wire, without
//! their CRLF; a response code is the levels joined by `/`. The
//! configurations are structures (times in nanoseconds); the lists and texts
//! of a server's configuration are given beside its structure. An event is
//! the number of its variant and its contents: of a client, 0 Greeting (its
//! response), 1 Response (its command and response), 2 Data, 3 DataEnd,
//! 4 AuthChallenge (its data), 5 StartTLS, 6 Closed (its error, or null); of
//! a server, 0 Command, 1 AuthResponse (its data), 2 AuthCancelled,
//! 3 StartTLS, 4 Closed, 5 AuthFailed. Times are nanoseconds of the caller's monotonic clock.

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use crate::ffi::{Buffer, Char, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::pop::v3::{
    POP3Capabilities, POP3Client, POP3ClientEvent, POP3Command, POP3Config, POP3Error, POP3MultiLineReader,
    POP3MultiLineWriter, POP3Response, POP3Server, POP3ServerConfig, POP3ServerEvent, POP3State,
};
use crate::runtime::Instant;

/// The statuses of [`POP3Error`], one per variant.
pub struct POP3Status;

impl POP3Status {
    pub const SYNTAX: Status = Status::new(c"protocol.pop.v3", c"Syntax", c"text not of the grammar of POP3");
    pub const TOO_LONG: Status =
        Status::new(c"protocol.pop.v3", c"TooLong", c"a line longer than the configuration takes");
    pub const STATE: Status =
        Status::new(c"protocol.pop.v3", c"State", c"not in this state, or of a capability not announced");
    pub const TIMEOUT: Status = Status::new(c"protocol.pop.v3", c"Timeout", c"no response in time");
    pub const CLOSED: Status = Status::new(c"protocol.pop.v3", c"Closed", c"the connection is closed");

    /// The response of its status line, without its CRLF.
    pub fn response_of(line: &[u8]) -> Result<POP3Response, &'static Status> {
        let response = POP3Response::parse(line).map_err(|error| error.to_status())?;
        response.check().map_err(|error| error.to_status())?;
        Ok(response)
    }

    /// The status line of `response`, without its CRLF.
    pub fn line_of(response: &POP3Response) -> Vec<u8> {
        let mut out = Vec::new();
        response.encode(&mut out);
        out.truncate(out.len() - 2);
        out
    }

    /// The number of `state`: 0 AUTHORIZATION, 1 TRANSACTION, 2 UPDATE.
    pub fn state_number(state: POP3State) -> u8 {
        match state {
            POP3State::Authorization => 0,
            POP3State::Transaction => 1,
            POP3State::Update => 2,
        }
    }
}

impl ToStatus for POP3Error {
    fn to_status(&self) -> &'static Status {
        match self {
            POP3Error::Syntax { .. } => &POP3Status::SYNTAX,
            POP3Error::TooLong { .. } => &POP3Status::TOO_LONG,
            POP3Error::State { .. } => &POP3Status::STATE,
            POP3Error::Timeout => &POP3Status::TIMEOUT,
            POP3Error::Closed => &POP3Status::CLOSED,
        }
    }
}

/// [`POP3Config`] in the C ABI: the times in nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIPOP3Config {
    pub maximum_command_line: usize,
    pub maximum_response_line: usize,
    pub maximum_auth_line: usize,
    pub maximum_capabilities: usize,
    pub maximum_buffered: usize,
    pub response_timeout: u64,
    pub autologout: u64,
    pub passwords_require_tls: bool,
}

impl FFIPOP3Config {
    pub fn of(config: &POP3Config) -> FFIPOP3Config {
        let nanoseconds = |duration: Duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        FFIPOP3Config {
            maximum_command_line: config.maximum_command_line,
            maximum_response_line: config.maximum_response_line,
            maximum_auth_line: config.maximum_auth_line,
            maximum_capabilities: config.maximum_capabilities,
            maximum_buffered: config.maximum_buffered,
            response_timeout: nanoseconds(config.response_timeout),
            autologout: nanoseconds(config.autologout),
            passwords_require_tls: config.passwords_require_tls,
        }
    }

    pub fn config(&self) -> POP3Config {
        POP3Config {
            maximum_command_line: self.maximum_command_line,
            maximum_response_line: self.maximum_response_line,
            maximum_auth_line: self.maximum_auth_line,
            maximum_capabilities: self.maximum_capabilities,
            maximum_buffered: self.maximum_buffered,
            response_timeout: Duration::from_nanos(self.response_timeout),
            autologout: Duration::from_nanos(self.autologout),
            passwords_require_tls: self.passwords_require_tls,
        }
    }
}

/// The scalar fields of [`POP3ServerConfig`] in the C ABI; `login_delay` is of `has_login_delay`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIPOP3ServerConfig {
    pub user: bool,
    pub top: bool,
    pub uidl: bool,
    pub pipelining: bool,
    pub response_codes: bool,
    pub stls: bool,
    pub passwords_require_tls: bool,
    pub utf8: bool,
    pub utf8_user: bool,
    pub lang: bool,
    pub has_login_delay: bool,
    pub login_delay: u32,
}

impl FFIPOP3ServerConfig {
    pub fn of(config: &POP3ServerConfig) -> FFIPOP3ServerConfig {
        FFIPOP3ServerConfig {
            user: config.user,
            top: config.top,
            uidl: config.uidl,
            pipelining: config.pipelining,
            response_codes: config.response_codes,
            stls: config.stls,
            passwords_require_tls: config.passwords_require_tls,
            utf8: config.utf8,
            utf8_user: config.utf8_user,
            lang: config.lang,
            has_login_delay: config.login_delay.is_some(),
            login_delay: config.login_delay.unwrap_or(0),
        }
    }

    pub fn config(
        &self,
        mechanisms: Vec<String>,
        plaintext: Vec<String>,
        expire: Option<String>,
        implementation: Option<String>,
        commands: Vec<String>,
    ) -> POP3ServerConfig {
        POP3ServerConfig {
            user: self.user,
            top: self.top,
            uidl: self.uidl,
            pipelining: self.pipelining,
            response_codes: self.response_codes,
            stls: self.stls,
            sasl_mechanisms: mechanisms,
            plaintext_mechanisms: plaintext,
            passwords_require_tls: self.passwords_require_tls,
            utf8: self.utf8,
            utf8_user: self.utf8_user,
            lang: self.lang,
            login_delay: self.has_login_delay.then_some(self.login_delay),
            expire,
            implementation,
            commands,
        }
    }
}

/// The contents of an event, as the C ABI gives them.
#[derive(Clone, Debug, Default)]
pub struct FFIPOP3Event {
    pub kind: u8,
    pub command: Vec<u8>,
    pub response: Vec<u8>,
    pub data: Vec<u8>,
    pub error: Option<&'static Status>,
}

impl FFIPOP3Event {
    pub fn of_client(event: POP3ClientEvent) -> FFIPOP3Event {
        let mut out = FFIPOP3Event::default();
        match event {
            POP3ClientEvent::Greeting(response) => out.response = POP3Status::line_of(&response),
            POP3ClientEvent::Response { command, response } => {
                out.kind = 1;
                out.command = alloc::format!("{command}").into_bytes();
                out.response = POP3Status::line_of(&response);
            }
            POP3ClientEvent::Data(data) => {
                out.kind = 2;
                out.data = data;
            }
            POP3ClientEvent::DataEnd => out.kind = 3,
            POP3ClientEvent::AuthChallenge(data) => {
                out.kind = 4;
                out.data = data;
            }
            POP3ClientEvent::StartTLS => out.kind = 5,
            POP3ClientEvent::Closed { error } => {
                out.kind = 6;
                out.error = error.map(|error| error.to_status());
            }
        }
        out
    }

    pub fn of_server(event: POP3ServerEvent) -> FFIPOP3Event {
        let mut out = FFIPOP3Event::default();
        match event {
            POP3ServerEvent::Command(command) => out.command = alloc::format!("{command}").into_bytes(),
            POP3ServerEvent::AuthResponse(data) => {
                out.kind = 1;
                out.data = data;
            }
            POP3ServerEvent::AuthCancelled => out.kind = 2,
            POP3ServerEvent::StartTLS => out.kind = 3,
            POP3ServerEvent::Closed { error } => {
                out.kind = 4;
                out.error = error.map(|error| error.to_status());
            }
            POP3ServerEvent::AuthFailed => out.kind = 5,
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
        out_response: *mut Buffer,
        out_data: *mut Buffer,
        out_error: *mut *const Status,
    ) -> Result<(), &'static Status> {
        Pointer::check_range(out_kind, 1)?;
        Pointer::check_range(out_command, 1)?;
        Pointer::check_range(out_response, 1)?;
        Pointer::check_range(out_data, 1)?;
        Pointer::check_range(out_error, 1)?;
        // SAFETY: guaranteed by the caller; the ranges were checked.
        unsafe { Pointer::write(out_kind, self.kind) }?;
        unsafe { Pointer::write(out_error, self.error.map_or(core::ptr::null(), |error| error as *const Status)) }?;
        unsafe { Pointer::write(out_command, Buffer::from_vec(self.command)) }?;
        unsafe { Pointer::write(out_response, Buffer::from_vec(self.response)) }?;
        unsafe { Pointer::write(out_data, Buffer::from_vec(self.data)) }
    }
}

impl Value for FFIPOP3Config {
    const TYPE: Type = Type::Named("umilib_protocol_pop_v3_POP3Config");
}

impl Value for FFIPOP3ServerConfig {
    const TYPE: Type = Type::Named("umilib_protocol_pop_v3_POP3ServerConfig");
}

impl Value for POP3Client {
    const TYPE: Type = Type::Named("umilib_protocol_pop_v3_POP3Client");
}

impl Value for POP3Server {
    const TYPE: Type = Type::Named("umilib_protocol_pop_v3_POP3Server");
}

impl Value for POP3MultiLineReader {
    const TYPE: Type = Type::Named("umilib_protocol_pop_v3_POP3MultiLineReader");
}

impl Value for POP3MultiLineWriter {
    const TYPE: Type = Type::Named("umilib_protocol_pop_v3_POP3MultiLineWriter");
}

crate::ffi_functions! {
    /// Writes the default configuration (the times of RFC 1939 §3) into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_config_default(out: *mut FFIPOP3Config) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFIPOP3Config::of(&POP3Config::default())) })
    }

    /// Writes the default scalar fields of a server's configuration into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_config_default(out: *mut FFIPOP3ServerConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFIPOP3ServerConfig::of(&POP3ServerConfig::default())) })
    }

    /// Writes the command line of the line at `line`, as this crate writes it, into `out`; fails for a
    /// line that is not a command (UTF-8 arguments taken where `utf8`, RFC 6856).
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_command_normalize(line: *const u8, length: usize, utf8: bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let line = unsafe { Pointer::slice(line, length) }?;
            let command = POP3Command::parse(line, utf8).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, alloc::format!("{command}")) }
        })())
    }

    /// Writes whether the command of the line at `line` has a multi-line response when positive into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_command_is_multi_line(line: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(line, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let line = unsafe { Pointer::slice(line, length) }?;
            let command = POP3Command::parse(line, true).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, command.is_multi_line()) }
        })())
    }

    /// Writes whether the status line at `line` is positive into `out_ok`, its response code (levels
    /// joined by `/`, empty if none) into `out_code` and its text into `out_text` (RFC 2449 §8).
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_response_decode(line: *const u8, length: usize, out_ok: *mut bool, out_code: *mut Buffer, out_text: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(line, length)], &[Pointer::range(out_ok, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let line = unsafe { Pointer::slice(line, length) }?;
            Pointer::check_range(out_ok, 1)?;
            Pointer::check_range(out_code, 1)?;
            Pointer::check_range(out_text, 1)?;
            let response = POP3Status::response_of(line)?;
            unsafe { Pointer::write(out_ok, response.ok) }?;
            unsafe { Pointer::write_text(out_code, response.code.join("/")) }?;
            unsafe { Pointer::write(out_text, Buffer::from_vec(response.text)) }
        })())
    }

    /// Writes the status line of `ok`, the response code at `code` (levels joined by `/`, none if empty)
    /// and the text at `text` into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_response_encode(ok: bool, code: *const u8, code_length: usize, text: *const u8, text_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let code = unsafe { Pointer::text(code, code_length) }?;
            let text = unsafe { Pointer::slice(text, text_length) }?;
            Pointer::check_range(out, 1)?;
            let code = match code {
                "" => Vec::new(),
                code => code.split('/').map(String::from).collect(),
            };
            let response = POP3Response { ok, code, text: text.to_vec() };
            response.check().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(POP3Status::line_of(&response))) }
        })())
    }

    /// Writes whether the status line at `line` has a timestamp for APOP (RFC 1939 §7) into `out_found`
    /// and the timestamp, its angle brackets included, into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_response_timestamp(line: *const u8, length: usize, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(line, length)], &[Pointer::range(out_found, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let response = POP3Status::response_of(unsafe { Pointer::slice(line, length) }?)?;
            let timestamp = response.timestamp().map(|timestamp| Buffer::from_vec(timestamp.to_vec()));
            unsafe { Pointer::write_optional(timestamp, out_found, out) }
        })())
    }

    /// Writes the capabilities of the lines of a CAPA list at `list` (its periods removed), each a line
    /// of a tag in upper case and its parameters, joined by LF, into `out`; lines that are not
    /// capabilities are left out (RFC 2449 §5).
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_capabilities_decode(list: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let list = unsafe { Pointer::slice(list, length) }?;
            Pointer::check_range(out, 1)?;
            let lines: Vec<Vec<u8>> = POP3Capabilities::parse(list).entries.iter().map(|capability| capability.line()).collect();
            unsafe { Pointer::write(out, Buffer::from_vec(lines.join(&b'\n'))) }
        })())
    }

    /// Writes the number of octets of the bytes at `data` as a multi-line response sends them, line
    /// breaks as CRLF and without the added periods and the end, into `out` (RFC 6856 §2.1).
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_multi_line_canonical_length(data: *const u8, length: usize, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            unsafe { Pointer::write(out, POP3MultiLineWriter::canonical_length(data)) }
        })())
    }

    /// Writes a reader of the lines of a multi-line response into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_multi_line_reader_new(out: *mut *mut POP3MultiLineReader) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, POP3MultiLineReader::new()) })
    }

    /// Reads the bytes at `input` to the end of the response: writes the octets read into `out_read`,
    /// the lines, their added periods removed, into `out`, and whether the response ended into `out_end`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_multi_line_reader_read(reader: *mut POP3MultiLineReader, input: *const u8, length: usize, out_read: *mut usize, out: *mut Buffer, out_end: *mut bool) -> *const Status {
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

    /// Releases a reader. Does nothing if `reader` is null.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_multi_line_reader_free(reader: *mut POP3MultiLineReader) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(reader) }
    }

    /// Writes a writer of the lines of a multi-line response into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_multi_line_writer_new(out: *mut *mut POP3MultiLineWriter) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, POP3MultiLineWriter::new()) })
    }

    /// Writes the bytes at `data` as lines of the response into `out`: line breaks as CRLF, a period
    /// added before a line that begins with one.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_multi_line_writer_write(writer: *mut POP3MultiLineWriter, data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let writer = unsafe { Pointer::reference_mut(writer) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out, 1)?;
            let mut written = Vec::new();
            writer.write(data, &mut written);
            unsafe { Pointer::write(out, Buffer::from_vec(written)) }
        })())
    }

    /// Writes the end of the response into `out`: a CRLF if the last line has none, and the line of a period.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_multi_line_writer_finish(writer: *mut POP3MultiLineWriter, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let writer = unsafe { Pointer::reference_mut(writer) }?;
            Pointer::check_range(out, 1)?;
            let mut written = Vec::new();
            writer.finish(&mut written);
            unsafe { Pointer::write(out, Buffer::from_vec(written)) }
        })())
    }

    /// Releases a writer. Does nothing if `writer` is null.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_multi_line_writer_free(writer: *mut POP3MultiLineWriter) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(writer) }
    }

    /// Writes a client of a new connection into `out`; `secure` if it is TLS from its start (RFC 8314).
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_client_new(config: FFIPOP3Config, secure: bool, now: u64, out: *mut *mut POP3Client) -> *const Status {
        Status::from_result((|| {
            let client = POP3Client::new(config.config(), secure, Instant::from_nanos(now)).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, client) }
        })())
    }

    /// Takes the `length` bytes at `data` the server sent.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_client_receive(client: *mut POP3Client, data: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            client.receive(data, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Queues the command of the line at `line` (UTF-8 arguments taken where `utf8`).
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_client_send(client: *mut POP3Client, line: *const u8, length: usize, utf8: bool, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let line = unsafe { Pointer::slice(line, length) }?;
            let command = POP3Command::parse(line, utf8).map_err(|error| error.to_status())?;
            client.send(command, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Answers an AUTH challenge with the bytes at `response`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_client_auth_respond(client: *mut POP3Client, response: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let response = unsafe { Pointer::slice(response, length) }?;
            client.auth_respond(response, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Cancels an AUTH exchange (RFC 5034 §4).
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_client_auth_cancel(client: *mut POP3Client, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let client = unsafe { Pointer::reference_mut(client) }?;
            client.auth_cancel(Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Writes what is to be sent into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_client_transmit(client: *mut POP3Client, out: *mut Buffer) -> *const Status {
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
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_client_poll_event(client: *mut POP3Client, out_found: *mut bool, out_kind: *mut u8, out_command: *mut Buffer, out_response: *mut Buffer, out_data: *mut Buffer, out_error: *mut *const Status) -> *const Status {
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
            Pointer::check_range(out_response, 1)?;
            Pointer::check_range(out_data, 1)?;
            Pointer::check_range(out_error, 1)?;
            let event = client.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let event = event.map(FFIPOP3Event::of_client).unwrap_or_default();
            unsafe { event.write(out_kind, out_command, out_response, out_data, out_error) }
        })())
    }

    /// Writes whether the client waits for a response into `out_found` and when it times out into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_client_poll_timeout(client: *const POP3Client, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write_optional(client.poll_timeout().map(Instant::as_nanos), out_found, out) }
        })())
    }

    /// Times out what waits past `now`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_client_expire(client: *mut POP3Client, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(client) }?.expire(Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes whether the connection is open into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_client_is_open(client: *const POP3Client, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write(out, client.is_open()) }
        })())
    }

    /// Writes the session's state into `out`: 0 AUTHORIZATION, 1 TRANSACTION, 2 UPDATE (RFC 1939 §3).
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_client_state(client: *const POP3Client, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write(out, POP3Status::state_number(client.state)) }
        })())
    }

    /// Writes whether the server announced the capability of the tag at `tag` into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_client_has_capability(client: *const POP3Client, tag: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(tag, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable text and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            let tag = unsafe { Pointer::text(tag, length) }?;
            unsafe { Pointer::write(out, client.has_capability(tag)) }
        })())
    }

    /// Releases a client. Does nothing if `client` is null.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_client_free(client: *mut POP3Client) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(client) }
    }

    /// Writes a server of a new connection into `out`: of `config`, the scalar fields of `server`, the
    /// arrays of SASL mechanisms, plaintext mechanisms and extension commands, and the texts of EXPIRE
    /// and IMPLEMENTATION (none if null).
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_new(config: FFIPOP3Config, server: FFIPOP3ServerConfig, mechanisms: *const *const Char, mechanism_count: usize, plaintext: *const *const Char, plaintext_count: usize, commands: *const *const Char, command_count: usize, expire: *const u8, expire_length: usize, implementation: *const u8, implementation_length: usize, secure: bool, out: *mut *mut POP3Server) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes arrays of strings, readable text and a writable pointer.
            let mechanisms = unsafe { Pointer::strings(mechanisms, mechanism_count) }?;
            let plaintext = unsafe { Pointer::strings(plaintext, plaintext_count) }?;
            let commands = unsafe { Pointer::strings(commands, command_count) }?;
            let expire = unsafe { Pointer::optional_text(expire, expire_length) }?.map(String::from);
            let implementation = unsafe { Pointer::optional_text(implementation, implementation_length) }?.map(String::from);
            let server_config = server.config(mechanisms, plaintext, expire, implementation, commands);
            let server = POP3Server::new(config.config(), server_config, secure).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, server) }
        })())
    }

    /// Sends the greeting of the status line at `line`: +OK, with a timestamp in its text if APOP is
    /// offered (RFC 1939 §7); -ERR closes the connection.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_greet(server: *mut POP3Server, line: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let response = POP3Status::response_of(unsafe { Pointer::slice(line, length) }?)?;
            server.greet(response, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Writes the capabilities the server would announce now (RFC 2449 §5), a line each with its CRLF,
    /// without the period that ends the list, into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_capabilities(server: *const POP3Server, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            Pointer::check_range(out, 1)?;
            let mut list = Vec::new();
            server.capabilities().encode(&mut list);
            unsafe { Pointer::write(out, Buffer::from_vec(list)) }
        })())
    }

    /// Writes whether passwords sent as they are are taken now (RFC 5034 §4) into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_passwords_taken(server: *const POP3Server, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, server.passwords_taken()) }
        })())
    }

    /// Writes whether the server takes more input now into `out`: false while what it holds of
    /// the client (pipelined commands not yet answered) reaches `maximum_buffered`, so that a
    /// peer cannot make it hold more; stop reading from the connection until it is true again.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_wants_receive(server: *const POP3Server, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, server.wants_receive()) }
        })())
    }

    /// Takes the `length` bytes at `data` the client sent.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_receive(server: *mut POP3Server, data: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            server.receive(unsafe { Pointer::slice(data, length) }?, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Answers the command told with the status line at `line`; a positive answer to a multi-line
    /// command is followed by its lines ([`umilib_protocol_pop_v3_pop3_server_send_data`]) and their end.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_reply(server: *mut POP3Server, line: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let response = POP3Status::response_of(unsafe { Pointer::slice(line, length) }?)?;
            server.reply(response, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Sends the bytes at `data` as lines of the multi-line response being sent.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_send_data(server: *mut POP3Server, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            server.send_data(unsafe { Pointer::slice(data, length) }?).map_err(|error| error.to_status())
        })())
    }

    /// Ends the multi-line response being sent.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_end_data(server: *mut POP3Server, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let server = unsafe { Pointer::reference_mut(server) }?;
            server.end_data(Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Sends the bytes at `challenge` as a challenge of the AUTH exchange told.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_auth_challenge(server: *mut POP3Server, challenge: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let challenge = unsafe { Pointer::slice(challenge, length) }?;
            server.auth_challenge(challenge, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Writes what is to be sent into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_transmit(server: *mut POP3Server, out: *mut Buffer) -> *const Status {
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
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_poll_event(server: *mut POP3Server, out_found: *mut bool, out_kind: *mut u8, out_command: *mut Buffer, out_response: *mut Buffer, out_data: *mut Buffer, out_error: *mut *const Status) -> *const Status {
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
            Pointer::check_range(out_response, 1)?;
            Pointer::check_range(out_data, 1)?;
            Pointer::check_range(out_error, 1)?;
            let event = server.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let event = event.map(FFIPOP3Event::of_server).unwrap_or_default();
            unsafe { event.write(out_kind, out_command, out_response, out_data, out_error) }
        })())
    }

    /// Writes whether the server waits for the client into `out_found` and until when (the
    /// autologout timer, RFC 1939 §3) into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_poll_timeout(server: *const POP3Server, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write_optional(server.poll_timeout().map(Instant::as_nanos), out_found, out) }
        })())
    }

    /// Closes the connection, without a response, if the client was silent past its time.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_expire(server: *mut POP3Server, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(server) }?.expire(Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes whether the connection is open into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_is_open(server: *const POP3Server, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, server.is_open()) }
        })())
    }

    /// Releases a server. Does nothing if `server` is null.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_server_free(server: *mut POP3Server) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(server) }
    }
}

#[cfg(all(umilib_feature = "hash-md-v5", umilib_feature = "secret"))]
crate::ffi_functions! {
    const APOP;

    /// Writes the digest of APOP (RFC 1939 §7) of the timestamp at `timestamp` (its angle brackets
    /// included) and the shared secret at `secret`, in lower-case hexadecimal, into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_command_apop_digest(timestamp: *const u8, timestamp_length: usize, secret: *const u8, secret_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let timestamp = unsafe { Pointer::slice(timestamp, timestamp_length) }?;
            let secret = unsafe { Pointer::slice(secret, secret_length) }?;
            unsafe { Pointer::write_text(out, POP3Command::apop_digest(timestamp, secret)) }
        })())
    }

    /// Writes whether the digest at `digest` is that of the timestamp and the shared secret, compared
    /// in constant time, into `out`.
    pub unsafe extern "C" fn umilib_protocol_pop_v3_pop3_command_apop_matches(digest: *const u8, digest_length: usize, timestamp: *const u8, timestamp_length: usize, secret: *const u8, secret_length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[
                    Pointer::range(digest, digest_length),
                    Pointer::range(timestamp, timestamp_length),
                    Pointer::range(secret, secret_length),
                ],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let digest = unsafe { Pointer::text(digest, digest_length) }?;
            let timestamp = unsafe { Pointer::slice(timestamp, timestamp_length) }?;
            let secret = unsafe { Pointer::slice(secret, secret_length) }?;
            unsafe { Pointer::write(out, POP3Command::apop_matches(digest, timestamp, secret)) }
        })())
    }
}

/// The functions of APOP, of MD5.
#[cfg(not(all(umilib_feature = "hash-md-v5", umilib_feature = "secret")))]
pub const APOP: &[crate::ffi::Function] = &[];

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v3",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_pop_v3_POP3Config",
            documentation: " The limits and times (nanoseconds) of a POP3 connection.",
            fields: &[
                Parameter { name: "maximum_command_line", value: Type::USize },
                Parameter { name: "maximum_response_line", value: Type::USize },
                Parameter { name: "maximum_auth_line", value: Type::USize },
                Parameter { name: "maximum_capabilities", value: Type::USize },
                Parameter { name: "maximum_buffered", value: Type::USize },
                Parameter { name: "response_timeout", value: Type::U64 },
                Parameter { name: "autologout", value: Type::U64 },
                Parameter { name: "passwords_require_tls", value: Type::Bool },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_pop_v3_POP3ServerConfig",
            documentation: " The scalar fields of a POP3 server's configuration.",
            fields: &[
                Parameter { name: "user", value: Type::Bool },
                Parameter { name: "top", value: Type::Bool },
                Parameter { name: "uidl", value: Type::Bool },
                Parameter { name: "pipelining", value: Type::Bool },
                Parameter { name: "response_codes", value: Type::Bool },
                Parameter { name: "stls", value: Type::Bool },
                Parameter { name: "passwords_require_tls", value: Type::Bool },
                Parameter { name: "utf8", value: Type::Bool },
                Parameter { name: "utf8_user", value: Type::Bool },
                Parameter { name: "lang", value: Type::Bool },
                Parameter { name: "has_login_delay", value: Type::Bool },
                Parameter { name: "login_delay", value: Type::U32 },
            ],
        },
        Definition::Opaque { name: "umilib_protocol_pop_v3_POP3Client", documentation: " A POP3 client without I/O." },
        Definition::Opaque { name: "umilib_protocol_pop_v3_POP3Server", documentation: " A POP3 server without I/O." },
        Definition::Opaque {
            name: "umilib_protocol_pop_v3_POP3MultiLineReader",
            documentation: " A reader of the lines of a multi-line response.",
        },
        Definition::Opaque {
            name: "umilib_protocol_pop_v3_POP3MultiLineWriter",
            documentation: " A writer of the lines of a multi-line response.",
        },
    ],
    functions: &crate::ffi::Function::concat::<{ FUNCTIONS.len() + APOP.len() }>(&[FUNCTIONS, APOP]),
    modules: &[],
};
