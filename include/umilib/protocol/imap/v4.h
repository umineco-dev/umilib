/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_IMAP_V4_H
#define UMILIB_PROTOCOL_IMAP_V4_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec/mail.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The limits and times (nanoseconds) of an IMAP connection.
 */
typedef struct umilib_protocol_imap_v4_IMAPConfig {
    size_t maximum_line;
    uint64_t maximum_literal;
    uint64_t maximum_command;
    size_t maximum_depth;
    size_t maximum_buffered;
    uint64_t command_timeout;
    uint64_t autologout;
    uint64_t login_timeout;
    bool passwords_require_tls;
} umilib_protocol_imap_v4_IMAPConfig;

/**
 * The scalar fields of an IMAP server's configuration.
 */
typedef struct umilib_protocol_imap_v4_IMAPServerConfig {
    bool rev1;
    bool starttls;
    bool passwords_require_tls;
    bool literal_plus;
} umilib_protocol_imap_v4_IMAPServerConfig;

/**
 * An IMAP client without I/O.
 */
typedef struct umilib_protocol_imap_v4_IMAPClient umilib_protocol_imap_v4_IMAPClient;

/**
 * An IMAP server without I/O.
 */
typedef struct umilib_protocol_imap_v4_IMAPServer umilib_protocol_imap_v4_IMAPServer;

/**
 * Writes the default configuration (the timers of RFC 9051 §5.4) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_config_default(umilib_protocol_imap_v4_IMAPConfig* out);

/**
 * Writes the default scalar fields of a server's configuration into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_config_default(umilib_protocol_imap_v4_IMAPServerConfig* out);

/**
 * Writes the logical line of the command at `line` (a tag and a command), as this crate writes
 * it, into `out`, its name (in upper case; `UID` and the command after it for one of UIDs) into
 * `out_name` and its tag into `out_tag`; fails for a line that is not a command.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_command_normalize(const uint8_t* line, size_t length, umilib_ffi_Buffer* out_tag, umilib_ffi_Buffer* out_name, umilib_ffi_Buffer* out);

/**
 * Writes the logical line of the response at `line`, as this crate writes it, into `out`; fails
 * for a line that is not a response.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_response_normalize(const uint8_t* line, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes whether the response at `line` is a status response (RFC 9051 §7.1) into `out_status`,
 * and then whether it is tagged into `out_tagged`, its tag into `out_tag`, its condition into
 * `out_condition`, its response code (brackets included; empty if none) into `out_code` and its
 * text into `out_text`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_response_status(const uint8_t* line, size_t length, bool* out_status, bool* out_tagged, umilib_ffi_Buffer* out_tag, uint8_t* out_condition, umilib_ffi_Buffer* out_code, umilib_ffi_Buffer* out_text);

/**
 * Writes the logical line of the status response of the tag at `tag` (untagged if none), the
 * condition `condition`, the response code at `code` (brackets included; none if empty) and
 * the text at `text` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_response_status_encode(const uint8_t* tag, size_t tag_length, uint8_t condition, const uint8_t* code, size_t code_length, const uint8_t* text, size_t text_length, umilib_ffi_Buffer* out);

/**
 * Writes the mailbox name of the UTF-8 text at `text` in modified UTF-7 (RFC 3501 §5.1.3) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_mailbox_encode_modified_utf7(const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the UTF-8 text of the mailbox name in modified UTF-7 at `name` into `out`; fails for
 * one that is not of modified UTF-7.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_mailbox_decode_modified_utf7(const uint8_t* name, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the sequence set at `text` (RFC 9051 §9), as this crate writes it, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_sequence_set_normalize(const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the ranges of the sequence set at `text` when `last` is the highest number (`*`), in
 * order and merged, as `a:b` or `a` joined by `,`, into `out`; empty for `$`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_sequence_set_resolve(const uint8_t* text, size_t length, uint32_t last, umilib_ffi_Buffer* out);

/**
 * Writes whether `number` is of the sequence set at `text` when `last` is the highest number into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_sequence_set_contains(const uint8_t* text, size_t length, uint32_t number, uint32_t last, bool* out);

/**
 * Writes the seconds since 1970 and the offset in minutes of the date-time at `text` (RFC 9051
 * §9 `date-time`, with its quotes) into the outputs.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_date_time_parse(const uint8_t* text, size_t length, int64_t* out_seconds, int16_t* out_offset);

/**
 * Writes the date-time of `seconds` since 1970 at the offset `offset` in minutes, with its
 * quotes, into `out`; `InvalidArgument` for a date-time of a year outside 0000 to 9999 or a
 * zone beyond 99 hours, which the syntax cannot write.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_date_time_format(int64_t seconds, int16_t offset, umilib_ffi_Buffer* out);

/**
 * Writes the ENVELOPE (RFC 9051 §7.5.2) of the message at `message`, of `config`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_envelope_of_message(const uint8_t* message, size_t length, umilib_codec_mail_MailConfig config, umilib_ffi_Buffer* out);

/**
 * Writes the BODYSTRUCTURE (RFC 9051 §7.5.2) of the message at `message`, of `config`, into
 * `out`; without extension data (BODY) unless `extensible`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_body_of_message(const uint8_t* message, size_t length, umilib_codec_mail_MailConfig config, bool extensible, umilib_ffi_Buffer* out);

/**
 * Writes whether the message at `message`, of `config`, has the section at `section` (RFC 9051
 * §6.4.5, with its brackets: `[1.HEADER]`) into `out_found`, and its octets into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_section_extract(const uint8_t* section, size_t section_length, const uint8_t* message, size_t length, umilib_codec_mail_MailConfig config, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes a client of a new connection into `out`: `secure` if it is TLS from its start (RFC
 * 8314), its tags the text at `prefix` and a number.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_new(umilib_protocol_imap_v4_IMAPConfig config, bool secure, const uint8_t* prefix, size_t prefix_length, uint64_t now, umilib_protocol_imap_v4_IMAPClient** out);

/**
 * Takes the `length` bytes at `data` the server sent.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_receive(umilib_protocol_imap_v4_IMAPClient* client, const uint8_t* data, size_t length, uint64_t now);

/**
 * Queues the command of the body at `body` (a command without its tag) and writes its tag into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_send(umilib_protocol_imap_v4_IMAPClient* client, const uint8_t* body, size_t length, uint64_t now, umilib_ffi_Buffer* out);

/**
 * Queues the command of the body at `body` with the tag at `tag`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_send_with_tag(umilib_protocol_imap_v4_IMAPClient* client, const uint8_t* tag, size_t tag_length, const uint8_t* body, size_t length, uint64_t now);

/**
 * Answers an AUTHENTICATE challenge with the bytes at `response`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_authenticate_respond(umilib_protocol_imap_v4_IMAPClient* client, const uint8_t* response, size_t length, uint64_t now);

/**
 * Cancels an AUTHENTICATE exchange with `*` (RFC 9051 §6.2.2).
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_authenticate_cancel(umilib_protocol_imap_v4_IMAPClient* client, uint64_t now);

/**
 * Ends IDLE with DONE (RFC 9051 §6.3.13).
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_idle_done(umilib_protocol_imap_v4_IMAPClient* client, uint64_t now);

/**
 * Takes the `count` capabilities at `capabilities` as those the server announced.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_learn_capabilities(umilib_protocol_imap_v4_IMAPClient* client, const char* const* capabilities, size_t count);

/**
 * Writes whether the server announced the capability at `capability` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_has_capability(const umilib_protocol_imap_v4_IMAPClient* client, const uint8_t* capability, size_t length, bool* out);

/**
 * Writes the session's state into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_state(const umilib_protocol_imap_v4_IMAPClient* client, uint8_t* out);

/**
 * Writes what is to be sent into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_transmit(umilib_protocol_imap_v4_IMAPClient* client, umilib_ffi_Buffer* out);

/**
 * Writes whether an event is pending into `out_found` and its contents into the outputs.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_poll_event(umilib_protocol_imap_v4_IMAPClient* client, bool* out_found, uint8_t* out_kind, umilib_ffi_Buffer* out_tag, umilib_ffi_Buffer* out_command, umilib_ffi_Buffer* out_response, umilib_ffi_Buffer* out_data, const umilib_ffi_Status** out_error);

/**
 * Writes whether the client waits for a response into `out_found` and when it times out into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_poll_timeout(const umilib_protocol_imap_v4_IMAPClient* client, bool* out_found, uint64_t* out);

/**
 * Times out what waits past `now`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_expire(umilib_protocol_imap_v4_IMAPClient* client, uint64_t now);

/**
 * Writes whether the connection is open into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_client_is_open(const umilib_protocol_imap_v4_IMAPClient* client, bool* out);

/**
 * Releases a client. Does nothing if `client` is null.
 */
void umilib_protocol_imap_v4_imap_client_free(umilib_protocol_imap_v4_IMAPClient* client);

/**
 * Writes a server of a new connection into `out`: of `config`, the scalar fields of `server`,
 * and the arrays of SASL mechanisms, plaintext mechanisms, other capabilities and extension commands.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_new(umilib_protocol_imap_v4_IMAPConfig config, umilib_protocol_imap_v4_IMAPServerConfig server, const char* const* mechanisms, size_t mechanism_count, const char* const* plaintext, size_t plaintext_count, const char* const* capabilities, size_t capability_count, const char* const* commands, size_t command_count, bool secure, umilib_protocol_imap_v4_IMAPServer** out);

/**
 * Sends the greeting of `condition` (OK, PREAUTH or BYE) and the text at `text`, with the
 * capabilities (RFC 9051 §7.1).
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_greet(umilib_protocol_imap_v4_IMAPServer* server, uint8_t condition, const uint8_t* text, size_t length, uint64_t now);

/**
 * Writes the capabilities the server announces now, joined by spaces, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_capabilities(const umilib_protocol_imap_v4_IMAPServer* server, umilib_ffi_Buffer* out);

/**
 * Writes whether passwords sent as they are are taken now (RFC 9051 §6.2.3) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_passwords_taken(const umilib_protocol_imap_v4_IMAPServer* server, bool* out);

/**
 * Writes whether IMAP4rev2 is in use (the server offers it alone, or the client enabled it)
 * into `out`: SEARCH is answered with ESEARCH and RECENT is not sent then.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_rev2(const umilib_protocol_imap_v4_IMAPServer* server, bool* out);

/**
 * Writes the session's state into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_state(const umilib_protocol_imap_v4_IMAPServer* server, uint8_t* out);

/**
 * Writes whether the server takes more input now into `out`: false while what it holds of
 * the client (pipelined commands not yet answered) reaches `maximum_buffered`, so that a
 * peer cannot make it hold more; stop reading from the connection until it is true again.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_wants_receive(const umilib_protocol_imap_v4_IMAPServer* server, bool* out);

/**
 * Takes the `length` bytes at `data` the client sent.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_receive(umilib_protocol_imap_v4_IMAPServer* server, const uint8_t* data, size_t length, uint64_t now);

/**
 * Sends the untagged response at `line` of the command told.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_respond(umilib_protocol_imap_v4_IMAPServer* server, const uint8_t* line, size_t length);

/**
 * Completes the command told with its tagged response of `condition` (OK, NO or BAD), the response
 * code at `code` (brackets included; none if empty) and the text at `text` (RFC 9051 §7.1).
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_complete(umilib_protocol_imap_v4_IMAPServer* server, uint8_t condition, const uint8_t* code, size_t code_length, const uint8_t* text, size_t text_length, uint64_t now);

/**
 * Sends the bytes at `challenge` as a challenge of the AUTHENTICATE told.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_authenticate_challenge(umilib_protocol_imap_v4_IMAPServer* server, const uint8_t* challenge, size_t length, uint64_t now);

/**
 * Accepts the IDLE told with a continuation request of the text at `text` (RFC 9051 §6.3.13).
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_idle(umilib_protocol_imap_v4_IMAPServer* server, const uint8_t* text, size_t length, uint64_t now);

/**
 * Closes the connection with an untagged BYE of the text at `text` (RFC 9051 §7.1.5).
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_shutdown(umilib_protocol_imap_v4_IMAPServer* server, const uint8_t* text, size_t length);

/**
 * Writes what is to be sent into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_transmit(umilib_protocol_imap_v4_IMAPServer* server, umilib_ffi_Buffer* out);

/**
 * Writes whether an event is pending into `out_found` and its contents into the outputs.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_poll_event(umilib_protocol_imap_v4_IMAPServer* server, bool* out_found, uint8_t* out_kind, umilib_ffi_Buffer* out_tag, umilib_ffi_Buffer* out_command, umilib_ffi_Buffer* out_response, umilib_ffi_Buffer* out_data, const umilib_ffi_Status** out_error);

/**
 * Writes whether the server waits for the client into `out_found` and until when (the
 * autologout timer, RFC 9051 §5.4) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_poll_timeout(const umilib_protocol_imap_v4_IMAPServer* server, bool* out_found, uint64_t* out);

/**
 * Closes the connection with BYE if the client was silent past its time.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_expire(umilib_protocol_imap_v4_IMAPServer* server, uint64_t now);

/**
 * Writes whether the connection is open into `out`.
 */
const umilib_ffi_Status* umilib_protocol_imap_v4_imap_server_is_open(const umilib_protocol_imap_v4_IMAPServer* server, bool* out);

/**
 * Releases a server. Does nothing if `server` is null.
 */
void umilib_protocol_imap_v4_imap_server_free(umilib_protocol_imap_v4_IMAPServer* server);

#ifdef __cplusplus
}
#endif

#endif
