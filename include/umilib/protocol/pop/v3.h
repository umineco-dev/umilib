/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_POP_V3_H
#define UMILIB_PROTOCOL_POP_V3_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The limits and times (nanoseconds) of a POP3 connection.
 */
typedef struct umilib_protocol_pop_v3_POP3Config {
    size_t maximum_command_line;
    size_t maximum_response_line;
    size_t maximum_auth_line;
    size_t maximum_capabilities;
    size_t maximum_buffered;
    uint64_t response_timeout;
    uint64_t autologout;
    bool passwords_require_tls;
} umilib_protocol_pop_v3_POP3Config;

/**
 * The scalar fields of a POP3 server's configuration.
 */
typedef struct umilib_protocol_pop_v3_POP3ServerConfig {
    bool user;
    bool top;
    bool uidl;
    bool pipelining;
    bool response_codes;
    bool stls;
    bool passwords_require_tls;
    bool utf8;
    bool utf8_user;
    bool lang;
    bool has_login_delay;
    uint32_t login_delay;
} umilib_protocol_pop_v3_POP3ServerConfig;

/**
 * A POP3 client without I/O.
 */
typedef struct umilib_protocol_pop_v3_POP3Client umilib_protocol_pop_v3_POP3Client;

/**
 * A POP3 server without I/O.
 */
typedef struct umilib_protocol_pop_v3_POP3Server umilib_protocol_pop_v3_POP3Server;

/**
 * A reader of the lines of a multi-line response.
 */
typedef struct umilib_protocol_pop_v3_POP3MultiLineReader umilib_protocol_pop_v3_POP3MultiLineReader;

/**
 * A writer of the lines of a multi-line response.
 */
typedef struct umilib_protocol_pop_v3_POP3MultiLineWriter umilib_protocol_pop_v3_POP3MultiLineWriter;

/**
 * Writes the default configuration (the times of RFC 1939 §3) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_config_default(umilib_protocol_pop_v3_POP3Config* out);

/**
 * Writes the default scalar fields of a server's configuration into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_config_default(umilib_protocol_pop_v3_POP3ServerConfig* out);

/**
 * Writes the command line of the line at `line`, as this crate writes it, into `out`; fails for a
 * line that is not a command (UTF-8 arguments taken where `utf8`, RFC 6856).
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_command_normalize(const uint8_t* line, size_t length, bool utf8, umilib_ffi_Buffer* out);

/**
 * Writes whether the command of the line at `line` has a multi-line response when positive into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_command_is_multi_line(const uint8_t* line, size_t length, bool* out);

/**
 * Writes whether the status line at `line` is positive into `out_ok`, its response code (levels
 * joined by `/`, empty if none) into `out_code` and its text into `out_text` (RFC 2449 §8).
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_response_decode(const uint8_t* line, size_t length, bool* out_ok, umilib_ffi_Buffer* out_code, umilib_ffi_Buffer* out_text);

/**
 * Writes the status line of `ok`, the response code at `code` (levels joined by `/`, none if empty)
 * and the text at `text` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_response_encode(bool ok, const uint8_t* code, size_t code_length, const uint8_t* text, size_t text_length, umilib_ffi_Buffer* out);

/**
 * Writes whether the status line at `line` has a timestamp for APOP (RFC 1939 §7) into `out_found`
 * and the timestamp, its angle brackets included, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_response_timestamp(const uint8_t* line, size_t length, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes the capabilities of the lines of a CAPA list at `list` (its periods removed), each a line
 * of a tag in upper case and its parameters, joined by LF, into `out`; lines that are not
 * capabilities are left out (RFC 2449 §5).
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_capabilities_decode(const uint8_t* list, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the number of octets of the bytes at `data` as a multi-line response sends them, line
 * breaks as CRLF and without the added periods and the end, into `out` (RFC 6856 §2.1).
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_multi_line_canonical_length(const uint8_t* data, size_t length, uint64_t* out);

/**
 * Writes a reader of the lines of a multi-line response into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_multi_line_reader_new(umilib_protocol_pop_v3_POP3MultiLineReader** out);

/**
 * Reads the bytes at `input` to the end of the response: writes the octets read into `out_read`,
 * the lines, their added periods removed, into `out`, and whether the response ended into `out_end`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_multi_line_reader_read(umilib_protocol_pop_v3_POP3MultiLineReader* reader, const uint8_t* input, size_t length, size_t* out_read, umilib_ffi_Buffer* out, bool* out_end);

/**
 * Releases a reader. Does nothing if `reader` is null.
 */
void umilib_protocol_pop_v3_pop3_multi_line_reader_free(umilib_protocol_pop_v3_POP3MultiLineReader* reader);

/**
 * Writes a writer of the lines of a multi-line response into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_multi_line_writer_new(umilib_protocol_pop_v3_POP3MultiLineWriter** out);

/**
 * Writes the bytes at `data` as lines of the response into `out`: line breaks as CRLF, a period
 * added before a line that begins with one.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_multi_line_writer_write(umilib_protocol_pop_v3_POP3MultiLineWriter* writer, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the end of the response into `out`: a CRLF if the last line has none, and the line of a period.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_multi_line_writer_finish(umilib_protocol_pop_v3_POP3MultiLineWriter* writer, umilib_ffi_Buffer* out);

/**
 * Releases a writer. Does nothing if `writer` is null.
 */
void umilib_protocol_pop_v3_pop3_multi_line_writer_free(umilib_protocol_pop_v3_POP3MultiLineWriter* writer);

/**
 * Writes a client of a new connection into `out`; `secure` if it is TLS from its start (RFC 8314).
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_client_new(umilib_protocol_pop_v3_POP3Config config, bool secure, uint64_t now, umilib_protocol_pop_v3_POP3Client** out);

/**
 * Takes the `length` bytes at `data` the server sent.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_client_receive(umilib_protocol_pop_v3_POP3Client* client, const uint8_t* data, size_t length, uint64_t now);

/**
 * Queues the command of the line at `line` (UTF-8 arguments taken where `utf8`).
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_client_send(umilib_protocol_pop_v3_POP3Client* client, const uint8_t* line, size_t length, bool utf8, uint64_t now);

/**
 * Answers an AUTH challenge with the bytes at `response`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_client_auth_respond(umilib_protocol_pop_v3_POP3Client* client, const uint8_t* response, size_t length, uint64_t now);

/**
 * Cancels an AUTH exchange (RFC 5034 §4).
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_client_auth_cancel(umilib_protocol_pop_v3_POP3Client* client, uint64_t now);

/**
 * Writes what is to be sent into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_client_transmit(umilib_protocol_pop_v3_POP3Client* client, umilib_ffi_Buffer* out);

/**
 * Writes whether an event is pending into `out_found` and its contents into the outputs.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_client_poll_event(umilib_protocol_pop_v3_POP3Client* client, bool* out_found, uint8_t* out_kind, umilib_ffi_Buffer* out_command, umilib_ffi_Buffer* out_response, umilib_ffi_Buffer* out_data, const umilib_ffi_Status** out_error);

/**
 * Writes whether the client waits for a response into `out_found` and when it times out into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_client_poll_timeout(const umilib_protocol_pop_v3_POP3Client* client, bool* out_found, uint64_t* out);

/**
 * Times out what waits past `now`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_client_expire(umilib_protocol_pop_v3_POP3Client* client, uint64_t now);

/**
 * Writes whether the connection is open into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_client_is_open(const umilib_protocol_pop_v3_POP3Client* client, bool* out);

/**
 * Writes the session's state into `out`: 0 AUTHORIZATION, 1 TRANSACTION, 2 UPDATE (RFC 1939 §3).
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_client_state(const umilib_protocol_pop_v3_POP3Client* client, uint8_t* out);

/**
 * Writes whether the server announced the capability of the tag at `tag` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_client_has_capability(const umilib_protocol_pop_v3_POP3Client* client, const uint8_t* tag, size_t length, bool* out);

/**
 * Releases a client. Does nothing if `client` is null.
 */
void umilib_protocol_pop_v3_pop3_client_free(umilib_protocol_pop_v3_POP3Client* client);

/**
 * Writes a server of a new connection into `out`: of `config`, the scalar fields of `server`, the
 * arrays of SASL mechanisms, plaintext mechanisms and extension commands, and the texts of EXPIRE
 * and IMPLEMENTATION (none if null).
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_new(umilib_protocol_pop_v3_POP3Config config, umilib_protocol_pop_v3_POP3ServerConfig server, const char* const* mechanisms, size_t mechanism_count, const char* const* plaintext, size_t plaintext_count, const char* const* commands, size_t command_count, const uint8_t* expire, size_t expire_length, const uint8_t* implementation, size_t implementation_length, bool secure, umilib_protocol_pop_v3_POP3Server** out);

/**
 * Sends the greeting of the status line at `line`: +OK, with a timestamp in its text if APOP is
 * offered (RFC 1939 §7); -ERR closes the connection.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_greet(umilib_protocol_pop_v3_POP3Server* server, const uint8_t* line, size_t length, uint64_t now);

/**
 * Writes the capabilities the server would announce now (RFC 2449 §5), a line each with its CRLF,
 * without the period that ends the list, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_capabilities(const umilib_protocol_pop_v3_POP3Server* server, umilib_ffi_Buffer* out);

/**
 * Writes whether passwords sent as they are are taken now (RFC 5034 §4) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_passwords_taken(const umilib_protocol_pop_v3_POP3Server* server, bool* out);

/**
 * Writes whether the server takes more input now into `out`: false while what it holds of
 * the client (pipelined commands not yet answered) reaches `maximum_buffered`, so that a
 * peer cannot make it hold more; stop reading from the connection until it is true again.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_wants_receive(const umilib_protocol_pop_v3_POP3Server* server, bool* out);

/**
 * Takes the `length` bytes at `data` the client sent.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_receive(umilib_protocol_pop_v3_POP3Server* server, const uint8_t* data, size_t length, uint64_t now);

/**
 * Answers the command told with the status line at `line`; a positive answer to a multi-line
 * command is followed by its lines ([`umilib_protocol_pop_v3_pop3_server_send_data`]) and their end.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_reply(umilib_protocol_pop_v3_POP3Server* server, const uint8_t* line, size_t length, uint64_t now);

/**
 * Sends the bytes at `data` as lines of the multi-line response being sent.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_send_data(umilib_protocol_pop_v3_POP3Server* server, const uint8_t* data, size_t length);

/**
 * Ends the multi-line response being sent.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_end_data(umilib_protocol_pop_v3_POP3Server* server, uint64_t now);

/**
 * Sends the bytes at `challenge` as a challenge of the AUTH exchange told.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_auth_challenge(umilib_protocol_pop_v3_POP3Server* server, const uint8_t* challenge, size_t length, uint64_t now);

/**
 * Closes the connection with -ERR and the text at `text`: for shutting down.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_shutdown(umilib_protocol_pop_v3_POP3Server* server, const uint8_t* text, size_t length);

/**
 * Writes what is to be sent into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_transmit(umilib_protocol_pop_v3_POP3Server* server, umilib_ffi_Buffer* out);

/**
 * Writes whether an event is pending into `out_found` and its contents into the outputs.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_poll_event(umilib_protocol_pop_v3_POP3Server* server, bool* out_found, uint8_t* out_kind, umilib_ffi_Buffer* out_command, umilib_ffi_Buffer* out_response, umilib_ffi_Buffer* out_data, const umilib_ffi_Status** out_error);

/**
 * Writes whether the server waits for the client into `out_found` and until when (the
 * autologout timer, RFC 1939 §3) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_poll_timeout(const umilib_protocol_pop_v3_POP3Server* server, bool* out_found, uint64_t* out);

/**
 * Closes the connection, without a response, if the client was silent past its time.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_expire(umilib_protocol_pop_v3_POP3Server* server, uint64_t now);

/**
 * Writes whether the connection is open into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_server_is_open(const umilib_protocol_pop_v3_POP3Server* server, bool* out);

/**
 * Releases a server. Does nothing if `server` is null.
 */
void umilib_protocol_pop_v3_pop3_server_free(umilib_protocol_pop_v3_POP3Server* server);

/**
 * Writes the digest of APOP (RFC 1939 §7) of the timestamp at `timestamp` (its angle brackets
 * included) and the shared secret at `secret`, in lower-case hexadecimal, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_command_apop_digest(const uint8_t* timestamp, size_t timestamp_length, const uint8_t* secret, size_t secret_length, umilib_ffi_Buffer* out);

/**
 * Writes whether the digest at `digest` is that of the timestamp and the shared secret, compared
 * in constant time, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_pop_v3_pop3_command_apop_matches(const uint8_t* digest, size_t digest_length, const uint8_t* timestamp, size_t timestamp_length, const uint8_t* secret, size_t secret_length, bool* out);

#ifdef __cplusplus
}
#endif

#endif
