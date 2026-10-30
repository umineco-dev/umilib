/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_SMTP_H
#define UMILIB_PROTOCOL_SMTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The limits and times (nanoseconds) of an SMTP connection.
 */
typedef struct umilib_protocol_smtp_SMTPConfig {
    size_t maximum_command_line;
    size_t maximum_reply_line;
    size_t maximum_reply_lines;
    size_t maximum_text_line;
    size_t maximum_auth_line;
    size_t maximum_buffered;
    uint64_t greeting_timeout;
    uint64_t command_timeout;
    uint64_t data_initiation_timeout;
    uint64_t data_termination_timeout;
    uint64_t server_timeout;
    bool passwords_require_tls;
} umilib_protocol_smtp_SMTPConfig;

/**
 * The scalar fields of an SMTP server's configuration.
 */
typedef struct umilib_protocol_smtp_SMTPServerConfig {
    uint64_t maximum_message_size;
    size_t maximum_recipients;
    bool pipelining;
    bool eight_bit_mime;
    bool smtputf8;
    bool chunking;
    bool binary_mime;
    bool dsn;
    bool enhanced_status_codes;
    bool starttls;
    bool passwords_require_tls;
    bool requires_tls;
    bool requires_auth;
} umilib_protocol_smtp_SMTPServerConfig;

/**
 * An SMTP client without I/O.
 */
typedef struct umilib_protocol_smtp_SMTPClient umilib_protocol_smtp_SMTPClient;

/**
 * An SMTP server without I/O.
 */
typedef struct umilib_protocol_smtp_SMTPServer umilib_protocol_smtp_SMTPServer;

/**
 * A reader of the mail data of DATA.
 */
typedef struct umilib_protocol_smtp_SMTPDataReader umilib_protocol_smtp_SMTPDataReader;

/**
 * Writes the default configuration (the minimums and times of RFC 5321 §4.5.3) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_config_default(umilib_protocol_smtp_SMTPConfig* out);

/**
 * Writes the default scalar fields of a server's configuration into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_config_default(umilib_protocol_smtp_SMTPServerConfig* out);

/**
 * Writes the command line of the line at `line`, as this crate writes it, into `out`; fails for a
 * line that is not a command (UTF-8 taken where `utf8`, RFC 6531).
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_command_normalize(const uint8_t* line, size_t length, bool utf8, umilib_ffi_Buffer* out);

/**
 * Writes the code of the reply of the text at `wire` into `out_code` and its lines, joined by LF,
 * into `out_lines`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_reply_decode(const uint8_t* wire, size_t length, uint16_t* out_code, umilib_ffi_Buffer* out_lines);

/**
 * Writes the text on the wire of the reply of `code` and the lines at `lines` (joined by LF) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_reply_encode(uint16_t code, const uint8_t* lines, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes whether the first line of the reply text at `wire` begins with an enhanced status code of
 * its class into `out_found`, and the code's class, subject and detail into the outputs (RFC 2034).
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_reply_status(const uint8_t* wire, size_t length, bool* out_found, uint8_t* out_class, uint16_t* out_subject, uint16_t* out_detail);

/**
 * Writes the greeting of the reply to EHLO at `wire` into `out_greeting` and its extensions, each
 * a line of a keyword and its parameters, joined by LF, into `out_entries`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_extensions_decode(const uint8_t* wire, size_t length, umilib_ffi_Buffer* out_greeting, umilib_ffi_Buffer* out_entries);

/**
 * Writes the local part and the domain of the mailbox at `text` into the outputs (RFC 5321 §4.1.2).
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_mailbox_parse(const uint8_t* text, size_t length, bool utf8, umilib_ffi_Buffer* out_local, umilib_ffi_Buffer* out_domain);

/**
 * Writes the mailbox of the local part at `local` and the domain at `domain` as it is written into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_mailbox_format(const uint8_t* local, size_t local_length, const uint8_t* domain, size_t domain_length, umilib_ffi_Buffer* out);

/**
 * Writes the xtext of the bytes at `data` into `out` (RFC 3461 §4).
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_xtext_encode(const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the bytes of the xtext at `text` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_xtext_decode(const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the message at `message` as mail data (RFC 5321 §4.5.2) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_data_encode(const uint8_t* message, size_t length, size_t maximum_line, umilib_ffi_Buffer* out);

/**
 * Writes a reader of mail data of at most `maximum_size` octets delivered and lines of at most
 * `maximum_line` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_data_reader_new(uint64_t maximum_size, size_t maximum_line, umilib_protocol_smtp_SMTPDataReader** out);

/**
 * Reads the bytes at `input` to the end of the data: writes the octets read into `out_read`, the
 * data into `out`, and whether the data ended into `out_end`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_data_reader_read(umilib_protocol_smtp_SMTPDataReader* reader, const uint8_t* input, size_t length, size_t* out_read, umilib_ffi_Buffer* out, bool* out_end);

/**
 * Writes whether the end of the data was read into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_data_reader_is_end(const umilib_protocol_smtp_SMTPDataReader* reader, bool* out);

/**
 * Writes the error of the data read into `out` (null if it is of the data SMTP takes).
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_data_reader_error(const umilib_protocol_smtp_SMTPDataReader* reader, const umilib_ffi_Status** out);

/**
 * Releases a reader of mail data. Does nothing if `reader` is null.
 */
void umilib_protocol_smtp_smtp_data_reader_free(umilib_protocol_smtp_SMTPDataReader* reader);

/**
 * Writes a client of a new connection into `out`; `secure` if it is TLS from its start.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_client_new(umilib_protocol_smtp_SMTPConfig config, bool secure, uint64_t now, umilib_protocol_smtp_SMTPClient** out);

/**
 * Takes the `length` bytes at `data` the server sent.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_client_receive(umilib_protocol_smtp_SMTPClient* client, const uint8_t* data, size_t length, uint64_t now);

/**
 * Queues the command of the line at `line` (UTF-8 taken where `utf8`).
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_client_send(umilib_protocol_smtp_SMTPClient* client, const uint8_t* line, size_t length, bool utf8, uint64_t now);

/**
 * Sends the message at `message` after the server's 354 to DATA.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_client_send_data(umilib_protocol_smtp_SMTPClient* client, const uint8_t* message, size_t length, uint64_t now);

/**
 * Sends the bytes at `data` as a chunk of BDAT, the last if `last` (RFC 3030).
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_client_send_chunk(umilib_protocol_smtp_SMTPClient* client, const uint8_t* data, size_t length, bool last, uint64_t now);

/**
 * Answers an AUTH challenge with the bytes at `response`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_client_auth_respond(umilib_protocol_smtp_SMTPClient* client, const uint8_t* response, size_t length, uint64_t now);

/**
 * Cancels an AUTH exchange.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_client_auth_cancel(umilib_protocol_smtp_SMTPClient* client, uint64_t now);

/**
 * Writes what is to be sent into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_client_transmit(umilib_protocol_smtp_SMTPClient* client, umilib_ffi_Buffer* out);

/**
 * Writes whether an event is pending into `out_found` and its contents into the outputs.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_client_poll_event(umilib_protocol_smtp_SMTPClient* client, bool* out_found, uint8_t* out_kind, umilib_ffi_Buffer* out_command, umilib_ffi_Buffer* out_reply, umilib_ffi_Buffer* out_data, bool* out_last, const umilib_ffi_Status** out_error);

/**
 * Writes whether the client waits for anything into `out_found` and when it times out into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_client_poll_timeout(const umilib_protocol_smtp_SMTPClient* client, bool* out_found, uint64_t* out);

/**
 * Times out what waits past `now`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_client_expire(umilib_protocol_smtp_SMTPClient* client, uint64_t now);

/**
 * Writes whether the connection is open into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_client_is_open(const umilib_protocol_smtp_SMTPClient* client, bool* out);

/**
 * Writes whether the server advertised the extension of the UTF-8 keyword at `keyword` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_client_has_extension(const umilib_protocol_smtp_SMTPClient* client, const uint8_t* keyword, size_t length, bool* out);

/**
 * Releases a client. Does nothing if `client` is null.
 */
void umilib_protocol_smtp_smtp_client_free(umilib_protocol_smtp_SMTPClient* client);

/**
 * Writes a server of a new connection into `out`: of `config`, the scalar fields of `server`, the
 * domain at `domain`, and the arrays of mechanisms, plaintext mechanisms and extension commands.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_new(umilib_protocol_smtp_SMTPConfig config, umilib_protocol_smtp_SMTPServerConfig server, const uint8_t* domain, size_t domain_length, const char* const* mechanisms, size_t mechanism_count, const char* const* plaintext, size_t plaintext_count, const char* const* commands, size_t command_count, bool secure, umilib_protocol_smtp_SMTPServer** out);

/**
 * Sends the greeting of the reply text at `wire`: 220, or 554.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_greet(umilib_protocol_smtp_SMTPServer* server, const uint8_t* wire, size_t length, uint64_t now);

/**
 * Writes the server's greeting of its domain into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_greeting(const umilib_protocol_smtp_SMTPServer* server, umilib_ffi_Buffer* out);

/**
 * Writes whether the server takes more input now into `out`: false while what it holds of
 * the client (pipelined commands not yet answered) reaches `maximum_buffered`, so that a
 * peer cannot make it hold more; stop reading from the connection until it is true again.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_wants_receive(const umilib_protocol_smtp_SMTPServer* server, bool* out);

/**
 * Takes the `length` bytes at `data` the client sent.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_receive(umilib_protocol_smtp_SMTPServer* server, const uint8_t* data, size_t length, uint64_t now);

/**
 * Answers the command told with the reply text at `wire`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_reply(umilib_protocol_smtp_SMTPServer* server, const uint8_t* wire, size_t length, uint64_t now);

/**
 * Sends the bytes at `challenge` as a challenge of the AUTH exchange told.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_auth_challenge(umilib_protocol_smtp_SMTPServer* server, const uint8_t* challenge, size_t length, uint64_t now);

/**
 * Writes the reply to EHLO the server would send now (its extensions) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_extensions(const umilib_protocol_smtp_SMTPServer* server, umilib_ffi_Buffer* out);

/**
 * Closes the connection with 421 and the UTF-8 text at `text`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_shutdown(umilib_protocol_smtp_SMTPServer* server, const uint8_t* text, size_t length);

/**
 * Writes what is to be sent into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_transmit(umilib_protocol_smtp_SMTPServer* server, umilib_ffi_Buffer* out);

/**
 * Writes whether an event is pending into `out_found` and its contents into the outputs.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_poll_event(umilib_protocol_smtp_SMTPServer* server, bool* out_found, uint8_t* out_kind, umilib_ffi_Buffer* out_command, umilib_ffi_Buffer* out_reply, umilib_ffi_Buffer* out_data, bool* out_last, const umilib_ffi_Status** out_error);

/**
 * Writes whether the server waits for the client into `out_found` and until when into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_poll_timeout(const umilib_protocol_smtp_SMTPServer* server, bool* out_found, uint64_t* out);

/**
 * Closes the connection with 421 if the client was silent past its time.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_expire(umilib_protocol_smtp_SMTPServer* server, uint64_t now);

/**
 * Writes whether the connection is open into `out`.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_server_is_open(const umilib_protocol_smtp_SMTPServer* server, bool* out);

/**
 * Releases a server. Does nothing if `server` is null.
 */
void umilib_protocol_smtp_smtp_server_free(umilib_protocol_smtp_SMTPServer* server);

/**
 * Writes the hosts of the mail of the domain at `domain`, in the order to try them, one a line
 * of its preference and name, into `out`: of the MX records of the zone-file text at `records`
 * (absolute names), without the hosts at or after the preference of the `local_count` names at
 * `local` (this host), those of one preference in an order drawn from `random`. Fails with NoMail
 * for a null MX (RFC 7505) and when no host is left.
 */
const umilib_ffi_Status* umilib_protocol_smtp_smtp_mail_exchanger_order(const uint8_t* domain, size_t domain_length, const uint8_t* records, size_t records_length, const char* const* local, size_t local_count, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
