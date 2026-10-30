/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_FTP_H
#define UMILIB_PROTOCOL_FTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The address of a data connection: the first `length` (4 or 16) octets the host, none if 0.
 */
typedef struct umilib_protocol_ftp_FTPDataAddress {
    uint8_t octets[16];
    uint8_t length;
    uint16_t port;
} umilib_protocol_ftp_FTPDataAddress;

/**
 * The limits and times (nanoseconds) of an FTP control connection.
 */
typedef struct umilib_protocol_ftp_FTPConfig {
    size_t maximum_line;
    size_t maximum_reply_lines;
    size_t maximum_buffered;
    uint64_t reply_timeout;
    uint64_t idle_timeout;
} umilib_protocol_ftp_FTPConfig;

/**
 * The scalar fields of an FTP server's configuration.
 */
typedef struct umilib_protocol_ftp_FTPServerConfig {
    bool tls;
    bool require_tls;
    bool require_protection;
    bool allow_ccc;
    bool allow_foreign_data;
    bool size;
    bool mdtm;
    bool rest_stream;
    bool utf8;
    bool host;
} umilib_protocol_ftp_FTPServerConfig;

/**
 * An FTP client of the control connection, without I/O.
 */
typedef struct umilib_protocol_ftp_FTPClient umilib_protocol_ftp_FTPClient;

/**
 * An FTP server of the control connection, without I/O.
 */
typedef struct umilib_protocol_ftp_FTPServer umilib_protocol_ftp_FTPServer;

/**
 * Writes the default configuration into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_config_default(umilib_protocol_ftp_FTPConfig* out);

/**
 * Writes the default scalar fields of a server's configuration into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_server_config_default(umilib_protocol_ftp_FTPServerConfig* out);

/**
 * Writes the command line of the line at `line`, as this crate writes it, into `out`, and whether
 * the command transfers data on a data connection into `out_transfers`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_command_normalize(const uint8_t* line, size_t length, bool* out_transfers, umilib_ffi_Buffer* out);

/**
 * Writes the code of the reply of the text at `wire` into `out_code` and its lines, joined by LF,
 * into `out_lines` (RFC 959 §4.2).
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_reply_decode(const uint8_t* wire, size_t length, uint16_t* out_code, umilib_ffi_Buffer* out_lines);

/**
 * Writes the text on the wire of the reply of `code` and the lines at `lines` (joined by LF) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_reply_encode(uint16_t code, const uint8_t* lines, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes whether the reply at `wire` names a pathname (of PWD and MKD, RFC 959 Appendix II) into
 * `out_found` and the pathname into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_reply_pathname(const uint8_t* wire, size_t length, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes the 257 reply of the pathname at `pathname` and the text at `text` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_reply_with_pathname(const uint8_t* pathname, size_t pathname_length, const uint8_t* text, size_t text_length, umilib_ffi_Buffer* out);

/**
 * Writes the features of the reply to FEAT at `wire`, a line each of a name in upper case and its
 * parameters, joined by LF, into `out` (RFC 2389 §3.2).
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_features_decode(const uint8_t* wire, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the address of the argument of PORT at `text` (RFC 959 §4.1.2) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_data_address_parse_port(const uint8_t* text, size_t length, umilib_protocol_ftp_FTPDataAddress* out);

/**
 * Writes the argument of PORT of the IPv4 address `address` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_data_address_format_port(umilib_protocol_ftp_FTPDataAddress address, umilib_ffi_Buffer* out);

/**
 * Writes the address of the argument of EPRT at `text` (RFC 2428 §2) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_data_address_parse_eprt(const uint8_t* text, size_t length, umilib_protocol_ftp_FTPDataAddress* out);

/**
 * Writes the argument of EPRT of `address` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_data_address_format_eprt(umilib_protocol_ftp_FTPDataAddress address, umilib_ffi_Buffer* out);

/**
 * Writes the address of the 227 reply to PASV at `wire` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_data_address_from_pasv(const uint8_t* wire, size_t length, umilib_protocol_ftp_FTPDataAddress* out);

/**
 * Writes the 227 reply to PASV of the IPv4 address `address` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_data_address_pasv_reply(umilib_protocol_ftp_FTPDataAddress address, umilib_ffi_Buffer* out);

/**
 * Writes the address (a port, no host) of the 229 reply to EPSV at `wire` into `out` (RFC 2428 §3).
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_data_address_from_epsv(const uint8_t* wire, size_t length, umilib_protocol_ftp_FTPDataAddress* out);

/**
 * Writes the 229 reply to EPSV of the port of `address` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_data_address_epsv_reply(umilib_protocol_ftp_FTPDataAddress address, umilib_ffi_Buffer* out);

/**
 * Writes the seconds since 1970 and the nanoseconds of the time-val at `text` (RFC 3659 §2.3) into the outputs.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_time_parse(const uint8_t* text, size_t length, int64_t* out_seconds, uint32_t* out_nanoseconds);

/**
 * Writes the time-val of `seconds` since 1970 and `nanoseconds` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_time_format(int64_t seconds, uint32_t nanoseconds, umilib_ffi_Buffer* out);

/**
 * Writes the entry of facts of the line at `line` (of MLSD, RFC 3659 §7.2), as this crate writes
 * it, its fact names in lower case, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_facts_normalize(const uint8_t* line, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes a client of a new control connection into `out`; `secure` if it is TLS from its start.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_client_new(umilib_protocol_ftp_FTPConfig config, bool secure, uint64_t now, umilib_protocol_ftp_FTPClient** out);

/**
 * Takes the `length` bytes at `data` the server sent.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_client_receive(umilib_protocol_ftp_FTPClient* client, const uint8_t* data, size_t length, uint64_t now);

/**
 * Queues the command of the line at `line`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_client_send(umilib_protocol_ftp_FTPClient* client, const uint8_t* line, size_t length, uint64_t now);

/**
 * Writes what is to be sent into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_client_transmit(umilib_protocol_ftp_FTPClient* client, umilib_ffi_Buffer* out);

/**
 * Writes whether an event is pending into `out_found` and its contents into the outputs.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_client_poll_event(umilib_protocol_ftp_FTPClient* client, bool* out_found, uint8_t* out_kind, umilib_ffi_Buffer* out_command, umilib_ffi_Buffer* out_reply, const umilib_ffi_Status** out_error);

/**
 * Writes whether the client waits for a reply into `out_found` and when it times out into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_client_poll_timeout(const umilib_protocol_ftp_FTPClient* client, bool* out_found, uint64_t* out);

/**
 * Times out what waits past `now`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_client_expire(umilib_protocol_ftp_FTPClient* client, uint64_t now);

/**
 * Writes whether the connection is open into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_client_is_open(const umilib_protocol_ftp_FTPClient* client, bool* out);

/**
 * Writes whether the server listed the feature of the name at `name` (RFC 2389) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_client_has_feature(const umilib_protocol_ftp_FTPClient* client, const uint8_t* name, size_t length, bool* out);

/**
 * Releases a client. Does nothing if `client` is null.
 */
void umilib_protocol_ftp_ftp_client_free(umilib_protocol_ftp_FTPClient* client);

/**
 * Writes a server of a new control connection from the host of the `peer_length` (4 or 16)
 * octets at `peer` into `out`: of `config`, the scalar fields of `server`, the system's type at
 * `system`, and the arrays of MLST facts, other features and extension commands.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_server_new(umilib_protocol_ftp_FTPConfig config, umilib_protocol_ftp_FTPServerConfig server, const uint8_t* system, size_t system_length, const char* const* facts, size_t fact_count, const char* const* features, size_t feature_count, const char* const* commands, size_t command_count, const uint8_t* peer, size_t peer_length, bool secure, umilib_protocol_ftp_FTPServer** out);

/**
 * Sends the greeting of the reply at `wire`: 220, or 421 (RFC 959 §5.4).
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_server_greet(umilib_protocol_ftp_FTPServer* server, const uint8_t* wire, size_t length, uint64_t now);

/**
 * Writes the reply to FEAT the server would send now into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_server_features(const umilib_protocol_ftp_FTPServer* server, umilib_ffi_Buffer* out);

/**
 * Writes whether the server takes more input now into `out`: false while what it holds of
 * the client (pipelined commands not yet answered) reaches `maximum_buffered`, so that a
 * peer cannot make it hold more; stop reading from the connection until it is true again.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_server_wants_receive(const umilib_protocol_ftp_FTPServer* server, bool* out);

/**
 * Takes the `length` bytes at `data` the client sent.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_server_receive(umilib_protocol_ftp_FTPServer* server, const uint8_t* data, size_t length, uint64_t now);

/**
 * Answers the command told with the reply at `wire`: of a transfer, a preliminary reply (1xx)
 * and then its final one.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_server_reply(umilib_protocol_ftp_FTPServer* server, const uint8_t* wire, size_t length, uint64_t now);

/**
 * Closes the connection with 421 and the text at `text`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_server_shutdown(umilib_protocol_ftp_FTPServer* server, const uint8_t* text, size_t length);

/**
 * Writes what is to be sent into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_server_transmit(umilib_protocol_ftp_FTPServer* server, umilib_ffi_Buffer* out);

/**
 * Writes whether an event is pending into `out_found` and its contents into the outputs.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_server_poll_event(umilib_protocol_ftp_FTPServer* server, bool* out_found, uint8_t* out_kind, umilib_ffi_Buffer* out_command, umilib_ffi_Buffer* out_reply, const umilib_ffi_Status** out_error);

/**
 * Writes whether the server waits for a command into `out_found` and until when into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_server_poll_timeout(const umilib_protocol_ftp_FTPServer* server, bool* out_found, uint64_t* out);

/**
 * Closes the connection with 421 if the client was idle past its time.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_server_expire(umilib_protocol_ftp_FTPServer* server, uint64_t now);

/**
 * Writes whether the connection is open into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_server_is_open(const umilib_protocol_ftp_FTPServer* server, bool* out);

/**
 * Writes what the session set into the outputs: whether a user is logged in, the
 * representation type of TYPE (`A N`, `I` or `L 8`), the mode of MODE and the structure of
 * STRU (as ASCII letters), the protection of data connections of PROT (`C` or `P`, RFC 4217
 * §9), and whether a REST marker is set for the next transfer and the marker.
 */
const umilib_ffi_Status* umilib_protocol_ftp_ftp_server_session(const umilib_protocol_ftp_FTPServer* server, bool* out_logged_in, umilib_ffi_Buffer* out_representation, uint8_t* out_mode, uint8_t* out_structure, uint8_t* out_protection, bool* out_has_restart, umilib_ffi_Buffer* out_restart);

/**
 * Releases a server. Does nothing if `server` is null.
 */
void umilib_protocol_ftp_ftp_server_free(umilib_protocol_ftp_FTPServer* server);

#ifdef __cplusplus
}
#endif

#endif
