/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_DNS_QUIC_H
#define UMILIB_PROTOCOL_DNS_QUIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/quic.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The DNS of a QUIC connection.
 */
typedef struct umilib_protocol_dns_quic_DNSQUICConnection umilib_protocol_dns_quic_DNSQUICConnection;

/**
 * An event: 0 a query, 1 a response, 2 a stream cancelled, 3 an event of QUIC.
 */
typedef struct umilib_protocol_dns_quic_DNSQUICEvent {
    uint8_t kind;
    uint64_t stream;
    uint64_t error;
} umilib_protocol_dns_quic_DNSQUICEvent;

/**
 * Writes the DNS of a connection of a client (or, if `server`, of a server) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_quic_dns_quic_connection_new(bool server, umilib_protocol_dns_quic_DNSQUICConnection** out);

/**
 * Releases a connection's DNS. Does nothing if `connection` is null.
 */
void umilib_protocol_dns_quic_dns_quic_connection_free(umilib_protocol_dns_quic_DNSQUICConnection* connection);

/**
 * Sends the query of the `length` bytes at `query` on a new stream of the QUIC connection `quic`
 * of `endpoint` (its ID made 0, RFC 9250 §4.2.1), and writes the stream into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_quic_dns_quic_connection_send_query(umilib_protocol_dns_quic_DNSQUICConnection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic, const uint8_t* query, size_t length, uint64_t* out);

/**
 * Sends the responses of the `length` bytes at `responses` (each after its 2-byte length, as
 * `dns_authority_respond` writes them: one, or the messages of a zone transfer) to the query of
 * `stream`, the stream ended after them; fails with Malformed for bytes not so framed.
 */
const umilib_ffi_Status* umilib_protocol_dns_quic_dns_quic_connection_send_response(umilib_protocol_dns_quic_DNSQUICConnection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic, uint64_t stream, const uint8_t* responses, size_t length);

/**
 * Takes the events of the QUIC connection `quic` of `endpoint` at `now`; a breach of RFC 9250
 * closes the connection and fails with Protocol.
 */
const umilib_ffi_Status* umilib_protocol_dns_quic_dns_quic_connection_process(umilib_protocol_dns_quic_DNSQUICConnection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic, uint64_t now);

/**
 * Writes whether an event is pending into `out_found`, the event into `out`, and its message (or,
 * for an event of QUIC, its token or reason phrase) into `out_message`; an event of QUIC itself
 * into `out_quic`.
 */
const umilib_ffi_Status* umilib_protocol_dns_quic_dns_quic_connection_poll_event(umilib_protocol_dns_quic_DNSQUICConnection* connection, bool* out_found, umilib_protocol_dns_quic_DNSQUICEvent* out, umilib_protocol_quic_QUICEvent* out_quic, umilib_ffi_Buffer* out_message);

#ifdef __cplusplus
}
#endif

#endif
