/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_QUIC_H
#define UMILIB_PROTOCOL_QUIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/ip.h"
#include "umilib/protocol/tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The limits and flags of a QUIC configuration; durations in milliseconds.
 */
typedef struct umilib_protocol_quic_QUICLimits {
    size_t connection_id_length;
    uint64_t max_idle_timeout;
    uint64_t max_udp_payload_size;
    size_t datagram_size;
    uint64_t initial_max_data;
    uint64_t initial_max_stream_data_bidi_local;
    uint64_t initial_max_stream_data_bidi_remote;
    uint64_t initial_max_stream_data_uni;
    uint64_t initial_max_streams_bidi;
    uint64_t initial_max_streams_uni;
    uint64_t ack_delay_exponent;
    uint64_t max_ack_delay;
    uint64_t active_connection_id_limit;
    uint64_t initial_rtt;
    uint64_t max_datagram_frame_size;
    bool disable_active_migration;
    bool pacing;
    bool grease_quic_bit;
    bool spin_bit;
    bool grease_transport_parameters;
    size_t maximum_crypto_buffer;
    size_t maximum_send_buffer;
    size_t maximum_datagrams;
} umilib_protocol_quic_QUICLimits;

/**
 * Where a QUIC connection stands.
 */
typedef struct umilib_protocol_quic_QUICSession {
    uint8_t state;
    uint32_t version;
    bool handshake_complete;
    bool handshake_confirmed;
    bool zero_rtt_rejected;
} umilib_protocol_quic_QUICSession;

/**
 * An event of a QUIC connection.
 */
typedef struct umilib_protocol_quic_QUICEvent {
    uint8_t kind;
    uint64_t stream;
    uint64_t error;
    bool bidirectional;
    uint8_t reason;
} umilib_protocol_quic_QUICEvent;

/**
 * The configuration of QUIC connections.
 */
typedef struct umilib_protocol_quic_QUICConfig umilib_protocol_quic_QUICConfig;

/**
 * A QUIC endpoint without I/O and its connections.
 */
typedef struct umilib_protocol_quic_QUICEndpoint umilib_protocol_quic_QUICEndpoint;

/**
 * Writes the default configuration (every version compiled in, version 1 first) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_config_new(umilib_protocol_quic_QUICConfig** out);

/**
 * Releases a configuration. Does nothing if `config` is null.
 */
void umilib_protocol_quic_quic_config_free(umilib_protocol_quic_QUICConfig* config);

/**
 * Sets the versions, most preferred first, to the `count` numbers at `versions`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_config_set_versions(umilib_protocol_quic_QUICConfig* config, const uint32_t* versions, size_t count);

/**
 * Writes the limits and flags of the configuration into `out`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_config_limits(const umilib_protocol_quic_QUICConfig* config, umilib_protocol_quic_QUICLimits* out);

/**
 * Sets the limits and flags of the configuration; fails with Config, changing nothing, if they cannot work.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_config_set_limits(umilib_protocol_quic_QUICConfig* config, const umilib_protocol_quic_QUICLimits* limits);

/**
 * Sets the key of stateless reset tokens to the 32 bytes at `key`, or none if `key` is null.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_config_set_reset_key(umilib_protocol_quic_QUICConfig* config, const uint8_t* key);

/**
 * Writes an endpoint of the connection configuration `config` into `out`: one that accepts
 * connections with the TLS configuration `tls`, or only connects if `tls` is null; with the 32
 * bytes at `token_key` (none if null) it validates addresses, with a Retry first if `retry`.
 * Its randomness is seeded by the `seed_length` bytes at `seed` (at least 48).
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_endpoint_new(const umilib_protocol_quic_QUICConfig* config, const umilib_protocol_tls_TLSServerConfig* tls, const uint8_t* token_key, bool retry, const uint8_t* seed, size_t seed_length, umilib_protocol_quic_QUICEndpoint** out);

/**
 * Releases an endpoint and its connections. Does nothing if `endpoint` is null.
 */
void umilib_protocol_quic_quic_endpoint_free(umilib_protocol_quic_QUICEndpoint* endpoint);

/**
 * Opens a connection to `remote` as the server `server_name` (none for 0 bytes) with the TLS
 * configuration `tls`, and the NEW_TOKEN token of `token_length` bytes at `token` (none for 0),
 * at `now` (nanoseconds) and `time` (seconds since 1970); its randomness is seeded by the
 * `seed_length` bytes at `seed` (at least 48). Writes its number into `out`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_endpoint_connect(umilib_protocol_quic_QUICEndpoint* endpoint, const umilib_protocol_tls_TLSClientConfig* tls, const uint8_t* server_name, size_t length, const umilib_protocol_ip_IPEndpoint* remote, const uint8_t* token, size_t token_length, const uint8_t* seed, size_t seed_length, uint64_t now, int64_t time, uint64_t* out);

/**
 * Takes the datagram of `length` bytes at `datagram` from `remote` with the ECN codepoint `ecn`
 * (0 Not-ECT, 1 ECT(1), 2 ECT(0), 3 CE); writes whether a connection took it into `out_found`
 * and its number into `out`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_endpoint_receive(umilib_protocol_quic_QUICEndpoint* endpoint, const uint8_t* datagram, size_t length, const umilib_protocol_ip_IPEndpoint* remote, uint8_t ecn, uint64_t now, int64_t time, bool* out_found, uint64_t* out);

/**
 * Writes the next datagram to send into `out` and its destination into `out_destination`, and
 * whether there was one into `out_found`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_endpoint_transmit(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t now, bool* out_found, umilib_protocol_ip_IPEndpoint* out_destination, umilib_ffi_Buffer* out);

/**
 * Writes whether a timer is set into `out_found` and when it fires (nanoseconds) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_endpoint_poll_timeout(const umilib_protocol_quic_QUICEndpoint* endpoint, bool* out_found, uint64_t* out);

/**
 * Fires the timers due at `now`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_endpoint_expire(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t now, int64_t time);

/**
 * Writes whether a connection was accepted into `out_found` and its number into `out`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_endpoint_accept(umilib_protocol_quic_QUICEndpoint* endpoint, bool* out_found, uint64_t* out);

/**
 * Writes where the connection `connection` stands into `out`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_connection_session(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t connection, umilib_protocol_quic_QUICSession* out);

/**
 * Writes the application protocol the connection negotiated (empty before) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_connection_protocol(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t connection, umilib_ffi_Buffer* out);

/**
 * Writes whether an event is pending into `out_found`, the event into `out`, and its token or
 * reason phrase into `out_bytes`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_connection_poll_event(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t connection, bool* out_found, umilib_protocol_quic_QUICEvent* out, umilib_ffi_Buffer* out_bytes);

/**
 * Opens a stream, bidirectional if `bidirectional`, and writes its ID into `out`; fails with
 * State at the peer's limit.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_connection_open_stream(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t connection, bool bidirectional, uint64_t* out);

/**
 * Writes the `length` bytes at `data` to the stream, as many as it takes (into `out`), and its
 * end after them if `fin`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_connection_stream_send(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t connection, uint64_t stream, const uint8_t* data, size_t length, bool fin, size_t* out);

/**
 * Reads up to `capacity` bytes of the stream into `out`; writes how many into `out_count` and
 * whether the stream ended into `out_fin`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_connection_stream_read(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t connection, uint64_t stream, uint8_t* out, size_t capacity, size_t* out_count, bool* out_fin);

/**
 * Resets the sending half of the stream with the application's `error`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_connection_stream_reset(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t connection, uint64_t stream, uint64_t error);

/**
 * Asks the peer to stop sending on the stream, with the application's `error`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_connection_stream_stop(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t connection, uint64_t stream, uint64_t error);

/**
 * Queues the DATAGRAM frame of the `length` bytes at `data`; fails with State if the peer does not accept it.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_connection_send_datagram(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t connection, const uint8_t* data, size_t length);

/**
 * Writes whether a DATAGRAM frame was received into `out_found` and its data into `out`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_connection_read_datagram(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t connection, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Closes the connection with the application's `error` and the reason of `length` bytes at `reason`.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_connection_close(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t connection, uint64_t error, const uint8_t* reason, size_t length, uint64_t now);

/**
 * Updates the 1-RTT keys; fails with State before the handshake is confirmed or while an update is unacknowledged.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_connection_update_keys(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t connection, uint64_t now);

/**
 * Asks the peer for an acknowledgment, as keep-alive.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_connection_ping(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t connection);

/**
 * Moves a client's connection to a new local address (the caller's next datagrams come from it);
 * fails with State before confirmation, when the server disabled it, or without a connection ID to spare.
 */
const umilib_ffi_Status* umilib_protocol_quic_quic_connection_migrate(umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t connection, uint64_t now);

#ifdef __cplusplus
}
#endif

#endif
