/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_TCP_H
#define UMILIB_PROTOCOL_TCP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/ip.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The fixed 20 bytes of a TCP header (RFC 9293 §3.1), its fields as they are.
 */
typedef struct umilib_protocol_tcp_TCPHeader {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence;
    uint32_t acknowledgment;
    uint8_t data_offset;
    uint8_t reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
} umilib_protocol_tcp_TCPHeader;

/**
 * The fields of a TCP segment but its options and data.
 */
typedef struct umilib_protocol_tcp_TCPSegment {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence;
    uint32_t acknowledgment;
    uint8_t flags;
    uint16_t window;
    uint16_t urgent_pointer;
} umilib_protocol_tcp_TCPSegment;

/**
 * A block of a SACK option (RFC 2018 §3): from `left` up to `right`.
 */
typedef struct umilib_protocol_tcp_TCPSACKBlock {
    uint32_t left;
    uint32_t right;
} umilib_protocol_tcp_TCPSACKBlock;

/**
 * The values of a Timestamps option (RFC 7323 §3.2).
 */
typedef struct umilib_protocol_tcp_TCPTimestamps {
    uint32_t value;
    uint32_t echo_reply;
} umilib_protocol_tcp_TCPTimestamps;

/**
 * The options this crate understands, each optional one with whether it is present.
 */
typedef struct umilib_protocol_tcp_TCPOptionSet {
    bool has_mss;
    uint16_t mss;
    bool has_window_scale;
    uint8_t window_scale;
    bool sack_permitted;
    bool has_timestamps;
    umilib_protocol_tcp_TCPTimestamps timestamps;
    umilib_protocol_tcp_TCPSACKBlock sack_blocks[4];
    uint8_t sack_count;
} umilib_protocol_tcp_TCPOptionSet;

/**
 * The retransmission timer of RFC 6298, durations in nanoseconds.
 */
typedef struct umilib_protocol_tcp_TCPRetransmissionTimer {
    bool has_smoothed;
    uint64_t smoothed;
    uint64_t variation;
    uint64_t timeout;
    uint32_t backoff;
    uint64_t minimum;
    uint64_t maximum;
    uint64_t granularity;
} umilib_protocol_tcp_TCPRetransmissionTimer;

/**
 * The parameters of a connection, durations in nanoseconds.
 */
typedef struct umilib_protocol_tcp_TCPConfig {
    uint16_t mtu;
    size_t send_buffer;
    size_t receive_buffer;
    bool window_scale;
    bool timestamps;
    bool sack;
    uint8_t ecn;
    bool nagle;
    uint64_t delayed_ack;
    uint64_t initial_rto;
    uint64_t minimum_rto;
    uint64_t maximum_rto;
    uint64_t clock_granularity;
    uint8_t congestion;
    bool has_initial_window;
    uint32_t initial_window;
    uint32_t retries;
    uint64_t user_timeout;
    uint64_t connect_timeout;
    bool keepalive;
    uint64_t keepalive_idle;
    uint64_t keepalive_interval;
    uint32_t keepalive_probes;
    uint64_t time_wait;
    uint32_t challenge_acks;
    bool hard_error_abort;
} umilib_protocol_tcp_TCPConfig;

/**
 * What a connection's state machine holds that an application may read.
 */
typedef struct umilib_protocol_tcp_TCPConnectionInfo {
    uint8_t state;
    bool passive;
    uint32_t iss;
    uint32_t send_unacknowledged;
    uint32_t send_next;
    uint32_t send_maximum;
    uint32_t send_window;
    uint32_t maximum_send_window;
    uint32_t irs;
    uint32_t receive_next;
    uint16_t peer_mss;
    uint16_t mtu;
    bool window_scaling;
    uint8_t send_scale;
    uint8_t receive_scale;
    bool sack;
    bool timestamps;
    bool ecn;
    uint32_t congestion_window;
    uint32_t congestion_threshold;
    bool in_recovery;
    umilib_protocol_tcp_TCPRetransmissionTimer timer;
} umilib_protocol_tcp_TCPConnectionInfo;

/**
 * A rule that routes connections by their local and remote endpoints.
 */
typedef struct umilib_protocol_tcp_TCPRule {
    umilib_protocol_ip_IPEndpointPattern local;
    umilib_protocol_ip_IPEndpointPattern remote;
} umilib_protocol_tcp_TCPRule;

/**
 * The generator of initial sequence numbers of RFC 6528.
 */
typedef struct umilib_protocol_tcp_TCPISNGenerator umilib_protocol_tcp_TCPISNGenerator;

/**
 * A congestion control: NewReno or CUBIC.
 */
typedef struct umilib_protocol_tcp_TCPCongestion umilib_protocol_tcp_TCPCongestion;

/**
 * A TCP connection without I/O.
 */
typedef struct umilib_protocol_tcp_TCPConnection umilib_protocol_tcp_TCPConnection;

/**
 * A passive OPEN and its connections being set up.
 */
typedef struct umilib_protocol_tcp_TCPListener umilib_protocol_tcp_TCPListener;

/**
 * Whether `a` is before `b` modulo 2^32 (RFC 9293 §3.4).
 */
bool umilib_protocol_tcp_tcp_sequence_is_before(uint32_t a, uint32_t b);

/**
 * How far `later` is after `earlier`, modulo 2^32.
 */
uint32_t umilib_protocol_tcp_tcp_sequence_distance(uint32_t later, uint32_t earlier);

/**
 * Reads the header at the start of the `length` bytes at `bytes` into `out`; fails with Length.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_header_decode(const uint8_t* bytes, size_t length, umilib_protocol_tcp_TCPHeader* out);

/**
 * Writes the 20 bytes of `header` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_header_encode(umilib_protocol_tcp_TCPHeader header, umilib_ffi_Buffer* out);

/**
 * Reads the segment of the `length` bytes at `bytes`, carried from the address at `source` to that
 * at `destination`, into `out`, with the offsets and lengths of its options and its data in the
 * bytes. Fails with Length, Checksum, Option or Family, and with the ip module's Length for an
 * address of other than 4 or 16 octets.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_segment_decode(const uint8_t* bytes, size_t length, const uint8_t* source, size_t source_length, const uint8_t* destination, size_t destination_length, umilib_protocol_tcp_TCPSegment* out, size_t* out_options_offset, size_t* out_options_length, size_t* out_payload_offset, size_t* out_payload_length);

/**
 * Writes the segment of `segment`, the `options_length` bytes of options at `options` and the
 * `payload_length` bytes of data at `payload`, from the address at `source` to that at
 * `destination`, with its data offset and checksum, into `out`; fails with Option, Length or Family.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_segment_encode(const umilib_protocol_tcp_TCPSegment* segment, const uint8_t* options, size_t options_length, const uint8_t* payload, size_t payload_length, const uint8_t* source, size_t source_length, const uint8_t* destination, size_t destination_length, umilib_ffi_Buffer* out);

/**
 * Writes whether a reset answers the segment `segment` (with its options and data) when no
 * connection exists (RFC 9293 §3.10.7.1) into `out_found` and the reset into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_segment_reset_reply(const umilib_protocol_tcp_TCPSegment* segment, const uint8_t* options, size_t options_length, const uint8_t* payload, size_t payload_length, bool* out_found, umilib_protocol_tcp_TCPSegment* out);

/**
 * Writes the options of the `length` bytes at `options` that this crate understands into `out`;
 * fails with Option for an illegal length.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_option_set_decode(const uint8_t* options, size_t length, umilib_protocol_tcp_TCPOptionSet* out);

/**
 * Writes the options of `set` as Linux lays them out into `out`; fails with Option if they do not fit.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_option_set_encode(const umilib_protocol_tcp_TCPOptionSet* set, umilib_ffi_Buffer* out);

/**
 * Writes whether the options of the `length` bytes at `options` have one at `index` (No-Operation
 * included) into `out_found`, its kind into `out_kind` and its data into `out`; fails with Option.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_options_get(const uint8_t* options, size_t length, size_t index, bool* out_found, uint8_t* out_kind, umilib_ffi_Buffer* out);

/**
 * Writes the option of `kind` and the `length` bytes of data at `data` into `out`; fails with Option.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_option_encode(uint8_t kind, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes a generator of initial sequence numbers under the 16 bytes of key at `key` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_isn_generator_new(const uint8_t* key, umilib_protocol_tcp_TCPISNGenerator** out);

/**
 * Releases a generator. Does nothing if `generator` is null.
 */
void umilib_protocol_tcp_tcp_isn_generator_free(umilib_protocol_tcp_TCPISNGenerator* generator);

/**
 * Writes the initial sequence number of a connection between `local` and `remote` opened at `now` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_isn_generator_generate(const umilib_protocol_tcp_TCPISNGenerator* generator, const umilib_protocol_ip_IPEndpoint* local, const umilib_protocol_ip_IPEndpoint* remote, uint64_t now, uint32_t* out);

/**
 * Writes a retransmission timer of RTO `initial`, bounded by `minimum` and `maximum`, with the
 * clock granularity `granularity`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_retransmission_timer_new(uint64_t initial, uint64_t minimum, uint64_t maximum, uint64_t granularity, umilib_protocol_tcp_TCPRetransmissionTimer* out);

/**
 * Takes the RTT sample `rtt` into the timer at `timer` (RFC 6298 (2.2), (2.3)).
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_retransmission_timer_sample(umilib_protocol_tcp_TCPRetransmissionTimer* timer, uint64_t rtt);

/**
 * Records an expiry of the timer at `timer`: the RTO doubles (RFC 6298 (5.5)).
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_retransmission_timer_expire(umilib_protocol_tcp_TCPRetransmissionTimer* timer);

/**
 * Restores the timer at `timer` after a lost SYN (RFC 6298 (5.7)).
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_retransmission_timer_restore_after_syn_loss(umilib_protocol_tcp_TCPRetransmissionTimer* timer);

/**
 * The current RTO of `timer`, backoff included.
 */
uint64_t umilib_protocol_tcp_tcp_retransmission_timer_current(umilib_protocol_tcp_TCPRetransmissionTimer timer);

/**
 * Writes the congestion control of `kind` (0 NewReno, 1 CUBIC) with the window `window` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_congestion_new(uint8_t kind, uint32_t window, umilib_protocol_tcp_TCPCongestion** out);

/**
 * Releases a congestion control. Does nothing if `congestion` is null.
 */
void umilib_protocol_tcp_tcp_congestion_free(umilib_protocol_tcp_TCPCongestion* congestion);

/**
 * The initial window of RFC 5681 §3.1 for `mss`.
 */
uint32_t umilib_protocol_tcp_tcp_congestion_initial_window(uint32_t mss);

/**
 * Writes cwnd and ssthresh of the control at `congestion` into `out_window` and `out_threshold`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_congestion_window(const umilib_protocol_tcp_TCPCongestion* congestion, uint32_t* out_window, uint32_t* out_threshold);

/**
 * Sets cwnd of the control at `congestion` to `window`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_congestion_set_window(umilib_protocol_tcp_TCPCongestion* congestion, uint32_t window);

/**
 * Tells the control at `congestion` that `acknowledged` bytes were acknowledged at `now`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_congestion_acknowledge(umilib_protocol_tcp_TCPCongestion* congestion, uint32_t acknowledged, uint32_t mss, uint64_t rtt, bool limited, uint64_t now);

/**
 * Tells the control at `congestion` of a congestion event at `now`, an ECN-Echo if `ecn`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_congestion_congestion(umilib_protocol_tcp_TCPCongestion* congestion, uint32_t in_flight, uint32_t mss, bool ecn, uint64_t now);

/**
 * Tells the control at `congestion` that the retransmission timer expired at `now`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_congestion_timeout(umilib_protocol_tcp_TCPCongestion* congestion, uint32_t in_flight, uint32_t mss, uint64_t now);

/**
 * Restarts the control at `congestion` after idleness at `restart` bytes (RFC 5681 §4.1).
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_congestion_restart(umilib_protocol_tcp_TCPCongestion* congestion, uint32_t restart, uint64_t now);

/**
 * Writes the default configuration (RFC 9293 and the RFCs it relies on) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_config_default(umilib_protocol_tcp_TCPConfig* out);

/**
 * Writes a connection actively opened from `local` to `remote` with `iss` at `now` into `out`;
 * fails with Address (MUST-46), Family, or InvalidArgument for a bad configuration.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_connect(const umilib_protocol_tcp_TCPConfig* config, const umilib_protocol_ip_IPEndpoint* local, const umilib_protocol_ip_IPEndpoint* remote, uint32_t iss, uint64_t now, umilib_protocol_tcp_TCPConnection** out);

/**
 * Writes a connection passively opened from the SYN `syn` (with its options and data) that came
 * from `remote` to `local`, with `iss` at `now`, into `out`; fails with State, Address or Family.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_accept(const umilib_protocol_tcp_TCPConfig* config, const umilib_protocol_ip_IPEndpoint* local, const umilib_protocol_ip_IPEndpoint* remote, const umilib_protocol_tcp_TCPSegment* syn, const uint8_t* options, size_t options_length, const uint8_t* payload, size_t payload_length, uint32_t iss, uint64_t now, umilib_protocol_tcp_TCPConnection** out);

/**
 * Releases a connection. Does nothing if `connection` is null.
 */
void umilib_protocol_tcp_tcp_connection_free(umilib_protocol_tcp_TCPConnection* connection);

/**
 * Gives the connection a segment that arrived at `now`, with Congestion Experienced if `ce`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_receive(umilib_protocol_tcp_TCPConnection* connection, const umilib_protocol_tcp_TCPSegment* segment, const uint8_t* options, size_t options_length, const uint8_t* payload, size_t payload_length, bool ce, uint64_t now);

/**
 * Writes whether the connection has a segment to send at `now` into `out_found`, the segment into
 * `out`, and whether its IP header carries ECT(0) into `out_ect`. Call it until it finds none.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_transmit(umilib_protocol_tcp_TCPConnection* connection, uint64_t now, bool* out_found, umilib_ffi_Buffer* out, bool* out_ect);

/**
 * Writes whether the connection has a timer into `out_found` and the earliest into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_poll_timeout(const umilib_protocol_tcp_TCPConnection* connection, bool* out_found, uint64_t* out);

/**
 * Writes whether an event is waiting into `out_found`, its kind (0 Connected, 1 Readable, 2
 * Writable, 3 Urgent, 4 PeerClosed, 5 Trouble, 6 Closed) into `out_kind` and the close reason of
 * Closed into `out_reason`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_poll_event(umilib_protocol_tcp_TCPConnection* connection, bool* out_found, uint8_t* out_kind, uint8_t* out_reason);

/**
 * Takes as much of the `length` bytes at `data` as fits, urgent if `urgent`, and writes how
 * many into `out`; fails with State once the application or the connection closed.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_send(umilib_protocol_tcp_TCPConnection* connection, const uint8_t* data, size_t length, bool urgent, size_t* out);

/**
 * Reads into the `length` bytes at `out` and writes how many into `out_count`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_read(umilib_protocol_tcp_TCPConnection* connection, uint8_t* out, size_t length, size_t* out_count);

/**
 * Writes the bytes that can be read, the room to send and the urgent bytes not yet read into
 * `out_readable`, `out_writable` and `out_urgent`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_sizes(const umilib_protocol_tcp_TCPConnection* connection, size_t* out_readable, size_t* out_writable, uint32_t* out_urgent);

/**
 * Closes the sending half: a FIN follows the data; fails with State.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_close(umilib_protocol_tcp_TCPConnection* connection);

/**
 * Aborts the connection: a reset is sent if it was synchronized; fails with State once it closed.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_abort(umilib_protocol_tcp_TCPConnection* connection);

/**
 * Gives the connection an ICMP error about the segment of `sequence`: `kind` 0 soft, 1 hard, 2
 * Packet Too Big with the MTU `mtu`; fails with InvalidArgument for another kind.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_receive_error(umilib_protocol_tcp_TCPConnection* connection, uint8_t kind, uint16_t mtu, uint32_t sequence, uint64_t now);

/**
 * Writes whether the SYN `syn` (with its options and data) may open a new incarnation of the
 * connection in TIME-WAIT (RFC 6191 §2) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_accepts_syn(const umilib_protocol_tcp_TCPConnection* connection, const umilib_protocol_tcp_TCPSegment* syn, const uint8_t* options, size_t options_length, const uint8_t* payload, size_t payload_length, bool* out);

/**
 * Writes what the connection's state machine holds into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_info(const umilib_protocol_tcp_TCPConnection* connection, umilib_protocol_tcp_TCPConnectionInfo* out);

/**
 * Writes the configuration of the connection into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_config(const umilib_protocol_tcp_TCPConnection* connection, umilib_protocol_tcp_TCPConfig* out);

/**
 * Changes the configuration of the connection to `config`, such as Nagle (MUST-17) or
 * keep-alives (MUST-24); fails with InvalidArgument for an unknown ECN mode or congestion
 * control, and with Config for a configuration that cannot work.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_set_config(umilib_protocol_tcp_TCPConnection* connection, const umilib_protocol_tcp_TCPConfig* config, uint64_t now);

/**
 * Writes the local and remote endpoints of the connection into `out_local` and `out_remote`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_connection_endpoints(const umilib_protocol_tcp_TCPConnection* connection, umilib_protocol_ip_IPEndpoint* out_local, umilib_protocol_ip_IPEndpoint* out_remote);

/**
 * Writes a listener for the local endpoints of `local`, of `backlog` connections, with initial
 * sequence numbers under the 16 bytes of key at `key`, into `out`; fails with Config for a
 * configuration that cannot work.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_listener_new(const umilib_protocol_tcp_TCPConfig* config, const umilib_protocol_ip_IPEndpointPattern* local, size_t backlog, const uint8_t* key, umilib_protocol_tcp_TCPListener** out);

/**
 * Releases a listener. Does nothing if `listener` is null.
 */
void umilib_protocol_tcp_tcp_listener_free(umilib_protocol_tcp_TCPListener* listener);

/**
 * Gives the listener a segment from `remote` to `local` that no connection took.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_listener_receive(umilib_protocol_tcp_TCPListener* listener, const umilib_protocol_tcp_TCPSegment* segment, const uint8_t* options, size_t options_length, const uint8_t* payload, size_t payload_length, const umilib_protocol_ip_IPEndpoint* local, const umilib_protocol_ip_IPEndpoint* remote, bool ce, uint64_t now);

/**
 * Writes whether the listener has a segment to send at `now` into `out_found`, its endpoints into
 * `out_local` and `out_remote`, the segment into `out` and ECT(0) into `out_ect`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_listener_transmit(umilib_protocol_tcp_TCPListener* listener, uint64_t now, bool* out_found, umilib_protocol_ip_IPEndpoint* out_local, umilib_protocol_ip_IPEndpoint* out_remote, umilib_ffi_Buffer* out, bool* out_ect);

/**
 * Writes whether a connection is established and waiting into `out_found`, and its handle into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_listener_accept(umilib_protocol_tcp_TCPListener* listener, bool* out_found, umilib_protocol_tcp_TCPConnection** out);

/**
 * Writes whether the listener has a timer into `out_found` and the earliest into `out`, and the
 * connections being set up and waiting into `out_pending` and `out_ready`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_listener_poll_timeout(const umilib_protocol_tcp_TCPListener* listener, bool* out_found, uint64_t* out, size_t* out_pending, size_t* out_ready);

/**
 * Writes whether the local endpoint `local` is one of the listener's into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_listener_matches(const umilib_protocol_tcp_TCPListener* listener, const umilib_protocol_ip_IPEndpoint* local, bool* out);

/**
 * Writes whether the rule at `rule` matches a connection to `local` from `remote` into `out`;
 * fails with the ip module's Length for a bad address length.
 */
const umilib_ffi_Status* umilib_protocol_tcp_tcp_rule_matches(const umilib_protocol_tcp_TCPRule* rule, const umilib_protocol_ip_IPEndpoint* local, const umilib_protocol_ip_IPEndpoint* remote, bool* out);

#ifdef __cplusplus
}
#endif

#endif
