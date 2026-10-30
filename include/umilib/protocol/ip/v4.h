/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_IP_V4_H
#define UMILIB_PROTOCOL_IP_V4_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/ip.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The options of a header: the bytes after its fixed 20 bytes, at most 40.
 */
typedef struct umilib_protocol_ip_v4_IPv4Options {
    uint8_t bytes[40];
    uint8_t length;
} umilib_protocol_ip_v4_IPv4Options;

/**
 * The header of an IPv4 packet (RFC 791 §3.1), without its checksum.
 */
typedef struct umilib_protocol_ip_v4_IPv4Header {
    uint8_t dscp;
    uint8_t ecn;
    uint16_t total_length;
    uint16_t identification;
    bool dont_fragment;
    bool more_fragments;
    uint16_t fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    umilib_protocol_ip_IPv4Address source;
    umilib_protocol_ip_IPv4Address destination;
    umilib_protocol_ip_v4_IPv4Options options;
} umilib_protocol_ip_v4_IPv4Header;

/**
 * The limits of a reassembler; the timeout in nanoseconds.
 */
typedef struct umilib_protocol_ip_v4_IPv4ReassemblyConfig {
    uint64_t timeout;
    size_t maximum_length;
    size_t maximum_datagrams;
    size_t maximum_buffered;
} umilib_protocol_ip_v4_IPv4ReassemblyConfig;

/**
 * What identifies the fragments of one datagram.
 */
typedef struct umilib_protocol_ip_v4_IPv4ReassemblyKey {
    umilib_protocol_ip_IPv4Address source;
    umilib_protocol_ip_IPv4Address destination;
    uint8_t protocol;
    uint16_t identification;
} umilib_protocol_ip_v4_IPv4ReassemblyKey;

/**
 * The fragments of a datagram that fit an MTU.
 */
typedef struct umilib_protocol_ip_v4_IPv4Fragmenter umilib_protocol_ip_v4_IPv4Fragmenter;

/**
 * The reassembly of IPv4 datagrams from their fragments.
 */
typedef struct umilib_protocol_ip_v4_IPv4Reassembler umilib_protocol_ip_v4_IPv4Reassembler;

/**
 * A datagram given back by the reassembler at its deadline.
 */
typedef struct umilib_protocol_ip_v4_IPv4Reassembly umilib_protocol_ip_v4_IPv4Reassembly;

/**
 * Writes the header of a datagram of `payload_length` bytes of `protocol` without options into
 * `out`; fails with Length beyond 65,535 bytes.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_header_new(umilib_protocol_ip_IPv4Address source, umilib_protocol_ip_IPv4Address destination, uint8_t protocol, size_t payload_length, umilib_protocol_ip_v4_IPv4Header* out);

/**
 * Reads the header at the start of the `length` bytes at `bytes` into `out` and the offset and
 * length of its data into `out_offset` and `out_length`; fails with Version, Length, Checksum or Option.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_header_decode(const uint8_t* bytes, size_t length, umilib_protocol_ip_v4_IPv4Header* out, size_t* out_offset, size_t* out_length);

/**
 * Reads the header at the start of the `length` bytes at `bytes`, whose data may be cut short
 * (as an ICMP error quotes it), into `out` and the offset and length of the data present into
 * `out_offset` and `out_length`; fails with Version, Length, Checksum or Option.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_header_decode_truncated(const uint8_t* bytes, size_t length, umilib_protocol_ip_v4_IPv4Header* out, size_t* out_offset, size_t* out_length);

/**
 * Writes the bytes of the header, with its checksum, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_header_encode(const umilib_protocol_ip_v4_IPv4Header* header, umilib_ffi_Buffer* out);

/**
 * The length of the header with its padded options.
 */
size_t umilib_protocol_ip_v4_ipv4_header_header_length(umilib_protocol_ip_v4_IPv4Header header);

/**
 * The total length less the header.
 */
size_t umilib_protocol_ip_v4_ipv4_header_payload_length(umilib_protocol_ip_v4_IPv4Header header);

/**
 * Whether the packet is a fragment of a larger datagram.
 */
bool umilib_protocol_ip_v4_ipv4_header_is_fragment(umilib_protocol_ip_v4_IPv4Header header);

/**
 * Sets the total length of `header` for `length` bytes of data; fails with Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_header_set_payload_length(umilib_protocol_ip_v4_IPv4Header* header, size_t length);

/**
 * Reads the options of the `length` bytes at `bytes` (the header after its 20 fixed bytes)
 * into `out`; fails with Option.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_options_decode(const uint8_t* bytes, size_t length, umilib_protocol_ip_v4_IPv4Options* out);

/**
 * Appends an option of `kind` with the `length` bytes of data at `data`; fails with Option.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_options_push(umilib_protocol_ip_v4_IPv4Options* options, uint8_t kind, const uint8_t* data, size_t length);

/**
 * Writes whether there is an option at `index` (counting neither padding nor No Operation)
 * into `out_found`, its kind into `out_kind` and its data into `out`; fails with Option for a
 * malformed option before it.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_options_get(const umilib_protocol_ip_v4_IPv4Options* options, size_t index, bool* out_found, uint8_t* out_kind, umilib_ffi_Buffer* out);

/**
 * The options copied into every fragment but the first.
 */
umilib_protocol_ip_v4_IPv4Options umilib_protocol_ip_v4_ipv4_options_copied(umilib_protocol_ip_v4_IPv4Options options);

/**
 * The length of the options padded to a multiple of 4.
 */
size_t umilib_protocol_ip_v4_ipv4_options_padded_length(umilib_protocol_ip_v4_IPv4Options options);

/**
 * Whether an option of `kind` is copied into every fragment.
 */
bool umilib_protocol_ip_v4_ipv4_option_kind_is_copied(uint8_t kind);

/**
 * The class of an option of `kind`: 0 for control, 2 for debugging and measurement.
 */
uint8_t umilib_protocol_ip_v4_ipv4_option_kind_class(uint8_t kind);

/**
 * The number of an option of `kind`.
 */
uint8_t umilib_protocol_ip_v4_ipv4_option_kind_number(uint8_t kind);

/**
 * Writes a fragmenter of a copy of the `length` bytes of data at `payload` after `header` for
 * `mtu` into `out`; fails with Fragment or Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_fragmenter_new(const umilib_protocol_ip_v4_IPv4Header* header, const uint8_t* payload, size_t length, size_t mtu, umilib_protocol_ip_v4_IPv4Fragmenter** out);

/**
 * Releases a fragmenter. Does nothing if `fragmenter` is null.
 */
void umilib_protocol_ip_v4_ipv4_fragmenter_free(umilib_protocol_ip_v4_IPv4Fragmenter* fragmenter);

/**
 * Writes whether there is a next fragment into `out_found`, its header into `out` and the
 * offset and length of its part of the data into `out_offset` and `out_length`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_fragmenter_next(umilib_protocol_ip_v4_IPv4Fragmenter* fragmenter, bool* out_found, umilib_protocol_ip_v4_IPv4Header* out, size_t* out_offset, size_t* out_length);

/**
 * Writes the default limits of a reassembler into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_reassembly_config_default(umilib_protocol_ip_v4_IPv4ReassemblyConfig* out);

/**
 * Writes a reassembler with the limits `config` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_reassembler_new(umilib_protocol_ip_v4_IPv4ReassemblyConfig config, umilib_protocol_ip_v4_IPv4Reassembler** out);

/**
 * Releases a reassembler. Does nothing if `reassembler` is null.
 */
void umilib_protocol_ip_v4_ipv4_reassembler_free(umilib_protocol_ip_v4_IPv4Reassembler* reassembler);

/**
 * Adds the fragment of `header` and the `length` bytes of data at `payload`, received at `now`,
 * and writes whether it completes a datagram into `out_complete`, and that datagram's header and
 * data into `out` and `out_data`; fails with Length, Limit, Overlap (the datagram is discarded)
 * or the Length of `protocol.ip`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_reassembler_receive(umilib_protocol_ip_v4_IPv4Reassembler* reassembler, const umilib_protocol_ip_v4_IPv4Header* header, const uint8_t* payload, size_t length, uint64_t now, bool* out_complete, umilib_protocol_ip_v4_IPv4Header* out, umilib_ffi_Buffer* out_data);

/**
 * Writes whether a datagram is being reassembled into `out_found` and the earliest deadline into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_reassembler_poll_timeout(const umilib_protocol_ip_v4_IPv4Reassembler* reassembler, bool* out_found, uint64_t* out);

/**
 * Removes a datagram whose deadline is at or before `now` and writes whether there was one into
 * `out_found`, its key into `out_key` and it into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_reassembler_expire(umilib_protocol_ip_v4_IPv4Reassembler* reassembler, uint64_t now, bool* out_found, umilib_protocol_ip_v4_IPv4ReassemblyKey* out_key, umilib_protocol_ip_v4_IPv4Reassembly** out);

/**
 * Writes whether fragments of the datagram overlapped (RFC 5722) into `out`: it then has no
 * first fragment, and no ICMP message is sent for it.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_reassembly_abandoned(const umilib_protocol_ip_v4_IPv4Reassembly* reassembly, bool* out);

/**
 * Releases a datagram given back by expire. Does nothing if `reassembly` is null.
 */
void umilib_protocol_ip_v4_ipv4_reassembly_free(umilib_protocol_ip_v4_IPv4Reassembly* reassembly);

/**
 * Writes whether the first fragment was received into `out_found`, its header into `out` and
 * the data received (zeros between the fragments) into `out_data`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v4_ipv4_reassembly_first(const umilib_protocol_ip_v4_IPv4Reassembly* reassembly, bool* out_found, umilib_protocol_ip_v4_IPv4Header* out, umilib_ffi_Buffer* out_data);

#ifdef __cplusplus
}
#endif

#endif
