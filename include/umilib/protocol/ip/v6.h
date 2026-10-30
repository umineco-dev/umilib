/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_IP_V6_H
#define UMILIB_PROTOCOL_IP_V6_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/ip.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The fixed header of an IPv6 packet (RFC 8200 §3).
 */
typedef struct umilib_protocol_ip_v6_IPv6Header {
    uint8_t dscp;
    uint8_t ecn;
    uint32_t flow_label;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    umilib_protocol_ip_IPv6Address source;
    umilib_protocol_ip_IPv6Address destination;
} umilib_protocol_ip_v6_IPv6Header;

/**
 * A Fragment header (RFC 8200 §4.5); the offset in units of 8 bytes.
 */
typedef struct umilib_protocol_ip_v6_IPv6FragmentHeader {
    uint8_t next_header;
    uint16_t fragment_offset;
    bool more_fragments;
    uint32_t identification;
} umilib_protocol_ip_v6_IPv6FragmentHeader;

/**
 * The limits of a reassembler; the timeout in nanoseconds.
 */
typedef struct umilib_protocol_ip_v6_IPv6ReassemblyConfig {
    uint64_t timeout;
    size_t maximum_length;
    size_t maximum_datagrams;
    size_t maximum_buffered;
} umilib_protocol_ip_v6_IPv6ReassemblyConfig;

/**
 * What identifies the fragments of one packet.
 */
typedef struct umilib_protocol_ip_v6_IPv6ReassemblyKey {
    umilib_protocol_ip_IPv6Address source;
    umilib_protocol_ip_IPv6Address destination;
    uint32_t identification;
} umilib_protocol_ip_v6_IPv6ReassemblyKey;

/**
 * The fragments of a packet that fit an MTU.
 */
typedef struct umilib_protocol_ip_v6_IPv6Fragmenter umilib_protocol_ip_v6_IPv6Fragmenter;

/**
 * The reassembly of IPv6 packets from their fragments.
 */
typedef struct umilib_protocol_ip_v6_IPv6Reassembler umilib_protocol_ip_v6_IPv6Reassembler;

/**
 * A packet given back by the reassembler at its deadline.
 */
typedef struct umilib_protocol_ip_v6_IPv6Reassembly umilib_protocol_ip_v6_IPv6Reassembly;

/**
 * Writes the header of a packet of `payload_length` bytes starting with `next_header` into
 * `out`; fails with Length beyond 65,535 bytes.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_header_new(umilib_protocol_ip_IPv6Address source, umilib_protocol_ip_IPv6Address destination, uint8_t next_header, size_t payload_length, umilib_protocol_ip_v6_IPv6Header* out);

/**
 * Reads the header at the start of the `length` bytes at `bytes` into `out` and the offset and
 * length of its payload into `out_offset` and `out_length`; fails with Version or Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_header_decode(const uint8_t* bytes, size_t length, umilib_protocol_ip_v6_IPv6Header* out, size_t* out_offset, size_t* out_length);

/**
 * Reads the header at the start of the `length` bytes at `bytes`, whose payload may be cut short
 * (as an ICMP error quotes it), into `out` and the offset and length of the payload present into
 * `out_offset` and `out_length`; fails with Version or Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_header_decode_truncated(const uint8_t* bytes, size_t length, umilib_protocol_ip_v6_IPv6Header* out, size_t* out_offset, size_t* out_length);

/**
 * Writes the 40 bytes of the header into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_header_encode(const umilib_protocol_ip_v6_IPv6Header* header, umilib_ffi_Buffer* out);

/**
 * Whether `kind` names an extension header that a chain continues after.
 */
bool umilib_protocol_ip_v6_ipv6_extension_header_is_extension(uint8_t kind);

/**
 * Writes the length of the extension header of `kind` that the `length` bytes at `bytes` start
 * with into `out`; fails with Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_extension_header_length(uint8_t kind, const uint8_t* bytes, size_t length, size_t* out);

/**
 * Reads the extension header at `*offset` of the `length` bytes of payload at `payload`, named
 * by `*next_header`: writes whether there is one into `out_found` and its length into
 * `out_length`, and moves `*next_header` and `*offset` past it. At the end of the chain,
 * `*next_header` is the upper layer and `*offset` its start. Fails with Length or
 * ExtensionHeader.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_extension_headers_next(uint8_t* next_header, const uint8_t* payload, size_t length, size_t* offset, bool* out_found, size_t* out_length);

/**
 * Writes the upper layer of the `length` bytes of payload at `payload`, whose first header is
 * named by `next_header`, into `out_protocol` and the offset of its data into `out_offset`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_extension_headers_upper_layer(uint8_t next_header, const uint8_t* payload, size_t length, uint8_t* out_protocol, size_t* out_offset);

/**
 * What a node that does not recognize an option of `kind` does (0 to 3).
 */
uint8_t umilib_protocol_ip_v6_ipv6_option_kind_action(uint8_t kind);

/**
 * Whether the data of an option of `kind` may change en route.
 */
bool umilib_protocol_ip_v6_ipv6_option_kind_may_change(uint8_t kind);

/**
 * Writes an option of `kind` with the `length` bytes of data at `data` into `out`; fails with Option.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_option_encode(uint8_t kind, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes `length` bytes of padding (Pad1 or PadN) into `out`; fails with Option beyond 257.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_option_encode_padding(size_t length, umilib_ffi_Buffer* out);

/**
 * Checks the Hop-by-Hop or Destination Options header of the `length` bytes at `bytes` and
 * writes its Next Header value into `out`; fails with Length or Option.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_options_header_decode(const uint8_t* bytes, size_t length, uint8_t* out);

/**
 * Writes whether the options header of the `length` bytes at `bytes` has an option at `index`
 * (padding not counted) into `out_found`, its type into `out_kind`, the offset of its type in
 * the header into `out_offset` and its data into `out`; fails with Length or Option.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_options_header_get(const uint8_t* bytes, size_t length, size_t index, bool* out_found, uint8_t* out_kind, size_t* out_offset, umilib_ffi_Buffer* out);

/**
 * Writes an options header of `next_header` with the `length` bytes of encoded options at
 * `options`, padded to a multiple of 8 bytes, into `out`; fails with Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_options_header_encode(uint8_t next_header, const uint8_t* options, size_t length, umilib_ffi_Buffer* out);

/**
 * Reads the Routing header of the `length` bytes at `bytes`: its Next Header value into
 * `out_next_header`, its type into `out_routing_type`, its Segments Left into
 * `out_segments_left` and the bytes after the first four into `out`; fails with Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_routing_header_decode(const uint8_t* bytes, size_t length, uint8_t* out_next_header, uint8_t* out_routing_type, uint8_t* out_segments_left, umilib_ffi_Buffer* out);

/**
 * Writes the Routing header of `next_header`, `routing_type`, `segments_left` and the `length`
 * bytes at `data` into `out`; fails with Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_routing_header_encode(uint8_t next_header, uint8_t routing_type, uint8_t segments_left, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Reads the Fragment header at the start of the `length` bytes at `bytes` into `out`; fails with Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_fragment_header_decode(const uint8_t* bytes, size_t length, umilib_protocol_ip_v6_IPv6FragmentHeader* out);

/**
 * Writes the 8 bytes of the Fragment header into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_fragment_header_encode(umilib_protocol_ip_v6_IPv6FragmentHeader header, umilib_ffi_Buffer* out);

/**
 * Whether the fragment is a whole packet (RFC 6946).
 */
bool umilib_protocol_ip_v6_ipv6_fragment_header_is_atomic(umilib_protocol_ip_v6_IPv6FragmentHeader header);

/**
 * Writes a fragmenter of a copy of the `length` bytes of payload at `payload` after `header`,
 * identified by `identification`, for `mtu` into `out`; fails with Fragment, HeaderChain or Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_fragmenter_new(const umilib_protocol_ip_v6_IPv6Header* header, const uint8_t* payload, size_t length, uint32_t identification, size_t mtu, umilib_protocol_ip_v6_IPv6Fragmenter** out);

/**
 * Releases a fragmenter. Does nothing if `fragmenter` is null.
 */
void umilib_protocol_ip_v6_ipv6_fragmenter_free(umilib_protocol_ip_v6_IPv6Fragmenter* fragmenter);

/**
 * Writes whether there is a next packet into `out_found` and its bytes into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_fragmenter_next(umilib_protocol_ip_v6_IPv6Fragmenter* fragmenter, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes the default limits of a reassembler into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_reassembly_config_default(umilib_protocol_ip_v6_IPv6ReassemblyConfig* out);

/**
 * Writes a reassembler with the limits `config` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_reassembler_new(umilib_protocol_ip_v6_IPv6ReassemblyConfig config, umilib_protocol_ip_v6_IPv6Reassembler** out);

/**
 * Releases a reassembler. Does nothing if `reassembler` is null.
 */
void umilib_protocol_ip_v6_ipv6_reassembler_free(umilib_protocol_ip_v6_IPv6Reassembler* reassembler);

/**
 * Adds the packet of `header` and the `length` bytes of payload at `payload`, received at `now`,
 * and writes whether it completes a packet into `out_complete`, and that packet's header and
 * payload into `out` and `out_payload`; fails with Length, HeaderChain, Limit, ExtensionHeader,
 * Overlap (the packet is discarded) or the Length of `protocol.ip`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_reassembler_receive(umilib_protocol_ip_v6_IPv6Reassembler* reassembler, const umilib_protocol_ip_v6_IPv6Header* header, const uint8_t* payload, size_t length, uint64_t now, bool* out_complete, umilib_protocol_ip_v6_IPv6Header* out, umilib_ffi_Buffer* out_payload);

/**
 * Writes whether a packet is being reassembled into `out_found` and the earliest deadline into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_reassembler_poll_timeout(const umilib_protocol_ip_v6_IPv6Reassembler* reassembler, bool* out_found, uint64_t* out);

/**
 * Removes a packet whose deadline is at or before `now` and writes whether there was one into
 * `out_found`, its key into `out_key` and it into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_reassembler_expire(umilib_protocol_ip_v6_IPv6Reassembler* reassembler, uint64_t now, bool* out_found, umilib_protocol_ip_v6_IPv6ReassemblyKey* out_key, umilib_protocol_ip_v6_IPv6Reassembly** out);

/**
 * Writes whether fragments of the packet overlapped (RFC 5722) into `out`: it then has no
 * first fragment, and no ICMP message is sent for it.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_reassembly_abandoned(const umilib_protocol_ip_v6_IPv6Reassembly* reassembly, bool* out);

/**
 * Releases a packet given back by expire. Does nothing if `reassembly` is null.
 */
void umilib_protocol_ip_v6_ipv6_reassembly_free(umilib_protocol_ip_v6_IPv6Reassembly* reassembly);

/**
 * Writes whether the first fragment was received into `out_found`, the bytes of its packet up
 * to its data (the IPv6 header, the per-fragment headers and the Fragment header) into
 * `out_headers`, and the data received (zeros between the fragments) into `out_data`.
 */
const umilib_ffi_Status* umilib_protocol_ip_v6_ipv6_reassembly_first(const umilib_protocol_ip_v6_IPv6Reassembly* reassembly, bool* out_found, umilib_ffi_Buffer* out_headers, umilib_ffi_Buffer* out_data);

#ifdef __cplusplus
}
#endif

#endif
