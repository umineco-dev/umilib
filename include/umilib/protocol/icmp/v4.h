/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_ICMP_V4_H
#define UMILIB_PROTOCOL_ICMP_V4_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/icmp.h"
#include "umilib/protocol/ip.h"
#include "umilib/protocol/ip/v4.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Reads the message of the `length` bytes at `bytes`, whose checksum must be right, into `out`
 * (its body is the bytes after the first eight); fails with Length or Checksum.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v4_icmpv4_message_decode(const uint8_t* bytes, size_t length, umilib_protocol_icmp_ICMPHeader* out);

/**
 * Writes the message of `header` and the `length` bytes of body at `body`, with its checksum, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v4_icmpv4_message_encode(umilib_protocol_icmp_ICMPHeader header, const uint8_t* body, size_t length, umilib_ffi_Buffer* out);

/**
 * The header of an Echo Request of `identifier` and `sequence`.
 */
umilib_protocol_icmp_ICMPHeader umilib_protocol_icmp_v4_icmpv4_message_echo_request(uint16_t identifier, uint16_t sequence);

/**
 * Writes whether `header` is an Echo Request into `out_found` and the header of its reply into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v4_icmpv4_message_echo_reply(umilib_protocol_icmp_ICMPHeader header, bool* out_found, umilib_protocol_icmp_ICMPHeader* out);

/**
 * Writes whether `header` is of an Echo, a Timestamp or their replies into `out_found`, and its
 * identifier and sequence number into `out_identifier` and `out_sequence`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v4_icmpv4_message_query(umilib_protocol_icmp_ICMPHeader header, bool* out_found, uint16_t* out_identifier, uint16_t* out_sequence);

/**
 * Writes whether the message of `header` and the `length` bytes at `body` is a Timestamp or
 * Timestamp Reply with its timestamps into `out_found`, and the originate, receive and transmit
 * timestamps into the 3 values at `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v4_icmpv4_message_timestamps(umilib_protocol_icmp_ICMPHeader header, const uint8_t* body, size_t length, bool* out_found, uint32_t* out);

/**
 * Writes whether `header` is a Fragmentation Needed message into `out_found` and the MTU of the
 * next hop into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v4_icmpv4_message_next_hop_mtu(umilib_protocol_icmp_ICMPHeader header, bool* out_found, uint16_t* out);

/**
 * Writes whether `header` is a Parameter Problem into `out_found` and its pointer into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v4_icmpv4_message_pointer(umilib_protocol_icmp_ICMPHeader header, bool* out_found, uint8_t* out);

/**
 * Writes whether `header` is a Redirect into `out_found` and its gateway into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v4_icmpv4_message_gateway(umilib_protocol_icmp_ICMPHeader header, bool* out_found, umilib_protocol_ip_IPv4Address* out);

/**
 * Writes the length of the original datagram an error message of `header` and the `length`
 * bytes at `body` quotes into `out_original` and whether an extension structure follows it into
 * `out_found`; fails with Length, Version or Checksum.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v4_icmpv4_message_original(umilib_protocol_icmp_ICMPHeader header, const uint8_t* body, size_t length, size_t* out_original, bool* out_found);

/**
 * The bytes of a datagram of `length` bytes that an error message quotes under an IPv4 header
 * of `header_length` bytes, within 576 bytes (RFC 1812 §4.3.2.3).
 */
size_t umilib_protocol_icmp_v4_icmpv4_message_quote_length(size_t length, size_t header_length);

/**
 * Writes whether an error message may be sent about the datagram of `header` and the `length`
 * bytes of data at `payload`, received as a broadcast if `broadcast` (RFC 1122 §3.2.2), into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v4_icmpv4_message_may_report(const umilib_protocol_ip_v4_IPv4Header* header, const uint8_t* payload, size_t length, bool broadcast, bool* out);

/**
 * Whether the type `kind` is that of an error message.
 */
bool umilib_protocol_icmp_v4_icmpv4_type_is_error(uint8_t kind);

/**
 * Whether the type `kind` is deprecated (RFC 6633, RFC 6918).
 */
bool umilib_protocol_icmp_v4_icmpv4_type_is_deprecated(uint8_t kind);

/**
 * Whether an error of the type `kind` carries the length attribute of RFC 4884.
 */
bool umilib_protocol_icmp_v4_icmpv4_type_is_extensible(uint8_t kind);

#ifdef __cplusplus
}
#endif

#endif
