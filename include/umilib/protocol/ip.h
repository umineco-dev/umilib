/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_IP_H
#define UMILIB_PROTOCOL_IP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * An IPv4 address, in network byte order.
 */
typedef struct umilib_protocol_ip_IPv4Address {
    uint8_t octets[4];
} umilib_protocol_ip_IPv4Address;

/**
 * An IPv6 address, in network byte order.
 */
typedef struct umilib_protocol_ip_IPv6Address {
    uint8_t octets[16];
} umilib_protocol_ip_IPv6Address;

/**
 * The Internet checksum (RFC 1071) being computed: start with zeros.
 */
typedef struct umilib_protocol_ip_InternetChecksum {
    uint64_t sum;
    bool odd;
} umilib_protocol_ip_InternetChecksum;

/**
 * An endpoint of a transport protocol: the first `length` (4 or 16) of `octets` are the address.
 */
typedef struct umilib_protocol_ip_IPEndpoint {
    uint8_t octets[16];
    uint8_t length;
    uint16_t port;
} umilib_protocol_ip_IPEndpoint;

/**
 * Endpoints by address prefix and port range; a `length` of 0 is any address.
 */
typedef struct umilib_protocol_ip_IPEndpointPattern {
    uint8_t octets[16];
    uint8_t length;
    uint8_t prefix_length;
    uint16_t first_port;
    uint16_t last_port;
} umilib_protocol_ip_IPEndpointPattern;

/**
 * The data of a datagram being reassembled from fragments.
 */
typedef struct umilib_protocol_ip_IPFragmentBuffer umilib_protocol_ip_IPFragmentBuffer;

/**
 * Reads the endpoint of the UTF-8 text at `text`, `address:port` or `[address]:port` (RFC 3986
 * §3.2.2), into `out`; fails with Syntax.
 */
const umilib_ffi_Status* umilib_protocol_ip_ip_endpoint_parse(const uint8_t* text, size_t length, umilib_protocol_ip_IPEndpoint* out);

/**
 * Writes the text of the endpoint at `endpoint` into `out`; fails with Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_ip_endpoint_to_string(const umilib_protocol_ip_IPEndpoint* endpoint, umilib_ffi_Buffer* out);

/**
 * Writes the canonical prefix of `length` bits of the address of the `octets_length` octets at
 * `octets` (an IPv4 prefix for at least 96 bits of an IPv4-mapped address, RFC 4291 §2.5.5.2)
 * into the 16 bytes at `out`, the number of them used into `out_octets` and its length into
 * `out_length`; fails with Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_ip_address_to_canonical_prefix(const uint8_t* octets, size_t octets_length, uint8_t length, uint8_t* out, uint8_t* out_octets, uint8_t* out_length);

/**
 * Writes whether the pattern at `pattern` matches the endpoint at `endpoint` into `out`; fails with Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_ip_endpoint_pattern_matches(const umilib_protocol_ip_IPEndpointPattern* pattern, const umilib_protocol_ip_IPEndpoint* endpoint, bool* out);

/**
 * Reads the dotted decimal UTF-8 text at `text` into `out`; fails with Syntax.
 */
const umilib_ffi_Status* umilib_protocol_ip_ipv4_address_parse(const uint8_t* text, size_t length, umilib_protocol_ip_IPv4Address* out);

/**
 * Writes the dotted decimal text of `address` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_ipv4_address_to_string(umilib_protocol_ip_IPv4Address address, umilib_ffi_Buffer* out);

/**
 * `address` with every bit after the first `length` cleared.
 */
umilib_protocol_ip_IPv4Address umilib_protocol_ip_ipv4_address_prefix(umilib_protocol_ip_IPv4Address address, uint8_t length);

/**
 * Whether the first `length` bits of `address` are those of `prefix`.
 */
bool umilib_protocol_ip_ipv4_address_has_prefix(umilib_protocol_ip_IPv4Address address, umilib_protocol_ip_IPv4Address prefix, uint8_t length);

/**
 * 0.0.0.0.
 */
bool umilib_protocol_ip_ipv4_address_is_unspecified(umilib_protocol_ip_IPv4Address address);

/**
 * 127.0.0.0/8.
 */
bool umilib_protocol_ip_ipv4_address_is_loopback(umilib_protocol_ip_IPv4Address address);

/**
 * 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16 (RFC 1918).
 */
bool umilib_protocol_ip_ipv4_address_is_private(umilib_protocol_ip_IPv4Address address);

/**
 * 169.254.0.0/16.
 */
bool umilib_protocol_ip_ipv4_address_is_link_local(umilib_protocol_ip_IPv4Address address);

/**
 * 224.0.0.0/4.
 */
bool umilib_protocol_ip_ipv4_address_is_multicast(umilib_protocol_ip_IPv4Address address);

/**
 * 255.255.255.255.
 */
bool umilib_protocol_ip_ipv4_address_is_broadcast(umilib_protocol_ip_IPv4Address address);

/**
 * 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 (RFC 5737).
 */
bool umilib_protocol_ip_ipv4_address_is_documentation(umilib_protocol_ip_IPv4Address address);

/**
 * The IPv4-mapped IPv6 address `::ffff:a.b.c.d` of `address`.
 */
umilib_protocol_ip_IPv6Address umilib_protocol_ip_ipv4_address_to_ipv6_mapped(umilib_protocol_ip_IPv4Address address);

/**
 * Reads an IPv6 address in any form of RFC 4291 §2.2 from the UTF-8 text at `text` into `out`;
 * fails with Syntax.
 */
const umilib_ffi_Status* umilib_protocol_ip_ipv6_address_parse(const uint8_t* text, size_t length, umilib_protocol_ip_IPv6Address* out);

/**
 * Writes the text form of RFC 5952 of `address` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_ipv6_address_to_string(umilib_protocol_ip_IPv6Address address, umilib_ffi_Buffer* out);

/**
 * `address` with every bit after the first `length` cleared.
 */
umilib_protocol_ip_IPv6Address umilib_protocol_ip_ipv6_address_prefix(umilib_protocol_ip_IPv6Address address, uint8_t length);

/**
 * Whether the first `length` bits of `address` are those of `prefix`.
 */
bool umilib_protocol_ip_ipv6_address_has_prefix(umilib_protocol_ip_IPv6Address address, umilib_protocol_ip_IPv6Address prefix, uint8_t length);

/**
 * The address of the 64-bit prefix at `prefix` and the interface identifier at
 * `interface_identifier` (8 bytes each).
 */
const umilib_ffi_Status* umilib_protocol_ip_ipv6_address_from_interface_identifier(const uint8_t* prefix, const uint8_t* interface_identifier, umilib_protocol_ip_IPv6Address* out);

/**
 * The solicited-node multicast address of `address` (RFC 4291 §2.7.1).
 */
umilib_protocol_ip_IPv6Address umilib_protocol_ip_ipv6_address_solicited_node(umilib_protocol_ip_IPv6Address address);

/**
 * `::`.
 */
bool umilib_protocol_ip_ipv6_address_is_unspecified(umilib_protocol_ip_IPv6Address address);

/**
 * `::1`.
 */
bool umilib_protocol_ip_ipv6_address_is_loopback(umilib_protocol_ip_IPv6Address address);

/**
 * `ff00::/8`.
 */
bool umilib_protocol_ip_ipv6_address_is_multicast(umilib_protocol_ip_IPv6Address address);

/**
 * `fe80::/10`.
 */
bool umilib_protocol_ip_ipv6_address_is_link_local(umilib_protocol_ip_IPv6Address address);

/**
 * `fc00::/7`.
 */
bool umilib_protocol_ip_ipv6_address_is_unique_local(umilib_protocol_ip_IPv6Address address);

/**
 * `2001:db8::/32` and `3fff::/20`.
 */
bool umilib_protocol_ip_ipv6_address_is_documentation(umilib_protocol_ip_IPv6Address address);

/**
 * Writes whether `address` is multicast into `out_found` and its scope into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_ipv6_address_multicast_scope(umilib_protocol_ip_IPv6Address address, bool* out_found, uint8_t* out);

/**
 * Writes whether `address` is IPv4-mapped into `out_found` and its IPv4 address into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_ipv6_address_to_ipv4_mapped(umilib_protocol_ip_IPv6Address address, bool* out_found, umilib_protocol_ip_IPv4Address* out);

/**
 * Writes the keyword of the IANA registry of protocol `number`, if it has one here, into
 * `out_found` and `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_ip_protocol_name(uint8_t number, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Adds the `length` bytes at `data`, which follow those added before, to `checksum`.
 */
const umilib_ffi_Status* umilib_protocol_ip_internet_checksum_update(umilib_protocol_ip_InternetChecksum* checksum, const uint8_t* data, size_t length);

/**
 * The one's complement sum of the bytes added, folded to 16 bits.
 */
uint16_t umilib_protocol_ip_internet_checksum_sum16(umilib_protocol_ip_InternetChecksum checksum);

/**
 * The checksum of the bytes added.
 */
uint16_t umilib_protocol_ip_internet_checksum_finish(umilib_protocol_ip_InternetChecksum checksum);

/**
 * Writes the checksum of the `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_internet_checksum_checksum(const uint8_t* data, size_t length, uint16_t* out);

/**
 * Writes whether the `length` bytes at `data`, their checksum field included, sum to all ones
 * into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_internet_checksum_verify(const uint8_t* data, size_t length, bool* out);

/**
 * `sum` folded to 16 bits by adding the carries back.
 */
uint16_t umilib_protocol_ip_internet_checksum_fold(uint64_t sum);

/**
 * The checksum `checksum` after a 16-bit word changes from `before` to `after` (RFC 1624 §3).
 */
uint16_t umilib_protocol_ip_internet_checksum_adjust(uint16_t checksum, uint16_t before, uint16_t after);

/**
 * Writes the checksum `checksum` after the `length` bytes at `before`, at an even offset of the
 * data, change to the `length` bytes at `after` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_internet_checksum_adjust_bytes(uint16_t checksum, const uint8_t* before, const uint8_t* after, size_t length, uint16_t* out);

/**
 * Writes the pseudo-header of `length` upper-layer bytes of `protocol` between the addresses of
 * `source_length` octets at `source` and `destination_length` octets at `destination` (4 for
 * IPv4, 16 for IPv6) into `out`; fails with Family or Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_ip_pseudo_header_to_bytes(const uint8_t* source, size_t source_length, const uint8_t* destination, size_t destination_length, uint8_t protocol, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes an empty reassembly buffer into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_ip_fragment_buffer_new(umilib_protocol_ip_IPFragmentBuffer** out);

/**
 * Releases a buffer. Does nothing if `buffer` is null.
 */
void umilib_protocol_ip_ip_fragment_buffer_free(umilib_protocol_ip_IPFragmentBuffer* buffer);

/**
 * Adds the `length` bytes at `data` at `offset`, the last ones if `last`, the data being at
 * most `maximum` bytes, and writes whether every byte is received into `out`; fails with
 * Overlap or Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_ip_fragment_buffer_insert(umilib_protocol_ip_IPFragmentBuffer* buffer, size_t offset, const uint8_t* data, size_t length, bool last, size_t maximum, bool* out);

/**
 * Checks the `length` bytes at `data` at `offset`, the last ones if `last`, against the
 * fragments received, the data being at most `maximum` bytes, without adding them, and writes
 * how much the buffer's memory would grow into `out`; fails with Overlap or Length.
 */
const umilib_ffi_Status* umilib_protocol_ip_ip_fragment_buffer_check(const umilib_protocol_ip_IPFragmentBuffer* buffer, size_t offset, const uint8_t* data, size_t length, bool last, size_t maximum, size_t* out);

/**
 * Writes a copy of the bytes received at their offsets (zeros between them) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_ip_fragment_buffer_data(const umilib_protocol_ip_IPFragmentBuffer* buffer, umilib_ffi_Buffer* out);

/**
 * Writes whether the length of the data is known into `out_found` and it into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ip_ip_fragment_buffer_length(const umilib_protocol_ip_IPFragmentBuffer* buffer, bool* out_found, size_t* out);

/**
 * The bytes the buffer holds, approximately: its data and the record of its fragments.
 */
const umilib_ffi_Status* umilib_protocol_ip_ip_fragment_buffer_memory(const umilib_protocol_ip_IPFragmentBuffer* buffer, size_t* out);

/**
 * Writes whether every byte is received into `out_complete` and how many are into `out_received`.
 */
const umilib_ffi_Status* umilib_protocol_ip_ip_fragment_buffer_progress(const umilib_protocol_ip_IPFragmentBuffer* buffer, bool* out_complete, size_t* out_received);

#ifdef __cplusplus
}
#endif

#endif
