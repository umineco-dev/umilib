/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_UDP_H
#define UMILIB_PROTOCOL_UDP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/ip.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The header of a UDP datagram (RFC 768), its fields as they are.
 */
typedef struct umilib_protocol_udp_UDPHeader {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
} umilib_protocol_udp_UDPHeader;

/**
 * The fields of a UDP datagram but its payload.
 */
typedef struct umilib_protocol_udp_UDPDatagram {
    uint16_t source_port;
    uint16_t destination_port;
    bool checksummed;
} umilib_protocol_udp_UDPDatagram;

/**
 * A rule that routes datagrams by their local and remote endpoints.
 */
typedef struct umilib_protocol_udp_UDPRule {
    umilib_protocol_ip_IPEndpointPattern local;
    umilib_protocol_ip_IPEndpointPattern remote;
} umilib_protocol_udp_UDPRule;

/**
 * Reads the header at the start of the `length` bytes at `bytes` into `out`; fails with Length.
 */
const umilib_ffi_Status* umilib_protocol_udp_udp_header_decode(const uint8_t* bytes, size_t length, umilib_protocol_udp_UDPHeader* out);

/**
 * Writes the 8 bytes of `header` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_udp_udp_header_encode(umilib_protocol_udp_UDPHeader header, umilib_ffi_Buffer* out);

/**
 * Reads the datagram of the `length` bytes at `bytes`, carried from the address of the
 * `source_length` octets at `source` to that of the `destination_length` octets at
 * `destination`, into `out`, and the length of its payload, which starts 8 bytes in, into
 * `out_length`. A zero checksum over IPv6 needs the destination port among the `count` ports at
 * `ports`. Fails with Length, Checksum, ZeroChecksum, Family or Source, and with the ip module's
 * Length for an address of other than 4 or 16 octets.
 */
const umilib_ffi_Status* umilib_protocol_udp_udp_datagram_decode(const uint8_t* bytes, size_t length, const uint8_t* source, size_t source_length, const uint8_t* destination, size_t destination_length, const uint16_t* ports, size_t count, umilib_protocol_udp_UDPDatagram* out, size_t* out_length);

/**
 * Writes the header of the datagram of `datagram` and the `length` bytes of payload at `payload`
 * from the address at `source` to that at `destination` into `out`. Without a checksum over IPv6,
 * the source port must be among the `count` ports at `ports`. Fails with Length, ZeroChecksum,
 * Family or Source, and with the ip module's Length for an address of other than 4 or 16 octets.
 */
const umilib_ffi_Status* umilib_protocol_udp_udp_datagram_header(umilib_protocol_udp_UDPDatagram datagram, const uint8_t* payload, size_t length, const uint8_t* source, size_t source_length, const uint8_t* destination, size_t destination_length, const uint16_t* ports, size_t count, umilib_protocol_udp_UDPHeader* out);

/**
 * Writes the datagram of `datagram` and the `length` bytes of payload at `payload`, as
 * `umilib_protocol_udp_udp_datagram_header` makes its header, into `out`; fails as it does.
 */
const umilib_ffi_Status* umilib_protocol_udp_udp_datagram_encode(umilib_protocol_udp_UDPDatagram datagram, const uint8_t* payload, size_t length, const uint8_t* source, size_t source_length, const uint8_t* destination, size_t destination_length, const uint16_t* ports, size_t count, umilib_ffi_Buffer* out);

/**
 * Writes whether the rule at `rule` matches a datagram to the endpoint at `local` from the
 * endpoint at `remote` into `out`; fails with the ip module's Length for a bad address length.
 */
const umilib_ffi_Status* umilib_protocol_udp_udp_rule_matches(const umilib_protocol_udp_UDPRule* rule, const umilib_protocol_ip_IPEndpoint* local, const umilib_protocol_ip_IPEndpoint* remote, bool* out);

#ifdef __cplusplus
}
#endif

#endif
