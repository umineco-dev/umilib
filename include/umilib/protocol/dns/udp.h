/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_DNS_UDP_H
#define UMILIB_PROTOCOL_DNS_UDP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/ip.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes whether a datagram from `source` may be the response to a query sent to `destination`
 * (RFC 5452 §9.1: the same address and port) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_udp_dns_udp_accepts(umilib_protocol_ip_IPEndpoint source, umilib_protocol_ip_IPEndpoint destination, bool* out);

#ifdef __cplusplus
}
#endif

#endif
