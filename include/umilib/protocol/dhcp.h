/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_DHCP_H
#define UMILIB_PROTOCOL_DHCP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A DHCP Unique Identifier (RFC 9915 §11) but its variable bytes: kind 1 DUID-LLT, 2 DUID-EN,
 * 3 DUID-LL, 4 DUID-UUID, any other a type kept as it is; the fields a type has not are zero.
 */
typedef struct umilib_protocol_dhcp_DHCPDUID {
    uint16_t kind;
    uint16_t hardware;
    uint32_t time;
    uint32_t enterprise;
} umilib_protocol_dhcp_DHCPDUID;

/**
 * Reads the DUID of the `length` bytes at `bytes` (RFC 9915 §11) into `out` and its variable bytes
 * into `out_data`; fails with Malformed for one of fewer than 3 or more than 130 bytes, or of a
 * known type shorter than its fixed fields.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_dhcp_duid_decode(const uint8_t* bytes, size_t length, umilib_protocol_dhcp_DHCPDUID* out, umilib_ffi_Buffer* out_data);

/**
 * Writes the DUID of `duid` and the `length` bytes at `data` into `out`; fails with Malformed
 * without variable bytes, for a UUID of other than 16 bytes, or for more than 130 bytes in all
 * (RFC 9915 §11.1).
 */
const umilib_ffi_Status* umilib_protocol_dhcp_dhcp_duid_encode(umilib_protocol_dhcp_DHCPDUID duid, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * The time of a DUID-LLT made at `unix` seconds since 1970: the seconds since 2000-01-01 UTC,
 * modulo 2^32 (RFC 9915 §11.2).
 */
uint32_t umilib_protocol_dhcp_dhcp_duid_time(uint64_t unix);

#ifdef __cplusplus
}
#endif

#endif
