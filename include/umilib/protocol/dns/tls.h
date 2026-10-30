/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_DNS_TLS_H
#define UMILIB_PROTOCOL_DNS_TLS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes the ALPN of DNS over TLS, "dot", into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_tls_dns_tls_alpn(umilib_ffi_Buffer* out);

/**
 * Writes whether the application protocol `connection` negotiated is none or "dot" into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_tls_dns_tls_check_protocol(const umilib_protocol_tls_TLSConnection* connection, bool* out);

#ifdef __cplusplus
}
#endif

#endif
