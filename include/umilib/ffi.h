/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_FFI_H
#define UMILIB_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The error returned by a fallible function; success is a null pointer.
 * Every string is static and NUL-terminated.
 */
typedef struct umilib_ffi_Status {
    const char* domain;
    const char* name;
    const char* message;
} umilib_ffi_Status;

/**
 * Bytes owned by umilib; release them with umilib_ffi_buffer_free, which
 * overwrites them with zeros. Do not modify the fields.
 */
typedef struct umilib_ffi_Buffer {
    uint8_t* data;
    size_t length;
    size_t capacity;
} umilib_ffi_Buffer;

/**
 * An unsigned 128-bit integer: (high << 64) | low.
 */
typedef struct umilib_ffi_U128 {
    uint64_t high;
    uint64_t low;
} umilib_ffi_U128;

/**
 * A signed 128-bit integer in two's complement: (high << 64) | low.
 */
typedef struct umilib_ffi_I128 {
    int64_t high;
    uint64_t low;
} umilib_ffi_I128;

/**
 * Overwrites the bytes owned by `buffer` with zeros, releases them and resets it to empty.
 * Does nothing if `buffer` is null or already empty.
 */
void umilib_ffi_buffer_free(umilib_ffi_Buffer* buffer);

/**
 * Writes the manifest of this build, as UTF-8 JSON, into `out`.
 */
const umilib_ffi_Status* umilib_ffi_manifest(umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
