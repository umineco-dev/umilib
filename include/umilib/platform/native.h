/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PLATFORM_NATIVE_H
#define UMILIB_PLATFORM_NATIVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fills the `length` bytes at `data` with the system's random bytes.
 */
const umilib_ffi_Status* umilib_platform_native_random_fill(uint8_t* data, size_t length);

/**
 * Writes the name of the operating system ("linux", "android", "darwin", "windows" or "other"),
 * a static NUL-terminated string, into `out`.
 */
const umilib_ffi_Status* umilib_platform_native_system_name(const char** out);

#ifdef __cplusplus
}
#endif

#endif
