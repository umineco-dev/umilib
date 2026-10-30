/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_H
#define UMILIB_CODEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * What one call of a compressor or a decompressor did: the bytes it consumed and
 * produced, and whether the stream ended.
 */
typedef struct umilib_codec_Progress {
    size_t consumed;
    size_t produced;
    bool finished;
} umilib_codec_Progress;

#ifdef __cplusplus
}
#endif

#endif
