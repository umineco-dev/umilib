/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_ICMP_H
#define UMILIB_PROTOCOL_ICMP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The first eight bytes of an ICMP or ICMPv6 message but the checksum.
 */
typedef struct umilib_protocol_icmp_ICMPHeader {
    uint8_t kind;
    uint8_t code;
    uint8_t rest[4];
} umilib_protocol_icmp_ICMPHeader;

/**
 * The token bucket that limits the error messages a node originates.
 */
typedef struct umilib_protocol_icmp_ICMPRateLimiter umilib_protocol_icmp_ICMPRateLimiter;

/**
 * Checks the extension structure of the `length` bytes at `bytes` (version 2, the checksum if
 * one was sent, the objects) and writes its checksum as received into `out`; fails with Version,
 * Checksum or Length.
 */
const umilib_ffi_Status* umilib_protocol_icmp_icmp_extensions_decode(const uint8_t* bytes, size_t length, uint16_t* out);

/**
 * Writes whether the extension structure of the `length` bytes at `bytes` has an object at
 * `index` into `out_found`, its class and sub-type into `out_class` and `out_kind`, and its
 * payload into `out`; fails as `umilib_protocol_icmp_icmp_extensions_decode` does.
 */
const umilib_ffi_Status* umilib_protocol_icmp_icmp_extensions_get(const uint8_t* bytes, size_t length, size_t index, bool* out_found, uint8_t* out_class, uint8_t* out_kind, umilib_ffi_Buffer* out);

/**
 * Writes an object of the class `object_class`, the sub-type `kind` and the `length` bytes of
 * payload at `payload` into `out`; fails with Length unless the object is a multiple of 4 bytes.
 */
const umilib_ffi_Status* umilib_protocol_icmp_icmp_extension_object_encode(uint8_t object_class, uint8_t kind, const uint8_t* payload, size_t length, umilib_ffi_Buffer* out);

/**
 * Checks that the `length` bytes of encoded objects at `objects` are one or more objects of whole
 * 32-bit words (RFC 4884 §7, §8); fails with Length.
 */
const umilib_ffi_Status* umilib_protocol_icmp_icmp_extensions_check(const uint8_t* objects, size_t length);

/**
 * Checks that `word` is the word of a version of ICMP, 4 or 8 (RFC 4884 §4); fails with Invalid.
 */
const umilib_ffi_Status* umilib_protocol_icmp_icmp_extensions_check_word(size_t word);

/**
 * Writes the extension structure of the `length` bytes of encoded objects at `objects` into `out`;
 * fails with Length unless they are one or more objects of whole 32-bit words.
 */
const umilib_ffi_Status* umilib_protocol_icmp_icmp_extensions_encode(const uint8_t* objects, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the body of an extended error message (the `original_length` bytes of the original
 * datagram at `original`, padded to a multiple of `word` bytes and to 128, then the structure of
 * the `objects_length` bytes of objects at `objects`) into `out` and its length attribute into
 * `out_attribute`; fails with Invalid unless `word` is 4 or 8, and with Length if the attribute
 * does not fit 8 bits or the objects are not one or more of whole 32-bit words.
 */
const umilib_ffi_Status* umilib_protocol_icmp_icmp_extensions_encode_body(const uint8_t* objects, size_t objects_length, const uint8_t* original, size_t original_length, size_t word, uint8_t* out_attribute, umilib_ffi_Buffer* out);

/**
 * Splits the `length` bytes of body at `body` of an error message whose length attribute is
 * `attribute` words of `word` bytes: writes the length of the original datagram into
 * `out_original` and whether an extension structure follows it into `out_found`; fails with
 * Invalid unless `word` is 4 or 8, and with Length, Version or Checksum if the body or the
 * structure is malformed.
 */
const umilib_ffi_Status* umilib_protocol_icmp_icmp_extensions_split_body(const uint8_t* body, size_t length, uint8_t attribute, size_t word, size_t* out_original, bool* out_found);

/**
 * Writes a full token bucket of `burst` tokens, one added every `interval` nanoseconds, at
 * `now` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_icmp_rate_limiter_new(uint32_t burst, uint64_t interval, uint64_t now, umilib_protocol_icmp_ICMPRateLimiter** out);

/**
 * Releases a bucket. Does nothing if `limiter` is null.
 */
void umilib_protocol_icmp_icmp_rate_limiter_free(umilib_protocol_icmp_ICMPRateLimiter* limiter);

/**
 * Writes whether a message may be sent at `now` into `out`, taking its token if so.
 */
const umilib_ffi_Status* umilib_protocol_icmp_icmp_rate_limiter_allow(umilib_protocol_icmp_ICMPRateLimiter* limiter, uint64_t now, bool* out);

#ifdef __cplusplus
}
#endif

#endif
