/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_SERVICE_H
#define UMILIB_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A pattern of bytes: any, exact, prefix or suffix.
 */
typedef struct umilib_service_Pattern umilib_service_Pattern;

/**
 * The answer a service callback writes with `umilib_service_response_write`.
 */
typedef struct umilib_service_Response umilib_service_Response;

/**
 * The call callback of a service: writes the answer to the request and returns true, or false if it failed.
 */
typedef bool (*umilib_service_ServiceCall)(void* context, const uint8_t* request, size_t length, umilib_service_Response* response);

/**
 * The drop callback of a service, called once when it is dropped.
 */
typedef void (*umilib_service_ServiceDrop)(void* context);

/**
 * A router of patterns of the request's bytes to callback services.
 */
typedef struct umilib_service_Router umilib_service_Router;

/**
 * Writes the pattern of the `length` bytes of text at `text` into `out` (case not ignored);
 * fails with `MisplacedWildcard` or `UnfinishedEscape`.
 */
const umilib_ffi_Status* umilib_service_pattern_parse(const uint8_t* text, size_t length, umilib_service_Pattern** out);

/**
 * Releases a pattern. Does nothing if `pattern` is null.
 */
void umilib_service_pattern_free(umilib_service_Pattern* pattern);

/**
 * Writes the text of the pattern into `out`.
 */
const umilib_ffi_Status* umilib_service_pattern_format(const umilib_service_Pattern* pattern, umilib_ffi_Buffer* out);

/**
 * Writes a copy of the pattern that ignores the case of ASCII letters if `ignore` is true into `out`.
 */
const umilib_ffi_Status* umilib_service_pattern_ignoring_ascii_case(const umilib_service_Pattern* pattern, bool ignore, umilib_service_Pattern** out);

/**
 * Writes whether the pattern ignores the case of ASCII letters into `out`.
 */
const umilib_ffi_Status* umilib_service_pattern_ignores_ascii_case(const umilib_service_Pattern* pattern, bool* out);

/**
 * Writes whether the `length` bytes at `data` match the pattern into `out`.
 */
const umilib_ffi_Status* umilib_service_pattern_matches_bytes(const umilib_service_Pattern* pattern, const uint8_t* data, size_t length, bool* out);

/**
 * Appends the `length` bytes at `data` to the answer of a service callback.
 */
const umilib_ffi_Status* umilib_service_response_write(umilib_service_Response* response, const uint8_t* data, size_t length);

/**
 * Writes a new router without routes into `out`.
 */
const umilib_ffi_Status* umilib_service_router_new(umilib_service_Router** out);

/**
 * Releases a router; the drop callbacks of its services are called. Does nothing if `router`
 * is null. Not during a call of the router (from one of its services).
 */
void umilib_service_router_free(umilib_service_Router* router);

/**
 * Adds a route of (a copy of) `pattern` to the service of `call`, `drop` (may be null) and
 * `context` after the routes. The router owns the service from then on; if this function
 * fails, the service is not added and the caller keeps its context (`drop` is not called).
 * Not during a call of the router (from one of its services).
 */
const umilib_ffi_Status* umilib_service_router_push(umilib_service_Router* router, const umilib_service_Pattern* pattern, umilib_service_ServiceCall call, umilib_service_ServiceDrop drop, void* context);

/**
 * Sets the service of the requests no route matches to that of `call`, `drop` and `context`;
 * with a null `call`, removes it (`drop` and `context` are then ignored). The drop callback of
 * a service replaced is called. If this function fails, nothing changes and the caller keeps
 * its context. Not during a call of the router (from one of its services).
 */
const umilib_ffi_Status* umilib_service_router_set_fallback(umilib_service_Router* router, umilib_service_ServiceCall call, umilib_service_ServiceDrop drop, void* context);

/**
 * Writes the routes of the router into `out`.
 */
const umilib_ffi_Status* umilib_service_router_len(const umilib_service_Router* router, size_t* out);

/**
 * Gives the `length` bytes at `data` to the service of the first route whose pattern matches
 * them (or the fallback) and writes its answer into `out`; fails with `Unrouted` if there is
 * none, and `Failed` if the service failed. The router must not be changed or released
 * until the call returns, by its services either.
 */
const umilib_ffi_Status* umilib_service_router_call(const umilib_service_Router* router, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
