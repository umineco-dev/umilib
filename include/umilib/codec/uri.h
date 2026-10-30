/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_URI_H
#define UMILIB_CODEC_URI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A URI reference of RFC 3986.
 */
typedef struct umilib_codec_uri_URIReference umilib_codec_uri_URIReference;

/**
 * The name and value pairs of the form encoding.
 */
typedef struct umilib_codec_uri_URIFormPairs umilib_codec_uri_URIFormPairs;

/**
 * Writes an empty relative reference (no scheme, authority, query or fragment, an empty
 * path) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_new(umilib_codec_uri_URIReference** out);

/**
 * Releases a reference. Does nothing if `reference` is null.
 */
void umilib_codec_uri_uri_reference_free(umilib_codec_uri_URIReference* reference);

/**
 * Writes the reference of the text at `text`, checked against RFC 3986, into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_parse(const uint8_t* text, size_t length, umilib_codec_uri_URIReference** out);

/**
 * Writes the text of `reference`, its components written back (RFC 3986 §5.3), into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_format(const umilib_codec_uri_URIReference* reference, umilib_ffi_Buffer* out);

/**
 * Succeeds if the components of `reference`, written back, read as the same reference.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_check(const umilib_codec_uri_URIReference* reference);

/**
 * Writes whether `reference` has a scheme into `out_has` and the scheme into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_scheme(const umilib_codec_uri_URIReference* reference, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Sets the scheme of `reference` to the text at `text`, or removes it if `text` is null.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_set_scheme(umilib_codec_uri_URIReference* reference, const uint8_t* text, size_t length);

/**
 * Writes whether `reference` has an authority into `out_has`, and its userinfo (whether it
 * has one into `out_has_userinfo`), its host and its port (whether it has one into
 * `out_has_port`) into the other outputs; every output is empty without an authority.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_authority(const umilib_codec_uri_URIReference* reference, bool* out_has, bool* out_has_userinfo, umilib_ffi_Buffer* out_userinfo, umilib_ffi_Buffer* out_host, bool* out_has_port, umilib_ffi_Buffer* out_port);

/**
 * Sets the authority of `reference` to the userinfo at `userinfo` (null for none), the host
 * at `host` and the port at `port` (null for none) if `has` is true, or removes it.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_set_authority(umilib_codec_uri_URIReference* reference, bool has, const uint8_t* userinfo, size_t userinfo_length, const uint8_t* host, size_t host_length, const uint8_t* port, size_t port_length);

/**
 * Writes the path of `reference` into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_path(const umilib_codec_uri_URIReference* reference, umilib_ffi_Buffer* out);

/**
 * Sets the path of `reference` to the text at `text`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_set_path(umilib_codec_uri_URIReference* reference, const uint8_t* text, size_t length);

/**
 * Writes whether `reference` has a query into `out_has` and the query into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_query(const umilib_codec_uri_URIReference* reference, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Sets the query of `reference` to the text at `text`, or removes it if `text` is null.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_set_query(umilib_codec_uri_URIReference* reference, const uint8_t* text, size_t length);

/**
 * Writes whether `reference` has a fragment into `out_has` and the fragment into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_fragment(const umilib_codec_uri_URIReference* reference, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Sets the fragment of `reference` to the text at `text`, or removes it if `text` is null.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_set_fragment(umilib_codec_uri_URIReference* reference, const uint8_t* text, size_t length);

/**
 * Writes whether `reference` is a relative reference (RFC 3986 §4.2, no scheme) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_is_relative(const umilib_codec_uri_URIReference* reference, bool* out);

/**
 * Writes whether `reference` is an absolute URI (RFC 3986 §4.3, a scheme and no fragment)
 * into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_is_absolute(const umilib_codec_uri_URIReference* reference, bool* out);

/**
 * Writes the target of `reference` resolved against `base` (RFC 3986 §5.2.2) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_resolve(const umilib_codec_uri_URIReference* reference, const umilib_codec_uri_URIReference* base, umilib_codec_uri_URIReference** out);

/**
 * Writes `reference` normalized by its syntax (RFC 3986 §6.2.2) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_normalize(const umilib_codec_uri_URIReference* reference, umilib_codec_uri_URIReference** out);

/**
 * Writes the path of `base` merged with the relative path at `path` (RFC 3986 §5.2.3) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_merge(const umilib_codec_uri_URIReference* base, const uint8_t* path, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the path at `path` with its `.` and `..` segments removed (RFC 3986 §5.2.4) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_remove_dot_segments(const uint8_t* path, size_t length, umilib_ffi_Buffer* out);

/**
 * Succeeds if the text at `scheme` is a scheme (RFC 3986 §3.1).
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_check_scheme(const uint8_t* scheme, size_t length);

/**
 * Writes whether `byte` may stand in a path as it is into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_is_path_byte(uint8_t byte, bool* out);

/**
 * Writes whether `byte` may stand in a query or a fragment as it is into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_reference_is_query_byte(uint8_t byte, bool* out);

/**
 * Writes the authority of the text at `text` (RFC 3986 §3.2) as
 * `umilib_codec_uri_uri_reference_authority` does, without `out_has`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_authority_parse(const uint8_t* text, size_t length, bool* out_has_userinfo, umilib_ffi_Buffer* out_userinfo, umilib_ffi_Buffer* out_host, bool* out_has_port, umilib_ffi_Buffer* out_port);

/**
 * Writes the form of the host at `host` (RFC 3986 §3.2.2: 0 IPv6, 1 IPvFuture, 2 IPv4,
 * 3 RegName) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_authority_host_kind(const uint8_t* host, size_t length, uint8_t* out);

/**
 * Writes whether the bytes at `text` are an IPv4address (RFC 3986 §3.2.2) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_authority_is_ipv4(const uint8_t* text, size_t length, bool* out);

/**
 * Writes whether the bytes at `text` are an IPv6address (RFC 3986 §3.2.2) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_authority_is_ipv6(const uint8_t* text, size_t length, bool* out);

/**
 * Writes whether the bytes at `text` are an IPvFuture (RFC 3986 §3.2.2) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_authority_is_ipvfuture(const uint8_t* text, size_t length, bool* out);

/**
 * Writes the `length` bytes at `data` with every octet not among the `keep_length` bytes
 * at `keep` percent-encoded (RFC 3986 §2.1) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_percent_encode(const uint8_t* data, size_t length, const uint8_t* keep, size_t keep_length, umilib_ffi_Buffer* out);

/**
 * Writes the `length` bytes at `data` with every octet but the unreserved percent-encoded into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_percent_encode_component(const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the octets of the `length` bytes at `text`, percent-encodings decoded, into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_percent_decode(const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the UTF-8 text of the `length` bytes at `text`, percent-encodings decoded, into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_percent_decode_text(const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Succeeds if every `%` of the `length` bytes at `text` begins a percent-encoding.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_percent_check(const uint8_t* text, size_t length);

/**
 * Writes whether `byte` is unreserved (RFC 3986 §2.3) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_percent_is_unreserved(uint8_t byte, bool* out);

/**
 * Writes whether `byte` is a sub-delimiter (RFC 3986 §2.2) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_percent_is_sub_delim(uint8_t byte, bool* out);

/**
 * Writes whether `byte` is a general delimiter (RFC 3986 §2.2) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_percent_is_gen_delim(uint8_t byte, bool* out);

/**
 * Writes whether `byte` is a pchar other than a percent-encoding (RFC 3986 §3.3) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_percent_is_pchar(uint8_t byte, bool* out);

/**
 * Writes whether `byte` is a hexadecimal digit into `out_found` and its value into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_percent_digit(uint8_t byte, bool* out_found, uint8_t* out);

/**
 * Writes an empty list of name and value pairs into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_form_pairs_new(umilib_codec_uri_URIFormPairs** out);

/**
 * Releases a list of pairs. Does nothing if `pairs` is null.
 */
void umilib_codec_uri_uri_form_pairs_free(umilib_codec_uri_URIFormPairs* pairs);

/**
 * Appends the pair of the UTF-8 `name` and `value`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_form_pairs_push(umilib_codec_uri_URIFormPairs* pairs, const uint8_t* name, size_t name_length, const uint8_t* value, size_t value_length);

/**
 * Writes the number of pairs of the list into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_form_pairs_count(const umilib_codec_uri_URIFormPairs* pairs, size_t* out);

/**
 * Writes the name of the pair `index` into `out_name` and its value into `out_value`;
 * fails with NoSuchPair past the end.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_form_pairs_get(const umilib_codec_uri_URIFormPairs* pairs, size_t index, umilib_ffi_Buffer* out_name, umilib_ffi_Buffer* out_value);

/**
 * Writes the pairs of the `length` bytes at `input` (WHATWG URL Standard §5.1; octets that
 * are not UTF-8 fail) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_form_parse(const uint8_t* input, size_t length, umilib_codec_uri_URIFormPairs** out);

/**
 * Writes the text of one name or value at `text` (`+` a space, percent-encodings decoded) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_form_decode(const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the UTF-8 `text` as one name or value of the form encoding (WHATWG URL Standard §5.2) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_form_encode_text(const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes `pairs` in the form encoding (`name=value` joined by `&`) into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_form_encode(const umilib_codec_uri_URIFormPairs* pairs, umilib_ffi_Buffer* out);

/**
 * Writes whether the form serializer keeps `byte` as it is into `out`.
 */
const umilib_ffi_Status* umilib_codec_uri_uri_form_is_kept(uint8_t byte, bool* out);

#ifdef __cplusplus
}
#endif

#endif
