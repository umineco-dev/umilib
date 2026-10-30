/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_JSON_H
#define UMILIB_CODEC_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A JSON value and everything it contains.
 */
typedef struct umilib_codec_json_JSONValue umilib_codec_json_JSONValue;

/**
 * A JSON number, kept exactly as written.
 */
typedef struct umilib_codec_json_JSONNumber umilib_codec_json_JSONNumber;

/**
 * Limits and options of parsing.
 */
typedef struct umilib_codec_json_JSONConfig umilib_codec_json_JSONConfig;

/**
 * How values are written as text.
 */
typedef struct umilib_codec_json_JSONEncoder umilib_codec_json_JSONEncoder;

/**
 * A pull parser over caller-owned bytes.
 */
typedef struct umilib_codec_json_JSONReader umilib_codec_json_JSONReader;

/**
 * The deepest nesting of arrays and objects.
 */
const umilib_ffi_Status* umilib_codec_json_json_config_maximum_depth(const umilib_codec_json_JSONConfig* config, size_t* out);

/**
 * The deepest nesting of arrays and objects.
 */
const umilib_ffi_Status* umilib_codec_json_json_config_set_maximum_depth(umilib_codec_json_JSONConfig* config, size_t value);

/**
 * The longest input, in bytes.
 */
const umilib_ffi_Status* umilib_codec_json_json_config_maximum_length(const umilib_codec_json_JSONConfig* config, size_t* out);

/**
 * The longest input, in bytes.
 */
const umilib_ffi_Status* umilib_codec_json_json_config_set_maximum_length(umilib_codec_json_JSONConfig* config, size_t value);

/**
 * Whether a UTF-8 byte order mark before the text is skipped.
 */
const umilib_ffi_Status* umilib_codec_json_json_config_allow_byte_order_mark(const umilib_codec_json_JSONConfig* config, bool* out);

/**
 * Whether a UTF-8 byte order mark before the text is skipped.
 */
const umilib_ffi_Status* umilib_codec_json_json_config_set_allow_byte_order_mark(umilib_codec_json_JSONConfig* config, bool value);

/**
 * Creates the default configuration.
 */
const umilib_ffi_Status* umilib_codec_json_json_config_new(umilib_codec_json_JSONConfig** out);

/**
 * Releases a configuration. Does nothing if `config` is null.
 */
void umilib_codec_json_json_config_free(umilib_codec_json_JSONConfig* config);

/**
 * Writes the duplicate key policy (0 reject, 1 keep first, 2 keep last, 3 keep all) into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_config_duplicate_keys(const umilib_codec_json_JSONConfig* config, uint8_t* out);

/**
 * Sets the duplicate key policy (0 reject, 1 keep first, 2 keep last, 3 keep all).
 */
const umilib_ffi_Status* umilib_codec_json_json_config_set_duplicate_keys(umilib_codec_json_JSONConfig* config, uint8_t policy);

/**
 * Parses `length` bytes at `data` with `config` (null for the defaults) into a new value.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_decode(const uint8_t* data, size_t length, const umilib_codec_json_JSONConfig* config, umilib_codec_json_JSONValue** out);

/**
 * Parses the UTF-8 `text` with the default limits into a new value.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_parse(const uint8_t* text, size_t length, umilib_codec_json_JSONValue** out);

/**
 * Releases a value and everything it contains. Does nothing if `value` is null.
 */
void umilib_codec_json_json_value_free(umilib_codec_json_JSONValue* value);

/**
 * Writes a new handle holding a copy of `value` into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_clone(const umilib_codec_json_JSONValue* value, umilib_codec_json_JSONValue** out);

/**
 * Writes whether two values are equal into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_equal(const umilib_codec_json_JSONValue* a, const umilib_codec_json_JSONValue* b, bool* out);

/**
 * Writes the kind of `value` (0 null, 1 bool, 2 number, 3 string, 4 array, 5 object) into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_kind(const umilib_codec_json_JSONValue* value, uint8_t* out);

/**
 * Creates `null`.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_null(umilib_codec_json_JSONValue** out);

/**
 * Creates a boolean.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_from_bool(bool value, umilib_codec_json_JSONValue** out);

/**
 * Creates a number holding a copy of `number`.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_from_number(const umilib_codec_json_JSONNumber* number, umilib_codec_json_JSONValue** out);

/**
 * Creates a string from UTF-8 `text`.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_from_string(const uint8_t* text, size_t length, umilib_codec_json_JSONValue** out);

/**
 * Creates an empty array.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_array(umilib_codec_json_JSONValue** out);

/**
 * Creates an empty object.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_object(umilib_codec_json_JSONValue** out);

/**
 * Writes the value of a boolean into `out`; fails with `WrongKind` for other values.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_as_bool(const umilib_codec_json_JSONValue* value, bool* out);

/**
 * Writes a new handle holding a copy of a number into `out`; fails with `WrongKind` for other values.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_as_number(const umilib_codec_json_JSONValue* value, umilib_codec_json_JSONNumber** out);

/**
 * Writes a copy of a string, as UTF-8, into `out`; fails with `WrongKind` for other values.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_as_str(const umilib_codec_json_JSONValue* value, umilib_ffi_Buffer* out);

/**
 * Writes the number of elements of an array or members of an object into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_len(const umilib_codec_json_JSONValue* value, size_t* out);

/**
 * Writes a new handle holding a copy of the array element at `index` into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_index(const umilib_codec_json_JSONValue* value, size_t index, umilib_codec_json_JSONValue** out);

/**
 * Appends a copy of `element` to an array.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_push(umilib_codec_json_JSONValue* value, const umilib_codec_json_JSONValue* element);

/**
 * Writes the key of the object member at `index`, as UTF-8, into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_member_key(const umilib_codec_json_JSONValue* value, size_t index, umilib_ffi_Buffer* out);

/**
 * Writes a new handle holding a copy of the value of the object member at `index` into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_member_value(const umilib_codec_json_JSONValue* value, size_t index, umilib_codec_json_JSONValue** out);

/**
 * Writes whether an object has the UTF-8 `key` into `out_found`, and a new handle holding a
 * copy of its first value into `out` (null if not found).
 */
const umilib_ffi_Status* umilib_codec_json_json_value_get(const umilib_codec_json_JSONValue* value, const uint8_t* key, size_t key_length, bool* out_found, umilib_codec_json_JSONValue** out);

/**
 * Sets the member named by the UTF-8 `key` of an object to a copy of `member`.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_insert(umilib_codec_json_JSONValue* value, const uint8_t* key, size_t key_length, const umilib_codec_json_JSONValue* member);

/**
 * Removes every member named by the UTF-8 `key` of an object and writes whether one existed into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_remove(umilib_codec_json_JSONValue* value, const uint8_t* key, size_t key_length, bool* out);

/**
 * Writes `value` as compact JSON text into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_value_encode(const umilib_codec_json_JSONValue* value, umilib_ffi_Buffer* out);

/**
 * Creates a number from UTF-8 `text`, which must follow the JSON grammar exactly.
 */
const umilib_ffi_Status* umilib_codec_json_json_number_new(const uint8_t* text, size_t length, umilib_codec_json_JSONNumber** out);

/**
 * Creates a number from a finite `value`; fails with `OutOfRange` for NaN and infinities.
 */
const umilib_ffi_Status* umilib_codec_json_json_number_from_f64(double value, umilib_codec_json_JSONNumber** out);

/**
 * Creates a number from `value`.
 */
const umilib_ffi_Status* umilib_codec_json_json_number_from_i64(int64_t value, umilib_codec_json_JSONNumber** out);

/**
 * Creates a number from `value`.
 */
const umilib_ffi_Status* umilib_codec_json_json_number_from_u64(uint64_t value, umilib_codec_json_JSONNumber** out);

/**
 * Creates a number from `value`.
 */
const umilib_ffi_Status* umilib_codec_json_json_number_from_i128(umilib_ffi_I128 value, umilib_codec_json_JSONNumber** out);

/**
 * Releases a number. Does nothing if `number` is null.
 */
void umilib_codec_json_json_number_free(umilib_codec_json_JSONNumber* number);

/**
 * Writes the text of `number` into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_number_as_str(const umilib_codec_json_JSONNumber* number, umilib_ffi_Buffer* out);

/**
 * Writes whether `number` is written without fraction or exponent into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_number_is_integer(const umilib_codec_json_JSONNumber* number, bool* out);

/**
 * Writes the nearest `f64` into `out`; fails with `OutOfRange` if it is too large for `f64`.
 */
const umilib_ffi_Status* umilib_codec_json_json_number_as_f64(const umilib_codec_json_JSONNumber* number, double* out);

/**
 * Writes the number as an `int64_t` into `out`; fails with `OutOfRange` if it is not an integer in range.
 */
const umilib_ffi_Status* umilib_codec_json_json_number_as_i64(const umilib_codec_json_JSONNumber* number, int64_t* out);

/**
 * Writes the number as a `uint64_t` into `out`; fails with `OutOfRange` if it is not a non-negative integer in range.
 */
const umilib_ffi_Status* umilib_codec_json_json_number_as_u64(const umilib_codec_json_JSONNumber* number, uint64_t* out);

/**
 * Writes the number as a 128-bit integer into `out`; fails with `OutOfRange` if it is not an integer in range.
 */
const umilib_ffi_Status* umilib_codec_json_json_number_as_i128(const umilib_codec_json_JSONNumber* number, umilib_ffi_I128* out);

/**
 * Creates the compact encoder (one line, no spaces, UTF-8).
 */
const umilib_ffi_Status* umilib_codec_json_json_encoder_compact(umilib_codec_json_JSONEncoder** out);

/**
 * Creates the pretty encoder (two spaces per level).
 */
const umilib_ffi_Status* umilib_codec_json_json_encoder_pretty(umilib_codec_json_JSONEncoder** out);

/**
 * Creates an encoder: `indent` spaces per level if `has_indent`, and `\u` escapes for non-ASCII if `ascii_only`.
 */
const umilib_ffi_Status* umilib_codec_json_json_encoder_new(bool has_indent, uint8_t indent, bool ascii_only, umilib_codec_json_JSONEncoder** out);

/**
 * Writes the settings of `encoder`: whether it indents, by how many spaces, and whether it escapes non-ASCII.
 */
const umilib_ffi_Status* umilib_codec_json_json_encoder_settings(const umilib_codec_json_JSONEncoder* encoder, bool* out_has_indent, uint8_t* out_indent, bool* out_ascii_only);

/**
 * Releases an encoder. Does nothing if `encoder` is null.
 */
void umilib_codec_json_json_encoder_free(umilib_codec_json_JSONEncoder* encoder);

/**
 * Writes `value` as text with `encoder` into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_encoder_encode(const umilib_codec_json_JSONEncoder* encoder, const umilib_codec_json_JSONValue* value, umilib_ffi_Buffer* out);

/**
 * Writes the UTF-8 `text` as a JSON string literal with `encoder` into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_encoder_write_string(const umilib_codec_json_JSONEncoder* encoder, const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Creates a reader over `length` bytes at `data`, which must stay valid and
 * unchanged while the reader is used, with `config` (null for the defaults).
 */
const umilib_ffi_Status* umilib_codec_json_json_reader_new(const uint8_t* data, size_t length, const umilib_codec_json_JSONConfig* config, umilib_codec_json_JSONReader** out);

/**
 * Releases a reader. Does nothing if `reader` is null.
 */
void umilib_codec_json_json_reader_free(umilib_codec_json_JSONReader* reader);

/**
 * Reads the next event. Writes whether there was one into `out_has_event` and its kind
 * (0 begin object, 1 end object, 2 begin array, 3 end array, 4 key, 5 string, 6 number,
 * 7 bool, 8 null) into `out_kind`. For keys, strings and numbers, `out_data` and
 * `out_length` describe the text as written in the input (without quotes, with escapes),
 * and `out_escaped` whether it has escape sequences; for booleans, `out_escaped` holds the value.
 */
const umilib_ffi_Status* umilib_codec_json_json_reader_next_event(umilib_codec_json_JSONReader* reader, bool* out_has_event, uint8_t* out_kind, const uint8_t** out_data, size_t* out_length, bool* out_escaped);

/**
 * Writes the byte offset of the next unread byte into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_reader_position(const umilib_codec_json_JSONReader* reader, size_t* out);

/**
 * Writes the number of open arrays and objects into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_reader_depth(const umilib_codec_json_JSONReader* reader, size_t* out);

/**
 * Reads every remaining event, which validates the rest of the text.
 */
const umilib_ffi_Status* umilib_codec_json_json_reader_validate(umilib_codec_json_JSONReader* reader);

/**
 * Decodes the escape sequences of a string as written in JSON text (without
 * quotes), validating it first, and writes the result as UTF-8 into `out`.
 */
const umilib_ffi_Status* umilib_codec_json_json_string_decode(const uint8_t* raw, size_t length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
