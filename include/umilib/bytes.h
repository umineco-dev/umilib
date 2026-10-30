/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_BYTES_H
#define UMILIB_BYTES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A cursor over caller-owned bytes, which must outlive the reader.
 */
typedef struct umilib_bytes_Reader umilib_bytes_Reader;

/**
 * A growable byte buffer with an optional limit.
 */
typedef struct umilib_bytes_Buffer umilib_bytes_Buffer;

/**
 * Received bytes read as CRLF-ended lines or counted bytes.
 */
typedef struct umilib_bytes_LineBuffer umilib_bytes_LineBuffer;

/**
 * A writer into caller-owned bytes, which must outlive the writer.
 */
typedef struct umilib_bytes_SliceWriter umilib_bytes_SliceWriter;

/**
 * Creates a reader over `length` bytes at `data`, which must stay valid
 * and unchanged until the reader and every slice read from it are no longer used.
 */
const umilib_ffi_Status* umilib_bytes_reader_new(const uint8_t* data, size_t length, umilib_bytes_Reader** out);

/**
 * Releases a reader. Does nothing if `reader` is null.
 */
void umilib_bytes_reader_free(umilib_bytes_Reader* reader);

/**
 * Writes the number of bytes already read into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_position(const umilib_bytes_Reader* reader, size_t* out);

/**
 * Writes the number of bytes left to read into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_remaining(const umilib_bytes_Reader* reader, size_t* out);

/**
 * Writes whether every byte has been read into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_is_empty(const umilib_bytes_Reader* reader, bool* out);

/**
 * Writes a pointer to the next `length` bytes into `out` without consuming them.
 */
const umilib_ffi_Status* umilib_bytes_reader_peek(const umilib_bytes_Reader* reader, size_t length, const uint8_t** out);

/**
 * Consumes the next `length` bytes and writes a pointer to them into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_slice(umilib_bytes_Reader* reader, size_t length, const uint8_t** out);

/**
 * Consumes the next `length` bytes and copies them to `out`, which has room for `length` bytes.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_array(umilib_bytes_Reader* reader, size_t length, uint8_t* out);

/**
 * Consumes the next `length` bytes and writes a new reader over them into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_reader(umilib_bytes_Reader* reader, size_t length, umilib_bytes_Reader** out);

/**
 * Consumes every remaining byte and writes a pointer to them into `out_data` and their number into `out_length`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_rest(umilib_bytes_Reader* reader, const uint8_t** out_data, size_t* out_length);

/**
 * Consumes `length` bytes.
 */
const umilib_ffi_Status* umilib_bytes_reader_skip(umilib_bytes_Reader* reader, size_t length);

/**
 * Consumes one byte and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_u8(umilib_bytes_Reader* reader, uint8_t* out);

/**
 * Consumes a big-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_u8(umilib_bytes_Reader* reader, uint8_t* out);

/**
 * Consumes a little-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_u8(umilib_bytes_Reader* reader, uint8_t* out);

/**
 * Consumes a big-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_sized_u8(umilib_bytes_Reader* reader, size_t length, uint8_t* out);

/**
 * Consumes a little-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_sized_u8(umilib_bytes_Reader* reader, size_t length, uint8_t* out);

/**
 * Consumes a big-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_u16(umilib_bytes_Reader* reader, uint16_t* out);

/**
 * Consumes a little-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_u16(umilib_bytes_Reader* reader, uint16_t* out);

/**
 * Consumes a big-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_sized_u16(umilib_bytes_Reader* reader, size_t length, uint16_t* out);

/**
 * Consumes a little-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_sized_u16(umilib_bytes_Reader* reader, size_t length, uint16_t* out);

/**
 * Consumes a big-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_u32(umilib_bytes_Reader* reader, uint32_t* out);

/**
 * Consumes a little-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_u32(umilib_bytes_Reader* reader, uint32_t* out);

/**
 * Consumes a big-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_sized_u32(umilib_bytes_Reader* reader, size_t length, uint32_t* out);

/**
 * Consumes a little-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_sized_u32(umilib_bytes_Reader* reader, size_t length, uint32_t* out);

/**
 * Consumes a big-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_u64(umilib_bytes_Reader* reader, uint64_t* out);

/**
 * Consumes a little-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_u64(umilib_bytes_Reader* reader, uint64_t* out);

/**
 * Consumes a big-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_sized_u64(umilib_bytes_Reader* reader, size_t length, uint64_t* out);

/**
 * Consumes a little-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_sized_u64(umilib_bytes_Reader* reader, size_t length, uint64_t* out);

/**
 * Consumes a big-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_u128(umilib_bytes_Reader* reader, umilib_ffi_U128* out);

/**
 * Consumes a little-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_u128(umilib_bytes_Reader* reader, umilib_ffi_U128* out);

/**
 * Consumes a big-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_sized_u128(umilib_bytes_Reader* reader, size_t length, umilib_ffi_U128* out);

/**
 * Consumes a little-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_sized_u128(umilib_bytes_Reader* reader, size_t length, umilib_ffi_U128* out);

/**
 * Consumes a big-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_i8(umilib_bytes_Reader* reader, int8_t* out);

/**
 * Consumes a little-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_i8(umilib_bytes_Reader* reader, int8_t* out);

/**
 * Consumes a big-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_sized_i8(umilib_bytes_Reader* reader, size_t length, int8_t* out);

/**
 * Consumes a little-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_sized_i8(umilib_bytes_Reader* reader, size_t length, int8_t* out);

/**
 * Consumes a big-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_i16(umilib_bytes_Reader* reader, int16_t* out);

/**
 * Consumes a little-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_i16(umilib_bytes_Reader* reader, int16_t* out);

/**
 * Consumes a big-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_sized_i16(umilib_bytes_Reader* reader, size_t length, int16_t* out);

/**
 * Consumes a little-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_sized_i16(umilib_bytes_Reader* reader, size_t length, int16_t* out);

/**
 * Consumes a big-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_i32(umilib_bytes_Reader* reader, int32_t* out);

/**
 * Consumes a little-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_i32(umilib_bytes_Reader* reader, int32_t* out);

/**
 * Consumes a big-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_sized_i32(umilib_bytes_Reader* reader, size_t length, int32_t* out);

/**
 * Consumes a little-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_sized_i32(umilib_bytes_Reader* reader, size_t length, int32_t* out);

/**
 * Consumes a big-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_i64(umilib_bytes_Reader* reader, int64_t* out);

/**
 * Consumes a little-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_i64(umilib_bytes_Reader* reader, int64_t* out);

/**
 * Consumes a big-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_sized_i64(umilib_bytes_Reader* reader, size_t length, int64_t* out);

/**
 * Consumes a little-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_sized_i64(umilib_bytes_Reader* reader, size_t length, int64_t* out);

/**
 * Consumes a big-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_i128(umilib_bytes_Reader* reader, umilib_ffi_I128* out);

/**
 * Consumes a little-endian integer of the full size of the type and writes it into `out`.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_i128(umilib_bytes_Reader* reader, umilib_ffi_I128* out);

/**
 * Consumes a big-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_be_sized_i128(umilib_bytes_Reader* reader, size_t length, umilib_ffi_I128* out);

/**
 * Consumes a little-endian integer encoded in `length` bytes and writes it into `out`.
 * Signed integers are sign-extended.
 */
const umilib_ffi_Status* umilib_bytes_reader_read_le_sized_i128(umilib_bytes_Reader* reader, size_t length, umilib_ffi_I128* out);

/**
 * Creates an empty buffer without a limit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_new(umilib_bytes_Buffer** out);

/**
 * Creates an empty buffer that never holds more than `limit` bytes.
 */
const umilib_ffi_Status* umilib_bytes_buffer_with_limit(size_t limit, umilib_bytes_Buffer** out);

/**
 * Creates an empty buffer that can hold `capacity` bytes without reallocating.
 * Fails with `CapacityExceeded` if the memory cannot be allocated.
 */
const umilib_ffi_Status* umilib_bytes_buffer_with_capacity(size_t capacity, umilib_bytes_Buffer** out);

/**
 * Like `umilib_bytes_buffer_with_capacity`; both fail instead of aborting
 * when the memory cannot be allocated.
 */
const umilib_ffi_Status* umilib_bytes_buffer_try_with_capacity(size_t capacity, umilib_bytes_Buffer** out);

/**
 * Writes the number of bytes the buffer can hold without reallocating into `out`.
 */
const umilib_ffi_Status* umilib_bytes_buffer_capacity(const umilib_bytes_Buffer* buffer, size_t* out);

/**
 * Releases a buffer. Does nothing if `buffer` is null.
 */
void umilib_bytes_buffer_free(umilib_bytes_Buffer* buffer);

/**
 * Writes whether the buffer has a limit into `out_has_limit` and the limit, if any, into `out_limit`.
 */
const umilib_ffi_Status* umilib_bytes_buffer_limit(const umilib_bytes_Buffer* buffer, bool* out_has_limit, size_t* out_limit);

/**
 * Sets the limit to `limit` if `has_limit` is true, or removes it.
 * Fails if the buffer already holds more than the new limit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_set_limit(umilib_bytes_Buffer* buffer, bool has_limit, size_t limit);

/**
 * Writes the number of bytes written into `out`.
 */
const umilib_ffi_Status* umilib_bytes_buffer_len(const umilib_bytes_Buffer* buffer, size_t* out);

/**
 * Writes whether nothing has been written into `out`.
 */
const umilib_ffi_Status* umilib_bytes_buffer_is_empty(const umilib_bytes_Buffer* buffer, bool* out);

/**
 * Writes a pointer to the written bytes into `out_data` and their number into `out_length`.
 * The pointer is valid until the buffer is next modified or released.
 */
const umilib_ffi_Status* umilib_bytes_buffer_as_slice(const umilib_bytes_Buffer* buffer, const uint8_t** out_data, size_t* out_length);

/**
 * Removes every byte, keeping the allocation and the limit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_clear(umilib_bytes_Buffer* buffer);

/**
 * Shortens the buffer to `length` bytes. Does nothing if it is already shorter.
 */
const umilib_ffi_Status* umilib_bytes_buffer_truncate(umilib_bytes_Buffer* buffer, size_t length);

/**
 * Moves the written bytes into `out` and releases the buffer handle.
 * On failure the handle is not released.
 */
const umilib_ffi_Status* umilib_bytes_buffer_into_vec(umilib_bytes_Buffer* buffer, umilib_ffi_Buffer* out);

/**
 * Appends `length` bytes at `data`. `data` may point into the writer's own storage.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write(umilib_bytes_Buffer* writer, const uint8_t* data, size_t length);

/**
 * Appends one byte.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_u8(umilib_bytes_Buffer* writer, uint8_t value);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_u8(umilib_bytes_Buffer* writer, uint8_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_u8(umilib_bytes_Buffer* writer, uint8_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_sized_u8(umilib_bytes_Buffer* writer, uint8_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_sized_u8(umilib_bytes_Buffer* writer, uint8_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_u16(umilib_bytes_Buffer* writer, uint16_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_u16(umilib_bytes_Buffer* writer, uint16_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_sized_u16(umilib_bytes_Buffer* writer, uint16_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_sized_u16(umilib_bytes_Buffer* writer, uint16_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_u32(umilib_bytes_Buffer* writer, uint32_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_u32(umilib_bytes_Buffer* writer, uint32_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_sized_u32(umilib_bytes_Buffer* writer, uint32_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_sized_u32(umilib_bytes_Buffer* writer, uint32_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_u64(umilib_bytes_Buffer* writer, uint64_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_u64(umilib_bytes_Buffer* writer, uint64_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_sized_u64(umilib_bytes_Buffer* writer, uint64_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_sized_u64(umilib_bytes_Buffer* writer, uint64_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_u128(umilib_bytes_Buffer* writer, umilib_ffi_U128 value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_u128(umilib_bytes_Buffer* writer, umilib_ffi_U128 value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_sized_u128(umilib_bytes_Buffer* writer, umilib_ffi_U128 value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_sized_u128(umilib_bytes_Buffer* writer, umilib_ffi_U128 value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_i8(umilib_bytes_Buffer* writer, int8_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_i8(umilib_bytes_Buffer* writer, int8_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_sized_i8(umilib_bytes_Buffer* writer, int8_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_sized_i8(umilib_bytes_Buffer* writer, int8_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_i16(umilib_bytes_Buffer* writer, int16_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_i16(umilib_bytes_Buffer* writer, int16_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_sized_i16(umilib_bytes_Buffer* writer, int16_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_sized_i16(umilib_bytes_Buffer* writer, int16_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_i32(umilib_bytes_Buffer* writer, int32_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_i32(umilib_bytes_Buffer* writer, int32_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_sized_i32(umilib_bytes_Buffer* writer, int32_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_sized_i32(umilib_bytes_Buffer* writer, int32_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_i64(umilib_bytes_Buffer* writer, int64_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_i64(umilib_bytes_Buffer* writer, int64_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_sized_i64(umilib_bytes_Buffer* writer, int64_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_sized_i64(umilib_bytes_Buffer* writer, int64_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_i128(umilib_bytes_Buffer* writer, umilib_ffi_I128 value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_i128(umilib_bytes_Buffer* writer, umilib_ffi_I128 value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_be_sized_i128(umilib_bytes_Buffer* writer, umilib_ffi_I128 value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_buffer_write_le_sized_i128(umilib_bytes_Buffer* writer, umilib_ffi_I128 value, size_t length);

/**
 * Creates an empty line buffer.
 */
const umilib_ffi_Status* umilib_bytes_line_buffer_new(umilib_bytes_LineBuffer** out);

/**
 * Appends the `length` bytes at `data`.
 */
const umilib_ffi_Status* umilib_bytes_line_buffer_push(umilib_bytes_LineBuffer* buffer, const uint8_t* data, size_t length);

/**
 * Writes the number of bytes not yet read into `out`.
 */
const umilib_ffi_Status* umilib_bytes_line_buffer_len(const umilib_bytes_LineBuffer* buffer, size_t* out);

/**
 * Writes a copy of the bytes not yet read into `out`.
 */
const umilib_ffi_Status* umilib_bytes_line_buffer_unread(const umilib_bytes_LineBuffer* buffer, umilib_ffi_Buffer* out);

/**
 * Skips up to `count` bytes.
 */
const umilib_ffi_Status* umilib_bytes_line_buffer_consume(umilib_bytes_LineBuffer* buffer, size_t count);

/**
 * Writes up to `count` bytes, read, into `out`.
 */
const umilib_ffi_Status* umilib_bytes_line_buffer_take(umilib_bytes_LineBuffer* buffer, size_t count, umilib_ffi_Buffer* out);

/**
 * Discards every byte not yet read.
 */
const umilib_ffi_Status* umilib_bytes_line_buffer_clear(umilib_bytes_LineBuffer* buffer);

/**
 * Writes whether a whole line is here into `out_found` and the line, its CRLF removed, into
 * `out`. A line of more than `maximum` bytes, its CRLF counted, fails once with LineTooLong.
 */
const umilib_ffi_Status* umilib_bytes_line_buffer_line(umilib_bytes_LineBuffer* buffer, size_t maximum, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Releases a line buffer. Does nothing if `buffer` is null.
 */
void umilib_bytes_line_buffer_free(umilib_bytes_LineBuffer* buffer);

/**
 * Creates a writer that fills `length` bytes at `data` from the start.
 * The bytes must stay valid until the writer is released.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_new(uint8_t* data, size_t length, umilib_bytes_SliceWriter** out);

/**
 * Releases a writer. Does nothing if `writer` is null.
 */
void umilib_bytes_slice_writer_free(umilib_bytes_SliceWriter* writer);

/**
 * Writes the number of bytes written into `out`.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_position(const umilib_bytes_SliceWriter* writer, size_t* out);

/**
 * Writes the length of the whole slice into `out`.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_capacity(const umilib_bytes_SliceWriter* writer, size_t* out);

/**
 * Writes the number of bytes that can still be written into `out`.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_remaining(const umilib_bytes_SliceWriter* writer, size_t* out);

/**
 * Writes a pointer to the written bytes into `out_data` and their number into `out_length`.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_written(const umilib_bytes_SliceWriter* writer, const uint8_t** out_data, size_t* out_length);

/**
 * Writes the number of bytes written into `out` and releases the writer handle.
 * On failure the handle is not released.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_into_written(umilib_bytes_SliceWriter* writer, size_t* out);

/**
 * Appends `length` bytes at `data`. `data` may point into the writer's own storage.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write(umilib_bytes_SliceWriter* writer, const uint8_t* data, size_t length);

/**
 * Appends one byte.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_u8(umilib_bytes_SliceWriter* writer, uint8_t value);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_u8(umilib_bytes_SliceWriter* writer, uint8_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_u8(umilib_bytes_SliceWriter* writer, uint8_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_sized_u8(umilib_bytes_SliceWriter* writer, uint8_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_sized_u8(umilib_bytes_SliceWriter* writer, uint8_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_u16(umilib_bytes_SliceWriter* writer, uint16_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_u16(umilib_bytes_SliceWriter* writer, uint16_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_sized_u16(umilib_bytes_SliceWriter* writer, uint16_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_sized_u16(umilib_bytes_SliceWriter* writer, uint16_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_u32(umilib_bytes_SliceWriter* writer, uint32_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_u32(umilib_bytes_SliceWriter* writer, uint32_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_sized_u32(umilib_bytes_SliceWriter* writer, uint32_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_sized_u32(umilib_bytes_SliceWriter* writer, uint32_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_u64(umilib_bytes_SliceWriter* writer, uint64_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_u64(umilib_bytes_SliceWriter* writer, uint64_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_sized_u64(umilib_bytes_SliceWriter* writer, uint64_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_sized_u64(umilib_bytes_SliceWriter* writer, uint64_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_u128(umilib_bytes_SliceWriter* writer, umilib_ffi_U128 value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_u128(umilib_bytes_SliceWriter* writer, umilib_ffi_U128 value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_sized_u128(umilib_bytes_SliceWriter* writer, umilib_ffi_U128 value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_sized_u128(umilib_bytes_SliceWriter* writer, umilib_ffi_U128 value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_i8(umilib_bytes_SliceWriter* writer, int8_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_i8(umilib_bytes_SliceWriter* writer, int8_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_sized_i8(umilib_bytes_SliceWriter* writer, int8_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_sized_i8(umilib_bytes_SliceWriter* writer, int8_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_i16(umilib_bytes_SliceWriter* writer, int16_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_i16(umilib_bytes_SliceWriter* writer, int16_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_sized_i16(umilib_bytes_SliceWriter* writer, int16_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_sized_i16(umilib_bytes_SliceWriter* writer, int16_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_i32(umilib_bytes_SliceWriter* writer, int32_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_i32(umilib_bytes_SliceWriter* writer, int32_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_sized_i32(umilib_bytes_SliceWriter* writer, int32_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_sized_i32(umilib_bytes_SliceWriter* writer, int32_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_i64(umilib_bytes_SliceWriter* writer, int64_t value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_i64(umilib_bytes_SliceWriter* writer, int64_t value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_sized_i64(umilib_bytes_SliceWriter* writer, int64_t value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_sized_i64(umilib_bytes_SliceWriter* writer, int64_t value, size_t length);

/**
 * Appends `value` as big-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_i128(umilib_bytes_SliceWriter* writer, umilib_ffi_I128 value);

/**
 * Appends `value` as little-endian bytes of the full size of the type.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_i128(umilib_bytes_SliceWriter* writer, umilib_ffi_I128 value);

/**
 * Appends `value` as `length` big-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_be_sized_i128(umilib_bytes_SliceWriter* writer, umilib_ffi_I128 value, size_t length);

/**
 * Appends `value` as `length` little-endian bytes; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_bytes_slice_writer_write_le_sized_i128(umilib_bytes_SliceWriter* writer, umilib_ffi_I128 value, size_t length);

#ifdef __cplusplus
}
#endif

#endif
