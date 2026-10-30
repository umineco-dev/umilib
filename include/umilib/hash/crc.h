/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_HASH_CRC_H
#define UMILIB_HASH_CRC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The parameters of a CRC in the Rocksoft model, with 128-bit values.
 */
typedef struct umilib_hash_crc_CRCParameters {
    uint32_t width;
    umilib_ffi_U128 polynomial;
    umilib_ffi_U128 initial;
    bool reflect_input;
    bool reflect_output;
    umilib_ffi_U128 xor_output;
    umilib_ffi_U128 check;
    umilib_ffi_U128 residue;
} umilib_hash_crc_CRCParameters;

/**
 * The parameters of a CRC and its table, with any register size.
 */
typedef struct umilib_hash_crc_CRCTable umilib_hash_crc_CRCTable;

/**
 * A CRC computation over its own copy of a table.
 */
typedef struct umilib_hash_crc_CRC umilib_hash_crc_CRC;

/**
 * Creates the table of `parameters`; fails unless the width is 1 to 128 and every value fits it.
 * The table has an empty name.
 */
const umilib_ffi_Status* umilib_hash_crc_crc_table_new(const umilib_hash_crc_CRCParameters* parameters, umilib_hash_crc_CRCTable** out);

/**
 * Creates a copy of the catalogue table named by the UTF-8 text at `name`, such as
 * `CRC-32/ISO-HDLC`; fails with InvalidArgument if there is none.
 */
const umilib_ffi_Status* umilib_hash_crc_crc_catalogue_find(const uint8_t* name, size_t length, umilib_hash_crc_CRCTable** out);

/**
 * Writes the names of the catalogue, each followed by a line feed, into `out`.
 */
const umilib_ffi_Status* umilib_hash_crc_crc_catalogue_names(umilib_ffi_Buffer* out);

/**
 * Releases a table. Does nothing if `table` is null.
 */
void umilib_hash_crc_crc_table_free(umilib_hash_crc_CRCTable* table);

/**
 * Writes a copy of `table` into `out`.
 */
const umilib_ffi_Status* umilib_hash_crc_crc_table_clone(const umilib_hash_crc_CRCTable* table, umilib_hash_crc_CRCTable** out);

/**
 * Writes the parameters of `table` into `out`.
 */
const umilib_ffi_Status* umilib_hash_crc_crc_table_parameters(const umilib_hash_crc_CRCTable* table, umilib_hash_crc_CRCParameters* out);

/**
 * Writes the name of `table` as UTF-8 into `out`; empty for a table not from the catalogue.
 */
const umilib_ffi_Status* umilib_hash_crc_crc_table_name(const umilib_hash_crc_CRCTable* table, umilib_ffi_Buffer* out);

/**
 * Creates a computation over a copy of `table`, which may be released afterwards.
 */
const umilib_ffi_Status* umilib_hash_crc_crc_new(const umilib_hash_crc_CRCTable* table, umilib_hash_crc_CRC** out);

/**
 * Writes the CRC of the `length` bytes at `data` with `table` into `out`.
 */
const umilib_ffi_Status* umilib_hash_crc_crc_checksum(const umilib_hash_crc_CRCTable* table, const uint8_t* data, size_t length, umilib_ffi_U128* out);

/**
 * Releases a computation. Does nothing if `state` is null.
 */
void umilib_hash_crc_crc_free(umilib_hash_crc_CRC* state);

/**
 * Writes a copy of `state`, over the same table, into `out`.
 */
const umilib_ffi_Status* umilib_hash_crc_crc_clone(const umilib_hash_crc_CRC* state, umilib_hash_crc_CRC** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_crc_crc_update(umilib_hash_crc_CRC* state, const uint8_t* data, size_t length);

/**
 * Writes the CRC of the input so far into `out`.
 */
const umilib_ffi_Status* umilib_hash_crc_crc_value(const umilib_hash_crc_CRC* state, umilib_ffi_U128* out);

/**
 * Writes the CRC of the input so far before the final xor into `out`: after an error-free
 * codeword, the residue of the parameters.
 */
const umilib_ffi_Status* umilib_hash_crc_crc_remainder(const umilib_hash_crc_CRC* state, umilib_ffi_U128* out);

/**
 * Returns to the empty input.
 */
const umilib_ffi_Status* umilib_hash_crc_crc_reset(umilib_hash_crc_CRC* state);

#ifdef __cplusplus
}
#endif

#endif
