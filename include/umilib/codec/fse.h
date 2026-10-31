/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_FSE_H
#define UMILIB_CODEC_FSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A normalized distribution of Finite State Entropy.
 */
typedef struct umilib_codec_fse_FSEDistribution umilib_codec_fse_FSEDistribution;

/**
 * The decoding table of a distribution of Finite State Entropy.
 */
typedef struct umilib_codec_fse_FSEDecodingTable umilib_codec_fse_FSEDecodingTable;

/**
 * The encoding table of a distribution of Finite State Entropy.
 */
typedef struct umilib_codec_fse_FSEEncodingTable umilib_codec_fse_FSEEncodingTable;

/**
 * Writes a new distribution of the `count` probabilities at `probabilities` (-1 for "less
 * than 1") on a scale of 2^`accuracy_log` into `out`.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_distribution_new(uint32_t accuracy_log, const int16_t* probabilities, size_t count, umilib_codec_fse_FSEDistribution** out);

/**
 * Reads a table description from the start of the `length` bytes at `data`, of an accuracy
 * log of at most `maximum_log` and at most `maximum_symbols` symbols: writes the new
 * distribution into `out` and the bytes it took into `used`.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_distribution_read(const uint8_t* data, size_t length, uint32_t maximum_log, size_t maximum_symbols, umilib_codec_fse_FSEDistribution** out, size_t* used);

/**
 * Writes a new distribution of the `count` symbol counts at `counts` on a scale of
 * 2^`accuracy_log` into `out`.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_distribution_normalize(const uint32_t* counts, size_t count, uint32_t accuracy_log, umilib_codec_fse_FSEDistribution** out);

/**
 * Releases a distribution. Does nothing if `distribution` is null.
 */
void umilib_codec_fse_fse_distribution_free(umilib_codec_fse_FSEDistribution* distribution);

/**
 * Writes the accuracy log of `distribution` into `out`.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_distribution_accuracy_log(const umilib_codec_fse_FSEDistribution* distribution, uint32_t* out);

/**
 * Writes the number of probabilities of `distribution` (the last present symbol plus 1) into `out`.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_distribution_symbols(const umilib_codec_fse_FSEDistribution* distribution, size_t* out);

/**
 * Writes the probability of `symbol` (-1 for "less than 1") into `out`.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_distribution_probability(const umilib_codec_fse_FSEDistribution* distribution, size_t symbol, int16_t* out);

/**
 * Writes the table description of `distribution` into `out`.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_distribution_write(const umilib_codec_fse_FSEDistribution* distribution, umilib_ffi_Buffer* out);

/**
 * Writes the symbol of each table position, one byte each, into `out`.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_distribution_spread(const umilib_codec_fse_FSEDistribution* distribution, umilib_ffi_Buffer* out);

/**
 * Writes a new decoding table of `distribution` into `out`.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_decoding_table_new(const umilib_codec_fse_FSEDistribution* distribution, umilib_codec_fse_FSEDecodingTable** out);

/**
 * Writes a new table of the single `symbol` (one state, no bits) into `out`.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_decoding_table_single(uint8_t symbol, umilib_codec_fse_FSEDecodingTable** out);

/**
 * Releases a table. Does nothing if `table` is null.
 */
void umilib_codec_fse_fse_decoding_table_free(umilib_codec_fse_FSEDecodingTable* table);

/**
 * Writes the accuracy log of `table` (the bits of the initial state) into `out`.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_decoding_table_accuracy_log(const umilib_codec_fse_FSEDecodingTable* table, uint32_t* out);

/**
 * Writes the entry of `state`: its symbol into `symbol`, and the bits to read and the
 * baseline to add to them for the next state into `bits` and `baseline`.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_decoding_table_entry(const umilib_codec_fse_FSEDecodingTable* table, size_t state, uint8_t* symbol, uint8_t* bits, uint16_t* baseline);

/**
 * Writes a new encoding table of `distribution` into `out`.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_encoding_table_new(const umilib_codec_fse_FSEDistribution* distribution, umilib_codec_fse_FSEEncodingTable** out);

/**
 * Releases a table. Does nothing if `table` is null.
 */
void umilib_codec_fse_fse_encoding_table_free(umilib_codec_fse_FSEEncodingTable* table);

/**
 * Writes the accuracy log of `table` (the bits of the final state) into `out`.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_encoding_table_accuracy_log(const umilib_codec_fse_FSEEncodingTable* table, uint32_t* out);

/**
 * Writes the first state, for `symbol` (the symbol decoded last), into `out`; fails with
 * `InvalidArgument` if `symbol` has no probability.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_encoding_table_initial_state(const umilib_codec_fse_FSEEncodingTable* table, size_t symbol, uint32_t* out);

/**
 * Writes the step from the encoder state `state` for `symbol`: the number of low bits of
 * `state` to write into `bits`, and the state before it into `previous`; fails with
 * `InvalidArgument` if `state` is not an encoder state or `symbol` has no probability.
 */
const umilib_ffi_Status* umilib_codec_fse_fse_encoding_table_transition(const umilib_codec_fse_FSEEncodingTable* table, uint32_t state, size_t symbol, uint32_t* bits, uint32_t* previous);

#ifdef __cplusplus
}
#endif

#endif
