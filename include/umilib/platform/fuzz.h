/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PLATFORM_FUZZ_H
#define UMILIB_PLATFORM_FUZZ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A target under test; returns true if the input passed and false if it failed.
 */
typedef bool (*umilib_platform_fuzz_Target)(void* context, const uint8_t* data, size_t length);

/**
 * How inputs are generated and when fuzzing stops.
 */
typedef struct umilib_platform_fuzz_FuzzConfig umilib_platform_fuzz_FuzzConfig;

/**
 * Runs targets with the built-in mutation engine.
 */
typedef struct umilib_platform_fuzz_Fuzzer umilib_platform_fuzz_Fuzzer;

/**
 * The outcome of a fuzzing or replay run.
 */
typedef struct umilib_platform_fuzz_FuzzReport umilib_platform_fuzz_FuzzReport;

/**
 * A deterministic generator of input mutations.
 */
typedef struct umilib_platform_fuzz_Mutator umilib_platform_fuzz_Mutator;

/**
 * A set of inputs stored as files in a directory.
 */
typedef struct umilib_platform_fuzz_Corpus umilib_platform_fuzz_Corpus;

/**
 * Parsed command-line arguments of a fuzzing program.
 */
typedef struct umilib_platform_fuzz_FuzzArguments umilib_platform_fuzz_FuzzArguments;

/**
 * Creates the default configuration.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_new(umilib_platform_fuzz_FuzzConfig** out);

/**
 * Releases a configuration. Does nothing if `config` is null.
 */
void umilib_platform_fuzz_fuzz_config_free(umilib_platform_fuzz_FuzzConfig* config);

/**
 * Sets the seed of the mutation engine.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_set_seed(umilib_platform_fuzz_FuzzConfig* config, uint64_t seed);

/**
 * Sets the maximum length of a generated input.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_set_maximum_length(umilib_platform_fuzz_FuzzConfig* config, size_t maximum_length);

/**
 * Sets the number of inputs in memory below which generated inputs are kept as material for mutations.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_set_maximum_corpus_inputs(umilib_platform_fuzz_FuzzConfig* config, size_t maximum_corpus_inputs);

/**
 * Keeps about one generated input in `sample_interval` in memory; 0 keeps none.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_set_sample_interval(umilib_platform_fuzz_FuzzConfig* config, size_t sample_interval);

/**
 * Stops after `iterations` inputs if `has_iterations` is true, or removes the limit.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_set_iterations(umilib_platform_fuzz_FuzzConfig* config, bool has_iterations, uint64_t iterations);

/**
 * Stops after `nanoseconds` if `has_duration` is true, or removes the limit.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_set_duration(umilib_platform_fuzz_FuzzConfig* config, bool has_duration, uint64_t nanoseconds);

/**
 * Creates a fuzzer with a copy of `config`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzzer_new(const umilib_platform_fuzz_FuzzConfig* config, umilib_platform_fuzz_Fuzzer** out);

/**
 * Releases a fuzzer. Does nothing if `fuzzer` is null.
 */
void umilib_platform_fuzz_fuzzer_free(umilib_platform_fuzz_Fuzzer* fuzzer);

/**
 * Fuzzes `target`, called with `context`, under the UTF-8 `name`, and writes a new report into `out`.
 * Fails with the `IO` status of `platform.fuzz` if a directory cannot be used.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzzer_run(const umilib_platform_fuzz_Fuzzer* fuzzer, const uint8_t* name, size_t name_length, umilib_platform_fuzz_Target target, void* context, umilib_platform_fuzz_FuzzReport** out);

/**
 * Runs `target` on every input in the configured corpus directory and writes a new report into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzzer_replay(const umilib_platform_fuzz_Fuzzer* fuzzer, const uint8_t* name, size_t name_length, umilib_platform_fuzz_Target target, void* context, umilib_platform_fuzz_FuzzReport** out);

/**
 * Writes the seed into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_seed(const umilib_platform_fuzz_FuzzConfig* config, uint64_t* out);

/**
 * Writes the maximum length of a generated input into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_maximum_length(const umilib_platform_fuzz_FuzzConfig* config, size_t* out);

/**
 * Writes the number of inputs in memory below which generated inputs are kept into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_maximum_corpus_inputs(const umilib_platform_fuzz_FuzzConfig* config, size_t* out);

/**
 * Writes the interval of the generated inputs kept in memory into `out` (0 keeps none).
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_sample_interval(const umilib_platform_fuzz_FuzzConfig* config, size_t* out);

/**
 * Writes a copy of the configuration of `fuzzer` into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzzer_config(const umilib_platform_fuzz_Fuzzer* fuzzer, umilib_platform_fuzz_FuzzConfig** out);

/**
 * Runs `target` on `length` bytes at `input` and writes whether it passed into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzzer_check(const uint8_t* name, size_t name_length, umilib_platform_fuzz_Target target, void* context, const uint8_t* input, size_t length, bool* out);

/**
 * Writes whether the UTF-8 `name` can name a fuzz target directory into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzzer_is_valid_name(const uint8_t* name, size_t name_length, bool* out);

/**
 * Creates a mutator from a seed.
 */
const umilib_ffi_Status* umilib_platform_fuzz_mutator_new(uint64_t seed, umilib_platform_fuzz_Mutator** out);

/**
 * Releases a mutator. Does nothing if `mutator` is null.
 */
void umilib_platform_fuzz_mutator_free(umilib_platform_fuzz_Mutator* mutator);

/**
 * Writes the next pseudo-random 64-bit value into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_mutator_next_u64(umilib_platform_fuzz_Mutator* mutator, uint64_t* out);

/**
 * Writes a pseudo-random value in `0..bound` into `out`; `bound` must not be zero.
 */
const umilib_ffi_Status* umilib_platform_fuzz_mutator_below(umilib_platform_fuzz_Mutator* mutator, size_t bound, size_t* out);

/**
 * Mutates a copy of `length` bytes at `data`, keeping it at most `maximum_length` bytes long,
 * splicing from the `count` corpus inputs, and writes the result into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_mutator_mutate(umilib_platform_fuzz_Mutator* mutator, const uint8_t* data, size_t length, size_t maximum_length, const uint8_t* const* inputs, const size_t* lengths, size_t count, umilib_ffi_Buffer* out);

/**
 * Reads every file in the UTF-8 `directory` into a new corpus written into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_corpus_load(const uint8_t* directory, size_t directory_length, umilib_platform_fuzz_Corpus** out);

/**
 * Creates an empty corpus.
 */
const umilib_ffi_Status* umilib_platform_fuzz_corpus_new(umilib_platform_fuzz_Corpus** out);

/**
 * Releases a corpus. Does nothing if `corpus` is null.
 */
void umilib_platform_fuzz_corpus_free(umilib_platform_fuzz_Corpus* corpus);

/**
 * Writes the number of inputs into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_corpus_input_count(const umilib_platform_fuzz_Corpus* corpus, size_t* out);

/**
 * Writes a copy of the input at `index` into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_corpus_inputs(const umilib_platform_fuzz_Corpus* corpus, size_t index, umilib_ffi_Buffer* out);

/**
 * Appends a copy of `length` bytes at `data` to the inputs.
 */
const umilib_ffi_Status* umilib_platform_fuzz_corpus_push_input(umilib_platform_fuzz_Corpus* corpus, const uint8_t* data, size_t length);

/**
 * Writes the file name of an input, a hash of its contents, into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_corpus_file_name(const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes `length` bytes at `data` into the UTF-8 `directory`, creating it if needed,
 * and writes the file path as UTF-8 into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_corpus_save(const uint8_t* directory, size_t directory_length, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Runs `target` on every input of `corpus` and writes a new report into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzzer_replay_corpus(const umilib_platform_fuzz_Fuzzer* fuzzer, const uint8_t* name, size_t name_length, umilib_platform_fuzz_Target target, void* context, const umilib_platform_fuzz_Corpus* corpus, umilib_platform_fuzz_FuzzReport** out);

/**
 * Parses `count` NUL-terminated UTF-8 command-line arguments, without the program name, into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_arguments_parse(const char* const* arguments, size_t count, umilib_platform_fuzz_FuzzArguments** out);

/**
 * Releases parsed arguments. Does nothing if `arguments` is null.
 */
void umilib_platform_fuzz_fuzz_arguments_free(umilib_platform_fuzz_FuzzArguments* arguments);

/**
 * Writes the engine (0 built-in, 1 libFuzzer) into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_arguments_engine(const umilib_platform_fuzz_FuzzArguments* arguments, uint8_t* out);

/**
 * Writes the number of arguments given after `--` into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_arguments_engine_argument_count(const umilib_platform_fuzz_FuzzArguments* arguments, size_t* out);

/**
 * Writes the argument given after `--` at `index`, as UTF-8, into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_arguments_engine_arguments(const umilib_platform_fuzz_FuzzArguments* arguments, size_t index, umilib_ffi_Buffer* out);

/**
 * Writes the number of failing inputs that were saved into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_report_saved_count(const umilib_platform_fuzz_FuzzReport* report, size_t* out);

/**
 * Writes the path, as UTF-8, of the saved failing input at `index` into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_report_saved(const umilib_platform_fuzz_FuzzReport* report, size_t index, umilib_ffi_Buffer* out);

/**
 * Writes whether `--list` was given into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_arguments_list(const umilib_platform_fuzz_FuzzArguments* arguments, bool* out);

/**
 * Writes the number of `--skip` texts into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_arguments_skip_count(const umilib_platform_fuzz_FuzzArguments* arguments, size_t* out);

/**
 * Writes the `--skip` text at `index`, as UTF-8, into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_arguments_skip(const umilib_platform_fuzz_FuzzArguments* arguments, size_t index, umilib_ffi_Buffer* out);

/**
 * Releases a report. Does nothing if `report` is null.
 */
void umilib_platform_fuzz_fuzz_report_free(umilib_platform_fuzz_FuzzReport* report);

/**
 * Writes the number of inputs run into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_report_iterations(const umilib_platform_fuzz_FuzzReport* report, uint64_t* out);

/**
 * Writes the elapsed time in nanoseconds into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_report_elapsed(const umilib_platform_fuzz_FuzzReport* report, uint64_t* out);

/**
 * Writes the number of failing inputs into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_report_failure_count(const umilib_platform_fuzz_FuzzReport* report, size_t* out);

/**
 * Writes a copy of the failing input at `index` into `out`.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_report_failure(const umilib_platform_fuzz_FuzzReport* report, size_t index, umilib_ffi_Buffer* out);

/**
 * Sets the UTF-8 path of the corpus directory; a null `path` removes it.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_set_corpus(umilib_platform_fuzz_FuzzConfig* config, const uint8_t* path, size_t path_length);

/**
 * Sets the UTF-8 path of the crash directory; a null `path` removes it.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_set_crashes(umilib_platform_fuzz_FuzzConfig* config, const uint8_t* path, size_t path_length);

/**
 * Writes whether an iteration limit is set and the limit.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_iterations(const umilib_platform_fuzz_FuzzConfig* handle, bool* out_has_value, uint64_t* out_value);

/**
 * Writes whether a time limit is set and the limit in nanoseconds.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_duration(const umilib_platform_fuzz_FuzzConfig* handle, bool* out_has_value, uint64_t* out_value);

/**
 * Writes whether a corpus directory is set and its path as UTF-8.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_corpus(const umilib_platform_fuzz_FuzzConfig* handle, bool* out_has_value, umilib_ffi_Buffer* out_value);

/**
 * Writes whether a crash directory is set and its path as UTF-8.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_config_crashes(const umilib_platform_fuzz_FuzzConfig* handle, bool* out_has_value, umilib_ffi_Buffer* out_value);

/**
 * Writes whether a filter was given and the filter as UTF-8.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_arguments_filter(const umilib_platform_fuzz_FuzzArguments* handle, bool* out_has_value, umilib_ffi_Buffer* out_value);

/**
 * Writes whether `--fuzz` was given and the target name as UTF-8.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_arguments_fuzz(const umilib_platform_fuzz_FuzzArguments* handle, bool* out_has_value, umilib_ffi_Buffer* out_value);

/**
 * Writes whether `--time` was given and the time in nanoseconds.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_arguments_duration(const umilib_platform_fuzz_FuzzArguments* handle, bool* out_has_value, uint64_t* out_value);

/**
 * Writes whether `--iterations` was given and the count.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_arguments_iterations(const umilib_platform_fuzz_FuzzArguments* handle, bool* out_has_value, uint64_t* out_value);

/**
 * Writes whether `--seed` was given and the seed.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_arguments_seed(const umilib_platform_fuzz_FuzzArguments* handle, bool* out_has_value, uint64_t* out_value);

/**
 * Writes whether `--maximum-length` was given and the length.
 */
const umilib_ffi_Status* umilib_platform_fuzz_fuzz_arguments_maximum_length(const umilib_platform_fuzz_FuzzArguments* handle, bool* out_has_value, size_t* out_value);

#ifdef __cplusplus
}
#endif

#endif
