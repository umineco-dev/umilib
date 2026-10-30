/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PLATFORM_BENCH_H
#define UMILIB_PLATFORM_BENCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A routine to measure, called with the context given to umilib_platform_bench_bench_run.
 */
typedef void (*umilib_platform_bench_Routine)(void* context);

/**
 * How long and how often each routine is measured.
 */
typedef struct umilib_platform_bench_BenchConfig umilib_platform_bench_BenchConfig;

/**
 * Runs routines and collects their results.
 */
typedef struct umilib_platform_bench_Bench umilib_platform_bench_Bench;

/**
 * The measurement of one routine.
 */
typedef struct umilib_platform_bench_BenchResult umilib_platform_bench_BenchResult;

/**
 * Parsed command-line arguments of a benchmark program.
 */
typedef struct umilib_platform_bench_BenchArguments umilib_platform_bench_BenchArguments;

/**
 * A summary of samples, in nanoseconds per iteration.
 */
typedef struct umilib_platform_bench_Statistics {
    double mean;
    double median;
    double median_absolute_deviation;
    double standard_deviation;
    double minimum;
    double maximum;
} umilib_platform_bench_Statistics;

/**
 * Creates the default configuration.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_config_new(umilib_platform_bench_BenchConfig** out);

/**
 * Creates the short configuration for checking that benchmarks run.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_config_quick(umilib_platform_bench_BenchConfig** out);

/**
 * Releases a configuration. Does nothing if `config` is null.
 */
void umilib_platform_bench_bench_config_free(umilib_platform_bench_BenchConfig* config);

/**
 * Writes the warm-up time in nanoseconds into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_config_warmup(const umilib_platform_bench_BenchConfig* config, uint64_t* out);

/**
 * Sets the warm-up time in nanoseconds.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_config_set_warmup(umilib_platform_bench_BenchConfig* config, uint64_t nanoseconds);

/**
 * Writes the total measurement time in nanoseconds into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_config_measurement(const umilib_platform_bench_BenchConfig* config, uint64_t* out);

/**
 * Sets the total measurement time in nanoseconds.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_config_set_measurement(umilib_platform_bench_BenchConfig* config, uint64_t nanoseconds);

/**
 * Writes the number of samples into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_config_samples(const umilib_platform_bench_BenchConfig* config, size_t* out);

/**
 * Sets the number of samples; values outside 1 to 1000000 are clamped when measuring.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_config_set_samples(umilib_platform_bench_BenchConfig* config, size_t samples);

/**
 * Creates a bench that measures with a copy of `config`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_new(const umilib_platform_bench_BenchConfig* config, umilib_platform_bench_Bench** out);

/**
 * Releases a bench. Does nothing if `bench` is null.
 */
void umilib_platform_bench_bench_free(umilib_platform_bench_Bench* bench);

/**
 * Runs only routines whose name contains the UTF-8 `filter`; a null `filter` removes the filter.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_set_filter(umilib_platform_bench_Bench* bench, const uint8_t* filter, size_t filter_length);

/**
 * Measures `routine`, called with `context`, under the UTF-8 `name`.
 * Writes a new result into `out`, or null if the filter excludes the routine.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_run(umilib_platform_bench_Bench* bench, const uint8_t* name, size_t name_length, uint8_t throughput_kind, uint64_t throughput_amount, umilib_platform_bench_Routine routine, void* context, umilib_platform_bench_BenchResult** out);

/**
 * Writes every result as text into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_report_text(const umilib_platform_bench_Bench* bench, umilib_ffi_Buffer* out);

/**
 * Writes every result as JSON into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_report_json(const umilib_platform_bench_Bench* bench, umilib_ffi_Buffer* out);

/**
 * Releases a result. Does nothing if `result` is null.
 */
void umilib_platform_bench_bench_result_free(umilib_platform_bench_BenchResult* result);

/**
 * Writes the name of the routine, as UTF-8, into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_result_name(const umilib_platform_bench_BenchResult* result, umilib_ffi_Buffer* out);

/**
 * Writes the work per second at the median duration into `out`, or 0 if there is no throughput.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_result_throughput_per_second(const umilib_platform_bench_BenchResult* result, double* out);

/**
 * Writes a copy of the configuration of `bench` into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_config(const umilib_platform_bench_Bench* bench, umilib_platform_bench_BenchConfig** out);

/**
 * Writes the number of results measured so far into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_result_count(const umilib_platform_bench_Bench* bench, size_t* out);

/**
 * Writes a copy of the result at `index` into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_results(const umilib_platform_bench_Bench* bench, size_t index, umilib_platform_bench_BenchResult** out);

/**
 * Writes `nanoseconds` formatted with a readable unit, as UTF-8, into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_format_duration(double nanoseconds, umilib_ffi_Buffer* out);

/**
 * Writes `result` formatted as a line of text into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_format_result(const umilib_platform_bench_BenchResult* result, umilib_ffi_Buffer* out);

/**
 * Writes the statistics of `result` into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_result_statistics(const umilib_platform_bench_BenchResult* result, umilib_platform_bench_Statistics* out);

/**
 * Summarizes the `count` samples at `samples`, which are reordered, into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_statistics_from_samples(double* samples, size_t count, umilib_platform_bench_Statistics* out);

/**
 * Writes the median of the `count` sorted values at `values` into `out`; `count` must not be zero.
 */
const umilib_ffi_Status* umilib_platform_bench_statistics_median_of_sorted(const double* values, size_t count, double* out);

/**
 * Parses `count` NUL-terminated UTF-8 command-line arguments, without the program name, into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_arguments_parse(const char* const* arguments, size_t count, umilib_platform_bench_BenchArguments** out);

/**
 * Releases parsed arguments. Does nothing if `arguments` is null.
 */
void umilib_platform_bench_bench_arguments_free(umilib_platform_bench_BenchArguments* arguments);

/**
 * Writes whether `--quick` was given into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_arguments_quick(const umilib_platform_bench_BenchArguments* arguments, bool* out);

/**
 * Writes whether a JSON path was given into `out_has_json` and the path, as UTF-8, into `out_json`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_arguments_json(const umilib_platform_bench_BenchArguments* arguments, bool* out_has_json, umilib_ffi_Buffer* out_json);

/**
 * Writes whether a filter was given into `out_has_filter` and the filter, as UTF-8, into `out_filter`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_arguments_filter(const umilib_platform_bench_BenchArguments* arguments, bool* out_has_filter, umilib_ffi_Buffer* out_filter);

/**
 * Writes the iterations run in each sample into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_result_iterations(const umilib_platform_bench_BenchResult* result, uint64_t* out);

/**
 * Writes the number of samples into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_result_samples(const umilib_platform_bench_BenchResult* result, size_t* out);

/**
 * Writes the throughput kind (0 none, 1 bytes, 2 elements) into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_result_throughput_kind(const umilib_platform_bench_BenchResult* result, uint8_t* out);

/**
 * Writes the throughput amount per iteration into `out`.
 */
const umilib_ffi_Status* umilib_platform_bench_bench_result_throughput_amount(const umilib_platform_bench_BenchResult* result, uint64_t* out);

#ifdef __cplusplus
}
#endif

#endif
