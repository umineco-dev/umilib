//! The C ABI of [`crate::platform::bench`].
//!
//! [`Throughput`] is passed as a kind (`0` none, `1` bytes, `2` elements) and
//! an amount. Durations are in nanoseconds.

use core::ffi::c_void;
use core::time::Duration;
use std::string::String;

use crate::ffi::{Buffer as FFIBuffer, Char, Definition, Module, Parameter, Pointer, Status, Type, Value};
use crate::platform::bench::{Bench, BenchArguments, BenchConfig, BenchResult, Statistics, Throughput};

/// A routine to measure: `void routine(void* context)`.
pub type Routine = Option<unsafe extern "C" fn(context: *mut c_void)>;

impl Value for Routine {
    const TYPE: Type = Type::Named("umilib_platform_bench_Routine");
}

impl Value for Bench {
    const TYPE: Type = Type::Named("umilib_platform_bench_Bench");
}

impl Value for BenchConfig {
    const TYPE: Type = Type::Named("umilib_platform_bench_BenchConfig");
}

impl Value for BenchResult {
    const TYPE: Type = Type::Named("umilib_platform_bench_BenchResult");
}

impl Value for BenchArguments {
    const TYPE: Type = Type::Named("umilib_platform_bench_BenchArguments");
}

impl Value for Statistics {
    const TYPE: Type = Type::Named("umilib_platform_bench_Statistics");
}

/// The statuses of this module.
pub struct BenchStatus;

impl BenchStatus {
    /// The command-line arguments are not valid.
    pub const INVALID_ARGUMENTS: Status =
        Status::new(c"platform.bench", c"InvalidArguments", c"the benchmark arguments are not valid");
}

/// The throughput kinds of the C ABI.
pub struct ThroughputKind;

impl ThroughputKind {
    pub const NONE: u8 = 0;
    pub const BYTES: u8 = 1;
    pub const ELEMENTS: u8 = 2;

    /// Converts a kind and an amount into a throughput.
    pub fn decode(kind: u8, amount: u64) -> Result<Option<Throughput>, &'static Status> {
        match kind {
            ThroughputKind::NONE => Ok(None),
            ThroughputKind::BYTES => Ok(Some(Throughput::Bytes(amount))),
            ThroughputKind::ELEMENTS => Ok(Some(Throughput::Elements(amount))),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    /// Converts a throughput into a kind and an amount.
    pub fn encode(throughput: Option<Throughput>) -> (u8, u64) {
        match throughput {
            None => (ThroughputKind::NONE, 0),
            Some(Throughput::Bytes(amount)) => (ThroughputKind::BYTES, amount),
            Some(Throughput::Elements(amount)) => (ThroughputKind::ELEMENTS, amount),
        }
    }
}

/// Defines a function that writes one field of a [`BenchResult`] into `out`.
macro_rules! result_getters {
    ($($name:ident: $type:ty = |$result:ident| $value:expr, $documentation:literal;)*) => {
        crate::ffi_functions! {
            const RESULT;
            $(
                #[doc = $documentation]
                pub unsafe extern "C" fn $name(result: *const BenchResult, out: *mut $type) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle and a writable pointer.
                        let $result = unsafe { Pointer::reference(result) }?;
                        unsafe { Pointer::write(out, $value) }
                    })())
                }
            )*
        }
    };
}

result_getters! {
    umilib_platform_bench_bench_result_iterations: u64 = |result| result.iterations, " Writes the iterations run in each sample into `out`.";
    umilib_platform_bench_bench_result_samples: usize = |result| result.samples, " Writes the number of samples into `out`.";
    umilib_platform_bench_bench_result_throughput_kind: u8 = |result| ThroughputKind::encode(result.throughput).0, " Writes the throughput kind (0 none, 1 bytes, 2 elements) into `out`.";
    umilib_platform_bench_bench_result_throughput_amount: u64 = |result| ThroughputKind::encode(result.throughput).1, " Writes the throughput amount per iteration into `out`.";
}

crate::ffi_functions! {
    const METHODS;

    /// Creates the default configuration.
    pub unsafe extern "C" fn umilib_platform_bench_bench_config_new(out: *mut *mut BenchConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, BenchConfig::default()) })
    }

    /// Creates the short configuration for checking that benchmarks run.
    pub unsafe extern "C" fn umilib_platform_bench_bench_config_quick(out: *mut *mut BenchConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, BenchConfig::quick()) })
    }

    /// Releases a configuration. Does nothing if `config` is null.
    pub unsafe extern "C" fn umilib_platform_bench_bench_config_free(config: *mut BenchConfig) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(config) }
    }

    /// Writes the warm-up time in nanoseconds into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_config_warmup(config: *const BenchConfig, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            unsafe { Pointer::write(out, config.warmup.as_nanos().min(u64::MAX as u128) as u64) }
        })())
    }

    /// Sets the warm-up time in nanoseconds.
    pub unsafe extern "C" fn umilib_platform_bench_bench_config_set_warmup(config: *mut BenchConfig, nanoseconds: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(config) }?.warmup = Duration::from_nanos(nanoseconds);
            Ok(())
        })())
    }

    /// Writes the total measurement time in nanoseconds into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_config_measurement(config: *const BenchConfig, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            unsafe { Pointer::write(out, config.measurement.as_nanos().min(u64::MAX as u128) as u64) }
        })())
    }

    /// Sets the total measurement time in nanoseconds.
    pub unsafe extern "C" fn umilib_platform_bench_bench_config_set_measurement(config: *mut BenchConfig, nanoseconds: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(config) }?.measurement = Duration::from_nanos(nanoseconds);
            Ok(())
        })())
    }

    /// Writes the number of samples into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_config_samples(config: *const BenchConfig, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            unsafe { Pointer::write(out, config.samples) }
        })())
    }

    /// Sets the number of samples; values outside 1 to 1000000 are clamped when measuring.
    pub unsafe extern "C" fn umilib_platform_bench_bench_config_set_samples(config: *mut BenchConfig, samples: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(config) }?.samples = samples;
            Ok(())
        })())
    }

    /// Creates a bench that measures with a copy of `config`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_new(config: *const BenchConfig, out: *mut *mut Bench) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            unsafe { Pointer::write_handle(out, Bench::new(*config)) }
        })())
    }

    /// Releases a bench. Does nothing if `bench` is null.
    pub unsafe extern "C" fn umilib_platform_bench_bench_free(bench: *mut Bench) {
        // SAFETY: the caller passes a handle from `umilib_platform_bench_bench_new`.
        unsafe { Pointer::free(bench) }
    }

    /// Runs only routines whose name contains the UTF-8 `filter`; a null `filter` removes the filter.
    pub unsafe extern "C" fn umilib_platform_bench_bench_set_filter(bench: *mut Bench, filter: *const u8, filter_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let bench = unsafe { Pointer::reference_mut(bench) }?;
            let filter = if filter.is_null() { None } else { Some(String::from(unsafe { Pointer::text(filter, filter_length) }?)) };
            bench.set_filter(filter);
            Ok(())
        })())
    }

    /// Measures `routine`, called with `context`, under the UTF-8 `name`.
    /// Writes a new result into `out`, or null if the filter excludes the routine.
    pub unsafe extern "C" fn umilib_platform_bench_bench_run(bench: *mut Bench, name: *const u8, name_length: usize, throughput_kind: u8, throughput_amount: u64, routine: Routine, context: *mut c_void, out: *mut *mut BenchResult) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and a writable pointer.
            let bench = unsafe { Pointer::reference_mut(bench) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            let routine = routine.ok_or(&Status::NULL_POINTER)?;
            let throughput = ThroughputKind::decode(throughput_kind, throughput_amount)?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller guarantees that `routine` may be called with `context`.
            match bench.run(name, throughput, || unsafe { routine(context) }) {
                Some(result) => unsafe { Pointer::write_handle(out, result.clone()) },
                None => unsafe { Pointer::write(out, core::ptr::null_mut()) },
            }
        })())
    }

    /// Writes every result as text into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_report_text(bench: *const Bench, out: *mut FFIBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let bench = unsafe { Pointer::reference(bench) }?;
            unsafe { Pointer::write(out, FFIBuffer::from_vec(bench.report_text().into_bytes())) }
        })())
    }

    /// Writes every result as JSON into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_report_json(bench: *const Bench, out: *mut FFIBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let bench = unsafe { Pointer::reference(bench) }?;
            unsafe { Pointer::write(out, FFIBuffer::from_vec(bench.report_json().into_bytes())) }
        })())
    }

    /// Releases a result. Does nothing if `result` is null.
    pub unsafe extern "C" fn umilib_platform_bench_bench_result_free(result: *mut BenchResult) {
        // SAFETY: the caller passes a handle from `umilib_platform_bench_bench_run`.
        unsafe { Pointer::free(result) }
    }

    /// Writes the name of the routine, as UTF-8, into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_result_name(result: *const BenchResult, out: *mut FFIBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let result = unsafe { Pointer::reference(result) }?;
            unsafe { Pointer::write(out, FFIBuffer::from_vec(result.name.clone().into_bytes())) }
        })())
    }

    /// Writes the work per second at the median duration into `out`, or 0 if there is no throughput.
    pub unsafe extern "C" fn umilib_platform_bench_bench_result_throughput_per_second(result: *const BenchResult, out: *mut f64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let result = unsafe { Pointer::reference(result) }?;
            unsafe { Pointer::write(out, result.throughput_per_second().unwrap_or(0.0)) }
        })())
    }
    /// Writes a copy of the configuration of `bench` into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_config(bench: *const Bench, out: *mut *mut BenchConfig) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let bench = unsafe { Pointer::reference(bench) }?;
            unsafe { Pointer::write_handle(out, *bench.config()) }
        })())
    }

    /// Writes the number of results measured so far into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_result_count(bench: *const Bench, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let bench = unsafe { Pointer::reference(bench) }?;
            unsafe { Pointer::write(out, bench.results().len()) }
        })())
    }

    /// Writes a copy of the result at `index` into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_results(bench: *const Bench, index: usize, out: *mut *mut BenchResult) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let bench = unsafe { Pointer::reference(bench) }?;
            let result = bench.results().get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, result.clone()) }
        })())
    }

    /// Writes `nanoseconds` formatted with a readable unit, as UTF-8, into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_format_duration(nanoseconds: f64, out: *mut FFIBuffer) -> *const Status {
        // SAFETY: the caller passes a writable buffer.
        Status::from_result(unsafe { Pointer::write(out, FFIBuffer::from_vec(Bench::format_duration(nanoseconds).into_bytes())) })
    }

    /// Writes `result` formatted as a line of text into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_format_result(result: *const BenchResult, out: *mut FFIBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let result = unsafe { Pointer::reference(result) }?;
            unsafe { Pointer::write(out, FFIBuffer::from_vec(Bench::format_result(result).into_bytes())) }
        })())
    }

    /// Writes the statistics of `result` into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_result_statistics(result: *const BenchResult, out: *mut Statistics) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let result = unsafe { Pointer::reference(result) }?;
            unsafe { Pointer::write(out, result.statistics) }
        })())
    }

    /// Summarizes the `count` samples at `samples`, which are reordered, into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_statistics_from_samples(samples: *mut f64, count: usize, out: *mut Statistics) -> *const Status {
        Status::from_result((|| {
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes `count` writable samples and a writable pointer.
            let samples = unsafe { Pointer::slice_of_mut(samples, count) }?;
            let statistics = Statistics::from_samples(samples);
            unsafe { Pointer::write(out, statistics) }
        })())
    }

    /// Writes the median of the `count` sorted values at `values` into `out`; `count` must not be zero.
    pub unsafe extern "C" fn umilib_platform_bench_statistics_median_of_sorted(values: *const f64, count: usize, out: *mut f64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes `count` readable values and a writable pointer.
            let values = unsafe { Pointer::slice_of(values, count) }?;
            if values.is_empty() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            unsafe { Pointer::write(out, Statistics::median_of_sorted(values)) }
        })())
    }

    /// Parses `count` NUL-terminated UTF-8 command-line arguments, without the program name, into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_arguments_parse(arguments: *const *const Char, count: usize, out: *mut *mut BenchArguments) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes `count` NUL-terminated strings and a writable pointer.
            let arguments = unsafe { Pointer::strings(arguments, count) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let parsed = BenchArguments::parse(arguments).map_err(|_| &BenchStatus::INVALID_ARGUMENTS)?;
            unsafe { Pointer::write_handle(out, parsed) }
        })())
    }

    /// Releases parsed arguments. Does nothing if `arguments` is null.
    pub unsafe extern "C" fn umilib_platform_bench_bench_arguments_free(arguments: *mut BenchArguments) {
        // SAFETY: the caller passes a handle from `umilib_platform_bench_bench_arguments_parse`.
        unsafe { Pointer::free(arguments) }
    }

    /// Writes whether `--quick` was given into `out`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_arguments_quick(arguments: *const BenchArguments, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let arguments = unsafe { Pointer::reference(arguments) }?;
            unsafe { Pointer::write(out, arguments.quick) }
        })())
    }

    /// Writes whether a JSON path was given into `out_has_json` and the path, as UTF-8, into `out_json`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_arguments_json(arguments: *const BenchArguments, out_has_json: *mut bool, out_json: *mut FFIBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let arguments = unsafe { Pointer::reference(arguments) }?;
            if out_has_json.is_null() || out_json.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let json = arguments.json.as_ref().map(|path| path.to_string_lossy().into_owned());
            unsafe { Pointer::write(out_has_json, json.is_some()) }?;
            unsafe { Pointer::write(out_json, FFIBuffer::from_vec(json.unwrap_or_default().into_bytes())) }
        })())
    }

    /// Writes whether a filter was given into `out_has_filter` and the filter, as UTF-8, into `out_filter`.
    pub unsafe extern "C" fn umilib_platform_bench_bench_arguments_filter(arguments: *const BenchArguments, out_has_filter: *mut bool, out_filter: *mut FFIBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let arguments = unsafe { Pointer::reference(arguments) }?;
            if out_has_filter.is_null() || out_filter.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write(out_has_filter, arguments.filter.is_some()) }?;
            unsafe { Pointer::write(out_filter, FFIBuffer::from_vec(arguments.filter.clone().unwrap_or_default().into_bytes())) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "bench",
    definitions: &[
        Definition::Callback {
            name: "umilib_platform_bench_Routine",
            documentation: " A routine to measure, called with the context given to umilib_platform_bench_bench_run.",
            parameters: &[Parameter { name: "context", value: <*mut c_void as Value>::TYPE }],
            returns: Type::Void,
        },
        Definition::Opaque {
            name: "umilib_platform_bench_BenchConfig",
            documentation: " How long and how often each routine is measured.",
        },
        Definition::Opaque {
            name: "umilib_platform_bench_Bench",
            documentation: " Runs routines and collects their results.",
        },
        Definition::Opaque {
            name: "umilib_platform_bench_BenchResult",
            documentation: " The measurement of one routine.",
        },
        Definition::Opaque {
            name: "umilib_platform_bench_BenchArguments",
            documentation: " Parsed command-line arguments of a benchmark program.",
        },
        Definition::Structure {
            name: "umilib_platform_bench_Statistics",
            documentation: " A summary of samples, in nanoseconds per iteration.",
            fields: &[
                Parameter { name: "mean", value: Type::F64 },
                Parameter { name: "median", value: Type::F64 },
                Parameter { name: "median_absolute_deviation", value: Type::F64 },
                Parameter { name: "standard_deviation", value: Type::F64 },
                Parameter { name: "minimum", value: Type::F64 },
                Parameter { name: "maximum", value: Type::F64 },
            ],
        },
    ],
    functions: &crate::ffi::Function::concat::<{ METHODS.len() + RESULT.len() }>(&[METHODS, RESULT]),
    modules: &[],
};
