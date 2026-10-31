//! The C ABI of [`crate::platform::fuzz`].
//!
//! A C target is a [`Target`] callback that returns `true` when the input
//! passed and `false` when it failed; a failure is treated like a panic of a
//! Rust [`FuzzTarget`]. Durations are in nanoseconds.

use core::ffi::c_void;
use core::time::Duration;
use std::path::PathBuf;
use std::string::String;

use std::path::Path;
use std::vec::Vec;

use crate::ffi::{Buffer as FFIBuffer, Char, Definition, Module, Parameter, Pointer, Status, Type, Value};
use crate::platform::fuzz::{Corpus, FuzzArguments, FuzzConfig, FuzzEngine, FuzzReport, FuzzTarget, Fuzzer, Mutator};

/// A target under test: `bool target(void* context, const uint8_t* data, size_t length)`.
pub type Target = Option<unsafe extern "C" fn(context: *mut c_void, data: *const u8, length: usize) -> bool>;

impl Value for Target {
    const TYPE: Type = Type::Named("umilib_platform_fuzz_Target");
}

impl Value for Fuzzer {
    const TYPE: Type = Type::Named("umilib_platform_fuzz_Fuzzer");
}

impl Value for FuzzConfig {
    const TYPE: Type = Type::Named("umilib_platform_fuzz_FuzzConfig");
}

impl Value for FuzzReport {
    const TYPE: Type = Type::Named("umilib_platform_fuzz_FuzzReport");
}

impl Value for Mutator {
    const TYPE: Type = Type::Named("umilib_platform_fuzz_Mutator");
}

impl Value for Corpus {
    const TYPE: Type = Type::Named("umilib_platform_fuzz_Corpus");
}

impl Value for FuzzArguments {
    const TYPE: Type = Type::Named("umilib_platform_fuzz_FuzzArguments");
}

/// The [`FuzzEngine`] values of the C ABI.
pub struct FuzzEngineKind;

impl FuzzEngineKind {
    pub const BUILTIN: u8 = 0;
    pub const LIB_FUZZER: u8 = 1;

    /// Converts an engine into its C value.
    pub fn encode(engine: FuzzEngine) -> u8 {
        match engine {
            FuzzEngine::Builtin => FuzzEngineKind::BUILTIN,
            FuzzEngine::LibFuzzer => FuzzEngineKind::LIB_FUZZER,
        }
    }
}

/// Defines a function that writes an optional field of a [`FuzzArguments`] or [`FuzzConfig`] into two outputs.
macro_rules! optional_getters {
    ($($name:ident($handle:ty): $type:ty = |$value:ident| $read:expr, $documentation:literal;)*) => {
        crate::ffi_functions! {
            const OPTIONAL;
            $(
                #[doc = $documentation]
                pub unsafe extern "C" fn $name(handle: *const $handle, out_has_value: *mut bool, out_value: *mut $type) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle and writable pointers.
                        let $value = unsafe { Pointer::reference(handle) }?;
                        let read: Option<$type> = $read;
                        // Checks both outputs (null, overlap) before writing either.
                        unsafe { Pointer::write_optional(read, out_has_value, out_value) }
                    })())
                }
            )*
        }
    };
}

optional_getters! {
    umilib_platform_fuzz_fuzz_config_iterations(FuzzConfig): u64 = |config| config.iterations, " Writes whether an iteration limit is set and the limit.";
    umilib_platform_fuzz_fuzz_config_duration(FuzzConfig): u64 = |config| config.duration.map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64), " Writes whether a time limit is set and the limit in nanoseconds.";
    umilib_platform_fuzz_fuzz_config_corpus(FuzzConfig): FFIBuffer = |config| config.corpus.as_ref().map(|path| FFIBuffer::from_vec(path.to_string_lossy().into_owned().into_bytes())), " Writes whether a corpus directory is set and its path as UTF-8.";
    umilib_platform_fuzz_fuzz_config_crashes(FuzzConfig): FFIBuffer = |config| config.crashes.as_ref().map(|path| FFIBuffer::from_vec(path.to_string_lossy().into_owned().into_bytes())), " Writes whether a crash directory is set and its path as UTF-8.";
    umilib_platform_fuzz_fuzz_arguments_filter(FuzzArguments): FFIBuffer = |arguments| arguments.filter.clone().map(|text| FFIBuffer::from_vec(text.into_bytes())), " Writes whether a filter was given and the filter as UTF-8.";
    umilib_platform_fuzz_fuzz_arguments_fuzz(FuzzArguments): FFIBuffer = |arguments| arguments.fuzz.clone().map(|text| FFIBuffer::from_vec(text.into_bytes())), " Writes whether `--fuzz` was given and the target name as UTF-8.";
    umilib_platform_fuzz_fuzz_arguments_duration(FuzzArguments): u64 = |arguments| arguments.duration.map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64), " Writes whether `--time` was given and the time in nanoseconds.";
    umilib_platform_fuzz_fuzz_arguments_iterations(FuzzArguments): u64 = |arguments| arguments.iterations, " Writes whether `--iterations` was given and the count.";
    umilib_platform_fuzz_fuzz_arguments_seed(FuzzArguments): u64 = |arguments| arguments.seed, " Writes whether `--seed` was given and the seed.";
    umilib_platform_fuzz_fuzz_arguments_maximum_length(FuzzArguments): usize = |arguments| arguments.maximum_length, " Writes whether `--maximum-length` was given and the length.";
}

/// A [`FuzzTarget`] implemented by a C callback.
pub struct CallbackTarget {
    pub name: String,
    pub callback: unsafe extern "C" fn(context: *mut c_void, data: *const u8, length: usize) -> bool,
    pub context: *mut c_void,
}

// SAFETY: the fuzzer calls the target from the thread that started the run
// only; the C caller guarantees that the context may be used from that thread.
unsafe impl Sync for CallbackTarget {}

impl FuzzTarget for CallbackTarget {
    fn name(&self) -> &str {
        &self.name
    }

    fn run(&self, data: &[u8]) {
        // SAFETY: the C caller guarantees that `callback` may be called with
        // `context`; `data` is valid for the duration of the call.
        let passed = unsafe { (self.callback)(self.context, data.as_ptr(), data.len()) };
        assert!(passed, "the fuzz target reported a failure");
    }
}

impl CallbackTarget {
    /// Builds a target from C arguments.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn from_arguments(
        name: *const u8,
        name_length: usize,
        target: Target,
        context: *mut c_void,
    ) -> Result<CallbackTarget, &'static Status> {
        // SAFETY: guaranteed by the caller.
        let name = String::from(unsafe { Pointer::text(name, name_length) }?);
        let callback = target.ok_or(&Status::NULL_POINTER)?;
        Ok(CallbackTarget { name, callback, context })
    }
}

/// Defines functions that set an optional path of a [`FuzzConfig`].
macro_rules! config_paths {
    ($($name:ident: $field:ident, $documentation:literal;)*) => {
        crate::ffi_functions! {
            const PATHS;
            $(
                #[doc = $documentation]
                pub unsafe extern "C" fn $name(config: *mut FuzzConfig, path: *const u8, path_length: usize) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle and readable text.
                        let config = unsafe { Pointer::reference_mut(config) }?;
                        config.$field = if path.is_null() { None } else { Some(PathBuf::from(unsafe { Pointer::text(path, path_length) }?)) };
                        Ok(())
                    })())
                }
            )*
        }
    };
}

config_paths! {
    umilib_platform_fuzz_fuzz_config_set_corpus: corpus, " Sets the UTF-8 path of the corpus directory; a null `path` removes it.";
    umilib_platform_fuzz_fuzz_config_set_crashes: crashes, " Sets the UTF-8 path of the crash directory; a null `path` removes it.";
}

crate::ffi_functions! {
    const METHODS;

    /// Creates the default configuration.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_config_new(out: *mut *mut FuzzConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, FuzzConfig::default()) })
    }

    /// Releases a configuration. Does nothing if `config` is null.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_config_free(config: *mut FuzzConfig) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(config) }
    }

    /// Sets the seed of the mutation engine.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_config_set_seed(config: *mut FuzzConfig, seed: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(config) }?.seed = seed;
            Ok(())
        })())
    }

    /// Sets the maximum length of a generated input.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_config_set_maximum_length(config: *mut FuzzConfig, maximum_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(config) }?.maximum_length = maximum_length;
            Ok(())
        })())
    }

    /// Sets the number of inputs in memory below which generated inputs are kept as material for mutations.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_config_set_maximum_corpus_inputs(config: *mut FuzzConfig, maximum_corpus_inputs: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(config) }?.maximum_corpus_inputs = maximum_corpus_inputs;
            Ok(())
        })())
    }

    /// Keeps about one generated input in `sample_interval` in memory; 0 keeps none.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_config_set_sample_interval(config: *mut FuzzConfig, sample_interval: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(config) }?.sample_interval = sample_interval;
            Ok(())
        })())
    }

    /// Stops after `iterations` inputs if `has_iterations` is true, or removes the limit.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_config_set_iterations(config: *mut FuzzConfig, has_iterations: bool, iterations: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(config) }?.iterations = has_iterations.then_some(iterations);
            Ok(())
        })())
    }

    /// Stops after `nanoseconds` if `has_duration` is true, or removes the limit.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_config_set_duration(config: *mut FuzzConfig, has_duration: bool, nanoseconds: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(config) }?.duration = has_duration.then_some(Duration::from_nanos(nanoseconds));
            Ok(())
        })())
    }

    /// Creates a fuzzer with a copy of `config`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzzer_new(config: *const FuzzConfig, out: *mut *mut Fuzzer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            unsafe { Pointer::write_handle(out, Fuzzer::new(config.clone())) }
        })())
    }

    /// Releases a fuzzer. Does nothing if `fuzzer` is null.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzzer_free(fuzzer: *mut Fuzzer) {
        // SAFETY: the caller passes a handle from `umilib_platform_fuzz_fuzzer_new`.
        unsafe { Pointer::free(fuzzer) }
    }

    /// Fuzzes `target`, called with `context`, under the UTF-8 `name`, and writes a new report into `out`.
    /// Fails with the `IO` status of `platform.fuzz` if a directory cannot be used.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzzer_run(fuzzer: *const Fuzzer, name: *const u8, name_length: usize, target: Target, context: *mut c_void, out: *mut *mut FuzzReport) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text, a callable target and a writable pointer.
            let fuzzer = unsafe { Pointer::reference(fuzzer) }?;
            let target = unsafe { CallbackTarget::from_arguments(name, name_length, target, context) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let report = fuzzer.run(&target).map_err(|error| match error.kind() {
                std::io::ErrorKind::InvalidInput => &FuzzStatus::INVALID_NAME,
                _ => &FuzzStatus::IO,
            })?;
            unsafe { Pointer::write_handle(out, report) }
        })())
    }

    /// Runs `target` on every input in the configured corpus directory and writes a new report into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzzer_replay(fuzzer: *const Fuzzer, name: *const u8, name_length: usize, target: Target, context: *mut c_void, out: *mut *mut FuzzReport) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text, a callable target and a writable pointer.
            let fuzzer = unsafe { Pointer::reference(fuzzer) }?;
            let target = unsafe { CallbackTarget::from_arguments(name, name_length, target, context) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let corpus = match &fuzzer.config().corpus {
                Some(directory) => Corpus::load(directory).map_err(|_| &FuzzStatus::IO)?,
                None => Corpus::default(),
            };
            unsafe { Pointer::write_handle(out, fuzzer.replay(&target, &corpus)) }
        })())
    }

    /// Writes the seed into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_config_seed(config: *const FuzzConfig, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            unsafe { Pointer::write(out, config.seed) }
        })())
    }

    /// Writes the maximum length of a generated input into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_config_maximum_length(config: *const FuzzConfig, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            unsafe { Pointer::write(out, config.maximum_length) }
        })())
    }

    /// Writes the number of inputs in memory below which generated inputs are kept into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_config_maximum_corpus_inputs(config: *const FuzzConfig, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            unsafe { Pointer::write(out, config.maximum_corpus_inputs) }
        })())
    }

    /// Writes the interval of the generated inputs kept in memory into `out` (0 keeps none).
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_config_sample_interval(config: *const FuzzConfig, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            unsafe { Pointer::write(out, config.sample_interval) }
        })())
    }

    /// Writes a copy of the configuration of `fuzzer` into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzzer_config(fuzzer: *const Fuzzer, out: *mut *mut FuzzConfig) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let fuzzer = unsafe { Pointer::reference(fuzzer) }?;
            unsafe { Pointer::write_handle(out, fuzzer.config().clone()) }
        })())
    }

    /// Runs `target` on `length` bytes at `input` and writes whether it passed into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzzer_check(name: *const u8, name_length: usize, target: Target, context: *mut c_void, input: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes, a callable target and a writable pointer.
            let target = unsafe { CallbackTarget::from_arguments(name, name_length, target, context) }?;
            let input = unsafe { Pointer::slice(input, length) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write(out, Fuzzer::check(&target, input)) }
        })())
    }

    /// Writes whether the UTF-8 `name` can name a fuzz target directory into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzzer_is_valid_name(name: *const u8, name_length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let name = unsafe { Pointer::text(name, name_length) }?;
            unsafe { Pointer::write(out, Fuzzer::is_valid_name(name)) }
        })())
    }

    /// Creates a mutator from a seed.
    pub unsafe extern "C" fn umilib_platform_fuzz_mutator_new(seed: u64, out: *mut *mut Mutator) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, Mutator::new(seed)) })
    }

    /// Releases a mutator. Does nothing if `mutator` is null.
    pub unsafe extern "C" fn umilib_platform_fuzz_mutator_free(mutator: *mut Mutator) {
        // SAFETY: the caller passes a handle from `umilib_platform_fuzz_mutator_new`.
        unsafe { Pointer::free(mutator) }
    }

    /// Writes the next pseudo-random 64-bit value into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_mutator_next_u64(mutator: *mut Mutator, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let mutator = unsafe { Pointer::reference_mut(mutator) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write(out, mutator.next_u64()) }
        })())
    }

    /// Writes a pseudo-random value in `0..bound` into `out`; `bound` must not be zero.
    pub unsafe extern "C" fn umilib_platform_fuzz_mutator_below(mutator: *mut Mutator, bound: usize, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let mutator = unsafe { Pointer::reference_mut(mutator) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            if bound == 0 {
                return Err(&Status::INVALID_ARGUMENT);
            }
            unsafe { Pointer::write(out, mutator.below(bound)) }
        })())
    }

    /// Mutates a copy of `length` bytes at `data`, keeping it at most `maximum_length` bytes long,
    /// splicing from the `count` corpus inputs, and writes the result into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_mutator_mutate(mutator: *mut Mutator, data: *const u8, length: usize, maximum_length: usize, inputs: *const *const u8, lengths: *const usize, count: usize, out: *mut FFIBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and arrays, and a writable buffer.
            let mutator = unsafe { Pointer::reference_mut(mutator) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            let corpus: Vec<Vec<u8>> = unsafe { Pointer::slices(inputs, lengths, count) }?.into_iter().map(Vec::from).collect();
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let mut data = Vec::from(data);
            mutator.mutate(&mut data, maximum_length, &corpus);
            unsafe { Pointer::write(out, FFIBuffer::from_vec(data)) }
        })())
    }

    /// Reads every file in the UTF-8 `directory` into a new corpus written into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_corpus_load(directory: *const u8, directory_length: usize, out: *mut *mut Corpus) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let directory = unsafe { Pointer::text(directory, directory_length) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let corpus = Corpus::load(Path::new(directory)).map_err(|_| &FuzzStatus::IO)?;
            unsafe { Pointer::write_handle(out, corpus) }
        })())
    }

    /// Creates an empty corpus.
    pub unsafe extern "C" fn umilib_platform_fuzz_corpus_new(out: *mut *mut Corpus) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, Corpus::default()) })
    }

    /// Releases a corpus. Does nothing if `corpus` is null.
    pub unsafe extern "C" fn umilib_platform_fuzz_corpus_free(corpus: *mut Corpus) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(corpus) }
    }

    /// Writes the number of inputs into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_corpus_input_count(corpus: *const Corpus, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let corpus = unsafe { Pointer::reference(corpus) }?;
            unsafe { Pointer::write(out, corpus.inputs.len()) }
        })())
    }

    /// Writes a copy of the input at `index` into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_corpus_inputs(corpus: *const Corpus, index: usize, out: *mut FFIBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let corpus = unsafe { Pointer::reference(corpus) }?;
            let input = corpus.inputs.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, FFIBuffer::from_vec(input.clone())) }
        })())
    }

    /// Appends a copy of `length` bytes at `data` to the inputs.
    pub unsafe extern "C" fn umilib_platform_fuzz_corpus_push_input(corpus: *mut Corpus, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let corpus = unsafe { Pointer::reference_mut(corpus) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            corpus.inputs.push(Vec::from(data));
            Ok(())
        })())
    }

    /// Writes the file name of an input, a hash of its contents, into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_corpus_file_name(data: *const u8, length: usize, out: *mut FFIBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let data = unsafe { Pointer::slice(data, length) }?;
            unsafe { Pointer::write(out, FFIBuffer::from_vec(Corpus::file_name(data).into_bytes())) }
        })())
    }

    /// Writes `length` bytes at `data` into the UTF-8 `directory`, creating it if needed,
    /// and writes the file path as UTF-8 into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_corpus_save(directory: *const u8, directory_length: usize, data: *const u8, length: usize, out: *mut FFIBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable buffer.
            let directory = unsafe { Pointer::text(directory, directory_length) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let path = Corpus::save(Path::new(directory), data).map_err(|_| &FuzzStatus::IO)?;
            unsafe { Pointer::write(out, FFIBuffer::from_vec(path.to_string_lossy().into_owned().into_bytes())) }
        })())
    }

    /// Runs `target` on every input of `corpus` and writes a new report into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzzer_replay_corpus(fuzzer: *const Fuzzer, name: *const u8, name_length: usize, target: Target, context: *mut c_void, corpus: *const Corpus, out: *mut *mut FuzzReport) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, readable text, a callable target and a writable pointer.
            let fuzzer = unsafe { Pointer::reference(fuzzer) }?;
            let corpus = unsafe { Pointer::reference(corpus) }?;
            let target = unsafe { CallbackTarget::from_arguments(name, name_length, target, context) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write_handle(out, fuzzer.replay(&target, corpus)) }
        })())
    }

    /// Parses `count` NUL-terminated UTF-8 command-line arguments, without the program name, into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_arguments_parse(arguments: *const *const Char, count: usize, out: *mut *mut FuzzArguments) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes `count` NUL-terminated strings and a writable pointer.
            let arguments = unsafe { Pointer::strings(arguments, count) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let parsed = FuzzArguments::parse(arguments).map_err(|_| &FuzzStatus::INVALID_ARGUMENTS)?;
            unsafe { Pointer::write_handle(out, parsed) }
        })())
    }

    /// Releases parsed arguments. Does nothing if `arguments` is null.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_arguments_free(arguments: *mut FuzzArguments) {
        // SAFETY: the caller passes a handle from `umilib_platform_fuzz_fuzz_arguments_parse`.
        unsafe { Pointer::free(arguments) }
    }

    /// Writes the engine (0 built-in, 1 libFuzzer) into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_arguments_engine(arguments: *const FuzzArguments, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let arguments = unsafe { Pointer::reference(arguments) }?;
            unsafe { Pointer::write(out, FuzzEngineKind::encode(arguments.engine)) }
        })())
    }

    /// Writes the number of arguments given after `--` into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_arguments_engine_argument_count(arguments: *const FuzzArguments, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let arguments = unsafe { Pointer::reference(arguments) }?;
            unsafe { Pointer::write(out, arguments.engine_arguments.len()) }
        })())
    }

    /// Writes the argument given after `--` at `index`, as UTF-8, into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_arguments_engine_arguments(arguments: *const FuzzArguments, index: usize, out: *mut FFIBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let arguments = unsafe { Pointer::reference(arguments) }?;
            let argument = arguments.engine_arguments.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, FFIBuffer::from_vec(argument.clone().into_bytes())) }
        })())
    }

    /// Writes the number of failing inputs that were saved into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_report_saved_count(report: *const FuzzReport, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let report = unsafe { Pointer::reference(report) }?;
            unsafe { Pointer::write(out, report.saved.len()) }
        })())
    }

    /// Writes the path, as UTF-8, of the saved failing input at `index` into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_report_saved(report: *const FuzzReport, index: usize, out: *mut FFIBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let report = unsafe { Pointer::reference(report) }?;
            let path = report.saved.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, FFIBuffer::from_vec(path.to_string_lossy().into_owned().into_bytes())) }
        })())
    }

    /// Writes whether `--list` was given into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_arguments_list(arguments: *const FuzzArguments, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let arguments = unsafe { Pointer::reference(arguments) }?;
            unsafe { Pointer::write(out, arguments.list) }
        })())
    }

    /// Writes the number of `--skip` texts into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_arguments_skip_count(arguments: *const FuzzArguments, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let arguments = unsafe { Pointer::reference(arguments) }?;
            unsafe { Pointer::write(out, arguments.skip.len()) }
        })())
    }

    /// Writes the `--skip` text at `index`, as UTF-8, into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_arguments_skip(arguments: *const FuzzArguments, index: usize, out: *mut FFIBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let arguments = unsafe { Pointer::reference(arguments) }?;
            let skip = arguments.skip.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, FFIBuffer::from_vec(skip.clone().into_bytes())) }
        })())
    }

    /// Releases a report. Does nothing if `report` is null.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_report_free(report: *mut FuzzReport) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(report) }
    }

    /// Writes the number of inputs run into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_report_iterations(report: *const FuzzReport, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let report = unsafe { Pointer::reference(report) }?;
            unsafe { Pointer::write(out, report.iterations) }
        })())
    }

    /// Writes the elapsed time in nanoseconds into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_report_elapsed(report: *const FuzzReport, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let report = unsafe { Pointer::reference(report) }?;
            unsafe { Pointer::write(out, report.elapsed.as_nanos().min(u64::MAX as u128) as u64) }
        })())
    }

    /// Writes the number of failing inputs into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_report_failure_count(report: *const FuzzReport, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let report = unsafe { Pointer::reference(report) }?;
            unsafe { Pointer::write(out, report.failures.len()) }
        })())
    }

    /// Writes a copy of the failing input at `index` into `out`.
    pub unsafe extern "C" fn umilib_platform_fuzz_fuzz_report_failure(report: *const FuzzReport, index: usize, out: *mut FFIBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let report = unsafe { Pointer::reference(report) }?;
            let failure = report.failures.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, FFIBuffer::from_vec(failure.clone())) }
        })())
    }
}

/// The statuses of this module.
pub struct FuzzStatus;

impl FuzzStatus {
    /// Reading the corpus or writing a crash failed.
    pub const IO: Status = Status::new(c"platform.fuzz", c"IO", c"a corpus or crash directory could not be used");
    /// The target name cannot name a directory (see `Fuzzer::is_valid_name`).
    pub const INVALID_NAME: Status =
        Status::new(c"platform.fuzz", c"InvalidName", c"the fuzz target name is not valid");
    /// The command-line arguments are not valid.
    pub const INVALID_ARGUMENTS: Status =
        Status::new(c"platform.fuzz", c"InvalidArguments", c"the fuzzing arguments are not valid");
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "fuzz",
    definitions: &[
        Definition::Callback {
            name: "umilib_platform_fuzz_Target",
            documentation: " A target under test; returns true if the input passed and false if it failed.",
            parameters: &[
                Parameter { name: "context", value: <*mut c_void as Value>::TYPE },
                Parameter { name: "data", value: <*const u8 as Value>::TYPE },
                Parameter { name: "length", value: Type::USize },
            ],
            returns: Type::Bool,
        },
        Definition::Opaque {
            name: "umilib_platform_fuzz_FuzzConfig",
            documentation: " How inputs are generated and when fuzzing stops.",
        },
        Definition::Opaque {
            name: "umilib_platform_fuzz_Fuzzer",
            documentation: " Runs targets with the built-in mutation engine.",
        },
        Definition::Opaque {
            name: "umilib_platform_fuzz_FuzzReport",
            documentation: " The outcome of a fuzzing or replay run.",
        },
        Definition::Opaque {
            name: "umilib_platform_fuzz_Mutator",
            documentation: " A deterministic generator of input mutations.",
        },
        Definition::Opaque {
            name: "umilib_platform_fuzz_Corpus",
            documentation: " A set of inputs stored as files in a directory.",
        },
        Definition::Opaque {
            name: "umilib_platform_fuzz_FuzzArguments",
            documentation: " Parsed command-line arguments of a fuzzing program.",
        },
    ],
    functions: &crate::ffi::Function::concat::<{ METHODS.len() + PATHS.len() + OPTIONAL.len() }>(&[
        METHODS, PATHS, OPTIONAL,
    ]),
    modules: &[],
};
