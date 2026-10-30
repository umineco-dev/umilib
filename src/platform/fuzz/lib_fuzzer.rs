use core::ffi::{c_char, c_int};
use std::ffi::CString;
use std::string::String;
use std::sync::OnceLock;
use std::vec::Vec;

use super::FuzzTarget;

unsafe extern "C" {
    /// The public entry point of libFuzzer when it is linked without its own `main`
    /// (`libclang_rt.fuzzer_no_main`).
    fn LLVMFuzzerRunDriver(
        argc: *mut c_int,
        argv: *mut *mut *mut c_char,
        callback: unsafe extern "C" fn(data: *const u8, size: usize) -> c_int,
    ) -> c_int;
}

/// Runs a [`FuzzTarget`] under LLVM libFuzzer. One target can run per process.
///
/// libFuzzer re-executes its program for some modes (`-merge`, `-fork`,
/// `-jobs`), passing only libFuzzer flags. A program that holds several
/// targets therefore starts the fuzzing process with
/// [`LibFuzzer::TARGET_VARIABLE`] set to the target name, and at start-up runs
/// [`LibFuzzer::requested_target`] under libFuzzer with its own arguments, so
/// that the processes libFuzzer starts run the same target.
pub struct LibFuzzer;

impl LibFuzzer {
    /// The environment variable naming the target a fuzzing process runs.
    pub const TARGET_VARIABLE: &'static str = "UMILIB_FUZZ_TARGET";

    /// The target this process was started to run under libFuzzer, if any.
    pub fn requested_target() -> Option<String> {
        std::env::var(LibFuzzer::TARGET_VARIABLE).ok()
    }

    /// Runs `target` under libFuzzer with `arguments` (libFuzzer flags and
    /// corpus directories) and returns libFuzzer's exit code. `program` must be
    /// the path of the running executable, which libFuzzer re-executes. Fails
    /// if a target is already running in this process.
    pub fn run(target: &'static dyn FuzzTarget, program: &str, arguments: &[String]) -> Result<i32, String> {
        let strings: Vec<CString> = core::iter::once(program)
            .chain(arguments.iter().map(String::as_str))
            .map(|argument| CString::new(argument).map_err(|_| String::from("arguments must not contain NUL")))
            .collect::<Result<_, _>>()?;
        LibFuzzer::target().set(target).map_err(|_| String::from("a libFuzzer target is already running"))?;
        let mut pointers: Vec<*mut c_char> = strings.iter().map(|string| string.as_ptr().cast_mut()).collect();
        pointers.push(core::ptr::null_mut());
        let mut argc = strings.len() as c_int;
        let mut argv = pointers.as_mut_ptr();
        // SAFETY: `argc` and `argv` describe NUL-terminated strings that live
        // until libFuzzer returns; libFuzzer does not write through them.
        Ok(unsafe { LLVMFuzzerRunDriver(&mut argc, &mut argv, LibFuzzer::test_one_input) })
    }

    /// The process-wide slot holding the running target.
    pub fn target() -> &'static OnceLock<&'static dyn FuzzTarget> {
        static TARGET: OnceLock<&'static dyn FuzzTarget> = OnceLock::new();
        &TARGET
    }

    /// The callback libFuzzer calls with each input. A panic aborts the
    /// process, which libFuzzer reports as a crash and saves the input.
    ///
    /// # Safety
    ///
    /// `data` must point to `size` readable bytes, as libFuzzer guarantees.
    pub unsafe extern "C" fn test_one_input(data: *const u8, size: usize) -> c_int {
        let input = if size == 0 {
            &[][..]
        } else {
            // SAFETY: libFuzzer passes `size` readable bytes at `data`.
            unsafe { core::slice::from_raw_parts(data, size) }
        };
        if let Some(target) = LibFuzzer::target().get() {
            target.run(input);
        }
        0
    }
}
