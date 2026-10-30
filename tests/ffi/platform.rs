use std::ptr;

use super::Check;

#[cfg(umilib_feature = "platform-bench")]
#[test]
fn bench_runs_a_c_routine() {
    use std::ffi::c_void;

    use umilib::ffi::Buffer;
    use umilib::ffi::platform::bench::*;
    use umilib::platform::bench::{Bench, BenchConfig, BenchResult};

    unsafe extern "C" fn routine(context: *mut c_void) {
        unsafe { *(context as *mut u64) += 1 };
    }

    let mut calls = 0u64;
    unsafe {
        let mut config: *mut BenchConfig = ptr::null_mut();
        Check::ok(umilib_platform_bench_bench_config_quick(&mut config));
        Check::ok(umilib_platform_bench_bench_config_set_samples(config, 3));
        let mut samples = 0usize;
        Check::ok(umilib_platform_bench_bench_config_samples(config, &mut samples));
        assert_eq!(samples, 3);
        Check::ok(umilib_platform_bench_bench_config_set_warmup(config, 1_000_000));
        Check::ok(umilib_platform_bench_bench_config_set_measurement(config, 3_000_000));
        let mut warmup = 0u64;
        Check::ok(umilib_platform_bench_bench_config_warmup(config, &mut warmup));
        assert_eq!(warmup, 1_000_000);

        let mut bench: *mut Bench = ptr::null_mut();
        Check::ok(umilib_platform_bench_bench_new(config, &mut bench));
        umilib_platform_bench_bench_config_free(config);

        let name = "count";
        let mut result: *mut BenchResult = ptr::null_mut();
        Check::ok(umilib_platform_bench_bench_run(
            bench,
            name.as_ptr(),
            name.len(),
            2,
            1,
            Some(routine),
            (&mut calls as *mut u64).cast(),
            &mut result,
        ));
        assert!(!result.is_null());
        assert!(calls > 0);
        let mut recorded = 0usize;
        Check::ok(umilib_platform_bench_bench_result_samples(result, &mut recorded));
        assert_eq!(recorded, 3);
        let mut kind = 0u8;
        Check::ok(umilib_platform_bench_bench_result_throughput_kind(result, &mut kind));
        assert_eq!(kind, 2);
        let mut text = Buffer::EMPTY;
        Check::ok(umilib_platform_bench_bench_result_name(result, &mut text));
        assert_eq!(text.as_slice(), b"count");
        umilib::ffi::umilib_ffi_buffer_free(&mut text);
        umilib_platform_bench_bench_result_free(result);

        Check::fails(
            umilib_platform_bench_bench_run(
                bench,
                name.as_ptr(),
                name.len(),
                3,
                1,
                Some(routine),
                ptr::null_mut(),
                &mut result,
            ),
            "ffi",
            "InvalidArgument",
        );
        Check::fails(
            umilib_platform_bench_bench_run(bench, name.as_ptr(), name.len(), 0, 0, None, ptr::null_mut(), &mut result),
            "ffi",
            "NullPointer",
        );
        let arguments = [c"--quick".as_ptr().cast::<umilib::ffi::Char>()];
        let mut parsed = ptr::null_mut();
        Check::fails(
            umilib_platform_bench_bench_arguments_parse(arguments.as_ptr(), usize::MAX / 2, &mut parsed),
            "ffi",
            "InvalidArgument",
        );

        let filter = "other";
        Check::ok(umilib_platform_bench_bench_set_filter(bench, filter.as_ptr(), filter.len()));
        Check::ok(umilib_platform_bench_bench_run(
            bench,
            name.as_ptr(),
            name.len(),
            0,
            0,
            Some(routine),
            (&mut calls as *mut u64).cast(),
            &mut result,
        ));
        assert!(result.is_null());

        Check::ok(umilib_platform_bench_bench_report_json(bench, &mut text));
        assert!(std::str::from_utf8(text.as_slice()).unwrap().starts_with("[{\"name\":\"count\""));
        umilib::ffi::umilib_ffi_buffer_free(&mut text);
        umilib_platform_bench_bench_free(bench);
    }
}

#[cfg(umilib_feature = "platform-fuzz")]
#[test]
fn fuzzer_runs_a_c_target_and_reports_failures() {
    use std::ffi::c_void;

    use umilib::ffi::Buffer;
    use umilib::ffi::platform::fuzz::*;
    use umilib::platform::fuzz::{FuzzConfig, FuzzReport, Fuzzer};

    unsafe extern "C" fn rejects_long_inputs(_: *mut c_void, _: *const u8, length: usize) -> bool {
        length < 4
    }

    unsafe {
        let mut config: *mut FuzzConfig = ptr::null_mut();
        Check::ok(umilib_platform_fuzz_fuzz_config_new(&mut config));
        Check::ok(umilib_platform_fuzz_fuzz_config_set_iterations(config, true, 10_000));
        Check::ok(umilib_platform_fuzz_fuzz_config_set_seed(config, 1));
        Check::ok(umilib_platform_fuzz_fuzz_config_set_maximum_length(config, 64));
        let mut fuzzer: *mut Fuzzer = ptr::null_mut();
        Check::ok(umilib_platform_fuzz_fuzzer_new(config, &mut fuzzer));
        umilib_platform_fuzz_fuzz_config_free(config);

        let name = "ffi-test";
        let mut report: *mut FuzzReport = ptr::null_mut();
        Check::ok(umilib_platform_fuzz_fuzzer_run(
            fuzzer,
            name.as_ptr(),
            name.len(),
            Some(rejects_long_inputs),
            ptr::null_mut(),
            &mut report,
        ));
        let mut failures = 0usize;
        Check::ok(umilib_platform_fuzz_fuzz_report_failure_count(report, &mut failures));
        assert_eq!(failures, 1);
        let mut input = Buffer::EMPTY;
        Check::ok(umilib_platform_fuzz_fuzz_report_failure(report, 0, &mut input));
        assert!(input.as_slice().len() >= 4);
        Check::fails(umilib_platform_fuzz_fuzz_report_failure(report, 1, &mut input), "ffi", "InvalidArgument");
        umilib::ffi::umilib_ffi_buffer_free(&mut input);
        let mut saved = 9usize;
        Check::ok(umilib_platform_fuzz_fuzz_report_saved_count(report, &mut saved));
        assert_eq!(saved, 0, "no crash directory is configured");
        umilib_platform_fuzz_fuzz_report_free(report);
        let name = "../escape";
        Check::fails(
            umilib_platform_fuzz_fuzzer_run(
                fuzzer,
                name.as_ptr(),
                name.len(),
                Some(rejects_long_inputs),
                ptr::null_mut(),
                &mut report,
            ),
            "platform.fuzz",
            "InvalidName",
        );
        umilib_platform_fuzz_fuzzer_free(fuzzer);
    }
}

#[cfg(umilib_feature = "platform-native")]
#[test]
fn the_native_layer_gives_random_bytes_and_the_system_name() {
    use std::ffi::CStr;

    use umilib::ffi::Char;
    use umilib::ffi::platform::native::*;

    unsafe {
        let mut bytes = [0u8; 300];
        Check::ok(umilib_platform_native_random_fill(bytes.as_mut_ptr(), bytes.len()));
        assert!(bytes[256..].iter().any(|byte| *byte != 0));
        Check::ok(umilib_platform_native_random_fill(ptr::null_mut(), 0));
        Check::fails(umilib_platform_native_random_fill(ptr::null_mut(), 4), "ffi", "NullPointer");
        let mut name: *const Char = ptr::null();
        Check::ok(umilib_platform_native_system_name(&mut name));
        let name = CStr::from_ptr(name.cast()).to_str().unwrap();
        assert_eq!(name, umilib::platform::native::System::NAME);
    }
}
