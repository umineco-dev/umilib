use std::time::Duration;

use umilib::platform::fuzz::{
    Corpus, FuzzArguments, FuzzConfig, FuzzEngine, FuzzFunction, FuzzTarget, Fuzzer, Mutator,
};

/// Temporary directories for tests.
struct Scratch;

impl Scratch {
    /// A fresh, empty, process-specific directory path.
    fn directory(name: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!("umilib-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        directory
    }
}

#[test]
fn mutator_is_deterministic_and_respects_the_maximum_length() {
    let (mut a, mut b) = (Mutator::new(42), Mutator::new(42));
    for _ in 0..100 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
    // SplitMix64 with seed 0 starts with 0xE220A8397B1DCDAF.
    assert_eq!(Mutator::new(0).next_u64(), 0xE220_A839_7B1D_CDAF);
    let mut mutator = Mutator::new(7);
    let mut data = vec![0u8; 8];
    let corpus = vec![vec![1u8; 32]];
    for _ in 0..10_000 {
        mutator.mutate(&mut data, 16, &corpus);
        assert!(data.len() <= 16);
    }
    for _ in 0..1000 {
        assert!(mutator.below(3) < 3);
    }
}

#[test]
fn fuzzer_finds_a_failing_input_and_saves_it() {
    let crashes = Scratch::directory("crashes");
    let target = FuzzFunction::new("finds-magic", |data: &[u8]| {
        assert!(!data.windows(2).any(|window| window == [0xFF, 0xFF]), "magic found");
    });
    let config =
        FuzzConfig { seed: 3, iterations: Some(1_000_000), crashes: Some(crashes.clone()), ..FuzzConfig::default() };
    let report = Fuzzer::new(config).run(&target).unwrap();
    assert!(!report.is_success());
    assert_eq!(report.failures.len(), 1);
    let saved = Corpus::load(&crashes.join("finds-magic")).unwrap();
    assert_eq!(saved.inputs, report.failures);
    let _ = std::fs::remove_dir_all(&crashes);
}

#[test]
fn fuzzer_stops_at_the_iteration_or_time_limit() {
    let target = FuzzFunction::new("passes", |_: &[u8]| {});
    let report = Fuzzer::new(FuzzConfig { iterations: Some(500), ..FuzzConfig::default() }).run(&target).unwrap();
    assert!(report.is_success());
    assert_eq!(report.iterations, 500);
    let config = FuzzConfig { iterations: None, duration: Some(Duration::from_millis(20)), ..FuzzConfig::default() };
    let report = Fuzzer::new(config).run(&target).unwrap();
    assert!(report.elapsed >= Duration::from_millis(20));
    assert_eq!(target.name(), "passes");
}

#[test]
fn corpus_round_trips_and_replay_reports_each_failure() {
    let directory = Scratch::directory("corpus");
    assert!(Corpus::load(&directory).unwrap().inputs.is_empty());
    let first = Corpus::save(&directory, b"pass").unwrap();
    Corpus::save(&directory, b"fail").unwrap();
    assert_eq!(Corpus::save(&directory, b"pass").unwrap(), first);
    let corpus = Corpus::load(&directory).unwrap();
    assert_eq!(corpus.inputs.len(), 2);
    let target = FuzzFunction::new("replay", |data: &[u8]| assert_ne!(data, b"fail"));
    let report = Fuzzer::default().replay(&target, &corpus);
    assert_eq!(report.iterations, 2);
    assert_eq!(report.failures, vec![b"fail".to_vec()]);
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn arguments_are_parsed() {
    let parse = |arguments: &[&str]| FuzzArguments::parse(arguments.iter().map(|argument| argument.to_string()));
    assert_eq!(parse(&["--quiet", "--test-threads=1"]), Ok(FuzzArguments::default()));
    let parsed =
        parse(&["--fuzz", "bytes-reader", "--engine", "libfuzzer", "--time", "5", "--seed", "9", "--", "-runs=10"])
            .unwrap();
    assert_eq!(parsed.fuzz.as_deref(), Some("bytes-reader"));
    assert_eq!(parsed.engine, FuzzEngine::LibFuzzer);
    assert_eq!(parsed.duration, Some(Duration::from_secs(5)));
    assert_eq!(parsed.seed, Some(9));
    assert_eq!(parsed.engine_arguments, vec![String::from("-runs=10")]);
    assert_eq!(parse(&["bytes"]).unwrap().filter.as_deref(), Some("bytes"));
    assert!(parse(&["--engine", "other"]).is_err());
    assert!(parse(&["--time", "x"]).is_err());
    assert!(parse(&["--bogus"]).is_err());
    // Values of ignored test-harness flags are not mistaken for a filter.
    assert_eq!(parse(&["--test-threads", "1", "--format", "terse"]), Ok(FuzzArguments::default()));
    let listed = parse(&["--list", "--skip", "secret", "--skip", "writer"]).unwrap();
    assert!(listed.list);
    assert_eq!(listed.skip, vec![String::from("secret"), String::from("writer")]);
}

#[test]
fn corpus_names_are_stable_fnv1a_hashes() {
    // FNV-1a 64-bit: offset basis 0xcbf29ce484222325, prime 0x100000001b3.
    assert_eq!(Corpus::file_name(b""), "cbf29ce484222325");
    assert_eq!(Corpus::file_name(b"a"), "af63dc4c8601ec8c");
    assert_eq!(Corpus::file_name(b"foobar"), "85944171f73967e8");
}

#[test]
fn corpus_ignores_hidden_files() {
    let directory = Scratch::directory("hidden");
    Corpus::save(&directory, b"input").unwrap();
    std::fs::write(directory.join(".DS_Store"), b"metadata").unwrap();
    assert_eq!(Corpus::load(&directory).unwrap().inputs, vec![b"input".to_vec()]);
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn target_names_must_be_directory_names() {
    for valid in ["bytes-reader", "a_b.c", "x"] {
        assert!(Fuzzer::is_valid_name(valid), "{valid}");
    }
    for invalid in ["", ".hidden", "../escape", "a/b", "a\\b", "/absolute", "space here"] {
        assert!(!Fuzzer::is_valid_name(invalid), "{invalid}");
    }
    let target = FuzzFunction::new("../escape", |_: &[u8]| {});
    assert_eq!(Fuzzer::default().run(&target).unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn failures_that_cannot_be_saved_are_still_reported() {
    let file = Scratch::directory("not-a-directory");
    std::fs::write(&file, b"").unwrap();
    let target = FuzzFunction::new("always-fails", |_: &[u8]| panic!("failure"));
    let config = FuzzConfig { crashes: Some(file.clone()), ..FuzzConfig::default() };
    let report = Fuzzer::new(config).run(&target).unwrap();
    assert_eq!(report.failures.len(), 1);
    assert!(report.saved.is_empty());
    let _ = std::fs::remove_file(&file);
}
