use std::time::Duration;

use umilib::platform::bench::{Bench, BenchArguments, BenchConfig, BenchResult, Statistics, Throughput};

#[test]
fn statistics_follow_their_definitions() {
    let mut samples = [4.0, 1.0, 100.0, 3.0, 2.0];
    let statistics = Statistics::from_samples(&mut samples);
    assert_eq!(statistics.mean, 22.0);
    assert_eq!(statistics.median, 3.0);
    // |x - 3| = [2, 1, 97, 0, 1], whose median is 1.
    assert_eq!(statistics.median_absolute_deviation, 1.0);
    assert_eq!(statistics.minimum, 1.0);
    assert_eq!(statistics.maximum, 100.0);
    // Population standard deviation: sqrt(((21^2 + 20^2 + 19^2 + 18^2 + 78^2) / 5)).
    let expected =
        ((21.0f64.powi(2) + 20.0f64.powi(2) + 19.0f64.powi(2) + 18.0f64.powi(2) + 78.0f64.powi(2)) / 5.0).sqrt();
    assert!((statistics.standard_deviation - expected).abs() < 1e-9);

    let mut even = [1.0, 2.0, 3.0, 4.0];
    assert_eq!(Statistics::from_samples(&mut even).median, 2.5);
    assert_eq!(Statistics::from_samples(&mut []), Statistics::default());
}

#[test]
fn bench_measures_and_reports() {
    let config = BenchConfig { warmup: Duration::from_millis(1), measurement: Duration::from_millis(5), samples: 5 };
    let mut bench = Bench::new(config);
    let mut counter = 0u64;
    let result =
        bench.run("count", Some(Throughput::Bytes(1024)), || counter = std::hint::black_box(counter + 1)).unwrap();
    assert_eq!(result.name, "count");
    assert_eq!(result.samples, 5);
    assert!(result.iterations >= 1);
    assert!(
        result.statistics.minimum <= result.statistics.median && result.statistics.median <= result.statistics.maximum
    );
    assert!(result.throughput_per_second().unwrap() > 0.0);
    assert!(counter >= result.iterations * 5);

    bench.set_filter(Some(String::from("hash")));
    assert!(bench.run("count", None, || {}).is_none());
    assert!(bench.run("hash-sha", None, || {}).is_some());
    assert_eq!(bench.results().len(), 2);

    let text = bench.report_text();
    assert_eq!(text.lines().count(), 2);
    assert!(text.contains("MiB/s"));
    let json = bench.report_json();
    assert!(json.starts_with("[{\"name\":\"count\",\"iterations\":"));
    assert!(json.contains("\"throughput\":{\"unit\":\"bytes\",\"amount\":1024}"));
    assert!(json.contains("\"name\":\"hash-sha\""));
    assert!(json.ends_with("\"throughput\":null}]"));
}

#[test]
fn sample_counts_are_clamped() {
    let mut bench =
        Bench::new(BenchConfig { warmup: Duration::ZERO, measurement: Duration::from_micros(10), samples: 0 });
    assert_eq!(bench.run("zero", None, || {}).unwrap().samples, 1);
    assert_eq!(BenchConfig::MAXIMUM_SAMPLES, 1_000_000);
}

#[test]
fn throughput_is_computed_at_the_median() {
    let result = BenchResult {
        name: String::from("x"),
        iterations: 1,
        samples: 1,
        statistics: Statistics { median: 500.0, ..Statistics::default() },
        throughput: Some(Throughput::Elements(2)),
    };
    // Two elements every 500 ns is four million elements per second.
    assert_eq!(result.throughput_per_second(), Some(4e6));
    assert_eq!(Throughput::Elements(2).unit(), "elements");
    assert_eq!(Throughput::Bytes(3).amount(), 3);
}

#[test]
fn durations_are_formatted_with_units() {
    assert_eq!(Bench::format_duration(12.345), "12.35 ns");
    assert_eq!(Bench::format_duration(1_500.0), "1.50 µs");
    assert_eq!(Bench::format_duration(2_500_000.0), "2.50 ms");
    assert_eq!(Bench::format_duration(3e9), "3.00 s");
}

#[test]
fn arguments_are_parsed() {
    let parse = |arguments: &[&str]| BenchArguments::parse(arguments.iter().map(|argument| argument.to_string()));
    assert_eq!(parse(&["--bench"]), Ok(BenchArguments::default()));
    let parsed = parse(&["--bench", "--quick", "sha", "--json", "out.json"]).unwrap();
    assert!(parsed.quick);
    assert_eq!(parsed.filter.as_deref(), Some("sha"));
    assert_eq!(parsed.json, Some("out.json".into()));
    assert!(parse(&["--json"]).is_err());
    assert!(parse(&["--unknown"]).is_err());
    assert!(parse(&["a", "b"]).is_err());
}
