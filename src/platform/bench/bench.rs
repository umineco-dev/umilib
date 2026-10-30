use std::fmt::Write;
use std::string::String;
use std::time::Instant;
use std::vec::Vec;

use super::{BenchConfig, BenchResult, Statistics, Throughput};

/// Runs routines and collects their [`BenchResult`]s.
#[derive(Clone, Debug)]
pub struct Bench {
    config: BenchConfig,
    filter: Option<String>,
    results: Vec<BenchResult>,
}

impl Bench {
    /// Creates a bench that measures with `config`.
    pub fn new(config: BenchConfig) -> Bench {
        Bench { config, filter: None, results: Vec::new() }
    }

    /// The configuration used for every routine.
    pub fn config(&self) -> &BenchConfig {
        &self.config
    }

    /// Runs only routines whose name contains `filter`, or every routine if `None`.
    pub fn set_filter(&mut self, filter: Option<String>) {
        self.filter = filter;
    }

    /// Every result measured so far, in order.
    pub fn results(&self) -> &[BenchResult] {
        &self.results
    }

    /// Measures `routine` under `name` unless the filter excludes it.
    ///
    /// Pass values the routine computes to [`core::hint::black_box`] so that
    /// the optimizer cannot remove the work being measured.
    pub fn run(
        &mut self,
        name: &str,
        throughput: Option<Throughput>,
        mut routine: impl FnMut(),
    ) -> Option<&BenchResult> {
        if let Some(filter) = &self.filter
            && !name.contains(filter.as_str())
        {
            return None;
        }

        // Warm up, doubling the batch size, to estimate the time per iteration.
        let mut iterations: u64 = 0;
        let mut batch: u64 = 1;
        let start = Instant::now();
        loop {
            for _ in 0..batch {
                // Through `black_box`, so that the optimizer keeps every call, even of an empty routine.
                core::hint::black_box(&mut routine)();
            }
            iterations = iterations.saturating_add(batch);
            if start.elapsed() >= self.config.warmup {
                break;
            }
            batch = batch.saturating_mul(2);
        }
        let per_iteration = start.elapsed().as_nanos() as f64 / iterations as f64;

        let samples = self.config.samples.clamp(1, BenchConfig::MAXIMUM_SAMPLES);
        let per_sample = self.config.measurement.as_nanos() as f64 / samples as f64;
        let iterations = ((per_sample / per_iteration.max(1.0)) as u64).max(1);
        let mut measured = Vec::with_capacity(samples);
        for _ in 0..samples {
            let sample = Instant::now();
            for _ in 0..iterations {
                core::hint::black_box(&mut routine)();
            }
            measured.push(sample.elapsed().as_nanos() as f64 / iterations as f64);
        }

        self.results.push(BenchResult {
            name: String::from(name),
            iterations,
            samples,
            statistics: Statistics::from_samples(&mut measured),
            throughput,
        });
        self.results.last()
    }

    /// Formats a nanosecond duration with a readable unit.
    pub fn format_duration(nanoseconds: f64) -> String {
        if nanoseconds < 1e3 {
            std::format!("{nanoseconds:.2} ns")
        } else if nanoseconds < 1e6 {
            std::format!("{:.2} µs", nanoseconds / 1e3)
        } else if nanoseconds < 1e9 {
            std::format!("{:.2} ms", nanoseconds / 1e6)
        } else {
            std::format!("{:.2} s", nanoseconds / 1e9)
        }
    }

    /// Formats one result as a line of text.
    pub fn format_result(result: &BenchResult) -> String {
        let mut line = std::format!(
            "{:<48} {:>12} ± {:>10}",
            result.name,
            Bench::format_duration(result.statistics.median),
            Bench::format_duration(result.statistics.median_absolute_deviation)
        );
        if let (Some(throughput), Some(rate)) = (result.throughput, result.throughput_per_second()) {
            let _ = match throughput {
                Throughput::Bytes(_) => write!(line, "  {:>10.2} MiB/s", rate / (1024.0 * 1024.0)),
                Throughput::Elements(_) => write!(line, "  {:>10.0} elements/s", rate),
            };
        }
        line
    }

    /// Every result as text, one line each: name, median and median absolute deviation.
    pub fn report_text(&self) -> String {
        let mut text = String::new();
        for result in &self.results {
            text.push_str(&Bench::format_result(result));
            text.push('\n');
        }
        text
    }

    /// Every result as a JSON array of objects; durations are in nanoseconds.
    pub fn report_json(&self) -> String {
        let mut json = String::from("[");
        for (index, result) in self.results.iter().enumerate() {
            if index > 0 {
                json.push(',');
            }
            let statistics = &result.statistics;
            json.push_str("{\"name\":\"");
            for character in result.name.chars() {
                match character {
                    '"' => json.push_str("\\\""),
                    '\\' => json.push_str("\\\\"),
                    character if (character as u32) < 0x20 => {
                        let _ = write!(json, "\\u{:04x}", character as u32);
                    }
                    character => json.push(character),
                }
            }
            let _ = write!(
                json,
                "\",\"iterations\":{},\"samples\":{},\"mean\":{},\"median\":{},\"median_absolute_deviation\":{},\
                 \"standard_deviation\":{},\"minimum\":{},\"maximum\":{}",
                result.iterations,
                result.samples,
                statistics.mean,
                statistics.median,
                statistics.median_absolute_deviation,
                statistics.standard_deviation,
                statistics.minimum,
                statistics.maximum
            );
            match result.throughput {
                Some(throughput) => {
                    let _ = write!(
                        json,
                        ",\"throughput\":{{\"unit\":\"{}\",\"amount\":{}}}",
                        throughput.unit(),
                        throughput.amount()
                    );
                }
                None => json.push_str(",\"throughput\":null"),
            }
            json.push('}');
        }
        json.push(']');
        json
    }
}
