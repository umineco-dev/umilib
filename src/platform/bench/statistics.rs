/// A summary of samples, in nanoseconds per iteration.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Statistics {
    pub mean: f64,
    pub median: f64,
    /// The median of the absolute deviations from the median; robust against outliers.
    pub median_absolute_deviation: f64,
    /// The population standard deviation (divided by the number of samples).
    pub standard_deviation: f64,
    pub minimum: f64,
    pub maximum: f64,
}

impl Statistics {
    /// Summarizes `samples`, which are reordered. Returns zeros if there are no samples.
    pub fn from_samples(samples: &mut [f64]) -> Statistics {
        if samples.is_empty() {
            return Statistics::default();
        }
        samples.sort_by(f64::total_cmp);
        let count = samples.len() as f64;
        let mean = samples.iter().sum::<f64>() / count;
        let median = Statistics::median_of_sorted(samples);
        let variance = samples.iter().map(|sample| (sample - mean) * (sample - mean)).sum::<f64>() / count;
        let mut deviations: std::vec::Vec<f64> = samples.iter().map(|sample| (sample - median).abs()).collect();
        deviations.sort_by(f64::total_cmp);
        Statistics {
            mean,
            median,
            median_absolute_deviation: Statistics::median_of_sorted(&deviations),
            standard_deviation: variance.sqrt(),
            minimum: samples[0],
            maximum: samples[samples.len() - 1],
        }
    }

    /// The median of sorted, non-empty `values`.
    pub fn median_of_sorted(values: &[f64]) -> f64 {
        let middle = values.len() / 2;
        if values.len().is_multiple_of(2) { (values[middle - 1] + values[middle]) / 2.0 } else { values[middle] }
    }
}
