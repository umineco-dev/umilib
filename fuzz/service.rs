//! Fuzz targets of `umilib::service`.

use umilib::platform::fuzz::{FuzzFunction, FuzzTarget};
use umilib::service::{Pattern, PatternKind};

/// Text that parses formats to a canonical text (which may drop needless
/// escapes) of the same pattern, which formats to itself; patterns match as
/// an oracle of std's slice methods says.
pub const PATTERNS: FuzzFunction<fn(&[u8])> = FuzzFunction::new("service-patterns", |data| {
    if let Ok(pattern) = Pattern::parse(data) {
        let canonical = pattern.format();
        let parsed = Pattern::parse(&canonical).expect("the text of a pattern parses");
        assert_eq!(parsed, pattern);
        assert_eq!(parsed.format(), canonical);
        if !data.contains(&Pattern::ESCAPE) {
            assert_eq!(canonical, data, "text without escapes is canonical");
        }
    }
    let Some((&control, rest)) = data.split_first() else { return };
    let split = rest.first().map_or(0, |byte| *byte as usize).min(rest.len());
    let (bytes, input) = rest.split_at(split);
    let kind = [PatternKind::Any, PatternKind::Exact, PatternKind::Prefix, PatternKind::Suffix][control as usize % 4];
    let ignore = control & 4 != 0;
    let pattern = Pattern::new(kind, bytes).ignoring_ascii_case(ignore);
    assert_eq!(Pattern::parse(&pattern.format()).map(|parsed| parsed.ignoring_ascii_case(ignore)), Ok(pattern.clone()));
    let fold = |bytes: &[u8]| if ignore { bytes.to_ascii_lowercase() } else { bytes.to_vec() };
    let (folded, input_folded) = (fold(bytes), fold(input));
    let expected = match kind {
        PatternKind::Any => true,
        PatternKind::Exact => input_folded == folded,
        PatternKind::Prefix => input_folded.starts_with(&folded),
        PatternKind::Suffix => input_folded.ends_with(&folded),
    };
    assert_eq!(pattern.matches_bytes(input), expected);
});

pub const TARGETS: &[&dyn FuzzTarget] = &[&PATTERNS];
