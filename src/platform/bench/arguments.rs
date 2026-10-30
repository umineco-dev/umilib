use std::path::PathBuf;
use std::string::String;

/// Command-line arguments of a benchmark program.
///
/// `--quick` selects [`BenchConfig::quick`](super::BenchConfig::quick),
/// `--json PATH` writes the JSON report to `PATH`, and the first other
/// argument is a filter: only routines whose name contains it are run.
/// `--bench`, which `cargo bench` passes, is accepted and ignored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BenchArguments {
    pub quick: bool,
    pub json: Option<PathBuf>,
    pub filter: Option<String>,
}

impl BenchArguments {
    /// Parses `arguments`, which do not include the program name.
    pub fn parse(arguments: impl IntoIterator<Item = String>) -> Result<BenchArguments, String> {
        let mut parsed = BenchArguments::default();
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--bench" => {}
                "--quick" => parsed.quick = true,
                "--json" => {
                    let path = arguments.next().ok_or_else(|| String::from("--json requires a path"))?;
                    parsed.json = Some(PathBuf::from(path));
                }
                flag if flag.starts_with('-') => return Err(std::format!("unknown argument: {flag}")),
                filter => {
                    if parsed.filter.is_some() {
                        return Err(std::format!("unexpected argument: {filter}"));
                    }
                    parsed.filter = Some(String::from(filter));
                }
            }
        }
        Ok(parsed)
    }
}
