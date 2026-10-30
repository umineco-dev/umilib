use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::vec::Vec;

/// A set of inputs stored as files in a directory, one input per file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Corpus {
    pub inputs: Vec<Vec<u8>>,
}

impl Corpus {
    /// Reads every file in `directory` whose name does not start with `.`,
    /// sorted by name. A missing directory is an empty corpus.
    pub fn load(directory: &Path) -> io::Result<Corpus> {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Corpus::default()),
            Err(error) => return Err(error),
        };
        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_file() && !entry.file_name().to_string_lossy().starts_with('.') {
                paths.push(entry.path());
            }
        }
        paths.sort();
        let mut inputs = Vec::with_capacity(paths.len());
        for path in paths {
            inputs.push(fs::read(path)?);
        }
        Ok(Corpus { inputs })
    }

    /// The file name of `input`: its 64-bit FNV-1a hash in hexadecimal, so
    /// that equal inputs share a file on every platform and Rust version.
    pub fn file_name(input: &[u8]) -> std::string::String {
        let hash = input
            .iter()
            .fold(0xCBF2_9CE4_8422_2325u64, |hash, &byte| (hash ^ byte as u64).wrapping_mul(0x0100_0000_01B3));
        std::format!("{hash:016x}")
    }

    /// Writes `input` into `directory`, creating it if needed, and returns the file path.
    pub fn save(directory: &Path, input: &[u8]) -> io::Result<PathBuf> {
        fs::create_dir_all(directory)?;
        let path = directory.join(Corpus::file_name(input));
        fs::write(&path, input)?;
        Ok(path)
    }
}
