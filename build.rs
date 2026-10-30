//! Emits `umilib_feature` cfgs: for every enabled feature `a-b-c`, the cfgs
//! `umilib_feature = "a"`, `"a-b"` and `"a-b-c"` are set, so a parent module
//! is compiled whenever any of its descendants is enabled. `umilib_all_features`
//! is set when every feature is enabled.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::Path;

struct FeatureTable {
    names: Vec<String>,
}

impl FeatureTable {
    fn parse(manifest: &str) -> FeatureTable {
        let mut names = Vec::new();
        let mut in_features = false;
        for line in manifest.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                let header = line.split('#').next().unwrap_or_default().trim();
                in_features = header == "[features]";
                continue;
            }
            if !in_features || line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Only `name = [...]` lines start a feature; Cargo writes the
            // published manifest with one array item per line.
            if let Some((name, _)) = line.split_once('=') {
                let name = name.trim();
                if !name.is_empty()
                    && name.chars().all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
                {
                    names.push(name.to_string());
                }
            }
        }
        FeatureTable { names }
    }

    /// The enabled features: `CARGO_CFG_FEATURE` (Cargo 1.85 and later), or
    /// else the `CARGO_FEATURE_<NAME>` variable of each feature in the table.
    fn enabled(&self) -> Vec<String> {
        match env::var("CARGO_CFG_FEATURE") {
            Ok(list) => list.split(',').filter(|name| !name.is_empty()).map(String::from).collect(),
            Err(_) => self
                .names
                .iter()
                .filter(|name| {
                    env::var_os(format!("CARGO_FEATURE_{}", name.to_uppercase().replace('-', "_"))).is_some()
                })
                .cloned()
                .collect(),
        }
    }

    fn prefixes(name: &str) -> impl Iterator<Item = &str> {
        name.match_indices('-').map(|(index, _)| &name[..index]).chain([name])
    }
}

fn main() {
    let directory = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo");
    let manifest = fs::read_to_string(Path::new(&directory).join("Cargo.toml")).expect("Cargo.toml is readable");
    let table = FeatureTable::parse(&manifest);
    println!("cargo::rerun-if-changed=Cargo.toml");

    let known: BTreeSet<&str> = table.names.iter().flat_map(|name| FeatureTable::prefixes(name)).collect();
    let values: Vec<String> = known.iter().map(|value| format!("\"{value}\"")).collect();
    println!("cargo::rustc-check-cfg=cfg(umilib_feature, values({}))", values.join(", "));
    println!("cargo::rustc-check-cfg=cfg(umilib_libfuzzer)");
    println!("cargo::rustc-check-cfg=cfg(umilib_all_features)");

    let enabled = table.enabled();
    let active: BTreeSet<&str> = enabled.iter().flat_map(|name| FeatureTable::prefixes(name)).collect();
    for value in &active {
        println!("cargo::rustc-cfg=umilib_feature=\"{value}\"");
    }
    // Set when every feature is enabled, for checks that need the whole crate.
    if table.names.iter().filter(|name| *name != "default").all(|name| active.contains(name.as_str())) {
        println!("cargo::rustc-cfg=umilib_all_features");
    }
}
