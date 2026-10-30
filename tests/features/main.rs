//! Tests of the feature rules (see `.docs/feature-system.md`):
//! - every canonical feature `a-b-c` is the directory `src/a/b/c` with a
//!   `mod.rs`, and every directory of `src` is a canonical feature;
//! - every module has an FFI mirror in `src/ffi/a/b/c` and a Python mirror
//!   in `port/python/umilib/a/b/c`, and nothing else is mirrored;
//! - a parent feature lists all of its direct children;
//! - an alias lists exactly one canonical feature;
//! - every `umilib_feature` cfg in the sources names an existing feature.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

struct Manifest {
    features: BTreeMap<String, Vec<String>>,
}

impl Manifest {
    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn load() -> Manifest {
        let text = fs::read_to_string(Manifest::root().join("Cargo.toml")).unwrap();
        let mut features = BTreeMap::new();
        let mut in_features = false;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_features = line == "[features]";
                continue;
            }
            if !in_features || line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, list) = line.split_once('=').expect("feature lines are `name = [...]`");
            let list = list.trim();
            assert!(list.starts_with('[') && list.ends_with(']'), "feature {name} must be on one line");
            let items = list[1..list.len() - 1]
                .split(',')
                .map(|item| item.trim().trim_matches('"').to_string())
                .filter(|item| !item.is_empty())
                .collect();
            assert!(features.insert(name.trim().to_string(), items).is_none(), "duplicate feature {name}");
        }
        Manifest { features }
    }

    fn path_of(feature: &str) -> PathBuf {
        feature.split('-').collect()
    }

    fn canonical(&self) -> BTreeSet<String> {
        self.features
            .keys()
            .filter(|name| *name != "default" && Manifest::root().join("src").join(Manifest::path_of(name)).is_dir())
            .cloned()
            .collect()
    }

    fn aliases(&self) -> BTreeSet<String> {
        let canonical = self.canonical();
        self.features.keys().filter(|name| *name != "default" && !canonical.contains(*name)).cloned().collect()
    }

    /// Every directory below `root` that satisfies `is_module`, as feature names.
    fn module_directories(root: &Path, is_module: &dyn Fn(&Path) -> bool) -> BTreeSet<String> {
        let mut found = BTreeSet::new();
        let mut stack = vec![(root.to_path_buf(), Vec::<String>::new())];
        while let Some((directory, path)) = stack.pop() {
            for entry in fs::read_dir(&directory).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().to_string();
                if !entry.file_type().unwrap().is_dir() || name.starts_with('.') || name == "__pycache__" {
                    continue;
                }
                let mut child = path.clone();
                child.push(name);
                if is_module(&entry.path()) {
                    found.insert(child.join("-"));
                }
                stack.push((entry.path(), child));
            }
        }
        found
    }
}

#[test]
fn every_canonical_feature_is_a_module_directory_and_back() {
    let manifest = Manifest::load();
    let canonical = manifest.canonical();
    let source = Manifest::root().join("src");
    let mut directories = Manifest::module_directories(&source, &|_| true);
    // The subtree of `src/ffi` mirrors the other modules and is checked separately.
    directories.retain(|name| !name.starts_with("ffi-"));
    assert_eq!(directories, canonical, "src directories and canonical features differ");
    for feature in &canonical {
        let module = source.join(Manifest::path_of(feature)).join("mod.rs");
        assert!(module.is_file(), "{} is missing", module.display());
    }
}

#[test]
fn every_module_has_an_ffi_mirror_and_back() {
    let manifest = Manifest::load();
    let expected: BTreeSet<String> = manifest.canonical().into_iter().filter(|name| name != "ffi").collect();
    let mirrors = Manifest::module_directories(&Manifest::root().join("src").join("ffi"), &|_| true);
    assert_eq!(mirrors, expected, "src/ffi mirrors and modules differ");
    for feature in &expected {
        let module = Manifest::root().join("src").join("ffi").join(Manifest::path_of(feature)).join("mod.rs");
        assert!(module.is_file(), "{} is missing", module.display());
    }
}

#[test]
fn every_module_has_a_python_mirror_and_back() {
    let manifest = Manifest::load();
    let package = Manifest::root().join("port").join("python").join("umilib");
    let mirrors = Manifest::module_directories(&package, &|path| path.join("__init__.py").is_file());
    assert_eq!(mirrors, manifest.canonical(), "Python packages and modules differ");
    let all = Manifest::module_directories(&package, &|_| true);
    assert_eq!(all, mirrors, "every directory of the Python package must be a package");
}

#[test]
fn parents_list_all_of_their_children() {
    let manifest = Manifest::load();
    let canonical = manifest.canonical();
    for feature in &canonical {
        let children: BTreeSet<&String> = canonical
            .iter()
            .filter(|child| {
                child
                    .strip_prefix(feature.as_str())
                    .and_then(|rest| rest.strip_prefix('-'))
                    .is_some_and(|rest| !rest.contains('-'))
            })
            .collect();
        for child in children {
            assert!(manifest.features[feature].contains(child), "feature {feature} must list its child {child}");
        }
    }
}

#[test]
fn aliases_name_exactly_one_canonical_feature() {
    let manifest = Manifest::load();
    let canonical = manifest.canonical();
    for alias in manifest.aliases() {
        let items = &manifest.features[&alias];
        assert!(
            items.len() == 1 && canonical.contains(&items[0]),
            "alias {alias} must list exactly one canonical feature"
        );
    }
}

#[test]
fn every_dependency_is_a_feature() {
    let manifest = Manifest::load();
    for (feature, items) in &manifest.features {
        for item in items {
            assert!(manifest.features.contains_key(item), "feature {feature} lists unknown feature {item}");
        }
    }
}

#[test]
fn every_cfg_names_a_feature() {
    let manifest = Manifest::load();
    let mut sources = Vec::new();
    for directory in ["src", "tests", "benches", "fuzz"] {
        let mut stack = vec![Manifest::root().join(directory)];
        while let Some(path) = stack.pop() {
            if path.is_dir() {
                stack.extend(fs::read_dir(&path).unwrap().map(|entry| entry.unwrap().path()));
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                sources.push(path);
            }
        }
    }
    let marker = ["umilib_feature", " = \""].concat();
    for source in sources {
        let text = fs::read_to_string(&source).unwrap();
        let mut rest = text.as_str();
        while let Some(index) = rest.find(&marker) {
            rest = &rest[index + marker.len()..];
            let name = &rest[..rest.find('"').unwrap()];
            assert!(manifest.features.contains_key(name), "{} uses unknown feature {name}", source.display());
        }
    }
}
