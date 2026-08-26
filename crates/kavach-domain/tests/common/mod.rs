//! Shared helpers for contract validation integration tests.

use jsonschema::Validator;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn load_json(path: &Path) -> Value {
    let content =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("parse JSON {}: {e}", path.display()))
}

pub fn load_schema(name: &str) -> Value {
    let path = workspace_root().join("schemas").join(name);
    load_json(&path)
}

pub fn validator_for_schema(schema_file: &str) -> Validator {
    let schema = load_schema(schema_file);
    Validator::new(&schema).unwrap_or_else(|e| panic!("invalid schema {schema_file}: {e}"))
}

pub fn assert_valid(validator: &Validator, instance: &Value, label: &str) {
    let errors: Vec<String> = validator
        .iter_errors(instance)
        .map(|e| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "{label} failed schema validation:\n{}",
        errors.join("\n")
    );
}

pub fn yaml_to_json(path: &Path) -> Value {
    let content =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let value: serde_yaml::Value = serde_yaml::from_str(&content)
        .unwrap_or_else(|e| panic!("parse YAML {}: {e}", path.display()));
    serde_json::to_value(value).unwrap_or_else(|e| panic!("yaml to json {}: {e}", path.display()))
}

pub fn golden_v0_dir() -> PathBuf {
    workspace_root().join("golden/finance/v0")
}

pub fn golden_mvp_dir() -> PathBuf {
    workspace_root().join("golden/finance/mvp_mechanics")
}

pub fn collect_json_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .map(|e| e.path().to_path_buf())
        .collect();
    files.sort();
    files
}
