//! The list of relaxations is one list: the code, the OpenAPI enum and the
//! bypass inventory name exactly the same ones, so a new relaxation cannot be
//! added in one place and forgotten in the others.

use std::collections::BTreeSet;
use std::path::PathBuf;

use kavach_api::relaxations::Relaxation;

fn doc(path: &str) -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path),
    )
    .unwrap()
}

fn names() -> BTreeSet<&'static str> {
    Relaxation::ALL.iter().map(|r| r.as_str()).collect()
}

#[test]
fn the_openapi_enum_names_every_relaxation() {
    let spec: serde_yaml::Value = serde_yaml::from_str(&doc("docs/openapi.yaml")).unwrap();
    let listed: BTreeSet<String> = spec["components"]["schemas"]["RuntimeView"]["properties"]
        ["relaxations"]["items"]["enum"]
        .as_sequence()
        .expect("an enum")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = names().into_iter().map(str::to_string).collect();
    assert_eq!(listed, expected);
}

#[test]
fn the_bypass_inventory_names_every_relaxation() {
    let inventory = doc("docs/BYPASS_INVENTORY.md");
    for name in names() {
        assert!(
            inventory.contains(&format!("`{name}`")),
            "{name} is not in BYPASS_INVENTORY.md"
        );
    }
}

#[test]
fn every_relaxation_has_a_series_and_the_alert_reads_them() {
    let rules = doc("deploy/monitoring/kavach-alerts.rules.yml");
    assert!(rules.contains("kavach_insecure_dev > 0"));
    assert!(rules.contains("kavach_relaxation_active > 0"));
}
