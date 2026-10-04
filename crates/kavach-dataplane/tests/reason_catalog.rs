//! Every reason code a decision can carry has an entry in the catalog
//! (`kavach_domain::reasons`). The codes are read from where they are
//! made: the agent policies, the authorizer, the gateway and core, the tool
//! registry and the policy pack. A new code without an entry fails here.

use kavach_domain::reasons::explain;
use regex::Regex;

fn codes(source: &str, pattern: &str) -> Vec<String> {
    Regex::new(pattern)
        .unwrap()
        .captures_iter(source)
        .map(|c| c[1].to_string())
        .collect()
}

fn missing(found: &[String], make: impl Fn(&str) -> String) -> Vec<String> {
    found
        .iter()
        .map(|c| make(c))
        .filter(|code| explain(code).is_none())
        .collect()
}

#[test]
fn every_agent_policy_id_is_explained() {
    let ids = codes(kavach_authz::AGENT_POLICIES, r#"@id\("([^"]+)"\)"#);
    assert!(ids.len() >= 20, "found {ids:?}");
    assert_eq!(missing(&ids, str::to_string), Vec::<String>::new());
}

#[test]
fn every_decision_word_is_explained() {
    let words = codes(
        include_str!("../../kavach-authz/src/lib.rs"),
        r#"outcome\(Decision::\w+, names, "([a-z_]+)"\)"#,
    );
    assert!(words.len() >= 4, "{words:?}");
    assert_eq!(missing(&words, str::to_string), Vec::<String>::new());
}

#[test]
fn every_core_and_gateway_code_is_explained() {
    let source = [
        include_str!("../src/authorize.rs"),
        include_str!("../src/gateway.rs"),
    ]
    .concat();
    // Literal codes (`"name".into()`), except values that are not reasons.
    let found: Vec<_> = codes(&source, r#""([a-z][a-z_]+)"\.into\(\)"#)
        .into_iter()
        .filter(|c| c != "default")
        .collect();
    assert!(found.len() >= 5, "{found:?}");
    assert_eq!(missing(&found, str::to_string), Vec::<String>::new());
}

#[test]
fn every_registry_code_is_explained() {
    let prefixes = codes(include_str!("../src/tools.rs"), r#"format!\("([a-z_]+):\{"#);
    assert!(prefixes.len() >= 4, "{prefixes:?}");
    assert_eq!(
        missing(&prefixes, |p| format!("{p}:field")),
        Vec::<String>::new()
    );
}

#[test]
fn every_pack_code_is_explained() {
    let found = codes(
        include_str!("../../../packs/finance/v0.yaml"),
        r"reason_code:\s*([A-Z_]+)",
    );
    assert!(found.len() >= 5, "{found:?}");
    assert_eq!(missing(&found, str::to_string), Vec::<String>::new());
    assert!(explain(kavach_evaluate_codes::POLICY_EVALUATION_ERROR).is_some());
    assert!(explain(kavach_evaluate_codes::CONSENT_MISMATCH).is_some());
}

/// The evaluate engine's own codes (kept here to avoid a dependency).
mod kavach_evaluate_codes {
    pub const POLICY_EVALUATION_ERROR: &str = "POLICY_EVALUATION_ERROR";
    pub const CONSENT_MISMATCH: &str = "CONSENT_MISMATCH";
}
