//! RFC 8785 (JCS) vectors for `kavach_ports::jcs`, the canonical form of
//! everything Kavach signs or hashes as evidence.
//!
//! `tests/vectors/jcs-v1.json` holds inputs, their expected canonical form,
//! and inputs that must be refused (numbers that are not safe integers).
//! The same file is checked independently with the `canonicalize` package
//! (the reference implementation by an RFC 8785 author) in the CI job
//! *Credential interop (independent jose)*: `scripts/jose-crosscheck/jcs.mjs`.
//! Both must agree with the file, so they agree with each other.

use serde_json::Value;

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/jcs-v1.json");

fn vectors() -> Value {
    serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap()
}

#[test]
fn canonical_forms_match_the_vectors() {
    let doc = vectors();
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 9);
    for case in cases {
        let input: Value = serde_json::from_str(case["input"].as_str().unwrap()).unwrap();
        let canonical = kavach_ports::jcs::to_vec(&input).unwrap();
        assert_eq!(
            String::from_utf8(canonical).unwrap(),
            case["canonical"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn numbers_that_are_not_safe_integers_are_refused() {
    let doc = vectors();
    let refused = doc["refused"].as_array().unwrap();
    assert!(!refused.is_empty());
    for case in refused {
        let input: Value = serde_json::from_str(case["input"].as_str().unwrap()).unwrap();
        assert!(
            kavach_ports::jcs::to_vec(&input).is_err(),
            "{} was not refused",
            case["name"]
        );
    }
}
