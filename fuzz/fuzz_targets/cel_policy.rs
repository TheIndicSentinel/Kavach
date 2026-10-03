//! CEL policy rules as Kavach loads and evaluates them (`kavach-policy`).
//! Packs are operator-supplied and signed, so this is the least exposed
//! target; it looks for crashes and for inputs that defeat the load limits.
//!
//! Input: an expression, NUL, then the JSON value bound as `request`.
//!
//! Invariants: loading enforces the expression limit (2048 characters);
//! evaluation of a loaded rule either decides or returns an error (which the
//! API records as a BLOCK), never a panic. A hang beyond libFuzzer's timeout
//! is a finding: it becomes a tighter load limit, or a documented gap when
//! no limit can catch it.

#![no_main]

use chrono::{TimeZone, Utc};
use kavach_domain::decision::Decision;
use kavach_domain::types::{CelRuntimeLimits, PolicyPack, PolicyRule};
use kavach_policy::{PackLoader, PolicyEngine};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

/// The documented load limit (docs/SECURITY_PROPERTIES.md: "expressions
/// ≤ 2048 chars").
const MAX_EXPRESSION_CHARS: usize = 2048;

fn pack(expression: &str) -> PolicyPack {
    PolicyPack {
        id: "fuzz".into(),
        version: "1".into(),
        sector: "finance".into(),
        jurisdiction: "IN".into(),
        effective_from: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        description: None,
        cel_runtime_limits: Some(CelRuntimeLimits {
            timeout_ms: 50,
            max_alloc_bytes: 0,
        }),
        rules: vec![PolicyRule {
            id: "r1".into(),
            expression: expression.into(),
            decision: Decision::Block,
            reason_code: "FUZZ".into(),
            severity: None,
            control_mappings: vec![],
        }],
        control_mappings: None,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(2, |b| *b == 0);
    let (Some(expression), Some(input)) = (parts.next(), parts.next()) else {
        return;
    };
    let Ok(expression) = std::str::from_utf8(expression) else {
        return;
    };
    let loaded = PackLoader::load_from_pack(pack(expression));
    if expression.chars().count() > MAX_EXPRESSION_CHARS {
        assert!(loaded.is_err(), "an over-long expression loaded");
        return;
    }
    let Ok(loaded) = loaded else {
        return;
    };
    let value: Value = serde_json::from_slice(input).unwrap_or(Value::Null);
    let now = Utc.with_ymd_and_hms(2026, 10, 1, 5, 30, 0).unwrap();
    let _ = PolicyEngine::evaluate_named(&loaded, "request", &value, now);
});
