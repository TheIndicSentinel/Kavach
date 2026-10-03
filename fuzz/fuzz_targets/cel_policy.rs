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
//!
//! Kavach contains panics inside the third-party CEL parser and interpreter
//! (`kavach-policy`'s `contained`): they become a refused pack or a recorded
//! BLOCK. libFuzzer's panic hook aborts on every panic, even a caught one,
//! so this target lets panics raised inside those crates pass; any other
//! panic, and any panic that escapes, still fails the run.

#![no_main]

use std::sync::Once;

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

/// Crates whose panics Kavach contains.
const CONTAINED: [&str; 3] = ["antlr4rust", "cel-parser", "cel-interpreter"];

fn let_contained_panics_pass() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let libfuzzer = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let contained = info
                .location()
                .is_some_and(|l| CONTAINED.iter().any(|c| l.file().contains(c)));
            if !contained {
                libfuzzer(info);
            }
        }));
    });
}

fuzz_target!(|data: &[u8]| {
    let_contained_panics_pass();
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
