//! RFC 8785 (JCS) as Kavach signs it (`kavach_ports::jcs`), against a small
//! reference serialiser written here from the RFC. The authority is the
//! Node `canonicalize` cross-check in CI; this target looks for inputs where
//! the two Rust implementations disagree.
//!
//! Invariants: both refuse exactly the same values (numbers that are not
//! safe integers); otherwise their bytes are identical, and canonicalising
//! the output again changes nothing.

#![no_main]

use std::cmp::Ordering;
use std::fmt::Write as _;

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

const MAX_SAFE: u64 = (1 << 53) - 1;

/// RFC 8785 §3.2.2.2: escape `"`, `\` and controls; everything else is
/// written as is.
fn string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// RFC 8785 §3.2.3: property names ordered by UTF-16 code units.
fn utf16_order(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn reference(out: &mut String, value: &Value) -> Option<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let safe = n.as_u64().is_some_and(|u| u <= MAX_SAFE)
                || n.as_i64().is_some_and(|i| i.unsigned_abs() <= MAX_SAFE);
            if !safe {
                return None;
            }
            let _ = write!(out, "{n}");
        }
        Value::String(s) => string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                reference(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_order(a, b));
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(out, key);
                out.push(':');
                reference(out, &map[key])?;
            }
            out.push('}');
        }
    }
    Some(())
}

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let mut expected = String::new();
    let expected = reference(&mut expected, &value).map(|()| expected);
    let actual = kavach_ports::jcs::to_vec(&value);
    match (actual, expected) {
        (Ok(bytes), Some(expected)) => {
            assert_eq!(
                String::from_utf8(bytes.clone()).expect("JCS output is UTF-8"),
                expected,
                "the implementations disagree"
            );
            let again: Value = serde_json::from_slice(&bytes).expect("JCS output parses");
            assert_eq!(kavach_ports::jcs::to_vec(&again).unwrap(), bytes, "not idempotent");
        }
        (Err(_), None) => {}
        (actual, expected) => panic!(
            "only one refused: kavach {:?}, reference {}",
            actual.map(String::from_utf8),
            if expected.is_some() { "accepted" } else { "refused" }
        ),
    }
});
