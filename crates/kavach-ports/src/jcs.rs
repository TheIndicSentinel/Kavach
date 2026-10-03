//! RFC 8785 (JCS) bytes for everything Kavach signs or hashes as evidence:
//! JWS headers and payloads, credential claims and JWE headers, agent
//! evidence records, checkpoints, bundle manifests, and the parameters a
//! decision binds.
//!
//! Numbers are restricted to safe integers (RFC 7493 §2.2: magnitude at
//! most 2^53 − 1). JCS writes numbers the way ECMAScript does, and that is
//! where implementations disagree: fractions, exponents, `-0` and integers
//! too large for an IEEE 754 double. No signed type has a fraction, so
//! refusing every other number removes that risk instead of testing for it.
//! A value that breaks the rule is refused before anything is signed or
//! accepted.

use serde::Serialize;
use serde_json::Value;

use crate::PortError;

/// The largest integer every JCS implementation represents exactly.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Whether `n` is an integer of magnitude at most [`MAX_SAFE_INTEGER`].
#[must_use]
pub fn is_safe_integer(n: &serde_json::Number) -> bool {
    if let Some(i) = n.as_i64() {
        i.unsigned_abs() <= MAX_SAFE_INTEGER
    } else {
        n.as_u64().is_some_and(|u| u <= MAX_SAFE_INTEGER)
    }
}

/// JCS bytes of `value`. `Invalid` when it holds a number that is not a
/// safe integer, or cannot be represented as JSON.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, PortError> {
    let value = serde_json::to_value(value)
        .map_err(|e| PortError::invalid(format!("canonical json: {e}")))?;
    let mut pending = vec![&value];
    while let Some(item) = pending.pop() {
        match item {
            Value::Number(n) if !is_safe_integer(n) => {
                return Err(PortError::invalid(format!(
                    "canonical json: {n} is not a safe integer (fractions, exponents and \
                     magnitudes over 2^53 - 1 are not signed)"
                )));
            }
            Value::Array(items) => pending.extend(items),
            Value::Object(map) => pending.extend(map.values()),
            _ => {}
        }
    }
    serde_json_canonicalizer::to_vec(&value)
        .map_err(|e| PortError::invalid(format!("canonical json: {e}")))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn integers_within_the_safe_range_are_canonical() {
        let bytes = to_vec(
            &json!({ "b": [9_007_199_254_740_991_u64, -9_007_199_254_740_991_i64, 0], "a": 1 }),
        )
        .unwrap();
        assert_eq!(
            bytes,
            br#"{"a":1,"b":[9007199254740991,-9007199254740991,0]}"#
        );
    }

    #[test]
    fn other_numbers_are_refused_wherever_they_are() {
        for value in [
            json!(1.5),
            json!(1.0),
            json!(-0.0),
            json!(1e300),
            json!(9_007_199_254_740_992_u64),
            json!(-9_007_199_254_740_992_i64),
            json!(u64::MAX),
            json!({ "a": { "b": [1, 2, 0.1] } }),
        ] {
            let err = to_vec(&value).unwrap_err();
            assert!(
                err.message.contains("not a safe integer"),
                "{value}: {err:?}"
            );
        }
    }

    #[test]
    fn matches_the_canonicaliser_for_everything_else() {
        let value =
            json!({ "z": "é\u{1F600}\n\"", "a": [true, null, { "y": 1, "x": "" }], "€": 2 });
        assert_eq!(
            to_vec(&value).unwrap(),
            serde_json_canonicalizer::to_vec(&value).unwrap()
        );
    }
}
