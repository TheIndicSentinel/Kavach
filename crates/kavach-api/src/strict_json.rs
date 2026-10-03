//! Request bodies that carry free-form JSON are parsed strictly.
//!
//! serde_json's `raw_value` feature (switched on by axum and sqlx, so it
//! cannot be turned off) gives one object key a special meaning: when a
//! generic JSON value (`serde_json::Value`) is parsed and an object's first
//! key is `$serde_json::private::RawValue`, the key's value is read as a
//! string of JSON and that is parsed instead. Kavach would then act on a
//! structure that a WAF, a log or another parser does not see in the same
//! bytes. This module refuses any body that uses the key, anywhere and in
//! any position, escaped forms included (keys are compared after
//! unescaping), before the body is parsed into its type.
//!
//! It applies to the bodies with free-form JSON fields: `/v1/evaluate`
//! (`input`, `output`), `/v1/authorize` and `/v1/tools/{tool}` (`params`)
//! and change proposals (`params`). Fixed-shape bodies (SoR events,
//! approvals, rejections) are structs that refuse unknown fields; the key
//! has no special meaning there.

use std::borrow::Cow;
use std::fmt;

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::de::{self, Deserialize, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;

use crate::error::ApiError;

/// serde_json's private marker for raw values.
pub const RAW_VALUE_KEY: &str = "$serde_json::private::RawValue";
const FOUND: &str = "kavach: raw-value key";

/// Walks a document without building it, failing on the marker key.
struct Walk;

impl<'de> Deserialize<'de> for Walk {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(WalkVisitor)
    }
}

struct WalkVisitor;

impl<'de> Visitor<'de> for WalkVisitor {
    type Value = Walk;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Walk, E> {
        Ok(Walk)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Walk, E> {
        Ok(Walk)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Walk, E> {
        Ok(Walk)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Walk, E> {
        Ok(Walk)
    }
    fn visit_str<E>(self, _: &str) -> Result<Walk, E> {
        Ok(Walk)
    }
    fn visit_unit<E>(self) -> Result<Walk, E> {
        Ok(Walk)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Walk, A::Error> {
        while seq.next_element::<Walk>()?.is_some() {}
        Ok(Walk)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Walk, A::Error> {
        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
            if key == RAW_VALUE_KEY {
                return Err(de::Error::custom(FOUND));
            }
            map.next_value::<Walk>()?;
        }
        Ok(Walk)
    }
}

/// Whether `body` is JSON that uses the raw-value key. Bodies that are not
/// JSON at all are left to the normal parser and its error.
#[must_use]
pub fn uses_raw_value_key(body: &[u8]) -> bool {
    matches!(serde_json::from_slice::<Walk>(body), Err(e) if e.to_string().contains(FOUND))
}

/// The refusal message: names the key, never echoes a value.
pub fn refusal_message() -> String {
    format!("the JSON key {RAW_VALUE_KEY} is not accepted")
}

/// Why [`StrictJson`] refused a body.
#[derive(Debug)]
pub enum StrictJsonRejection {
    /// What `axum::Json` would have refused (content type, syntax, shape).
    Json(JsonRejection),
    /// The body uses the raw-value key.
    RawValueKey,
}

impl IntoResponse for StrictJsonRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Json(rejection) => rejection.into_response(),
            Self::RawValueKey => ApiError::BadRequest(refusal_message()).into_response(),
        }
    }
}

/// `axum::Json`, plus the raw-value check. Content type, syntax and shape
/// errors are axum's own, unchanged.
#[derive(Debug)]
pub struct StrictJson<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for StrictJson<T> {
    type Rejection = StrictJsonRejection;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(raw) = Json::<Box<RawValue>>::from_request(request, state)
            .await
            .map_err(StrictJsonRejection::Json)?;
        if uses_raw_value_key(raw.get().as_bytes()) {
            return Err(StrictJsonRejection::RawValueKey);
        }
        let Json(value) =
            Json::<T>::from_bytes(raw.get().as_bytes()).map_err(StrictJsonRejection::Json)?;
        Ok(Self(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_found_anywhere_and_in_escaped_form() {
        for body in [
            r#"{"$serde_json::private::RawValue":"{\"a\":1}"}"#,
            r#"{"a":1,"$serde_json::private::RawValue":"1"}"#,
            r#"{"params":{"subject_ref":{"$serde_json::private::RawValue":"\"ref:x:y\""}}}"#,
            r#"[1,{"b":[{"$serde_json::private::RawValue":"2"}]}]"#,
            r#"{"$serde_json::private::RawValue":"1"}"#,
        ] {
            assert!(uses_raw_value_key(body.as_bytes()), "{body}");
        }
    }

    #[test]
    fn ordinary_and_non_json_bodies_pass_through() {
        for body in [
            &br#"{"a":{"b":[1,2.5,"x",null,true]},"$other":1}"#[..],
            br#""$serde_json::private::RawValue""#,
            br#"{"x":"$serde_json::private::RawValue"}"#,
            b"not json",
            b"",
        ] {
            assert!(
                !uses_raw_value_key(body),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    /// The quirk this guards against: serde_json reads the key's value as a
    /// string of JSON when it builds a generic value.
    #[test]
    fn serde_json_does_parse_the_key_specially() {
        let parsed: serde_json::Value =
            serde_json::from_str(r#"{"$serde_json::private::RawValue":"[1,2]"}"#).unwrap();
        assert_eq!(parsed, serde_json::json!([1, 2]));
    }
}
