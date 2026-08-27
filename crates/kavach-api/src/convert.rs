use chrono::{DateTime, Utc};
use kavach_domain::{Consent, Decision, EvaluateRequest, EvaluateResponse};
use prost_types::value::Kind;
use prost_types::{ListValue, Struct, Timestamp, Value};

use crate::error::ApiError;
use crate::proto::kavach::v1::{
    Decision as ProtoDecision, EvaluateRequest as ProtoEvaluateRequest,
    EvaluateResponse as ProtoEvaluateResponse,
};

pub fn proto_to_domain(request: ProtoEvaluateRequest) -> Result<EvaluateRequest, ApiError> {
    let consent = request
        .consent
        .ok_or_else(|| ApiError::BadRequest("missing consent".into()))?;
    let input = request
        .input
        .ok_or_else(|| ApiError::BadRequest("missing input".into()))?;
    let decision_time = request
        .decision_time
        .ok_or_else(|| ApiError::BadRequest("missing decision_time".into()))?;

    Ok(EvaluateRequest {
        model_id: request.model_id,
        model_version: request.model_version,
        purpose: request.purpose,
        consent: Consent {
            purpose_id: consent.purpose_id,
            timestamp: timestamp_to_datetime(
                consent
                    .timestamp
                    .ok_or_else(|| ApiError::BadRequest("missing consent.timestamp".into()))?,
            )?,
            valid: consent.valid,
        },
        input: struct_to_json(&input),
        output: request.output.as_ref().map(struct_to_json),
        score: request.score,
        confidence: request.confidence,
        decision_time: timestamp_to_datetime(decision_time)?,
        correlation_id: request.correlation_id,
        idempotency_key: request.idempotency_key,
    })
}

pub fn domain_to_proto(response: EvaluateResponse) -> ProtoEvaluateResponse {
    ProtoEvaluateResponse {
        policy_decision: i32::from(domain_decision_to_proto(response.policy_decision)),
        returned_decision: i32::from(domain_decision_to_proto(response.returned_decision)),
        evidence_id: response.evidence_id.unwrap_or_default(),
        reason_codes: response.reason_codes,
        policy_hits: response.policy_hits,
        latency_ms: i64::try_from(response.latency_ms).unwrap_or(i64::MAX),
    }
}

fn domain_decision_to_proto(decision: Decision) -> ProtoDecision {
    match decision {
        Decision::Pass => ProtoDecision::Pass,
        Decision::Alert => ProtoDecision::Alert,
        Decision::Block => ProtoDecision::Block,
        Decision::HumanReview => ProtoDecision::HumanReview,
    }
}

fn timestamp_to_datetime(ts: Timestamp) -> Result<DateTime<Utc>, ApiError> {
    DateTime::from_timestamp(ts.seconds, ts.nanos.cast_unsigned())
        .ok_or_else(|| ApiError::BadRequest("invalid timestamp".into()))
}

fn struct_to_json(value: &Struct) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (key, field) in &value.fields {
        map.insert(key.clone(), prost_value_to_json(field));
    }
    serde_json::Value::Object(map)
}

fn prost_value_to_json(value: &Value) -> serde_json::Value {
    match value.kind.as_ref() {
        Some(Kind::NullValue(_)) | None => serde_json::Value::Null,
        Some(Kind::BoolValue(v)) => serde_json::Value::Bool(*v),
        Some(Kind::NumberValue(v)) => serde_json::Number::from_f64(*v)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Some(Kind::StringValue(v)) => serde_json::Value::String(v.clone()),
        Some(Kind::StructValue(v)) => struct_to_json(v),
        Some(Kind::ListValue(ListValue { values })) => {
            serde_json::Value::Array(values.iter().map(prost_value_to_json).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::kavach::v1::EvaluateRequest as ProtoEvaluateRequest;

    #[test]
    fn round_trip_clean_fixture_fields() {
        let now = Utc::now();
        let ts = Timestamp {
            seconds: now.timestamp(),
            nanos: now.timestamp_subsec_nanos().cast_signed(),
        };
        let mut input = Struct::default();
        input.fields.insert(
            "debt_ratio".into(),
            Value {
                kind: Some(Kind::NumberValue(0.32)),
            },
        );

        let proto = ProtoEvaluateRequest {
            model_id: "credit-underwriting-v1".into(),
            model_version: "1.0.0".into(),
            purpose: "credit_decision".into(),
            consent: Some(crate::proto::kavach::v1::Consent {
                purpose_id: "credit_decision".into(),
                timestamp: Some(ts),
                valid: None,
            }),
            input: Some(input),
            output: None,
            score: None,
            confidence: Some(0.89),
            decision_time: Some(ts),
            correlation_id: "grpc-test-001".into(),
            idempotency_key: None,
        };

        let domain = proto_to_domain(proto).expect("convert");
        assert_eq!(domain.model_id, "credit-underwriting-v1");
        assert_eq!(domain.input["debt_ratio"], 0.32);
    }
}
