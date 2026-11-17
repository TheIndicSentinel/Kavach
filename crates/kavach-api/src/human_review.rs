//! Authenticated D17 reviewer reads. Clear action details are returned only
//! from the tenant-scoped encrypted snapshot, never from general evidence.

use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use kavach_auth::KavachAction;
use kavach_dataplane::{EncryptedReviewSnapshot, ReviewActionSnapshot};
use kavach_ports::agent_evidence::{check_record_signature, AgentDecisionRecord};
use kavach_ports::{
    EncryptedReviewSnapshot as StoredReviewSnapshot, ReviewApprovalRecord, ReviewApprovalStore,
    ReviewDecision, ReviewSnapshotStore, VerifiedStepUp,
};
use kavach_storage::AuditInsert;
use serde::Serialize;
use serde_json::json;

use crate::auth::{authorize_credentials, Credentials};
use crate::dataplane::REVIEW_SNAPSHOT_TTL_SECONDS;
use crate::error::ApiError;
use crate::state::AppState;

const READS_PER_SECOND: f64 = 5.0;
const BURST: f64 = 20.0;
const APPROVAL_TTL_SECONDS: i64 = 300;

struct Bucket {
    tokens: f64,
    last: Instant,
}

fn take_read() -> bool {
    static BUCKET: OnceLock<Mutex<Bucket>> = OnceLock::new();
    let bucket = BUCKET.get_or_init(|| {
        Mutex::new(Bucket {
            tokens: BURST,
            last: Instant::now(),
        })
    });
    let Ok(mut bucket) = bucket.lock() else {
        return false;
    };
    let now = Instant::now();
    bucket.tokens = (bucket.tokens
        + now.duration_since(bucket.last).as_secs_f64() * READS_PER_SECOND)
        .min(BURST);
    bucket.last = now;
    if bucket.tokens < 1.0 {
        return false;
    }
    bucket.tokens -= 1.0;
    true
}

#[derive(Serialize)]
pub struct HumanReviewSnapshotView {
    pub record_id: String,
    pub action_hash: String,
    pub agent_id: String,
    pub action: String,
    pub subject_ref: String,
    pub channel: Option<String>,
    pub waiver_bps: Option<i64>,
    pub requested_fields: std::collections::BTreeSet<String>,
    pub parameters: std::collections::BTreeMap<String, String>,
    pub expires_at: DateTime<Utc>,
}

impl HumanReviewSnapshotView {
    fn from_snapshot(
        mut snapshot: ReviewActionSnapshot,
        record_id: &str,
        action_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            record_id: record_id.to_owned(),
            action_hash: action_hash.to_owned(),
            agent_id: std::mem::take(&mut snapshot.agent_id),
            action: std::mem::take(&mut snapshot.action),
            subject_ref: std::mem::take(&mut snapshot.subject_ref),
            channel: snapshot.channel.take(),
            waiver_bps: snapshot.waiver_bps,
            requested_fields: std::mem::take(&mut snapshot.requested_fields),
            parameters: std::mem::take(&mut snapshot.parameters),
            expires_at,
        }
    }
}

impl Drop for HumanReviewSnapshotView {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.record_id.zeroize();
        self.action_hash.zeroize();
        self.agent_id.zeroize();
        self.action.zeroize();
        self.subject_ref.zeroize();
        if let Some(channel) = &mut self.channel {
            channel.zeroize();
        }
        for mut field in std::mem::take(&mut self.requested_fields) {
            field.zeroize();
        }
        for (mut name, mut value) in std::mem::take(&mut self.parameters) {
            name.zeroize();
            value.zeroize();
        }
    }
}

fn open_snapshot(
    key: &crate::review_snapshot_key::ReviewSnapshotKey,
    record: &AgentDecisionRecord,
    stored: &StoredReviewSnapshot,
    tenant_id: &str,
    now: DateTime<Utc>,
    evidence_keys: &std::collections::BTreeMap<String, kavach_ports::PublicKey>,
    allow_dev_keys: bool,
) -> Result<HumanReviewSnapshotView, ApiError> {
    check_record_signature(record, evidence_keys, allow_dev_keys)
        .map_err(|_| ApiError::NotFound("no eligible HUMAN_REVIEW record".into()))?;
    let action_hash = record
        .payload
        .review_action_hash
        .as_deref()
        .filter(|hash| !hash.is_empty())
        .ok_or_else(|| ApiError::NotFound("no eligible HUMAN_REVIEW record".into()))?;
    if record.payload.tenant_id != tenant_id
        || record.payload.policy_decision != kavach_domain::Decision::HumanReview
        || record.payload.returned_decision != kavach_domain::Decision::HumanReview
        || stored.tenant_id != tenant_id
        || stored.record_id != record.payload.record_id
        || stored.action_hash != action_hash
    {
        return Err(ApiError::NotFound("no eligible HUMAN_REVIEW record".into()));
    }
    let expected_expiry = record
        .payload
        .ts
        .checked_add_signed(Duration::seconds(REVIEW_SNAPSHOT_TTL_SECONDS))
        .ok_or_else(|| ApiError::NotFound("no eligible HUMAN_REVIEW record".into()))?;
    if stored.expires_at != expected_expiry || stored.expires_at <= now {
        return Err(ApiError::NotFound("no eligible HUMAN_REVIEW record".into()));
    }
    let envelope = EncryptedReviewSnapshot {
        version: stored.version,
        key_id: stored.key_id.clone(),
        tenant_id: stored.tenant_id.clone(),
        record_id: stored.record_id.clone(),
        action_hash: stored.action_hash.clone(),
        nonce: stored.nonce,
        ciphertext: stored.ciphertext.clone(),
    };
    let snapshot = key
        .open(&envelope, tenant_id, &record.payload.record_id, action_hash)
        .map_err(|_| ApiError::NotFound("no eligible HUMAN_REVIEW record".into()))?;
    let registry_digest = record
        .payload
        .policy_versions
        .tools
        .as_deref()
        .ok_or_else(|| ApiError::NotFound("no eligible HUMAN_REVIEW record".into()))?;
    if snapshot.tenant_id != tenant_id
        || snapshot.agent_id != record.payload.actor.agent_id
        || snapshot.identity_key != record.payload.actor.identity_key
        || snapshot.action != record.payload.action
        || snapshot.mandate_id != record.payload.mandate_id
        || snapshot.request_id != record.payload.request_id
        || snapshot.tool_registry_digest != registry_digest
    {
        return Err(ApiError::NotFound("no eligible HUMAN_REVIEW record".into()));
    }
    Ok(HumanReviewSnapshotView::from_snapshot(
        snapshot,
        &record.payload.record_id,
        action_hash,
        stored.expires_at,
    ))
}

/// `GET /auth/human-review/{record_id}`: return the minimum exact-action
/// projection needed for a reviewer to inspect a live HUMAN_REVIEW record.
pub async fn read(
    State(state): State<std::sync::Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(record_id): Path<String>,
    credentials: Credentials,
) -> Response {
    match read_inner(&state, &headers, &record_id, &credentials).await {
        Ok(view) => Json(view).into_response(),
        Err(error) => error.into_response(),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecisionBody {
    pub decision: ReviewDecision,
}

#[derive(Serialize)]
pub struct ApprovalCreated {
    pub approval_id: String,
    pub execution_id: Option<String>,
    pub decision: ReviewDecision,
    pub expires_at: DateTime<Utc>,
}

/// `POST /auth/human-review/{record_id}/approval`: records one explicit
/// decision after reloading the signed action and consuming its session proof.
pub async fn approve(
    State(state): State<std::sync::Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(record_id): Path<String>,
    credentials: Credentials,
    body: Result<Json<ApprovalDecisionBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    match approve_inner(&state, &headers, &record_id, &credentials, body).await {
        Ok(created) => Json(created).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn approve_inner(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    record_id: &str,
    credentials: &Credentials,
    body: Result<Json<ApprovalDecisionBody>, axum::extract::rejection::JsonRejection>,
) -> Result<ApprovalCreated, ApiError> {
    let login = state.console_login().ok_or_else(|| {
        ApiError::Unavailable("console reviewer session is not configured".into())
    })?;
    // The router's cookie_step middleware checks the console marker and
    // same-origin headers before it injects the session bearer token.
    let session_cookie =
        cookie(headers, crate::console_login::SESSION_COOKIE).ok_or(ApiError::Unauthorized)?;
    let principal = login
        .step_up_principal_key(session_cookie)
        .map_err(|_| ApiError::Unauthorized)?;
    let authorization =
        authorize_credentials(state, credentials, KavachAction::ApproveHumanReview).await?;
    let Json(ApprovalDecisionBody { decision }) =
        body.map_err(|_| ApiError::BadRequest("malformed human-review decision".into()))?;

    // Reload and re-verify the signed record and encrypted snapshot at the
    // decision boundary. This also enforces the current Cedar permission.
    let view = read_inner(state, headers, record_id, credentials).await?;
    let now = Utc::now();
    let proof = login
        .take_verified_step_up(session_cookie, &view.action_hash)
        .map_err(|_| ApiError::Conflict("fresh exact-action step-up is required".into()))?;
    let approval =
        build_approval_record(&view, state.tenant_id(), &principal, proof, decision, now)?;
    let created = ApprovalCreated {
        approval_id: approval.approval_id.clone(),
        execution_id: approval.execution_id.clone(),
        decision,
        expires_at: approval.expires,
    };

    // Audit before inserting an actionable record; an audit outage fails
    // closed and cannot leave an approval that downstream callers can use.
    state
        .admin()
        .append_audit(AuditInsert {
            acting_as_superadmin: authorization.acting_as_superadmin,
            action: "create_human_review_approval".into(),
            resource_type: "human_review_approval".into(),
            resource_id: approval.approval_id.clone(),
            actor_principal: principal.clone(),
            approver_principal: principal,
            payload: json!({
                "decision": match decision {
                    ReviewDecision::Approve => "approve",
                    ReviewDecision::Reject => "reject",
                },
                "record_id": record_id,
                "action_hash": approval.action_hash,
            }),
        })
        .await
        .map_err(|_| ApiError::Unavailable("human-review decision could not be audited".into()))?;
    state
        .review_approval_store()
        .insert(approval)
        .await
        .map_err(|_| ApiError::Unavailable("human-review approval store is unavailable".into()))?;
    Ok(created)
}

fn build_approval_record(
    view: &HumanReviewSnapshotView,
    expected_tenant: &str,
    principal: &str,
    proof: VerifiedStepUp,
    decision: ReviewDecision,
    now: DateTime<Utc>,
) -> Result<ReviewApprovalRecord, ApiError> {
    if proof.tenant_id != expected_tenant
        || proof.principal_key != principal
        || proof.action_hash != view.action_hash
        || proof.verified_at > now
    {
        return Err(ApiError::Conflict(
            "step-up proof does not match this review".into(),
        ));
    }
    let proof_expiry = proof
        .verified_at
        .checked_add_signed(Duration::seconds(APPROVAL_TTL_SECONDS))
        .ok_or_else(|| ApiError::Conflict("step-up proof has expired".into()))?;
    let expires = view.expires_at.min(proof_expiry);
    if expires <= now {
        return Err(ApiError::Conflict("step-up proof has expired".into()));
    }
    let rendered_action = serde_json::to_string(view)
        .map_err(|_| ApiError::Internal("review action rendering failed".into()))?;
    let approval = ReviewApprovalRecord {
        tenant_id: proof.tenant_id,
        approval_id: uuid::Uuid::new_v4().to_string(),
        review_record_id: view.record_id.clone(),
        execution_id: (decision == ReviewDecision::Approve)
            .then(|| uuid::Uuid::new_v4().to_string()),
        action_hash: view.action_hash.clone(),
        rendered_action,
        approver: principal.to_owned(),
        step_up_ref: proof.step_up_ref,
        decision,
        single_use_credential_id: (decision == ReviewDecision::Approve)
            .then(|| uuid::Uuid::new_v4().to_string()),
        expires,
    };
    approval
        .validate()
        .map_err(|_| ApiError::Internal("human-review approval was invalid".into()))?;
    Ok(approval)
}

async fn read_inner(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    record_id: &str,
    credentials: &Credentials,
) -> Result<HumanReviewSnapshotView, ApiError> {
    let login = state.console_login().ok_or_else(|| {
        ApiError::Unavailable("console reviewer session is not configured".into())
    })?;
    let session_cookie =
        cookie(headers, crate::console_login::SESSION_COOKIE).ok_or(ApiError::Unauthorized)?;
    let principal = login
        .step_up_principal_key(session_cookie)
        .map_err(|_| ApiError::Unauthorized)?;
    if state.access_control().is_none() {
        return Err(ApiError::Unavailable(
            "review access control is not configured".into(),
        ));
    }
    let authorization =
        authorize_credentials(state, credentials, KavachAction::ApproveHumanReview).await?;
    if !crate::evidence_read::valid_record_id(record_id) {
        return Err(ApiError::BadRequest(
            "record_id must be adr:<tenant>:<partition>:<seq>".into(),
        ));
    }
    if !take_read() {
        return Err(ApiError::Unavailable(
            "review reads are temporarily rate limited".into(),
        ));
    }
    let key = state.review_snapshot_key().ok_or_else(|| {
        ApiError::Unavailable("review snapshot encryption is not configured".into())
    })?;
    let dataplane = state
        .dataplane()
        .ok_or_else(|| ApiError::NotFound("no eligible HUMAN_REVIEW record".into()))?;
    let record = dataplane
        .human_review_record(record_id)
        .await
        .map_err(|_| ApiError::Unavailable("review evidence is unavailable".into()))?;
    let now = Utc::now();
    let stored = state
        .review_snapshot_store()
        .get_live(state.tenant_id(), record_id, now)
        .await
        .map_err(|_| ApiError::Unavailable("review snapshot store is unavailable".into()))?;
    let Some(record) = record else {
        audit_read(
            state,
            &principal,
            record_id,
            false,
            authorization.acting_as_superadmin,
        )
        .await?;
        return Err(ApiError::NotFound("no eligible HUMAN_REVIEW record".into()));
    };
    let Some(stored) = stored else {
        audit_read(
            state,
            &principal,
            record_id,
            false,
            authorization.acting_as_superadmin,
        )
        .await?;
        return Err(ApiError::NotFound("no eligible HUMAN_REVIEW record".into()));
    };
    let view = open_snapshot(
        key,
        &record,
        &stored,
        state.tenant_id(),
        now,
        dataplane.review_evidence_keys(),
        state.insecure_dev(),
    );
    audit_read(
        state,
        &principal,
        record_id,
        view.is_ok(),
        authorization.acting_as_superadmin,
    )
    .await?;
    view
}

async fn audit_read(
    state: &AppState,
    principal: &str,
    record_id: &str,
    found: bool,
    acting_as_superadmin: bool,
) -> Result<(), ApiError> {
    state
        .admin()
        .append_audit(AuditInsert {
            acting_as_superadmin,
            action: "read_human_review_snapshot".into(),
            resource_type: "human_review_snapshot".into(),
            resource_id: record_id.into(),
            actor_principal: principal.into(),
            approver_principal: String::new(),
            payload: json!({ "found": found }),
        })
        .await
        .map(|_| ())
        .map_err(|_| ApiError::Unavailable("review read could not be audited".into()))
}

fn cookie<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(cookie_name, _)| *cookie_name == name)
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use chrono::TimeZone;
    use kavach_domain::Decision;
    use kavach_ports::agent_evidence::{
        payload_hash, signing_message, Actor, AgentDecisionPayload, AgentDecisionRecord,
        PolicyVersions, TimeSync, HASH_ALG_V2, KIND_AGENT_DECISION,
    };
    use kavach_ports::{KeyAlgorithm, PublicKey};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;

    fn signed_review(
        snapshot: &ReviewActionSnapshot,
        at: DateTime<Utc>,
    ) -> (AgentDecisionRecord, BTreeMap<String, PublicKey>) {
        let keypair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).expect("seed");
        let payload = AgentDecisionPayload {
            record_id: "adr:tenant-1:0:1".into(),
            tenant_id: "tenant-1".into(),
            partition_id: 0,
            seq: 1,
            prev_hash: "0".repeat(64),
            kind: KIND_AGENT_DECISION.into(),
            hash_alg: HASH_ALG_V2.into(),
            key_id: "evidence-key-1".into(),
            actor: Actor {
                agent_id: snapshot.agent_id.clone(),
                identity_key: snapshot.identity_key.clone(),
            },
            chain: vec!["mandate-1".into()],
            mandate_id: snapshot.mandate_id.clone(),
            purpose: "loan_recovery".into(),
            consent_refs: vec![],
            action: snapshot.action.clone(),
            request_id: snapshot.request_id.clone(),
            subject_pseudonym: "psn:review-subject".into(),
            params_mac: None,
            review_action_hash: Some(snapshot.action_hash().expect("action hash")),
            policy_versions: PolicyVersions {
                cedar: "sha256:cedar".into(),
                cel: None,
                packs: vec![],
                tools: Some(snapshot.tool_registry_digest.clone()),
                build: "test".into(),
            },
            signals: vec!["escalated".into()],
            pre_commit_decision: Decision::HumanReview,
            policy_decision: Decision::HumanReview,
            returned_decision: Decision::HumanReview,
            obligations: vec![],
            credential_id: None,
            credential_expires_at: None,
            send_by: None,
            time_sync: TimeSync {
                status: "synced".into(),
                max_error_ms: Some(1),
            },
            ts: at,
        };
        let hash = payload_hash(&payload).expect("payload hash");
        let sig = hex::encode(keypair.sign(&signing_message(&hash)).as_ref());
        let record = AgentDecisionRecord { payload, hash, sig };
        let public = PublicKey {
            kid: "evidence-key-1".into(),
            algorithm: KeyAlgorithm::Ed25519,
            bytes: keypair
                .public_key()
                .as_ref()
                .try_into()
                .expect("public key"),
        };
        (record, BTreeMap::from([(public.kid.clone(), public)]))
    }

    #[test]
    fn opens_only_signed_tenant_action_bound_snapshot_and_returns_display_fields() {
        let now = Utc.with_ymd_and_hms(2026, 11, 17, 12, 0, 0).unwrap();
        let snapshot = ReviewActionSnapshot {
            tenant_id: "tenant-1".into(),
            agent_id: "collections-agent".into(),
            identity_key: "oidc:https://agent.example#collections-agent".into(),
            tool_registry_digest: "sha256:tools".into(),
            mandate_id: "mandate-1".into(),
            request_id: "request-1".into(),
            action: "propose_plan".into(),
            subject_ref: "ref:borrower:B-9382".into(),
            channel: None,
            waiver_bps: Some(3500),
            requested_fields: Default::default(),
            parameters: Default::default(),
        };
        let (record, keys) = signed_review(&snapshot, now);
        let path =
            std::env::temp_dir().join(format!("kavach-review-read-{}.key", uuid::Uuid::new_v4()));
        fs::write(&path, hex::encode([9; 32])).expect("write key");
        let key = crate::review_snapshot_key::ReviewSnapshotKey::from_file(&path, "review-v1")
            .expect("load key");
        let _ = fs::remove_file(path);
        let action_hash = snapshot.action_hash().expect("action hash");
        let sealed = key
            .seal(&snapshot, &record.payload.record_id, &action_hash)
            .expect("seal");
        let stored = StoredReviewSnapshot {
            version: sealed.version,
            key_id: sealed.key_id,
            tenant_id: sealed.tenant_id,
            record_id: sealed.record_id,
            action_hash,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            expires_at: now + Duration::seconds(REVIEW_SNAPSHOT_TTL_SECONDS),
        };
        let view =
            open_snapshot(&key, &record, &stored, "tenant-1", now, &keys, false).expect("open");
        let json = serde_json::to_value(&view).expect("serialize");
        assert_eq!(json["action"], "propose_plan");
        assert_eq!(json["waiver_bps"], 3500);
        for hidden in [
            "tenant_id",
            "identity_key",
            "tool_registry_digest",
            "mandate_id",
            "request_id",
        ] {
            assert!(
                json.get(hidden).is_none(),
                "unexpected response field {hidden}"
            );
        }
        let mut bad_signature = record;
        bad_signature.sig = "00".into();
        assert!(
            open_snapshot(&key, &bad_signature, &stored, "tenant-1", now, &keys, false,).is_err()
        );
    }

    #[test]
    fn approval_record_requires_exact_live_step_up_and_is_short_lived() {
        let now = Utc.with_ymd_and_hms(2026, 11, 17, 12, 0, 0).unwrap();
        let view = HumanReviewSnapshotView {
            record_id: "adr:tenant-1:0:1".into(),
            action_hash: format!("sha256-action-v1:{}", "a".repeat(64)),
            agent_id: "agent-1".into(),
            action: "propose_plan".into(),
            subject_ref: "ref:borrower:B-1".into(),
            channel: None,
            waiver_bps: Some(3500),
            requested_fields: Default::default(),
            parameters: Default::default(),
            expires_at: now + Duration::minutes(30),
        };
        let proof = VerifiedStepUp {
            tenant_id: "tenant-1".into(),
            principal_key: "oidc:https://idp.example#reviewer".into(),
            action_hash: view.action_hash.clone(),
            step_up_ref: "webauthn:opaque-ref".into(),
            verified_at: now - Duration::seconds(1),
        };
        let approval = build_approval_record(
            &view,
            "tenant-1",
            &proof.principal_key,
            proof.clone(),
            ReviewDecision::Approve,
            now,
        )
        .expect("bound approval");
        assert_eq!(approval.action_hash, view.action_hash);
        assert_eq!(approval.tenant_id, "tenant-1");
        assert_eq!(approval.review_record_id, view.record_id);
        assert!(approval.execution_id.is_some());
        assert!(approval.single_use_credential_id.is_some());
        assert!(approval.expires <= now + Duration::seconds(APPROVAL_TTL_SECONDS));
        assert!(approval.rendered_action.contains("propose_plan"));

        let rejected = build_approval_record(
            &view,
            "tenant-1",
            &proof.principal_key,
            proof.clone(),
            ReviewDecision::Reject,
            now,
        )
        .expect("bound rejection");
        assert!(rejected.execution_id.is_none());
        assert!(rejected.single_use_credential_id.is_none());

        assert!(build_approval_record(
            &view,
            "tenant-other",
            &proof.principal_key,
            proof.clone(),
            ReviewDecision::Approve,
            now,
        )
        .is_err());
        let mut mismatched = proof;
        mismatched.action_hash = format!("sha256-action-v1:{}", "b".repeat(64));
        assert!(build_approval_record(
            &view,
            "tenant-1",
            "oidc:https://idp.example#reviewer",
            mismatched,
            ReviewDecision::Approve,
            now,
        )
        .is_err());
    }
}
