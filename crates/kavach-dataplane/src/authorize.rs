//! The authorization core (ADR-003, ADR-007, H5a-4).
//!
//! Effective authority = verified mandate chain ∩ policy (Cedar) ∩ trusted
//! time ∩ stored counters, with the parameters checked for raw identifiers.
//! Two modes:
//!
//! - **Commit** (the gateway, in-process): the decision is written through
//!   the one-transaction evidence commit; only a committed allow yields a
//!   credential grant.
//! - **Pre-check** (`/v1/authorize`): the same decision, but nothing is
//!   reserved or recorded — it authorises nothing (metrics only).
//!
//! Every failure is BLOCK-shaped: a dependency that is down yields
//! `BLOCK` + `dependency_unavailable`, never an error a client could retry
//! or forward on.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Duration, FixedOffset, NaiveDate, NaiveTime, TimeZone, Utc};
use kavach_authz::{ist_date, AgentAction, AgentAuthorizer, AgentState, AuthzRequest};
use kavach_domain::mandate::{is_capability_ref, Mandate, CONTACT_ACTIONS, CONTACT_FLOOR_TO_MIN};
use kavach_domain::Decision;
use kavach_keys::SubjectKeys;
use kavach_ports::agent_evidence::{
    is_allow, sign_outcome, Actor, AgentDecisionPayload, AgentDecisionRecord, AgentEvidenceStore,
    CommitRequest, CommitResult, ContactReservation, EvidenceSigner, Outcome, OutcomeRecord,
    PolicyVersions, RequestBinding, TimeSync, HASH_ALG_V2, KIND_AGENT_DECISION,
};
use kavach_ports::{ErrorClass, PortError, TimeSource, TrustedNow};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::detect::{raw_identifier, reference_identifier};
use crate::tools::ToolRegistry;

/// Loads and verifies a mandate (and its whole chain) by id.
pub trait MandateVerifier: Send + Sync {
    /// The mandate and its chain of ids from the root.
    fn verify(
        &self,
        tenant_id: &str,
        mandate_id: &str,
    ) -> impl Future<Output = Result<(Mandate, Vec<String>), PortError>> + Send;
}

impl<K, R, C, S, E, T> MandateVerifier for kavach_mandate::MandateService<K, R, C, S, E, T>
where
    K: kavach_ports::KeyProvider,
    R: kavach_ports::ReplayGuard,
    C: kavach_ports::ConsentSource,
    S: kavach_ports::MandateStore,
    E: kavach_ports::EventBus,
    T: TimeSource,
{
    async fn verify(
        &self,
        tenant_id: &str,
        mandate_id: &str,
    ) -> Result<(Mandate, Vec<String>), PortError> {
        let stored = self
            .store()
            .get(tenant_id, mandate_id)
            .await?
            .ok_or_else(|| PortError::rejected(format!("unknown mandate {mandate_id}")))?;
        self.verify_active_chain(&stored.token).await
    }
}

impl<V: MandateVerifier> MandateVerifier for Arc<V> {
    fn verify(
        &self,
        tenant_id: &str,
        mandate_id: &str,
    ) -> impl Future<Output = Result<(Mandate, Vec<String>), PortError>> + Send {
        V::verify(self, tenant_id, mandate_id)
    }
}

/// The authenticated agent (identity from the agent token; state from the
/// agent registry).
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub identity_key: String,
    pub state: AgentState,
}

/// A tool call, after the gateway extracted typed parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolCall {
    pub mandate_id: String,
    pub action: String,
    pub request_id: String,
    pub subject_ref: String,
    pub channel: Option<String>,
    pub waiver_bps: Option<i64>,
    pub requested_fields: BTreeSet<String>,
    /// Other declared parameters (e.g. `template_id`); scanned like all
    /// string parameters.
    pub extra: BTreeMap<String, String>,
    /// Policy violations found by tool-registry extraction (reference-only,
    /// allowlist, range). Decided BLOCK and recorded by reason only; not part
    /// of the parameters.
    #[serde(skip)]
    pub violations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Precheck,
    Commit,
}

/// How the commit went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitStatus {
    /// Pre-check: nothing written.
    NotRecorded,
    Committed,
    /// A retry of a committed request; its stored decision is returned.
    Replayed,
    /// The request id was used for different content (HTTP 409).
    Conflict,
    /// The evidence write failed; BLOCK, nothing recorded.
    Failed,
}

/// What the gateway may do with an allow: forward once, with this credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialGrant {
    pub credential_id: String,
    pub mandate_id: String,
    pub expires_at: DateTime<Utc>,
    pub send_by: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct Decided {
    pub decision: Decision,
    pub reasons: Vec<String>,
    pub status: CommitStatus,
    pub record: Option<AgentDecisionRecord>,
    /// Only for a committed (or replayed) allow.
    pub grant: Option<CredentialGrant>,
    /// Time spent in the evidence store's commit, when one was made (for
    /// the gateway's per-stage latency).
    pub commit_time: Option<std::time::Duration>,
}

impl Decided {
    /// True only for the call that created the record (`Committed`).
    /// **Forward-once ownership:** only this call may resolve, obtain a
    /// credential and forward; a replay (including a concurrent duplicate)
    /// returns the recorded outcome (even `unknown`), or is refused as in
    /// flight while the first call is still running.
    #[must_use]
    pub fn created(&self) -> bool {
        self.status == CommitStatus::Committed
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizeConfig {
    pub tenant_id: String,
    pub partition_id: i32,
    /// Lifetime of an injected credential (10–15 s: the gateway uses it at once).
    pub credential_ttl: Duration,
    /// Largest acceptable kernel clock error.
    pub max_clock_error_ms: u64,
}

impl Default for AuthorizeConfig {
    fn default() -> Self {
        Self {
            tenant_id: "default".into(),
            partition_id: 0,
            credential_ttl: Duration::seconds(15),
            max_clock_error_ms: 500,
        }
    }
}

/// Digest of the compiled-in agent policies and schema, the tool registry
/// and the build.
#[must_use]
pub fn policy_versions(tools: &ToolRegistry) -> PolicyVersions {
    let mut hasher = Sha256::new();
    hasher.update(kavach_authz::AGENT_SCHEMA.as_bytes());
    hasher.update(b"\n--\n");
    hasher.update(kavach_authz::AGENT_POLICIES.as_bytes());
    PolicyVersions {
        cedar: format!("sha256:{:x}", hasher.finalize()),
        cel: None,
        packs: Vec::new(),
        tools: Some(tools.digest().to_string()),
        build: concat!("kavach-dataplane/", env!("CARGO_PKG_VERSION")).into(),
    }
}

/// `request_id`: 1–128 characters of `[A-Za-z0-9._:-]`.
pub fn validate_request_id(request_id: &str) -> Result<(), PortError> {
    let ok = (1..=128).contains(&request_id.len())
        && request_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    if ok {
        Ok(())
    } else {
        Err(PortError::invalid(
            "request_id must be 1-128 characters of [A-Za-z0-9._:-]",
        ))
    }
}

const IST_OFFSET_SECONDS: i32 = 5 * 3600 + 30 * 60;

/// `minute` of the IST day `date`, as UTC.
fn ist_minute_to_utc(date: NaiveDate, minute: u16) -> DateTime<Utc> {
    let ist = FixedOffset::east_opt(IST_OFFSET_SECONDS).expect("valid offset");
    let midnight = ist
        .from_local_datetime(&date.and_time(NaiveTime::MIN))
        .single()
        .expect("IST has no gaps");
    (midnight + Duration::minutes(i64::from(minute))).with_timezone(&Utc)
}

pub struct AuthorizeCore<V, S> {
    verifier: V,
    store: Arc<S>,
    tools: Arc<ToolRegistry>,
    authorizer: AgentAuthorizer,
    subject_keys: SubjectKeys,
    signer: Box<dyn EvidenceSigner>,
    clock: Box<dyn TimeSource>,
    config: AuthorizeConfig,
    versions: PolicyVersions,
    prechecks: AtomicU64,
}

/// Facts gathered before the policy decision.
struct Assessment {
    pseudonym: String,
    params_mac: Option<String>,
    violations: Vec<String>,
    now: TrustedNow,
}

impl<V: MandateVerifier, S: AgentEvidenceStore> AuthorizeCore<V, S> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verifier: V,
        store: Arc<S>,
        tools: Arc<ToolRegistry>,
        subject_keys: SubjectKeys,
        signer: Box<dyn EvidenceSigner>,
        clock: Box<dyn TimeSource>,
        config: AuthorizeConfig,
    ) -> Result<Self, PortError> {
        let authorizer = AgentAuthorizer::bundled()
            .map_err(|e| PortError::invalid(format!("agent policies: {e}")))?;
        Ok(Self {
            versions: policy_versions(&tools),
            verifier,
            store,
            tools,
            authorizer,
            subject_keys,
            signer,
            clock,
            config,
            prechecks: AtomicU64::new(0),
        })
    }

    /// Pre-checks answered so far (metrics; they are never recorded).
    pub fn prechecks(&self) -> u64 {
        self.prechecks.load(Ordering::Relaxed)
    }

    pub fn store(&self) -> &Arc<S> {
        &self.store
    }

    /// Records what happened after an allow (signed with the evidence key,
    /// with a reason code; append-only, once per credential).
    pub async fn record_outcome(
        &self,
        record: &AgentDecisionRecord,
        outcome: Outcome,
        reason: &str,
    ) -> Result<OutcomeRecord, PortError> {
        let credential_id = record
            .payload
            .credential_id
            .as_deref()
            .filter(|_| record.is_allow())
            .ok_or_else(|| PortError::invalid("outcomes are recorded only for allows"))?;
        let written = sign_outcome(
            &record.payload.tenant_id,
            credential_id,
            &record.hash,
            outcome,
            reason,
            self.clock.now().utc,
            &*self.signer,
        )?;
        self.store.record_outcome(written.clone()).await?;
        Ok(written)
    }

    /// The recorded outcome for a credential, if any.
    pub async fn outcome(&self, credential_id: &str) -> Result<Option<OutcomeRecord>, PortError> {
        self.store
            .outcome(&self.config.tenant_id, credential_id)
            .await
    }

    /// The tenant this core decides for.
    pub fn tenant_id(&self) -> &str {
        &self.config.tenant_id
    }

    /// Trusted time now, and whether it is synced within the configured
    /// error (the gateway re-checks `send_by` just before forwarding).
    pub fn trusted_now(&self) -> Option<DateTime<Utc>> {
        self.clock
            .now()
            .require_synced(self.config.max_clock_error_ms)
            .ok()
    }

    /// The tool registry this core decides under.
    pub fn tools(&self) -> &ToolRegistry {
        &self.tools
    }

    /// Decides a tool call. `Err` only for a malformed request (`Invalid`,
    /// HTTP 400); every other failure is a BLOCK-shaped `Decided`.
    pub async fn authorize(
        &self,
        agent: &AgentIdentity,
        call: &ToolCall,
        mode: Mode,
    ) -> Result<Decided, PortError> {
        validate_request_id(&call.request_id)?;
        let action = AgentAction::from_name(&call.action)
            .filter(|a| self.tools.for_action(a.name()).is_some())
            .ok_or_else(|| {
                PortError::invalid(format!("action {} has no registered tool", call.action))
            })?;
        let assessment = self.assess(call)?;
        let tenant = &self.config.tenant_id;

        let verified = self.verifier.verify(tenant, &call.mandate_id).await;
        let (decision, reasons, mandate_view) = match verified {
            Err(err) => {
                let reason = if err.class == ErrorClass::Unavailable {
                    "dependency_unavailable"
                } else {
                    "mandate_invalid"
                };
                (Decision::Block, vec![reason.to_string()], None)
            }
            Ok((mandate, chain)) => {
                let (decision, reasons) = self
                    .decide(agent, action, call, &mandate, &assessment)
                    .await;
                (decision, reasons, Some((mandate, chain)))
            }
        };

        if mode == Mode::Precheck {
            self.prechecks.fetch_add(1, Ordering::Relaxed);
            return Ok(Decided {
                decision,
                reasons,
                status: CommitStatus::NotRecorded,
                record: None,
                grant: None,
                commit_time: None,
            });
        }
        Ok(self
            .commit(
                agent,
                action,
                call,
                assessment,
                decision,
                reasons,
                mandate_view.as_ref(),
            )
            .await)
    }

    /// Pseudonym, params MAC and raw-identifier violations. A violating call
    /// gets no params MAC: only the reason and field are recorded.
    fn assess(&self, call: &ToolCall) -> Result<Assessment, PortError> {
        let tenant = &self.config.tenant_id;
        let mut violations = call.violations.clone();
        let subject_violation = "reference_only_violation:subject_ref".to_string();
        if !is_capability_ref(&call.subject_ref) && !violations.contains(&subject_violation) {
            violations.push(subject_violation);
        }
        let mut strings: Vec<(&str, &str)> = vec![("subject_ref", call.subject_ref.as_str())];
        if let Some(channel) = &call.channel {
            strings.push(("channel", channel));
        }
        strings.extend(
            call.requested_fields
                .iter()
                .map(|f| ("requested_fields", f.as_str())),
        );
        strings.extend(call.extra.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        for (field, value) in strings {
            // The subject is reference-only: held to the stricter rule.
            let found = if field == "subject_ref" {
                reference_identifier(value)
            } else {
                raw_identifier(value)
            };
            if let Some(kind) = found {
                let reason = format!("raw_identifier:{field}:{kind}");
                if !violations.contains(&reason) {
                    violations.push(reason);
                }
            }
        }
        let params_mac = if violations.is_empty() {
            let canonical = kavach_ports::jcs::to_vec(call)?;
            Some(self.subject_keys.params_mac(tenant, &canonical))
        } else {
            None
        };
        Ok(Assessment {
            pseudonym: self.subject_keys.pseudonym(tenant, &call.subject_ref),
            params_mac,
            violations,
            now: self.clock.now(),
        })
    }

    async fn decide(
        &self,
        agent: &AgentIdentity,
        action: AgentAction,
        call: &ToolCall,
        mandate: &Mandate,
        assessment: &Assessment,
    ) -> (Decision, Vec<String>) {
        if !assessment.violations.is_empty() {
            return (Decision::Block, assessment.violations.clone());
        }
        let Ok(now) = assessment
            .now
            .require_synced(self.config.max_clock_error_ms)
        else {
            return (Decision::Block, vec!["trusted_time_unavailable".into()]);
        };
        let Ok(contacts_today) = self
            .store
            .contacts_on(&self.config.tenant_id, &assessment.pseudonym, ist_date(now))
            .await
        else {
            return (Decision::Block, vec!["dependency_unavailable".into()]);
        };
        let request = AuthzRequest {
            agent_id: &agent.agent_id,
            action,
            subject_ref: &call.subject_ref,
            mandate,
            requested_fields: call.requested_fields.clone(),
            channel: call.channel.clone(),
            waiver_bps: call.waiver_bps,
            contacts_today,
            task_tainted: false,
            agent_state: agent.state,
            approval_valid: false,
            now,
        };
        match self.authorizer.authorize(&request) {
            Ok(outcome) => {
                let mut reasons = outcome.reason_codes;
                reasons.extend(outcome.determining_policies);
                (outcome.decision, reasons)
            }
            Err(_) => (Decision::Block, vec!["policy_evaluation_error".into()]),
        }
    }

    /// End of the contact window today: the earlier of the mandate window and
    /// the 19:00 IST floor (contact actions only).
    fn send_by(
        call: &ToolCall,
        mandate: Option<&Mandate>,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        if !CONTACT_ACTIONS.contains(&call.action.as_str()) {
            return None;
        }
        let window_end = mandate
            .and_then(|m| m.window)
            .map_or(CONTACT_FLOOR_TO_MIN, |w| w.to_min.min(CONTACT_FLOOR_TO_MIN));
        Some(ist_minute_to_utc(ist_date(now), window_end))
    }

    #[allow(clippy::too_many_arguments)]
    async fn commit(
        &self,
        agent: &AgentIdentity,
        action: AgentAction,
        call: &ToolCall,
        assessment: Assessment,
        decision: Decision,
        reasons: Vec<String>,
        mandate_view: Option<&(Mandate, Vec<String>)>,
    ) -> Decided {
        let request = self.commit_request(
            agent,
            action,
            call,
            assessment,
            decision,
            reasons,
            mandate_view,
        );
        let started = std::time::Instant::now();
        let result = self
            .store
            .commit(request, self.clock.as_ref(), self.signer.as_ref())
            .await;
        Decided {
            commit_time: Some(started.elapsed()),
            ..decided(result)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_request(
        &self,
        agent: &AgentIdentity,
        action: AgentAction,
        call: &ToolCall,
        assessment: Assessment,
        decision: Decision,
        reasons: Vec<String>,
        mandate_view: Option<&(Mandate, Vec<String>)>,
    ) -> CommitRequest {
        let (mandate, chain) = match mandate_view {
            Some((m, c)) => (Some(m), c.clone()),
            None => (None, Vec::new()),
        };
        let contact = CONTACT_ACTIONS
            .contains(&action.name())
            .then(|| ContactReservation {
                ist_date: ist_date(assessment.now.utc),
                max_per_day: mandate
                    .and_then(|m| m.window)
                    .map_or(0, |w| u32::from(w.max_per_day)),
            });
        let draft = AgentDecisionPayload {
            record_id: String::new(),
            tenant_id: self.config.tenant_id.clone(),
            partition_id: self.config.partition_id,
            seq: 0,
            prev_hash: String::new(),
            kind: KIND_AGENT_DECISION.into(),
            hash_alg: HASH_ALG_V2.into(),
            key_id: self.signer.key_id().into(),
            actor: Actor {
                agent_id: agent.agent_id.clone(),
                identity_key: agent.identity_key.clone(),
            },
            chain,
            mandate_id: call.mandate_id.clone(),
            purpose: mandate.map(|m| m.purpose.clone()).unwrap_or_default(),
            consent_refs: mandate
                .map(|m| m.consent_refs.iter().cloned().collect())
                .unwrap_or_default(),
            action: action.name().into(),
            request_id: call.request_id.clone(),
            subject_pseudonym: assessment.pseudonym.clone(),
            params_mac: assessment.params_mac.clone(),
            policy_versions: self.versions.clone(),
            signals: reasons,
            pre_commit_decision: decision,
            policy_decision: decision,
            returned_decision: decision,
            obligations: Vec::new(),
            credential_id: None,
            credential_expires_at: None,
            send_by: Self::send_by(call, mandate, assessment.now.utc),
            time_sync: TimeSync::from(assessment.now.sync),
            ts: assessment.now.utc,
        };
        CommitRequest {
            tenant_id: self.config.tenant_id.clone(),
            partition_id: self.config.partition_id,
            binding: RequestBinding {
                action: action.name().into(),
                params_mac: assessment.params_mac,
                subject_pseudonym: assessment.pseudonym,
                mandate_id: call.mandate_id.clone(),
            },
            draft,
            contact,
            // Unguessable; the credential is minted with this `jti`.
            credential_id: uuid::Uuid::new_v4().to_string(),
            credential_ttl: self.config.credential_ttl,
            max_clock_error_ms: self.config.max_clock_error_ms,
        }
    }
}

/// Maps a commit result to the decision returned to the gateway.
fn decided(result: Result<CommitResult, PortError>) -> Decided {
    let (record, status) = match result {
        Ok(CommitResult::Committed(r)) => (*r, CommitStatus::Committed),
        Ok(CommitResult::Replayed(r)) => (*r, CommitStatus::Replayed),
        Ok(CommitResult::Conflict(r)) => {
            return Decided {
                decision: Decision::Block,
                reasons: vec!["request_id_conflict".into()],
                status: CommitStatus::Conflict,
                record: Some(*r),
                grant: None,
                commit_time: None,
            };
        }
        Err(_) => {
            return Decided {
                decision: Decision::Block,
                reasons: vec!["dependency_unavailable".into()],
                status: CommitStatus::Failed,
                record: None,
                grant: None,
                commit_time: None,
            };
        }
    };
    let grant = (is_allow(record.payload.returned_decision))
        .then(|| {
            Some(CredentialGrant {
                credential_id: record.payload.credential_id.clone()?,
                mandate_id: record.payload.mandate_id.clone(),
                expires_at: record.payload.credential_expires_at?,
                send_by: record.payload.send_by,
            })
        })
        .flatten();
    Decided {
        decision: record.payload.returned_decision,
        reasons: record.payload.signals.clone(),
        status,
        grant,
        record: Some(record),
        commit_time: None,
    }
}
