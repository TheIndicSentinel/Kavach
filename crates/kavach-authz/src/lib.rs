//! Agent authorization core (ADR-003).
//!
//! - Cedar (`Kavach::Agent`) decides "is this action authorised?" from a
//!   context computed server-side ([`AuthzRequest`] → [`build_context`]).
//! - A deny whose determining policies are **all** annotated
//!   `@escalate("human_review")` becomes `HUMAN_REVIEW`; any other deny —
//!   including default deny and any policy evaluation error — is `BLOCK`.
//! - CEL pack rules may only raise the outcome ([`refine`]); they can never
//!   downgrade a Cedar result (PRD D15).

mod time;

use std::collections::BTreeSet;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, EntityId, EntityTypeName, EntityUid,
    PolicyId, PolicySet, Request, Schema, ValidationMode, Validator,
};
use chrono::{DateTime, Utc};
use kavach_domain::mandate::Mandate;
use kavach_domain::Decision;
use kavach_policy::PolicyEvaluation;
use serde_json::json;

pub use time::{ist_date, ist_minute_of_day};

/// Bundled schema and policies for the collections reference workflow.
pub const AGENT_SCHEMA: &str = include_str!("../policies/agent.cedarschema");
pub const AGENT_POLICIES: &str = include_str!("../policies/agent.cedar");

const ESCALATE_ANNOTATION: &str = "escalate";
const HUMAN_REVIEW: &str = "human_review";

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("agent schema: {0}")]
    Schema(String),
    #[error("agent policies: {0}")]
    Policy(String),
    #[error("authorization request: {0}")]
    Request(String),
}

/// Agent tool actions known to the schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentAction {
    ReadFields,
    SendReminder,
    PlaceCall,
    ProposePlan,
    UpdateStatus,
}

impl AgentAction {
    pub const ALL: [Self; 5] = [
        Self::ReadFields,
        Self::SendReminder,
        Self::PlaceCall,
        Self::ProposePlan,
        Self::UpdateStatus,
    ];

    /// Name used in the Cedar schema and in `Mandate::actions`.
    pub fn name(self) -> &'static str {
        match self {
            Self::ReadFields => "read_fields",
            Self::SendReminder => "send_reminder",
            Self::PlaceCall => "place_call",
            Self::ProposePlan => "propose_plan",
            Self::UpdateStatus => "update_status",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.name() == name)
    }
}

/// Agent risk state (ADR-003 §6). Anything but `Active` blocks all actions
/// in the MVP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    Active,
    Restricted,
    Quarantined,
    Revoked,
}

/// Everything the decision depends on. The caller builds it from the
/// verified mandate, extracted tool parameters, server-side counters, risk
/// state and trusted time — never from the agent's own claims.
#[derive(Debug, Clone)]
pub struct AuthzRequest<'a> {
    /// Authenticated agent identity.
    pub agent_id: &'a str,
    pub action: AgentAction,
    /// Capability reference the action targets.
    pub subject_ref: &'a str,
    /// A mandate already verified as active (`MandateService::verify_active`).
    pub mandate: &'a Mandate,
    pub requested_fields: BTreeSet<String>,
    pub channel: Option<String>,
    pub waiver_bps: Option<i64>,
    /// Contacts already made today (IST day) for this subject.
    pub contacts_today: i64,
    pub task_tainted: bool,
    pub agent_state: AgentState,
    /// True only if an approval exists bound to this request's `action_hash`.
    pub approval_valid: bool,
    /// Trusted server time.
    pub now: DateTime<Utc>,
}

/// Outcome of the combined Cedar + CEL decision, with explanations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthzOutcome {
    pub decision: Decision,
    /// Policy ids that determined the Cedar result.
    pub determining_policies: Vec<String>,
    pub reason_codes: Vec<String>,
}

/// Validated agent policy set.
pub struct AgentAuthorizer {
    authorizer: Authorizer,
    policies: PolicySet,
    schema: Schema,
    escalate_ids: BTreeSet<PolicyId>,
}

impl AgentAuthorizer {
    /// Loads and strictly validates `policies` against `schema`. Every policy
    /// must carry `@id`; `@escalate` may only be `"human_review"` and only on
    /// `forbid` policies.
    pub fn new(schema_text: &str, policies_text: &str) -> Result<Self, AuthzError> {
        let (schema, _warnings) = Schema::from_cedarschema_str(schema_text)
            .map_err(|e| AuthzError::Schema(e.to_string()))?;
        let policies =
            PolicySet::from_str(policies_text).map_err(|e| AuthzError::Policy(e.to_string()))?;
        let validation = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        if !validation.validation_passed() {
            let errors: Vec<String> = validation
                .validation_errors()
                .map(ToString::to_string)
                .collect();
            return Err(AuthzError::Policy(errors.join("; ")));
        }
        let mut escalate_ids = BTreeSet::new();
        for policy in policies.policies() {
            if policy.annotation("id").is_none_or(str::is_empty) {
                return Err(AuthzError::Policy(format!(
                    "policy {} has no @id annotation",
                    policy.id()
                )));
            }
            if let Some(value) = policy.annotation(ESCALATE_ANNOTATION) {
                if value != HUMAN_REVIEW || policy.effect() != cedar_policy::Effect::Forbid {
                    return Err(AuthzError::Policy(format!(
                        "policy {}: @escalate must be \"{HUMAN_REVIEW}\" on a forbid",
                        policy.id()
                    )));
                }
                escalate_ids.insert(policy.id().clone());
            }
        }
        Ok(Self {
            authorizer: Authorizer::new(),
            policies,
            schema,
            escalate_ids,
        })
    }

    /// The bundled collections reference policies.
    pub fn bundled() -> Result<Self, AuthzError> {
        Self::new(AGENT_SCHEMA, AGENT_POLICIES)
    }

    /// Cedar stage: authorised, escalated to review, or blocked.
    pub fn authorize(&self, req: &AuthzRequest<'_>) -> Result<AuthzOutcome, AuthzError> {
        let action = uid("Kavach::Agent::Action", req.action.name())?;
        let context = Context::from_json_value(build_context(req), Some((&self.schema, &action)))
            .map_err(|e| AuthzError::Request(e.to_string()))?;
        let request = Request::new(
            uid("Kavach::Agent::Agent", req.agent_id)?,
            action,
            uid("Kavach::Agent::Subject", req.subject_ref)?,
            context,
            Some(&self.schema),
        )
        .map_err(|e| AuthzError::Request(e.to_string()))?;
        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &Entities::empty());

        let determining: Vec<PolicyId> = response.diagnostics().reason().cloned().collect();
        let names: Vec<String> = determining.iter().map(|id| self.policy_name(id)).collect();

        // Fail closed: a policy that errored is treated as not applying by
        // Cedar, which could hide a forbid. Any error blocks.
        if response.diagnostics().errors().next().is_some() {
            return Ok(outcome(Decision::Block, names, "policy_evaluation_error"));
        }
        Ok(match response.decision() {
            CedarDecision::Allow => outcome(Decision::Pass, names, "authorized"),
            CedarDecision::Deny if determining.is_empty() => {
                outcome(Decision::Block, names, "no_matching_permit")
            }
            CedarDecision::Deny if determining.iter().all(|id| self.escalate_ids.contains(id)) => {
                outcome(Decision::HumanReview, names, "escalated")
            }
            CedarDecision::Deny => outcome(Decision::Block, names, "forbidden"),
        })
    }

    fn policy_name(&self, id: &PolicyId) -> String {
        self.policies
            .policy(id)
            .and_then(|p| p.annotation("id"))
            .map_or_else(|| id.to_string(), ToString::to_string)
    }
}

fn outcome(decision: Decision, determining_policies: Vec<String>, reason: &str) -> AuthzOutcome {
    AuthzOutcome {
        decision,
        determining_policies,
        reason_codes: vec![reason.to_string()],
    }
}

/// CEL refinement (PRD D15): the final decision is the most restrictive of the
/// Cedar outcome and the CEL evaluation; CEL can never downgrade Cedar.
pub fn refine(cedar: AuthzOutcome, cel: Option<&PolicyEvaluation>) -> AuthzOutcome {
    let Some(cel) = cel else {
        return cedar;
    };
    let mut reason_codes = cedar.reason_codes;
    for code in &cel.reason_codes {
        if !reason_codes.contains(code) {
            reason_codes.push(code.clone());
        }
    }
    AuthzOutcome {
        decision: Decision::max(cedar.decision, cel.policy_decision),
        determining_policies: cedar.determining_policies,
        reason_codes,
    }
}

fn uid(type_name: &str, id: &str) -> Result<EntityUid, AuthzError> {
    let type_name =
        EntityTypeName::from_str(type_name).map_err(|e| AuthzError::Request(e.to_string()))?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(id),
    ))
}

fn entity_json(type_name: &str, id: &str) -> serde_json::Value {
    json!({ "__entity": { "type": type_name, "id": id } })
}

/// Builds the Cedar context JSON. Absent limits are encoded with a `has_*`
/// flag (the policies treat a missing waiver ceiling as "needs review").
pub fn build_context(req: &AuthzRequest<'_>) -> serde_json::Value {
    let m = req.mandate;
    let (has_window, from, to, max) = m.window.map_or((false, 0, 0, 0), |w| {
        (
            true,
            i64::from(w.from_min),
            i64::from(w.to_min),
            i64::from(w.max_per_day),
        )
    });
    let ceiling = m.ceilings.get("waiver_bps").copied();
    json!({
        "mandate_subject": entity_json("Kavach::Agent::Subject", &m.subject_ref),
        "mandate_holder": entity_json("Kavach::Agent::Agent", &m.holder),
        "mandate_actions": m.actions,
        "mandate_fields": m.data_fields,
        "mandate_channels": m.channels,
        "has_window": has_window,
        "window_from": from,
        "window_to": to,
        "max_per_day": max,
        "has_waiver_ceiling": ceiling.is_some(),
        "waiver_ceiling_bps": ceiling.unwrap_or(0),
        "ist_minute_of_day": ist_minute_of_day(req.now),
        "contacts_today": req.contacts_today,
        "requested_fields": req.requested_fields,
        "channel": req.channel.clone().unwrap_or_default(),
        "waiver_bps": req.waiver_bps.unwrap_or(0),
        "task_tainted": req.task_tainted,
        "agent_restricted": req.agent_state != AgentState::Active,
        "approval_valid": req.approval_valid,
    })
}
