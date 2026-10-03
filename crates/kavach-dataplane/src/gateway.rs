//! The resource gateway (H5b step 8, ADR-007): the one path by which an
//! agent's tool call reaches a backend. Transport-independent: the HTTP
//! route (and later MCP) call [`execute`].
//!
//! Flow: extract (registry) → authorize and commit (evidence first) →
//! **only the call that created the record** proceeds (forward-once
//! ownership; replays return the stored outcome or are refused as in
//! flight) → resolve the destination → obtain a request-bound credential →
//! **re-check trusted time against `send_by`** → forward once, no retry →
//! classify → record a signed outcome with a reason code.
//!
//! Nothing here ever returns the destination, the credential or a
//! provider's raw response to the agent: [`GatewayReply`] is an allowlist.

use std::future::Future;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use kavach_domain::Decision;
use kavach_ports::agent_evidence::{is_allow, AgentDecisionRecord, Outcome};
use kavach_ports::{
    CredentialBroker, CredentialRequest, ErrorClass, ReferenceResolver, TokenSecret,
};
use serde::Serialize;

use crate::authorize::{AgentIdentity, AuthorizeCore, CommitStatus, MandateVerifier, Mode};
use crate::tools::{ToolRequest, Trust};

/// What happened on the wire, as the forwarder saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardResult {
    /// The provider answered (bounded body already parsed).
    Responded {
        status: u16,
        message_id: Option<String>,
    },
    /// The connection failed before any request was sent: provably not
    /// delivered.
    NotSent,
    /// The request was (or may have been) sent, and no complete response
    /// came back: timeout or connection loss.
    Lost,
}

/// Sends one credential to a provider. Implementations must not retry, must
/// not follow redirects and must not use ambient proxies.
pub trait Forwarder: Send + Sync {
    fn forward(
        &self,
        provider: &str,
        credential: &TokenSecret,
    ) -> impl Future<Output = ForwardResult> + Send;
}

/// Outcome and reason code for what the provider said (the agreed status
/// contract, ADR-007). The second value is true for an anomaly to alert on.
pub fn classify(result: &ForwardResult) -> (Outcome, String, bool) {
    match result {
        ForwardResult::NotSent => (Outcome::Failed, "connect_failed".into(), false),
        ForwardResult::Lost => (Outcome::Unknown, "timeout_after_send".into(), false),
        ForwardResult::Responded { status, .. } => {
            let reason = format!("provider_{status}");
            match *status {
                202 | 200 => (Outcome::Delivered, reason, false),
                // The jti was used for other claims: the first use may have
                // delivered.
                409 => (Outcome::Unknown, reason, true),
                408 => (Outcome::Unknown, reason, false),
                400..=499 => (Outcome::Refused, reason, false),
                // Any other 2xx, any 1xx/3xx (redirects are never followed)
                // and 5xx: not known.
                _ => (Outcome::Unknown, reason, false),
            }
        }
    }
}

/// A provider-controlled identifier, echoed only if it is short and plain.
pub fn bounded_message_id(value: &str) -> Option<String> {
    let ok = (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    ok.then(|| value.to_string())
}

/// The reply to the agent: an allowlist of fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GatewayReply {
    pub decision: Decision,
    pub reasons: Vec<String>,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    /// Only when something was (or was not) executed after an allow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome_reason: Option<String>,
    /// False only if the outcome happened but could not be recorded (an
    /// alert is raised; a retry is refused as in flight).
    pub outcome_recorded: bool,
    /// True when this is the stored result of an earlier identical call.
    pub replayed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_message_id: Option<String>,
}

/// Why a call produced no decision reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    /// Malformed: unknown tool or parameter, wrong type (400; nothing
    /// recorded).
    Invalid(String),
    /// The tool exists but is not executed by the gateway yet (501).
    NotForwardable(String),
    /// The `request_id` was used for different content (409).
    Conflict,
    /// A previous identical call has no final outcome (409; never re-run).
    InFlight,
}

/// One stage of a gateway call, for per-stage latency. A fixed list: it is
/// a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Mandate, policy and parameter checks (everything in `authorize` but
    /// the evidence commit).
    Decide,
    /// The evidence commit: the signed record, in one transaction.
    Commit,
    /// The capability reference resolved to a destination.
    Resolve,
    /// The resource credential issued (signed and encrypted).
    Credential,
    /// The request forwarded to the provider, until its reply.
    Forward,
    /// The signed outcome written.
    Outcome,
}

impl Stage {
    pub const ALL: [Self; 6] = [
        Self::Decide,
        Self::Commit,
        Self::Resolve,
        Self::Credential,
        Self::Forward,
        Self::Outcome,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Decide => "decide",
            Self::Commit => "commit",
            Self::Resolve => "resolve",
            Self::Credential => "credential",
            Self::Forward => "forward",
            Self::Outcome => "outcome",
        }
    }
}

/// Counters the caller exports; labels are fixed vocabularies only.
pub trait GatewayObserver: Send + Sync {
    fn call(&self, tool: &str, decision: Decision, outcome: Option<Outcome>);
    fn jti_conflict(&self);
    fn outcome_write_failed(&self);
    /// How long one stage of a call took. Ignored unless implemented.
    fn stage(&self, _stage: Stage, _elapsed: Duration) {}
}

/// What the gateway needs from its host.
pub struct GatewayDeps<'a, V, S, R, B, F, O> {
    pub core: &'a AuthorizeCore<V, S>,
    pub resolver: &'a R,
    pub broker: &'a B,
    pub forwarder: &'a F,
    pub observer: &'a O,
}

struct Allowed<'a> {
    record: &'a AgentDecisionRecord,
    credential_id: &'a str,
    expires_at: DateTime<Utc>,
    send_by: Option<DateTime<Utc>>,
}

/// Executes one tool call. `Err` only for calls that get no decision reply.
pub async fn execute<V, S, R, B, F, O>(
    deps: &GatewayDeps<'_, V, S, R, B, F, O>,
    agent: &AgentIdentity,
    tool: &str,
    request: ToolRequest,
) -> Result<GatewayReply, GatewayError>
where
    V: MandateVerifier,
    S: kavach_ports::agent_evidence::AgentEvidenceStore,
    R: ReferenceResolver,
    B: CredentialBroker,
    F: Forwarder,
    O: GatewayObserver,
{
    let core = deps.core;
    let spec = core
        .tools()
        .tool(tool)
        .ok_or_else(|| GatewayError::Invalid("unknown tool".into()))?
        .clone();
    if spec.trust != Trust::ExternalEffect {
        return Err(GatewayError::NotForwardable(format!(
            "tool {} is not executed by the gateway yet",
            spec.name
        )));
    }
    let call = core
        .tools()
        .extract(tool, request)
        .map_err(|e| GatewayError::Invalid(e.message))?;
    let started = Instant::now();
    let decided = core
        .authorize(agent, &call, Mode::Commit)
        .await
        .map_err(|e| GatewayError::Invalid(e.message))?;
    let authorize_time = started.elapsed();
    let commit_time = decided.commit_time.unwrap_or_default();
    deps.observer
        .stage(Stage::Decide, authorize_time.saturating_sub(commit_time));
    if decided.commit_time.is_some() {
        deps.observer.stage(Stage::Commit, commit_time);
    }

    let mut reply = GatewayReply {
        decision: decided.decision,
        reasons: decided.reasons.clone(),
        request_id: call.request_id.clone(),
        record_id: decided.record.as_ref().map(|r| r.payload.record_id.clone()),
        outcome: None,
        outcome_reason: None,
        outcome_recorded: true,
        replayed: decided.status == CommitStatus::Replayed,
        provider_message_id: None,
    };
    if decided.status == CommitStatus::Conflict {
        return Err(GatewayError::Conflict);
    }
    let (Some(record), Some(grant)) = (decided.record.as_ref(), decided.grant.as_ref()) else {
        // A refusal (or an evidence failure, which is BLOCK-shaped).
        deps.observer.call(&spec.name, reply.decision, None);
        return Ok(reply);
    };
    if !is_allow(decided.decision) {
        deps.observer.call(&spec.name, reply.decision, None);
        return Ok(reply);
    }

    // Forward-once ownership: only the creator proceeds.
    if !decided.created() {
        return match core.outcome(&grant.credential_id).await {
            Ok(Some(stored)) if stored.outcome.is_final() => {
                reply.outcome = Some(stored.outcome);
                reply.outcome_reason = stored.reason;
                Ok(reply)
            }
            _ => Err(GatewayError::InFlight),
        };
    }

    let allowed = Allowed {
        record,
        credential_id: &grant.credential_id,
        expires_at: grant.expires_at,
        send_by: grant.send_by,
    };
    let content_param = spec.content_param().unwrap_or("template_id");
    let (outcome, reason, message_id) =
        run_allowed(deps, agent, &spec, &call, content_param, &allowed).await;
    if reason == "provider_409" {
        deps.observer.jti_conflict();
    }
    let started = Instant::now();
    let written = core.record_outcome(record, outcome, &reason).await;
    deps.observer.stage(Stage::Outcome, started.elapsed());
    if written.is_err() {
        reply.outcome_recorded = false;
        deps.observer.outcome_write_failed();
    }
    deps.observer
        .call(&spec.name, reply.decision, Some(outcome));
    reply.outcome = Some(outcome);
    reply.outcome_reason = Some(reason);
    reply.provider_message_id = message_id;
    Ok(reply)
}

/// Resolve → credential → deadline re-check → forward → classify. Never
/// fails: every path ends in an outcome and a reason code.
async fn run_allowed<V, S, R, B, F, O>(
    deps: &GatewayDeps<'_, V, S, R, B, F, O>,
    agent: &AgentIdentity,
    spec: &crate::tools::ToolSpec,
    call: &crate::authorize::ToolCall,
    content_param: &str,
    allowed: &Allowed<'_>,
) -> (Outcome, String, Option<String>)
where
    V: MandateVerifier,
    S: kavach_ports::agent_evidence::AgentEvidenceStore,
    R: ReferenceResolver,
    B: CredentialBroker,
    F: Forwarder,
    O: GatewayObserver,
{
    let core = deps.core;
    let not_executed = |reason: &str| (Outcome::NotExecuted, reason.to_string(), None);
    let (Some(channel), Some(content), Some(provider)) = (
        call.channel.as_deref(),
        call.extra.get(content_param),
        spec.provider.as_deref(),
    ) else {
        return not_executed("tool_not_forwardable");
    };

    let started = Instant::now();
    let resolved = deps
        .resolver
        .resolve(core.tenant_id(), &call.subject_ref, channel)
        .await;
    deps.observer.stage(Stage::Resolve, started.elapsed());
    let destination = match resolved {
        Ok(destination) => destination,
        Err(err) => {
            return not_executed(match err.class {
                ErrorClass::Rejected => "no_destination",
                ErrorClass::Invalid => "invalid_reference",
                ErrorClass::Unavailable => "resolver_unavailable",
            })
        }
    };

    let Some(now) = core.trusted_now() else {
        return not_executed("trusted_time_unavailable");
    };
    let started = Instant::now();
    let issued = deps
        .broker
        .issue(&CredentialRequest {
            tenant_id: core.tenant_id(),
            agent_id: &agent.agent_id,
            mandate_id: &call.mandate_id,
            record_id: &allowed.record.payload.record_id,
            credential_id: allowed.credential_id,
            audience: provider,
            action: &call.action,
            destination: &destination,
            channel,
            template_id: content,
            expires_at: allowed.expires_at,
            send_by: allowed.send_by,
            now,
        })
        .await;
    deps.observer.stage(Stage::Credential, started.elapsed());
    drop(destination);
    let credential = match issued {
        Ok(credential) => credential,
        Err(err) => {
            return not_executed(match err.class {
                ErrorClass::Rejected => "credential_refused",
                ErrorClass::Invalid => "credential_invalid",
                ErrorClass::Unavailable => "credential_unavailable",
            })
        }
    };

    // A slow resolver or broker must not push the send past the deadline.
    let Some(now) = core.trusted_now() else {
        return not_executed("trusted_time_unavailable");
    };
    if allowed.send_by.is_some_and(|send_by| now >= send_by) {
        return not_executed("send_by_passed");
    }
    if now >= credential.expires_at {
        return not_executed("credential_expired");
    }

    let started = Instant::now();
    let result = deps.forwarder.forward(provider, &credential.token).await;
    deps.observer.stage(Stage::Forward, started.elapsed());
    drop(credential);
    let (outcome, reason, _) = classify(&result);
    let message_id = match result {
        ForwardResult::Responded { message_id, .. } => {
            message_id.as_deref().and_then(bounded_message_id)
        }
        _ => None,
    };
    (outcome, reason, message_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn responded(status: u16) -> ForwardResult {
        ForwardResult::Responded {
            status,
            message_id: None,
        }
    }

    #[test]
    fn status_contract() {
        let outcome = |r: ForwardResult| classify(&r).0;
        assert_eq!(outcome(responded(202)), Outcome::Delivered);
        assert_eq!(outcome(responded(200)), Outcome::Delivered);
        for status in [
            201, 204, 206, 301, 302, 307, 308, 408, 500, 502, 503, 504, 101,
        ] {
            assert_eq!(outcome(responded(status)), Outcome::Unknown, "{status}");
        }
        for status in [400, 401, 403, 404, 422, 429] {
            assert_eq!(outcome(responded(status)), Outcome::Refused, "{status}");
        }
        let (o, reason, anomaly) = classify(&responded(409));
        assert_eq!(
            (o, reason.as_str(), anomaly),
            (Outcome::Unknown, "provider_409", true)
        );
        assert_eq!(classify(&ForwardResult::NotSent).0, Outcome::Failed);
        assert_eq!(classify(&ForwardResult::Lost).1, "timeout_after_send");
    }

    #[test]
    fn provider_message_ids_are_bounded() {
        assert_eq!(
            bounded_message_id("pm-0af7651916cd"),
            Some("pm-0af7651916cd".into())
        );
        for bad in [
            "",
            "has space",
            "+91 98765 43210",
            "\u{1b}[31mred",
            &"x".repeat(129),
        ] {
            assert_eq!(bounded_message_id(bad), None, "{bad:?}");
        }
    }
}
