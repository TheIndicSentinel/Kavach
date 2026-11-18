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

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use kavach_domain::Decision;
use kavach_ports::agent_evidence::{is_allow, AgentDecisionRecord, Outcome};
use kavach_ports::{
    CredentialBroker, CredentialRequest, ErrorClass, ReferenceResolver, TokenSecret,
};
use serde::Serialize;

use crate::authorize::{
    AgentIdentity, AuthorizeCore, CommitStatus, MandateVerifier, Mode, StillAuthorised,
};
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

/// Request for a backend that accepts a Kavach-encrypted credential. Use
/// [`GatewayHeldRequest`] for an adapter that holds its own provider token.
pub struct CredentialAcceptingRequest<'a> {
    pub credential_id: &'a str,
    pub destination: &'a kavach_ports::Destination,
    pub channel: &'a str,
    pub template_id: &'a str,
    pub credential: &'a TokenSecret,
}

/// Request context for a gateway-held provider adapter. It deliberately has
/// no Kavach token field; provider credentials must be resolved separately
/// from the configured secret store at send time. These values are sensitive
/// and must never be logged.
pub struct GatewayHeldRequest<'a> {
    pub credential_id: &'a str,
    pub destination: &'a kavach_ports::Destination,
    pub channel: &'a str,
    pub template_id: &'a str,
}

/// Runtime selection for providers whose credentials are held by Kavach.
/// Each selected provider is issued an internal artifact and sent through the
/// tokenless adapter. Providers absent from this set use the standard path.
pub struct GatewayHeldDispatch<'a> {
    pub providers: &'a BTreeSet<String>,
    pub broker: &'a dyn kavach_ports::InternalCredentialBroker,
    pub forwarder: &'a dyn GatewayHeldForwarder,
}

/// Object-safe future returned by [`GatewayHeldForwarder`].
pub type GatewayHeldForwardFuture<'a> = Pin<Box<dyn Future<Output = ForwardResult> + Send + 'a>>;

/// Sends one credential to a provider. Implementations must not retry, must
/// not follow redirects and must not use ambient proxies.
pub trait Forwarder: Send + Sync {
    fn forward(
        &self,
        provider: &str,
        credential: &TokenSecret,
    ) -> impl Future<Output = ForwardResult> + Send;

    /// Builds a provider-specific request from the gateway's resolved,
    /// authorized values. Credential-accepting providers keep the original
    /// wire format through the default implementation.
    fn forward_request(
        &self,
        provider: &str,
        request: &CredentialAcceptingRequest<'_>,
    ) -> impl Future<Output = ForwardResult> + Send {
        self.forward(provider, request.credential)
    }
}

/// Sends one gateway-held provider request. The interface intentionally has
/// no `TokenSecret` argument, so an adapter implementing this trait cannot
/// accidentally forward a Kavach credential. Implementations must send once,
/// without retries, redirects or ambient proxies.
pub trait GatewayHeldForwarder: Send + Sync {
    fn forward_gateway_held<'a>(
        &'a self,
        provider: &'a str,
        request: &'a GatewayHeldRequest<'a>,
    ) -> GatewayHeldForwardFuture<'a>;
}

async fn send_forward_request<F: Forwarder>(
    forwarder: &F,
    provider: &str,
    request: CredentialAcceptingRequest<'_>,
) -> ForwardResult {
    forwarder.forward_request(provider, &request).await
}

fn forwarded_message_id(result: &ForwardResult) -> Option<String> {
    match result {
        ForwardResult::Responded { message_id, .. } => {
            message_id.as_deref().and_then(bounded_message_id)
        }
        _ => None,
    }
}

/// What a provider says became of one earlier send (the status contract,
/// ADR-017 R2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderStatus {
    Delivered,
    NotDelivered,
    /// The provider answered, and cannot say.
    Unknown,
}

/// A provider's answer to a status question, with the digest that goes into
/// the resolution as its evidence: the SHA-256 (lowercase hex) of the answer
/// body, never the body itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusAnswer {
    pub status: ProviderStatus,
    pub digest: String,
}

/// Asks a provider what became of one earlier send. **It has no send path**:
/// it takes a status question (a signed JWS with no destination), never a
/// credential, so nothing the reconciler holds can deliver anything. A
/// provider that cannot be reached, answers outside the contract, or refuses
/// is `None`: no answer is not an answer, and never becomes a confirmed
/// state. Implementations must not retry, must not follow redirects and must
/// not use ambient proxies.
pub trait StatusAsker: Send + Sync {
    fn status(
        &self,
        provider: &str,
        jti: &str,
        question: &TokenSecret,
    ) -> impl Future<Output = Option<StatusAnswer>> + Send;
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
    /// A previous identical call is still running: no outcome is recorded
    /// yet (409; never re-run).
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
    /// Optional per-provider dispatch for gateway-held provider tokens.
    pub gateway_held: Option<&'a GatewayHeldDispatch<'a>>,
    /// A release atomically consumed by the host for this exact request.
    pub approval_release: Option<&'a kavach_ports::ReviewReleaseRecord>,
    pub observer: &'a O,
}

struct Allowed<'a> {
    record: &'a AgentDecisionRecord,
    credential_id: &'a str,
    expires_at: DateTime<Utc>,
    send_by: Option<DateTime<Utc>>,
}

enum IssuedForCall {
    Provider(kavach_ports::IssuedCredential),
    Internal(kavach_ports::InternalCredentialReceipt),
}

impl IssuedForCall {
    fn expires_at(&self) -> DateTime<Utc> {
        match self {
            Self::Provider(credential) => credential.expires_at,
            Self::Internal(receipt) => receipt.expires_at,
        }
    }
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
    S: kavach_ports::agent_evidence::AgentEvidenceStore
        + kavach_ports::agent_state::AgentStateStore,
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
    let decided = if let Some(release) = deps.approval_release {
        core.authorize_released(agent, &call, release).await
    } else {
        core.authorize(agent, &call, Mode::Commit).await
    }
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

    // Forward-once ownership: only the creator proceeds. A retry never
    // mints or sends: once the first call's outcome is recorded (even
    // `unknown`), it gets that stored outcome, replayed, so an agent stops
    // retrying and the case goes to reconciliation; while the first call
    // is still running (nothing recorded yet), it is in flight.
    if !decided.created() {
        return match core.outcome(&grant.credential_id).await {
            Ok(Some(stored)) => {
                reply.outcome = Some(stored.outcome);
                reply.outcome_reason = stored.reason;
                Ok(reply)
            }
            Ok(None) | Err(_) => Err(GatewayError::InFlight),
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
    let written = record_outcome_retrying(core, record, outcome, &reason).await;
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

/// Waits between the attempts to write an outcome: short, because the
/// agent is waiting for its reply, and few, because an outcome that still
/// cannot be written is recovered later (the reconciler records `unknown`).
const OUTCOME_WRITE_BACKOFF: [Duration; 2] =
    [Duration::from_millis(50), Duration::from_millis(200)];

/// Writes the outcome, trying again a couple of times when the store is
/// unavailable. No lock is held across the waits: each attempt is a whole
/// call of its own. If an attempt failed in a way that may have written the
/// row (the answer was lost), a later "already recorded" is not an error
/// when the stored outcome is the one being written.
async fn record_outcome_retrying<V, S>(
    core: &AuthorizeCore<V, S>,
    record: &AgentDecisionRecord,
    outcome: Outcome,
    reason: &str,
) -> Result<(), kavach_ports::PortError>
where
    V: MandateVerifier,
    S: kavach_ports::agent_evidence::AgentEvidenceStore
        + kavach_ports::agent_state::AgentStateStore,
{
    let mut waits = OUTCOME_WRITE_BACKOFF.iter();
    let mut tried = false;
    loop {
        match core.record_outcome(record, outcome, reason).await {
            Ok(_) => return Ok(()),
            Err(err) if err.class == ErrorClass::Unavailable => {
                tried = true;
                let Some(wait) = waits.next() else {
                    return Err(err);
                };
                tokio::time::sleep(*wait).await;
            }
            Err(err) => {
                // Rejected after an unavailable answer: it may have been
                // written after all.
                if tried && err.class == ErrorClass::Rejected {
                    let stored = match record.payload.credential_id.as_deref() {
                        Some(credential) => core.outcome(credential).await.ok().flatten(),
                        None => None,
                    };
                    if stored.is_some_and(|s| s.outcome == outcome) {
                        return Ok(());
                    }
                }
                return Err(err);
            }
        }
    }
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
    S: kavach_ports::agent_evidence::AgentEvidenceStore
        + kavach_ports::agent_state::AgentStateStore,
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
    // Revoked (or expired) since the decision was recorded: no credential,
    // nothing sent (ADR-012 §5).
    if let Err(why) = core
        .still_authorised(&agent.agent_id, &call.mandate_id)
        .await
    {
        return not_executed(match why {
            StillAuthorised::Unavailable => "mandate_unavailable",
            StillAuthorised::MandateGone => "mandate_revoked",
            StillAuthorised::AgentStopped => "agent_stopped",
        });
    }
    let started = Instant::now();
    let credential_request = CredentialRequest {
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
    };
    let gateway_held = deps
        .gateway_held
        .filter(|dispatch| dispatch.providers.contains(provider));
    let issued = match issue_for_call(deps.broker, gateway_held, &credential_request).await {
        Ok(issued) => issued,
        Err(err) => {
            deps.observer.stage(Stage::Credential, started.elapsed());
            return not_executed(match err.class {
                ErrorClass::Rejected => "credential_refused",
                ErrorClass::Invalid => "credential_invalid",
                ErrorClass::Unavailable => "credential_unavailable",
            });
        }
    };
    deps.observer.stage(Stage::Credential, started.elapsed());
    // A slow resolver or broker must not push the send past the deadline.
    let Some(now) = core.trusted_now() else {
        return not_executed("trusted_time_unavailable");
    };
    if allowed.send_by.is_some_and(|send_by| now >= send_by) {
        return not_executed("send_by_passed");
    }
    if now >= issued.expires_at() {
        return not_executed("credential_expired");
    }

    let started = Instant::now();
    let Ok(result) =
        forward_issued(deps.forwarder, gateway_held, &credential_request, &issued).await
    else {
        return not_executed("provider_mode_mismatch");
    };
    deps.observer.stage(Stage::Forward, started.elapsed());
    let (outcome, reason, _) = classify(&result);
    let message_id = forwarded_message_id(&result);
    (outcome, reason, message_id)
}

async fn issue_for_call<B: CredentialBroker>(
    broker: &B,
    gateway_held: Option<&GatewayHeldDispatch<'_>>,
    request: &CredentialRequest<'_>,
) -> Result<IssuedForCall, kavach_ports::PortError> {
    match gateway_held {
        Some(dispatch) => dispatch
            .broker
            .issue_internal(request)
            .await
            .map(IssuedForCall::Internal),
        None => broker.issue(request).await.map(IssuedForCall::Provider),
    }
}

async fn forward_issued<F: Forwarder>(
    forwarder: &F,
    gateway_held: Option<&GatewayHeldDispatch<'_>>,
    request: &CredentialRequest<'_>,
    issued: &IssuedForCall,
) -> Result<ForwardResult, ()> {
    match (gateway_held, issued) {
        (Some(dispatch), IssuedForCall::Internal(_)) => Ok(dispatch
            .forwarder
            .forward_gateway_held(
                request.audience,
                &GatewayHeldRequest {
                    credential_id: request.credential_id,
                    destination: request.destination,
                    channel: request.channel,
                    template_id: request.template_id,
                },
            )
            .await),
        (None, IssuedForCall::Provider(credential)) => Ok(send_forward_request(
            forwarder,
            request.audience,
            CredentialAcceptingRequest {
                credential_id: request.credential_id,
                destination: request.destination,
                channel: request.channel,
                template_id: request.template_id,
                credential: &credential.token,
            },
        )
        .await),
        _ => Err(()),
    }
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

    struct TokenlessGatewayHeldAdapter;

    impl GatewayHeldForwarder for TokenlessGatewayHeldAdapter {
        fn forward_gateway_held<'a>(
            &'a self,
            provider: &'a str,
            request: &'a GatewayHeldRequest<'a>,
        ) -> GatewayHeldForwardFuture<'a> {
            Box::pin(async move {
                assert_eq!(provider, "free-local-adapter");
                assert_eq!(request.credential_id, "record-1");
                assert_eq!(request.destination.expose(), "+919876543210");
                assert_eq!(request.channel, "whatsapp");
                assert_eq!(request.template_id, "reminder-v1");
                responded(202)
            })
        }
    }

    #[tokio::test]
    async fn gateway_held_adapter_contract_has_no_kavach_token_parameter() {
        let destination = kavach_ports::Destination::new("+919876543210");
        let request = GatewayHeldRequest {
            credential_id: "record-1",
            destination: &destination,
            channel: "whatsapp",
            template_id: "reminder-v1",
        };
        let adapter: &dyn GatewayHeldForwarder = &TokenlessGatewayHeldAdapter;
        let result = adapter
            .forward_gateway_held("free-local-adapter", &request)
            .await;
        assert_eq!(result, responded(202));
    }
}
