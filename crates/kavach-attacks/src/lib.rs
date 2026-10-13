//! The attack catalog: known attacks on the agent surfaces, each with the
//! outcome that means it was refused.
//!
//! One catalog, two runners: `kavach attack` (over HTTP, against a local
//! `kavach dev up`) and the acceptance tests (in process, on memory and
//! Postgres). Both implement [`Target`] and call [`run`], so the CLI runs
//! exactly the tests CI runs.
//!
//! An attack is judged on ground truth as well as on the reply: it
//! **succeeded** if any credential was minted (an allowed gateway call) or
//! the provider's inbox changed while it ran, whatever the reply said.
//!
//! Every attack aims at a refusal: none needs an allowed call, so a run
//! consumes no contact and sends nothing. Request ids start with
//! `attack-`, so the BLOCK records it leaves are easy to find in evidence.

use std::future::Future;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};

mod agent_state;
mod revocation;

/// Bumped whenever an attack is added, removed or its expectation changes.
pub const CATALOG_VERSION: &str = "5";

/// The borrower the dev mandate covers, and one it does not.
pub const SUBJECT: &str = "ref:borrower:B-9382";
/// The borrower the revocation attacks (v4) issue, revoke and replay
/// mandates for, so the dev mandate is never touched. Nothing is sent to
/// it: its mandates are only pre-checked.
pub const ATTACK_SUBJECT: &str = "ref:borrower:B-ATTACK";
const OTHER_SUBJECT: &str = "ref:borrower:B-1";

/// How a request authenticates (or fails to).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Auth {
    /// The holder agent's own token.
    Agent,
    /// Another agent's valid token (not the mandate's holder).
    OtherAgent,
    /// An operator token, on the agent route.
    Operator,
    /// No credential.
    None,
    /// The self-asserted `X-Kavach-Principal` header instead of a token.
    PrincipalHeader,
    /// The agent's token with its signature changed.
    Tampered,
    /// The agent's claims, unsigned (`alg: none`).
    Unsigned,
}

/// What an attack sends.
#[derive(Debug, Clone, Copy)]
pub enum Probe {
    /// `POST /v1/tools/{tool}` on the agent listener.
    ToolCall {
        tool: &'static str,
        auth: Auth,
        /// The mandate to act under: the holder's (`true`) or a forged id.
        real_mandate: bool,
        params: fn() -> Value,
    },
    /// `GET /v1/runtime` on the operator listener.
    OperatorRead { auth: Auth },
    /// `POST /v1/authorize` (the agent pre-check, which records nothing),
    /// for tools the gateway does not execute (proposals).
    Precheck {
        tool: &'static str,
        params: fn() -> Value,
    },
    /// The system-of-record event that issued the mandate, sent again.
    SorReplay,
    /// A message straight to the provider, with no gateway credential.
    ProviderDirect,
    /// A reminder at 20:30 IST: the stack's clock is moved there first
    /// (needs a development clock), and on to the next 11:00 afterwards.
    OutOfHours,
    /// A fourth reminder in a day: the clock moves to 11:00 on a fresh day,
    /// three allowed reminders are made as declared setup (not judged, and
    /// reported), then the fourth is judged (needs a development clock).
    DailyCap,
    /// A system-of-record event against the attack borrower's mandates
    /// (ADR-012). Its declared setup assigns the borrower (a mandate);
    /// ground truth is that mandate, pre-checked, and the evidence chain.
    Revocation(RevocationAttack),
    /// An attack on the agent kill switch (ADR-013). Its declared setup
    /// assigns the attack borrower and stops the holder agent through the
    /// operator API; it is judged on the reply and on ground truth (the
    /// state read back, a pre-check of the attack mandate, nothing minted),
    /// and then the agent is brought back through the real approval path.
    AgentState(AgentStateAttack),
}

/// The kill-switch attacks (catalog v5, ADR-013 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentStateAttack {
    /// A quarantined agent calls a tool under its own mandate.
    QuarantinedActs,
    /// A restricted agent tries to contact the borrower.
    RestrictedContacts,
    /// A quarantined agent is loosened without anyone approving: through a
    /// weaker stop, and by a proposal nobody approved.
    ReinstateWithoutApproval,
    /// The principal who proposed a reinstatement approves it.
    SelfApprovedReinstate,
    /// A client-certificate (machine) principal approves a reinstatement.
    CertificatePrincipalApproves,
}

/// Who speaks on the operator API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    /// The operator: may stop and propose, and (in the development and
    /// acceptance worlds) holds the approver role too, so that only the
    /// distinct-identity rule refuses its own approval.
    Operator,
    /// A second human principal with the approver role.
    Approver,
    /// A machine principal identified by a client certificate, holding the
    /// approver role in the policy.
    Certificate,
}

/// The revocation attacks (catalog v4, ADR-012 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationAttack {
    /// A payment signed with a key no system of record is registered with.
    Forged,
    /// A payment dated 15 minutes ago: outside the freshness window.
    Stale,
    /// A payment dated 15 minutes ahead: outside the freshness window.
    Future,
    /// A validly signed event of a type no template or revocation knows.
    UnknownType,
    /// A validly signed payment for the same loan, for another tenant.
    OtherTenant,
    /// A validly signed payment for another loan.
    WrongLoan,
    /// A validly signed payment dated before the attack mandate was issued.
    ReachesForward,
    /// A payment that revoked one mandate, sent again after a new mandate
    /// was issued for the same loan.
    Replayed,
}

/// Which key signs a system-of-record event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SorKey {
    /// The issuer key registered for the system (`lms`).
    Registered,
    /// A key nobody registered.
    Unregistered,
}

/// Which loan a system-of-record event names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loan {
    /// The attack borrower's loan.
    Attack,
    /// A loan no mandate was ever issued for.
    Unused,
}

/// A system-of-record event for the target to sign: dated
/// `offset_seconds` from the stack's own clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorSpec {
    pub event_id: String,
    pub event_type: &'static str,
    pub key: SorKey,
    /// For a tenant other than the one the stack serves.
    pub other_tenant: bool,
    pub loan: Loan,
    pub offset_seconds: i64,
}

impl Probe {
    /// Whether the attack needs to move the stack's clock.
    #[must_use]
    pub fn needs_clock(self) -> bool {
        matches!(self, Self::OutOfHours | Self::DailyCap)
    }
}

/// The reply that means the attack was refused.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expect {
    /// A decision (never PASS or ALERT) whose reasons include `reason`
    /// (a prefix for parameterised codes such as `raw_identifier:`).
    Decision {
        decision: &'static str,
        reason: &'static str,
    },
    /// An HTTP status.
    Status { status: u16 },
    /// The replayed event returns the existing mandate, marked replayed.
    SameMandate,
    /// The event is refused (any 4xx), the attack mandate stays live and
    /// no revocation is recorded for the event.
    EventRefused,
    /// The event is accepted and revokes nothing: the attack mandate stays
    /// live.
    RevokesNothing,
    /// The event again returns the first result, marked replayed: the
    /// mandate issued since stays live and no second record is written.
    StoredRevocation,
    /// Any 4xx from the provider.
    Refused,
    /// The agent stays stopped: its call is a BLOCK for `reason`, the state
    /// read back is still `state`, and no reinstatement went through.
    AgentStaysStopped {
        state: &'static str,
        reason: &'static str,
    },
}

/// One attack.
#[derive(Debug, Clone, Copy)]
pub struct Attack {
    pub id: &'static str,
    pub group: &'static str,
    pub tries: &'static str,
    pub probe: Probe,
    pub expect: Expect,
    /// The `SECURITY_PROPERTIES.md` row it exercises (its bold title).
    pub security_property: &'static str,
    /// The `BYPASS_INVENTORY.md` row it relates to, if any.
    pub bypass: Option<&'static str>,
}

fn reminder(subject: &'static str, channel: &'static str) -> Value {
    json!({ "subject_ref": subject, "channel": channel, "template_id": "emi_reminder_v1" })
}

const CORE: &str = "Agent authorization core (library):";
const REGISTRY: &str = "Agent tool registry:";
const SURFACES: &str = "Agent surfaces:";
const OPERATORS: &str = "With OIDC configured";
const BACKENDS: &str = "Credential-accepting backends";
const UNSEEN_IDENTIFIER: &str = "An identifier the detectors do not see, in a tool parameter";
const STOLEN_TOKEN: &str = "An agent token stolen before it expires";
const SOR_KEY: &str = "A system of record with a valid issuer key";
const REVOCATION: &str = "Revocation by system-of-record event (ADR-012):";
const AROUND: &str = "A resource the agent reaches without the gateway";
const STOPPED: &str =
    "A stopped agent does nothing, from its next call, on every replica (ADR-013, K1-1):";

/// The catalog, in the order it runs.
pub const CATALOG: [Attack; 35] = [
    Attack {
        id: "raw-phone-number",
        group: "identifiers",
        tries: "a raw mobile number in place of the borrower reference",
        probe: Probe::ToolCall {
            tool: "send_reminder",
            auth: Auth::Agent,
            real_mandate: true,
            params: || reminder("ref:borrower:9876543210", "whatsapp"),
        },
        expect: Expect::Decision {
            decision: "BLOCK",
            reason: "raw_identifier:",
        },
        security_property: CORE,
        bypass: Some(UNSEEN_IDENTIFIER),
    },
    Attack {
        id: "raw-pan",
        group: "identifiers",
        tries: "a PAN in place of the borrower reference",
        probe: Probe::ToolCall {
            tool: "send_reminder",
            auth: Auth::Agent,
            real_mandate: true,
            params: || reminder("ref:borrower:ABCPE1234F", "whatsapp"),
        },
        expect: Expect::Decision {
            decision: "BLOCK",
            reason: "raw_identifier:",
        },
        security_property: CORE,
        bypass: Some(UNSEEN_IDENTIFIER),
    },
    Attack {
        id: "raw-aadhaar",
        group: "identifiers",
        tries: "an Aadhaar-like 12-digit number in place of the borrower reference",
        probe: Probe::ToolCall {
            tool: "send_reminder",
            auth: Auth::Agent,
            real_mandate: true,
            params: || reminder("ref:borrower:234567890123", "whatsapp"),
        },
        expect: Expect::Decision {
            decision: "BLOCK",
            reason: "raw_identifier:",
        },
        security_property: CORE,
        bypass: Some(UNSEEN_IDENTIFIER),
    },
    Attack {
        id: "another-borrower",
        group: "mandate",
        tries: "contacting a borrower the mandate does not cover",
        probe: Probe::ToolCall {
            tool: "send_reminder",
            auth: Auth::Agent,
            real_mandate: true,
            params: || reminder(OTHER_SUBJECT, "whatsapp"),
        },
        expect: Expect::Decision {
            decision: "BLOCK",
            reason: "subject-binding",
        },
        security_property: CORE,
        bypass: None,
    },
    Attack {
        id: "forged-mandate",
        group: "mandate",
        tries: "acting under a mandate id that was never issued",
        probe: Probe::ToolCall {
            tool: "send_reminder",
            auth: Auth::Agent,
            real_mandate: false,
            params: || reminder(SUBJECT, "whatsapp"),
        },
        expect: Expect::Decision {
            decision: "BLOCK",
            reason: "mandate_invalid",
        },
        security_property: CORE,
        bypass: None,
    },
    Attack {
        id: "other-agent-on-mandate",
        group: "mandate",
        tries: "another agent's valid token acting under this agent's mandate",
        probe: Probe::ToolCall {
            tool: "send_reminder",
            auth: Auth::OtherAgent,
            real_mandate: true,
            params: || reminder(SUBJECT, "whatsapp"),
        },
        expect: Expect::Decision {
            decision: "BLOCK",
            reason: "no_matching_permit",
        },
        security_property: CORE,
        bypass: Some(STOLEN_TOKEN),
    },
    Attack {
        id: "replayed-sor-event",
        group: "mandate",
        tries: "sending the system-of-record event again to get a second mandate",
        probe: Probe::SorReplay,
        expect: Expect::SameMandate,
        security_property: SURFACES,
        bypass: Some(SOR_KEY),
    },
    Attack {
        id: "channel-outside-mandate",
        group: "policy",
        tries: "a channel the mandate does not allow",
        probe: Probe::ToolCall {
            tool: "send_reminder",
            auth: Auth::Agent,
            real_mandate: true,
            params: || reminder(SUBJECT, "sms"),
        },
        expect: Expect::Decision {
            decision: "BLOCK",
            reason: "channel-within-mandate",
        },
        security_property: CORE,
        bypass: None,
    },
    Attack {
        id: "value-outside-registry",
        group: "policy",
        tries: "a channel value the signed tool registry does not list",
        probe: Probe::ToolCall {
            tool: "send_reminder",
            auth: Auth::Agent,
            real_mandate: true,
            params: || reminder(SUBJECT, "voice"),
        },
        expect: Expect::Decision {
            decision: "BLOCK",
            reason: "value_not_allowed:channel",
        },
        security_property: REGISTRY,
        bypass: None,
    },
    Attack {
        id: "waiver-above-ceiling",
        group: "policy",
        tries: "a 25% waiver where the mandate's ceiling is 10%",
        probe: Probe::Precheck {
            tool: "propose_plan",
            params: || json!({ "subject_ref": SUBJECT, "waiver_bps": 2500 }),
        },
        expect: Expect::Decision {
            decision: "HUMAN_REVIEW",
            reason: "waiver-ceiling",
        },
        security_property: CORE,
        bypass: None,
    },
    Attack {
        id: "agent-set-timestamp",
        group: "request",
        tries: "the agent supplying its own timestamp to dodge the contact window",
        probe: Probe::ToolCall {
            tool: "send_reminder",
            auth: Auth::Agent,
            real_mandate: true,
            params: || {
                let mut p = reminder(SUBJECT, "whatsapp");
                p["timestamp"] = json!("2026-10-01T05:30:00Z");
                p
            },
        },
        expect: Expect::Status { status: 400 },
        security_property: REGISTRY,
        bypass: None,
    },
    Attack {
        id: "unregistered-tool",
        group: "request",
        tries: "calling a tool the signed registry does not list",
        probe: Probe::ToolCall {
            tool: "export_all_borrowers",
            auth: Auth::Agent,
            real_mandate: true,
            params: || json!({ "subject_ref": SUBJECT }),
        },
        expect: Expect::Status { status: 400 },
        security_property: REGISTRY,
        bypass: None,
    },
    Attack {
        id: "no-token",
        group: "authentication",
        tries: "a tool call with no credential",
        probe: Probe::ToolCall {
            tool: "send_reminder",
            auth: Auth::None,
            real_mandate: true,
            params: || reminder(SUBJECT, "whatsapp"),
        },
        expect: Expect::Status { status: 401 },
        security_property: SURFACES,
        bypass: None,
    },
    Attack {
        id: "operator-token-on-agent-route",
        group: "authentication",
        tries: "an operator's token on the agent listener",
        probe: Probe::ToolCall {
            tool: "send_reminder",
            auth: Auth::Operator,
            real_mandate: true,
            params: || reminder(SUBJECT, "whatsapp"),
        },
        expect: Expect::Status { status: 401 },
        security_property: SURFACES,
        bypass: None,
    },
    Attack {
        id: "principal-header",
        group: "authentication",
        tries: "claiming an identity with the X-Kavach-Principal header",
        probe: Probe::ToolCall {
            tool: "send_reminder",
            auth: Auth::PrincipalHeader,
            real_mandate: true,
            params: || reminder(SUBJECT, "whatsapp"),
        },
        expect: Expect::Status { status: 401 },
        security_property: SURFACES,
        bypass: None,
    },
    Attack {
        id: "tampered-token",
        group: "authentication",
        tries: "the agent's token with its signature changed",
        probe: Probe::ToolCall {
            tool: "send_reminder",
            auth: Auth::Tampered,
            real_mandate: true,
            params: || reminder(SUBJECT, "whatsapp"),
        },
        expect: Expect::Status { status: 401 },
        security_property: SURFACES,
        bypass: None,
    },
    Attack {
        id: "unsigned-token",
        group: "authentication",
        tries: "the agent's claims with `alg: none` and no signature",
        probe: Probe::ToolCall {
            tool: "send_reminder",
            auth: Auth::Unsigned,
            real_mandate: true,
            params: || reminder(SUBJECT, "whatsapp"),
        },
        expect: Expect::Status { status: 401 },
        security_property: SURFACES,
        bypass: None,
    },
    Attack {
        id: "agent-token-on-operator-route",
        group: "authentication",
        tries: "an agent's token on the operator API",
        probe: Probe::OperatorRead { auth: Auth::Agent },
        expect: Expect::Status { status: 401 },
        security_property: OPERATORS,
        bypass: Some(STOLEN_TOKEN),
    },
    Attack {
        id: "no-token-on-operator-route",
        group: "authentication",
        tries: "the operator API with no credential",
        probe: Probe::OperatorRead { auth: Auth::None },
        expect: Expect::Status { status: 401 },
        security_property: OPERATORS,
        bypass: None,
    },
    Attack {
        id: "out-of-hours",
        group: "policy",
        tries: "a reminder at 20:30 IST, outside the contact window",
        probe: Probe::OutOfHours,
        expect: Expect::Decision {
            decision: "BLOCK",
            reason: "contact-window",
        },
        security_property: CORE,
        bypass: None,
    },
    Attack {
        id: "daily-cap",
        group: "policy",
        tries: "a fourth reminder to the same borrower in one day",
        probe: Probe::DailyCap,
        expect: Expect::Decision {
            decision: "BLOCK",
            reason: "contact-daily-cap",
        },
        security_property: CORE,
        bypass: None,
    },
    Attack {
        id: "provider-without-credential",
        group: "around the gateway",
        tries: "sending a message straight to the provider, with no gateway credential",
        probe: Probe::ProviderDirect,
        expect: Expect::Refused,
        security_property: BACKENDS,
        bypass: Some(AROUND),
    },
    Attack {
        id: "forged-revocation",
        group: "revocation",
        tries: "a payment signed with a key no system of record is registered with",
        probe: Probe::Revocation(RevocationAttack::Forged),
        expect: Expect::EventRefused,
        security_property: REVOCATION,
        bypass: None,
    },
    Attack {
        id: "stale-revocation",
        group: "revocation",
        tries: "a validly signed payment dated 15 minutes ago, outside the freshness window",
        probe: Probe::Revocation(RevocationAttack::Stale),
        expect: Expect::EventRefused,
        security_property: REVOCATION,
        bypass: Some(SOR_KEY),
    },
    Attack {
        id: "future-revocation",
        group: "revocation",
        tries: "a validly signed payment dated 15 minutes ahead, outside the freshness window",
        probe: Probe::Revocation(RevocationAttack::Future),
        expect: Expect::EventRefused,
        security_property: REVOCATION,
        bypass: Some(SOR_KEY),
    },
    Attack {
        id: "unknown-event-type",
        group: "revocation",
        tries: "a validly signed event of a type nothing is registered for",
        probe: Probe::Revocation(RevocationAttack::UnknownType),
        expect: Expect::EventRefused,
        security_property: REVOCATION,
        bypass: Some(SOR_KEY),
    },
    Attack {
        id: "revocation-for-another-tenant",
        group: "revocation",
        tries: "a validly signed payment for the same loan, for another tenant",
        probe: Probe::Revocation(RevocationAttack::OtherTenant),
        expect: Expect::EventRefused,
        security_property: REVOCATION,
        bypass: Some(SOR_KEY),
    },
    Attack {
        id: "revocation-wrong-loan",
        group: "revocation",
        tries: "a validly signed payment for another loan, to reach this borrower's mandate",
        probe: Probe::Revocation(RevocationAttack::WrongLoan),
        expect: Expect::RevokesNothing,
        security_property: REVOCATION,
        bypass: Some(SOR_KEY),
    },
    Attack {
        id: "revocation-reaches-forward",
        group: "revocation",
        tries: "a validly signed payment dated before the mandate was issued",
        probe: Probe::Revocation(RevocationAttack::ReachesForward),
        expect: Expect::RevokesNothing,
        security_property: REVOCATION,
        bypass: Some(SOR_KEY),
    },
    Attack {
        id: "replayed-revocation",
        group: "revocation",
        tries: "an old payment sent again, to revoke the mandate issued after it",
        probe: Probe::Revocation(RevocationAttack::Replayed),
        expect: Expect::StoredRevocation,
        security_property: REVOCATION,
        bypass: Some(SOR_KEY),
    },
    Attack {
        id: "quarantined-agent-acts",
        group: "agent-state",
        tries: "a quarantined agent calling a tool under its own mandate",
        probe: Probe::AgentState(AgentStateAttack::QuarantinedActs),
        expect: Expect::AgentStaysStopped {
            state: "quarantined",
            reason: "agent-stopped",
        },
        security_property: STOPPED,
        bypass: None,
    },
    Attack {
        id: "restricted-agent-contacts",
        group: "agent-state",
        tries: "a restricted agent contacting the borrower",
        probe: Probe::AgentState(AgentStateAttack::RestrictedContacts),
        expect: Expect::AgentStaysStopped {
            state: "restricted",
            reason: "agent-restricted",
        },
        security_property: STOPPED,
        bypass: None,
    },
    Attack {
        id: "reinstate-without-approval",
        group: "agent-state",
        tries: "loosening a quarantined agent with no approver: a weaker stop, and a proposal nobody approves",
        probe: Probe::AgentState(AgentStateAttack::ReinstateWithoutApproval),
        expect: Expect::AgentStaysStopped {
            state: "quarantined",
            reason: "agent-stopped",
        },
        security_property: STOPPED,
        bypass: None,
    },
    Attack {
        id: "self-approved-reinstate",
        group: "agent-state",
        tries: "the principal who proposed a reinstatement approving it",
        probe: Probe::AgentState(AgentStateAttack::SelfApprovedReinstate),
        expect: Expect::AgentStaysStopped {
            state: "quarantined",
            reason: "agent-stopped",
        },
        security_property: STOPPED,
        bypass: None,
    },
    Attack {
        id: "certificate-principal-approves",
        group: "agent-state",
        tries: "a client-certificate principal, holding the approver role, approving a reinstatement",
        probe: Probe::AgentState(AgentStateAttack::CertificatePrincipalApproves),
        expect: Expect::AgentStaysStopped {
            state: "quarantined",
            reason: "agent-stopped",
        },
        security_property: STOPPED,
        bypass: None,
    },
];

/// The agent token of the attack that uses one, changed as `auth` asks.
#[must_use]
pub fn headers(
    auth: Auth,
    agent: &str,
    other_agent: &str,
    operator: &str,
) -> Vec<(String, String)> {
    let bearer = |t: &str| vec![("authorization".to_string(), format!("Bearer {t}"))];
    match auth {
        Auth::Agent => bearer(agent),
        Auth::OtherAgent => bearer(other_agent),
        Auth::Operator => bearer(operator),
        Auth::None => Vec::new(),
        Auth::PrincipalHeader => {
            vec![(
                "x-kavach-principal".to_string(),
                "collections-agent".to_string(),
            )]
        }
        Auth::Tampered => bearer(&tampered(agent)),
        Auth::Unsigned => bearer(&unsigned(agent)),
    }
}

/// The token with the first character of its signature changed.
fn tampered(token: &str) -> String {
    let Some((head, sig)) = token.rsplit_once('.') else {
        return format!("{token}x");
    };
    let mut sig: Vec<char> = sig.chars().collect();
    if let Some(c) = sig.first_mut() {
        *c = if *c == 'A' { 'B' } else { 'A' };
    }
    format!("{head}.{}", sig.into_iter().collect::<String>())
}

/// The token's claims under `{"alg":"none"}`, with an empty signature.
fn unsigned(token: &str) -> String {
    let claims = token.split('.').nth(1).unwrap_or_default();
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    format!("{header}.{claims}.")
}

/// Allowed gateway calls (credentials minted) in a Prometheus text
/// exposition: the sum of `kavach_gateway_calls_total` with decision PASS
/// or ALERT.
#[must_use]
pub fn allowed_calls(metrics: &str) -> u64 {
    metrics
        .lines()
        .filter(|l| l.starts_with("kavach_gateway_calls_total{"))
        .filter(|l| l.contains("decision=\"PASS\"") || l.contains("decision=\"ALERT\""))
        // Integer counters print as integers.
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

/// What a runner can do against a stack.
pub trait Target {
    fn agent_token(&self) -> String;
    fn other_agent_token(&self) -> String;
    fn operator_token(&self) -> String;
    /// The holder agent's mandate on this stack.
    fn mandate(&self) -> String;
    /// `POST` on the agent listener: status and JSON body.
    fn post_agent(
        &self,
        path: &str,
        headers: Vec<(String, String)>,
        body: Value,
    ) -> impl Future<Output = Result<(u16, Value), String>>;
    /// `GET` on the operator listener: status.
    fn get_operator(
        &self,
        path: &str,
        headers: Vec<(String, String)>,
    ) -> impl Future<Output = Result<u16, String>>;
    /// The event that issued [`mandate`](Self::mandate), sent again:
    /// status and body.
    fn replay_sor_event(&self) -> impl Future<Output = Result<(u16, Value), String>>;
    /// A message straight to the provider, without a credential: status.
    fn post_provider(&self) -> impl Future<Output = Result<u16, String>>;
    /// Messages the provider has delivered so far.
    fn delivered(&self) -> impl Future<Output = Result<usize, String>>;
    /// Allowed gateway calls so far (see [`allowed_calls`]).
    fn allowed(&self) -> impl Future<Output = Result<u64, String>>;
    /// Called between attacks (a live runner rate-limits itself here).
    fn pause(&self) -> impl Future<Output = ()>;
    /// Whether this stack's clock can be moved (a fixed development clock).
    fn clock_control(&self) -> bool;
    /// Whether the stack holds [`ATTACK_SUBJECT`] (projects made before
    /// catalog v4 do not: `kavach init --force`).
    fn has_attack_borrower(&self) -> bool;
    /// Assigns [`ATTACK_SUBJECT`] to the holder agent with a fresh event:
    /// the new mandate's id.
    fn assign_attack_borrower(&self) -> impl Future<Output = Result<String, String>>;
    /// Signs a system-of-record event to `spec`.
    fn sign_sor_event(&self, spec: &SorSpec) -> impl Future<Output = Result<String, String>>;
    /// Sends a signed system-of-record event: status and body.
    fn post_sor_event(&self, token: &str) -> impl Future<Output = Result<(u16, Value), String>>;
    /// The hash of the evidence-chain record of the revocation by
    /// `event_id` (system `lms`), if one was written.
    fn revocation_record(
        &self,
        event_id: &str,
    ) -> impl Future<Output = Result<Option<String>, String>>;
    /// The agent that holds [`mandate`](Self::mandate): the one the
    /// kill-switch attacks stop.
    fn agent_id(&self) -> String {
        "collections-agent".into()
    }
    /// Whether this runner can speak as `who` on the operator API (a
    /// development stack made before catalog v5 has no approver token:
    /// `kavach init --force`; only some runners can present a client
    /// certificate).
    fn has_principal(&self, who: Principal) -> bool {
        who == Principal::Operator
    }
    /// A request to the operator API as `who`: status and JSON body (a
    /// problem document for an error).
    fn operator_request(
        &self,
        who: Principal,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> impl Future<Output = Result<(u16, Value), String>>;
    /// Moves the stack's clock forward to the next `hour:minute` IST; with
    /// `fresh_day`, to that time on a later IST day than any so far.
    fn move_clock(
        &self,
        hour: u32,
        minute: u32,
        fresh_day: bool,
    ) -> impl Future<Output = Result<(), String>>;
}

/// How an attack ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Refused as expected, and nothing was minted or sent.
    Refused,
    /// Refused, but not as the catalog expects (the policies changed or
    /// the catalog is stale). Not a breach; the run still fails.
    RefusedUnexpectedly,
    /// It got through: an allowed decision, a 2xx where a refusal was
    /// expected, a credential minted or a message sent.
    Succeeded,
    /// It could not be judged (a request failed to reach the stack, or its
    /// declared setup did not run as expected).
    Error,
    /// Not run: it needs a development clock this stack does not have.
    Skipped,
    /// Not run: the stack lacks what it needs (the attack borrower), so
    /// nothing can be concluded. Never a pass.
    Inconclusive,
}

/// One attack's result.
#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub id: &'static str,
    pub group: &'static str,
    pub tries: &'static str,
    pub expected: Expect,
    pub observed: Value,
    pub verdict: Verdict,
    pub security_property: &'static str,
    pub bypass: Option<&'static str>,
    /// What its declared setup did, if it has one (not judged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup: Option<Value>,
}

/// A run of the catalog.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub catalog_version: &'static str,
    pub outcomes: Vec<Outcome>,
    /// Ground truth across every attack's judged window.
    pub credentials_minted: u64,
    pub messages_delivered: usize,
    /// What declared setups did (allowed on purpose, not judged).
    pub setup_credentials: u64,
    pub setup_messages: usize,
}

impl Report {
    /// Whether any attack got through, or ground truth moved.
    #[must_use]
    pub fn breached(&self) -> bool {
        self.credentials_minted > 0
            || self.messages_delivered > 0
            || self
                .outcomes
                .iter()
                .any(|o| o.verdict == Verdict::Succeeded)
    }

    /// Whether every attack was refused exactly as the catalog expects.
    #[must_use]
    pub fn all_refused_as_expected(&self) -> bool {
        !self.breached() && self.outcomes.iter().all(|o| o.verdict == Verdict::Refused)
    }

    /// Whether every attack that ran was refused as expected (skipped ones
    /// did not run, and are reported).
    #[must_use]
    pub fn passed(&self) -> bool {
        !self.breached()
            && self
                .outcomes
                .iter()
                .all(|o| matches!(o.verdict, Verdict::Refused | Verdict::Skipped))
    }

    /// Attacks that could not be run on this stack (never a pass).
    #[must_use]
    pub fn inconclusive(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| o.verdict == Verdict::Inconclusive)
            .count()
    }

    /// Attacks skipped for want of a development clock.
    #[must_use]
    pub fn skipped(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| o.verdict == Verdict::Skipped)
            .count()
    }
}

fn allowed_decision(decision: &str) -> bool {
    matches!(decision, "PASS" | "ALERT")
}

/// Judges a reply against the expectation (ground truth is checked by the
/// caller).
fn judge(expect: Expect, status: u16, body: &Value) -> Verdict {
    match expect {
        Expect::Decision { decision, reason } => {
            let got = body["decision"].as_str().unwrap_or_default();
            if allowed_decision(got) {
                return Verdict::Succeeded;
            }
            let reasons: Vec<&str> = body["reasons"]
                .as_array()
                .map(|r| r.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let has_reason = reasons.iter().any(|r| r.starts_with(reason));
            if status == 200 && got == decision && has_reason {
                Verdict::Refused
            } else if (200..300).contains(&status) && got.is_empty() {
                Verdict::Succeeded
            } else {
                Verdict::RefusedUnexpectedly
            }
        }
        Expect::Status { status: want } => {
            if (200..300).contains(&status)
                && allowed_decision(body["decision"].as_str().unwrap_or("PASS"))
            {
                Verdict::Succeeded
            } else if status == want {
                Verdict::Refused
            } else {
                Verdict::RefusedUnexpectedly
            }
        }
        Expect::SameMandate
        | Expect::Refused
        | Expect::EventRefused
        | Expect::RevokesNothing
        | Expect::StoredRevocation
        | Expect::AgentStaysStopped { .. } => Verdict::Error,
    }
}

/// A suffix no earlier run used: the wall clock's nanoseconds and a counter
/// (two runs in the same nanosecond still differ).
fn unique() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{nanos:x}{:x}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Ground truth now: allowed calls (credentials minted), messages delivered.
async fn ground<T: Target>(target: &T) -> (Result<u64, String>, Result<usize, String>) {
    (target.allowed().await, target.delivered().await)
}

/// A revocation attack judged, with what it minted and sent (nothing, if
/// the stack holds: ground truth overrides the reply).
struct Judged {
    verdict: Verdict,
    observed: Value,
    setup: Option<Value>,
    minted: u64,
    sent: usize,
}

async fn revocation_with_ground_truth<T: Target>(
    target: &T,
    kind: RevocationAttack,
    expect: Expect,
    n: &str,
) -> Judged {
    let (before_allowed, before_delivered) = ground(target).await;
    let (verdict, observed, setup) = if target.has_attack_borrower() {
        crate::revocation::run(target, kind, expect, n).await
    } else {
        (
            Verdict::Inconclusive,
            json!({
                "inconclusive": format!("the project has no {ATTACK_SUBJECT}"),
                "fix": "kavach init --force (it rewrites the development bundle)",
            }),
            None,
        )
    };
    // Nothing may be minted or sent, setup included.
    let (after_allowed, after_delivered) = ground(target).await;
    let minted = match (&before_allowed, &after_allowed) {
        (Ok(b), Ok(a)) => a.saturating_sub(*b),
        _ => 0,
    };
    let sent = match (&before_delivered, &after_delivered) {
        (Ok(b), Ok(a)) => a.abs_diff(*b),
        _ => 0,
    };
    let verdict = if minted > 0 || sent > 0 {
        Verdict::Succeeded
    } else {
        verdict
    };
    Judged {
        verdict,
        observed,
        setup,
        minted,
        sent,
    }
}

async fn agent_state_with_ground_truth<T: Target>(
    target: &T,
    kind: AgentStateAttack,
    expect: Expect,
    n: &str,
) -> Judged {
    let (before_allowed, before_delivered) = ground(target).await;
    let (verdict, observed, setup) = if target.has_attack_borrower() {
        crate::agent_state::run(target, kind, expect, n).await
    } else {
        (
            Verdict::Inconclusive,
            json!({
                "inconclusive": format!("the project has no {ATTACK_SUBJECT}"),
                "fix": "kavach init --force (it rewrites the development bundle)",
            }),
            None,
        )
    };
    // Nothing may be minted or sent, setup and teardown included.
    let (after_allowed, after_delivered) = ground(target).await;
    let minted = match (&before_allowed, &after_allowed) {
        (Ok(b), Ok(a)) => a.saturating_sub(*b),
        _ => 0,
    };
    let sent = match (&before_delivered, &after_delivered) {
        (Ok(b), Ok(a)) => a.abs_diff(*b),
        _ => 0,
    };
    let verdict = if minted > 0 || sent > 0 {
        Verdict::Succeeded
    } else {
        verdict
    };
    Judged {
        verdict,
        observed,
        setup,
        minted,
        sent,
    }
}

/// Runs `attacks` against `target`, judging each on its reply and on
/// ground truth (credentials minted, messages delivered).
pub async fn run<T: Target>(target: &T, attacks: &[Attack]) -> Report {
    // Every id a run sends (request ids, event ids) carries this: a stack
    // keeps every id it has seen, and another run's content under the same
    // id would be refused as a conflict, not judged.
    let run_id = unique();
    let mut outcomes = Vec::new();
    let (mut minted_total, mut delivered_total) = (0u64, 0usize);
    let (mut setup_minted, mut setup_delivered) = (0u64, 0usize);
    for (index, attack) in attacks.iter().enumerate() {
        let n = format!("{index}-{run_id}");
        let n = n.as_str();
        target.pause().await;
        let outcome = |verdict, observed, setup| Outcome {
            id: attack.id,
            group: attack.group,
            tries: attack.tries,
            expected: attack.expect,
            observed,
            verdict,
            security_property: attack.security_property,
            bypass: attack.bypass,
            setup,
        };
        if attack.probe.needs_clock() && !target.clock_control() {
            outcomes.push(outcome(
                Verdict::Skipped,
                json!({ "skipped": "needs a development clock: kavach dev up --clock" }),
                None,
            ));
            continue;
        }
        if let Probe::Revocation(kind) = attack.probe {
            let judged = revocation_with_ground_truth(target, kind, attack.expect, n).await;
            minted_total += judged.minted;
            delivered_total += judged.sent;
            outcomes.push(outcome(judged.verdict, judged.observed, judged.setup));
            continue;
        }
        if let Probe::AgentState(kind) = attack.probe {
            let judged = agent_state_with_ground_truth(target, kind, attack.expect, n).await;
            minted_total += judged.minted;
            delivered_total += judged.sent;
            outcomes.push(outcome(judged.verdict, judged.observed, judged.setup));
            continue;
        }
        // Declared setup first, outside the judged window.
        let setup = match prepare(target, attack, n).await {
            Ok(setup) => setup,
            Err(e) => {
                outcomes.push(outcome(Verdict::Error, json!({ "setup_failed": e }), None));
                continue;
            }
        };
        if let Some((allowed, delivered, _)) = &setup {
            setup_minted += allowed;
            setup_delivered += delivered;
        }
        let (before_allowed, before_delivered) = ground(target).await;
        let (verdict, observed) = probe(target, attack, n).await;
        let (after_allowed, after_delivered) = ground(target).await;
        let minted = match (&before_allowed, &after_allowed) {
            (Ok(b), Ok(a)) => a.saturating_sub(*b),
            _ => 0,
        };
        let sent = match (&before_delivered, &after_delivered) {
            (Ok(b), Ok(a)) => a.abs_diff(*b),
            _ => 0,
        };
        minted_total += minted;
        delivered_total += sent;
        let verdict = if minted > 0 || sent > 0 {
            Verdict::Succeeded
        } else {
            verdict
        };
        outcomes.push(outcome(verdict, observed, setup.map(|(_, _, v)| v)));
        if matches!(attack.probe, Probe::OutOfHours) {
            // Back inside the contact window for what follows.
            let _ = target.move_clock(11, 0, false).await;
        }
    }
    Report {
        catalog_version: CATALOG_VERSION,
        outcomes,
        credentials_minted: minted_total,
        messages_delivered: delivered_total,
        setup_credentials: setup_minted,
        setup_messages: setup_delivered,
    }
}

type Setup = Option<(u64, usize, Value)>;

/// An attack's declared setup, before its judged window: what it allowed
/// and delivered on purpose, and a description.
async fn prepare<T: Target>(target: &T, attack: &Attack, n: &str) -> Result<Setup, String> {
    match attack.probe {
        Probe::OutOfHours => {
            target.move_clock(20, 30, false).await?;
            Ok(None)
        }
        Probe::DailyCap => {
            target.move_clock(11, 0, true).await?;
            let (before_allowed, before_delivered) = ground(target).await;
            for k in 1..=3 {
                let body = json!({
                    "mandate_id": target.mandate(),
                    "request_id": format!("attack-setup-{}-{n}-{k}", attack.id),
                    "params": reminder(SUBJECT, "whatsapp"),
                });
                let (status, reply) = target
                    .post_agent(
                        "/v1/tools/send_reminder",
                        auth_headers(target, Auth::Agent),
                        body,
                    )
                    .await?;
                if status != 200 || reply["decision"] != "PASS" {
                    return Err(format!(
                        "setup call {k} of 3 was not allowed ({status}: {})",
                        reply["reasons"]
                    ));
                }
                target.pause().await;
            }
            let (after_allowed, after_delivered) = ground(target).await;
            let allowed = match (before_allowed, after_allowed) {
                (Ok(b), Ok(a)) => a.saturating_sub(b),
                _ => 0,
            };
            let delivered = match (before_delivered, after_delivered) {
                (Ok(b), Ok(a)) => a.abs_diff(b),
                _ => 0,
            };
            Ok(Some((
                allowed,
                delivered,
                json!({
                    "declared": "three allowed reminders on a fresh day, to reach the daily cap",
                    "allowed_calls": allowed,
                    "messages_delivered": delivered,
                }),
            )))
        }
        _ => Ok(None),
    }
}

fn auth_headers<T: Target>(target: &T, auth: Auth) -> Vec<(String, String)> {
    headers(
        auth,
        &target.agent_token(),
        &target.other_agent_token(),
        &target.operator_token(),
    )
}

fn decision_reply(expect: Expect, status: u16, reply: &Value) -> (Verdict, Value) {
    (
        judge(expect, status, reply),
        json!({ "status": status, "decision": reply["decision"], "reasons": reply["reasons"] }),
    )
}

async fn probe<T: Target>(target: &T, attack: &Attack, n: &str) -> (Verdict, Value) {
    let request_id = format!("attack-{}-{n}", attack.id);
    match attack.probe {
        Probe::ToolCall {
            tool,
            auth,
            real_mandate,
            params,
        } => {
            let headers = auth_headers(target, auth);
            let mandate = if real_mandate {
                target.mandate()
            } else {
                "ma-attack-forged".to_string()
            };
            let body =
                json!({ "mandate_id": mandate, "request_id": request_id, "params": params() });
            match target
                .post_agent(&format!("/v1/tools/{tool}"), headers, body)
                .await
            {
                Ok((status, reply)) => decision_reply(attack.expect, status, &reply),
                Err(e) => (Verdict::Error, json!({ "error": e })),
            }
        }
        Probe::OperatorRead { auth } => {
            let headers = auth_headers(target, auth);
            match target.get_operator("/v1/runtime", headers).await {
                Ok(status) => (
                    judge(attack.expect, status, &Value::Null),
                    json!({ "status": status }),
                ),
                Err(e) => (Verdict::Error, json!({ "error": e })),
            }
        }
        Probe::Precheck { tool, params } => {
            let headers = auth_headers(target, Auth::Agent);
            let body = json!({
                "tool": tool,
                "mandate_id": target.mandate(),
                "request_id": request_id,
                "params": params(),
            });
            match target.post_agent("/v1/authorize", headers, body).await {
                Ok((status, reply)) => decision_reply(attack.expect, status, &reply),
                Err(e) => (Verdict::Error, json!({ "error": e })),
            }
        }
        Probe::SorReplay => match target.replay_sor_event().await {
            Ok((status, reply)) => {
                let same = reply["mandate_id"].as_str() == Some(target.mandate().as_str());
                let replayed = reply["replayed"] == true;
                let verdict = if status == 200 && same && replayed {
                    Verdict::Refused
                } else if (200..300).contains(&status) && !same {
                    Verdict::Succeeded
                } else {
                    Verdict::RefusedUnexpectedly
                };
                (
                    verdict,
                    json!({ "status": status, "same_mandate": same, "replayed": replayed }),
                )
            }
            Err(e) => (Verdict::Error, json!({ "error": e })),
        },
        Probe::OutOfHours | Probe::DailyCap => {
            let body = json!({
                "mandate_id": target.mandate(),
                "request_id": request_id,
                "params": reminder(SUBJECT, "whatsapp"),
            });
            match target
                .post_agent(
                    "/v1/tools/send_reminder",
                    auth_headers(target, Auth::Agent),
                    body,
                )
                .await
            {
                Ok((status, reply)) => decision_reply(attack.expect, status, &reply),
                Err(e) => (Verdict::Error, json!({ "error": e })),
            }
        }
        Probe::Revocation(_) | Probe::AgentState(_) => (
            Verdict::Error,
            json!({ "error": "a revocation or agent-state attack is run on its own" }),
        ),
        Probe::ProviderDirect => provider_direct(target).await,
    }
}

/// A message straight to the provider: any 4xx is the refusal.
async fn provider_direct<T: Target>(target: &T) -> (Verdict, Value) {
    match target.post_provider().await {
        Ok(status) => {
            let verdict = if (400..500).contains(&status) {
                Verdict::Refused
            } else if (200..300).contains(&status) {
                Verdict::Succeeded
            } else {
                Verdict::RefusedUnexpectedly
            };
            (verdict, json!({ "status": status }))
        }
        Err(e) => (Verdict::Error, json!({ "error": e })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_every_attack_aims_at_a_refusal() {
        let mut ids = std::collections::BTreeSet::new();
        for attack in &CATALOG {
            assert!(ids.insert(attack.id), "{} twice", attack.id);
            if let Expect::Decision { decision, .. } = attack.expect {
                assert!(
                    !allowed_decision(decision),
                    "{} expects an allow",
                    attack.id
                );
            }
            if let Expect::Status { status } = attack.expect {
                assert!(status >= 400, "{} expects {status}", attack.id);
            }
        }
    }

    /// Each attack names a row that exists in the security properties and,
    /// if it gives one, in the bypass inventory.
    #[test]
    fn every_attack_maps_to_documented_rows() {
        let properties = include_str!("../../../docs/SECURITY_PROPERTIES.md");
        let bypasses = include_str!("../../../docs/BYPASS_INVENTORY.md");
        for attack in &CATALOG {
            assert!(
                properties.contains(&format!("| **{}", attack.security_property)),
                "{}: no row {:?}",
                attack.id,
                attack.security_property
            );
            if let Some(bypass) = attack.bypass {
                assert!(
                    bypasses.contains(&format!("| {bypass}")),
                    "{}: no row {bypass:?}",
                    attack.id
                );
            }
        }
    }

    #[test]
    fn decisions_are_judged_on_decision_and_reason() {
        let expect = Expect::Decision {
            decision: "BLOCK",
            reason: "raw_identifier:",
        };
        let body = |d: &str, r: &[&str]| json!({ "decision": d, "reasons": r });
        assert_eq!(
            judge(
                expect,
                200,
                &body("BLOCK", &["raw_identifier:subject_ref:phone"])
            ),
            Verdict::Refused
        );
        assert_eq!(
            judge(expect, 200, &body("PASS", &["authorized"])),
            Verdict::Succeeded
        );
        assert_eq!(
            judge(expect, 200, &body("BLOCK", &["contact-window"])),
            Verdict::RefusedUnexpectedly
        );
        let status = Expect::Status { status: 401 };
        assert_eq!(judge(status, 401, &Value::Null), Verdict::Refused);
        assert_eq!(judge(status, 200, &body("PASS", &[])), Verdict::Succeeded);
        assert_eq!(
            judge(status, 400, &Value::Null),
            Verdict::RefusedUnexpectedly
        );
    }

    #[test]
    fn only_the_clock_attacks_need_a_clock_and_skips_are_not_failures() {
        let clocked: Vec<_> = CATALOG
            .iter()
            .filter(|a| a.probe.needs_clock())
            .map(|a| a.id)
            .collect();
        assert_eq!(clocked, ["out-of-hours", "daily-cap"]);
        let outcome = |verdict| Outcome {
            id: "x",
            group: "g",
            tries: "t",
            expected: Expect::Refused,
            observed: Value::Null,
            verdict,
            security_property: CORE,
            bypass: None,
            setup: None,
        };
        let report = |verdicts: Vec<Verdict>| Report {
            catalog_version: CATALOG_VERSION,
            outcomes: verdicts.into_iter().map(outcome).collect(),
            credentials_minted: 0,
            messages_delivered: 0,
            setup_credentials: 3,
            setup_messages: 3,
        };
        let skipped = report(vec![Verdict::Refused, Verdict::Skipped]);
        assert!(skipped.passed() && !skipped.all_refused_as_expected());
        assert_eq!(skipped.skipped(), 1);
        assert!(!skipped.breached(), "declared setup is not a breach");
        assert!(!report(vec![Verdict::RefusedUnexpectedly]).passed());
    }

    #[test]
    fn forged_tokens_are_forged() {
        let token = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.AAAA";
        assert_eq!(tampered(token), "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.BAAA");
        let u = unsigned(token);
        assert!(u.ends_with('.') && u.contains(".eyJzdWIiOiJ4In0."), "{u}");
    }

    #[test]
    fn allowed_calls_are_read_from_metrics() {
        let text = "# HELP x\nkavach_gateway_calls_total{decision=\"PASS\",outcome=\"delivered\",tool=\"send_reminder\"} 2\n\
                    kavach_gateway_calls_total{decision=\"BLOCK\",outcome=\"none\",tool=\"send_reminder\"} 5\n\
                    kavach_gateway_calls_total{decision=\"ALERT\",outcome=\"delivered\",tool=\"send_reminder\"} 1\n";
        assert_eq!(allowed_calls(text), 3);
    }
}
