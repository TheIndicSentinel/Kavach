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

/// Bumped whenever an attack is added, removed or its expectation changes.
pub const CATALOG_VERSION: &str = "1";

/// The borrower the dev mandate covers, and one it does not.
pub const SUBJECT: &str = "ref:borrower:B-9382";
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
    /// Any 4xx from the provider.
    Refused,
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
const BACKENDS: &str = "Credential-accepting backends";
const UNSEEN_IDENTIFIER: &str = "An identifier the detectors do not see, in a tool parameter";
const STOLEN_TOKEN: &str = "An agent token stolen before it expires";
const SOR_KEY: &str = "A system of record with a valid issuer key";
const AROUND: &str = "A resource the agent reaches without the gateway";

/// The catalog, in the order it runs.
pub const CATALOG: [Attack; 18] = [
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
        id: "provider-without-credential",
        group: "around the gateway",
        tries: "sending a message straight to the provider, with no gateway credential",
        probe: Probe::ProviderDirect,
        expect: Expect::Refused,
        security_property: BACKENDS,
        bypass: Some(AROUND),
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
    /// It could not be judged (a request failed to reach the stack).
    Error,
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
}

/// A run of the catalog.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub catalog_version: &'static str,
    pub outcomes: Vec<Outcome>,
    /// Ground truth across the whole run.
    pub credentials_minted: u64,
    pub messages_delivered: usize,
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
        Expect::SameMandate | Expect::Refused => Verdict::Error,
    }
}

/// Ground truth now: allowed calls (credentials minted), messages delivered.
async fn ground<T: Target>(target: &T) -> (Result<u64, String>, Result<usize, String>) {
    (target.allowed().await, target.delivered().await)
}

/// Runs `attacks` against `target`, judging each on its reply and on
/// ground truth (credentials minted, messages delivered).
pub async fn run<T: Target>(target: &T, attacks: &[Attack]) -> Report {
    let (start_allowed, start_delivered) = ground(target).await;
    let mut outcomes = Vec::new();
    for (n, attack) in attacks.iter().enumerate() {
        target.pause().await;
        let (before_allowed, before_delivered) = ground(target).await;
        let (verdict, observed) = probe(target, attack, n).await;
        let (after_allowed, after_delivered) = ground(target).await;
        let minted = matches!((&before_allowed, &after_allowed), (Ok(b), Ok(a)) if a > b);
        let sent = matches!((&before_delivered, &after_delivered), (Ok(b), Ok(a)) if a != b);
        let verdict = if minted || sent {
            Verdict::Succeeded
        } else {
            verdict
        };
        outcomes.push(Outcome {
            id: attack.id,
            group: attack.group,
            tries: attack.tries,
            expected: attack.expect,
            observed,
            verdict,
            security_property: attack.security_property,
            bypass: attack.bypass,
        });
    }
    let (end_allowed, end_delivered) = ground(target).await;
    Report {
        catalog_version: CATALOG_VERSION,
        outcomes,
        credentials_minted: match (start_allowed, end_allowed) {
            (Ok(s), Ok(e)) => e.saturating_sub(s),
            _ => 0,
        },
        messages_delivered: match (start_delivered, end_delivered) {
            (Ok(s), Ok(e)) => e.abs_diff(s),
            _ => 0,
        },
    }
}

async fn probe<T: Target>(target: &T, attack: &Attack, n: usize) -> (Verdict, Value) {
    let request_id = format!("attack-{}-{n}", attack.id);
    match attack.probe {
        Probe::ToolCall {
            tool,
            auth,
            real_mandate,
            params,
        } => {
            let headers = headers(
                auth,
                &target.agent_token(),
                &target.other_agent_token(),
                &target.operator_token(),
            );
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
                Ok((status, reply)) => (
                    judge(attack.expect, status, &reply),
                    json!({ "status": status, "decision": reply["decision"], "reasons": reply["reasons"] }),
                ),
                Err(e) => (Verdict::Error, json!({ "error": e })),
            }
        }
        Probe::Precheck { tool, params } => {
            let headers = headers(
                Auth::Agent,
                &target.agent_token(),
                &target.other_agent_token(),
                &target.operator_token(),
            );
            let body = json!({
                "tool": tool,
                "mandate_id": target.mandate(),
                "request_id": request_id,
                "params": params(),
            });
            match target.post_agent("/v1/authorize", headers, body).await {
                Ok((status, reply)) => (
                    judge(attack.expect, status, &reply),
                    json!({ "status": status, "decision": reply["decision"], "reasons": reply["reasons"] }),
                ),
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
        Probe::ProviderDirect => match target.post_provider().await {
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
        },
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
