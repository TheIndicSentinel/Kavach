//! The kill-switch attacks (catalog v5, ADR-013 §5).
//!
//! Each one assigns the attack borrower (declared setup: a mandate, nothing
//! sent) and stops the holder agent through the operator API, then attacks
//! the stop. It is judged on the replies **and** on ground truth: the
//! agent's state read back through the API, a pre-check of the attack
//! mandate, and (by the caller) nothing minted or sent. Afterwards it brings
//! the agent back through the real approval path, as a different principal,
//! so a run leaves the stack as it found it; if it cannot, it says so and
//! the verdict is an error, never a pass.

use serde_json::{json, Value};

use crate::{
    auth_headers, reminder, AgentStateAttack, Auth, Expect, Principal, Target, Verdict,
    ATTACK_SUBJECT,
};

fn detail(body: &Value) -> String {
    body["detail"]
        .as_str()
        .or_else(|| body["error"].as_str())
        .unwrap_or_default()
        .to_string()
}

fn reasons(reply: &Value) -> Vec<String> {
    reply["reasons"]
        .as_array()
        .map(|r| {
            r.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The agent's state as the API says now.
async fn state_of<T: Target>(target: &T) -> Result<String, String> {
    let (status, body) = target
        .operator_request(
            Principal::Operator,
            "GET",
            &format!("/v1/agents/{}", target.agent_id()),
            None,
        )
        .await?;
    body["state"]
        .as_str()
        .filter(|_| status == 200)
        .map(str::to_string)
        .ok_or_else(|| format!("the agent's state could not be read ({status}: {body})"))
}

/// A call under the attack mandate: its status and reply.
async fn call<T: Target>(target: &T, mandate: &str, request_id: String) -> Result<Value, String> {
    let body = json!({
        "mandate_id": mandate,
        "request_id": request_id,
        "params": reminder(ATTACK_SUBJECT, "whatsapp"),
    });
    let (status, reply) = target
        .post_agent(
            "/v1/tools/send_reminder",
            auth_headers(target, Auth::Agent),
            body,
        )
        .await?;
    if status != 200 {
        return Err(format!(
            "the call was not answered with a decision ({status}: {reply})"
        ));
    }
    Ok(reply)
}

fn allowed(reply: &Value) -> bool {
    matches!(reply["decision"].as_str(), Some("PASS" | "ALERT"))
}

async fn propose<T: Target>(target: &T, reason_code: &str) -> Result<Value, String> {
    let (status, body) = target
        .operator_request(
            Principal::Operator,
            "POST",
            "/v1/change-requests",
            Some(json!({
                "kind": "reinstate_agent",
                "params": {
                    "agent_id": target.agent_id(),
                    "to": "active",
                    "reason_code": reason_code,
                },
            })),
        )
        .await?;
    if status != 201 {
        return Err(format!(
            "the reinstatement was not proposed ({status}: {body})"
        ));
    }
    Ok(body)
}

async fn approve<T: Target>(
    target: &T,
    who: Principal,
    request: &Value,
) -> Result<(u16, Value), String> {
    let id = request["id"].as_str().unwrap_or_default();
    target
        .operator_request(
            who,
            "POST",
            &format!("/v1/change-requests/{id}/approve"),
            Some(json!({ "change_digest": request["change_digest"] })),
        )
        .await
}

/// Withdraws a proposal nobody approved (its proposer cancels it).
async fn cancel<T: Target>(target: &T, request: &Value) {
    let id = request["id"].as_str().unwrap_or_default();
    let _ = target
        .operator_request(
            Principal::Operator,
            "POST",
            &format!("/v1/change-requests/{id}/cancel"),
            None,
        )
        .await;
}

/// Brings the agent back as the system intends: the operator proposes, a
/// different principal approves. The state is read back.
async fn reinstate<T: Target>(target: &T) -> Result<(), String> {
    let request = propose(target, "reviewed").await?;
    let (status, body) = approve(target, Principal::Approver, &request).await?;
    if status != 200 {
        return Err(format!("the approver was refused ({status}: {body})"));
    }
    let state = state_of(target).await?;
    if state != "active" {
        return Err(format!("the agent is {state} after its reinstatement"));
    }
    Ok(())
}

async fn stop<T: Target>(target: &T, verb: &str) -> Result<(), String> {
    let (status, body) = target
        .operator_request(
            Principal::Operator,
            "POST",
            &format!("/v1/agents/{}/{verb}", target.agent_id()),
            Some(json!({ "reason_code": "rogue_behaviour", "note": "attack catalog setup" })),
        )
        .await?;
    if status == 200 {
        Ok(())
    } else {
        Err(format!("the setup stop was refused ({status}: {body})"))
    }
}

/// Runs one kill-switch attack: its verdict, what it observed and its
/// declared setup.
pub(crate) async fn run<T: Target>(
    target: &T,
    kind: AgentStateAttack,
    expect: Expect,
    n: &str,
) -> (Verdict, Value, Option<Value>) {
    let Expect::AgentStaysStopped { state, reason } = expect else {
        return (
            Verdict::Error,
            json!({ "error": "not an agent-state expectation" }),
            None,
        );
    };
    if !target.has_principal(Principal::Approver) {
        return (
            Verdict::Inconclusive,
            json!({
                "inconclusive": "this stack has no second principal to bring the agent back with",
                "fix": "kavach init --force (it writes the approver token)",
            }),
            None,
        );
    }
    if kind == AgentStateAttack::CertificatePrincipalApproves
        && !target.has_principal(Principal::Certificate)
    {
        return (
            Verdict::Skipped,
            json!({ "skipped": "needs a client-certificate principal: this runner has none" }),
            None,
        );
    }
    match attempt(target, kind, state, reason, n).await {
        Ok(result) => result,
        Err(e) => (Verdict::Error, json!({ "error": e }), None),
    }
}

async fn attempt<T: Target>(
    target: &T,
    kind: AgentStateAttack,
    state: &'static str,
    reason: &'static str,
    n: &str,
) -> Result<(Verdict, Value, Option<Value>), String> {
    let mandate = target.assign_attack_borrower(0).await?;
    let verb = if state == "restricted" {
        "restrict"
    } else {
        "quarantine"
    };
    stop(target, verb).await?;
    let setup = json!({
        "declared": format!("{ATTACK_SUBJECT} assigned, then the holder was {state}"),
        "mandate": mandate,
        "agent": target.agent_id(),
    });
    let mut pending: Vec<Value> = Vec::new();
    let probed = probe(target, kind, &mandate, n, &mut pending).await;
    // Whatever the attack did, withdraw what it left pending and bring the
    // agent back through the approval path: the stack is left as it was.
    for request in &pending {
        cancel(target, request).await;
    }
    let restored = reinstate(target).await;
    let seen = probed?;
    restored.map_err(|e| format!("the stack was left stopped, bring it back by hand: {e}"))?;

    let reasons_ok = seen.reasons.iter().any(|r| r == reason)
        && seen
            .reasons
            .iter()
            .any(|r| r == &format!("agent_state:{state}"));
    let verdict = if seen.allowed || seen.approved || seen.state_after != state {
        Verdict::Succeeded
    } else if !reasons_ok || !seen.refusal_ok {
        Verdict::RefusedUnexpectedly
    } else {
        Verdict::Refused
    };
    let observed = json!({
        "decision": seen.decision,
        "reasons": seen.reasons,
        "state_after": seen.state_after,
        "refusal": seen.refusal,
        "restored": "active",
    });
    Ok((verdict, observed, Some(setup)))
}

/// What a probe saw.
struct Seen {
    decision: Value,
    reasons: Vec<String>,
    allowed: bool,
    /// An approval or loosening that should have been refused went through.
    approved: bool,
    /// The refusal of the loosening was the expected one (or there is none).
    refusal_ok: bool,
    refusal: Value,
    state_after: String,
}

async fn probe<T: Target>(
    target: &T,
    kind: AgentStateAttack,
    mandate: &str,
    n: &str,
    pending: &mut Vec<Value>,
) -> Result<Seen, String> {
    let mut approved = false;
    let mut refusal_ok = true;
    let mut refusal = Value::Null;
    match kind {
        AgentStateAttack::QuarantinedActs | AgentStateAttack::RestrictedContacts => {}
        AgentStateAttack::ReinstateWithoutApproval => {
            // A weaker stop: loosening by the stop route.
            let (status, body) = target
                .operator_request(
                    Principal::Operator,
                    "POST",
                    &format!("/v1/agents/{}/restrict", target.agent_id()),
                    Some(json!({ "reason_code": "reviewed" })),
                )
                .await?;
            approved |= (200..300).contains(&status);
            refusal_ok &= status == 409;
            refusal = json!({ "weaker_stop": { "status": status, "detail": detail(&body) } });
            // A proposal nobody approves loosens nothing.
            pending.push(propose(target, "reviewed").await?);
        }
        AgentStateAttack::SelfApprovedReinstate => {
            let request = propose(target, "reviewed").await?;
            let (status, body) = approve(target, Principal::Operator, &request).await?;
            approved |= (200..300).contains(&status);
            refusal_ok &= status == 403 && detail(&body).contains("different principal");
            refusal = json!({ "status": status, "detail": detail(&body) });
            pending.push(request);
        }
        AgentStateAttack::CertificatePrincipalApproves => {
            let request = propose(target, "reviewed").await?;
            let (status, body) = approve(target, Principal::Certificate, &request).await?;
            approved |= (200..300).contains(&status);
            refusal_ok &= status == 403 && detail(&body).contains("certificate principals");
            refusal = json!({ "status": status, "detail": detail(&body) });
            pending.push(request);
        }
    }
    let reply = call(target, mandate, format!("attack-state-{n}-{kind:?}")).await?;
    let state_after = state_of(target).await?;
    Ok(Seen {
        decision: reply["decision"].clone(),
        reasons: reasons(&reply),
        allowed: allowed(&reply),
        approved,
        refusal_ok,
        refusal,
        state_after,
    })
}

/// Each kill-switch attack can fail: against a stack with one defence
/// broken, the attack that targets it is judged `Succeeded`; with every
/// defence in place, all of them are refused and the agent is left active.
/// (The real stacks run in the acceptance suite and `kavach attack`.)
#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::{json, Value};

    use crate::{
        run, AgentStateAttack, Attack, Loan, Principal, Probe, SorSpec, Target, Verdict, CATALOG,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Broken {
        Nothing,
        /// A quarantined agent's call goes through.
        ActsWhenStopped,
        /// A restricted agent may still contact.
        ContactsWhenRestricted,
        /// The stop route loosens.
        StopRouteLoosens,
        /// A proposal reinstates by itself.
        ProposalApplies,
        /// The proposer may approve.
        SelfApproves,
        /// A certificate principal may approve.
        CertificateApproves,
        /// No second principal exists.
        NoApprover,
    }

    #[derive(Default)]
    struct State {
        agent: String,
        proposals: Vec<String>,
        next: u64,
    }

    struct Fake {
        broken: Broken,
        state: Mutex<State>,
    }

    impl Fake {
        fn new(broken: Broken) -> Self {
            Self {
                broken,
                state: Mutex::new(State {
                    agent: "active".into(),
                    ..State::default()
                }),
            }
        }
    }

    fn severity(state: &str) -> u8 {
        match state {
            "active" => 0,
            "restricted" => 1,
            "quarantined" => 2,
            _ => 3,
        }
    }

    // A synchronous fake behind an async trait: nothing in it awaits.
    #[allow(clippy::unused_async_trait_impl)]
    impl Target for Fake {
        fn agent_token(&self) -> String {
            "a".into()
        }
        fn other_agent_token(&self) -> String {
            "b".into()
        }
        fn operator_token(&self) -> String {
            "o".into()
        }
        fn mandate(&self) -> String {
            "m-dev".into()
        }
        fn has_principal(&self, who: Principal) -> bool {
            match who {
                Principal::Operator | Principal::Certificate => true,
                Principal::Approver => self.broken != Broken::NoApprover,
            }
        }
        async fn post_agent(
            &self,
            _path: &str,
            _headers: Vec<(String, String)>,
            _body: Value,
        ) -> Result<(u16, Value), String> {
            let state = self.state.lock().unwrap().agent.clone();
            let b = self.broken;
            let acts = match state.as_str() {
                "quarantined" => b == Broken::ActsWhenStopped,
                "restricted" => b == Broken::ContactsWhenRestricted,
                _ => true,
            };
            if acts {
                return Ok((200, json!({ "decision": "PASS", "reasons": [] })));
            }
            let why = if state == "restricted" {
                "agent-restricted"
            } else {
                "agent-stopped"
            };
            Ok((
                200,
                json!({ "decision": "BLOCK", "reasons": [why, format!("agent_state:{state}")] }),
            ))
        }
        async fn operator_request(
            &self,
            who: Principal,
            method: &str,
            path: &str,
            _body: Option<Value>,
        ) -> Result<(u16, Value), String> {
            let mut s = self.state.lock().unwrap();
            let b = self.broken;
            let problem = |status: u16, detail: &str| Ok((status, json!({ "detail": detail })));
            if method == "GET" {
                return Ok((200, json!({ "state": s.agent })));
            }
            if let Some(verb) = path.strip_prefix("/v1/agents/collections-agent/") {
                let to = match verb {
                    "restrict" => "restricted",
                    "quarantine" => "quarantined",
                    _ => "revoked",
                };
                if severity(to) < severity(&s.agent) && b != Broken::StopRouteLoosens {
                    return problem(409, "this would loosen the agent's state");
                }
                s.agent = to.into();
                return Ok((200, json!({ "state": to })));
            }
            if path == "/v1/change-requests" {
                s.next += 1;
                let id = format!("cr-{}", s.next);
                s.proposals.push(id.clone());
                if b == Broken::ProposalApplies {
                    s.agent = "active".into();
                }
                return Ok((201, json!({ "id": id, "change_digest": "sha256:x" })));
            }
            if path.ends_with("/cancel") {
                return Ok((200, json!({})));
            }
            if path.ends_with("/approve") {
                // The proposer is the operator.
                let refuses = match who {
                    Principal::Approver => None,
                    Principal::Operator if b == Broken::SelfApproves => None,
                    Principal::Operator => Some("the approver must be a different principal"),
                    Principal::Certificate if b == Broken::CertificateApproves => None,
                    Principal::Certificate => {
                        Some("approvals require an OIDC user token; certificate principals cannot approve")
                    }
                };
                if let Some(detail) = refuses {
                    return problem(403, detail);
                }
                s.agent = "active".into();
                return Ok((200, json!({ "status": "applied" })));
            }
            problem(404, "no such route")
        }
        async fn get_operator(&self, _: &str, _: Vec<(String, String)>) -> Result<u16, String> {
            Ok(200)
        }
        async fn replay_sor_event(&self) -> Result<(u16, Value), String> {
            Err("unused".into())
        }
        async fn post_provider(&self) -> Result<u16, String> {
            Ok(401)
        }
        async fn delivered(&self) -> Result<usize, String> {
            Ok(0)
        }
        async fn allowed(&self) -> Result<u64, String> {
            Ok(0)
        }
        async fn pause(&self) {}
        fn clock_control(&self) -> bool {
            false
        }
        async fn move_clock(&self, _: u32, _: u32, _: bool) -> Result<(), String> {
            Err("no clock".into())
        }
        fn has_attack_borrower(&self) -> bool {
            true
        }
        async fn assign_attack_borrower(&self, _: i64) -> Result<String, String> {
            Ok("m-attack".into())
        }
        async fn sign_sor_event(&self, _: &SorSpec) -> Result<String, String> {
            let _ = Loan::Attack;
            Err("unused".into())
        }
        async fn post_sor_event(&self, _: &str) -> Result<(u16, Value), String> {
            Err("unused".into())
        }
        async fn revocation_record(&self, _: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
    }

    fn attack(kind: AgentStateAttack) -> Attack {
        *CATALOG
            .iter()
            .find(|a| matches!(a.probe, Probe::AgentState(k) if k == kind))
            .unwrap()
    }

    async fn verdict(broken: Broken, kind: AgentStateAttack) -> (Verdict, Value, String) {
        let fake = Fake::new(broken);
        let report = run(&fake, &[attack(kind)]).await;
        let o = &report.outcomes[0];
        let left = fake.state.lock().unwrap().agent.clone();
        (o.verdict, o.observed.clone(), left)
    }

    const ALL: [AgentStateAttack; 5] = [
        AgentStateAttack::QuarantinedActs,
        AgentStateAttack::RestrictedContacts,
        AgentStateAttack::ReinstateWithoutApproval,
        AgentStateAttack::SelfApprovedReinstate,
        AgentStateAttack::CertificatePrincipalApproves,
    ];

    #[tokio::test]
    async fn every_kill_switch_attack_is_refused_when_its_defence_holds_and_leaves_the_agent_active(
    ) {
        for kind in ALL {
            let (verdict, observed, left) = verdict(Broken::Nothing, kind).await;
            assert_eq!(verdict, Verdict::Refused, "{kind:?}: {observed}");
            assert_eq!(left, "active", "{kind:?} left the agent {left}");
        }
    }

    #[tokio::test]
    async fn every_kill_switch_attack_succeeds_when_its_defence_is_broken() {
        use AgentStateAttack as A;
        for (broken, kind) in [
            (Broken::ActsWhenStopped, A::QuarantinedActs),
            (Broken::ContactsWhenRestricted, A::RestrictedContacts),
            (Broken::StopRouteLoosens, A::ReinstateWithoutApproval),
            (Broken::ProposalApplies, A::ReinstateWithoutApproval),
            (Broken::SelfApproves, A::SelfApprovedReinstate),
            (Broken::CertificateApproves, A::CertificatePrincipalApproves),
        ] {
            let (verdict, observed, _) = verdict(broken, kind).await;
            assert_eq!(
                verdict,
                Verdict::Succeeded,
                "{kind:?} against a stack with {broken:?}: {observed}"
            );
        }
    }

    #[tokio::test]
    async fn without_a_second_principal_nothing_is_concluded_and_nothing_is_stopped() {
        for kind in ALL {
            let (verdict, observed, left) = verdict(Broken::NoApprover, kind).await;
            assert_eq!(verdict, Verdict::Inconclusive, "{kind:?}: {observed}");
            assert_eq!(left, "active", "an inconclusive attack stopped nothing");
        }
    }
}
