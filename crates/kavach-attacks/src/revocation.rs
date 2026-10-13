//! The revocation attacks (catalog v4, ADR-012 §8).
//!
//! Each one first assigns the attack borrower (declared setup: a mandate,
//! nothing sent), then sends its event. It is judged on the reply and on
//! ground truth: the attack mandate must still authorise (a pre-check names
//! no `mandate_invalid`, at any hour), and an event that was refused must
//! have left no revocation record in the evidence chain.

use serde_json::{json, Value};

use crate::{
    auth_headers, reminder, Auth, Expect, Loan, RevocationAttack, SorKey, SorSpec, Target, Verdict,
    ATTACK_SUBJECT,
};

/// Outside the 300 s freshness window either way, with a wide margin.
const OUTSIDE_WINDOW: i64 = 15 * 60;
/// Before the attack mandate was issued, well inside the window.
const BEFORE_ISSUE: i64 = -60;

/// Whether `mandate` still authorises: a pre-check that names no
/// `mandate_invalid`. The hour does not matter (out of hours is another
/// reason); an unavailable dependency is an error, never a pass.
async fn live<T: Target>(target: &T, mandate: &str, request_id: String) -> Result<bool, String> {
    let body = json!({
        "tool": "send_reminder",
        "mandate_id": mandate,
        "request_id": request_id,
        "params": reminder(ATTACK_SUBJECT, "whatsapp"),
    });
    let (status, reply) = target
        .post_agent("/v1/authorize", auth_headers(target, Auth::Agent), body)
        .await?;
    let reasons: Vec<&str> = reply["reasons"]
        .as_array()
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if status != 200 || reasons.contains(&"dependency_unavailable") {
        return Err(format!("the pre-check could not judge ({status}: {reply})"));
    }
    Ok(!reasons.contains(&"mandate_invalid"))
}

fn spec(event_id: String, event_type: &'static str, offset_seconds: i64) -> SorSpec {
    SorSpec {
        event_id,
        event_type,
        key: SorKey::Registered,
        other_tenant: false,
        loan: Loan::Attack,
        offset_seconds,
    }
}

/// The event an attack sends.
fn event_for(kind: RevocationAttack, id: String) -> SorSpec {
    let paid = spec(id, "loan.paid", 0);
    match kind {
        RevocationAttack::Forged => SorSpec {
            key: SorKey::Unregistered,
            ..paid
        },
        RevocationAttack::Stale => SorSpec {
            offset_seconds: -OUTSIDE_WINDOW,
            ..paid
        },
        RevocationAttack::Future => SorSpec {
            offset_seconds: OUTSIDE_WINDOW,
            ..paid
        },
        RevocationAttack::UnknownType => SorSpec {
            event_type: "loan.closed",
            ..paid
        },
        RevocationAttack::OtherTenant => SorSpec {
            other_tenant: true,
            ..paid
        },
        RevocationAttack::AnotherTenantsKey => SorSpec {
            key: SorKey::AnotherTenants,
            ..paid
        },
        RevocationAttack::WrongLoan => SorSpec {
            loan: Loan::Unused,
            ..paid
        },
        RevocationAttack::ReachesForward => SorSpec {
            offset_seconds: BEFORE_ISSUE,
            ..paid
        },
        // Built in its setup.
        RevocationAttack::Replayed => paid,
    }
}

/// What a run of one revocation attack saw.
struct Seen {
    status: u16,
    reply: Value,
    live: bool,
    record: Option<String>,
}

fn verdict(expect: Expect, seen: &Seen, extra: impl Fn(&Seen) -> bool) -> Verdict {
    if !seen.live {
        return Verdict::Succeeded;
    }
    match expect {
        Expect::EventRefused => {
            if (400..500).contains(&seen.status) {
                if seen.record.is_some() {
                    // Refused, yet a revocation was recorded for it.
                    Verdict::Succeeded
                } else {
                    Verdict::Refused
                }
            } else if (200..300).contains(&seen.status) {
                // Accepted: the event got through, which is the breach
                // (a stale one, say, revokes nothing newer, yet a system of
                // record could replay it at will).
                Verdict::Succeeded
            } else {
                Verdict::Error
            }
        }
        Expect::RevokesNothing | Expect::StoredRevocation => {
            if seen.status == 200 && extra(seen) {
                Verdict::Refused
            } else if (500..600).contains(&seen.status) {
                Verdict::Error
            } else {
                Verdict::RefusedUnexpectedly
            }
        }
        _ => Verdict::Error,
    }
}

/// Runs one revocation attack: its verdict, what it observed and its
/// declared setup.
pub(crate) async fn run<T: Target>(
    target: &T,
    kind: RevocationAttack,
    expect: Expect,
    n: &str,
) -> (Verdict, Value, Option<Value>) {
    match attempt(target, kind, expect, n).await {
        Ok(result) => result,
        Err(e) => (Verdict::Error, json!({ "error": e }), None),
    }
}

async fn attempt<T: Target>(
    target: &T,
    kind: RevocationAttack,
    expect: Expect,
    n: &str,
) -> Result<(Verdict, Value, Option<Value>), String> {
    // `n` is unique per run (see `run`).
    let event_id = format!("attack-{kind:?}-{n}").to_lowercase();
    if kind == RevocationAttack::Replayed {
        return replayed(target, expect, event_id, n).await;
    }
    let mandate = target.assign_attack_borrower().await?;
    let setup = json!({
        "declared": format!("{ATTACK_SUBJECT} assigned: a mandate, nothing sent"),
        "mandate": mandate,
    });
    if !live(target, &mandate, format!("attack-check-{n}-0")).await? {
        return Err("the attack mandate did not authorise before the attack".into());
    }
    let token = target
        .sign_sor_event(&event_for(kind, event_id.clone()))
        .await?;
    let (status, reply) = target.post_sor_event(&token).await?;
    let seen = Seen {
        status,
        live: live(target, &mandate, format!("attack-check-{n}-1")).await?,
        record: target.revocation_record(&event_id).await?,
        reply,
    };
    let verdict = verdict(expect, &seen, |s| {
        s.reply["revoked"]
            .as_array()
            .is_some_and(|ids| !ids.iter().any(|id| id.as_str() == Some(mandate.as_str())))
    });
    let observed = json!({
        "status": seen.status,
        "revoked": seen.reply["revoked"],
        "attack_mandate_live": seen.live,
        "revocation_recorded": seen.record.is_some(),
    });
    Ok((verdict, observed, Some(setup)))
}

/// Setup: a mandate, a payment that revokes it, and a new mandate for the
/// same loan. The probe sends the very same payment again: it must return
/// the first result, leave the new mandate live, and write no second
/// record.
async fn replayed<T: Target>(
    target: &T,
    expect: Expect,
    event_id: String,
    n: &str,
) -> Result<(Verdict, Value, Option<Value>), String> {
    let first = target.assign_attack_borrower().await?;
    let token = target
        .sign_sor_event(&spec(event_id.clone(), "loan.paid", 0))
        .await?;
    let (status, reply) = target.post_sor_event(&token).await?;
    let revoked_first: Vec<String> = reply["revoked"]
        .as_array()
        .map(|ids| {
            ids.iter()
                .filter_map(|id| id.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if status != 200 || !revoked_first.contains(&first) {
        return Err(format!(
            "setup: the payment did not revoke the first mandate ({status}: {reply})"
        ));
    }
    let record_first = target.revocation_record(&event_id).await?;
    let second = target.assign_attack_borrower().await?;
    let setup = json!({
        "declared": "a mandate, a payment that revoked it, and a new mandate for the same loan",
        "revoked_by_the_payment": revoked_first,
        "new_mandate": second,
    });

    let (status, reply) = target.post_sor_event(&token).await?;
    let seen = Seen {
        status,
        live: live(target, &second, format!("attack-check-{n}-1")).await?,
        record: target.revocation_record(&event_id).await?,
        reply,
    };
    let same_record = seen.record.is_some() && seen.record == record_first;
    let verdict = verdict(expect, &seen, |s| {
        let revoked: Vec<&str> = s.reply["revoked"]
            .as_array()
            .map(|ids| ids.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        s.reply["replayed"] == true && revoked == revoked_first && same_record
    });
    let observed = json!({
        "status": seen.status,
        "replayed": seen.reply["replayed"],
        "revoked": seen.reply["revoked"],
        "new_mandate_live": seen.live,
        "one_record": same_record,
    });
    Ok((verdict, observed, Some(setup)))
}

/// Each revocation attack can fail: against a stack with one defence
/// broken, the attack that targets it is judged `Succeeded`; with every
/// defence in place, all of them are refused. (The real stacks run in the
/// acceptance suite and `kavach attack`.)
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use serde_json::{json, Value};

    use crate::{
        run, Attack, Loan, Probe, RevocationAttack, SorKey, SorSpec, Target, Verdict, CATALOG,
    };

    /// The defence a fake stack lacks.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Broken {
        Nothing,
        Signature,
        Freshness,
        EventType,
        Tenant,
        Loan,
        Ordering,
        Replay,
        RecordsRefused,
        IssuerTenant,
    }

    const NOW: i64 = 1_000_000;

    #[derive(Default)]
    struct State {
        /// id, nbf, live.
        mandates: Vec<(String, i64, bool)>,
        records: HashMap<String, String>,
        replies: HashMap<String, Value>,
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
                state: Mutex::new(State::default()),
            }
        }

        fn process(&self, event: &Value) -> (u16, Value) {
            let b = self.broken;
            let at = event["at"].as_i64().unwrap();
            let refused = if (event["other_issuer"] == true && b != Broken::IssuerTenant)
                || (event["forged"] == true && b != Broken::Signature)
                || ((at - NOW).abs() > 300 && b != Broken::Freshness)
            {
                Some(422)
            } else if event["other_tenant"] == true && b != Broken::Tenant {
                Some(400)
            } else if !["loan.paid", "loan.disputed"].contains(&event["type"].as_str().unwrap())
                && b != Broken::EventType
            {
                Some(422)
            } else {
                None
            };
            let mut state = self.state.lock().unwrap();
            let id = event["id"].as_str().unwrap().to_string();
            if let Some(status) = refused {
                if b == Broken::RecordsRefused {
                    state.records.insert(id, "h".into());
                }
                return (status, json!({}));
            }
            let ours = event["loan"] == "attack" || b == Broken::Loan;
            let mut revoked = Vec::new();
            for (mandate, nbf, live) in &mut state.mandates {
                if ours && *live && (*nbf <= at || b == Broken::Ordering) {
                    *live = false;
                    revoked.push(mandate.clone());
                }
            }
            let hash = format!("h{}", state.next);
            state.next += 1;
            state.records.insert(id, hash);
            (200, json!({ "revoked": revoked, "replayed": false }))
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
        async fn post_agent(
            &self,
            _path: &str,
            _headers: Vec<(String, String)>,
            body: Value,
        ) -> Result<(u16, Value), String> {
            let state = self.state.lock().unwrap();
            let live = state
                .mandates
                .iter()
                .any(|(id, _, live)| *live && body["mandate_id"] == id.as_str());
            let reasons = if live {
                json!(["authorized"])
            } else {
                json!(["mandate_invalid"])
            };
            Ok((200, json!({ "decision": "BLOCK", "reasons": reasons })))
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
        async fn assign_attack_borrower(&self) -> Result<String, String> {
            let mut state = self.state.lock().unwrap();
            let id = format!("m-{}", state.mandates.len());
            state.mandates.push((id.clone(), NOW, true));
            Ok(id)
        }
        async fn sign_sor_event(&self, spec: &SorSpec) -> Result<String, String> {
            Ok(json!({
                "id": spec.event_id,
                "type": spec.event_type,
                "forged": spec.key == SorKey::Unregistered,
                "other_issuer": spec.key == SorKey::AnotherTenants,
                "other_tenant": spec.other_tenant,
                "loan": if spec.loan == Loan::Attack { "attack" } else { "unused" },
                "at": NOW + spec.offset_seconds,
            })
            .to_string())
        }
        async fn post_sor_event(&self, token: &str) -> Result<(u16, Value), String> {
            let stored = self.state.lock().unwrap().replies.get(token).cloned();
            if let Some(mut reply) = stored {
                if self.broken != Broken::Replay {
                    reply["replayed"] = json!(true);
                    return Ok((200, reply));
                }
            }
            let (status, reply) = self.process(&serde_json::from_str(token).unwrap());
            if status == 200 {
                self.state
                    .lock()
                    .unwrap()
                    .replies
                    .insert(token.into(), reply.clone());
            }
            Ok((status, reply))
        }
        async fn revocation_record(&self, event_id: &str) -> Result<Option<String>, String> {
            Ok(self.state.lock().unwrap().records.get(event_id).cloned())
        }
        async fn operator_request(
            &self,
            _: crate::Principal,
            _: &str,
            _: &str,
            _: Option<Value>,
        ) -> Result<(u16, Value), String> {
            Err("unused".into())
        }
    }

    fn attack(kind: RevocationAttack) -> Attack {
        *CATALOG
            .iter()
            .find(|a| matches!(a.probe, Probe::Revocation(k) if k == kind))
            .unwrap()
    }

    async fn verdict(broken: Broken, kind: RevocationAttack) -> (Verdict, Value) {
        let report = run(&Fake::new(broken), &[attack(kind)]).await;
        let o = &report.outcomes[0];
        (o.verdict, o.observed.clone())
    }

    #[tokio::test]
    async fn every_revocation_attack_is_refused_when_its_defence_holds() {
        use RevocationAttack as R;
        for kind in [
            R::Forged,
            R::Stale,
            R::Future,
            R::UnknownType,
            R::OtherTenant,
            R::WrongLoan,
            R::ReachesForward,
            R::Replayed,
            R::AnotherTenantsKey,
        ] {
            let (verdict, observed) = verdict(Broken::Nothing, kind).await;
            assert_eq!(verdict, Verdict::Refused, "{kind:?}: {observed}");
        }
    }

    #[tokio::test]
    async fn every_revocation_attack_succeeds_when_its_defence_is_broken() {
        use RevocationAttack as R;
        for (broken, kind) in [
            (Broken::Signature, R::Forged),
            (Broken::Freshness, R::Stale),
            (Broken::Freshness, R::Future),
            (Broken::EventType, R::UnknownType),
            (Broken::Tenant, R::OtherTenant),
            (Broken::Loan, R::WrongLoan),
            (Broken::Ordering, R::ReachesForward),
            (Broken::Replay, R::Replayed),
            (Broken::IssuerTenant, R::AnotherTenantsKey),
            // Refused, but recorded as a revocation all the same.
            (Broken::RecordsRefused, R::Forged),
        ] {
            let (verdict, observed) = verdict(broken, kind).await;
            assert_eq!(
                verdict,
                Verdict::Succeeded,
                "{kind:?} against a stack without {broken:?}: {observed}"
            );
        }
    }
}
