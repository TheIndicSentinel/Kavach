//! The reconciler of `unknown` outcomes (ADR-017 R2).
//!
//! An outcome is `unknown` when a send may have reached the provider and no
//! complete answer came back. The gateway never resends (that could contact
//! a borrower twice), so this pass learns what happened by **asking**, never
//! by sending:
//!
//! - For [`UNKNOWN_OUTCOME_POLL_WINDOW`] after the outcome it puts a signed
//!   status question to the provider, with back-off, a cap on the questions
//!   per outcome and a cap on the questions per pass. A confirmed answer
//!   (`delivered` / `not_delivered`) is written as a `provider_status`
//!   resolution carrying the digest of the answer. `unknown` and no answer
//!   write nothing and are asked again later.
//! - After the window the call is left alone: a person may attest at any time
//!   (R3).
//! - [`UNKNOWN_OUTCOME_AMBIGUOUS_AFTER`] after the outcome, with nothing
//!   confirmed, it writes `ambiguous` (source `reconciler`) once.
//!
//! What it cannot do, by construction: it is given a [`StatusAsker`] (whose
//! only input is a status question, never a credential), a
//! [`StatusQuestions`] minter, the evidence store and the signer. It has no
//! [`Forwarder`](crate::gateway::Forwarder), so no send path; the only writes
//! it can make are `record_resolution` rows from the sources `provider_status`
//! and `reconciler` (the latter only `ambiguous`, enforced by `check_form`);
//! and it never touches the contact counter, which only `commit` writes, so
//! a resolution (even `confirmed_not_delivered`) never releases a slot.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use kavach_ports::agent_evidence::{AgentEvidenceStore, Outcome, UnresolvedOutcome};
use kavach_ports::agent_state::AgentStateStore;
use kavach_ports::outcome_resolution::{
    outcome_ref, sign_resolution, ResolutionDraft, ResolutionSource, ResolutionState,
    ResolutionSummary,
};
use kavach_ports::{ErrorClass, StatusQuestions};

use crate::authorize::{AuthorizeCore, MandateVerifier};
use crate::gateway::{ProviderStatus, StatusAnswer, StatusAsker};

/// How long after an `unknown` outcome the provider is asked (ADR-017).
pub const UNKNOWN_OUTCOME_POLL_WINDOW: Duration = Duration::hours(1);
/// How long after an `unknown` outcome, with nothing confirmed, the
/// reconciler says `ambiguous` (ADR-017).
pub const UNKNOWN_OUTCOME_AMBIGUOUS_AFTER: Duration = Duration::hours(24);
/// The wait before the first question after the outcome; each later wait is
/// twice the one before, up to [`POLL_MAX_DELAY`].
pub const POLL_FIRST_DELAY: Duration = Duration::seconds(30);
pub const POLL_MAX_DELAY: Duration = Duration::minutes(10);
/// Most questions put about one outcome by one process (a restart starts the
/// count again, still inside the window).
pub const MAX_QUESTIONS_PER_OUTCOME: u32 = 8;
/// Most questions put to providers in one pass, over all outcomes: the rate
/// limit.
pub const MAX_QUESTIONS_PER_PASS: usize = 20;
/// Outcomes read per pass.
pub const WORK_PAGE: u32 = 500;

/// An allow with no outcome row, decided longer ago than this, is taken to
/// have lost its outcome write and is recorded as `unknown` (F7). It is far
/// above the longest a live call can take: the credential lives 15 seconds
/// and the provider timeout is below that, so five minutes is twenty times
/// the life of the call. A live call that is somehow slower finds its row
/// already written (outcomes are written once) and its answer is then taken
/// from the stored `unknown`, which the status question resolves: wrong
/// only in being cautious.
pub const STUCK_OUTCOME_WINDOW: Duration = Duration::minutes(5);
/// How far back the recovery looks (a mandate's life).
pub const STUCK_OUTCOME_LOOKBACK: Duration = Duration::days(7);
/// Allows recovered in one pass.
const RECOVER_BATCH: u32 = 100;
/// Most allows beyond the lookback that a pass counts (the count is "this
/// many or more" at the cap).
const BEYOND_LOOKBACK_CAP: u32 = 1000;

/// The reason codes of the rows this pass writes.
const REASON_PROVIDER: &str = "provider_status";
const REASON_AMBIGUOUS: &str = "no_answer_in_24h";
/// The reason on the `unknown` outcome written for an allow whose own
/// outcome could not be recorded.
const REASON_NOT_RECORDED: &str = "outcome_not_recorded";

/// When each outcome may next be asked about: memory of one process.
#[derive(Debug, Default)]
pub struct PollState {
    by_credential: BTreeMap<String, Polling>,
}

#[derive(Debug, Clone, Copy)]
struct Polling {
    asked: u32,
    next_at: DateTime<Utc>,
}

/// What one pass found and did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutcomeReconcileReport {
    /// Allows with no outcome that this pass recorded as `unknown` (F7).
    pub recovered: usize,
    /// Allows with no outcome that are older than the lookback, so the pass
    /// does not record them: they stay as they are, reported here (up to a
    /// cap) and by the bundle verifier as missing.
    pub beyond_lookback: usize,
    /// Unknown outcomes still open at the start of the pass.
    pub open: usize,
    /// How long ago the oldest of them happened.
    pub oldest_age: Option<Duration>,
    pub asked: usize,
    pub confirmed_delivered: usize,
    pub confirmed_not_delivered: usize,
    /// Questions that got `unknown`, a refusal or nothing.
    pub no_answer: usize,
    /// `ambiguous` rows written because 24 hours passed with nothing confirmed.
    pub ambiguous: usize,
    /// Questions not put because the pass reached its cap.
    pub deferred: usize,
    /// Why a row could not be written or an outcome could not be asked about.
    pub problems: Vec<String>,
    pub error: Option<String>,
    /// What the tenant's unknown outcomes look like after this pass (the
    /// signals of ADR-017 R3a); `None` when it could not be read.
    pub summary: Option<ResolutionSummary>,
    /// The core's clock at the start of the pass: what ages are measured to.
    pub at: Option<DateTime<Utc>>,
}

/// When the next question about an outcome that has been asked about
/// `asked` times may be put: 30 s, 1 min, 2 min, 4 min… after the outcome or
/// the last question, never more than [`POLL_MAX_DELAY`].
fn delay_after(asked: u32) -> Duration {
    let doubled = POLL_FIRST_DELAY
        .num_seconds()
        .saturating_mul(1_i64 << asked.min(20));
    Duration::seconds(doubled.min(POLL_MAX_DELAY.num_seconds()))
}

/// An allow that has a credential and no outcome, past the stuck window, gets
/// an `unknown` outcome: never delivered or not delivered, because nobody
/// knows. The status question then does what it does for any unknown, and a
/// retry of the call stops being "in flight".
async fn recover_stuck_allows<V, S>(
    core: &AuthorizeCore<V, S>,
    now: DateTime<Utc>,
    report: &mut OutcomeReconcileReport,
) where
    V: MandateVerifier,
    S: AgentEvidenceStore + AgentStateStore,
{
    let stuck = match core
        .store()
        .stuck_allows(
            core.tenant_id(),
            now - STUCK_OUTCOME_LOOKBACK,
            now - STUCK_OUTCOME_WINDOW,
            RECOVER_BATCH,
        )
        .await
    {
        Ok(stuck) => stuck,
        Err(err) => {
            report
                .problems
                .push(format!("allows without an outcome: {}", err.message));
            return;
        }
    };
    for record in &stuck {
        match core
            .record_outcome(record, Outcome::Unknown, REASON_NOT_RECORDED)
            .await
        {
            Ok(_) => report.recovered += 1,
            // Written by the call itself in the meantime: nothing to do.
            Err(err) if err.class == ErrorClass::Rejected => {}
            Err(err) => report
                .problems
                .push(format!("recovering an outcome: {}", err.message)),
        }
    }
    // Older than the lookback, they are not touched: they must not vanish.
    match core
        .store()
        .stuck_allows(
            core.tenant_id(),
            DateTime::UNIX_EPOCH,
            now - STUCK_OUTCOME_LOOKBACK,
            BEYOND_LOOKBACK_CAP,
        )
        .await
    {
        Ok(older) => report.beyond_lookback = older.len(),
        Err(err) => report
            .problems
            .push(format!("allows beyond the lookback: {}", err.message)),
    }
}

/// One pass over the open unknown outcomes of the core's tenant.
pub async fn reconcile_outcomes<V, S, A, Q>(
    core: &AuthorizeCore<V, S>,
    asker: &A,
    questions: &Q,
    polls: &mut PollState,
) -> OutcomeReconcileReport
where
    V: MandateVerifier,
    S: AgentEvidenceStore + AgentStateStore,
    A: StatusAsker,
    Q: StatusQuestions,
{
    let mut report = OutcomeReconcileReport::default();
    let tenant = core.tenant_id();
    let now = core.clock_now();
    report.at = Some(now);
    recover_stuck_allows(core, now, &mut report).await;
    let open = match core.store().unresolved_outcomes(tenant, WORK_PAGE).await {
        Ok(open) => open,
        Err(err) => {
            report.error = Some(format!("unresolved outcomes: {}", err.message));
            return report;
        }
    };
    report.open = open.len();
    report.oldest_age = open.first().map(|u| now - u.outcome.ts);
    // Forget the memory of outcomes that are settled.
    polls
        .by_credential
        .retain(|id, _| open.iter().any(|u| &u.outcome.credential_id == id));

    for unresolved in &open {
        let age = now - unresolved.outcome.ts;
        if age >= UNKNOWN_OUTCOME_AMBIGUOUS_AFTER {
            write_ambiguous(core, unresolved, now, &mut report).await;
        } else if age < UNKNOWN_OUTCOME_POLL_WINDOW {
            ask(core, asker, questions, polls, unresolved, now, &mut report).await;
        }
        // Between the window and 24 hours: left alone, a person may attest.
    }
    match core.store().resolution_summary(tenant).await {
        Ok(summary) => report.summary = Some(summary),
        Err(err) => report
            .problems
            .push(format!("resolution summary: {}", err.message)),
    }
    report
}

/// `ambiguous`, once, because nobody could say.
async fn write_ambiguous<V, S>(
    core: &AuthorizeCore<V, S>,
    unresolved: &UnresolvedOutcome,
    now: DateTime<Utc>,
    report: &mut OutcomeReconcileReport,
) where
    V: MandateVerifier,
    S: AgentEvidenceStore + AgentStateStore,
{
    let draft = draft_for(
        unresolved,
        ResolutionState::Ambiguous,
        ResolutionSource::Reconciler,
        REASON_AMBIGUOUS,
        None,
    );
    match write(core, draft, now).await {
        Ok(true) => report.ambiguous += 1,
        Ok(false) => {}
        Err(problem) => report.problems.push(problem),
    }
}

/// One status question about one outcome, if it is due and the pass has room.
async fn ask<V, S, A, Q>(
    core: &AuthorizeCore<V, S>,
    asker: &A,
    questions: &Q,
    polls: &mut PollState,
    unresolved: &UnresolvedOutcome,
    now: DateTime<Utc>,
    report: &mut OutcomeReconcileReport,
) where
    V: MandateVerifier,
    S: AgentEvidenceStore + AgentStateStore,
    A: StatusAsker,
    Q: StatusQuestions,
{
    let credential = &unresolved.outcome.credential_id;
    let state = polls
        .by_credential
        .get(credential)
        .copied()
        .unwrap_or(Polling {
            asked: 0,
            next_at: unresolved.outcome.ts + delay_after(0),
        });
    if state.asked >= MAX_QUESTIONS_PER_OUTCOME || now < state.next_at {
        return;
    }
    if report.asked >= MAX_QUESTIONS_PER_PASS {
        report.deferred += 1;
        return;
    }
    // Where to ask is decided by the registry, never guessed.
    let Some(provider) = core.tools().provider_for_action(&unresolved.action) else {
        return;
    };
    let tenant = core.tenant_id();
    let question = match questions
        .status_question(tenant, provider, credential, now)
        .await
    {
        Ok(question) => question,
        Err(err) => {
            report
                .problems
                .push(format!("status question for {credential}: {}", err.message));
            return;
        }
    };
    report.asked += 1;
    let answer = asker.status(provider, credential, &question).await;
    polls.by_credential.insert(
        credential.clone(),
        Polling {
            asked: state.asked + 1,
            next_at: now + delay_after(state.asked + 1),
        },
    );
    let confirmed = match answer {
        Some(StatusAnswer {
            status: ProviderStatus::Delivered,
            digest,
        }) => Some((ResolutionState::ConfirmedDelivered, digest)),
        Some(StatusAnswer {
            status: ProviderStatus::NotDelivered,
            digest,
        }) => Some((ResolutionState::ConfirmedNotDelivered, digest)),
        // The provider cannot say, or did not answer: nothing is learned.
        Some(StatusAnswer {
            status: ProviderStatus::Unknown,
            ..
        })
        | None => None,
    };
    let Some((resolution_state, digest)) = confirmed else {
        report.no_answer += 1;
        return;
    };
    let draft = draft_for(
        unresolved,
        resolution_state,
        ResolutionSource::ProviderStatus,
        REASON_PROVIDER,
        Some(digest),
    );
    match write(core, draft, now).await {
        Ok(written) => {
            if written {
                match resolution_state {
                    ResolutionState::ConfirmedDelivered => report.confirmed_delivered += 1,
                    _ => report.confirmed_not_delivered += 1,
                }
            }
            polls.by_credential.remove(credential);
        }
        Err(problem) => report.problems.push(problem),
    }
}

fn draft_for(
    unresolved: &UnresolvedOutcome,
    state: ResolutionState,
    source: ResolutionSource,
    reason: &str,
    evidence_digest: Option<String>,
) -> ResolutionDraft {
    ResolutionDraft {
        tenant_id: unresolved.outcome.tenant_id.clone(),
        credential_id: unresolved.outcome.credential_id.clone(),
        outcome_ref: outcome_ref(&unresolved.outcome),
        state,
        source,
        reason: reason.into(),
        evidence_digest,
        resolved_by: None,
        approved_by: None,
    }
}

/// Signs and keeps one resolution; `Ok(false)` when it was already there.
async fn write<V, S>(
    core: &AuthorizeCore<V, S>,
    draft: ResolutionDraft,
    now: DateTime<Utc>,
) -> Result<bool, String>
where
    V: MandateVerifier,
    S: AgentEvidenceStore + AgentStateStore,
{
    let credential = draft.credential_id.clone();
    let record = sign_resolution(draft, now, core.evidence_signer())
        .map_err(|e| format!("resolution of {credential}: {}", e.message))?;
    core.store()
        .record_resolution(record)
        .await
        .map_err(|e| format!("resolution of {credential}: {}", e.message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_doubles_and_is_capped() {
        let waits: Vec<i64> = (0..7).map(|n| delay_after(n).num_seconds()).collect();
        assert_eq!(waits, [30, 60, 120, 240, 480, 600, 600]);
        assert_eq!(delay_after(u32::MAX), POLL_MAX_DELAY);
    }

    #[test]
    fn the_questions_fit_inside_the_window() {
        // The eight questions an outcome is allowed all come due within the
        // hour the ADR gives, so the cap never cuts the window short.
        let total: i64 = (0..MAX_QUESTIONS_PER_OUTCOME)
            .map(|n| delay_after(n).num_seconds())
            .sum();
        assert!(
            Duration::seconds(total) <= UNKNOWN_OUTCOME_POLL_WINDOW,
            "{total}"
        );
    }
}
