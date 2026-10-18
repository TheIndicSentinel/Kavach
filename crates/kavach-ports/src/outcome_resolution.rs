//! Outcome resolutions (ADR-017): how an `unknown` outcome becomes known,
//! without any path that can send again and without rewriting the outcome.
//!
//! An outcome is a signed row, written once. A resolution is a **second**
//! signed row that refers to it, so the history (it was unknown, then it was
//! confirmed, by whom, from what) is the evidence. Several may exist for one
//! outcome. The governing state is computed from **all** of them
//! ([`governing`]), never from the latest: a silent flip would hide exactly
//! what an auditor needs to see.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_evidence::{is_reason_code, EvidenceSigner, OutcomeRecord};
use crate::error::PortError;

/// Domain separation: a resolution signature is never valid as an outcome's,
/// a record's or a checkpoint's.
pub const RESOLUTION_SIG_PREFIX: &[u8] = b"kavach-outcome-resolution-sig-v1:";

/// What a resolution says happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionState {
    ConfirmedDelivered,
    ConfirmedNotDelivered,
    /// Nobody can say. Kept as history; never overrides a confirmed state.
    Ambiguous,
}

impl ResolutionState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfirmedDelivered => "confirmed_delivered",
            Self::ConfirmedNotDelivered => "confirmed_not_delivered",
            Self::Ambiguous => "ambiguous",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::ConfirmedDelivered,
            Self::ConfirmedNotDelivered,
            Self::Ambiguous,
        ]
        .into_iter()
        .find(|s| s.as_str() == value)
    }

    #[must_use]
    pub fn is_confirmed(self) -> bool {
        self != Self::Ambiguous
    }
}

/// How the state is known. They are never merged into one label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionSource {
    /// The provider's own status answer (with a digest of the answer).
    ProviderStatus,
    /// A person's attestation from outside Kavach (with a reference digest).
    OperatorAttested,
    /// A two-person decision that closes a conflict.
    ConflictResolution,
    /// The reconciler's own statement that nothing could be learned
    /// (`ambiguous` only).
    Reconciler,
}

impl ResolutionSource {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProviderStatus => "provider_status",
            Self::OperatorAttested => "operator_attested",
            Self::ConflictResolution => "conflict_resolution",
            Self::Reconciler => "reconciler",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::ProviderStatus,
            Self::OperatorAttested,
            Self::ConflictResolution,
            Self::Reconciler,
        ]
        .into_iter()
        .find(|s| s.as_str() == value)
    }
}

/// A signed resolution of an `unknown` outcome (off-chain, append-only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionRecord {
    pub tenant_id: String,
    pub credential_id: String,
    /// Which outcome row it resolves: the hex SHA-256 of that row's `sig`.
    pub outcome_ref: String,
    pub state: ResolutionState,
    pub source: ResolutionSource,
    /// A code (`[a-z0-9_]{1,64}`), never a value.
    pub reason: String,
    /// The hex SHA-256 of the provider's answer or of the operator's
    /// reference; never the thing itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
    /// The person who attested or proposed (operator sources).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<String>,
    /// The different person who approved (a "not delivered" attestation and a
    /// conflict resolution).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    pub ts: DateTime<Utc>,
    pub key_id: String,
    pub sig: String,
}

/// What a resolution is made from, before it is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionDraft {
    pub tenant_id: String,
    pub credential_id: String,
    pub outcome_ref: String,
    pub state: ResolutionState,
    pub source: ResolutionSource,
    pub reason: String,
    pub evidence_digest: Option<String>,
    pub resolved_by: Option<String>,
    pub approved_by: Option<String>,
}

/// The reference an outcome row is known by in a resolution.
#[must_use]
pub fn outcome_ref(outcome: &OutcomeRecord) -> String {
    hex::encode(Sha256::digest(outcome.sig.as_bytes()))
}

fn some(value: Option<&str>) -> String {
    value.map_or_else(|| "none".to_string(), |v| format!("some:{v}"))
}

/// The signed message. Every field is in it, in a fixed order; an absent
/// optional is `none` and a present one `some:<value>`, so none is ever
/// confused with a value.
#[must_use]
pub fn resolution_message(record: &ResolutionRecord) -> Vec<u8> {
    let ts = record
        .ts
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let body = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{ts}",
        record.tenant_id,
        record.credential_id,
        record.outcome_ref,
        record.state.as_str(),
        record.source.as_str(),
        record.reason,
        some(record.evidence_digest.as_deref()),
        some(record.resolved_by.as_deref()),
        some(record.approved_by.as_deref()),
    );
    let mut message = RESOLUTION_SIG_PREFIX.to_vec();
    message.extend_from_slice(body.as_bytes());
    message
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_principal(value: &str) -> bool {
    (1..=128).contains(&value.len()) && value.chars().all(|c| !c.is_control())
}

/// The rules a resolution must satisfy to be written (ADR-017 §Decision 4):
/// who may say what, and with what evidence. Shared by every store so they
/// agree.
///
/// `resolved_by` and `approved_by` hold the **source-qualified identity key**
/// of an authenticated human (the same form the change requests compare, for
/// example `oidc:<issuer>#<subject>`), and "two different people" is a
/// comparison of those whole keys, so the same name from two sources is two
/// identities and two spellings of one key are one. This module cannot know
/// that the caller authenticated; the route that writes an attestation (ADR-017
/// R3) must, and a certificate principal may not attest. The usual limit
/// stands: one person holding two accounts at the identity provider passes as
/// two.
pub fn check_form(record: &ResolutionRecord) -> Result<(), PortError> {
    let invalid = |why: &str| Err(PortError::invalid(format!("outcome resolution: {why}")));
    if !is_reason_code(&record.reason) {
        return invalid("the reason must be a code: [a-z0-9_]{1,64}");
    }
    if !is_digest(&record.outcome_ref) {
        return invalid("outcome_ref must be a SHA-256 in lowercase hex");
    }
    if record
        .evidence_digest
        .as_deref()
        .is_some_and(|d| !is_digest(d))
    {
        return invalid("evidence_digest must be a SHA-256 in lowercase hex");
    }
    for who in [&record.resolved_by, &record.approved_by]
        .into_iter()
        .flatten()
    {
        if !is_principal(who) {
            return invalid("a principal must be 1 to 128 printable characters");
        }
    }
    let (resolved, approved) = (&record.resolved_by, &record.approved_by);
    match record.source {
        ResolutionSource::Reconciler => {
            if record.state != ResolutionState::Ambiguous {
                return invalid("the reconciler only says ambiguous");
            }
            if record.evidence_digest.is_some() || resolved.is_some() || approved.is_some() {
                return invalid("the reconciler's statement carries no evidence or principals");
            }
        }
        ResolutionSource::ProviderStatus => {
            if record.evidence_digest.is_none() {
                return invalid("a provider status carries the digest of the answer");
            }
            if resolved.is_some() || approved.is_some() {
                return invalid("a provider status carries no principals");
            }
        }
        ResolutionSource::OperatorAttested => {
            if resolved.is_none() || record.evidence_digest.is_none() {
                return invalid("an attestation names the person and carries a reference digest");
            }
            // Loosening needs two: "not delivered" lowers the recorded contact.
            let two = record.state == ResolutionState::ConfirmedNotDelivered;
            if two && (approved.is_none() || approved == resolved) {
                return invalid("attesting not delivered needs a second, different person");
            }
            if !two && approved.is_some() {
                return invalid("this attestation needs one person, not two");
            }
        }
        ResolutionSource::ConflictResolution => {
            if !record.state.is_confirmed() {
                return invalid("a conflict is closed by a confirmed state");
            }
            if resolved.is_none()
                || approved.is_none()
                || approved == resolved
                || record.evidence_digest.is_none()
            {
                return invalid(
                    "a conflict resolution needs two different people and a reference digest",
                );
            }
        }
    }
    Ok(())
}

/// What a store checks against the outcome row before it keeps a resolution:
/// it resolves **this** outcome (by reference) and only an `unknown` one (a
/// settled outcome has nothing to resolve).
pub fn check_against_outcome(
    record: &ResolutionRecord,
    outcome: Option<&OutcomeRecord>,
) -> Result<(), PortError> {
    let Some(outcome) = outcome else {
        return Err(PortError::rejected(
            "outcome resolution: no outcome is recorded for this credential",
        ));
    };
    if outcome.tenant_id != record.tenant_id || outcome.credential_id != record.credential_id {
        return Err(PortError::rejected(
            "outcome resolution: the outcome belongs to another credential",
        ));
    }
    if outcome.outcome != crate::agent_evidence::Outcome::Unknown {
        return Err(PortError::rejected(
            "outcome resolution: only an unknown outcome is resolved",
        ));
    }
    if outcome_ref(outcome) != record.outcome_ref {
        return Err(PortError::rejected(
            "outcome resolution: it refers to another outcome row",
        ));
    }
    Ok(())
}

/// Signs a resolution at `ts` with the evidence key.
pub fn sign_resolution(
    draft: ResolutionDraft,
    ts: DateTime<Utc>,
    signer: &dyn EvidenceSigner,
) -> Result<ResolutionRecord, PortError> {
    let mut record = ResolutionRecord {
        tenant_id: draft.tenant_id,
        credential_id: draft.credential_id,
        outcome_ref: draft.outcome_ref,
        state: draft.state,
        source: draft.source,
        reason: draft.reason,
        evidence_digest: draft.evidence_digest,
        resolved_by: draft.resolved_by,
        approved_by: draft.approved_by,
        ts,
        key_id: signer.key_id().to_string(),
        sig: String::new(),
    };
    check_form(&record)?;
    record.sig = hex::encode(signer.sign(&resolution_message(&record))?);
    Ok(record)
}

/// What a set of resolutions says about one outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Governing {
    /// No resolution: still unknown, still reported.
    Unresolved,
    /// Nobody can say (and nothing confirmed).
    Ambiguous,
    /// One confirmed state, and how it is known.
    Confirmed {
        state: ResolutionState,
        source: ResolutionSource,
    },
    /// Two different confirmed states, and no two-person resolution closing
    /// them. Neither is reported as true; this is an incident.
    Conflicted,
}

/// The governing state, from **all** the rows (never "latest wins"):
///
/// - a two-person conflict resolution governs over everything else; two of
///   them that disagree are a conflict again;
/// - otherwise take the distinct *confirmed* states among the rest: none is
///   `Ambiguous` (if any ambiguous row exists) or `Unresolved`; one governs,
///   and a provider status outranks an attestation as the stated source; two
///   different ones are `Conflicted`;
/// - an `ambiguous` row never overrides a confirmed one, whenever written.
#[must_use]
pub fn governing(rows: &[ResolutionRecord]) -> Governing {
    let confirmed = |state: ResolutionState| state.is_confirmed();
    let mut closing: Vec<ResolutionState> = rows
        .iter()
        .filter(|r| r.source == ResolutionSource::ConflictResolution && confirmed(r.state))
        .map(|r| r.state)
        .collect();
    closing.sort_by_key(|s| s.as_str());
    closing.dedup();
    match closing.as_slice() {
        [state] => {
            return Governing::Confirmed {
                state: *state,
                source: ResolutionSource::ConflictResolution,
            }
        }
        [_, _, ..] => return Governing::Conflicted,
        [] => {}
    }
    let mut states: Vec<ResolutionState> = rows
        .iter()
        .filter(|r| confirmed(r.state))
        .map(|r| r.state)
        .collect();
    states.sort_by_key(|s| s.as_str());
    states.dedup();
    match states.as_slice() {
        [] if rows.iter().any(|r| r.state == ResolutionState::Ambiguous) => Governing::Ambiguous,
        [] => Governing::Unresolved,
        [state] => {
            let by_provider = rows
                .iter()
                .any(|r| r.state == *state && r.source == ResolutionSource::ProviderStatus);
            Governing::Confirmed {
                state: *state,
                source: if by_provider {
                    ResolutionSource::ProviderStatus
                } else {
                    ResolutionSource::OperatorAttested
                },
            }
        }
        _ => Governing::Conflicted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn row(state: ResolutionState, source: ResolutionSource) -> ResolutionRecord {
        ResolutionRecord {
            tenant_id: "t".into(),
            credential_id: "c".into(),
            outcome_ref: "ab".repeat(32),
            state,
            source,
            reason: "provider_said".into(),
            evidence_digest: Some("cd".repeat(32)),
            resolved_by: None,
            approved_by: None,
            ts: Utc.with_ymd_and_hms(2026, 10, 1, 6, 0, 0).unwrap(),
            key_id: "k".into(),
            sig: String::new(),
        }
    }

    use ResolutionSource::{ConflictResolution, OperatorAttested, ProviderStatus, Reconciler};
    use ResolutionState::{
        Ambiguous, ConfirmedDelivered as Delivered, ConfirmedNotDelivered as Not,
    };

    fn provider(state: ResolutionState) -> ResolutionRecord {
        row(state, ProviderStatus)
    }
    fn operator(state: ResolutionState, two: bool) -> ResolutionRecord {
        let mut r = row(state, OperatorAttested);
        r.resolved_by = Some("alice".into());
        r.approved_by = two.then(|| "bob".to_string());
        r
    }
    fn closing(state: ResolutionState) -> ResolutionRecord {
        let mut r = row(state, ConflictResolution);
        r.resolved_by = Some("alice".into());
        r.approved_by = Some("bob".into());
        r
    }
    fn reconciler() -> ResolutionRecord {
        let mut r = row(Ambiguous, Reconciler);
        r.evidence_digest = None;
        r
    }

    #[test]
    fn nothing_is_unresolved_and_only_ambiguity_is_ambiguous() {
        assert_eq!(governing(&[]), Governing::Unresolved);
        assert_eq!(governing(&[reconciler()]), Governing::Ambiguous);
    }

    #[test]
    fn one_confirmed_state_governs_and_a_provider_outranks_an_attestation() {
        assert_eq!(
            governing(&[operator(Delivered, false)]),
            Governing::Confirmed {
                state: Delivered,
                source: OperatorAttested
            }
        );
        // Both say the same: the provider is the stated source, in any order.
        for rows in [
            vec![operator(Delivered, false), provider(Delivered)],
            vec![provider(Delivered), operator(Delivered, false)],
        ] {
            assert_eq!(
                governing(&rows),
                Governing::Confirmed {
                    state: Delivered,
                    source: ProviderStatus
                }
            );
        }
    }

    #[test]
    fn ambiguous_never_overrides_a_confirmed_state_whenever_it_was_written() {
        for rows in [
            vec![provider(Delivered), reconciler()],
            vec![reconciler(), provider(Delivered)],
            vec![reconciler(), provider(Not), provider(Ambiguous)],
        ] {
            assert!(
                matches!(governing(&rows), Governing::Confirmed { .. }),
                "{rows:?}"
            );
        }
    }

    #[test]
    fn two_different_confirmed_states_are_a_conflict_whatever_the_order() {
        for rows in [
            vec![provider(Delivered), operator(Not, true)],
            vec![operator(Not, true), provider(Delivered)],
            vec![provider(Delivered), provider(Not)],
        ] {
            assert_eq!(governing(&rows), Governing::Conflicted, "{rows:?}");
        }
    }

    #[test]
    fn a_two_person_resolution_closes_a_conflict_and_conflicting_closures_reopen_it() {
        let conflict = vec![provider(Delivered), operator(Not, true)];
        let mut closed = conflict.clone();
        closed.push(closing(Not));
        assert_eq!(
            governing(&closed),
            Governing::Confirmed {
                state: Not,
                source: ConflictResolution
            }
        );
        closed.push(closing(Delivered));
        assert_eq!(governing(&closed), Governing::Conflicted);
    }

    #[test]
    fn who_may_say_what_is_checked_before_a_resolution_is_written() {
        // Delivered: one person is enough; two is not what was asked.
        assert!(check_form(&operator(Delivered, false)).is_ok());
        assert!(check_form(&operator(Delivered, true)).is_err());
        // Not delivered: two different people.
        assert!(check_form(&operator(Not, true)).is_ok());
        assert!(check_form(&operator(Not, false)).is_err());
        let mut same = operator(Not, true);
        same.approved_by = same.resolved_by.clone();
        assert!(check_form(&same).is_err());
        // A provider status carries a digest and no people.
        assert!(check_form(&provider(Not)).is_ok());
        let mut without = provider(Not);
        without.evidence_digest = None;
        assert!(check_form(&without).is_err());
        // The reconciler only says ambiguous.
        assert!(check_form(&reconciler()).is_ok());
        let mut confirming = reconciler();
        confirming.state = Delivered;
        assert!(check_form(&confirming).is_err());
        // A conflict is closed by two people and a confirmed state.
        assert!(check_form(&closing(Delivered)).is_ok());
        let mut one = closing(Delivered);
        one.approved_by = None;
        assert!(check_form(&one).is_err());
        let mut ambiguous = closing(Delivered);
        ambiguous.state = Ambiguous;
        assert!(check_form(&ambiguous).is_err());
        // Codes and digests are checked.
        let mut bad = provider(Delivered);
        bad.reason = "Has Spaces".into();
        assert!(check_form(&bad).is_err());
        let mut bad = provider(Delivered);
        bad.evidence_digest = Some("not-hex".into());
        assert!(check_form(&bad).is_err());
    }

    /// A conflict can be closed only by two people; the reconciler, a provider
    /// status and a single person cannot close one, whatever state they name.
    #[test]
    fn only_two_people_can_close_a_conflict() {
        for source in [Reconciler, ProviderStatus, OperatorAttested] {
            let mut r = row(Not, source);
            r.source = source;
            // As a *closing* row they are not: governing ignores them as such.
            let rows = vec![provider(Delivered), operator(Not, true), r];
            assert_eq!(governing(&rows), Governing::Conflicted, "{source:?}");
        }
        // The reconciler cannot even be written as a confirmed state.
        let mut reconciler_confirming = row(Not, Reconciler);
        reconciler_confirming.evidence_digest = None;
        assert!(check_form(&reconciler_confirming).is_err());
        // Source-qualified identities: the same name from two sources is two
        // different people; the same key twice is one.
        let mut two_sources = operator(Not, true);
        two_sources.resolved_by = Some("oidc:https://idp#alice".into());
        two_sources.approved_by = Some("cert:ca#alice".into());
        assert!(check_form(&two_sources).is_ok());
        two_sources.approved_by = two_sources.resolved_by.clone();
        assert!(check_form(&two_sources).is_err());
    }

    #[test]
    fn the_signed_message_covers_every_field_and_tells_none_from_a_value() {
        let base = operator(Delivered, false);
        let message = resolution_message(&base);
        assert!(message.starts_with(RESOLUTION_SIG_PREFIX));
        let mut changed = base.clone();
        changed.state = Not;
        assert_ne!(resolution_message(&changed), message);
        let mut changed = base.clone();
        changed.reason = "other".into();
        assert_ne!(resolution_message(&changed), message);
        let mut changed = base.clone();
        changed.resolved_by = Some("alicia".into());
        assert_ne!(resolution_message(&changed), message);
        // `none` and the value "none" are different messages.
        let mut none = base.clone();
        none.approved_by = None;
        let mut literal = base;
        literal.approved_by = Some("none".into());
        assert_ne!(resolution_message(&none), resolution_message(&literal));
    }
}
