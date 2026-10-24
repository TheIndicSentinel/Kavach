//! Properties of the outcome resolutions (ADR-017) that must hold for every
//! input, not for the examples someone thought of: who may say what, what
//! governs, and that nothing but a two-person closure changes a confirmed
//! state.

use kavach_ports::outcome_resolution::{
    check_form, governing_of, summarise, Governing, ResolutionRecord, ResolutionSource,
    ResolutionState,
};
use proptest::prelude::*;

const STATES: [ResolutionState; 3] = [
    ResolutionState::ConfirmedDelivered,
    ResolutionState::ConfirmedNotDelivered,
    ResolutionState::Ambiguous,
];
const SOURCES: [ResolutionSource; 4] = [
    ResolutionSource::ProviderStatus,
    ResolutionSource::OperatorAttested,
    ResolutionSource::ConflictResolution,
    ResolutionSource::Reconciler,
];

fn state() -> impl Strategy<Value = ResolutionState> {
    prop::sample::select(STATES.to_vec())
}

fn source() -> impl Strategy<Value = ResolutionSource> {
    prop::sample::select(SOURCES.to_vec())
}

fn person() -> impl Strategy<Value = Option<String>> {
    prop::option::of(prop::sample::select(vec![
        "oidc:https://idp#alice".to_string(),
        "oidc:https://idp#bob".to_string(),
        "oidc:https://other#alice".to_string(),
    ]))
}

fn digest() -> impl Strategy<Value = Option<String>> {
    prop::option::of(Just("ab".repeat(32)))
}

/// A resolution of any shape: valid or not. Only the fields the rules read
/// vary; the rest is well formed so that the rules, not the syntax, decide.
fn row() -> impl Strategy<Value = ResolutionRecord> {
    (state(), source(), digest(), person(), person()).prop_map(
        |(state, source, evidence_digest, resolved_by, approved_by)| ResolutionRecord {
            tenant_id: "t".into(),
            credential_id: "c".into(),
            outcome_ref: "00".repeat(32),
            state,
            source,
            reason: "provider_status".into(),
            evidence_digest,
            resolved_by,
            approved_by,
            ts: chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            key_id: "k".into(),
            sig: "00".repeat(64),
        },
    )
}

fn pairs() -> impl Strategy<Value = Vec<(ResolutionState, ResolutionSource)>> {
    prop::collection::vec((state(), source()), 0..8)
}

/// A pair that can exist at all: the form allows `ambiguous` only from the
/// reconciler and a closure only with a confirmed state.
fn possible(pair: (ResolutionState, ResolutionSource)) -> bool {
    match pair.1 {
        ResolutionSource::Reconciler => pair.0 == ResolutionState::Ambiguous,
        ResolutionSource::ConflictResolution => pair.0.is_confirmed(),
        ResolutionSource::ProviderStatus | ResolutionSource::OperatorAttested => {
            pair.0.is_confirmed()
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::with_cases(2000) })]

    /// "Nobody could say" is the reconciler's statement and nobody else's:
    /// no valid line has the state `ambiguous` from any other source.
    #[test]
    fn ambiguous_is_only_ever_the_reconcilers(row in row()) {
        if check_form(&row).is_ok() && row.state == ResolutionState::Ambiguous {
            prop_assert_eq!(row.source, ResolutionSource::Reconciler);
        }
    }

    /// And what the reconciler says is nothing else: `ambiguous`, with no
    /// evidence and no people.
    #[test]
    fn the_reconciler_says_only_ambiguous_and_names_no_one(row in row()) {
        if check_form(&row).is_ok() && row.source == ResolutionSource::Reconciler {
            prop_assert_eq!(row.state, ResolutionState::Ambiguous);
            prop_assert!(row.evidence_digest.is_none());
            prop_assert!(row.resolved_by.is_none() && row.approved_by.is_none());
        }
    }

    /// Who may confirm what: a provider's answer carries evidence and no
    /// people; "delivered" is one person's word, "not delivered" two
    /// different people's (it lowers the recorded contact), and so is a
    /// closure of a conflict.
    #[test]
    fn who_may_confirm_what(row in row()) {
        if check_form(&row).is_err() {
            return Ok(());
        }
        match (row.source, row.state) {
            (ResolutionSource::ProviderStatus, _) => {
                prop_assert!(row.evidence_digest.is_some());
                prop_assert!(row.resolved_by.is_none() && row.approved_by.is_none());
            }
            (ResolutionSource::OperatorAttested, ResolutionState::ConfirmedDelivered) => {
                prop_assert!(row.resolved_by.is_some() && row.evidence_digest.is_some());
                prop_assert!(row.approved_by.is_none());
            }
            (ResolutionSource::OperatorAttested, ResolutionState::ConfirmedNotDelivered)
            | (ResolutionSource::ConflictResolution, _) => {
                prop_assert!(row.resolved_by.is_some() && row.approved_by.is_some());
                prop_assert_ne!(&row.resolved_by, &row.approved_by);
                prop_assert!(row.evidence_digest.is_some());
                prop_assert!(row.state.is_confirmed());
            }
            _ => {}
        }
    }

    /// The governing state is a function of the set of lines: the order they
    /// were written in, and repeats, change nothing ("never the latest").
    #[test]
    fn the_governing_state_ignores_order_and_repeats(
        rows in pairs().prop_flat_map(|v| Just(v).prop_shuffle()),
        again in pairs()
    ) {
        let mut sorted = rows.clone();
        sorted.sort_by_key(|(s, src)| (s.as_str(), src.as_str()));
        prop_assert_eq!(governing_of(&rows), governing_of(&sorted));
        let mut doubled = rows.clone();
        doubled.extend(rows.iter().copied());
        prop_assert_eq!(governing_of(&rows), governing_of(&doubled));
        // A prefix of lines that were all repeats is also the same set.
        let mut with_repeats = rows.clone();
        with_repeats.extend(again.iter().filter(|p| rows.contains(p)).copied());
        prop_assert_eq!(governing_of(&rows), governing_of(&with_repeats));
    }

    /// With a confirmed line, the outcome is confirmed or in conflict: never
    /// unresolved, never merely ambiguous. Without one, it is ambiguous
    /// exactly when some line says so.
    #[test]
    fn a_confirmed_line_is_never_reported_as_unknown(rows in pairs()) {
        let rows: Vec<_> = rows.into_iter().filter(|p| possible(*p)).collect();
        let any_confirmed = rows.iter().any(|(s, _)| s.is_confirmed());
        let any_ambiguous = rows.iter().any(|(s, _)| *s == ResolutionState::Ambiguous);
        match governing_of(&rows) {
            Governing::Confirmed { .. } | Governing::Conflicted => prop_assert!(any_confirmed),
            Governing::Ambiguous => prop_assert!(!any_confirmed && any_ambiguous),
            Governing::Unresolved => prop_assert!(rows.is_empty()),
        }
        if any_confirmed {
            prop_assert!(!matches!(governing_of(&rows), Governing::Ambiguous | Governing::Unresolved));
        }
    }

    /// Ambiguity, from any source and written at any time, never overrides
    /// a confirmed state or a conflict.
    #[test]
    fn ambiguity_never_changes_what_is_confirmed(
        rows in pairs(),
        extra in prop::collection::vec(source(), 1..5)
    ) {
        let rows: Vec<_> = rows.into_iter().filter(|p| possible(*p)).collect();
        let before = governing_of(&rows);
        if matches!(before, Governing::Confirmed { .. } | Governing::Conflicted) {
            let mut after = rows.clone();
            after.extend(extra.into_iter().map(|s| (ResolutionState::Ambiguous, s)));
            prop_assert_eq!(governing_of(&after), before);
        }
    }

    /// A confirmed state is not overwritten by anything that is not a
    /// two-person closure: add any lines other than closures, and a confirmed
    /// state either stays or becomes a visible conflict. It never becomes the
    /// opposite confirmed state (no "latest wins").
    #[test]
    fn a_confirmed_state_is_never_silently_flipped(rows in pairs(), extra in pairs()) {
        let no_closures = |v: Vec<(ResolutionState, ResolutionSource)>| -> Vec<_> {
            v.into_iter()
                .filter(|p| possible(*p) && p.1 != ResolutionSource::ConflictResolution)
                .collect()
        };
        let rows = no_closures(rows);
        let extra = no_closures(extra);
        if let Governing::Confirmed { state, .. } = governing_of(&rows) {
            let mut after = rows.clone();
            after.extend(extra);
            match governing_of(&after) {
                Governing::Confirmed { state: now, .. } => prop_assert_eq!(now, state),
                Governing::Conflicted => {}
                other => prop_assert!(false, "{state:?} became {other:?}"),
            }
        }
    }

    /// Conflicted exactly when two different confirmed states stand and no
    /// closure settles it, or two closures disagree.
    #[test]
    fn a_conflict_is_two_confirmed_states_nobody_has_closed(rows in pairs()) {
        let rows: Vec<_> = rows.into_iter().filter(|p| possible(*p)).collect();
        let distinct = |pick: &dyn Fn(&(ResolutionState, ResolutionSource)) -> bool| {
            let mut states: Vec<&str> = rows
                .iter()
                .filter(|p| pick(p) && p.0.is_confirmed())
                .map(|p| p.0.as_str())
                .collect();
            states.sort_unstable();
            states.dedup();
            states.len()
        };
        let closures = distinct(&|p| p.1 == ResolutionSource::ConflictResolution);
        let confirmed = distinct(&|_| true);
        let expected_conflict = closures >= 2 || (closures == 0 && confirmed >= 2);
        prop_assert_eq!(
            matches!(governing_of(&rows), Governing::Conflicted),
            expected_conflict
        );
    }

    /// Every unknown outcome is counted once, in exactly one class.
    #[test]
    fn the_summary_counts_every_outcome_once(
        outcomes in prop::collection::vec(pairs(), 0..6)
    ) {
        let outcomes: Vec<Vec<_>> = outcomes
            .into_iter()
            .map(|v| v.into_iter().filter(|p| possible(*p)).collect())
            .collect();
        let at = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let summary = summarise(outcomes.iter().map(|rows| (at, rows.as_slice())));
        let total = summary.unresolved + summary.ambiguous + summary.conflicted + summary.resolved;
        prop_assert_eq!(total, outcomes.len() as u64);
        prop_assert_eq!(
            summary.oldest_unconfirmed.is_some(),
            summary.unresolved + summary.ambiguous + summary.conflicted > 0
        );
    }
}
