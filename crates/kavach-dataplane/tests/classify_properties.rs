//! `classify` turns what the provider said into the outcome recorded for an
//! allow. Whatever the provider says, these hold.

use kavach_dataplane::gateway::classify;
use kavach_dataplane::ForwardResult;
use kavach_ports::agent_evidence::{is_reason_code, Outcome};
use proptest::prelude::*;

fn result() -> impl Strategy<Value = ForwardResult> {
    prop_oneof![
        Just(ForwardResult::NotSent),
        Just(ForwardResult::Lost),
        // Any status a server can send, and a few that are not even HTTP.
        (any::<u16>(), prop::option::of("[a-z0-9._:-]{0,40}"))
            .prop_map(|(status, message_id)| ForwardResult::Responded { status, message_id }),
        (100u16..=599, Just(None))
            .prop_map(|(status, message_id)| ForwardResult::Responded { status, message_id }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::with_cases(5000) })]

    /// Nothing is "delivered" unless the provider answered 200 or 202.
    #[test]
    fn delivered_means_the_provider_said_200_or_202(r in result()) {
        let (outcome, _, _) = classify(&r);
        let said_yes = matches!(&r, ForwardResult::Responded { status: 200 | 202, .. });
        prop_assert_eq!(outcome == Outcome::Delivered, said_yes);
    }

    /// "Failed" (provably not delivered) only when nothing was sent;
    /// "refused" only for a client error that proves the provider declined it
    /// (not a timeout, not the id-conflict anomaly); and the gateway's own
    /// "not executed" is never something the provider's answer produces.
    #[test]
    fn failed_and_refused_need_proof(r in result()) {
        let (outcome, _, _) = classify(&r);
        prop_assert_eq!(outcome == Outcome::Failed, matches!(r, ForwardResult::NotSent));
        let declined = matches!(
            &r,
            ForwardResult::Responded { status, .. }
                if (400..=499).contains(status) && !matches!(status, 408 | 409)
        );
        prop_assert_eq!(outcome == Outcome::Refused, declined);
        prop_assert_ne!(outcome, Outcome::NotExecuted);
    }

    /// Everything else is unknown, never retried: a lost response, a timeout,
    /// any 5xx, a redirect, a 2xx outside the contract, and a provider that
    /// says an id was used for other claims (which is also an anomaly to alert
    /// on, and only then).
    #[test]
    fn what_is_not_known_is_unknown_and_only_a_409_is_an_anomaly(r in result()) {
        let (outcome, _, anomaly) = classify(&r);
        let is_409 = matches!(&r, ForwardResult::Responded { status: 409, .. });
        prop_assert_eq!(anomaly, is_409);
        let known = matches!(r, ForwardResult::NotSent)
            || matches!(&r, ForwardResult::Responded { status, .. }
                if matches!(status, 200 | 202) || ((400..=499).contains(status) && !matches!(status, 408 | 409)));
        prop_assert_eq!(outcome == Outcome::Unknown, !known);
    }

    /// The reason is always a code a signed outcome may carry, and names the
    /// status the provider gave.
    #[test]
    fn the_reason_is_a_code_that_names_the_status(r in result()) {
        let (_, reason, _) = classify(&r);
        prop_assert!(is_reason_code(&reason), "{reason}");
        if let ForwardResult::Responded { status, .. } = &r {
            prop_assert_eq!(reason, format!("provider_{status}"));
        }
    }
}
