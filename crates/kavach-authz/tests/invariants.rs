//! PRD D15: CEL refinement never downgrades the Cedar outcome.

use kavach_authz::{refine, AuthzOutcome};
use kavach_domain::Decision;
use kavach_policy::PolicyEvaluation;
use proptest::prelude::*;

fn decision() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Pass),
        Just(Decision::Alert),
        Just(Decision::HumanReview),
        Just(Decision::Block),
    ]
}

proptest! {
    #[test]
    fn cel_never_downgrades_cedar(cedar in decision(), cel in decision(), with_cel in any::<bool>()) {
        let base = AuthzOutcome {
            decision: cedar,
            determining_policies: vec!["p".into()],
            reason_codes: vec!["r".into()],
        };
        let evaluation = PolicyEvaluation {
            policy_decision: cel,
            reason_codes: vec!["cel".into()],
            policy_hits: vec![],
        };
        let out = refine(base, with_cel.then_some(&evaluation));
        prop_assert!(out.decision.severity_rank() >= cedar.severity_rank());
        if with_cel {
            prop_assert!(out.decision.severity_rank() >= cel.severity_rank());
            prop_assert_eq!(out.decision, Decision::max(cedar, cel));
        } else {
            prop_assert_eq!(out.decision, cedar);
        }
    }
}
