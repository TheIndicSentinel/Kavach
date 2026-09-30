//! Property-based tests (M1 exit criterion): delegation only narrows, and any
//! change to a signed token is rejected.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use chrono::Duration;
use common::*;
use kavach_domain::mandate::{
    AgentPassport, ContactWindow, DelegationRequest, DelegationRules, Mandate, MandateSource,
    TimeZoneId,
};
use kavach_mandate::delegation::{is_within, narrow_child, ChildIdentity};
use kavach_mandate::jws::{self, KeySet, TYP_MANDATE};
use proptest::prelude::*;

const ACTIONS: [&str; 6] = ["a0", "a1", "a2", "a3", "a4", "a5"];
const FIELDS: [&str; 5] = ["f0", "f1", "f2", "f3", "f4"];
const CHANNELS: [&str; 3] = ["whatsapp", "voice", "sms"];
const LIMITS: [&str; 3] = ["waiver_bps", "refund_paise", "calls"];

fn subset_of(universe: &'static [&'static str]) -> impl Strategy<Value = BTreeSet<String>> {
    proptest::collection::btree_set(proptest::sample::select(universe), 0..=universe.len())
        .prop_map(|s| s.into_iter().map(String::from).collect())
}

fn ceilings() -> impl Strategy<Value = BTreeMap<String, i64>> {
    proptest::collection::btree_map(proptest::sample::select(&LIMITS[..]), 0i64..20_000, 0..=3)
        .prop_map(|m| m.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn window() -> impl Strategy<Value = Option<ContactWindow>> {
    proptest::option::of(
        (0u16..1400, 1u16..40, 0u16..10).prop_map(|(from, len, max)| ContactWindow {
            tz: TimeZoneId::AsiaKolkata,
            from_min: from,
            to_min: (from + len).min(1440),
            max_per_day: max,
        }),
    )
}

prop_compose! {
    fn parent()(actions in subset_of(&ACTIONS), fields in subset_of(&FIELDS),
                channels in subset_of(&CHANNELS), window in window(), ceilings in ceilings(),
                max_depth in 1u8..4, exp_h in 1i64..200) -> Mandate {
        let now = t0();
        Mandate {
            mv: 1, id: "parent".into(), tenant_id: TENANT.into(), issuer: "kavach".into(),
            source: MandateSource { system: "lms".into(), record_ref: "r".into(), event_id: "e".into() },
            principal: "p".into(), holder: "h".into(), subject_ref: SUBJECT.into(),
            purpose: "loan_recovery".into(), consent_refs: set(&["C-1"]),
            actions, data_fields: fields, channels, window, ceilings,
            delegation: DelegationRules { max_depth, allowed_agents: set(&["child"]) },
            parent_id: None, depth: 0, nbf: now, exp: now + Duration::hours(exp_h),
            nonce: "n".into(),
        }
    }
}

prop_compose! {
    fn request()(actions in subset_of(&ACTIONS), fields in subset_of(&FIELDS),
                 channels in subset_of(&CHANNELS), window in window(), ceilings in ceilings(),
                 exp_h in proptest::option::of(1i64..400)) -> DelegationRequest {
        DelegationRequest {
            actions, data_fields: fields, channels, window, ceilings,
            exp: exp_h.map(|h| t0() + Duration::hours(h)),
        }
    }
}

prop_compose! {
    fn passport()(actions in subset_of(&ACTIONS), fields in subset_of(&FIELDS),
                  ceilings in ceilings()) -> AgentPassport {
        AgentPassport {
            agent_id: "child".into(), tenant_id: TENANT.into(), owner: "o".into(),
            allowed_purposes: set(&["loan_recovery"]), actions, data_fields: fields, ceilings,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// child ⊆ parent ∩ passport, for any parent, request and passport.
    #[test]
    fn delegation_only_narrows(parent in parent(), request in request(), passport in passport()) {
        let identity = ChildIdentity { id: "child-1".into(), nonce: "n2".into(), holder: "child", now: t0() };
        if let Ok(child) = narrow_child(&parent, &request, &passport, &identity) {
            prop_assert!(is_within(&child, &parent));
            prop_assert!(child.actions.is_subset(&passport.actions));
            prop_assert!(child.data_fields.is_subset(&passport.data_fields));
            for (k, v) in &child.ceilings {
                prop_assert!(passport.ceilings.get(k).is_some_and(|cap| v <= cap));
                prop_assert!(request.ceilings.get(k).is_none_or(|r| v <= r));
            }
            if let Some(req_exp) = request.exp {
                prop_assert!(child.exp <= req_exp);
            }
            prop_assert!(!child.actions.is_empty());
        }
    }
}

/// Signed once and shared by every case.
fn signed_mandate() -> &'static (String, KeySet) {
    static TOKEN: std::sync::OnceLock<(String, KeySet)> = std::sync::OnceLock::new();
    TOKEN.get_or_init(sign_fixture_mandate)
}

fn sign_fixture_mandate() -> (String, KeySet) {
    let mut provider = kavach_keys::InMemoryKeyProvider::new();
    let public = provider.insert_seed("kavach-mandate-1", [1u8; 32]).unwrap();
    let mandate = proptest::strategy::ValueTree::current(
        &parent()
            .new_tree(&mut proptest::test_runner::TestRunner::deterministic())
            .unwrap(),
    );
    let token = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(jws::sign(
            &provider,
            "kavach-mandate-1",
            TYP_MANDATE,
            &mandate,
        ))
        .unwrap();
    (token, KeySet::new([public]))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Changing any single byte of a signed token makes it invalid.
    #[test]
    fn any_byte_change_is_rejected(index in any::<prop::sample::Index>(), delta in 1u8..=255) {
        let (token, keys) = signed_mandate();
        prop_assert!(jws::verify::<Mandate>(token, TYP_MANDATE, keys).is_ok());
        let mut bytes = token.clone().into_bytes();
        let i = index.index(bytes.len());
        bytes[i] = bytes[i].wrapping_add(delta);
        if let Ok(tampered) = String::from_utf8(bytes) {
            prop_assert!(jws::verify::<Mandate>(&tampered, TYP_MANDATE, keys).is_err());
        }
    }
}
