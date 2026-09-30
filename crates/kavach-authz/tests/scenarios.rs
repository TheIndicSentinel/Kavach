//! Agent authorization scenarios (PRD acceptance scenarios 3–7, NFR-7) at the
//! library level, against the bundled collections policies.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, TimeZone, Utc};
use kavach_authz::{AgentAction, AgentAuthorizer, AgentState, AuthzRequest};
use kavach_domain::mandate::{ContactWindow, DelegationRules, Mandate, MandateSource, TimeZoneId};
use kavach_domain::Decision;

const SUBJECT: &str = "ref:borrower:B-9382";

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(ToString::to_string).collect()
}

/// `h:m` IST on 1 Oct 2026 as UTC.
fn ist(h: u32, m: u32, s: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap()
        + Duration::hours(i64::from(h))
        + Duration::minutes(i64::from(m))
        + Duration::seconds(i64::from(s))
        - Duration::minutes(330)
}

fn mandate() -> Mandate {
    Mandate {
        mv: 1,
        id: "M-1".into(),
        tenant_id: "nbfc-demo".into(),
        issuer: "kavach-dev".into(),
        source: MandateSource {
            system: "lms".into(),
            record_ref: "lms:loan/L-4471".into(),
            event_id: "evt-1".into(),
        },
        principal: "nbfc-collections-system".into(),
        holder: "collections-agent".into(),
        subject_ref: SUBJECT.into(),
        purpose: "loan_recovery".into(),
        consent_refs: set(&["C-1"]),
        actions: set(&[
            "read_fields",
            "send_reminder",
            "place_call",
            "propose_plan",
            "update_status",
        ]),
        data_fields: set(&["name", "overdue_amount", "emi_due_date", "loan_ref"]),
        channels: set(&["whatsapp", "voice"]),
        window: Some(ContactWindow {
            tz: TimeZoneId::AsiaKolkata,
            from_min: 8 * 60,
            to_min: 19 * 60,
            max_per_day: 3,
        }),
        ceilings: BTreeMap::from([("waiver_bps".to_string(), 1000)]),
        delegation: DelegationRules {
            max_depth: 1,
            allowed_agents: set(&["translator-agent"]),
        },
        parent_id: None,
        depth: 0,
        nbf: ist(0, 0, 0),
        exp: ist(0, 0, 0) + Duration::days(7),
        nonce: "n".into(),
    }
}

fn request(m: &Mandate, action: AgentAction) -> AuthzRequest<'_> {
    AuthzRequest {
        agent_id: "collections-agent",
        action,
        subject_ref: SUBJECT,
        mandate: m,
        requested_fields: set(&["name", "overdue_amount"]),
        channel: Some("whatsapp".into()),
        waiver_bps: None,
        contacts_today: 0,
        task_tainted: false,
        agent_state: AgentState::Active,
        approval_valid: false,
        now: ist(11, 0, 0),
    }
}

fn decide(r: &AuthzRequest<'_>) -> (Decision, Vec<String>) {
    let o = AgentAuthorizer::bundled().unwrap().authorize(r).unwrap();
    (o.decision, o.determining_policies)
}

#[test]
fn scenario1_reminder_within_mandate_passes() {
    let m = mandate();
    assert_eq!(
        decide(&request(&m, AgentAction::SendReminder)).0,
        Decision::Pass
    );
}

#[test]
fn scenario5_other_subject_is_blocked_without_a_human() {
    let m = mandate();
    let mut r = request(&m, AgentAction::SendReminder);
    r.subject_ref = "ref:borrower:B-5511";
    let (d, why) = decide(&r);
    assert_eq!(d, Decision::Block);
    assert!(why.contains(&"subject-binding".to_string()), "{why:?}");
}

#[test]
fn scenario3_window_boundaries_in_ist() {
    let m = mandate();
    for (h, mi, s, expected) in [
        (7, 59, 59, Decision::Block),
        (8, 0, 0, Decision::Pass),
        (18, 59, 59, Decision::Pass),
        (19, 0, 0, Decision::Block),
        (19, 45, 0, Decision::Block),
    ] {
        let mut r = request(&m, AgentAction::PlaceCall);
        r.channel = Some("voice".into());
        r.now = ist(h, mi, s);
        assert_eq!(decide(&r).0, expected, "{h:02}:{mi:02}:{s:02} IST");
    }
    // Reading is not a contact; the window does not apply.
    let mut r = request(&m, AgentAction::ReadFields);
    r.now = ist(19, 45, 0);
    assert_eq!(decide(&r).0, Decision::Pass);
}

#[test]
fn scenario3_daily_contact_cap() {
    let m = mandate();
    let mut r = request(&m, AgentAction::SendReminder);
    r.contacts_today = 2;
    assert_eq!(decide(&r).0, Decision::Pass);
    r.contacts_today = 3;
    assert_eq!(decide(&r).0, Decision::Block);
}

#[test]
fn scenario4_fields_and_channels_outside_mandate_are_blocked() {
    let m = mandate();
    let mut r = request(&m, AgentAction::ReadFields);
    r.requested_fields = set(&["name", "salary"]);
    assert_eq!(decide(&r).0, Decision::Block);

    let mut r = request(&m, AgentAction::SendReminder);
    r.channel = Some("sms".into());
    assert_eq!(decide(&r).0, Decision::Block);
}

#[test]
fn scenario6_waiver_above_ceiling_needs_exact_approval() {
    let m = mandate();
    let mut r = request(&m, AgentAction::ProposePlan);
    r.waiver_bps = Some(3500);
    let (d, why) = decide(&r);
    assert_eq!(d, Decision::HumanReview);
    assert_eq!(why, vec!["waiver-ceiling".to_string()]);

    r.approval_valid = true;
    assert_eq!(decide(&r).0, Decision::Pass);

    let mut r = request(&m, AgentAction::ProposePlan);
    r.waiver_bps = Some(500);
    assert_eq!(decide(&r).0, Decision::Pass);

    // No ceiling in the mandate: any waiver needs review.
    let mut m2 = mandate();
    m2.ceilings.clear();
    let mut r = request(&m2, AgentAction::ProposePlan);
    r.waiver_bps = Some(1);
    assert_eq!(decide(&r).0, Decision::HumanReview);
}

#[test]
fn escalation_mixed_with_a_hard_forbid_is_blocked() {
    let m = mandate();
    let mut r = request(&m, AgentAction::ProposePlan);
    r.waiver_bps = Some(3500);
    r.subject_ref = "ref:borrower:B-5511";
    assert_eq!(decide(&r).0, Decision::Block);
}

#[test]
fn tainted_task_escalates_only_critical_actions() {
    let m = mandate();
    let mut r = request(&m, AgentAction::UpdateStatus);
    r.task_tainted = true;
    assert_eq!(decide(&r).0, Decision::HumanReview);
    let mut r = request(&m, AgentAction::ReadFields);
    r.task_tainted = true;
    assert_eq!(decide(&r).0, Decision::Pass);
}

#[test]
fn scenario7_delegated_read_only_mandate_cannot_update() {
    let mut child = mandate();
    child.holder = "translator-agent".into();
    child.actions = set(&["read_fields"]);
    child.depth = 1;
    let mut r = request(&child, AgentAction::UpdateStatus);
    r.agent_id = "translator-agent";
    let (d, why) = decide(&r);
    assert_eq!(d, Decision::Block);
    assert!(why.is_empty(), "default deny, no permit matched: {why:?}");

    // The parent mandate is not usable by an agent that does not hold it.
    let parent = mandate();
    let mut r = request(&parent, AgentAction::ReadFields);
    r.agent_id = "translator-agent";
    assert_eq!(decide(&r).0, Decision::Block);
}

#[test]
fn non_active_agent_states_block() {
    let m = mandate();
    for state in [
        AgentState::Restricted,
        AgentState::Quarantined,
        AgentState::Revoked,
    ] {
        let mut r = request(&m, AgentAction::ReadFields);
        r.agent_state = state;
        assert_eq!(decide(&r).0, Decision::Block, "{state:?}");
    }
}

#[test]
fn policy_sets_must_be_well_formed() {
    let schema = kavach_authz::AGENT_SCHEMA;
    // Missing @id.
    assert!(AgentAuthorizer::new(schema, "permit (principal, action, resource);").is_err());
    // @escalate on a permit.
    assert!(AgentAuthorizer::new(
        schema,
        r#"@id("p") @escalate("human_review") permit (principal, action, resource);"#
    )
    .is_err());
    // Unknown context attribute fails strict validation.
    assert!(AgentAuthorizer::new(
        schema,
        r#"@id("p") permit (principal, action, resource) when { context.nope };"#
    )
    .is_err());
    AgentAuthorizer::bundled().expect("bundled policies are valid");
}

// ---- H4 (ADR-011) ----

fn blocked_by(r: &AuthzRequest<'_>, policy: &str) {
    let (decision, policies) = decide(r);
    assert_eq!(decision, Decision::Block, "{policies:?}");
    assert!(
        policies.iter().any(|p| p == policy),
        "{policy} not in {policies:?}"
    );
}

#[test]
fn h4_missing_parameters_fail_closed() {
    let m = mandate();
    // A plan must state its waiver, even when it is zero.
    blocked_by(&request(&m, AgentAction::ProposePlan), "waiver-required");
    let mut r = request(&m, AgentAction::ProposePlan);
    r.waiver_bps = Some(0);
    assert_eq!(decide(&r).0, Decision::Pass);

    let mut r = request(&m, AgentAction::SendReminder);
    r.channel = None;
    blocked_by(&r, "channel-required");

    let mut r = request(&m, AgentAction::ReadFields);
    r.requested_fields.clear();
    blocked_by(&r, "fields-required");
}

#[test]
fn h4_out_of_range_waivers_are_blocked() {
    let m = mandate();
    for waiver in [-5000, -1, 10_001] {
        let mut r = request(&m, AgentAction::ProposePlan);
        r.waiver_bps = Some(waiver);
        blocked_by(&r, "waiver-in-range");
    }
}

#[test]
fn h4_contact_needs_a_window() {
    let mut m = mandate();
    m.window = None;
    blocked_by(
        &request(&m, AgentAction::SendReminder),
        "contact-window-required",
    );
    blocked_by(
        &request(&m, AgentAction::PlaceCall),
        "contact-window-required",
    );
    // Non-contact actions are unaffected.
    assert_eq!(
        decide(&request(&m, AgentAction::ReadFields)).0,
        Decision::Pass
    );
}

/// The Cedar floor equals `CONTACT_FLOOR_*`: with a (non-validated) mandate
/// window wider than the floor, only the floor decides at its boundaries.
#[test]
fn h4_contact_floor_matches_the_domain_constants() {
    use kavach_domain::mandate::{CONTACT_FLOOR_FROM_MIN, CONTACT_FLOOR_TO_MIN};
    let mut m = mandate();
    m.window = Some(ContactWindow {
        tz: TimeZoneId::AsiaKolkata,
        from_min: 6 * 60,
        to_min: 22 * 60,
        max_per_day: 3,
    });
    let at = |minute: u16| {
        let (h, min) = (u32::from(minute / 60), u32::from(minute % 60));
        ist(h, min, 0)
    };
    let cases = [
        (CONTACT_FLOOR_FROM_MIN - 1, Decision::Block),
        (CONTACT_FLOOR_FROM_MIN, Decision::Pass),
        (CONTACT_FLOOR_TO_MIN - 1, Decision::Pass),
        (CONTACT_FLOOR_TO_MIN, Decision::Block),
    ];
    for (minute, expected) in cases {
        let mut r = request(&m, AgentAction::PlaceCall);
        r.channel = Some("voice".into());
        r.now = at(minute);
        let (decision, policies) = decide(&r);
        assert_eq!(decision, expected, "minute {minute}: {policies:?}");
        if expected == Decision::Block {
            assert!(
                policies.iter().any(|p| p == "contact-hours-floor"),
                "{policies:?}"
            );
        }
    }
    // The floor is for contact only.
    let mut r = request(&m, AgentAction::ReadFields);
    r.now = at(3 * 60);
    assert_eq!(decide(&r).0, Decision::Pass);
}

#[test]
fn h4_every_schema_action_needs_exactly_one_permit() {
    use kavach_authz::{AGENT_POLICIES, AGENT_SCHEMA};
    // A new schema action with no permit is refused at load.
    let schema = AGENT_SCHEMA.replace(
        "action read_fields, send_reminder,",
        "action read_fields, send_reminder, waive_fee,",
    );
    assert_ne!(schema, AGENT_SCHEMA);
    let err = AgentAuthorizer::new(&schema, AGENT_POLICIES)
        .err()
        .expect("refused");
    assert!(err.to_string().contains("waive_fee"), "{err}");

    // An unconstrained permit is refused.
    let extra =
        format!("{AGENT_POLICIES}\n@id(\"catch-all\")\npermit (principal, action, resource);\n");
    let err = AgentAuthorizer::new(AGENT_SCHEMA, &extra)
        .err()
        .expect("refused");
    assert!(err.to_string().contains("exactly one action"), "{err}");

    // A second permit for the same action is refused.
    let extra = format!(
        "{AGENT_POLICIES}\n@id(\"read-again\")\npermit (principal, action == Kavach::Agent::Action::\"read_fields\", resource);\n"
    );
    let err = AgentAuthorizer::new(AGENT_SCHEMA, &extra)
        .err()
        .expect("refused");
    assert!(err.to_string().contains("2 permits"), "{err}");
}
