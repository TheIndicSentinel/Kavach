//! Shared fixture: a mandate configuration and a signed SoR event.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use chrono::{DateTime, Duration, TimeZone, Utc};
use kavach_domain::mandate::{
    AgentPassport, ConsentRecord, ContactWindow, DelegationRules, MandateTemplate, SorEvent,
    TimeZoneId,
};
use kavach_keys::InMemoryKeyProvider;
use kavach_mandate::jws::{self, KeySet, TYP_SOR_EVENT};
use kavach_mandate::{MandateConfig, SorIssuer};
use kavach_ports::{TimeSource, TrustedNow};
use kavach_ports_testkit::FakeClock;

pub const TENANT: &str = "default";
pub const SUBJECT: &str = "ref:borrower:B-9382";

/// One clock shared by the mandate service and the core.
#[derive(Clone)]
pub struct Clock(pub Arc<FakeClock>);

impl TimeSource for Clock {
    fn now(&self) -> TrustedNow {
        self.0.now()
    }
}

pub fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(ToString::to_string).collect()
}

/// `h:m:s` IST on 1 Oct 2026, as UTC.
pub fn ist(h: i64, m: i64, s: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap()
        + Duration::hours(h)
        + Duration::minutes(m)
        + Duration::seconds(s)
        - Duration::minutes(330)
}

pub fn template() -> MandateTemplate {
    MandateTemplate {
        tenant_id: TENANT.into(),
        event_type: "loan.dpd30".into(),
        purpose: "loan_recovery".into(),
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
        ttl_seconds: 7 * 24 * 3600,
        delegation: DelegationRules {
            max_depth: 1,
            allowed_agents: set(&["translator-agent"]),
        },
        eligible_agents: set(&["collections-agent"]),
    }
}

pub fn passport(agent: &str, actions: &[&str]) -> AgentPassport {
    AgentPassport {
        agent_id: agent.into(),
        tenant_id: TENANT.into(),
        owner: "collections-ops".into(),
        allowed_purposes: set(&["loan_recovery"]),
        actions: set(actions),
        data_fields: set(&["name", "overdue_amount", "emi_due_date", "loan_ref"]),
        ceilings: BTreeMap::from([("waiver_bps".to_string(), 1000)]),
    }
}

/// Keys, consents and a valid mandate configuration.
pub struct Setup {
    pub kavach: InMemoryKeyProvider,
    pub sor: InMemoryKeyProvider,
    pub consents: Vec<ConsentRecord>,
    pub config: MandateConfig,
}

pub fn setup() -> Setup {
    let mut kavach = InMemoryKeyProvider::new();
    let kavach_pub = kavach.insert_seed("kavach-mandate-1", [1u8; 32]).unwrap();
    let mut sor = InMemoryKeyProvider::new();
    let lms_pub = sor.insert_seed("lms-issuer-1", [2u8; 32]).unwrap();
    // Consent artefact ids are opaque (they never embed the borrower).
    let consents: Vec<ConsentRecord> = [("B-9382", "C-7f3a"), ("B-5511", "C-91c2")]
        .map(|(b, id)| ConsentRecord {
            consent_id: id.into(),
            tenant_id: TENANT.into(),
            subject_ref: format!("ref:borrower:{b}"),
            purposes: set(&["loan_recovery"]),
            expires_at: ist(11, 0, 0) + Duration::days(30),
            active: true,
        })
        .into();
    let config = MandateConfig {
        issuer_id: "kavach-dev".into(),
        signing_kid: "kavach-mandate-1".into(),
        mandate_keys: KeySet::new([kavach_pub]),
        sor_issuers: vec![SorIssuer {
            system: "lms".into(),
            key: lms_pub,
        }],
        templates: vec![template()],
        passports: vec![
            passport(
                "collections-agent",
                &[
                    "read_fields",
                    "send_reminder",
                    "place_call",
                    "propose_plan",
                    "update_status",
                ],
            ),
            passport("translator-agent", &["read_fields"]),
        ],
        event_freshness_seconds: 300,
        replay_window_seconds: 24 * 3600,
    };
    Setup {
        kavach,
        sor,
        consents,
        config,
    }
}

/// A signed delinquency event for `borrower` at `now`.
pub async fn event_token(sor: &InMemoryKeyProvider, borrower: &str, now: DateTime<Utc>) -> String {
    let event = SorEvent {
        event_id: format!("evt-{borrower}"),
        tenant_id: TENANT.into(),
        system: "lms".into(),
        event_type: "loan.dpd30".into(),
        record_ref: format!("lms:loan/{borrower}"),
        subject_ref: format!("ref:borrower:{borrower}"),
        principal: "nbfc-collections-system".into(),
        consent_refs: set(&[if borrower == "B-9382" {
            "C-7f3a"
        } else {
            "C-91c2"
        }]),
        assigned_agent: "collections-agent".into(),
        occurred_at: now,
        nonce: format!("n-{borrower}"),
    };
    jws::sign(sor, "lms-issuer-1", TYP_SOR_EVENT, &event)
        .await
        .unwrap()
}
