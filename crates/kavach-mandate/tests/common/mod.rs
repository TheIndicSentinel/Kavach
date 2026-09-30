#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, TimeZone, Utc};
use kavach_domain::mandate::{
    AgentPassport, ConsentRecord, ContactWindow, DelegationRules, MandateTemplate, SorEvent,
    TimeZoneId,
};
use kavach_keys::InMemoryKeyProvider;
use kavach_mandate::jws::{self, KeySet, TYP_SOR_EVENT};
use kavach_mandate::memory::{InMemoryConsentSource, InMemoryEventBus, InMemoryMandateStore};
use kavach_mandate::{MandateConfig, MandateDeps, MandateService, SorIssuer};
use kavach_ports_testkit::{FakeClock, InMemoryReplayGuard};

pub const TENANT: &str = "nbfc-demo";
pub const SUBJECT: &str = "ref:borrower:B-9382";

pub type Service = MandateService<
    InMemoryKeyProvider,
    InMemoryReplayGuard,
    InMemoryConsentSource,
    InMemoryMandateStore,
    InMemoryEventBus,
    FakeClock,
>;

pub fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(ToString::to_string).collect()
}

pub fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 1, 5, 30, 0).unwrap()
}

pub struct Fixture {
    pub service: Service,
    pub sor: InMemoryKeyProvider,
    pub now: DateTime<Utc>,
}

impl Fixture {
    pub fn clock(&self) -> &FakeClock {
        self.service.clock()
    }
}

pub fn window() -> ContactWindow {
    ContactWindow {
        tz: TimeZoneId::AsiaKolkata,
        from_min: 8 * 60,
        to_min: 19 * 60,
        max_per_day: 3,
    }
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
        window: Some(window()),
        ceilings: BTreeMap::from([("waiver_bps".to_string(), 1000)]),
        ttl_seconds: 7 * 24 * 3600,
        delegation: DelegationRules {
            max_depth: 1,
            allowed_agents: set(&["translator-agent"]),
        },
        eligible_agents: set(&["collections-agent"]),
    }
}

pub fn passports() -> Vec<AgentPassport> {
    vec![
        AgentPassport {
            agent_id: "collections-agent".into(),
            tenant_id: TENANT.into(),
            owner: "collections-ops".into(),
            allowed_purposes: set(&["loan_recovery"]),
            actions: set(&[
                "read_fields",
                "send_reminder",
                "place_call",
                "propose_plan",
                "update_status",
            ]),
            data_fields: set(&["name", "overdue_amount", "emi_due_date", "loan_ref"]),
            ceilings: BTreeMap::from([("waiver_bps".to_string(), 1000)]),
        },
        AgentPassport {
            agent_id: "translator-agent".into(),
            tenant_id: TENANT.into(),
            owner: "collections-ops".into(),
            allowed_purposes: set(&["loan_recovery"]),
            actions: set(&["read_fields"]),
            data_fields: set(&["name", "loan_ref"]),
            ceilings: BTreeMap::new(),
        },
    ]
}

pub fn consent(now: DateTime<Utc>) -> ConsentRecord {
    ConsentRecord {
        consent_id: "C-1".into(),
        tenant_id: TENANT.into(),
        subject_ref: SUBJECT.into(),
        purposes: set(&["loan_recovery"]),
        expires_at: now + Duration::days(30),
        active: true,
    }
}

pub fn fixture_with(consents: Vec<ConsentRecord>, tmpl: MandateTemplate) -> Fixture {
    let now = t0();
    let mut kavach = InMemoryKeyProvider::new();
    let kavach_pub = kavach.insert_seed("kavach-mandate-1", [1u8; 32]).unwrap();
    let mut sor = InMemoryKeyProvider::new();
    let lms_pub = sor.insert_seed("lms-issuer-1", [2u8; 32]).unwrap();
    let crm_pub = sor.insert_seed("crm-issuer-1", [4u8; 32]).unwrap();
    let config = MandateConfig {
        issuer_id: "kavach-dev".into(),
        signing_kid: "kavach-mandate-1".into(),
        mandate_keys: KeySet::new([kavach_pub]),
        sor_issuers: vec![
            SorIssuer {
                system: "lms".into(),
                key: lms_pub,
            },
            SorIssuer {
                system: "crm".into(),
                key: crm_pub,
            },
        ],
        templates: vec![tmpl],
        passports: passports(),
        event_freshness_seconds: 300,
        replay_window_seconds: 24 * 3600,
    };
    let service = MandateService::new(
        MandateDeps {
            keys: kavach,
            replay: InMemoryReplayGuard::new(),
            consents: InMemoryConsentSource::new(consents),
            store: InMemoryMandateStore::new(),
            events: InMemoryEventBus::new(),
            clock: FakeClock::synced_at(now),
        },
        config,
    );
    Fixture { service, sor, now }
}

pub fn fixture() -> Fixture {
    let now = t0();
    fixture_with(vec![consent(now)], template())
}

pub fn event(now: DateTime<Utc>, event_id: &str) -> SorEvent {
    SorEvent {
        event_id: event_id.into(),
        tenant_id: TENANT.into(),
        system: "lms".into(),
        event_type: "loan.dpd30".into(),
        record_ref: "lms:loan/L-4471".into(),
        subject_ref: SUBJECT.into(),
        principal: "nbfc-collections-system".into(),
        consent_refs: set(&["C-1"]),
        assigned_agent: "collections-agent".into(),
        occurred_at: now,
        nonce: format!("n-{event_id}"),
    }
}

pub async fn sign_event(sor: &InMemoryKeyProvider, kid: &str, event: &SorEvent) -> String {
    jws::sign(sor, kid, TYP_SOR_EVENT, event).await.unwrap()
}
