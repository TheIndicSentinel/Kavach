//! Shared set-up for the fuzz targets. Everything here is deterministic:
//! fixed keys, a fixed clock and fresh in-memory stores, so a crash input
//! reproduces exactly.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use kavach_domain::mandate::{
    AgentPassport, ConsentRecord, ContactWindow, DelegationRules, MandateTemplate, TimeZoneId,
};
use kavach_keys::InMemoryKeyProvider;
use kavach_mandate::jws::KeySet;
use kavach_mandate::memory::{InMemoryConsentSource, InMemoryEventBus, InMemoryMandateStore};
use kavach_mandate::{MandateConfig, MandateDeps, MandateService, SorIssuer};
use kavach_ports_testkit::{FakeClock, InMemoryReplayGuard};

pub const TENANT: &str = "nbfc-demo";
/// Seed of the key every target signs its inputs with.
pub const SIGNING_SEED: [u8; 32] = [7u8; 32];

/// One single-threaded runtime for the async APIs.
pub fn block_on<F: std::future::Future>(future: F) -> F::Output {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime")
        })
        .block_on(future)
}

/// Splits `header\npayload`. JCS never emits a raw newline (it escapes it
/// inside strings), so a canonical header cannot contain one.
#[must_use]
pub fn split_header_payload(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = data.iter().position(|b| *b == b'\n')?;
    Some((&data[..at], &data[at + 1..]))
}

/// A compact JWS over exactly these header and payload bytes, signed with
/// Ed25519 (`seed`): lets a target reach everything after the signature
/// check with bytes the fuzzer chose.
#[must_use]
pub fn sign_raw(seed: &[u8; 32], header: &[u8], payload: &[u8]) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = SigningKey::from_bytes(seed).sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(ToString::to_string).collect()
}

/// The time the mandate fixture's clock reads.
#[must_use]
pub fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 1, 5, 30, 0).unwrap()
}

pub type Service = MandateService<
    InMemoryKeyProvider,
    InMemoryReplayGuard,
    InMemoryConsentSource,
    InMemoryMandateStore,
    InMemoryEventBus,
    FakeClock,
>;

/// A mandate service as the system-of-record listener runs it: one
/// template (`loan.dpd30`), two passports, one consent, the `lms` system
/// signing with `SIGNING_SEED` as `lms-issuer-1`.
#[must_use]
pub fn mandate_service() -> Service {
    let mut kavach = InMemoryKeyProvider::new();
    let kavach_pub = kavach.insert_seed("kavach-mandate-1", [1u8; 32]).unwrap();
    let mut sor = InMemoryKeyProvider::new();
    let lms_pub = sor.insert_seed("lms-issuer-1", SIGNING_SEED).unwrap();
    let actions = set(&["read_fields", "send_reminder", "place_call"]);
    let fields = set(&["name", "overdue_amount", "emi_due_date", "loan_ref"]);
    let template = MandateTemplate {
        tenant_id: TENANT.into(),
        event_type: "loan.dpd30".into(),
        purpose: "loan_recovery".into(),
        actions: actions.clone(),
        data_fields: fields.clone(),
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
    };
    let passports = vec![
        AgentPassport {
            agent_id: "collections-agent".into(),
            tenant_id: TENANT.into(),
            owner: "collections-ops".into(),
            allowed_purposes: set(&["loan_recovery"]),
            actions,
            data_fields: fields,
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
    ];
    let consent = ConsentRecord {
        consent_id: "C-1".into(),
        tenant_id: TENANT.into(),
        subject_ref: "ref:borrower:B-9382".into(),
        purposes: set(&["loan_recovery"]),
        expires_at: t0() + chrono::Duration::days(30),
        active: true,
    };
    let config = MandateConfig {
        issuer_id: "kavach-dev".into(),
        signing_kid: "kavach-mandate-1".into(),
        mandate_keys: KeySet::new([kavach_pub]),
        sor_issuers: vec![SorIssuer {
            system: "lms".into(),
            key: lms_pub,
        }],
        templates: vec![template],
        passports,
        event_freshness_seconds: 300,
        replay_window_seconds: 24 * 3600,
    };
    MandateService::new(
        MandateDeps {
            keys: kavach,
            replay: InMemoryReplayGuard::new(),
            consents: InMemoryConsentSource::new([consent]),
            store: InMemoryMandateStore::new(),
            events: InMemoryEventBus::new(),
            clock: FakeClock::synced_at(t0()),
        },
        config,
    )
    .expect("valid mandate config")
}
