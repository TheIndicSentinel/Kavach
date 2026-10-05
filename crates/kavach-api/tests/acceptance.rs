//! The PRD acceptance scenarios (H5b step 9) through the real stack: the
//! agent listener over HTTP → gateway → authorization core and evidence →
//! resolver → credential broker → the real mock provider on loopback.
//!
//! Each scenario runs on the in-memory stores and on Postgres (as the
//! least-privilege runtime role; skipped without `KAVACH_TEST_DATABASE_URL`).
//! A scenario this slice cannot fully prove carries `partial` in its name,
//! and docs/ACCEPTANCE.md says exactly what remains, so a green run is never
//! read as more than it is.

mod agent_fixture;

use std::collections::{BTreeMap, BTreeSet};

use axum::http::StatusCode;
use chrono::Duration;
use kavach_api::dataplane::agent_router;
use kavach_api::EvidenceStoreKind;
use kavach_domain::mandate::{DelegationRequest, RevocationReason};
use kavach_evidence_cli::postgres::{run_export, Signing, Target};
use kavach_evidence_cli::verify::{verify_dir, Verdict, VerifyRequest};
use kavach_evidence_cli::writer::BundleWriter;
use kavach_ports::agent_evidence::{AgentEvidenceStore, Outcome, SegmentStart};
use kavach_ports::bundle::Exporter;
use kavach_ports::checkpoint::{CheckpointStore, Scope, CHAIN_AGENT_DECISIONS};
use kavach_ports::{SyncStatus, TimeSource};
use serde_json::{json, Value};

use agent_fixture::*;

const SCENARIO_SCOPE: Scope<'static> = Scope {
    tenant_id: "default",
    partition_id: 0,
    chain: CHAIN_AGENT_DECISIONS,
};

#[derive(Clone, Copy)]
enum Store {
    Memory,
    Postgres,
}

/// The stack for one scenario, or `None` (Postgres without a database).
async fn world(store: Store, destination: Option<&str>, provider_up: bool) -> Option<Gw> {
    Some(world_and_database(store, destination, provider_up).await?.0)
}

/// [`world`], with the owner's database URL when the store is Postgres.
async fn world_and_database(
    store: Store,
    destination: Option<&str>,
    provider_up: bool,
) -> Option<(Gw, Option<String>)> {
    let (api, owner) = match store {
        Store::Memory => (config_for_gateway(), None),
        Store::Postgres => {
            let (owner, runtime) = kavach_storage::testing::isolated_database_urls().await?;
            let mut api = config(
                EvidenceStoreKind::Postgres {
                    database_url: runtime,
                },
                true,
                50,
            );
            api.migration_database_url = Some(owner.clone());
            (api, Some(owner))
        }
    };
    Some((gateway_on(api, destination, provider_up).await, owner))
}

/// Runs a scenario on both evidence stores, as `<scenario>::memory` and
/// `<scenario>::postgres`.
macro_rules! on_both_stores {
    ($($scenario:ident),* $(,)?) => {$(
        mod $scenario {
            #[tokio::test(flavor = "multi_thread")]
            async fn memory() {
                super::$scenario(super::Store::Memory).await;
            }
            #[tokio::test(flavor = "multi_thread")]
            async fn postgres() {
                super::$scenario(super::Store::Postgres).await;
            }
        }
    )*};
}

on_both_stores!(
    scenario01_reminder_is_delivered_once_with_minimal_disclosure,
    scenario02_partial_raw_phone_number_is_blocked_and_recorded,
    scenario03_contact_window_boundaries_and_daily_cap,
    scenario04_partial_fields_outside_the_mandate_are_blocked,
    scenario05_another_borrower_is_blocked_without_a_human,
    scenario06_partial_large_waiver_needs_human_review,
    scenario07_partial_delegated_sub_agent_cannot_exceed_its_mandate,
    scenario08_partial_revoked_mandate_blocks_the_next_call,
    scenario09_partial_unregistered_tool_is_refused,
    scenario10_a_full_run_verifies_offline_from_public_keys,
    scenario11_partial_bypass_attempts_fail,
    scenario12_partial_unavailable_dependencies_fail_safe,
    catalog_attacks_are_refused,
);

fn at(gw: &Gw, ist_hour: i64, minutes: i64, seconds: i64) {
    let target = ist_today(ist_hour) + Duration::minutes(minutes) + Duration::seconds(seconds);
    gw.clock.advance(target - gw.clock.now().utc);
}

fn decision(reply: &Value) -> &str {
    reply["decision"].as_str().unwrap_or("none")
}

/// A pre-check (`/v1/authorize`), for tools the gateway does not execute yet.
async fn precheck(gw: &Gw, body: Value) -> (StatusCode, Value) {
    send(
        agent_router(gw.state.clone()),
        "/v1/authorize",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        body,
    )
    .await
}

async fn record_for(gw: &Gw, agent: &str, request_id: &str) -> Option<Value> {
    let record = gw
        .state
        .dataplane()
        .unwrap()
        .core()
        .store()
        .get_by_request("default", agent, request_id)
        .await
        .unwrap()?;
    Some(serde_json::to_value(record).unwrap())
}

/// Scenario 1: Reminder to B-9382 at 11:00 IST → PASS; a request-bound credential is
/// injected; the agent sees neither destination nor credential; delivered
/// exactly once.
async fn scenario01_reminder_is_delivered_once_with_minimal_disclosure(store: Store) {
    let Some(gw) = world(store, Some(NUMBER), true).await else {
        return;
    };
    let (status, reply) = gw.remind("s1").await;
    assert_eq!(
        (status, decision(&reply)),
        (StatusCode::OK, "PASS"),
        "{reply}"
    );
    assert_eq!(reply["outcome"], "delivered");
    assert_eq!(gw.provider.inbox().len(), 1);
    assert_eq!(gw.provider.inbox()[0].destination.expose(), NUMBER);
    let (_, again) = gw.remind("s1").await;
    assert_eq!(again["replayed"], true);
    assert_eq!(gw.provider.inbox().len(), 1, "exactly once");
    assert_eq!(
        gw.stored_outcome("s1").await,
        Some((Outcome::Delivered, Some("provider_202".into())))
    );
}

/// Scenario 2 (partial): A raw phone number where a reference belongs → BLOCK,
/// recorded by reason only (no parameter MAC, never the value), nothing
/// resolved or sent. Remaining: taint tracking of the injected reply (M3).
async fn scenario02_partial_raw_phone_number_is_blocked_and_recorded(store: Store) {
    let Some(gw) = world(store, Some(NUMBER), true).await else {
        return;
    };
    let mut body = reminder(&gw.mandate, "s2");
    body["params"]["subject_ref"] = json!("+91 98765 43210");
    let (status, reply) = gw.call("send_reminder", body).await;
    assert_eq!(
        (status, decision(&reply)),
        (StatusCode::OK, "BLOCK"),
        "{reply}"
    );
    assert!(reply.get("outcome").is_none());
    let record = record_for(&gw, "collections-agent", "s2")
        .await
        .expect("recorded");
    let text = record.to_string();
    assert!(text.contains("reference_only_violation"), "{text}");
    assert!(record["payload"]["params_mac"].is_null());
    assert!(!text.contains("98765"), "{text}");
    assert!(gw.provider.inbox().is_empty());
}

/// Scenario 3: Outside 08:00–19:00 IST, or a 4th contact in a day → BLOCK, with the
/// NFR-7 boundaries exact.
async fn scenario03_contact_window_boundaries_and_daily_cap(store: Store) {
    let Some(gw) = world(store, Some(NUMBER), true).await else {
        return;
    };
    // The next day: the mandate (issued today at 11:00) is valid all day,
    // and the daily cap starts from zero.
    let tomorrow = |h: i64, m: i64, sec: i64| {
        let target =
            ist_today(h) + Duration::days(1) + Duration::minutes(m) + Duration::seconds(sec);
        gw.clock.advance(target - gw.clock.now().utc);
    };
    let window = ["contact-window", "contact-hours-floor"];
    let cap = ["contact-daily-cap", "contact_cap_reached"];
    let check = |(status, reply): (StatusCode, Value), want: &str, because: &[&str]| {
        assert_eq!(
            (status, decision(&reply)),
            (StatusCode::OK, want),
            "{reply}"
        );
        let reasons = reply["reasons"].to_string();
        assert!(!reasons.contains("mandate_invalid"), "{reply}");
        if !because.is_empty() {
            assert!(because.iter().any(|r| reasons.contains(r)), "{reply}");
        }
    };
    tomorrow(7, 59, 59);
    check(gw.remind("s3-0759").await, "BLOCK", &window);
    tomorrow(8, 0, 0);
    check(gw.remind("s3-0800").await, "PASS", &[]);
    tomorrow(11, 0, 0);
    check(gw.remind("s3-1100").await, "PASS", &[]);
    tomorrow(18, 59, 0);
    check(gw.remind("s3-1859").await, "PASS", &[]);
    // The cap (3 a day) is reached: a 4th contact is refused at any hour.
    tomorrow(12, 0, 0);
    check(gw.remind("s3-fourth").await, "BLOCK", &cap);
    tomorrow(19, 0, 0);
    check(gw.remind("s3-1900").await, "BLOCK", &[]);
    tomorrow(19, 45, 0);
    check(gw.remind("s3-1945").await, "BLOCK", &[]);
    assert_eq!(gw.provider.inbox().len(), 3);
}

/// Scenario 4 (partial): Fields outside the tool's allowlist, or allowed by the tool
/// but outside the mandate, → BLOCK; fields within the mandate → PASS.
/// Pre-check only: the gateway does not execute `read_fields` yet, and the
/// masking obligation for mixed requests is not built (mock LMS slice).
async fn scenario04_partial_fields_outside_the_mandate_are_blocked(store: Store) {
    let Some(gw) = world(store, Some(NUMBER), true).await else {
        return;
    };
    let read = |request_id: &str, fields: &[&str]| {
        json!({ "tool": "read_fields", "mandate_id": gw.mandate, "request_id": request_id,
                "params": { "subject_ref": SUBJECT, "requested_fields": fields } })
    };
    let (_, reply) = precheck(&gw, read("s4-salary", &["name", "salary"])).await;
    assert_eq!(
        decision(&reply),
        "BLOCK",
        "salary is not a registry field: {reply}"
    );
    let (_, reply) = precheck(&gw, read("s4-due", &["emi_due_date"])).await;
    assert_eq!(
        decision(&reply),
        "BLOCK",
        "allowed by the tool, not the mandate: {reply}"
    );
    let (_, reply) = precheck(&gw, read("s4-ok", &["name", "overdue_amount"])).await;
    assert_eq!(decision(&reply), "PASS", "{reply}");
}

/// Scenario 5: A contact to another borrower under B-9382's mandate → BLOCK with no
/// human involved; recorded; nothing resolved or sent.
async fn scenario05_another_borrower_is_blocked_without_a_human(store: Store) {
    let Some(gw) = world(store, Some(NUMBER), true).await else {
        return;
    };
    let mut body = reminder(&gw.mandate, "s5");
    body["params"]["subject_ref"] = json!("ref:borrower:B-5511");
    let (status, reply) = gw.call("send_reminder", body).await;
    assert_eq!(
        (status, decision(&reply)),
        (StatusCode::OK, "BLOCK"),
        "{reply}"
    );
    assert!(
        reply["reasons"].to_string().contains("subject-binding"),
        "blocked by the subject binding, not something else: {reply}"
    );
    assert!(record_for(&gw, "collections-agent", "s5").await.is_some());
    assert!(gw.provider.inbox().is_empty());
}

/// Scenario 6 (partial): A 35% waiver against a 10% ceiling → HUMAN_REVIEW; 5% →
/// PASS. Pre-check only; WebAuthn step-up and approvals bound to the action
/// hash are M4.
async fn scenario06_partial_large_waiver_needs_human_review(store: Store) {
    let Some(gw) = world(store, Some(NUMBER), true).await else {
        return;
    };
    let plan = |request_id: &str, bps: i64| {
        json!({ "tool": "propose_plan", "mandate_id": gw.mandate, "request_id": request_id,
                "params": { "subject_ref": SUBJECT, "waiver_bps": bps } })
    };
    let (_, reply) = precheck(&gw, plan("s6-35", 3500)).await;
    assert_eq!(decision(&reply), "HUMAN_REVIEW", "{reply}");
    let (_, reply) = precheck(&gw, plan("s6-5", 500)).await;
    assert_eq!(decision(&reply), "PASS", "{reply}");
}

/// Scenario 7 (partial): A translation sub-agent with a delegated read-only mandate
/// cannot send a reminder (BLOCK, recorded), and the parent agent cannot use
/// the child's mandate. Remaining: the translation-agent demo and
/// `update_status` (C).
async fn scenario07_partial_delegated_sub_agent_cannot_exceed_its_mandate(store: Store) {
    let Some(gw) = world(store, Some(NUMBER), true).await else {
        return;
    };
    let child = gw
        .state
        .dataplane()
        .unwrap()
        .mandates()
        .delegate(
            "default",
            &gw.mandate,
            "collections-agent",
            "translation-agent",
            &DelegationRequest {
                actions: BTreeSet::from(["read_fields".to_string()]),
                data_fields: BTreeSet::from(["name".to_string()]),
                channels: BTreeSet::new(),
                window: None,
                ceilings: BTreeMap::new(),
                exp: None,
                allowed_agents: BTreeSet::new(),
            },
        )
        .await
        .expect("delegation within the parent")
        .mandate
        .id;
    let as_agent = |agent: &'static str, body: Value| {
        let gw = &gw;
        async move {
            send(
                agent_router(gw.state.clone()),
                "/v1/tools/send_reminder",
                &[("authorization", format!("Bearer {}", agent_token(agent)))],
                body,
            )
            .await
        }
    };
    let (_, reply) = as_agent("translation-agent", reminder(&child, "s7-sub")).await;
    assert_eq!(decision(&reply), "BLOCK", "{reply}");
    assert!(record_for(&gw, "translation-agent", "s7-sub")
        .await
        .is_some());
    let (_, reply) = as_agent("collections-agent", reminder(&child, "s7-parent")).await;
    assert_eq!(decision(&reply), "BLOCK", "not the holder: {reply}");
    assert!(gw.provider.inbox().is_empty());
}

/// Scenario 8 (partial): A dispute revokes the mandate → the next call is BLOCK.
/// Remaining: event-driven revocation from the system of record (outbox)
/// and refusing an in-flight credential before its 15 s expiry (B).
async fn scenario08_partial_revoked_mandate_blocks_the_next_call(store: Store) {
    let Some(gw) = world(store, Some(NUMBER), true).await else {
        return;
    };
    let (_, reply) = gw.remind("s8-before").await;
    assert_eq!(reply["outcome"], "delivered", "{reply}");
    gw.state
        .dataplane()
        .unwrap()
        .mandates()
        .revoke("default", &gw.mandate, RevocationReason::Dispute)
        .await
        .expect("revoked");
    let (status, reply) = gw.remind("s8-after").await;
    assert_eq!(
        (status, decision(&reply)),
        (StatusCode::OK, "BLOCK"),
        "{reply}"
    );
    assert!(
        reply["reasons"].to_string().contains("mandate_invalid"),
        "{reply}"
    );
    assert_eq!(gw.provider.inbox().len(), 1);
}

/// Scenario 9 (partial): An unregistered tool is refused (400, counted, nothing
/// recorded); a changed registry is refused at startup (see
/// `startup_refuses_unsigned_tampered_or_unpinned_tool_registries`).
/// Remaining: the RESTRICTED agent state and an alert (M3).
async fn scenario09_partial_unregistered_tool_is_refused(store: Store) {
    let Some(gw) = world(store, Some(NUMBER), true).await else {
        return;
    };
    let (status, _) = gw.call("wire_money", reminder(&gw.mandate, "s9")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(record_for(&gw, "collections-agent", "s9").await.is_none());
    let metrics = gw.state.metrics().gather_text().unwrap();
    assert!(
        metrics.contains("kavach_gateway_malformed_total 1"),
        "{metrics}"
    );
}

const EXPORT_KID: &str = "export-s10-1";

/// Creates `work` with what an auditor holds: an export key
/// (`export-keys/`), the trusted public keys and the kept checkpoint.
/// Returns the paths of the last two.
fn auditor_material(
    work: &std::path::Path,
    kept_checkpoint: &kavach_ports::checkpoint::Checkpoint,
) -> (std::path::PathBuf, std::path::PathBuf) {
    std::fs::create_dir(work).unwrap();
    let export_public = kavach_keys::LocalFileKeyProvider::new(work.join("export-keys"))
        .create_key(EXPORT_KID)
        .unwrap();
    let public = |seed: [u8; 32]| {
        hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        )
    };
    let keys = work.join("trusted-keys.json");
    std::fs::write(
        &keys,
        json!({ "keys": [
            { "kid": "kavach-evidence-1", "alg": "Ed25519", "public_key": public([3u8; 32]) },
            { "kid": "kavach-checkpoint-1", "alg": "Ed25519",
              "public_key": public(CHECKPOINT_SEED) },
            { "kid": EXPORT_KID, "alg": "Ed25519",
              "public_key": hex::encode(export_public.bytes) },
        ]})
        .to_string(),
    )
    .unwrap();
    let kept = work.join("kept-checkpoint.json");
    std::fs::write(&kept, serde_json::to_string(kept_checkpoint).unwrap()).unwrap();
    (keys, kept)
}

/// The memory store has no export command: write the same bundle from the
/// store, signed with the auditor's export key.
async fn export_from_memory(gw: &Gw, work: &std::path::Path, bundle: &std::path::Path) {
    let core = gw.state.dataplane().unwrap().core();
    let records = core.store().records("default", 0).await.unwrap();
    let mut writer = BundleWriter::create(bundle, SCENARIO_SCOPE, SegmentStart::GENESIS).unwrap();
    for record in &records {
        writer.record(record).unwrap();
    }
    for record in records.iter().filter(|r| r.is_allow()) {
        let id = record.payload.credential_id.as_deref().unwrap();
        let outcome = core
            .outcome(id)
            .await
            .unwrap()
            .expect("an outcome per allow");
        writer.outcome(&outcome).unwrap();
    }
    for checkpoint in core.store().list(SCENARIO_SCOPE, 0, 100).await.unwrap() {
        writer.checkpoint(&checkpoint).unwrap();
    }
    let signer =
        kavach_keys::Ed25519EvidenceSigner::from_key_dir(&work.join("export-keys"), EXPORT_KID)
            .unwrap();
    let exporter = Exporter {
        tool: "kavach-evidence".into(),
        version: "test".into(),
    };
    writer
        .finish(chrono::Utc::now(), exporter, Some(&signer))
        .unwrap();
}

/// Any change to the exported evidence fails verification; restored, it
/// verifies again.
fn changes_to_the_bundle_are_caught(request: &VerifyRequest<'_>, bundle: &std::path::Path) {
    let records_file = bundle.join("records.jsonl");
    let original = std::fs::read_to_string(&records_file).unwrap();
    std::fs::write(
        &records_file,
        original.replacen("send_reminder", "place_call", 1),
    )
    .unwrap();
    assert!(verify_dir(request).is_err(), "an edited record");
    // The newest record removed: the kept checkpoint is ahead of the chain.
    let mut lines: Vec<&str> = original.lines().collect();
    lines.pop();
    std::fs::write(&records_file, lines.join("\n") + "\n").unwrap();
    assert!(verify_dir(request).is_err(), "a removed record");
    std::fs::write(&records_file, &original).unwrap();
    let outcomes_file = bundle.join("outcomes.jsonl");
    let outcomes = std::fs::read_to_string(&outcomes_file).unwrap();
    std::fs::write(&outcomes_file, outcomes.replacen("delivered", "failed", 1)).unwrap();
    assert!(verify_dir(request).is_err(), "a rewritten outcome");
    std::fs::write(&outcomes_file, &outcomes).unwrap();
    assert!(verify_dir(request).is_ok(), "restored, it verifies again");
}

/// Scenario 10: The evidence of a full run is exported as a bundle and
/// verified offline with only public keys the operator supplies: a signed
/// manifest, an unbroken signed chain, a valid outcome for every allow, a
/// checkpoint over the head that matches the one kept off-host, and
/// nothing left unprotected. On Postgres the export is the real command's,
/// as the read-only auditor role. Any change to the bundle is caught.
/// Remaining: crypto-shredding (B).
async fn scenario10_a_full_run_verifies_offline_from_public_keys(store: Store) {
    let Some((gw, owner)) = world_and_database(store, Some(NUMBER), true).await else {
        return;
    };
    gw.remind("s10-a").await;
    gw.remind("s10-a").await; // replay: no new record
    gw.remind("s10-b").await;
    let mut other = reminder(&gw.mandate, "s10-c");
    other["params"]["subject_ref"] = json!("ref:borrower:B-5511");
    gw.call("send_reminder", other).await; // a recorded BLOCK
    at(&gw, 20, 0, 0);
    gw.remind("s10-late").await; // a recorded BLOCK

    // The deployment checkpoints its chain; the operator keeps the newest
    // checkpoint off-host.
    let dataplane = gw.state.dataplane().unwrap();
    // (Two steps of the writer: it sees the uncovered records, and a
    // minute later they are due.)
    let seen = std::time::Instant::now();
    dataplane.checkpointer().tick(seen).await;
    let due = seen + std::time::Duration::from_secs(61);
    let written = dataplane.checkpointer().tick(due).await.tick;
    assert_eq!(written, kavach_dataplane::Tick::Written { seq: 4 });
    let store_ref = dataplane.core().store().clone();
    let kept_checkpoint = store_ref
        .latest(SCENARIO_SCOPE)
        .await
        .unwrap()
        .expect("a checkpoint");
    assert_eq!(kept_checkpoint.payload.seq, 4);

    // What the auditor holds: an export key, the public keys, the kept
    // checkpoint. None of it comes from the bundle.
    let work = std::env::temp_dir().join(format!("kavach-s10-{}", uuid::Uuid::new_v4().simple()));
    let (keys, kept) = auditor_material(&work, &kept_checkpoint);

    // Export: on Postgres the real command's export, as the read-only
    // auditor role; in memory the same bundle, written from the store.
    let bundle = work.join("bundle");
    if let Some(owner) = &owner {
        let target = Target {
            database_url: kavach_storage::testing::auditor_url(owner),
            tenant_id: "default".into(),
            partition_id: 0,
            allow_write_role: false,
            tls: kavach_storage::DatabaseTls::development(),
        };
        let signing = Signing::Key {
            key_dir: work.join("export-keys"),
            key_id: EXPORT_KID.into(),
        };
        run_export(&target, None, &bundle, &signing)
            .await
            .expect("export");
    } else {
        export_from_memory(&gw, &work, &bundle).await;
    }

    // Offline: the bundle, the operator's keys and the kept checkpoint.
    let request = VerifyRequest {
        bundle: &bundle,
        keys: &keys,
        expect_checkpoint: Some(&kept),
        dev: false,
        now: gw.clock.now().utc + Duration::hours(1),
    };
    let report = verify_dir(&request).expect("the bundle verifies");
    assert_eq!(
        report.records, 4,
        "two deliveries and two refusals, no duplicate for the replay"
    );
    assert_eq!((report.outcomes, report.checkpoints), (2, 1));
    assert_eq!(report.kept_checkpoint, Some(4));
    assert_eq!(report.not_protected(), [], "nothing is left unprotected");
    let verdict = Verdict {
        result: Ok(report),
        allow_warnings: false,
        bundle: bundle.clone(),
    };
    assert_eq!(verdict.exit_code(), 0);

    changes_to_the_bundle_are_caught(&request, &bundle);

    std::fs::remove_dir_all(&work).unwrap();
}

/// Scenario 11 (partial): Bypass attempts fail: a forged mandate id, a replayed
/// system-of-record event (no second mandate), an agent-supplied timestamp,
/// an operator token on the agent route. Expired and replayed credentials
/// are refused by the provider (`kavach-mock-provider` tests). Remaining:
/// direct backend calls, secret search and alternate endpoints (H5b-2).
async fn scenario11_partial_bypass_attempts_fail(store: Store) {
    let Some(gw) = world(store, Some(NUMBER), true).await else {
        return;
    };
    let (_, reply) = gw
        .call("send_reminder", reminder("ma-forged", "s11-forged"))
        .await;
    assert_eq!(decision(&reply), "BLOCK", "{reply}");

    // The same signed event again (identical content): 200 with the
    // existing mandate, never a second one.
    let (status, replayed) = send(
        kavach_api::dataplane::sor_router(gw.state.clone()),
        "/v1/sor/events",
        &[],
        json!({ "event": event_at("evt-gw", "lms:loan/L-1", gw.clock.now().utc).await }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replayed}");
    assert_eq!(replayed["mandate_id"], gw.mandate.as_str());
    assert_eq!(replayed["replayed"], true);

    let mut body = reminder(&gw.mandate, "s11-ts");
    body["params"]["timestamp"] = json!("2026-10-01T05:30:00Z");
    assert_eq!(
        gw.call("send_reminder", body).await.0,
        StatusCode::BAD_REQUEST
    );

    let (status, _) = send(
        agent_router(gw.state.clone()),
        "/v1/tools/send_reminder",
        &[("authorization", format!("Bearer {}", operator_token()))],
        reminder(&gw.mandate, "s11-op"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(gw.provider.inbox().is_empty());
}

/// Scenario 12 (partial): Trusted time unavailable → BLOCK before anything is sent;
/// a provider that is down → `failed`, never `delivered`. Evidence-store
/// failure is covered by the store contract
/// (`nothing_is_kept_when_signing_fails`). Remaining: OpenBao and Keycloak
/// outages (Stage 2 adapters).
async fn scenario12_partial_unavailable_dependencies_fail_safe(store: Store) {
    let Some(gw) = world(store, Some(NUMBER), true).await else {
        return;
    };
    gw.clock.set_sync(SyncStatus::Unsynced);
    let (status, reply) = gw.remind("s12-time").await;
    assert_eq!(
        (status, decision(&reply)),
        (StatusCode::OK, "BLOCK"),
        "{reply}"
    );
    assert!(
        reply["reasons"]
            .to_string()
            .contains("trusted_time_unavailable"),
        "{reply}"
    );
    assert!(gw.provider.inbox().is_empty());

    let Some(down) = world(store, Some(NUMBER), false).await else {
        return;
    };
    let (_, reply) = down.remind("s12-down").await;
    assert_eq!(
        (reply["outcome"].as_str(), reply["outcome_reason"].as_str()),
        (Some("failed"), Some("connect_failed"))
    );
}

/// The attack catalog `kavach attack` runs (`kavach-attacks`), in process:
/// every attack is refused as the catalog expects, and ground truth agrees
/// (no credential minted, nothing delivered). Covered by the 20× gate.
async fn catalog_attacks_are_refused(store: Store) {
    let Some(gw) = world(store, Some(NUMBER), true).await else {
        return;
    };
    let report = kavach_attacks::run(&InProcess(&gw), &kavach_attacks::CATALOG).await;
    for outcome in &report.outcomes {
        assert_eq!(
            outcome.verdict,
            kavach_attacks::Verdict::Refused,
            "{}: {}",
            outcome.id,
            outcome.observed
        );
    }
    assert_eq!(report.credentials_minted, 0);
    assert_eq!(report.messages_delivered, 0);
    assert!(report.all_refused_as_expected());
    // Only the daily-cap attack's declared setup reached the provider.
    assert_eq!(report.setup_credentials, 3);
    assert_eq!(report.setup_messages, 3);
    assert_eq!(gw.provider.inbox().len(), 3);
}

/// The acceptance world as an attack target.
struct InProcess<'a>(&'a Gw);

impl kavach_attacks::Target for InProcess<'_> {
    fn agent_token(&self) -> String {
        agent_token("collections-agent")
    }

    fn other_agent_token(&self) -> String {
        agent_token("translation-agent")
    }

    fn operator_token(&self) -> String {
        operator_token()
    }

    fn mandate(&self) -> String {
        self.0.mandate.clone()
    }

    async fn post_agent(
        &self,
        path: &str,
        headers: Vec<(String, String)>,
        body: Value,
    ) -> Result<(u16, Value), String> {
        let headers: Vec<(&str, String)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        let (status, reply) = send(agent_router(self.0.state.clone()), path, &headers, body).await;
        Ok((status.as_u16(), reply))
    }

    async fn get_operator(
        &self,
        path: &str,
        headers: Vec<(String, String)>,
    ) -> Result<u16, String> {
        let mut request = axum::http::Request::get(path);
        for (k, v) in headers {
            request = request.header(k, v);
        }
        let response = tower::ServiceExt::oneshot(
            kavach_api::router(self.0.state.clone()),
            request.body(axum::body::Body::empty()).unwrap(),
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok(response.status().as_u16())
    }

    async fn replay_sor_event(&self) -> Result<(u16, Value), String> {
        // The issuing event, identical (the test clock has not moved).
        let event = event_at("evt-gw", "lms:loan/L-1", self.0.clock.now().utc).await;
        let (status, reply) = send(
            kavach_api::dataplane::sor_router(self.0.state.clone()),
            "/v1/sor/events",
            &[],
            json!({ "event": event }),
        )
        .await;
        Ok((status.as_u16(), reply))
    }

    async fn post_provider(&self) -> Result<u16, String> {
        let response = reqwest::Client::new()
            .post(format!("{}/v1/messages", self.0.provider_url))
            .json(&json!({ "to": "ref:borrower:B-9382", "template_id": "emi_reminder_v1" }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        Ok(response.status().as_u16())
    }

    fn delivered(&self) -> impl std::future::Future<Output = Result<usize, String>> {
        std::future::ready(Ok(self.0.provider.inbox().len()))
    }

    async fn allowed(&self) -> Result<u64, String> {
        let response = tower::ServiceExt::oneshot(
            kavach_api::router(self.0.state.clone()),
            axum::http::Request::get("/metrics")
                .header("authorization", format!("Bearer {}", operator_token()))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .map_err(|e| e.to_string())?;
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();
        Ok(kavach_attacks::allowed_calls(&String::from_utf8_lossy(
            &bytes,
        )))
    }

    fn pause(&self) -> impl std::future::Future<Output = ()> {
        std::future::ready(())
    }

    fn clock_control(&self) -> bool {
        true
    }

    fn move_clock(
        &self,
        hour: u32,
        minute: u32,
        fresh_day: bool,
    ) -> impl std::future::Future<Output = Result<(), String>> {
        let now = self.0.clock.now().utc;
        let to = next_ist(now, hour, minute, fresh_day);
        self.0.clock.advance(to - now);
        std::future::ready(Ok(()))
    }
}

/// The next `hour:minute` IST after `after`; with `fresh_day`, on a later
/// IST date than `after`'s.
fn next_ist(
    after: chrono::DateTime<chrono::Utc>,
    hour: u32,
    minute: u32,
    fresh_day: bool,
) -> chrono::DateTime<chrono::Utc> {
    use chrono::TimeZone;
    let ist = chrono::FixedOffset::east_opt(5 * 3600 + 1800).unwrap();
    let today = after.with_timezone(&ist).date_naive();
    let mut day = if fresh_day {
        today.succ_opt().unwrap()
    } else {
        today
    };
    loop {
        let t = ist
            .from_local_datetime(&day.and_hms_opt(hour, minute, 0).unwrap())
            .single()
            .unwrap()
            .with_timezone(&chrono::Utc);
        if t > after {
            return t;
        }
        day = day.succ_opt().unwrap();
    }
}
