//! Evidence checkpoints in a running API (E2b, ADR-005 §13): the background
//! writer covers new records, a stall is visible without blocking
//! decisions, and startup refuses an unsafe checkpoint key.

mod agent_fixture;
mod contract;

use contract::router;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use kavach_api::{ApiConfig, AppState, EvidenceStoreKind};
use kavach_ports::agent_evidence::{AgentEvidenceStore, DevKeys, SegmentStart};
use kavach_ports::checkpoint::{
    verify_checkpoints, ChainSegment, CheckpointStore, Scope, CHAIN_AGENT_DECISIONS,
};
use kavach_ports::{KeyAlgorithm, PublicKey, SyncStatus};
use serde_json::Value;
use tower::ServiceExt;

use agent_fixture::*;

const SCOPE: Scope<'static> = Scope {
    tenant_id: "default",
    partition_id: 0,
    chain: CHAIN_AGENT_DECISIONS,
};

async fn get(state: &Arc<AppState>, path: &str) -> (StatusCode, String) {
    let response = router(state.clone())
        .oneshot(
            Request::get(path)
                .header("authorization", format!("Bearer {}", operator_token()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn runtime(state: &Arc<AppState>) -> Value {
    let (status, body) = get(state, "/v1/runtime").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_str(&body).unwrap()
}

/// Polls `/v1/runtime` until `done` holds (the writer ticks once a second).
async fn until(state: &Arc<AppState>, what: &str, done: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..150 {
        let view = runtime(state).await;
        if done(&view) {
            return view;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "timed out waiting for: {what}; last: {}",
        runtime(state).await
    );
}

fn with_checkpoints(interval: u64, stall: u64) -> ApiConfig {
    let mut api = config_for_gateway();
    let dp = api.dataplane.as_mut().unwrap();
    dp.checkpoint_interval_seconds = interval;
    dp.checkpoint_stall_seconds = stall;
    api
}

fn checkpoint_keys() -> BTreeMap<String, PublicKey> {
    BTreeMap::from([(
        "kavach-checkpoint-1".to_string(),
        PublicKey {
            kid: "kavach-checkpoint-1".into(),
            algorithm: KeyAlgorithm::Ed25519,
            bytes: SigningKey::from_bytes(&CHECKPOINT_SEED)
                .verifying_key()
                .to_bytes(),
        },
    )])
}

#[tokio::test(flavor = "multi_thread")]
async fn the_running_writer_covers_new_records_and_reports_it() {
    let gw = gateway_on(with_checkpoints(1, 600), Some(NUMBER), true).await;

    // Nothing to cover yet; the fields are present because agents are on.
    let view = runtime(&gw.state).await;
    assert_eq!(view["checkpoint_last_seq"], Value::Null, "{view}");
    assert_eq!(view["checkpoint_uncovered_records"], 0);
    assert_eq!(view["checkpoint_stalled"], false);
    assert!(view["checkpoint_lag_seconds"].as_u64().unwrap() < 600);

    let (status, reply) = gw.remind("ckpt-1").await;
    assert_eq!(
        (status, &reply["outcome"]),
        (StatusCode::OK, &"delivered".into()),
        "{reply}"
    );
    let (status, _) = gw.remind("ckpt-2").await;
    assert_eq!(status, StatusCode::OK);

    let store = gw.state.dataplane().unwrap().core().store().clone();
    let (head_seq, head_hash) = store.head(SCOPE).await.unwrap().expect("records");
    assert_eq!(head_seq, 2);
    until(&gw.state, "the head to be checkpointed", |view| {
        view["checkpoint_last_seq"] == head_seq && view["checkpoint_uncovered_records"] == 0
    })
    .await;

    // What the writer stored verifies with the checkpoint key alone.
    let checkpoints = store.list(SCOPE, 0, 100).await.unwrap();
    let last = checkpoints.last().expect("a checkpoint");
    assert_eq!(
        (last.payload.seq, &last.payload.head_hash),
        (head_seq, &head_hash)
    );
    assert_eq!(last.payload.key_id, "kavach-checkpoint-1");
    assert_eq!(last.payload.ts, gw.clock_now(), "dated by trusted time");
    let records = store.records("default", 0).await.unwrap();
    let segment = ChainSegment::of_records(SegmentStart::GENESIS, &records);
    let report = verify_checkpoints(
        &checkpoints,
        SCOPE,
        &segment,
        &checkpoint_keys(),
        DevKeys::Refuse,
    )
    .expect("checkpoints verify");
    assert_eq!(report.records_after_last, 0);

    // And it is counted.
    let mut metrics = String::new();
    for _ in 0..50 {
        metrics = get(&gw.state, "/metrics").await.1;
        if metrics.contains(&format!("kavach_checkpoint_last_seq {head_seq}")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        metrics.contains(&format!("kavach_checkpoint_last_seq {head_seq}")),
        "{metrics}"
    );
    assert!(metrics.contains("kavach_checkpoint_stalled 0"), "{metrics}");
    assert!(metrics.contains("kavach_checkpoint_uncovered_records 0"));
    assert!(
        !metrics.contains("kavach_checkpoints_written_total 0"),
        "{metrics}"
    );
    assert!(metrics.contains("kavach_checkpoint_last_covered_timestamp_seconds"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_writer_is_visible_and_blocks_nothing_it_does_not_own() {
    // Checkpoint after 3 seconds; stalled after 4.
    let gw = gateway_on(with_checkpoints(3, 4), Some(NUMBER), true).await;
    let (health_before, _) = get(&gw.state, "/health").await;

    let (status, reply) = gw.remind("stall-1").await;
    assert_eq!(
        (status, &reply["outcome"]),
        (StatusCode::OK, &"delivered".into()),
        "{reply}"
    );
    // Trusted time is lost before the checkpoint is due: none can be dated.
    gw.clock.set_sync(SyncStatus::Unsynced);

    let view = until(&gw.state, "the stall to show", |view| {
        view["checkpoint_stalled"] == true
    })
    .await;
    assert_eq!(view["checkpoint_uncovered_records"], 1, "{view}");
    assert_eq!(view["checkpoint_last_seq"], Value::Null);
    assert!(
        view["checkpoint_lag_seconds"].as_u64().unwrap() >= 4,
        "{view}"
    );
    let store = gw.state.dataplane().unwrap().core().store().clone();
    assert!(store.list(SCOPE, 0, 10).await.unwrap().is_empty());

    // Operator surfaces answer as before: the stall is information only.
    assert_eq!(get(&gw.state, "/health").await.0, health_before);
    // The stall can show a moment before the first due checkpoint is skipped.
    let skipped = r#"kavach_checkpoints_skipped_total{reason="time"}"#;
    let mut metrics = String::new();
    for _ in 0..50 {
        metrics = get(&gw.state, "/metrics").await.1;
        if metrics.contains(skipped) && metrics.contains("kavach_checkpoint_stalled 1") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(metrics.contains(skipped), "{metrics}");
    assert!(metrics.contains("kavach_checkpoint_stalled 1"), "{metrics}");

    // Time returns: the record is covered, the stall ends, and agents carry on.
    gw.clock.set_sync(SyncStatus::Synced { max_error_ms: 10 });
    let view = until(&gw.state, "the stall to end", |view| {
        view["checkpoint_stalled"] == false && view["checkpoint_last_seq"] == 1
    })
    .await;
    assert_eq!(view["checkpoint_uncovered_records"], 0, "{view}");
    let (status, reply) = gw.remind("stall-2").await;
    assert_eq!(
        (status, &reply["outcome"]),
        (StatusCode::OK, &"delivered".into()),
        "{reply}"
    );
}

#[tokio::test]
async fn startup_refuses_an_unsafe_checkpoint_key() {
    let refused = |api: ApiConfig| async move {
        format!(
            "{:?}",
            AppState::from_config(&api).await.err().expect("refused")
        )
    };
    let dev = |insecure: bool| {
        let mut api = config(EvidenceStoreKind::Memory, insecure, 50);
        api.dataplane.as_mut().unwrap().checkpoint_key_id = "dev-checkpoint-1".into();
        api
    };

    // A development key outside --insecure-dev, before anything else.
    let message = refused(dev(false)).await;
    assert!(
        message.contains("checkpoint key dev-checkpoint-1 is a development key"),
        "{message}"
    );
    // In the development profile it is allowed (here: but not present).
    let message = refused(dev(true)).await;
    assert!(message.contains("checkpoint key:"), "{message}");

    // An export key is the auditor's: never a key of the API, in any profile.
    for (insecure, kid) in [
        (true, "export-1"),
        (false, "export-1"),
        (true, "dev-export-1"),
    ] {
        let mut export = config(EvidenceStoreKind::Memory, insecure, 50);
        export.dataplane.as_mut().unwrap().checkpoint_key_id = kid.into();
        let message = refused(export).await;
        assert!(
            message.contains("named as an export key"),
            "{kid}: {message}"
        );
    }
    let mut export = config(EvidenceStoreKind::Memory, true, 50);
    export.dataplane.as_mut().unwrap().evidence_key_id = "export-evidence".into();
    let message = refused(export).await;
    assert!(
        message.contains("evidence key export-evidence"),
        "{message}"
    );

    // No key at all: there is no mode without checkpoints.
    let mut missing = config(EvidenceStoreKind::Memory, true, 50);
    missing.dataplane.as_mut().unwrap().checkpoint_key_id = "kavach-checkpoint-9".into();
    let message = refused(missing).await;
    assert!(message.contains("checkpoint key:"), "{message}");

    // The same key id as another key.
    for other in [
        "kavach-evidence-1",
        "kavach-mandate-1",
        "kavach-credential-1",
    ] {
        let mut shared = config(EvidenceStoreKind::Memory, true, 50);
        shared.dataplane.as_mut().unwrap().checkpoint_key_id = other.into();
        let message = refused(shared).await;
        assert!(
            message.contains("must be a separate key"),
            "{other}: {message}"
        );
    }
    // Another id, but the evidence key's material (seed 3 in the fixture).
    let mut copied = config(EvidenceStoreKind::Memory, true, 50);
    let dp = copied.dataplane.as_mut().unwrap();
    owner_only(
        &dp.checkpoint_keys_dir.join("kavach-checkpoint-2.ed25519"),
        &hex::encode([3u8; 32]),
    );
    dp.checkpoint_key_id = "kavach-checkpoint-2".into();
    let message = refused(copied).await;
    assert!(message.contains("same key material"), "{message}");

    // Timing that cannot work.
    for (interval, stall) in [(0, 600), (3601, 7200), (60, 60)] {
        let mut timing = config(EvidenceStoreKind::Memory, true, 50);
        let dp = timing.dataplane.as_mut().unwrap();
        dp.checkpoint_interval_seconds = interval;
        dp.checkpoint_stall_seconds = stall;
        let message = refused(timing).await;
        assert!(
            message.contains("checkpoint interval"),
            "{interval}/{stall}: {message}"
        );
    }
}
