//! No raw destination or subject reference in an evidence bundle (E3a,
//! ADR-005 §13). A bundle leaves the deployment, so this test fails if a
//! phone number or a raw reference ever reaches one: through a record, an
//! outcome, a checkpoint or the manifest.

mod agent_fixture;
mod contract;

use std::time::Duration;

use axum::http::StatusCode;
use kavach_evidence_cli::writer::BundleWriter;
use kavach_keys::Ed25519EvidenceSigner;
use kavach_ports::agent_evidence::{AgentEvidenceStore, SegmentStart};
use kavach_ports::bundle::Exporter;
use kavach_ports::checkpoint::{CheckpointStore, Scope, CHAIN_AGENT_DECISIONS};
use serde_json::json;

use agent_fixture::*;

const SCOPE: Scope<'static> = Scope {
    tenant_id: "default",
    partition_id: 0,
    chain: CHAIN_AGENT_DECISIONS,
};
const OTHER_SUBJECT: &str = "ref:borrower:B-5511";

/// What must never appear, and why it would be personal data.
fn leak(text: &str) -> Option<String> {
    let needles = [
        (NUMBER, "the destination"),
        (NUMBER.trim_start_matches('+'), "the destination's digits"),
        (SUBJECT, "the subject reference"),
        (OTHER_SUBJECT, "another subject's reference"),
        ("ref:borrower", "a raw borrower reference"),
        ("B-9382", "the borrower id"),
        ("B-5511", "another borrower id"),
    ];
    for (needle, what) in needles {
        if text.contains(needle) {
            return Some(format!("{what} ({needle})"));
        }
    }
    // Anything shaped like a phone number: `+` and eight or more digits.
    let bytes = text.as_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        if *byte == b'+' {
            let digits = bytes[i + 1..]
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .count();
            if digits >= 8 {
                return Some(format!("a phone-number-like value at byte {i}"));
            }
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bundle_of_a_real_run_holds_no_destination_and_no_raw_reference() {
    // The scan itself catches what it is meant to catch.
    assert!(leak(&format!(r#"{{"to":"{NUMBER}"}}"#)).is_some());
    assert!(leak(&format!(r#"{{"subject":"{SUBJECT}"}}"#)).is_some());
    assert!(leak(r#"{"to":"+14155550100"}"#).is_some());
    assert!(leak(r#"{"ts":"2026-10-02T05:30:00Z","n":12345678}"#).is_none());

    let mut api = config_for_gateway();
    api.dataplane.as_mut().unwrap().checkpoint_interval_seconds = 1;
    let gw = gateway_on(api, Some(NUMBER), true).await;

    // A delivery (the provider really receives the number)…
    let (status, reply) = gw.remind("priv-1").await;
    assert_eq!(
        (status, &reply["outcome"]),
        (StatusCode::OK, &"delivered".into()),
        "{reply}"
    );
    // …a raw phone number where only a reference is allowed (recorded BLOCK)…
    let mut raw = reminder(&gw.mandate, "priv-2");
    raw["params"]["subject_ref"] = json!(NUMBER);
    let (status, reply) = gw.call("send_reminder", raw).await;
    assert_eq!(
        (status, &reply["decision"]),
        (StatusCode::OK, &"BLOCK".into()),
        "{reply}"
    );
    // …and a borrower this agent has no mandate for (recorded BLOCK).
    let mut other = reminder(&gw.mandate, "priv-3");
    other["params"]["subject_ref"] = json!(OTHER_SUBJECT);
    let (status, reply) = gw.call("send_reminder", other).await;
    assert_eq!(
        (status, &reply["decision"]),
        (StatusCode::OK, &"BLOCK".into()),
        "{reply}"
    );

    // Wait for the writer to checkpoint the head, so the bundle has one.
    let core = gw.state.dataplane().unwrap().core();
    let store = core.store().clone();
    let records = store.records("default", 0).await.unwrap();
    assert_eq!(records.len(), 3, "every call above is on the chain");
    for _ in 0..150 {
        if store
            .latest(SCOPE)
            .await
            .unwrap()
            .is_some_and(|c| c.payload.seq == 3)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let checkpoints = store.list(SCOPE, 0, 100).await.unwrap();
    assert!(!checkpoints.is_empty(), "a checkpoint to export");

    // Export it as the export command will: through the bundle writer.
    let out =
        std::env::temp_dir().join(format!("kavach-privacy-{}", uuid::Uuid::new_v4().simple()));
    let mut writer = BundleWriter::create(&out, SCOPE, SegmentStart::GENESIS).unwrap();
    let mut outcomes = 0;
    for record in &records {
        writer.record(record).unwrap();
    }
    for record in records
        .iter()
        .filter_map(kavach_ports::agent_evidence::ChainEntry::as_decision)
    {
        if let Some(id) = record.payload.credential_id.as_deref() {
            if let Some(outcome) = core.outcome(id).await.unwrap() {
                writer.outcome(&outcome).unwrap();
                outcomes += 1;
            }
        }
    }
    assert_eq!(outcomes, 1, "the delivery's outcome");
    for checkpoint in &checkpoints {
        writer.checkpoint(checkpoint).unwrap();
    }
    let export_key = Ed25519EvidenceSigner::from_seed("export-test-1", [9u8; 32]).unwrap();
    let exporter = Exporter {
        tool: "kavach-evidence".into(),
        version: "test".into(),
    };
    writer
        .finish(chrono::Utc::now(), exporter, Some(&export_key))
        .unwrap();

    // Every byte of every file.
    let mut scanned = 0;
    for entry in std::fs::read_dir(&out).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(leak(&text), None, "{} leaks personal data", path.display());
        scanned += 1;
    }
    assert_eq!(scanned, 4);
    // The subject is there only as a keyed pseudonym.
    let records_text = std::fs::read_to_string(out.join("records.jsonl")).unwrap();
    assert!(records_text.contains("subject_pseudonym"), "{records_text}");
    std::fs::remove_dir_all(&out).unwrap();
}
