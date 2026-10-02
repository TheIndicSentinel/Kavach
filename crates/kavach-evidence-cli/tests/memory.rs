//! The verifier's memory does not grow with the chain (E4a).
//!
//! This test binary runs under an allocator that records peak heap use. It
//! writes two bundles, one ten times longer than the other, verifies both,
//! and requires the peak during verification to be the same for both (and
//! far below the size of the larger bundle). It has one test, so no other
//! test's allocations are measured.

mod common;

use std::fs;

use chrono::Duration;
use kavach_evidence_cli::verify::{verify_dir, VerifyRequest};
use kavach_evidence_cli::writer::BundleWriter;
use kavach_ports::agent_evidence::{seal, sign_outcome, Outcome, SegmentStart, GENESIS};
use kavach_ports::checkpoint::{sign_checkpoint, Checkpoint, Head};
use peak_alloc::PeakAlloc;

use common::*;

#[global_allocator]
static PEAK: PeakAlloc = PeakAlloc;

const SMALL: i64 = 300;
const LARGE: i64 = 3_000;

/// Writes a bundle of `n` records, each with an outcome, and a checkpoint
/// every 100 records, generating and writing one record at a time.
fn write_chain(out: &std::path::Path, n: i64) {
    let template = records().remove(0).payload;
    let (evidence, checkpoint) = (evidence_key(), checkpoint_key());
    let mut writer = BundleWriter::create(out, SCOPE, SegmentStart::GENESIS).unwrap();

    let mut outcomes = Vec::new();
    let mut checkpoints: Vec<Checkpoint> = Vec::new();
    let mut prev = GENESIS.to_string();
    for seq in 1..=n {
        let mut payload = template.clone();
        payload.seq = seq;
        payload.prev_hash.clone_from(&prev);
        payload.record_id = format!("adr:{TENANT}:0:{seq}");
        payload.request_id = format!("mem-{seq}");
        payload.credential_id = Some(format!("cred-{seq}"));
        payload.ts = t0() + Duration::seconds(seq);
        payload.credential_expires_at = Some(payload.ts + Duration::seconds(15));
        let record = seal(payload, &evidence).unwrap();
        writer.record(&record).unwrap();
        // Outcomes and checkpoints are written after the records; keep
        // only what is needed to write them (this is the generator's
        // memory, not the verifier's).
        outcomes.push(
            sign_outcome(
                TENANT,
                &format!("cred-{seq}"),
                &record.hash,
                Outcome::Delivered,
                "provider_202",
                record.payload.ts,
                &evidence,
            )
            .unwrap(),
        );
        if seq % 100 == 0 {
            let next = sign_checkpoint(
                Head {
                    scope: SCOPE,
                    seq,
                    hash: &record.hash,
                },
                checkpoints.last(),
                record.payload.ts,
                record.payload.time_sync.clone(),
                &checkpoint,
            )
            .unwrap();
            checkpoints.push(next);
        }
        prev.clone_from(&record.hash);
    }
    for outcome in &outcomes {
        writer.outcome(outcome).unwrap();
    }
    for checkpoint in &checkpoints {
        writer.checkpoint(checkpoint).unwrap();
    }
    writer
        .finish(exported_at(), exporter(), Some(&export_key()))
        .unwrap();
}

/// Peak heap bytes used while verifying `bundle`, above what was already
/// allocated when verification began.
fn peak_while_verifying(bundle: &std::path::Path, keys: &std::path::Path, records: u64) -> usize {
    let before = PEAK.current_usage();
    PEAK.reset_peak_usage();
    let report = verify_dir(&VerifyRequest {
        bundle,
        keys,
        expect_checkpoint: None,
        dev: false,
        now: exported_at() + Duration::days(1),
    })
    .expect("the generated bundle verifies");
    let peak = PEAK.peak_usage();
    assert_eq!(report.records, records);
    assert_eq!(report.outcomes, records);
    assert_eq!(
        (report.outcome_missing.count, report.uncovered_records),
        (0, 0)
    );
    peak.saturating_sub(before)
}

#[test]
fn verifying_a_ten_times_longer_chain_uses_no_more_memory() {
    let keys =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/bundle-v1.keys.json");
    let (small, large) = (scratch("memory-small"), scratch("memory-large"));
    write_chain(&small, SMALL);
    write_chain(&large, LARGE);
    let size = |dir: &std::path::Path| -> u64 {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum()
    };
    let (small_size, large_size) = (size(&small), size(&large));
    assert!(large_size > 9 * small_size, "{small_size} vs {large_size}");

    let small_peak = peak_while_verifying(&small, &keys, SMALL.unsigned_abs());
    let large_peak = peak_while_verifying(&large, &keys, LARGE.unsigned_abs());
    eprintln!(
        "bundle {small_size} B: peak {small_peak} B; bundle {large_size} B: peak {large_peak} B"
    );

    // Ten times the chain, the same memory (a little slack for allocator
    // rounding and the longer file names' buffers).
    assert!(
        large_peak <= small_peak + 64 * 1024,
        "memory grew with the chain: {small_peak} B for {SMALL} records, {large_peak} B for \
         {LARGE}"
    );
    // And nowhere near the size of what was verified.
    assert!(
        (large_peak as u64) < large_size / 4,
        "peak {large_peak} B while verifying a {large_size} B bundle"
    );

    fs::remove_dir_all(&small).unwrap();
    fs::remove_dir_all(&large).unwrap();
}
