//! Known-answer vectors for the evidence checkpoint format (v1).
//!
//! `tests/vectors/checkpoint-v1.json` holds two linked checkpoints signed
//! once with a test-only key, with the exact bytes that were hashed. It is
//! checked in, so a change to the format, the canonical form or the signing
//! message shows up as a failure here rather than as writer and verifier
//! agreeing with each other. It is also what an independent verifier is
//! written against (`docs/EVIDENCE_BUNDLE.md`).
//!
//! Regenerate only on a deliberate format change:
//! `cargo test -p kavach-ports --test checkpoint_vectors -- --ignored generate`.

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use kavach_ports::agent_evidence::{DevKeys, EvidenceSigner, SegmentStart, TimeSync};
use kavach_ports::checkpoint::{
    canonical_payload, checkpoint_hash, checkpoint_signing_message, sign_checkpoint,
    verify_checkpoints, ChainSegment, Checkpoint, Head, Scope, CHAIN_AGENT_DECISIONS,
    CHECKPOINT_HASH_PREFIX, CHECKPOINT_SIG_PREFIX,
};
use kavach_ports::{KeyAlgorithm, PortError, PublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/checkpoint-v1.json"
);
const SEED: [u8; 32] = [31u8; 32];
const KID: &str = "kavach-checkpoint-kat";
const SCOPE: Scope<'static> = Scope {
    tenant_id: "default",
    partition_id: 0,
    chain: CHAIN_AGENT_DECISIONS,
};

struct Key(SigningKey);

impl EvidenceSigner for Key {
    fn key_id(&self) -> &str {
        KID
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PortError> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}

fn key() -> Key {
    Key(SigningKey::from_bytes(&SEED))
}

fn keys() -> BTreeMap<String, PublicKey> {
    BTreeMap::from([(
        KID.to_string(),
        PublicKey {
            kid: KID.into(),
            algorithm: KeyAlgorithm::Ed25519,
            bytes: key().0.verifying_key().to_bytes(),
        },
    )])
}

/// Stand-ins for the hashes of records 1..=5.
fn record_hashes() -> Vec<String> {
    (1u8..=5)
        .map(|i| format!("{:x}", Sha256::digest([i])))
        .collect()
}

fn at(seconds: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 6, 30, seconds).unwrap()
}

fn build() -> Vec<Checkpoint> {
    let records = record_hashes();
    let head = |seq: usize| Head {
        scope: SCOPE,
        seq: i64::try_from(seq).unwrap(),
        hash: &records[seq - 1],
    };
    let synced = TimeSync {
        status: "synced".into(),
        max_error_ms: Some(12),
    };
    let unknown = TimeSync {
        status: "unknown".into(),
        max_error_ms: None,
    };
    let first = sign_checkpoint(head(2), None, at(0), synced, &key()).unwrap();
    let ts = at(59) + chrono::TimeDelta::microseconds(250_000);
    let second = sign_checkpoint(head(5), Some(&first), ts, unknown, &key()).unwrap();
    vec![first, second]
}

fn vector() -> Value {
    serde_json::from_str(&std::fs::read_to_string(PATH).expect("vector file")).unwrap()
}

#[test]
#[ignore = "regenerates the checked-in vector; run only on a deliberate format change"]
fn generate() {
    let checkpoints: Vec<Value> = build()
        .iter()
        .map(|c| {
            json!({
                "checkpoint": c,
                "canonical_payload": String::from_utf8(canonical_payload(&c.payload).unwrap()).unwrap(),
            })
        })
        .collect();
    let file = json!({
        "description": "Kavach evidence checkpoint v1. hash = SHA-256(hash_prefix || canonical_payload), lowercase hex; canonical_payload is the RFC 8785 (JCS) form of the checkpoint without `hash` and `sig`. sig = Ed25519(signing_prefix || hash as ASCII), hex. Test key only.",
        "hash_prefix": String::from_utf8(CHECKPOINT_HASH_PREFIX.to_vec()).unwrap(),
        "signing_prefix": String::from_utf8(CHECKPOINT_SIG_PREFIX.to_vec()).unwrap(),
        "public_key": { "kid": KID, "alg": "Ed25519",
            "public_key": hex::encode(key().0.verifying_key().to_bytes()) },
        "record_hashes": record_hashes(),
        "checkpoints": checkpoints,
    });
    std::fs::create_dir_all(std::path::Path::new(PATH).parent().unwrap()).unwrap();
    std::fs::write(PATH, serde_json::to_string_pretty(&file).unwrap() + "\n").unwrap();
}

#[test]
fn the_checked_in_checkpoints_have_the_documented_bytes() {
    let vector = vector();
    assert_eq!(vector["hash_prefix"], "kavach-evidence-checkpoint-v1");
    assert_eq!(vector["signing_prefix"], "kavach-evidence-checkpoint-v1:");
    let entries = vector["checkpoints"].as_array().unwrap();
    assert_eq!(entries.len(), 2);

    let mut parsed = Vec::new();
    for entry in entries {
        let checkpoint: Checkpoint = serde_json::from_value(entry["checkpoint"].clone()).unwrap();
        // Parsing and re-serialising loses nothing.
        assert_eq!(
            serde_json::to_value(&checkpoint).unwrap(),
            entry["checkpoint"]
        );

        // The hash, from the stored bytes alone (what another language does).
        let canonical = entry["canonical_payload"].as_str().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(vector["hash_prefix"].as_str().unwrap());
        hasher.update(canonical);
        assert_eq!(format!("{:x}", hasher.finalize()), checkpoint.hash);
        // And this implementation produces those bytes.
        assert_eq!(
            canonical_payload(&checkpoint.payload).unwrap(),
            canonical.as_bytes()
        );
        assert_eq!(
            checkpoint_hash(&checkpoint.payload).unwrap(),
            checkpoint.hash
        );

        // Ed25519 is deterministic: the same key signs to the same bytes.
        let message = checkpoint_signing_message(&checkpoint.hash);
        assert_eq!(hex::encode(key().sign(&message).unwrap()), checkpoint.sig);
        parsed.push(checkpoint);
    }
    assert_eq!(parsed, build(), "the format changed: see the module docs");

    // Canonical form: sorted keys, no whitespace, RFC 3339 UTC time.
    let canonical = entries[1]["canonical_payload"].as_str().unwrap();
    assert!(
        canonical.starts_with(r#"{"chain":"agent_decisions","head_hash":""#),
        "{canonical}"
    );
    assert!(
        canonical.contains(r#""ts":"2026-10-02T06:30:59.250Z""#),
        "{canonical}"
    );
    assert!(canonical.contains(r#""time_sync":{"max_error_ms":null,"status":"unknown"}"#));

    // The vector verifies end to end with the published key.
    let records = record_hashes();
    let segment = ChainSegment::new(
        SegmentStart::GENESIS,
        records.iter().map(String::as_str).collect(),
    );
    let report = verify_checkpoints(&parsed, SCOPE, &segment, &keys(), DevKeys::Refuse).unwrap();
    assert_eq!(report.last, Some((5, parsed[1].hash.clone())));
    assert_eq!(report.records_after_last, 0);
    assert_eq!(
        vector["public_key"]["public_key"],
        hex::encode(key().0.verifying_key().to_bytes())
    );
}
