//! A small, fixed run of the agent chain: four records, two outcomes and
//! two checkpoints, signed with test-only keys. Everything is
//! deterministic (fixed keys and times), so the bundle written from it is
//! byte-for-byte reproducible.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Duration, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use kavach_domain::Decision;
use kavach_ports::agent_evidence::{
    seal, sign_outcome, Actor, AgentDecisionPayload, AgentDecisionRecord, EvidenceSigner, Outcome,
    OutcomeRecord, PolicyVersions, TimeSync, GENESIS, HASH_ALG_V2, KIND_AGENT_DECISION,
};
use kavach_ports::bundle::Exporter;
use kavach_ports::checkpoint::{sign_checkpoint, Checkpoint, Head, Scope, CHAIN_AGENT_DECISIONS};
use kavach_ports::{KeyAlgorithm, PortError, PublicKey};

pub const TENANT: &str = "default";
pub const SCOPE: Scope<'static> = Scope {
    tenant_id: TENANT,
    partition_id: 0,
    chain: CHAIN_AGENT_DECISIONS,
};

pub struct Key(pub &'static str, pub SigningKey);

impl EvidenceSigner for Key {
    fn key_id(&self) -> &str {
        self.0
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PortError> {
        Ok(self.1.sign(message).to_bytes().to_vec())
    }
}

pub fn evidence_key() -> Key {
    Key("kavach-evidence-kat", SigningKey::from_bytes(&[41u8; 32]))
}

pub fn checkpoint_key() -> Key {
    Key("kavach-checkpoint-kat", SigningKey::from_bytes(&[42u8; 32]))
}

pub fn export_key() -> Key {
    Key("export-kat-1", SigningKey::from_bytes(&[43u8; 32]))
}

/// The public halves, as an operator would supply them to a verifier.
pub fn public_keys() -> BTreeMap<String, PublicKey> {
    [evidence_key(), checkpoint_key(), export_key()]
        .into_iter()
        .map(|key| {
            (
                key.0.to_string(),
                PublicKey {
                    kid: key.0.into(),
                    algorithm: KeyAlgorithm::Ed25519,
                    bytes: key.1.verifying_key().to_bytes(),
                },
            )
        })
        .collect()
}

pub fn t0() -> DateTime<Utc> {
    // 11:00 IST on 2 Oct 2026.
    Utc.with_ymd_and_hms(2026, 10, 2, 5, 30, 0).unwrap()
}

fn synced() -> TimeSync {
    TimeSync {
        status: "synced".into(),
        max_error_ms: Some(12),
    }
}

fn payload(seq: i64, prev: &str, decision: Decision) -> AgentDecisionPayload {
    let allow = decision == Decision::Pass;
    let ts = t0() + Duration::seconds(seq * 10);
    AgentDecisionPayload {
        record_id: format!("adr:{TENANT}:0:{seq}"),
        tenant_id: TENANT.into(),
        partition_id: 0,
        seq,
        prev_hash: prev.into(),
        kind: KIND_AGENT_DECISION.into(),
        hash_alg: HASH_ALG_V2.into(),
        key_id: evidence_key().0.into(),
        actor: Actor {
            agent_id: "collections-agent".into(),
            identity_key: "oidc:https://idp.example/realms/kavach#collections-agent".into(),
        },
        chain: vec!["ma-kat-root".into()],
        mandate_id: "ma-kat-root".into(),
        purpose: "loan_recovery".into(),
        consent_refs: vec!["C-kat-1".into()],
        action: "send_reminder".into(),
        request_id: format!("kat-{seq}"),
        subject_pseudonym: "psn:5b1f0a7c9d2e4f60".into(),
        params_mac: allow.then(|| "mac:9a8b7c6d5e4f3021".into()),
        policy_versions: PolicyVersions {
            cedar: "sha256:cedar-kat".into(),
            cel: None,
            packs: vec![],
            tools: Some("sha256:tools-kat".into()),
            build: "kat".into(),
        },
        signals: if allow {
            vec!["authorized".into()]
        } else {
            vec!["raw_identifier".into()]
        },
        pre_commit_decision: decision,
        policy_decision: decision,
        returned_decision: decision,
        obligations: vec![],
        credential_id: allow.then(|| format!("cred-{seq}")),
        credential_expires_at: allow.then(|| ts + Duration::seconds(15)),
        send_by: allow.then(|| t0() + Duration::hours(8)),
        time_sync: synced(),
        ts,
    }
}

/// Records 1, 3 and 4 are allows; record 2 is a block.
pub fn records() -> Vec<AgentDecisionRecord> {
    let key = evidence_key();
    let mut prev = GENESIS.to_string();
    [
        Decision::Pass,
        Decision::Block,
        Decision::Pass,
        Decision::Pass,
    ]
    .into_iter()
    .zip(1..)
    .map(|(decision, seq)| {
        let record = seal(payload(seq, &prev, decision), &key).unwrap();
        prev.clone_from(&record.hash);
        record
    })
    .collect()
}

/// Record 1 was delivered, record 3's result is unknown, and record 4 has
/// no outcome at all.
pub fn outcomes(records: &[AgentDecisionRecord]) -> Vec<OutcomeRecord> {
    let key = evidence_key();
    let outcome = |index: usize, outcome, reason| {
        let record = &records[index];
        sign_outcome(
            TENANT,
            record.payload.credential_id.as_deref().unwrap(),
            &record.hash,
            outcome,
            reason,
            record.payload.ts + Duration::seconds(2),
            &key,
        )
        .unwrap()
    };
    vec![
        outcome(0, Outcome::Delivered, "provider_202"),
        outcome(2, Outcome::Unknown, "timeout_after_send"),
    ]
}

/// Checkpoints of records 2 and 3; record 4 is newer than both.
pub fn checkpoints(records: &[AgentDecisionRecord]) -> Vec<Checkpoint> {
    let key = checkpoint_key();
    let at = |seq: usize, previous: Option<&Checkpoint>| {
        let record = &records[seq - 1];
        sign_checkpoint(
            Head {
                scope: SCOPE,
                seq: record.payload.seq,
                hash: &record.hash,
            },
            previous,
            record.payload.ts + Duration::seconds(5),
            synced(),
            &key,
        )
        .unwrap()
    };
    let second = at(2, None);
    let third = at(3, Some(&second));
    vec![second, third]
}

pub fn exported_at() -> DateTime<Utc> {
    t0() + Duration::hours(1)
}

pub fn exporter() -> Exporter {
    Exporter {
        tool: "kavach-evidence".into(),
        version: "kat".into(),
    }
}

/// A path in the system temporary directory that does not exist yet.
pub fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("kavach-{name}-{}", uuid::Uuid::new_v4().simple()))
}
