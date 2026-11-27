//! Evidence bundle manifest, format v1 (ADR-005 §13, `docs/EVIDENCE_BUNDLE.md`).
//!
//! A bundle is an export of one chain segment: its records, the outcomes
//! of those records and the checkpoints from the segment's start. The
//! manifest names the segment and the SHA-256 of each file.
//!
//! Records and checkpoints carry their own signatures. Outcome rows are
//! signed one by one but not as a set, so a missing outcome cannot be seen
//! from the rows alone. The manifest signature covers that gap: signed with
//! the **export key** of whoever ran the export, it states "this is what
//! the exporter saw". The export key lives with the auditor, never on the
//! API host, and its id starts with `export-` so it cannot be mistaken for
//! (or used as) a mandate, evidence, checkpoint or credential key.
//!
//! This module is pure: no I/O.

use std::collections::BTreeMap;

use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_evidence::{is_dev_key, DevKeys, EvidenceSigner, DEV_KEY_PREFIX};
use crate::checkpoint::Scope;
use crate::error::PortError;
use crate::keys::{verify_ed25519, PublicKey};

pub const BUNDLE_FORMAT: &str = "kavach-evidence-bundle";
/// The format version an export writes. Version 4 (ADR-017) adds a fifth
/// file, `resolutions.jsonl`, with the resolutions of `unknown` outcomes;
/// version 3 (ADR-013 §4) added `agent_state` records to version 2's decisions
/// and revocations (ADR-012 §7); version 1 carried decisions only.
pub const BUNDLE_VERSION: u32 = 4;
/// The versions a verifier reads; it refuses any other.
pub const BUNDLE_VERSIONS: [u32; 4] = [1, 2, 3, 4];
/// The first version with a resolutions file.
pub const RESOLUTIONS_SINCE: u32 = 4;
pub const BUNDLE_HASH_PREFIX: &[u8] = b"kavach-evidence-bundle-v1";
pub const BUNDLE_SIG_PREFIX: &[u8] = b"kavach-evidence-bundle-v1:";

/// The files of a bundle. The names are fixed: a manifest never names a path.
pub const MANIFEST_FILE: &str = "manifest.json";
pub const RECORDS_FILE: &str = "records.jsonl";
pub const OUTCOMES_FILE: &str = "outcomes.jsonl";
pub const CHECKPOINTS_FILE: &str = "checkpoints.jsonl";
/// Resolutions of unknown outcomes (version 4 only).
pub const RESOLUTIONS_FILE: &str = "resolutions.jsonl";

/// Export key ids start with this (after `dev-`, for a development key).
pub const EXPORT_KEY_PREFIX: &str = "export-";

/// `export-…`, or `dev-export-…` for a development stack.
#[must_use]
pub fn is_export_key(key_id: &str) -> bool {
    key_id
        .strip_prefix(DEV_KEY_PREFIX)
        .unwrap_or(key_id)
        .starts_with(EXPORT_KEY_PREFIX)
}

/// One file of the bundle: the SHA-256 of its bytes and its line count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub sha256: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Files {
    pub records: FileEntry,
    pub outcomes: FileEntry,
    pub checkpoints: FileEntry,
    /// Version 4 only: present exactly when the bundle has the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolutions: Option<FileEntry>,
}

/// The records in the bundle: those after record `after_seq` (0 and 64
/// zeros: from the first record) up to `last_seq`, whose hash is
/// `head_hash`. An empty segment has `last_seq == after_seq`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    pub after_seq: i64,
    pub after_hash: String,
    pub last_seq: i64,
    pub head_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exporter {
    pub tool: String,
    pub version: String,
}

/// The hashed and signed content of a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestPayload {
    pub format: String,
    pub version: u32,
    pub tenant_id: String,
    pub partition_id: i32,
    pub chain: String,
    pub segment: Segment,
    pub files: Files,
    /// The exporter's own clock (not trusted time), to the microsecond.
    pub exported_at: DateTime<Utc>,
    pub exporter: Exporter,
    /// The export key; absent on an unsigned bundle. Inside the payload so
    /// a signature cannot be paired with another key id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(flatten)]
    pub payload: ManifestPayload,
    pub hash: String,
    /// Absent on an unsigned bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// RFC 8785 (JCS) bytes of a payload: what is hashed.
pub fn canonical_manifest(payload: &ManifestPayload) -> Result<Vec<u8>, PortError> {
    crate::jcs::to_vec(payload)
}

/// SHA-256 over the hash prefix and the canonical payload, as lowercase hex.
pub fn manifest_hash(payload: &ManifestPayload) -> Result<String, PortError> {
    let mut hasher = Sha256::new();
    hasher.update(BUNDLE_HASH_PREFIX);
    hasher.update(canonical_manifest(payload)?);
    Ok(format!("{:x}", hasher.finalize()))
}

#[must_use]
pub fn manifest_signing_message(hash: &str) -> Vec<u8> {
    let mut message = BUNDLE_SIG_PREFIX.to_vec();
    message.extend_from_slice(hash.as_bytes());
    message
}

/// What an exporter states about a bundle, before hashing and signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDraft<'a> {
    pub scope: Scope<'a>,
    pub segment: Segment,
    pub files: Files,
    pub exported_at: DateTime<Utc>,
    pub exporter: Exporter,
}

/// Hashes the manifest and signs it with the export key.
///
/// `signer: None` makes an **unsigned** bundle: its records and checkpoints
/// still verify, but nothing vouches for the set of outcomes. A signer
/// whose key id is not an export key is refused.
pub fn seal_manifest(
    draft: ManifestDraft<'_>,
    signer: Option<&dyn EvidenceSigner>,
) -> Result<Manifest, PortError> {
    if let Some(signer) = signer {
        if !is_export_key(signer.key_id()) {
            return Err(PortError::invalid(format!(
                "{} is not an export key: a bundle is signed with a key whose id starts with \
                 {EXPORT_KEY_PREFIX}",
                signer.key_id()
            )));
        }
    }
    let exported_at = draft
        .exported_at
        .duration_trunc(TimeDelta::microseconds(1))
        .map_err(|e| PortError::invalid(format!("export time: {e}")))?;
    let payload = ManifestPayload {
        format: BUNDLE_FORMAT.into(),
        version: BUNDLE_VERSION,
        tenant_id: draft.scope.tenant_id.into(),
        partition_id: draft.scope.partition_id,
        chain: draft.scope.chain.into(),
        segment: draft.segment,
        files: draft.files,
        exported_at,
        exporter: draft.exporter,
        key_id: signer.map(|s| s.key_id().to_string()),
    };
    check_shape(&payload).map_err(|e| PortError::invalid(e.to_string()))?;
    let hash = manifest_hash(&payload)?;
    let sig = signer
        .map(|s| s.sign(&manifest_signing_message(&hash)).map(hex::encode))
        .transpose()?;
    Ok(Manifest { payload, hash, sig })
}

/// Problems found by [`verify_manifest`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest: {0}")]
    Format(String),
    #[error("manifest: hash does not match its content")]
    Hash,
    #[error("manifest: {key_id} is not an export key (its id must start with export-)")]
    NotExportKey { key_id: String },
    #[error(
        "manifest: signed with development key {key_id}; dev-signed bundles are accepted only \
         when verifying a development stack"
    )]
    DevKey { key_id: String },
    #[error("manifest: signature invalid ({0})")]
    Signature(String),
}

/// Whether a verified manifest is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestSignature {
    Signed {
        key_id: String,
    },
    /// Nothing vouches for the set of outcomes; the verifier must say so.
    Unsigned,
}

fn check_shape(p: &ManifestPayload) -> Result<(), ManifestError> {
    let format = |reason: &str| Err(ManifestError::Format(reason.into()));
    if p.format != BUNDLE_FORMAT {
        return format("not a Kavach evidence bundle");
    }
    if !BUNDLE_VERSIONS.contains(&p.version) {
        return format("unknown bundle version");
    }
    let s = &p.segment;
    if s.after_seq < 0 || s.last_seq < s.after_seq {
        return format("the segment bounds are out of order");
    }
    if !is_hash(&s.after_hash) || !is_hash(&s.head_hash) {
        return format("segment hashes must be 64 lowercase hex");
    }
    if s.last_seq == s.after_seq && s.head_hash != s.after_hash {
        return format("an empty segment must end where it starts");
    }
    let records = u64::try_from(s.last_seq - s.after_seq).unwrap_or(u64::MAX);
    if p.files.records.count != records {
        return format("the record count does not match the segment");
    }
    for file in [&p.files.records, &p.files.outcomes, &p.files.checkpoints]
        .into_iter()
        .chain(p.files.resolutions.as_ref())
    {
        if !is_hash(&file.sha256) {
            return format("file digests must be 64 lowercase hex");
        }
    }
    // A resolutions file exists in version 4 and only there: never accepted
    // inside a format that did not define it, never absent from one that did.
    if p.files.resolutions.is_some() != (p.version >= RESOLUTIONS_SINCE) {
        return format(if p.version >= RESOLUTIONS_SINCE {
            "a version 4 bundle lists its resolutions file"
        } else {
            "a resolutions file is not part of bundle versions before 4"
        });
    }
    Ok(())
}

/// Verifies a manifest offline: format, version, hash and, when signed,
/// the signature against `keys`.
///
/// `keys` must come from the operator, never from the bundle. This checks
/// the manifest only: the caller still compares each file with its digest
/// and count, and verifies the records and checkpoints.
pub fn verify_manifest(
    manifest: &Manifest,
    keys: &BTreeMap<String, PublicKey>,
    dev_keys: DevKeys,
) -> Result<ManifestSignature, ManifestError> {
    let p = &manifest.payload;
    check_shape(p)?;
    if manifest_hash(p).ok().as_deref() != Some(manifest.hash.as_str()) {
        return Err(ManifestError::Hash);
    }
    let (key_id, sig) = match (&p.key_id, &manifest.sig) {
        (None, None) => return Ok(ManifestSignature::Unsigned),
        (Some(key_id), Some(sig)) => (key_id, sig),
        _ => {
            return Err(ManifestError::Format(
                "key_id and sig must both be present or both absent".into(),
            ))
        }
    };
    if !is_export_key(key_id) {
        return Err(ManifestError::NotExportKey {
            key_id: key_id.clone(),
        });
    }
    if dev_keys == DevKeys::Refuse && is_dev_key(key_id) {
        return Err(ManifestError::DevKey {
            key_id: key_id.clone(),
        });
    }
    let key = keys
        .get(key_id)
        .ok_or_else(|| ManifestError::Signature(format!("unknown key {key_id}")))?;
    let sig = hex::decode(sig).map_err(|_| ManifestError::Signature("not hex".into()))?;
    verify_ed25519(key, &manifest_signing_message(&manifest.hash), &sig)
        .map_err(|e| ManifestError::Signature(e.to_string()))?;
    Ok(ManifestSignature::Signed {
        key_id: key_id.clone(),
    })
}

// ---------------------------------------------------------------------------
// Members a line may hold (docs/specs/evidence-bundle.md sections 4 to 6)
// ---------------------------------------------------------------------------

const RECORD_COMMON: &[&str] = &[
    "kind",
    "record_id",
    "tenant_id",
    "partition_id",
    "seq",
    "prev_hash",
    "hash_alg",
    "key_id",
    "time_sync",
    "hash",
    "sig",
];
const AGENT_DECISION_MEMBERS: &[&str] = &[
    "actor",
    "chain",
    "mandate_id",
    "purpose",
    "consent_refs",
    "action",
    "request_id",
    "subject_pseudonym",
    "params_mac",
    "review_action_hash",
    "policy_versions",
    "signals",
    "pre_commit_decision",
    "policy_decision",
    "returned_decision",
    "obligations",
    "credential_id",
    "credential_expires_at",
    "send_by",
    "ts",
];
const MANDATE_REVOCATION_MEMBERS: &[&str] = &[
    "source_system",
    "event_id",
    "event_type",
    "event_digest",
    "event_sha256",
    "record_pseudonym",
    "occurred_at",
    "revoked",
    "revoked_at",
    "recorded_at",
];
const AGENT_STATE_MEMBERS: &[&str] = &[
    "agent_id",
    "change_no",
    "from_state",
    "to_state",
    "reason_code",
    "reason_digest",
    "changed_by",
    "change_request_id",
    "approved_by",
    "changed_at",
    "recorded_at",
];
const ACTOR_MEMBERS: &[&str] = &["agent_id", "identity_key"];
const POLICY_VERSIONS_MEMBERS: &[&str] = &["cedar", "cel", "packs", "tools", "build"];
const TIME_SYNC_MEMBERS: &[&str] = &["status", "max_error_ms"];
const OUTCOME_MEMBERS: &[&str] = &[
    "tenant_id",
    "credential_id",
    "record_hash",
    "outcome",
    "reason",
    "ts",
    "key_id",
    "sig",
];
const CHECKPOINT_MEMBERS: &[&str] = &[
    "kind",
    "version",
    "tenant_id",
    "partition_id",
    "chain",
    "seq",
    "head_hash",
    "prev_checkpoint_hash",
    "key_id",
    "time_sync",
    "ts",
    "hash",
    "sig",
];

/// The first member of `value` that is not in `allowed`, as a message.
fn stray(value: &serde_json::Value, allowed: &[&[&str]], what: &str) -> Option<String> {
    let object = value.as_object()?;
    object
        .keys()
        .find(|name| !allowed.iter().any(|list| list.contains(&name.as_str())))
        .map(|name| format!("{what} has a member the specification does not define: {name:?}"))
}

fn stray_in(
    value: &serde_json::Value,
    member: &str,
    allowed: &[&str],
    what: &str,
) -> Option<String> {
    stray(value.get(member)?, &[allowed], &format!("{what}: {member}"))
}

/// A member a record holds that its kind does not define, at the top level
/// or in `actor`, `policy_versions` or `time_sync`. The hash covers every
/// member, so an unknown one that is signed passes the chain steps; a
/// verifier that only reads the members it knows would then accept bytes it
/// did not check (section 9).
#[must_use]
pub fn undefined_record_member(record: &serde_json::Value) -> Option<String> {
    let kind_members = match record.get("kind").and_then(serde_json::Value::as_str)? {
        "agent_decision" => AGENT_DECISION_MEMBERS,
        "mandate_revocation" => MANDATE_REVOCATION_MEMBERS,
        "agent_state" => AGENT_STATE_MEMBERS,
        _ => return None,
    };
    stray(record, &[RECORD_COMMON, kind_members], "the record")
        .or_else(|| stray_in(record, "time_sync", TIME_SYNC_MEMBERS, "the record"))
        .or_else(|| stray_in(record, "actor", ACTOR_MEMBERS, "the record"))
        .or_else(|| {
            stray_in(
                record,
                "policy_versions",
                POLICY_VERSIONS_MEMBERS,
                "the record",
            )
        })
}

/// As [`undefined_record_member`], for an outcome row (section 5).
#[must_use]
pub fn undefined_outcome_member(outcome: &serde_json::Value) -> Option<String> {
    stray(outcome, &[OUTCOME_MEMBERS], "the outcome")
}

/// As [`undefined_record_member`], for a checkpoint (section 6).
#[must_use]
pub fn undefined_checkpoint_member(checkpoint: &serde_json::Value) -> Option<String> {
    stray(checkpoint, &[CHECKPOINT_MEMBERS], "the checkpoint")
        .or_else(|| stray_in(checkpoint, "time_sync", TIME_SYNC_MEMBERS, "the checkpoint"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_evidence::GENESIS;
    use crate::checkpoint::CHAIN_AGENT_DECISIONS;
    use crate::KeyAlgorithm;
    use ed25519_dalek::{Signer, SigningKey};

    struct Key(&'static str, SigningKey);

    impl EvidenceSigner for Key {
        fn key_id(&self) -> &str {
            self.0
        }
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PortError> {
            Ok(self.1.sign(message).to_bytes().to_vec())
        }
    }

    fn key(kid: &'static str) -> Key {
        Key(kid, SigningKey::from_bytes(&[13u8; 32]))
    }

    fn keys(key: &Key) -> BTreeMap<String, PublicKey> {
        BTreeMap::from([(
            key.0.to_string(),
            PublicKey {
                kid: key.0.into(),
                algorithm: KeyAlgorithm::Ed25519,
                bytes: key.1.verifying_key().to_bytes(),
            },
        )])
    }

    fn entry(byte: &str, count: u64) -> FileEntry {
        FileEntry {
            sha256: byte.repeat(32),
            count,
        }
    }

    fn draft() -> ManifestDraft<'static> {
        ManifestDraft {
            scope: Scope {
                tenant_id: "t",
                partition_id: 0,
                chain: CHAIN_AGENT_DECISIONS,
            },
            segment: Segment {
                after_seq: 0,
                after_hash: GENESIS.into(),
                last_seq: 3,
                head_hash: "0c".repeat(32),
            },
            files: Files {
                records: entry("a1", 3),
                outcomes: entry("a2", 2),
                checkpoints: entry("a3", 1),
                resolutions: Some(entry("a4", 0)),
            },
            exported_at: DateTime::from_timestamp(1_790_000_000, 123_456_789).unwrap(),
            exporter: Exporter {
                tool: "kavach-evidence".into(),
                version: "0.1.0".into(),
            },
        }
    }

    #[test]
    fn a_signed_manifest_verifies_and_round_trips() {
        let key = key("export-auditor-1");
        let manifest = seal_manifest(draft(), Some(&key)).unwrap();
        assert_eq!(manifest.payload.key_id.as_deref(), Some("export-auditor-1"));
        assert_eq!(
            manifest.payload.exported_at.timestamp_subsec_nanos(),
            123_456_000
        );
        assert_eq!(
            verify_manifest(&manifest, &keys(&key), DevKeys::Refuse),
            Ok(ManifestSignature::Signed {
                key_id: "export-auditor-1".into()
            })
        );
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        assert_eq!(serde_json::from_str::<Manifest>(&json).unwrap(), manifest);
    }

    #[test]
    fn an_unsigned_manifest_is_reported_as_unsigned_not_as_valid_signed() {
        let manifest = seal_manifest(draft(), None).unwrap();
        assert_eq!((&manifest.payload.key_id, &manifest.sig), (&None, &None));
        let json = serde_json::to_value(&manifest).unwrap();
        assert!(
            json.get("key_id").is_none() && json.get("sig").is_none(),
            "{json}"
        );
        assert_eq!(
            verify_manifest(&manifest, &BTreeMap::new(), DevKeys::Refuse),
            Ok(ManifestSignature::Unsigned)
        );

        // Stripping the signature from a signed manifest is not "unsigned":
        // the key id is inside the hash.
        let key = key("export-auditor-1");
        let mut stripped = seal_manifest(draft(), Some(&key)).unwrap();
        stripped.sig = None;
        assert!(matches!(
            verify_manifest(&stripped, &keys(&key), DevKeys::Refuse),
            Err(ManifestError::Format(_))
        ));
        stripped.payload.key_id = None;
        assert_eq!(
            verify_manifest(&stripped, &keys(&key), DevKeys::Refuse),
            Err(ManifestError::Hash)
        );
    }

    #[test]
    fn only_an_export_key_signs_a_bundle() {
        assert!(is_export_key("export-1") && is_export_key("dev-export-1"));
        for other in [
            "kavach-evidence-1",
            "kavach-checkpoint-1",
            "dev-checkpoint-1",
            "exporter",
        ] {
            assert!(!is_export_key(other), "{other}");
            // Refused when signing…
            assert!(
                seal_manifest(draft(), Some(&key(other))).is_err(),
                "{other}"
            );
        }
        // …and when verifying, even if the operator's key set lists it.
        let checkpoint = key("kavach-checkpoint-1");
        let export = key("export-auditor-1");
        let mut manifest = seal_manifest(draft(), Some(&export)).unwrap();
        manifest.payload.key_id = Some("kavach-checkpoint-1".into());
        manifest.hash = manifest_hash(&manifest.payload).unwrap();
        manifest.sig = Some(hex::encode(
            checkpoint
                .sign(&manifest_signing_message(&manifest.hash))
                .unwrap(),
        ));
        assert_eq!(
            verify_manifest(&manifest, &keys(&checkpoint), DevKeys::Refuse),
            Err(ManifestError::NotExportKey {
                key_id: "kavach-checkpoint-1".into()
            })
        );

        // A development export key only for a development stack.
        let dev = key("dev-export-1");
        let manifest = seal_manifest(draft(), Some(&dev)).unwrap();
        assert_eq!(
            verify_manifest(&manifest, &keys(&dev), DevKeys::Refuse),
            Err(ManifestError::DevKey {
                key_id: "dev-export-1".into()
            })
        );
        assert!(verify_manifest(&manifest, &keys(&dev), DevKeys::Accept).is_ok());
    }

    #[test]
    fn tampered_or_malformed_manifests_are_refused() {
        let key = key("export-auditor-1");
        let good = seal_manifest(draft(), Some(&key)).unwrap();
        let verify = |m: &Manifest| verify_manifest(m, &keys(&key), DevKeys::Refuse);

        // An outcome dropped: the count and digest in the manifest change.
        let mut edited = good.clone();
        edited.payload.files.outcomes.count = 1;
        assert_eq!(verify(&edited), Err(ManifestError::Hash));
        // Re-hashed by someone without the export key.
        edited.hash = manifest_hash(&edited.payload).unwrap();
        assert!(matches!(verify(&edited), Err(ManifestError::Signature(_))));
        // A key the operator did not supply.
        assert!(matches!(
            verify_manifest(&good, &BTreeMap::new(), DevKeys::Refuse),
            Err(ManifestError::Signature(_))
        ));
        // A checkpoint signature is not a manifest signature.
        let mut cross = good.clone();
        cross.sig = Some(hex::encode(
            key.sign(&crate::checkpoint::checkpoint_signing_message(&good.hash))
                .unwrap(),
        ));
        assert!(matches!(verify(&cross), Err(ManifestError::Signature(_))));

        // Shapes a writer never produces, refused before anything else.
        let reshaped = |change: fn(&mut ManifestPayload)| {
            let mut m = good.clone();
            change(&mut m.payload);
            m.hash = manifest_hash(&m.payload).unwrap();
            verify(&m)
        };
        for change in [
            (|p| p.version = 5) as fn(&mut ManifestPayload),
            // The resolutions file belongs to version 4 and only there.
            |p| p.files.resolutions = None,
            |p| p.version = 3,
            |p| p.format = "something-else".into(),
            |p| p.segment.last_seq = -1,
            |p| p.files.records.count = 4,
            |p| p.files.outcomes.sha256 = "XYZ".into(),
            |p| p.segment.head_hash = "0C".repeat(32),
            |p| {
                p.segment.last_seq = 0;
                p.files.records.count = 0;
            },
        ] {
            assert!(matches!(reshaped(change), Err(ManifestError::Format(_))));
        }
        // And seal_manifest does not produce them either.
        let mut bad = draft();
        bad.files.records.count = 9;
        assert!(seal_manifest(bad, Some(&key)).is_err());
    }

    /// The `pub` field names of `struct_name` in `source`.
    fn fields(source: &str, struct_name: &str) -> Vec<String> {
        let start = source
            .find(&format!("pub struct {struct_name} {{"))
            .unwrap_or_else(|| panic!("no struct {struct_name}"));
        source[start..]
            .lines()
            .skip(1)
            .take_while(|l| l.trim() != "}")
            .filter_map(|l| l.trim().strip_prefix("pub "))
            .filter_map(|l| l.split(':').next())
            .map(str::to_string)
            .collect()
    }

    /// The lists are the structs' serialization plus `hash` and `sig`, so the
    /// exporter (which writes the structs) can never write a member the
    /// verifier refuses, and a field added to a struct without the
    /// specification and the lists fails here.
    #[test]
    fn the_member_lists_are_the_structs_fields() {
        let evidence = include_str!("agent_evidence.rs");
        let chain = include_str!("chain_record.rs");
        let checkpoint = include_str!("checkpoint.rs");
        let sorted = |mut v: Vec<String>| {
            v.sort();
            v.dedup();
            v
        };
        let list = |lists: &[&[&str]]| {
            sorted(
                lists
                    .iter()
                    .flat_map(|l| l.iter())
                    .map(|s| (*s).to_string())
                    .collect(),
            )
        };
        let with_hash_sig = |mut v: Vec<String>| {
            v.extend(["hash".to_string(), "sig".to_string()]);
            v
        };
        assert_eq!(
            list(&[RECORD_COMMON, AGENT_DECISION_MEMBERS]),
            sorted(with_hash_sig(fields(evidence, "AgentDecisionPayload")))
        );
        assert_eq!(
            list(&[RECORD_COMMON, MANDATE_REVOCATION_MEMBERS]),
            sorted(with_hash_sig(fields(chain, "RevocationPayload")))
        );
        assert_eq!(
            list(&[RECORD_COMMON, AGENT_STATE_MEMBERS]),
            sorted(with_hash_sig(fields(chain, "AgentStatePayload")))
        );
        assert_eq!(list(&[ACTOR_MEMBERS]), sorted(fields(evidence, "Actor")));
        assert_eq!(
            list(&[POLICY_VERSIONS_MEMBERS]),
            sorted(fields(evidence, "PolicyVersions"))
        );
        assert_eq!(
            list(&[TIME_SYNC_MEMBERS]),
            sorted(fields(evidence, "TimeSync"))
        );
        assert_eq!(
            list(&[OUTCOME_MEMBERS]),
            sorted(fields(evidence, "OutcomeRecord"))
        );
        assert_eq!(
            list(&[CHECKPOINT_MEMBERS]),
            sorted(with_hash_sig(fields(checkpoint, "CheckpointPayload")))
        );
    }

    #[test]
    fn a_stray_member_is_named_and_a_defined_one_is_not() {
        let ok =
            serde_json::json!({"kind": "evidence_checkpoint", "time_sync": {"status": "synced"}});
        assert_eq!(undefined_checkpoint_member(&ok), None);
        let bad = serde_json::json!({"kind": "evidence_checkpoint", "note": 1});
        assert!(undefined_checkpoint_member(&bad).unwrap().contains("note"));
        let nested = serde_json::json!({"time_sync": {"status": "synced", "x": 1}});
        assert!(undefined_checkpoint_member(&nested)
            .unwrap()
            .contains("time_sync"));
        let record = serde_json::json!({"kind": "agent_state", "change_no": 1, "purpose": "x"});
        assert!(undefined_record_member(&record)
            .unwrap()
            .contains("purpose"));
    }
}
