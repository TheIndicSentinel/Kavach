//! Evidence bundles as `kavach-evidence verify-bundle` reads them
//! (`verify_dir`: manifest, file digests, records, outcomes, checkpoints),
//! starting from the checked-in, signed bundle
//! (crates/kavach-evidence-cli/tests/vectors/bundle-v1).
//!
//! First byte selects the mode:
//! - even: the rest is a list of (file, position, byte) edits to the bundle.
//! - odd: the rest is the four files' contents, separated by NUL.
//!
//! Invariant: a bundle that verifies with the trusted export signature has
//! data files identical, byte for byte, to the original and a manifest with
//! the same content (its JSON layout may differ). Anything else must fail
//! or be reported unsigned.

#![no_main]

use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use chrono::{DateTime, TimeZone, Utc};
use kavach_evidence_cli::verify::{verify_dir, VerifyRequest};
use kavach_ports::bundle::{
    Manifest, ManifestSignature, CHECKPOINTS_FILE, MANIFEST_FILE, OUTCOMES_FILE, RECORDS_FILE,
};
use libfuzzer_sys::fuzz_target;

const FILES: [&str; 4] = [MANIFEST_FILE, RECORDS_FILE, OUTCOMES_FILE, CHECKPOINTS_FILE];
const ORIGINAL: [&[u8]; 4] = [
    include_bytes!("../../crates/kavach-evidence-cli/tests/vectors/bundle-v1/manifest.json"),
    include_bytes!("../../crates/kavach-evidence-cli/tests/vectors/bundle-v1/records.jsonl"),
    include_bytes!("../../crates/kavach-evidence-cli/tests/vectors/bundle-v1/outcomes.jsonl"),
    include_bytes!("../../crates/kavach-evidence-cli/tests/vectors/bundle-v1/checkpoints.jsonl"),
];
const KEYS: &[u8] = include_bytes!("../../crates/kavach-evidence-cli/tests/vectors/bundle-v1.keys.json");

/// The vector's export time plus one hour (`exported_at` in its tests).
fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 6, 30, 0).unwrap()
}

/// One scratch directory per process, rewritten for every input.
fn scratch() -> &'static (PathBuf, PathBuf) {
    static DIR: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();
    DIR.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("kavach-fuzz-bundle-{}", std::process::id()));
        let bundle = root.join("bundle");
        fs::create_dir_all(&bundle).unwrap();
        let keys = root.join("keys.json");
        fs::write(&keys, KEYS).unwrap();
        (bundle, keys)
    })
}

fn manifest(bytes: &[u8]) -> Option<Manifest> {
    serde_json::from_slice(bytes).ok()
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let mut files: Vec<Vec<u8>> = ORIGINAL.iter().map(|f| f.to_vec()).collect();
    if mode % 2 == 0 {
        for edit in rest.chunks_exact(4) {
            let file = &mut files[usize::from(edit[0]) % 4];
            if file.is_empty() {
                continue;
            }
            let at = usize::from(u16::from_le_bytes([edit[1], edit[2]])) % file.len();
            file[at] = edit[3];
        }
    } else {
        let parts: Vec<&[u8]> = rest.splitn(4, |b| *b == 0).collect();
        let [m, r, o, c] = parts.as_slice() else {
            return;
        };
        files = vec![m.to_vec(), r.to_vec(), o.to_vec(), c.to_vec()];
    }
    let (bundle, keys) = scratch();
    for (name, bytes) in FILES.iter().zip(&files) {
        fs::write(bundle.join(name), bytes).unwrap();
    }
    let Ok(report) = verify_dir(&VerifyRequest {
        bundle,
        keys,
        expect_checkpoint: None,
        dev: false,
        now: now(),
    }) else {
        return;
    };
    if !matches!(report.signature, ManifestSignature::Signed { .. }) {
        return;
    }
    for (i, name) in FILES.iter().enumerate().skip(1) {
        assert_eq!(files[i], ORIGINAL[i], "{name} changed and still verified as signed");
    }
    let (Some(ours), Some(original)) = (manifest(&files[0]), manifest(ORIGINAL[0])) else {
        panic!("a signed manifest that verified does not parse");
    };
    assert_eq!(
        serde_json::to_value(&ours.payload).unwrap(),
        serde_json::to_value(&original.payload).unwrap(),
        "the manifest's content changed and still verified as signed"
    );
});
