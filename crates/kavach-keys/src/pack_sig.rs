//! Detached pack signatures (M1.3).
//!
//! `<pack>.sig` is a small JSON envelope: signer key id, the SHA-256 digest of
//! the pack file bytes, and an Ed25519 signature over a domain-separated
//! message containing that digest. When trusted signers are configured, every
//! pack load (startup, activate, rollback, model update, batch) requires a
//! valid signature from one of them.

use std::path::{Path, PathBuf};

use kavach_ports::{verify_ed25519, KeyAlgorithm, KeyProvider, PortError, PublicKey};
use serde::{Deserialize, Serialize};

const SIGNATURE_VERSION: u32 = 1;
const MESSAGE_PREFIX: &[u8] = b"kavach-pack-signature-v1:";

/// Detached signature envelope stored at `<pack path>.sig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSignature {
    pub version: u32,
    pub alg: String,
    pub kid: String,
    pub pack_sha256: String,
    /// Hex-encoded 64-byte Ed25519 signature.
    pub signature: String,
}

/// Public keys allowed to sign packs, loaded from a JSON file:
/// `{"signers":[{"kid":"pack-signer-1","public_key":"<64 hex chars>"}]}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSigners {
    keys: Vec<PublicKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedSignersFile {
    signers: Vec<TrustedSignerEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedSignerEntry {
    kid: String,
    public_key: String,
}

impl TrustedSigners {
    pub fn new(keys: Vec<PublicKey>) -> Result<Self, PortError> {
        if keys.is_empty() {
            return Err(PortError::invalid("trusted signers list is empty"));
        }
        Ok(Self { keys })
    }

    pub fn from_json(text: &str) -> Result<Self, PortError> {
        let file: TrustedSignersFile = serde_json::from_str(text)
            .map_err(|e| PortError::invalid(format!("trusted signers file: {e}")))?;
        let keys = file
            .signers
            .into_iter()
            .map(|entry| {
                crate::validate_kid(&entry.kid)?;
                let bytes: [u8; 32] = hex::decode(entry.public_key.trim())
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| {
                        PortError::invalid(format!(
                            "signer {}: public_key must be 32 bytes hex",
                            entry.kid
                        ))
                    })?;
                Ok(PublicKey {
                    kid: entry.kid,
                    algorithm: KeyAlgorithm::Ed25519,
                    bytes,
                })
            })
            .collect::<Result<Vec<_>, PortError>>()?;
        Self::new(keys)
    }

    pub fn from_file(path: &Path) -> Result<Self, PortError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            PortError::unavailable(format!("read trusted signers {}: {e}", path.display()))
        })?;
        Self::from_json(&text)
    }

    fn key(&self, kid: &str) -> Option<&PublicKey> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

/// Path of the detached signature for `pack_path` (`<pack_path>.sig`).
pub fn signature_path(pack_path: &Path) -> PathBuf {
    let mut os = pack_path.as_os_str().to_owned();
    os.push(".sig");
    PathBuf::from(os)
}

fn signing_message(pack_sha256: &str) -> Vec<u8> {
    let mut message = MESSAGE_PREFIX.to_vec();
    message.extend_from_slice(pack_sha256.as_bytes());
    message
}

/// Signs the pack file at `pack_path` with key `kid` and returns the envelope.
pub async fn sign_pack<K: KeyProvider>(
    provider: &K,
    kid: &str,
    pack_path: &Path,
) -> Result<PackSignature, PortError> {
    let bytes = std::fs::read(pack_path)
        .map_err(|e| PortError::unavailable(format!("read pack {}: {e}", pack_path.display())))?;
    let pack_sha256 = kavach_policy::pack_digest(&bytes);
    let signature = provider.sign(kid, &signing_message(&pack_sha256)).await?;
    Ok(PackSignature {
        version: SIGNATURE_VERSION,
        alg: "EdDSA".into(),
        kid: kid.to_string(),
        pack_sha256,
        signature: hex::encode(signature),
    })
}

/// Verifies `signature` for a pack whose file digest is `pack_sha256`.
pub fn verify_pack_signature(
    signature: &PackSignature,
    pack_sha256: &str,
    trusted: &TrustedSigners,
) -> Result<(), PortError> {
    if signature.version != SIGNATURE_VERSION || signature.alg != "EdDSA" {
        return Err(PortError::invalid(format!(
            "unsupported pack signature version {} / alg {}",
            signature.version, signature.alg
        )));
    }
    if signature.pack_sha256 != pack_sha256 {
        return Err(PortError::rejected(format!(
            "signature covers {}, pack is {pack_sha256}",
            signature.pack_sha256
        )));
    }
    let key = trusted
        .key(&signature.kid)
        .ok_or_else(|| PortError::rejected(format!("signer {} is not trusted", signature.kid)))?;
    let sig_bytes = hex::decode(&signature.signature)
        .map_err(|_| PortError::invalid("pack signature is not hex"))?;
    verify_ed25519(key, &signing_message(pack_sha256), &sig_bytes)
}

/// Reads `<pack_path>.sig` and verifies it against the pack's digest.
pub fn verify_pack_file(
    pack_path: &Path,
    pack_sha256: &str,
    trusted: &TrustedSigners,
) -> Result<(), PortError> {
    let sig_path = signature_path(pack_path);
    let text = std::fs::read_to_string(&sig_path).map_err(|_| {
        PortError::rejected(format!("pack signature missing: {}", sig_path.display()))
    })?;
    let signature: PackSignature = serde_json::from_str(&text)
        .map_err(|e| PortError::invalid(format!("pack signature {}: {e}", sig_path.display())))?;
    verify_pack_signature(&signature, pack_sha256, trusted)
}
