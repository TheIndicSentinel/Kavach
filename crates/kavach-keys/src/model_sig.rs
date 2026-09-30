//! Detached model-record signatures (H3b).
//!
//! `<model.yaml>.sig` covers the model id, version and file SHA-256 under a
//! message prefix distinct from packs, so a pack signature can never pass as
//! a model signature, and signing a version is explicit. Only signers with
//! the `model` role are accepted.

use std::path::Path;

use kavach_ports::{verify_ed25519, KeyProvider, PortError};
use serde::{Deserialize, Serialize};

use crate::pack_sig::{signature_path, SignerRole, TrustedSigners};

const SIGNATURE_VERSION: u32 = 1;
const MESSAGE_PREFIX: &[u8] = b"kavach-model-signature-v1:";

/// Detached signature envelope stored at `<model path>.sig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSignature {
    pub version: u32,
    pub alg: String,
    pub kid: String,
    pub model_id: String,
    pub model_version: String,
    pub model_sha256: String,
    /// Hex-encoded 64-byte Ed25519 signature.
    pub signature: String,
}

/// Identity of the signed model file.
#[derive(Debug, Clone, Copy)]
pub struct ModelIdentity<'a> {
    pub model_id: &'a str,
    pub model_version: &'a str,
    pub model_sha256: &'a str,
}

fn signing_message(identity: ModelIdentity<'_>) -> Vec<u8> {
    let mut message = MESSAGE_PREFIX.to_vec();
    for (i, part) in [
        identity.model_id,
        identity.model_version,
        identity.model_sha256,
    ]
    .iter()
    .enumerate()
    {
        if i > 0 {
            message.push(b'\n');
        }
        message.extend_from_slice(part.as_bytes());
    }
    message
}

/// Signs a model file whose identity the caller has read from it.
pub async fn sign_model<K: KeyProvider>(
    provider: &K,
    kid: &str,
    identity: ModelIdentity<'_>,
) -> Result<ModelSignature, PortError> {
    if identity.model_id.contains('\n') || identity.model_version.contains('\n') {
        return Err(PortError::invalid(
            "model id and version must be single-line",
        ));
    }
    let signature = provider.sign(kid, &signing_message(identity)).await?;
    Ok(ModelSignature {
        version: SIGNATURE_VERSION,
        alg: "EdDSA".into(),
        kid: kid.to_string(),
        model_id: identity.model_id.into(),
        model_version: identity.model_version.into(),
        model_sha256: identity.model_sha256.into(),
        signature: hex::encode(signature),
    })
}

/// Verifies `signature` against the identity of the file being loaded.
pub fn verify_model_signature(
    signature: &ModelSignature,
    identity: ModelIdentity<'_>,
    trusted: &TrustedSigners,
) -> Result<(), PortError> {
    if signature.version != SIGNATURE_VERSION || signature.alg != "EdDSA" {
        return Err(PortError::invalid(format!(
            "unsupported model signature version {} / alg {}",
            signature.version, signature.alg
        )));
    }
    if signature.model_id != identity.model_id
        || signature.model_version != identity.model_version
        || signature.model_sha256 != identity.model_sha256
    {
        return Err(PortError::rejected(format!(
            "signature covers {} {} {}, file is {} {} {}",
            signature.model_id,
            signature.model_version,
            signature.model_sha256,
            identity.model_id,
            identity.model_version,
            identity.model_sha256
        )));
    }
    let key = trusted.key(&signature.kid, SignerRole::Model)?;
    let sig_bytes = hex::decode(&signature.signature)
        .map_err(|_| PortError::invalid("model signature is not hex"))?;
    verify_ed25519(key, &signing_message(identity), &sig_bytes)
}

/// Reads `<model_path>.sig` and verifies it against the file's identity.
pub fn verify_model_file(
    model_path: &Path,
    identity: ModelIdentity<'_>,
    trusted: &TrustedSigners,
) -> Result<(), PortError> {
    let sig_path = signature_path(model_path);
    let text = std::fs::read_to_string(&sig_path).map_err(|_| {
        PortError::rejected(format!("model signature missing: {}", sig_path.display()))
    })?;
    let signature: ModelSignature = serde_json::from_str(&text)
        .map_err(|e| PortError::invalid(format!("model signature {}: {e}", sig_path.display())))?;
    verify_model_signature(&signature, identity, trusted)
}
