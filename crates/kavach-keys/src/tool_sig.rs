//! Detached tool-registry signatures (H5b).
//!
//! The tool registry decides which agent parameters are reference-only and
//! which values are allowed, so it is security-critical configuration.
//! `<registry>.sig` covers the file's SHA-256 under a prefix distinct from
//! packs and models; only signers with the `tool` role are accepted.

use std::path::Path;

use kavach_ports::{verify_ed25519, KeyProvider, PortError};
use serde::{Deserialize, Serialize};

use crate::pack_sig::{signature_path, SignerRole, TrustedSigners};

const SIGNATURE_VERSION: u32 = 1;
const MESSAGE_PREFIX: &[u8] = b"kavach-tool-registry-signature-v1:";

/// Detached signature envelope stored at `<registry path>.sig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRegistrySignature {
    pub version: u32,
    pub alg: String,
    pub kid: String,
    pub registry_sha256: String,
    /// Hex-encoded 64-byte Ed25519 signature.
    pub signature: String,
}

fn signing_message(registry_sha256: &str) -> Vec<u8> {
    let mut message = MESSAGE_PREFIX.to_vec();
    message.extend_from_slice(registry_sha256.as_bytes());
    message
}

/// Signs a tool registry whose file digest is `registry_sha256`.
pub async fn sign_tool_registry<K: KeyProvider>(
    provider: &K,
    kid: &str,
    registry_sha256: &str,
) -> Result<ToolRegistrySignature, PortError> {
    let signature = provider
        .sign(kid, &signing_message(registry_sha256))
        .await?;
    Ok(ToolRegistrySignature {
        version: SIGNATURE_VERSION,
        alg: "EdDSA".into(),
        kid: kid.to_string(),
        registry_sha256: registry_sha256.to_string(),
        signature: hex::encode(signature),
    })
}

/// Verifies `signature` for a registry whose file digest is `registry_sha256`.
pub fn verify_tool_registry_signature(
    signature: &ToolRegistrySignature,
    registry_sha256: &str,
    trusted: &TrustedSigners,
) -> Result<(), PortError> {
    if signature.version != SIGNATURE_VERSION || signature.alg != "EdDSA" {
        return Err(PortError::invalid(format!(
            "unsupported tool registry signature version {} / alg {}",
            signature.version, signature.alg
        )));
    }
    if signature.registry_sha256 != registry_sha256 {
        return Err(PortError::rejected(format!(
            "signature covers {}, tool registry is {registry_sha256}",
            signature.registry_sha256
        )));
    }
    let key = trusted.key(&signature.kid, SignerRole::Tool)?;
    let sig_bytes = hex::decode(&signature.signature)
        .map_err(|_| PortError::invalid("tool registry signature is not hex"))?;
    verify_ed25519(key, &signing_message(registry_sha256), &sig_bytes)
}

/// Reads `<registry_path>.sig` and verifies it against the registry's digest.
pub fn verify_tool_registry_file(
    registry_path: &Path,
    registry_sha256: &str,
    trusted: &TrustedSigners,
) -> Result<(), PortError> {
    let sig_path = signature_path(registry_path);
    let text = std::fs::read_to_string(&sig_path).map_err(|_| {
        PortError::rejected(format!(
            "tool registry signature missing: {}",
            sig_path.display()
        ))
    })?;
    let signature: ToolRegistrySignature = serde_json::from_str(&text).map_err(|e| {
        PortError::invalid(format!(
            "tool registry signature {}: {e}",
            sig_path.display()
        ))
    })?;
    verify_tool_registry_signature(&signature, registry_sha256, trusted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryKeyProvider;
    use kavach_ports::PublicKey;

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000001";

    fn trusted(public: &PublicKey, roles: &[&str]) -> TrustedSigners {
        TrustedSigners::from_json(
            &serde_json::json!({ "signers": [{
                "kid": public.kid,
                "public_key": hex::encode(public.bytes),
                "roles": roles,
            }]})
            .to_string(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn registry_signatures_bind_digest_prefix_and_tool_role() {
        let mut provider = InMemoryKeyProvider::new();
        let public = provider.generate("signer-1").unwrap();
        let signature = sign_tool_registry(&provider, "signer-1", DIGEST)
            .await
            .unwrap();
        let tool_signer = trusted(&public, &["tool"]);
        verify_tool_registry_signature(&signature, DIGEST, &tool_signer).unwrap();

        // Another file: refused.
        let other = DIGEST.replace("01", "02");
        assert!(verify_tool_registry_signature(&signature, &other, &tool_signer).is_err());

        // A signer without the tool role: refused.
        let err = verify_tool_registry_signature(
            &signature,
            DIGEST,
            &trusted(&public, &["pack", "model"]),
        )
        .unwrap_err();
        assert!(err.message.contains("tool registries"), "{}", err.message);

        // A tampered signature: refused.
        let mut tampered = signature.clone();
        let flipped = if tampered.signature.starts_with('0') {
            "1"
        } else {
            "0"
        };
        tampered.signature.replace_range(0..1, flipped);
        assert!(verify_tool_registry_signature(&tampered, DIGEST, &tool_signer).is_err());

        // A signature over the same digest under another prefix (as a pack
        // signer would produce) does not pass as a registry signature.
        let foreign = provider
            .sign(
                "signer-1",
                &[b"kavach-pack-signature-v1:".as_slice(), DIGEST.as_bytes()].concat(),
            )
            .await
            .unwrap();
        let forged = ToolRegistrySignature {
            signature: hex::encode(foreign),
            ..signature
        };
        assert!(verify_tool_registry_signature(&forged, DIGEST, &tool_signer).is_err());
    }
}
