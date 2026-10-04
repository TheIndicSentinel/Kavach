//! Where each signing key lives: an owner-only key file, or an HSM through
//! its PKCS#11 module (KMS milestone, K2). Each role is chosen on its own
//! (`--hsm-keys`); roles not listed keep their key files.
//!
//! - With an HSM, every listed key is found by its key id (the HSM label),
//!   checked and proven at startup (`kavach-keys-pkcs11`). Outside
//!   `--insecure-dev` a key must have been generated in the HSM and never
//!   been readable; with `--insecure-dev` only that check is relaxed.
//! - A signing failure in the HSM fails closed: the decision that needed
//!   the signature is a BLOCK, and nothing is forwarded.
//! - `/v1/runtime` reports which roles are in the HSM and whether it
//!   answers now ([`KeySources::status`]).

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use kavach_keys::{Ed25519EvidenceSigner, LocalFileKeyProvider};
use kavach_keys_pkcs11::{read_pin_file, Pkcs11Config, Pkcs11KeyProvider};
use kavach_ports::agent_evidence::EvidenceSigner;
use kavach_ports::{KeyProvider, PortError, PublicKey};
use serde::Serialize;

/// A signing role whose key may live in an HSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HsmRole {
    Mandate,
    Evidence,
    Checkpoint,
    Credential,
}

impl HsmRole {
    pub const ALL: [Self; 4] = [
        Self::Mandate,
        Self::Evidence,
        Self::Checkpoint,
        Self::Credential,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mandate => "mandate",
            Self::Evidence => "evidence",
            Self::Checkpoint => "checkpoint",
            Self::Credential => "credential",
        }
    }
}

impl fmt::Display for HsmRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HsmRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|r| r.as_str() == s.trim())
            .ok_or_else(|| {
                format!("unknown HSM key role {s:?} (mandate, evidence, checkpoint, credential)")
            })
    }
}

/// The HSM and the roles whose keys live in it.
#[derive(Debug, Clone)]
pub struct HsmConfig {
    /// The vendor's PKCS#11 module (`.so`).
    pub module: PathBuf,
    pub token_label: String,
    /// Owner-only file holding the token's user PIN.
    pub pin_file: PathBuf,
    pub roles: BTreeSet<HsmRole>,
    /// Sessions kept open for reuse.
    pub max_sessions: usize,
}

/// A key provider backed by a key file or the HSM.
pub enum SigningKeys {
    File(LocalFileKeyProvider),
    Hsm(Pkcs11KeyProvider),
}

impl fmt::Debug for SigningKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::File(_) => "SigningKeys::File",
            Self::Hsm(_) => "SigningKeys::Hsm",
        })
    }
}

impl KeyProvider for SigningKeys {
    async fn sign(&self, kid: &str, message: &[u8]) -> Result<Vec<u8>, PortError> {
        match self {
            Self::File(keys) => keys.sign(kid, message).await,
            Self::Hsm(keys) => keys.sign(kid, message).await,
        }
    }

    async fn public_key(&self, kid: &str) -> Result<PublicKey, PortError> {
        match self {
            Self::File(keys) => keys.public_key(kid).await,
            Self::Hsm(keys) => keys.public_key(kid).await,
        }
    }
}

/// What `/v1/runtime` says about the HSM.
#[derive(Debug, Clone, Serialize)]
pub struct HsmStatus {
    pub roles: Vec<HsmRole>,
    /// Whether the HSM answered just now (it reconnects on its own).
    pub healthy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The HSM, when one is configured, and which roles use it.
pub struct KeySources {
    hsm: Option<(Pkcs11KeyProvider, BTreeSet<HsmRole>)>,
}

impl fmt::Debug for KeySources {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySources")
            .field("hsm_roles", &self.hsm.as_ref().map(|(_, roles)| roles))
            .finish()
    }
}

impl KeySources {
    /// Key files only.
    #[must_use]
    pub fn files() -> Self {
        Self { hsm: None }
    }

    /// Opens the HSM for the listed roles: loads, checks and proves each
    /// role's key (`kid_of(role)`). Strict about how keys were made unless
    /// `insecure_dev`.
    pub fn open(
        hsm: &HsmConfig,
        kid_of: impl Fn(HsmRole) -> String,
        insecure_dev: bool,
    ) -> Result<Self, String> {
        if hsm.roles.is_empty() {
            return Err("--hsm-keys lists no role".into());
        }
        let pin = read_pin_file(&hsm.pin_file).map_err(|e| e.message)?;
        let provider = Pkcs11KeyProvider::open(Pkcs11Config {
            module: hsm.module.clone(),
            token_label: hsm.token_label.clone(),
            pin,
            key_ids: hsm.roles.iter().map(|r| kid_of(*r)).collect(),
            max_sessions: hsm.max_sessions,
            require_hsm_generated: !insecure_dev,
        })
        .map_err(|e| format!("HSM: {}", e.message))?;
        if insecure_dev {
            tracing::warn!(
                "--insecure-dev: HSM keys are not required to have been generated in the HSM. \
                 Development only."
            );
        }
        Ok(Self {
            hsm: Some((provider, hsm.roles.clone())),
        })
    }

    fn hsm_for(&self, role: HsmRole) -> Option<&Pkcs11KeyProvider> {
        self.hsm
            .as_ref()
            .filter(|(_, roles)| roles.contains(&role))
            .map(|(provider, _)| provider)
    }

    /// A key provider for `role`: the HSM, or the key files in `dir`.
    #[must_use]
    pub fn keys(&self, role: HsmRole, dir: &Path) -> SigningKeys {
        match self.hsm_for(role) {
            Some(provider) => SigningKeys::Hsm(provider.clone()),
            None => SigningKeys::File(LocalFileKeyProvider::new(dir)),
        }
    }

    /// A synchronous signer (evidence records, checkpoints) for `role`.
    pub fn evidence_signer(
        &self,
        role: HsmRole,
        dir: &Path,
        kid: &str,
    ) -> Result<Box<dyn EvidenceSigner>, String> {
        match self.hsm_for(role) {
            Some(provider) => Ok(Box::new(
                provider
                    .evidence_signer(kid)
                    .map_err(|e| format!("{role} key: {}", e.message))?,
            )),
            None => Ok(Box::new(
                Ed25519EvidenceSigner::from_key_dir(dir, kid)
                    .map_err(|e| format!("{role} key: {e}"))?,
            )),
        }
    }

    /// The public key of `role`'s key, wherever it lives.
    pub async fn public_key(
        &self,
        role: HsmRole,
        dir: &Path,
        kid: &str,
    ) -> Result<PublicKey, String> {
        self.keys(role, dir)
            .public_key(kid)
            .await
            .map_err(|e| format!("{role} key: {}", e.message))
    }

    /// For `/v1/runtime`: the roles in the HSM and whether it answers now.
    /// `None` without an HSM.
    pub async fn status(&self) -> Option<HsmStatus> {
        let (provider, roles) = self.hsm.as_ref()?;
        let provider = provider.clone();
        let health = tokio::task::spawn_blocking(move || provider.health())
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r.map_err(|e| e.message));
        Some(HsmStatus {
            roles: roles.iter().copied().collect(),
            healthy: health.is_ok(),
            error: health.err(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_parse_by_name_only() {
        for role in HsmRole::ALL {
            assert_eq!(role.as_str().parse::<HsmRole>(), Ok(role));
        }
        assert!("Mandate".parse::<HsmRole>().is_err());
        assert!("subject".parse::<HsmRole>().is_err());
    }

    #[tokio::test]
    async fn without_an_hsm_every_role_uses_its_key_files() {
        let sources = KeySources::files();
        for role in HsmRole::ALL {
            assert!(matches!(
                sources.keys(role, Path::new("/nonexistent")),
                SigningKeys::File(_)
            ));
        }
        assert!(sources.status().await.is_none());
    }
}
