use std::future::Future;

use ed25519_dalek::{Signature, VerifyingKey};

use crate::error::PortError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Ed25519,
}

/// Public half of a signing key, identified by `kid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub kid: String,
    pub algorithm: KeyAlgorithm,
    pub bytes: [u8; 32],
}

/// Signing keys addressed by key id (ADR-006 §4). Private key material never
/// leaves the provider; callers get signatures and public keys only.
pub trait KeyProvider: Send + Sync {
    /// Signs `message` with key `kid`. Unknown `kid` → `Rejected`.
    fn sign(
        &self,
        kid: &str,
        message: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send;

    /// Returns the public key for `kid`. Unknown `kid` → `Rejected`.
    fn public_key(&self, kid: &str) -> impl Future<Output = Result<PublicKey, PortError>> + Send;
}

/// Verifies an Ed25519 signature with strict (non-malleable) verification.
/// Anyone holding the public key can verify; no provider is needed.
pub fn verify_ed25519(key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<(), PortError> {
    let KeyAlgorithm::Ed25519 = key.algorithm;
    let verifying = VerifyingKey::from_bytes(&key.bytes)
        .map_err(|e| PortError::invalid(format!("public key {}: {e}", key.kid)))?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| PortError::invalid("ed25519 signature must be 64 bytes"))?;
    verifying
        .verify_strict(message, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| PortError::rejected(format!("signature does not verify for {}", key.kid)))
}
