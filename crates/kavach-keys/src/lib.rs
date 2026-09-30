//! `KeyProvider` adapters (ADR-006 §4).
//!
//! - [`LocalFileKeyProvider`]: Ed25519 seeds in owner-only files, one per key id.
//! - [`InMemoryKeyProvider`]: keys held in memory (tests, ephemeral CI keys).
//!
//! Encryption at rest and HSM/KMS providers arrive with M2 / Stage 2.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::future::{ready, Future};
use std::path::{Path, PathBuf};

mod model_sig;
mod pack_sig;

pub use model_sig::{
    sign_model, verify_model_file, verify_model_signature, ModelIdentity, ModelSignature,
};
pub use pack_sig::{
    sign_pack, signature_path, verify_pack_file, verify_pack_signature, PackSignature, SignerRole,
    TrustedSigners,
};

use ed25519_dalek::{Signer, SigningKey};
use kavach_ports::{KeyAlgorithm, KeyProvider, PortError, PublicKey};

const KEY_FILE_EXT: &str = "ed25519";

/// Key ids are restricted so they can never escape the key directory.
pub fn validate_kid(kid: &str) -> Result<(), PortError> {
    let ok = !kid.is_empty()
        && kid.len() <= 128
        && !kid.starts_with('.')
        && kid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(())
    } else {
        Err(PortError::invalid(format!("invalid key id: {kid:?}")))
    }
}

fn public_key_of(kid: &str, key: &SigningKey) -> PublicKey {
    PublicKey {
        kid: kid.to_string(),
        algorithm: KeyAlgorithm::Ed25519,
        bytes: key.verifying_key().to_bytes(),
    }
}

fn random_seed() -> Result<[u8; 32], PortError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| PortError::unavailable(format!("os rng: {e}")))?;
    Ok(seed)
}

/// Ed25519 keys held in memory.
#[derive(Default)]
pub struct InMemoryKeyProvider {
    keys: HashMap<String, SigningKey>,
}

impl fmt::Debug for InMemoryKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut kids: Vec<&String> = self.keys.keys().collect();
        kids.sort();
        f.debug_struct("InMemoryKeyProvider")
            .field("kids", &kids)
            .finish()
    }
}

impl InMemoryKeyProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a key from a fixed 32-byte seed (deterministic tests).
    pub fn insert_seed(&mut self, kid: &str, seed: [u8; 32]) -> Result<PublicKey, PortError> {
        validate_kid(kid)?;
        let key = SigningKey::from_bytes(&seed);
        let public = public_key_of(kid, &key);
        self.keys.insert(kid.to_string(), key);
        Ok(public)
    }

    /// Adds a freshly generated key (ephemeral CI signing).
    pub fn generate(&mut self, kid: &str) -> Result<PublicKey, PortError> {
        let seed = random_seed()?;
        self.insert_seed(kid, seed)
    }

    fn key(&self, kid: &str) -> Result<&SigningKey, PortError> {
        self.keys
            .get(kid)
            .ok_or_else(|| PortError::rejected(format!("unknown key id: {kid}")))
    }
}

impl KeyProvider for InMemoryKeyProvider {
    fn sign(
        &self,
        kid: &str,
        message: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send {
        ready(self.key(kid).map(|k| k.sign(message).to_bytes().to_vec()))
    }

    fn public_key(&self, kid: &str) -> impl Future<Output = Result<PublicKey, PortError>> + Send {
        ready(self.key(kid).map(|k| public_key_of(kid, k)))
    }
}

/// Ed25519 seeds stored as hex in `<dir>/<kid>.ed25519`, owner-only (0600)
/// on Unix. Keys are loaded on each call so rotation needs no restart.
#[derive(Debug, Clone)]
pub struct LocalFileKeyProvider {
    dir: PathBuf,
}

impl LocalFileKeyProvider {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path_for(&self, kid: &str) -> Result<PathBuf, PortError> {
        validate_kid(kid)?;
        Ok(self.dir.join(format!("{kid}.{KEY_FILE_EXT}")))
    }

    /// Generates a new key file. Fails if the key id already exists.
    pub fn create_key(&self, kid: &str) -> Result<PublicKey, PortError> {
        let path = self.path_for(kid)?;
        fs::create_dir_all(&self.dir)
            .map_err(|e| PortError::unavailable(format!("create key dir: {e}")))?;
        let seed = random_seed()?;
        write_owner_only(&path, hex::encode(seed).as_bytes())?;
        Ok(public_key_of(kid, &SigningKey::from_bytes(&seed)))
    }

    fn load(&self, kid: &str) -> Result<SigningKey, PortError> {
        let path = self.path_for(kid)?;
        if !path.is_file() {
            return Err(PortError::rejected(format!("unknown key id: {kid}")));
        }
        check_owner_only(&path)?;
        let text = fs::read_to_string(&path)
            .map_err(|e| PortError::unavailable(format!("read key {kid}: {e}")))?;
        let bytes = hex::decode(text.trim())
            .map_err(|_| PortError::invalid(format!("key {kid}: not hex")))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| PortError::invalid(format!("key {kid}: seed must be 32 bytes")))?;
        Ok(SigningKey::from_bytes(&seed))
    }
}

impl KeyProvider for LocalFileKeyProvider {
    fn sign(
        &self,
        kid: &str,
        message: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send {
        ready(self.load(kid).map(|k| k.sign(message).to_bytes().to_vec()))
    }

    fn public_key(&self, kid: &str) -> impl Future<Output = Result<PublicKey, PortError>> + Send {
        ready(self.load(kid).map(|k| public_key_of(kid, &k)))
    }
}

#[cfg(unix)]
fn write_owner_only(path: &Path, contents: &[u8]) -> Result<(), PortError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| PortError::rejected(format!("create key file {}: {e}", path.display())))?;
    file.write_all(contents)
        .map_err(|e| PortError::unavailable(format!("write key file: {e}")))
}

#[cfg(not(unix))]
fn write_owner_only(path: &Path, contents: &[u8]) -> Result<(), PortError> {
    if path.exists() {
        return Err(PortError::rejected(format!(
            "key file exists: {}",
            path.display()
        )));
    }
    fs::write(path, contents).map_err(|e| PortError::unavailable(format!("write key file: {e}")))
}

#[cfg(unix)]
fn check_owner_only(path: &Path) -> Result<(), PortError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|e| PortError::unavailable(format!("stat key file: {e}")))?
        .permissions()
        .mode();
    // Explicit mask kept for readability: no group (0o070) or other (0o007) bits.
    #[allow(clippy::verbose_bit_mask)]
    let owner_only = mode & 0o077 == 0;
    if owner_only {
        Ok(())
    } else {
        Err(PortError::rejected(format!(
            "key file {} must not be accessible by group/others (mode {:o})",
            path.display(),
            mode & 0o777
        )))
    }
}

#[cfg(not(unix))]
fn check_owner_only(_path: &Path) -> Result<(), PortError> {
    Ok(())
}
