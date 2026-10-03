//! Minimal, strict JWS compact serialisation (RFC 7515) for Kavach tokens
//! (mandates, system-of-record events, broker credentials). A verifier such
//! as a resource provider depends on this crate alone, not on the mandate
//! service.
//!
//! - `alg` must be `EdDSA` (Ed25519, RFC 8037); `typ` must match exactly;
//!   `kid` is required and must be in the supplied key set.
//! - Header and payload are RFC 8785 (JCS) canonical JSON; a token whose
//!   header or payload is not in canonical form is rejected, so every token
//!   has exactly one valid encoding.
//! - base64url without padding; trailing bits and padding are rejected.
//! - The signature is verified before the payload is parsed.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use kavach_ports::{verify_ed25519, KeyProvider, PortError, PublicKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Maximum accepted token size.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    typ: String,
}

/// Verification keys by key id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeySet {
    keys: BTreeMap<String, PublicKey>,
}

impl KeySet {
    pub fn new(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            keys: keys.into_iter().map(|k| (k.kid.clone(), k)).collect(),
        }
    }

    pub fn get(&self, kid: &str) -> Option<&PublicKey> {
        self.keys.get(kid)
    }
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, PortError> {
    kavach_ports::jcs::to_vec(value)
}

fn b64d(part: &str, what: &str) -> Result<Vec<u8>, PortError> {
    URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| PortError::invalid(format!("{what}: invalid base64url")))
}

/// Signs `payload` as a compact JWS with key `kid` and the given `typ`.
pub async fn sign<T: Serialize, K: KeyProvider>(
    provider: &K,
    kid: &str,
    typ: &str,
    payload: &T,
) -> Result<String, PortError> {
    let header = canonical(&Header {
        alg: "EdDSA".into(),
        kid: kid.into(),
        typ: typ.into(),
    })?;
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(canonical(payload)?)
    );
    let signature = provider.sign(kid, signing_input.as_bytes()).await?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

/// Verifies a compact JWS and returns the signing key id and the payload.
pub fn verify<T: DeserializeOwned + Serialize>(
    token: &str,
    typ: &str,
    keys: &KeySet,
) -> Result<(String, T), PortError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(PortError::invalid("token exceeds size limit"));
    }
    let parts: Vec<&str> = token.split('.').collect();
    let [h64, p64, s64] = parts.as_slice() else {
        return Err(PortError::invalid("token must have three parts"));
    };

    let header_bytes = b64d(h64, "header")?;
    let header: Header = serde_json::from_slice(&header_bytes)
        .map_err(|e| PortError::invalid(format!("header: {e}")))?;
    if header.alg != "EdDSA" {
        return Err(PortError::invalid(format!(
            "unsupported alg {}",
            header.alg
        )));
    }
    if header.typ != typ {
        return Err(PortError::invalid(format!(
            "unexpected typ {}, expected {typ}",
            header.typ
        )));
    }
    if canonical(&header)? != header_bytes {
        return Err(PortError::invalid("header is not canonical JSON"));
    }
    let key = keys
        .get(&header.kid)
        .ok_or_else(|| PortError::rejected(format!("unknown signing key {}", header.kid)))?;
    let signature = b64d(s64, "signature")?;
    verify_ed25519(key, format!("{h64}.{p64}").as_bytes(), &signature)?;

    let payload_bytes = b64d(p64, "payload")?;
    let payload: T = serde_json::from_slice(&payload_bytes)
        .map_err(|e| PortError::invalid(format!("payload: {e}")))?;
    if canonical(&payload)? != payload_bytes {
        return Err(PortError::invalid("payload is not canonical JSON"));
    }
    Ok((header.kid, payload))
}
