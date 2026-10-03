//! Compact JWE (RFC 7516) for one recipient: `alg: ECDH-ES` (direct key
//! agreement, RFC 7518 §4.6) on X25519 (RFC 8037), `enc: A256GCM`
//! (RFC 7518 §5.3). Interoperable with standard JOSE libraries (Nimbus,
//! jose, go-jose), so a real provider can decrypt without Kavach code.
//!
//! The protected header is the only header (no unprotected parts), the
//! encrypted key is empty (direct agreement), and the header must name the
//! recipient's `kid`. An ephemeral key is generated per token, so two tokens
//! never share a content key.

use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use kavach_ports::PortError;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroizing;

pub const ALG: &str = "ECDH-ES";
pub const ENC: &str = "A256GCM";
/// Largest accepted JWE (the nested credential is far smaller).
pub const MAX_JWE_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Epk {
    kty: String,
    crv: String,
    x: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    enc: String,
    epk: Epk,
    kid: String,
    typ: String,
    cty: String,
}

/// A recipient's public encryption key (X25519).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKey {
    pub kid: String,
    pub public: [u8; 32],
}

/// A recipient's private encryption key. Never printed.
pub struct DecryptionKey {
    kid: String,
    secret: StaticSecret,
}

impl fmt::Debug for DecryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecryptionKey({}, <redacted>)", self.kid)
    }
}

impl DecryptionKey {
    pub fn from_bytes(kid: impl Into<String>, secret: [u8; 32]) -> Self {
        Self {
            kid: kid.into(),
            secret: StaticSecret::from(secret),
        }
    }

    /// A fresh random key (providers generate their own).
    pub fn generate(kid: impl Into<String>) -> Result<Self, PortError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut())
            .map_err(|e| PortError::unavailable(format!("os rng: {e}")))?;
        Ok(Self::from_bytes(kid, *bytes))
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public half, to configure in Kavach.
    pub fn recipient(&self) -> RecipientKey {
        RecipientKey {
            kid: self.kid.clone(),
            public: X25519Public::from(&self.secret).to_bytes(),
        }
    }
}

/// Concat KDF (NIST SP 800-56A, RFC 7518 §4.6.2), one SHA-256 round
/// (`key_bits` ≤ 256).
pub fn concat_kdf(z: &[u8], algorithm_id: &str, apu: &[u8], apv: &[u8], key_bits: u32) -> Vec<u8> {
    let field = |bytes: &[u8]| {
        let mut out = u32::try_from(bytes.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(bytes);
        out
    };
    let mut hasher = Sha256::new();
    hasher.update(1u32.to_be_bytes());
    hasher.update(z);
    hasher.update(field(algorithm_id.as_bytes()));
    hasher.update(field(apu));
    hasher.update(field(apv));
    hasher.update(key_bits.to_be_bytes());
    let digest = hasher.finalize();
    digest[..(key_bits as usize / 8)].to_vec()
}

fn content_key(shared: &[u8; 32]) -> Result<LessSafeKey, PortError> {
    let cek = Zeroizing::new(concat_kdf(shared, ENC, &[], &[], 256));
    let unbound = UnboundKey::new(&AES_256_GCM, &cek)
        .map_err(|_| PortError::invalid("content encryption key"))?;
    Ok(LessSafeKey::new(unbound))
}

/// Encrypts `plaintext` to `recipient`. `typ` and `cty` are the explicit
/// token and content types (RFC 8725 §3.11).
pub fn encrypt(
    plaintext: &[u8],
    recipient: &RecipientKey,
    typ: &str,
    cty: &str,
) -> Result<String, PortError> {
    // Ephemeral: fresh random bytes per token, dropped (and zeroised) here.
    let ephemeral = DecryptionKey::generate("ephemeral")?.secret;
    let epk = X25519Public::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&X25519Public::from(recipient.public));
    if !shared.was_contributory() {
        return Err(PortError::invalid("recipient key is a low-order point"));
    }
    let header = Header {
        alg: ALG.into(),
        enc: ENC.into(),
        epk: Epk {
            kty: "OKP".into(),
            crv: "X25519".into(),
            x: URL_SAFE_NO_PAD.encode(epk.as_bytes()),
        },
        kid: recipient.kid.clone(),
        typ: typ.into(),
        cty: cty.into(),
    };
    let header_b64 = URL_SAFE_NO_PAD.encode(kavach_ports::jcs::to_vec(&header)?);
    let mut iv = [0u8; NONCE_LEN];
    getrandom::fill(&mut iv).map_err(|e| PortError::unavailable(format!("os rng: {e}")))?;
    let key = content_key(shared.as_bytes())?;
    let mut buffer = plaintext.to_vec();
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(iv),
            Aad::from(header_b64.as_bytes()),
            &mut buffer,
        )
        .map_err(|_| PortError::invalid("jwe encryption failed"))?;
    Ok(format!(
        "{header_b64}..{}.{}.{}",
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(&buffer),
        URL_SAFE_NO_PAD.encode(tag.as_ref())
    ))
}

fn b64d(part: &str, what: &str) -> Result<Vec<u8>, PortError> {
    URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| PortError::invalid(format!("jwe {what}: invalid base64url")))
}

/// Decrypts a JWE addressed to `key`, requiring the given `typ` and `cty`.
/// Any failure to authenticate is `Rejected`; a malformed token is `Invalid`.
pub fn decrypt(
    token: &str,
    key: &DecryptionKey,
    typ: &str,
    cty: &str,
) -> Result<Zeroizing<Vec<u8>>, PortError> {
    if token.len() > MAX_JWE_BYTES {
        return Err(PortError::invalid("jwe exceeds size limit"));
    }
    let parts: Vec<&str> = token.split('.').collect();
    let [h64, encrypted_key, iv64, ct64, tag64] = parts.as_slice() else {
        return Err(PortError::invalid("jwe must have five parts"));
    };
    if !encrypted_key.is_empty() {
        return Err(PortError::invalid("jwe: ECDH-ES carries no encrypted key"));
    }
    let header: Header = serde_json::from_slice(&b64d(h64, "header")?)
        .map_err(|e| PortError::invalid(format!("jwe header: {e}")))?;
    if header.alg != ALG || header.enc != ENC {
        return Err(PortError::invalid(format!(
            "unsupported jwe alg/enc {}/{}",
            header.alg, header.enc
        )));
    }
    if header.typ != typ || header.cty != cty {
        return Err(PortError::invalid("unexpected jwe typ or cty"));
    }
    if header.kid != key.kid {
        return Err(PortError::rejected("jwe is for another recipient key"));
    }
    if header.epk.kty != "OKP" || header.epk.crv != "X25519" {
        return Err(PortError::invalid("jwe epk must be an X25519 OKP key"));
    }
    let epk: [u8; 32] = b64d(&header.epk.x, "epk")?
        .try_into()
        .map_err(|_| PortError::invalid("jwe epk must be 32 bytes"))?;
    let shared = key.secret.diffie_hellman(&X25519Public::from(epk));
    if !shared.was_contributory() {
        return Err(PortError::rejected("jwe epk is a low-order point"));
    }
    let iv: [u8; NONCE_LEN] = b64d(iv64, "iv")?
        .try_into()
        .map_err(|_| PortError::invalid("jwe iv must be 96 bits"))?;
    let mut buffer = Zeroizing::new(b64d(ct64, "ciphertext")?);
    let tag = b64d(tag64, "tag")?;
    if tag.len() != 16 {
        return Err(PortError::invalid("jwe tag must be 128 bits"));
    }
    buffer.extend_from_slice(&tag);
    let opened_len = content_key(shared.as_bytes())?
        .open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(h64.as_bytes()),
            &mut buffer,
        )
        .map_err(|_| PortError::rejected("jwe does not authenticate"))?
        .len();
    buffer.truncate(opened_len);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7518 Appendix C: the Concat KDF example (A128GCM, apu "Alice",
    /// apv "Bob").
    #[test]
    fn concat_kdf_matches_rfc7518_appendix_c() {
        let z: [u8; 32] = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        let key = concat_kdf(&z, "A128GCM", b"Alice", b"Bob", 128);
        assert_eq!(URL_SAFE_NO_PAD.encode(key), "VqqN6vgjbSBcIijNcacQGg");
    }

    fn hex32(text: &str) -> [u8; 32] {
        hex::decode(text).unwrap().try_into().unwrap()
    }

    /// RFC 8037 Appendix A.6 (the RFC 7748 §6.1 keys): the recipient's
    /// static key, the ephemeral key and the agreed secret.
    #[test]
    fn x25519_matches_rfc8037_appendix_a6() {
        let bob = DecryptionKey::from_bytes(
            "bob",
            hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
        );
        let bob_public = bob.recipient().public;
        assert_eq!(
            URL_SAFE_NO_PAD.encode(bob_public),
            "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
        );
        let ephemeral = StaticSecret::from(hex32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let epk = X25519Public::from(&ephemeral);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(epk.as_bytes()),
            "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
        );
        let z = bob.secret.diffie_hellman(&epk);
        assert_eq!(
            hex::encode(z.as_bytes()),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
        // And both sides agree.
        let z2 = ephemeral.diffie_hellman(&X25519Public::from(bob_public));
        assert_eq!(z.as_bytes(), z2.as_bytes());
    }

    fn key(kid: &str, seed: u8) -> DecryptionKey {
        DecryptionKey::from_bytes(kid, [seed; 32])
    }

    #[test]
    fn round_trip_and_fresh_ephemeral_keys() {
        let provider = key("p-1", 9);
        let a = encrypt(b"secret", &provider.recipient(), "t", "c").unwrap();
        let b = encrypt(b"secret", &provider.recipient(), "t", "c").unwrap();
        assert_ne!(a, b, "fresh epk and iv per token");
        assert_eq!(&*decrypt(&a, &provider, "t", "c").unwrap(), b"secret");
        assert!(!a.contains("secret"));
        assert_eq!(a.split('.').nth(1), Some(""), "no encrypted key");
    }

    #[test]
    fn refuses_other_recipients_tampering_and_header_changes() {
        let provider = key("p-1", 9);
        let token = encrypt(b"secret", &provider.recipient(), "t", "c").unwrap();

        // Another provider's key, even under the same kid.
        assert!(decrypt(&token, &key("p-1", 10), "t", "c").is_err());
        assert_eq!(
            decrypt(&token, &key("p-2", 9), "t", "c").unwrap_err().class,
            kavach_ports::ErrorClass::Rejected
        );
        // Wrong expected types.
        assert!(decrypt(&token, &provider, "other", "c").is_err());
        assert!(decrypt(&token, &provider, "t", "other").is_err());

        let parts: Vec<&str> = token.split('.').collect();
        let with = |i: usize, value: &str| {
            let mut p: Vec<String> = parts.iter().map(|s| (*s).to_string()).collect();
            p[i] = value.to_string();
            p.join(".")
        };
        // Flipped ciphertext or tag bit: does not authenticate.
        let mut ct = b64d(parts[3], "ct").unwrap();
        ct[0] ^= 1;
        let err = decrypt(&with(3, &URL_SAFE_NO_PAD.encode(&ct)), &provider, "t", "c").unwrap_err();
        assert_eq!(err.class, kavach_ports::ErrorClass::Rejected);
        let mut tag = b64d(parts[4], "tag").unwrap();
        tag[0] ^= 1;
        assert!(decrypt(&with(4, &URL_SAFE_NO_PAD.encode(&tag)), &provider, "t", "c").is_err());
        // A rewritten header (it is the AAD) does not authenticate either,
        // even when every field still passes the checks.
        let mut header: Header = serde_json::from_slice(&b64d(parts[0], "h").unwrap()).unwrap();
        header.epk.x = URL_SAFE_NO_PAD.encode(key("e", 3).recipient().public);
        let forged = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        assert!(decrypt(&with(0, &forged), &provider, "t", "c").is_err());
        // A low-order epk (all zeros) is refused.
        header.epk.x = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let low = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        assert!(decrypt(&with(0, &low), &provider, "t", "c")
            .unwrap_err()
            .message
            .contains("low-order"));
        // An encrypted key where none belongs.
        assert!(decrypt(&with(1, "AAAA"), &provider, "t", "c").is_err());
        assert_eq!(
            format!("{provider:?}"),
            "DecryptionKey(p-1, <redacted>)",
            "keys never print"
        );
    }
}
