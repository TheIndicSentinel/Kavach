//! **DEVELOPMENT ONLY.** Generates a complete Kavach development bundle:
//! everything a local or compose stack needs, with every key id prefixed
//! `dev-` so production startup and the offline verifier refuse it.
//!
//! Layout of `<out>/`:
//!
//! | Path | For | Contents |
//! |---|---|---|
//! | `kavach/keys/` | kavach-api | `dev-mandate-1`, `dev-evidence-1`, `dev-checkpoint-1`, `dev-credential-1` (owner-only) |
//! | `kavach/pseudonym.key` | kavach-api | subject pseudonym secret (owner-only) |
//! | `kavach/*.json`, `kavach/tools/` | kavach-api | mandate config, consents, references (synthetic numbers), providers, JWKS, signed tool registry, tool signers |
//! | `kavach/tls/ca.pem` | kavach-api | the dev CA the gateway trusts for providers |
//! | `kavach/kavach.env` | kavach-api | every setting, as environment variables |
//! | `provider/` | mock provider | X25519 encryption key, credential public keys, TLS certificate and key |
//! | `agents/<id>.jwt` | each agent | its access token (and nothing else) |
//! | `operator.jwt` | operators | an operator token |
//! | `sor/` | system of record | the event-signing key, used by `kavach-dev sor-event` |
//! | `signing/` | offline | the tool-registry signing key |
//!
//! Each consumer mounts only its own directory: an agent container gets its
//! token and no key material.

pub mod probe;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use kavach_credential::DecryptionKey;
use kavach_domain::mandate::{
    AgentPassport, ConsentRecord, ContactWindow, DelegationRules, MandateTemplate, SorEvent,
    TimeZoneId,
};
use kavach_keys::{sign_tool_registry, LocalFileKeyProvider};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const TENANT: &str = "default";
pub const ISSUER: &str = "https://idp.dev.kavach.local";
pub const OPERATOR_AUDIENCE: &str = "kavach-api";
pub const AGENT_AUDIENCE: &str = "kavach-agents";
pub const AGENTS: [&str; 2] = ["collections-agent", "translation-agent"];
pub const SUBJECT: &str = "ref:borrower:B-9382";
/// Synthetic: `+910…` is never an Indian mobile number.
pub const DESTINATION: &str = "+910000000001";
pub const PROVIDER_AUDIENCE: &str = "mock-messaging";

pub const MANDATE_KID: &str = "dev-mandate-1";
pub const EVIDENCE_KID: &str = "dev-evidence-1";
/// Signs evidence checkpoints and nothing else (ADR-005 §13).
pub const CHECKPOINT_KID: &str = "dev-checkpoint-1";
pub const CREDENTIAL_KID: &str = "dev-credential-1";
pub const TOOL_SIGNER_KID: &str = "dev-tool-signer-1";
pub const SOR_KID: &str = "dev-sor-issuer-1";
pub const IDP_KID: &str = "dev-idp-1";
pub const PROVIDER_KID: &str = "dev-provider-enc-1";

const REGISTRY: &str = include_str!("../../../tools/agent-tools.yaml");

#[derive(Debug, Clone)]
pub struct Options {
    pub out: PathBuf,
    /// Where `<out>/kavach` is mounted for kavach-api (paths in kavach.env).
    pub kavach_mount: String,
    /// The provider base URL the gateway forwards to (must be https).
    pub provider_endpoint: String,
    /// DNS names and IPs on the provider's TLS certificate.
    pub provider_hosts: Vec<String>,
    /// Lifetime of the minted access tokens.
    pub token_hours: i64,
}

fn random32() -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("os rng: {e}"))?;
    Ok(bytes)
}

/// Writes `contents`, owner-only on Unix (secrets).
fn write_secret(path: &Path, contents: &str) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut f| f.write_all(contents.as_bytes()))
        .map_err(|e| format!("write {}: {e}", path.display()))
}

fn write(path: &Path, contents: &str) -> Result<(), String> {
    std::fs::write(path, contents).map_err(|e| format!("write {}: {e}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    write(
        path,
        &(serde_json::to_string_pretty(value).unwrap_or_default() + "\n"),
    )
}

fn mkdir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|e| format!("mkdir {}: {e}", path.display()))
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(ToString::to_string).collect()
}

/// The collections mandate template (the PRD's loan-recovery slice).
pub fn template() -> MandateTemplate {
    MandateTemplate {
        tenant_id: TENANT.into(),
        event_type: "loan.dpd30".into(),
        purpose: "loan_recovery".into(),
        actions: set(&["read_fields", "send_reminder", "place_call", "propose_plan"]),
        data_fields: set(&["name", "overdue_amount", "loan_ref"]),
        channels: set(&["whatsapp", "voice"]),
        window: Some(ContactWindow {
            tz: TimeZoneId::AsiaKolkata,
            from_min: 8 * 60,
            to_min: 19 * 60,
            max_per_day: 3,
        }),
        ceilings: BTreeMap::from([("waiver_bps".to_string(), 1000)]),
        ttl_seconds: 7 * 24 * 3600,
        delegation: DelegationRules {
            max_depth: 1,
            allowed_agents: set(&["translation-agent"]),
        },
        eligible_agents: set(&["collections-agent"]),
    }
}

fn passport(agent: &str) -> AgentPassport {
    AgentPassport {
        agent_id: agent.into(),
        tenant_id: TENANT.into(),
        owner: "collections-ops".into(),
        allowed_purposes: set(&["loan_recovery"]),
        actions: set(&["read_fields", "send_reminder", "place_call", "propose_plan"]),
        data_fields: set(&["name", "overdue_amount", "loan_ref"]),
        ceilings: BTreeMap::from([("waiver_bps".to_string(), 1000)]),
    }
}

/// A JWT signed by the dev identity provider.
fn mint(seed: &[u8; 32], audience: &str, claims: Value, hours: i64) -> Result<String, String> {
    // PKCS#8 wrapper for a raw Ed25519 seed.
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(seed);
    let now = Utc::now().timestamp();
    let mut claims = claims;
    claims["iss"] = ISSUER.into();
    claims["aud"] = audience.into();
    claims["iat"] = now.into();
    claims["exp"] = (now + hours * 3600).into();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some(IDP_KID.into());
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_ed_der(&der),
    )
    .map_err(|e| format!("mint token: {e}"))
}

/// The dev CA and a provider certificate for `hosts` (PEM: ca, cert, key).
fn tls(hosts: &[String]) -> Result<(String, String, String), String> {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };
    let err = |e: rcgen::Error| format!("dev CA: {e}");
    let mut ca = CertificateParams::new(Vec::<String>::new()).map_err(err)?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.distinguished_name.push(
        DnType::CommonName,
        "Kavach DEVELOPMENT CA (never trust in production)",
    );
    let ca_key = KeyPair::generate().map_err(err)?;
    let ca_pem = ca.self_signed(&ca_key).map_err(err)?.pem();
    let issuer = Issuer::new(ca, ca_key);

    let mut leaf = CertificateParams::new(hosts.to_vec()).map_err(err)?;
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.distinguished_name
        .push(DnType::CommonName, "kavach dev mock provider");
    let leaf_key = KeyPair::generate().map_err(err)?;
    let cert = leaf.signed_by(&leaf_key, &issuer).map_err(err)?;
    Ok((ca_pem, cert.pem(), leaf_key.serialize_pem()))
}

/// What `generate` produced, for the caller to print.
#[derive(Debug, Clone)]
pub struct Summary {
    pub out: PathBuf,
    pub registry_sha256: String,
    pub agents: Vec<String>,
}

/// Generates the bundle into `opts.out` (which should be empty).
pub async fn generate(opts: &Options) -> Result<Summary, String> {
    if !opts.provider_endpoint.starts_with("https://") {
        return Err("the dev provider endpoint must be https (TLS to the provider)".into());
    }
    let out = &opts.out;
    let (kavach, provider, agents, sor, signing) = (
        out.join("kavach"),
        out.join("provider"),
        out.join("agents"),
        out.join("sor"),
        out.join("signing"),
    );
    for dir in [
        &kavach.join("keys"),
        &kavach.join("tools"),
        &kavach.join("tls"),
        &provider,
        &agents,
        &sor,
        &signing,
    ] {
        mkdir(dir)?;
    }

    // Kavach's own keys (dev- ids).
    let keys = LocalFileKeyProvider::new(kavach.join("keys"));
    keys.create_key(MANDATE_KID).map_err(|e| e.to_string())?;
    keys.create_key(EVIDENCE_KID).map_err(|e| e.to_string())?;
    keys.create_key(CHECKPOINT_KID).map_err(|e| e.to_string())?;
    let credential_public = keys.create_key(CREDENTIAL_KID).map_err(|e| e.to_string())?;
    write_secret(&kavach.join("pseudonym.key"), &hex::encode(random32()?))?;

    // The system of record's event key, and the tool-registry signer.
    let sor_keys = LocalFileKeyProvider::new(&sor);
    let sor_public = sor_keys.create_key(SOR_KID).map_err(|e| e.to_string())?;
    let signer = LocalFileKeyProvider::new(&signing);
    let signer_public = signer
        .create_key(TOOL_SIGNER_KID)
        .map_err(|e| e.to_string())?;

    // The signed tool registry.
    let registry_path = kavach.join("tools/agent-tools.yaml");
    write(&registry_path, REGISTRY)?;
    let digest = format!("sha256:{:x}", Sha256::digest(REGISTRY.as_bytes()));
    let signature = sign_tool_registry(&signer, TOOL_SIGNER_KID, &digest)
        .await
        .map_err(|e| e.to_string())?;
    write(
        &kavach.join("tools/agent-tools.yaml.sig"),
        &serde_json::to_string_pretty(&signature).unwrap_or_default(),
    )?;
    write_json(
        &kavach.join("tool-signers.json"),
        &json!({ "signers": [{ "kid": TOOL_SIGNER_KID, "roles": ["tool"],
            "public_key": hex::encode(signer_public.bytes) }] }),
    )?;

    write_identity(&kavach, &agents, out, opts.token_hours)?;

    // The provider: encryption key, trusted credential key, TLS.
    let provider_secret = random32()?;
    let provider_key = DecryptionKey::from_bytes(PROVIDER_KID, provider_secret);
    write_secret(
        &provider.join("encryption.key"),
        &hex::encode(provider_secret),
    )?;
    write_json(
        &provider.join("credential-keys.json"),
        &json!({ "keys": [{ "kid": CREDENTIAL_KID, "public_key": hex::encode(credential_public.bytes) }] }),
    )?;
    let (ca_pem, cert_pem, key_pem) = tls(&opts.provider_hosts)?;
    write(&kavach.join("tls/ca.pem"), &ca_pem)?;
    write(&provider.join("tls.pem"), &cert_pem)?;
    write_secret(&provider.join("tls-key.pem"), &key_pem)?;

    write_kavach_config(&kavach, opts, &sor_public, &provider_key)?;
    write(&kavach.join("kavach.env"), &env_file(&opts.kavach_mount))?;
    write(&out.join("README.txt"), README)?;

    Ok(Summary {
        out: out.clone(),
        registry_sha256: digest,
        agents: AGENTS.iter().map(ToString::to_string).collect(),
    })
}

/// The dev identity provider: its JWKS for Kavach, and minted tokens (one
/// per agent, in that agent's file; one for operators).
fn write_identity(kavach: &Path, agents: &Path, out: &Path, hours: i64) -> Result<(), String> {
    // The dev identity provider and tokens.
    let idp_seed = random32()?;
    let idp_public = ed25519_dalek::SigningKey::from_bytes(&idp_seed)
        .verifying_key()
        .to_bytes();
    write_json(
        &kavach.join("jwks.json"),
        &json!({ "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(idp_public),
            "kid": IDP_KID, "alg": "EdDSA", "use": "sig" }] }),
    )?;
    for agent in AGENTS {
        let token = mint(
            &idp_seed,
            AGENT_AUDIENCE,
            json!({ "sub": format!("svc-{agent}"), "azp": agent }),
            hours,
        )?;
        write_secret(&agents.join(format!("{agent}.jwt")), &token)?;
    }
    write_secret(
        &out.join("operator.jwt"),
        &mint(
            &idp_seed,
            OPERATOR_AUDIENCE,
            json!({ "sub": "dev-operator", "groups": ["admins"] }),
            hours,
        )?,
    )?;

    Ok(())
}

/// Kavach's configuration: mandates, consents, references, providers.
fn write_kavach_config(
    kavach: &Path,
    opts: &Options,
    sor_public: &kavach_ports::PublicKey,
    provider_key: &DecryptionKey,
) -> Result<(), String> {
    // Kavach's configuration.
    write_json(
        &kavach.join("mandate-config.json"),
        &json!({
            "issuer_id": "kavach-dev",
            "signing_kid": MANDATE_KID,
            "sor_issuers": [{ "system": "lms", "kid": SOR_KID, "public_key": hex::encode(sor_public.bytes) }],
            "templates": [template()],
            "passports": AGENTS.iter().map(|a| passport(a)).collect::<Vec<_>>(),
            "event_freshness_seconds": 300,
            "replay_window_seconds": 86400,
        }),
    )?;
    write_json(
        &kavach.join("consents.json"),
        &serde_json::to_value(vec![ConsentRecord {
            consent_id: "C-dev-1".into(),
            tenant_id: TENANT.into(),
            subject_ref: SUBJECT.into(),
            purposes: set(&["loan_recovery"]),
            expires_at: Utc::now() + Duration::days(30),
            active: true,
        }])
        .unwrap_or_default(),
    )?;
    write_json(
        &kavach.join("references.json"),
        &json!({ "references": [{ "tenant_id": TENANT, "subject_ref": SUBJECT,
            "destinations": { "whatsapp": DESTINATION, "sms": DESTINATION, "voice": "+910000000002" } }] }),
    )?;
    write_json(
        &kavach.join("providers.json"),
        &json!({ "providers": [
            { "audience": PROVIDER_AUDIENCE, "kid": PROVIDER_KID,
              "x25519_public_key": hex::encode(provider_key.recipient().public),
              "endpoint": opts.provider_endpoint },
            // The voice provider is not part of the dev stack: nothing listens.
            { "audience": "mock-voice", "kid": PROVIDER_KID,
              "x25519_public_key": hex::encode(provider_key.recipient().public),
              "endpoint": "https://127.0.0.1:9" },
        ]}),
    )?;
    Ok(())
}

fn env_file(m: &str) -> String {
    format!(
        "# DEVELOPMENT ONLY (kavach-devkit). Keys are dev-…: production startup refuses them.\n\
         KAVACH_OIDC_ISSUER={ISSUER}\n\
         KAVACH_OIDC_AUDIENCE={OPERATOR_AUDIENCE}\n\
         KAVACH_OIDC_JWKS_FILE={m}/jwks.json\n\
         KAVACH_AGENT_OIDC_AUDIENCE={AGENT_AUDIENCE}\n\
         KAVACH_MANDATE_CONFIG={m}/mandate-config.json\n\
         KAVACH_MANDATE_KEYS_DIR={m}/keys\n\
         KAVACH_EVIDENCE_KEYS_DIR={m}/keys\n\
         KAVACH_EVIDENCE_KEY_ID={EVIDENCE_KID}\n\
         KAVACH_CREDENTIAL_KEYS_DIR={m}/keys\n\
         KAVACH_CREDENTIAL_KEY_ID={CREDENTIAL_KID}\n\
         KAVACH_SUBJECT_PSEUDONYM_KEY={m}/pseudonym.key\n\
         KAVACH_CONSENTS={m}/consents.json\n\
         KAVACH_REFERENCES={m}/references.json\n\
         KAVACH_PROVIDERS={m}/providers.json\n\
         KAVACH_PROVIDER_CA={m}/tls/ca.pem\n\
         KAVACH_TOOL_REGISTRY={m}/tools/agent-tools.yaml\n\
         KAVACH_TOOL_SIGNERS={m}/tool-signers.json\n"
    )
}

const README: &str = "Kavach DEVELOPMENT bundle (kavach-devkit).\n\n\
Every key here is a dev- key: kavach-api refuses them outside --insecure-dev and\n\
the offline evidence verifier refuses evidence they signed. The dev CA must never\n\
be trusted outside this stack. Mount each directory only into the service it is\n\
for: agents get agents/<id>.jwt and nothing else.\n";

/// A signed system-of-record event that assigns `agent` to `subject_ref`.
pub async fn sor_event(
    bundle: &Path,
    event_id: &str,
    subject_ref: &str,
    agent: &str,
    occurred_at: DateTime<Utc>,
) -> Result<String, String> {
    let event = SorEvent {
        event_id: event_id.into(),
        tenant_id: TENANT.into(),
        system: "lms".into(),
        event_type: "loan.dpd30".into(),
        record_ref: format!("lms:loan/{event_id}"),
        subject_ref: subject_ref.into(),
        principal: "nbfc-collections-system".into(),
        consent_refs: set(&["C-dev-1"]),
        assigned_agent: agent.into(),
        occurred_at,
        nonce: format!("n-{event_id}"),
    };
    let keys = LocalFileKeyProvider::new(bundle.join("sor"));
    kavach_mandate::jws::sign(&keys, SOR_KID, kavach_mandate::jws::TYP_SOR_EVENT, &event)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_bundle_is_complete_dev_marked_and_least_privilege() {
        let out = std::env::temp_dir().join(format!("kavach-devkit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        let summary = generate(&Options {
            out: out.clone(),
            kavach_mount: "/etc/kavach".into(),
            provider_endpoint: "https://172.30.20.30:8443".into(),
            provider_hosts: vec!["mock-provider".into(), "172.30.20.30".into()],
            token_hours: 24,
        })
        .await
        .unwrap();
        assert!(summary.registry_sha256.starts_with("sha256:"));

        // Every Kavach key id is a dev key.
        for kid in [
            MANDATE_KID,
            EVIDENCE_KID,
            CHECKPOINT_KID,
            CREDENTIAL_KID,
            TOOL_SIGNER_KID,
            SOR_KID,
            IDP_KID,
            PROVIDER_KID,
        ] {
            assert!(kavach_ports::agent_evidence::is_dev_key(kid), "{kid}");
        }
        for file in [
            "kavach/keys/dev-mandate-1.ed25519",
            "kavach/keys/dev-checkpoint-1.ed25519",
            "kavach/mandate-config.json",
            "kavach/tools/agent-tools.yaml.sig",
            "kavach/tls/ca.pem",
            "kavach/kavach.env",
            "provider/encryption.key",
            "provider/tls.pem",
            "agents/collections-agent.jwt",
            "sor/dev-sor-issuer-1.ed25519",
        ] {
            assert!(out.join(file).exists(), "{file}");
        }
        // An agent's directory holds only tokens: no key material.
        for entry in std::fs::read_dir(out.join("agents")).unwrap() {
            let path = entry.unwrap().path();
            assert_eq!(
                path.extension().and_then(|e| e.to_str()),
                Some("jwt"),
                "{path:?}"
            );
        }
        // The registry signature verifies with the published signer.
        let signers =
            kavach_keys::TrustedSigners::from_file(&out.join("kavach/tool-signers.json")).unwrap();
        kavach_keys::verify_tool_registry_file(
            &out.join("kavach/tools/agent-tools.yaml"),
            &summary.registry_sha256,
            &signers,
        )
        .unwrap();
        // Secrets are owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for secret in [
                "kavach/pseudonym.key",
                "provider/encryption.key",
                "agents/collections-agent.jwt",
            ] {
                let mode = std::fs::metadata(out.join(secret))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600, "{secret}");
            }
        }
        // A signed SoR event is produced with the dev SoR key.
        let event = sor_event(&out, "evt-1", SUBJECT, "collections-agent", Utc::now())
            .await
            .unwrap();
        assert_eq!(event.split('.').count(), 3);
        // Plain HTTP to the provider is refused for the dev stack.
        let refused = generate(&Options {
            out: out.join("again"),
            kavach_mount: "/etc/kavach".into(),
            provider_endpoint: "http://mock-provider:8095".into(),
            provider_hosts: vec![],
            token_hours: 1,
        })
        .await;
        assert!(refused.is_err());
        std::fs::remove_dir_all(&out).unwrap();
    }
}
