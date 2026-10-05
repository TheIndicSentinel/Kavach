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
//! | `kavach/tls/ca.pem` | kavach-api | the dev CA the gateway trusts for providers and for Postgres |
//! | `postgres/` | Postgres | its TLS certificate and key (`server.crt`, `server.key`) |
//! | `kavach/kavach.env` | kavach-api | every setting, as environment variables |
//! | `provider/` | mock provider | X25519 encryption key, credential public keys, TLS certificate and key |
//! | `agents/<id>.jwt` | each agent | its access token (and nothing else) |
//! | `operator.jwt` | operators | an operator token |
//! | `sor/` | system of record | the event-signing key, used by `kavach-dev sor-event` |
//! | `signing/` | offline | the tool-registry signing key |
//! | `auditor/` | whoever exports evidence | the export key `dev-export-1`, which signs evidence bundles, and `trusted-keys.json`, the public keys for `kavach-evidence verify-bundle --dev` (never mounted into Kavach) |
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
/// Signs evidence bundles; held by the auditor, never by Kavach (ADR-005 §13).
pub const EXPORT_KID: &str = "dev-export-1";
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
    /// DNS names and IPs on Postgres's TLS certificate (prefer a DNS name
    /// in database URLs).
    pub database_hosts: Vec<String>,
    /// Lifetime of the minted access tokens.
    pub token_hours: i64,
}

/// Who a development project holds: agents (each with a token and a
/// passport) and borrowers (each with a consent and synthetic
/// destinations). The default is what `kavach init` writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct World {
    pub agents: Vec<String>,
    /// The agents the mandate template assigns borrowers to.
    pub eligible_agents: Vec<String>,
    pub borrowers: Vec<Borrower>,
}

/// One borrower: an opaque reference and synthetic destinations
/// (`+910` and nine digits; the reference fixture refuses anything else).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Borrower {
    pub subject_ref: String,
    /// WhatsApp and SMS.
    pub destination: String,
    pub voice: String,
}

impl Default for World {
    fn default() -> Self {
        Self {
            agents: AGENTS.iter().map(ToString::to_string).collect(),
            eligible_agents: vec!["collections-agent".into()],
            borrowers: vec![Borrower {
                subject_ref: SUBJECT.into(),
                destination: DESTINATION.into(),
                voice: "+910000000002".into(),
            }],
        }
    }
}

/// The collections template for `world`: its eligible agents, and
/// delegation only to agents it holds (none: no delegation).
fn world_template(world: &World) -> MandateTemplate {
    let base = template();
    let allowed: BTreeSet<String> = base
        .delegation
        .allowed_agents
        .iter()
        .filter(|a| world.agents.contains(a))
        .cloned()
        .collect();
    MandateTemplate {
        eligible_agents: world.eligible_agents.iter().cloned().collect(),
        delegation: DelegationRules {
            max_depth: if allowed.is_empty() {
                0
            } else {
                base.delegation.max_depth
            },
            allowed_agents: allowed,
        },
        ..base
    }
}

/// The consent a borrower's system-of-record events cite.
#[must_use]
pub fn consent_id(subject_ref: &str) -> String {
    if subject_ref == SUBJECT {
        "C-dev-1".into()
    } else {
        format!(
            "C-{}",
            subject_ref.rsplit(':').next().unwrap_or(subject_ref)
        )
    }
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
/// The dev CA (PEM) and an issuer for leaf certificates.
fn dev_ca() -> Result<(String, rcgen::Issuer<'static, rcgen::KeyPair>), String> {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
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
    Ok((ca_pem, Issuer::new(ca, ca_key)))
}

/// A server certificate and key (PEM) for `hosts` (DNS names and IPs),
/// issued by the dev CA.
fn server_cert(
    issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
    hosts: &[String],
    name: &str,
) -> Result<(String, String), String> {
    use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};
    let err = |e: rcgen::Error| format!("dev certificate for {name}: {e}");
    let mut leaf = CertificateParams::new(hosts.to_vec()).map_err(err)?;
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.distinguished_name.push(DnType::CommonName, name);
    let leaf_key = KeyPair::generate().map_err(err)?;
    let cert = leaf.signed_by(&leaf_key, issuer).map_err(err)?;
    Ok((cert.pem(), leaf_key.serialize_pem()))
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
    generate_with(opts, &World::default()).await
}

/// [`generate`], holding `world`'s agents and borrowers.
pub async fn generate_with(opts: &Options, world: &World) -> Result<Summary, String> {
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
    // The auditor's export key: its own directory, never mounted into Kavach.
    let export_public = LocalFileKeyProvider::new(out.join("auditor"))
        .create_key(EXPORT_KID)
        .map_err(|e| e.to_string())?;
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
    let evidence_public = keys.create_key(EVIDENCE_KID).map_err(|e| e.to_string())?;
    let checkpoint_public = keys.create_key(CHECKPOINT_KID).map_err(|e| e.to_string())?;
    // What the auditor trusts when verifying a bundle from this stack:
    // public keys only, kept with the auditor and never in a bundle.
    let trusted: Vec<Value> = [&evidence_public, &checkpoint_public, &export_public]
        .iter()
        .map(
            |key| json!({ "kid": key.kid, "alg": "Ed25519", "public_key": hex::encode(key.bytes) }),
        )
        .collect();
    write_json(
        &out.join("auditor/trusted-keys.json"),
        &json!({ "keys": trusted }),
    )?;
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

    write_identity(&kavach, &agents, out, opts.token_hours, &world.agents)?;

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
    let (ca_pem, issuer) = dev_ca()?;
    let (cert_pem, key_pem) =
        server_cert(&issuer, &opts.provider_hosts, "kavach dev mock provider")?;
    write(&kavach.join("tls/ca.pem"), &ca_pem)?;
    // Postgres serves TLS only; Kavach and the auditor verify it with the
    // dev CA (sslmode=verify-full, the default).
    let (db_cert, db_key) = server_cert(&issuer, &opts.database_hosts, "kavach dev postgres")?;
    mkdir(&out.join("postgres"))?;
    write(&out.join("postgres/server.crt"), &db_cert)?;
    write_secret(&out.join("postgres/server.key"), &db_key)?;
    write(&out.join("auditor/database-ca.pem"), &ca_pem)?;
    write(&provider.join("tls.pem"), &cert_pem)?;
    write_secret(&provider.join("tls-key.pem"), &key_pem)?;

    write_kavach_config(&kavach, opts, world, &sor_public, &provider_key)?;
    write(&kavach.join("kavach.env"), &env_file(&opts.kavach_mount))?;
    write(&out.join("README.txt"), README)?;

    Ok(Summary {
        out: out.clone(),
        registry_sha256: digest,
        agents: world.agents.clone(),
    })
}

/// The dev identity provider: its JWKS for Kavach, and minted tokens (one
/// per agent, in that agent's file; one for operators).
fn write_identity(
    kavach: &Path,
    agents: &Path,
    out: &Path,
    hours: i64,
    names: &[String],
) -> Result<(), String> {
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
    for agent in names {
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
    world: &World,
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
            "templates": [world_template(world)],
            "passports": world.agents.iter().map(|a| passport(a)).collect::<Vec<_>>(),
            "event_freshness_seconds": 300,
            "replay_window_seconds": 86400,
        }),
    )?;
    write_json(
        &kavach.join("consents.json"),
        &serde_json::to_value(
            world
                .borrowers
                .iter()
                .map(|b| ConsentRecord {
                    consent_id: consent_id(&b.subject_ref),
                    tenant_id: TENANT.into(),
                    subject_ref: b.subject_ref.clone(),
                    purposes: set(&["loan_recovery"]),
                    expires_at: Utc::now() + Duration::days(30),
                    active: true,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default(),
    )?;
    write_json(
        &kavach.join("references.json"),
        &json!({ "references": world.borrowers.iter().map(|b| json!({
            "tenant_id": TENANT, "subject_ref": b.subject_ref,
            "destinations": { "whatsapp": b.destination, "sms": b.destination, "voice": b.voice },
        })).collect::<Vec<_>>() }),
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
         KAVACH_CHECKPOINT_KEYS_DIR={m}/keys\n\
         KAVACH_CHECKPOINT_KEY_ID={CHECKPOINT_KID}\n\
         KAVACH_DATABASE_CA={m}/tls/ca.pem\n\
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
for: agents get agents/<id>.jwt and nothing else. auditor/ holds the export key\n\
that signs evidence bundles: it belongs to whoever exports, never to Kavach.\n";

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
        consent_refs: [consent_id(subject_ref)].into(),
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

    /// Secrets in the bundle are readable by their owner only.
    fn secrets_are_owner_only(out: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for secret in [
                "kavach/pseudonym.key",
                "provider/encryption.key",
                "postgres/server.key",
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
    }

    fn options(out: &std::path::Path) -> Options {
        Options {
            out: out.to_path_buf(),
            kavach_mount: "/etc/kavach".into(),
            provider_endpoint: "https://localhost:8443".into(),
            provider_hosts: vec!["localhost".into()],
            database_hosts: vec!["localhost".into()],
            token_hours: 1,
        }
    }

    fn read(path: &std::path::Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// `kavach init`'s world is exactly what it was before worlds existed.
    #[tokio::test]
    async fn the_default_world_is_init_s() {
        let out =
            std::env::temp_dir().join(format!("kavach-devkit-default-{}", std::process::id()));
        generate(&options(&out)).await.unwrap();
        let k = out.join("kavach");
        let config = read(&k.join("mandate-config.json"));
        let template = &config["templates"][0];
        assert_eq!(template["eligible_agents"], json!(["collections-agent"]));
        assert_eq!(
            template["delegation"],
            json!({ "max_depth": 1, "allowed_agents": ["translation-agent"] })
        );
        let passports: Vec<&str> = config["passports"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p["agent_id"].as_str())
            .collect();
        assert_eq!(passports, AGENTS);
        let consents = read(&k.join("consents.json"));
        assert_eq!(consents.as_array().unwrap().len(), 1);
        assert_eq!(consents[0]["consent_id"], "C-dev-1");
        assert_eq!(consents[0]["subject_ref"], SUBJECT);
        assert_eq!(
            read(&k.join("references.json")),
            json!({ "references": [{ "tenant_id": TENANT, "subject_ref": SUBJECT,
                "destinations": { "whatsapp": DESTINATION, "sms": DESTINATION, "voice": "+910000000002" } }] })
        );
        for agent in AGENTS {
            assert!(out.join(format!("agents/{agent}.jwt")).is_file());
        }
        std::fs::remove_dir_all(out).unwrap();
    }

    /// A simulated world: its agents (tokens, passports, all eligible), its
    /// borrowers (one consent each, synthetic destinations), delegation only
    /// to agents it holds, and events citing each borrower's consent.
    #[tokio::test]
    async fn a_world_has_its_agents_and_borrowers() {
        let out = std::env::temp_dir().join(format!("kavach-devkit-world-{}", std::process::id()));
        let agents = vec!["sim-a-1".to_string(), "sim-a-2".to_string()];
        let borrowers: Vec<Borrower> = (1..=3)
            .map(|i| Borrower {
                subject_ref: format!("ref:borrower:S-000{i}"),
                destination: format!("+910000100{i:03}"),
                voice: format!("+910000200{i:03}"),
            })
            .collect();
        let world = World {
            agents: agents.clone(),
            eligible_agents: agents.clone(),
            borrowers: borrowers.clone(),
        };
        let summary = generate_with(&options(&out), &world).await.unwrap();
        assert_eq!(summary.agents, agents);
        let k = out.join("kavach");
        let config = read(&k.join("mandate-config.json"));
        assert_eq!(config["templates"][0]["eligible_agents"], json!(agents));
        assert_eq!(
            config["templates"][0]["delegation"],
            json!({ "max_depth": 0, "allowed_agents": [] }),
            "no translation-agent in this world: no delegation"
        );
        assert_eq!(config["passports"].as_array().unwrap().len(), 2);
        for agent in &agents {
            assert!(out.join(format!("agents/{agent}.jwt")).is_file());
        }
        assert!(!out.join("agents/collections-agent.jwt").exists());
        let consents = read(&k.join("consents.json"));
        let ids: Vec<&str> = consents
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["consent_id"].as_str())
            .collect();
        assert_eq!(ids, ["C-S-0001", "C-S-0002", "C-S-0003"]);
        assert_eq!(
            read(&k.join("references.json"))["references"]
                .as_array()
                .unwrap()
                .len(),
            3
        );

        // An event cites its borrower's consent.
        let token = sor_event(&out, "evt-w", "ref:borrower:S-0002", "sim-a-1", Utc::now())
            .await
            .unwrap();
        let payload = token.split('.').nth(1).unwrap();
        let event: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert_eq!(event["consent_refs"], json!(["C-S-0002"]));
        std::fs::remove_dir_all(out).unwrap();
    }

    #[tokio::test]
    async fn the_bundle_is_complete_dev_marked_and_least_privilege() {
        let out = std::env::temp_dir().join(format!("kavach-devkit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        let summary = generate(&Options {
            out: out.clone(),
            kavach_mount: "/etc/kavach".into(),
            provider_endpoint: "https://172.30.20.30:8443".into(),
            provider_hosts: vec!["mock-provider".into(), "172.30.20.30".into()],
            database_hosts: vec!["postgres".into(), "172.30.20.20".into()],
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
            EXPORT_KID,
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
            "auditor/dev-export-1.ed25519",
            "auditor/trusted-keys.json",
            "auditor/database-ca.pem",
            "postgres/server.crt",
            "postgres/server.key",
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
        // The export key is the auditor's: an export key by name, and not
        // among Kavach's keys.
        assert!(kavach_ports::bundle::is_export_key(EXPORT_KID));
        assert!(!out.join("kavach/keys/dev-export-1.ed25519").exists());
        // The trusted keys file lists exactly the three keys a bundle of
        // this stack is verified with, and no private material.
        let trusted = std::fs::read_to_string(out.join("auditor/trusted-keys.json")).unwrap();
        let trusted: Value = serde_json::from_str(&trusted).unwrap();
        let kids: Vec<&str> = trusted["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap())
            .collect();
        assert_eq!(kids, [EVIDENCE_KID, CHECKPOINT_KID, EXPORT_KID]);
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
        secrets_are_owner_only(&out);
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
            database_hosts: vec!["postgres".into()],
            token_hours: 1,
        })
        .await;
        assert!(refused.is_err());
        std::fs::remove_dir_all(&out).unwrap();
    }
}
