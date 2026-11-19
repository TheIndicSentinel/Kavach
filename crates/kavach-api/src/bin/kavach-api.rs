use kavach_api::console_login::{ConsoleLogin, ConsoleLoginSettings, IdpEndpoints};
use kavach_api::signing::{HsmConfig, HsmRole};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use kavach_api::limits;
use kavach_api::{
    resolve_access_control, router, serve_grpc_until, serve_http_until_with_limits, shutdown,
    validate_hmac_secret, validate_principal_sources, AccessControlKind, AccessControlMode,
    ApiConfig, AppState, EvidenceStoreKind, GrpcEvaluateService, JwksSource, ListenerLimits,
    MtlsSanKind, OidcConfig, TlsConfig, DEFAULT_CHANGE_TTL_HOURS,
};
use kavach_ports::ReferenceResolver;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum EvidenceStoreArg {
    Memory,
    Postgres,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum AccessControlArg {
    None,
    Cedar,
}

/// Agent surfaces (ADR-007, H5a-5): enabled by `--agent-oidc-audience`.
/// Agents use the operator IdP (issuer and JWKS) with their own audience.
#[derive(clap::Args)]
struct AgentArgs {
    /// Audience of agent access tokens (must differ from `--oidc-audience`).
    #[arg(long, env = "KAVACH_AGENT_OIDC_AUDIENCE")]
    agent_oidc_audience: Option<String>,
    /// Claim naming the agent (Keycloak client id: `azp`).
    #[arg(long, env = "KAVACH_AGENT_ID_CLAIM", default_value = "azp")]
    agent_id_claim: String,
    /// Mandate configuration JSON (issuer, SoR issuers, templates, passports).
    #[arg(long, env = "KAVACH_MANDATE_CONFIG")]
    mandate_config: Option<PathBuf>,
    /// Directory with the mandate signing key.
    #[arg(long, env = "KAVACH_MANDATE_KEYS_DIR")]
    mandate_keys_dir: Option<PathBuf>,
    /// Directory with the evidence signing key (signs agent evidence only).
    #[arg(long, env = "KAVACH_EVIDENCE_KEYS_DIR")]
    evidence_keys_dir: Option<PathBuf>,
    #[arg(
        long,
        env = "KAVACH_EVIDENCE_KEY_ID",
        default_value = "kavach-evidence-1"
    )]
    evidence_key_id: String,
    /// Directory with the checkpoint signing key (signs evidence checkpoints
    /// only). Required with the agent surfaces.
    #[arg(long, env = "KAVACH_CHECKPOINT_KEYS_DIR")]
    checkpoint_keys_dir: Option<PathBuf>,
    #[arg(
        long,
        env = "KAVACH_CHECKPOINT_KEY_ID",
        default_value = "kavach-checkpoint-1"
    )]
    checkpoint_key_id: String,
    /// On SIGTERM or Ctrl-C: stop accepting, wait this long for requests and
    /// gateway calls in flight, then write a final checkpoint.
    #[arg(
        long,
        env = "KAVACH_SHUTDOWN_GRACE_SECONDS",
        default_value_t = kavach_api::shutdown::DEFAULT_GRACE_SECONDS,
        value_parser = clap::value_parser!(u64).range(1..=600)
    )]
    shutdown_grace_seconds: u64,
    /// Uncovered records get a checkpoint at least this often (or after
    /// 1,000 records, whichever comes first).
    #[arg(long, env = "KAVACH_CHECKPOINT_INTERVAL_SECONDS", default_value_t = 60)]
    checkpoint_interval_seconds: u64,
    /// Alert when records have had no checkpoint for this many seconds.
    #[arg(long, env = "KAVACH_CHECKPOINT_STALL_SECONDS", default_value_t = 600)]
    checkpoint_stall_seconds: u64,
    /// Owner-only file with a 32-byte hex secret for subject pseudonyms.
    #[arg(long, env = "KAVACH_SUBJECT_PSEUDONYM_KEY")]
    subject_pseudonym_key: Option<PathBuf>,
    /// Consent fixture JSON (PRD D7).
    #[arg(long, env = "KAVACH_CONSENTS")]
    consents: Option<PathBuf>,
    /// Optional explicit contact-preference fixture for no-database development.
    #[arg(long, env = "KAVACH_CONTACT_PREFERENCES")]
    contact_preferences: Option<PathBuf>,
    #[arg(long, env = "KAVACH_TENANT_ID", default_value = "default")]
    tenant_id: String,
    /// System-of-record events accepted per second.
    #[arg(long, env = "KAVACH_SOR_RATE_PER_SECOND", default_value_t = 20)]
    sor_rate_per_second: u32,
    /// Agent tool registry (YAML). Must be signed (`<path>.sig`, signer role
    /// `tool`) unless `--insecure-dev`.
    #[arg(long, env = "KAVACH_TOOL_REGISTRY")]
    tool_registry: Option<PathBuf>,
    /// Expected tool registry digest (`sha256:<hex>`).
    #[arg(long, env = "KAVACH_TOOL_REGISTRY_SHA256")]
    tool_registry_sha256: Option<String>,
    /// Trusted signers for the tool registry (default: `--pack-signers`).
    #[arg(long, env = "KAVACH_TOOL_SIGNERS")]
    tool_signers: Option<PathBuf>,
    /// Directory with the credential signing key (signs resource
    /// credentials only; a separate key from the mandate and evidence keys).
    #[arg(long, env = "KAVACH_CREDENTIAL_KEYS_DIR")]
    credential_keys_dir: Option<PathBuf>,
    #[arg(
        long,
        env = "KAVACH_CREDENTIAL_KEY_ID",
        default_value = "kavach-credential-1"
    )]
    credential_key_id: String,
    /// Resource providers JSON: each audience's X25519 encryption key.
    #[arg(long, env = "KAVACH_PROVIDERS")]
    providers: Option<PathBuf>,
    /// Reference fixture JSON (capability reference -> destination per
    /// channel; synthetic +910 numbers only).
    #[arg(long, env = "KAVACH_REFERENCES")]
    references: Option<PathBuf>,
    /// Owner-only 32-byte hex key file for signed destination updates.
    #[arg(long, env = "KAVACH_REFERENCE_VAULT_KEY_FILE")]
    reference_vault_key_file: Option<PathBuf>,
    /// Key id authenticated into new destination envelopes.
    #[arg(
        long,
        env = "KAVACH_REFERENCE_VAULT_KEY_ID",
        default_value = "reference-v1"
    )]
    reference_vault_key_id: String,
    /// Previous owner-only vault keys, decrypt-only (`KEY_ID=PATH`, repeatable).
    #[arg(long = "reference-vault-previous-key", value_name = "KEY_ID=PATH", action = clap::ArgAction::Append)]
    reference_vault_previous_keys: Vec<String>,
    /// Gateway → provider connect timeout (ms; no retries).
    #[arg(
        long,
        env = "KAVACH_PROVIDER_CONNECT_TIMEOUT_MS",
        default_value_t = 2000
    )]
    provider_connect_timeout_ms: u64,
    /// CA certificates (PEM) trusted for provider TLS, besides the system roots.
    #[arg(long, env = "KAVACH_PROVIDER_CA")]
    provider_ca: Option<PathBuf>,
    /// Gateway → provider total timeout (ms; below the 15 s credential lifetime).
    #[arg(long, env = "KAVACH_PROVIDER_TIMEOUT_MS", default_value_t = 5000)]
    provider_timeout_ms: u64,
    /// Serve the agent surfaces and the evidence reads only: no evaluate,
    /// pack, model, retention, incident or batch routes, no console and no
    /// gRPC evaluate. For hosted builds (the credit track is frozen).
    #[arg(long, env = "KAVACH_AGENT_ONLY")]
    agent_only: bool,
    /// Listener for agents (`/v1/authorize`, tools): the only listener to
    /// attach to the agent network.
    #[arg(long, env = "KAVACH_AGENT_LISTEN", default_value = "127.0.0.1:8091")]
    agent_listen: SocketAddr,
    /// Listener for `POST /v1/sor/events` (bind to the backend network only).
    #[arg(long, env = "KAVACH_SOR_LISTEN", default_value = "127.0.0.1:8090")]
    sor_listen: SocketAddr,
    /// Signing roles whose keys live in the HSM, comma separated: mandate,
    /// evidence, checkpoint, credential. Each key's id is its HSM label;
    /// the other roles keep their key directories. Measure signing latency
    /// on the target HSM before listing evidence or credential.
    #[arg(long, env = "KAVACH_HSM_KEYS", value_delimiter = ',')]
    hsm_keys: Vec<String>,
    /// The HSM vendor's PKCS#11 module (`.so`).
    #[arg(long, env = "KAVACH_HSM_MODULE")]
    hsm_module: Option<PathBuf>,
    /// Label of the token that holds the keys.
    #[arg(long, env = "KAVACH_HSM_TOKEN_LABEL")]
    hsm_token_label: Option<String>,
    /// Owner-only file holding the token's user PIN (never a flag value or
    /// an environment variable).
    #[arg(long, env = "KAVACH_HSM_PIN_FILE")]
    hsm_pin_file: Option<PathBuf>,
    /// HSM sessions kept open for reuse.
    #[arg(long, env = "KAVACH_HSM_SESSIONS", default_value_t = 8)]
    hsm_sessions: usize,
    /// Milliseconds one HSM sign or health call may wait for the token
    /// before it fails closed (the decision or record is not issued;
    /// 100-60000).
    #[arg(
        long,
        env = "KAVACH_HSM_TIMEOUT_MS",
        default_value_t = limits::DEFAULT_HSM_TIMEOUT_MS,
        value_parser = clap::value_parser!(u64).range(limits::HSM_TIMEOUT_MS)
    )]
    hsm_timeout_ms: u64,
}

impl AgentArgs {
    fn into_config(
        self,
        operator: Option<&OidcConfig>,
    ) -> Result<Option<kavach_api::dataplane::DataplaneConfig>, String> {
        let hsm = self.hsm_config()?;
        let Some(audience) = self.agent_oidc_audience else {
            if self.reference_vault_key_file.is_some()
                || !self.reference_vault_previous_keys.is_empty()
            {
                return Err("reference vault keys require the agent surfaces".into());
            }
            if self.agent_only {
                return Err(
                    "--agent-only serves the agent surfaces and nothing else: it needs them \
                     (--agent-oidc-audience and the agent flags)"
                        .into(),
                );
            }
            return Ok(None);
        };
        let operator = operator.ok_or(
            "agent surfaces use the operator IdP: configure --oidc-issuer and a JWKS source",
        )?;
        let in_hsm = |role: HsmRole| hsm.as_ref().is_some_and(|h| h.roles.contains(&role));
        let need = |value: Option<PathBuf>, flag: &str| {
            value.ok_or_else(|| format!("agent surfaces need {flag}"))
        };
        // A role whose key is in the HSM needs no key directory.
        let key_dir = |value: Option<PathBuf>, flag: &str, role: HsmRole| match value {
            Some(dir) => Ok(dir),
            None if in_hsm(role) => Ok(PathBuf::new()),
            None => Err(format!("agent surfaces need {flag} (or --hsm-keys {role})")),
        };
        let reference_vault = match &self.reference_vault_key_file {
            Some(key_file) => Some(kavach_api::dataplane::ReferenceVaultConfig {
                key_file: key_file.clone(),
                key_id: self.reference_vault_key_id.clone(),
                previous_keys: self
                    .reference_vault_previous_keys
                    .iter()
                    .map(|entry| parse_reference_vault_previous_key(entry))
                    .collect::<Result<Vec<_>, _>>()?,
            }),
            None if self.reference_vault_previous_keys.is_empty() => None,
            None => {
                return Err(
                    "--reference-vault-previous-key requires --reference-vault-key-file".into(),
                );
            }
        };
        Ok(Some(kavach_api::dataplane::DataplaneConfig {
            agent_oidc: OidcConfig {
                audience,
                principal_claim: self.agent_id_claim,
                ..operator.clone()
            },
            mandate_config: need(self.mandate_config, "--mandate-config")?,
            mandate_keys_dir: key_dir(
                self.mandate_keys_dir,
                "--mandate-keys-dir",
                HsmRole::Mandate,
            )?,
            evidence_keys_dir: key_dir(
                self.evidence_keys_dir,
                "--evidence-keys-dir",
                HsmRole::Evidence,
            )?,
            evidence_key_id: self.evidence_key_id,
            checkpoint_keys_dir: key_dir(
                self.checkpoint_keys_dir,
                "--checkpoint-keys-dir",
                HsmRole::Checkpoint,
            )?,
            checkpoint_key_id: self.checkpoint_key_id,
            checkpoint_interval_seconds: self.checkpoint_interval_seconds,
            checkpoint_stall_seconds: self.checkpoint_stall_seconds,
            subject_pseudonym_key: need(self.subject_pseudonym_key, "--subject-pseudonym-key")?,
            consents: need(self.consents, "--consents")?,
            contact_preferences: self.contact_preferences,
            tenant_id: self.tenant_id,
            agent_only: self.agent_only,
            sor_rate_per_second: self.sor_rate_per_second,
            tool_registry: need(self.tool_registry, "--tool-registry")?,
            tool_registry_sha256: self.tool_registry_sha256,
            tool_signers: self.tool_signers,
            credential_keys_dir: key_dir(
                self.credential_keys_dir,
                "--credential-keys-dir",
                HsmRole::Credential,
            )?,
            credential_key_id: self.credential_key_id,
            providers: need(self.providers, "--providers")?,
            references: need(self.references, "--references")?,
            reference_vault,
            provider_connect_timeout_ms: self.provider_connect_timeout_ms,
            provider_timeout_ms: self.provider_timeout_ms,
            provider_ca: self.provider_ca,
            test_clock: None,
            dev_clock: None,
            hsm,
        }))
    }
}

impl AgentArgs {
    /// The HSM settings, when `--hsm-keys` lists roles; all four settings
    /// are then required.
    fn hsm_config(&self) -> Result<Option<HsmConfig>, String> {
        if self.hsm_keys.is_empty() {
            if self.hsm_module.is_some()
                || self.hsm_token_label.is_some()
                || self.hsm_pin_file.is_some()
            {
                return Err(
                    "--hsm-module, --hsm-token-label and --hsm-pin-file need --hsm-keys".into(),
                );
            }
            return Ok(None);
        }
        let roles = self
            .hsm_keys
            .iter()
            .map(|r| r.parse::<HsmRole>())
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        let need = |value: Option<&PathBuf>, flag: &str| {
            value
                .cloned()
                .ok_or_else(|| format!("--hsm-keys needs {flag}"))
        };
        Ok(Some(HsmConfig {
            module: need(self.hsm_module.as_ref(), "--hsm-module")?,
            token_label: self
                .hsm_token_label
                .clone()
                .ok_or("--hsm-keys needs --hsm-token-label")?,
            pin_file: need(self.hsm_pin_file.as_ref(), "--hsm-pin-file")?,
            roles,
            max_sessions: self.hsm_sessions.max(1),
            call_timeout: std::time::Duration::from_millis(self.hsm_timeout_ms),
        }))
    }
}

/// OIDC / OAuth 2.0 JWT access tokens for API principals (ADR-008).
#[derive(clap::Args)]
#[allow(clippy::struct_field_names)] // field names become the `--oidc-*` flags
struct OidcArgs {
    /// Expected token issuer (`iss`), e.g. https://idp.bank.example/realms/kavach
    #[arg(long, env = "KAVACH_OIDC_ISSUER")]
    oidc_issuer: Option<String>,

    /// Expected audience (`aud`) for Kavach API tokens.
    #[arg(long, env = "KAVACH_OIDC_AUDIENCE")]
    oidc_audience: Option<String>,

    /// JWKS file with the issuer's signing keys (offline deployments).
    #[arg(long, env = "KAVACH_OIDC_JWKS_FILE", conflicts_with = "oidc_jwks_url")]
    oidc_jwks_file: Option<PathBuf>,

    /// HTTPS JWKS URL at the bank's identity provider (fetched at startup and refreshed).
    #[arg(long, env = "KAVACH_OIDC_JWKS_URL")]
    oidc_jwks_url: Option<String>,

    /// Claim holding the principal id.
    #[arg(long, env = "KAVACH_OIDC_PRINCIPAL_CLAIM", default_value = "sub")]
    oidc_principal_claim: String,

    /// Claim holding the principal's groups (array of strings).
    #[arg(long, env = "KAVACH_OIDC_GROUPS_CLAIM", default_value = "groups")]
    oidc_groups_claim: String,

    /// Allowed clock skew for `exp`/`nbf`.
    #[arg(long, env = "KAVACH_OIDC_LEEWAY_SECONDS", default_value_t = 60)]
    oidc_leeway_seconds: u64,
}

impl OidcArgs {
    fn into_config(self) -> Result<Option<OidcConfig>, String> {
        let jwks = match (self.oidc_jwks_file, self.oidc_jwks_url) {
            (Some(path), None) => Some(JwksSource::File(path)),
            (None, Some(url)) => Some(JwksSource::Url(url)),
            _ => None,
        };
        match (self.oidc_issuer, self.oidc_audience, jwks) {
            (None, None, None) => Ok(None),
            (Some(issuer), Some(audience), Some(jwks)) => Ok(Some(OidcConfig {
                issuer,
                audience,
                jwks,
                principal_claim: self.oidc_principal_claim,
                groups_claim: self.oidc_groups_claim,
                leeway_seconds: self.oidc_leeway_seconds,
            })),
            _ => Err("OIDC needs --oidc-issuer, --oidc-audience and one of \
                      --oidc-jwks-file / --oidc-jwks-url"
                .into()),
        }
    }
}

/// Console sign-in (ADR-018): the API as a confidential OIDC client with
/// PKCE, an `HttpOnly` session cookie for the browser. Off unless
/// `--console-client-id` is set; needs operator OIDC.
#[derive(clap::Args)]
#[allow(clippy::struct_field_names)] // field names become the `--console-*` flags
struct ConsoleLoginArgs {
    /// Client id registered for the console at the identity provider (must
    /// differ from the operator and agent audiences).
    #[arg(long, env = "KAVACH_CONSOLE_CLIENT_ID")]
    console_client_id: Option<String>,

    /// File holding the console client secret (one line; owner-only under
    /// --require-hardening).
    #[arg(long, env = "KAVACH_CONSOLE_CLIENT_SECRET_FILE")]
    console_client_secret_file: Option<PathBuf>,

    /// The exact redirect URI registered at the IdP: https://<host>/auth/callback
    /// (http://localhost only with --insecure-dev).
    #[arg(long, env = "KAVACH_CONSOLE_REDIRECT_URI")]
    console_redirect_uri: Option<String>,

    /// Authorization endpoint. With --console-token-endpoint, replaces discovery
    /// (otherwise read once from {issuer}/.well-known/openid-configuration).
    #[arg(long, env = "KAVACH_CONSOLE_AUTHORIZATION_ENDPOINT")]
    console_authorization_endpoint: Option<String>,

    /// Token endpoint (with --console-authorization-endpoint).
    #[arg(long, env = "KAVACH_CONSOLE_TOKEN_ENDPOINT")]
    console_token_endpoint: Option<String>,

    /// RFC 7009 revocation endpoint: logout revokes the refresh token there.
    #[arg(long, env = "KAVACH_CONSOLE_REVOCATION_ENDPOINT")]
    console_revocation_endpoint: Option<String>,

    /// End-session endpoint, used only with --console-idp-logout.
    #[arg(long, env = "KAVACH_CONSOLE_END_SESSION_ENDPOINT")]
    console_end_session_endpoint: Option<String>,

    /// Scopes asked for (space-separated; must include openid; never offline_access).
    #[arg(long, env = "KAVACH_CONSOLE_SCOPE", default_value = kavach_api::console_login::DEFAULT_SCOPE)]
    console_scope: String,

    /// Minutes without a request before a session ends (5-60).
    #[arg(long, env = "KAVACH_CONSOLE_SESSION_IDLE_MINUTES",
          default_value_t = kavach_api::console_login::DEFAULT_IDLE_MINUTES)]
    console_session_idle_minutes: u64,

    /// Minutes after sign-in when a session ends whatever happens (at most 720,
    /// at least the idle limit). A refresh never extends it.
    #[arg(long, env = "KAVACH_CONSOLE_SESSION_ABSOLUTE_MINUTES",
          default_value_t = kavach_api::console_login::DEFAULT_ABSOLUTE_MINUTES)]
    console_session_absolute_minutes: u64,

    /// Logout also returns the IdP end-session URL (signs out of the IdP).
    #[arg(long, env = "KAVACH_CONSOLE_IDP_LOGOUT")]
    console_idp_logout: bool,

    /// Most live console sessions (1-10000). A full table refuses new sign-ins.
    #[arg(long, env = "KAVACH_CONSOLE_MAX_SESSIONS",
          default_value_t = kavach_api::console_login::DEFAULT_MAX_SESSIONS)]
    console_max_sessions: usize,

    /// IdP ACR value mapped to the intended WebAuthn/passkey flow for D17.
    /// Step-up is not enabled unless this value is configured.
    #[arg(long, env = "KAVACH_CONSOLE_STEP_UP_ACR")]
    console_step_up_acr: Option<String>,
}

impl ConsoleLoginArgs {
    fn into_settings(self) -> Result<Option<ConsoleLoginSettings>, String> {
        let endpoints = match (
            self.console_authorization_endpoint,
            self.console_token_endpoint,
        ) {
            (Some(authorization), Some(token)) => Some(IdpEndpoints {
                authorization,
                token,
                revocation: self.console_revocation_endpoint,
                end_session: self.console_end_session_endpoint,
            }),
            (None, None)
                if self.console_revocation_endpoint.is_none()
                    && self.console_end_session_endpoint.is_none() =>
            {
                None
            }
            _ => {
                return Err(
                    "console login endpoints: set both --console-authorization-endpoint \
                            and --console-token-endpoint (with the optional revocation and \
                            end-session endpoints), or none of them to use discovery"
                        .into(),
                )
            }
        };
        let step_up_acr = self.console_step_up_acr;
        match (
            self.console_client_id,
            self.console_client_secret_file,
            self.console_redirect_uri,
        ) {
            (None, None, None) if endpoints.is_none() && step_up_acr.is_none() => Ok(None),
            (Some(client_id), Some(secret_file), Some(redirect_uri)) => {
                Ok(Some(ConsoleLoginSettings {
                    endpoints,
                    scope: self.console_scope,
                    idle_minutes: self.console_session_idle_minutes,
                    absolute_minutes: self.console_session_absolute_minutes,
                    idp_logout: self.console_idp_logout,
                    max_sessions: self.console_max_sessions,
                    step_up_acr,
                    ..ConsoleLoginSettings::new(&client_id, secret_file, &redirect_uri)
                }))
            }
            (None, None, None) => Err(
                "--console-step-up-acr requires console login; configure --console-client-id, \
                 --console-client-secret-file and --console-redirect-uri"
                    .into(),
            ),
            _ => Err(
                "console login needs --console-client-id, --console-client-secret-file \
                      and --console-redirect-uri"
                    .into(),
            ),
        }
    }
}

#[derive(Parser)]
#[allow(clippy::struct_excessive_bools)] // independent command-line switches
#[command(name = "kavach-api", about = "Kavach sync evaluate HTTP + gRPC API")]
struct Cli {
    /// Log format: `text` or `json` (one object per line). Every line is
    /// redacted before it is written; the filter is `KAVACH_LOG` (default
    /// `info`).
    #[arg(long, env = "KAVACH_LOG_FORMAT", default_value = "text")]
    log_format: kavach_telemetry::LogFormat,

    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: SocketAddr,

    #[arg(long, default_value = "0.0.0.0:50051")]
    grpc_listen: SocketAddr,

    #[arg(long, env = "KAVACH_PACK_PATH")]
    pack: PathBuf,

    #[arg(long, env = "KAVACH_MODEL_PATH")]
    model: PathBuf,

    /// Expected SHA-256 of the pack file (`sha256:<hex>` or bare hex). Startup fails on mismatch.
    #[arg(long, env = "KAVACH_PACK_SHA256")]
    pack_sha256: Option<String>,

    /// When set, `/v1/evaluate` requires an HMAC v2 signature
    /// (`X-Kavach-Timestamp`, `X-Kavach-Nonce`, `X-Kavach-Signature`; ADR-008).
    #[arg(long, env = "KAVACH_HMAC_SECRET")]
    hmac_secret: Option<String>,

    #[command(flatten)]
    oidc: OidcArgs,

    #[command(flatten)]
    agents: AgentArgs,

    #[command(flatten)]
    console_login: ConsoleLoginArgs,

    #[arg(long, value_enum, default_value = "memory")]
    evidence_store: EvidenceStoreArg,

    #[arg(long, env = "KAVACH_DATABASE_URL")]
    database_url: Option<String>,

    /// Enable active/passive Postgres lease ownership (HA reference plan).
    #[arg(long, env = "KAVACH_HA_ACTIVE_PASSIVE")]
    ha_active_passive: bool,

    /// Owner role that runs migrations. When set, `--database-url` should be
    /// the least-privilege `kavach_runtime` role and never migrates.
    #[arg(long, env = "KAVACH_MIGRATION_DATABASE_URL")]
    migration_database_url: Option<String>,

    /// Extra CA certificates (PEM) trusted for the Postgres server's
    /// certificate, besides the system roots (e.g. a private CA).
    /// Connections always use TLS with a verified certificate and host
    /// name (`sslmode=verify-full`); a weaker `sslmode` in a database URL
    /// is refused outside `--insecure-dev`.
    #[arg(long, env = "KAVACH_DATABASE_CA")]
    database_ca: Option<PathBuf>,

    /// Connections in the runtime Postgres pool (1–256).
    #[arg(
        long,
        env = "KAVACH_DATABASE_POOL_SIZE",
        default_value_t = kavach_api::DEFAULT_POOL_SIZE,
        value_parser = clap::value_parser!(u32).range(1..=256)
    )]
    database_pool_size: u32,

    /// Access control for API principals. Defaults to Cedar (secure by default).
    #[arg(
        long,
        value_enum,
        default_value = "cedar",
        env = "KAVACH_ACCESS_CONTROL"
    )]
    access_control: AccessControlArg,

    /// Postgres mode only: start even if `--pack` differs from the governed
    /// runtime pointer. Audited; for recovery, not routine use.
    #[arg(long, env = "KAVACH_BOOTSTRAP_PACK")]
    bootstrap_pack: bool,

    /// Postgres recovery: start with a model file that differs from the pinned
    /// one. Re-pins path and digest only (audited); status and mode stay governed.
    #[arg(long, env = "KAVACH_BOOTSTRAP_MODEL")]
    bootstrap_model: bool,

    /// Trusted pack signers file (JSON). When set, every pack load (startup,
    /// activate, rollback, model update) requires a valid `<pack>.sig`.
    #[arg(long, env = "KAVACH_PACK_SIGNERS")]
    pack_signers: Option<PathBuf>,

    /// Required to run with `--access-control none`. Development only: every request is allowed.
    #[arg(long, env = "KAVACH_INSECURE_DEV")]
    insecure_dev: bool,

    /// Refuse to start unless every guarantee is on: no relaxation, TLS,
    /// HTTPS providers, owner-only secret files, no development routes
    /// (docs/BYPASS_INVENTORY.md). Every failing condition is reported.
    #[arg(long, env = "KAVACH_REQUIRE_HARDENING")]
    require_hardening: bool,

    /// Owner-only 32-byte hex key file for durable D17 review snapshots.
    #[arg(long, env = "KAVACH_REVIEW_SNAPSHOT_KEY_FILE")]
    review_snapshot_key_file: Option<PathBuf>,

    /// Rotation id stored with encrypted D17 review snapshots.
    #[arg(
        long,
        env = "KAVACH_REVIEW_SNAPSHOT_KEY_ID",
        default_value = kavach_api::config::DEFAULT_REVIEW_SNAPSHOT_KEY_ID
    )]
    review_snapshot_key_id: String,

    /// Previous owner-only D17 keys used only to decrypt live envelopes (repeatable `KEY_ID=PATH`).
    #[arg(long = "review-snapshot-previous-key", value_name = "KEY_ID=PATH", action = clap::ArgAction::Append)]
    review_snapshot_previous_keys: Vec<String>,

    /// Cedar policy file (required when --access-control cedar).
    #[arg(long, env = "KAVACH_CEDAR_POLICY")]
    cedar_policy: Option<PathBuf>,

    /// Cedar entities JSON (required when --access-control cedar).
    #[arg(long, env = "KAVACH_CEDAR_ENTITIES")]
    cedar_entities: Option<PathBuf>,

    #[arg(long, env = "KAVACH_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    #[arg(long, env = "KAVACH_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// When set with cert/key, require client certificate (mTLS).
    #[arg(long, env = "KAVACH_TLS_CLIENT_CA")]
    tls_client_ca: Option<PathBuf>,

    /// Use the client certificate's single SAN of this type (uri, e.g. a
    /// SPIFFE id, or dns) as the principal. Requires --tls-client-ca.
    #[arg(long, env = "KAVACH_MTLS_PRINCIPAL_SAN", value_enum)]
    mtls_principal_san: Option<MtlsSanKind>,

    /// Hours a change request stays approvable (1-168).
    #[arg(
        long,
        env = "KAVACH_CHANGE_REQUEST_TTL_HOURS",
        default_value_t = DEFAULT_CHANGE_TTL_HOURS,
        value_parser = clap::value_parser!(u64).range(1..=168)
    )]
    change_request_ttl_hours: u64,

    /// Seconds a request may take to produce its response, reading its
    /// body included, before it is answered 503 (every listener; 1-300).
    #[arg(
        long,
        env = "KAVACH_REQUEST_TIMEOUT_SECONDS",
        default_value_t = limits::DEFAULT_REQUEST_TIMEOUT_SECONDS,
        value_parser = clap::value_parser!(u64).range(limits::REQUEST_TIMEOUT_SECONDS)
    )]
    request_timeout_seconds: u64,

    /// Seconds a connection with no request in progress has to deliver a
    /// complete request head, from being accepted (TLS handshake included)
    /// or from its last response bytes; then it is closed (every listener;
    /// 1-120).
    #[arg(
        long,
        env = "KAVACH_HEADER_READ_TIMEOUT_SECONDS",
        default_value_t = limits::DEFAULT_HEADER_READ_TIMEOUT_SECONDS,
        value_parser = clap::value_parser!(u64).range(limits::HEADER_READ_TIMEOUT_SECONDS)
    )]
    header_read_timeout_seconds: u64,

    /// Seconds a TLS handshake may take (every listener; 1-60).
    #[arg(
        long,
        env = "KAVACH_TLS_HANDSHAKE_TIMEOUT_SECONDS",
        default_value_t = limits::DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS,
        value_parser = clap::value_parser!(u64).range(limits::TLS_HANDSHAKE_TIMEOUT_SECONDS)
    )]
    tls_handshake_timeout_seconds: u64,

    /// Requests each listener handles at once; one over the cap is answered
    /// 503 with Retry-After at once, never queued (1-65536).
    #[arg(
        long,
        env = "KAVACH_MAX_IN_FLIGHT_REQUESTS",
        default_value_t = limits::DEFAULT_MAX_IN_FLIGHT_REQUESTS,
        value_parser = clap::value_parser!(u64).range(limits::MAX_IN_FLIGHT_REQUESTS)
    )]
    max_in_flight_requests: u64,

    /// ADR-019: the first two superadmins, '<issuer>#<subject>,<issuer>#<subject>'
    /// (two different people of --oidc-issuer). Applied at startup only
    /// while the tenant has no active superadmin; afterwards ignored with a
    /// warning.
    #[arg(long, env = "KAVACH_BOOTSTRAP_SUPERADMINS")]
    bootstrap_superadmins: Option<String>,

    /// ADR-019 §9: the access review marks a person stale when they were
    /// last seen more than this many days ago, or never (1 to 3650).
    #[arg(
        long,
        env = "KAVACH_ACCESS_REVIEW_STALE_DAYS",
        default_value_t = kavach_api::config::DEFAULT_ACCESS_REVIEW_STALE_DAYS,
        value_parser = clap::value_parser!(u32)
            .range(1..=i64::from(kavach_api::config::MAX_ACCESS_REVIEW_STALE_DAYS))
    )]
    access_review_stale_days: u32,
}

fn parse_review_snapshot_previous_key(entry: &str) -> Result<(String, PathBuf), String> {
    let (key_id, path) = entry
        .split_once('=')
        .ok_or_else(|| "--review-snapshot-previous-key must be KEY_ID=PATH".to_owned())?;
    if key_id.is_empty() || path.is_empty() {
        return Err("--review-snapshot-previous-key must be KEY_ID=PATH".into());
    }
    Ok((key_id.to_owned(), PathBuf::from(path)))
}

fn parse_reference_vault_previous_key(entry: &str) -> Result<(String, PathBuf), String> {
    let (key_id, path) = entry
        .split_once('=')
        .ok_or_else(|| "--reference-vault-previous-key must be KEY_ID=PATH".to_owned())?;
    if key_id.is_empty() || path.is_empty() {
        return Err("--reference-vault-previous-key must be KEY_ID=PATH".into());
    }
    Ok((key_id.to_owned(), PathBuf::from(path)))
}

impl Cli {
    /// The limits every listener applies (bounds checked again here).
    fn listener_limits(&self) -> Result<ListenerLimits, String> {
        ListenerLimits::from_settings(
            self.request_timeout_seconds,
            self.header_read_timeout_seconds,
            self.tls_handshake_timeout_seconds,
            self.max_in_flight_requests,
        )
    }
}

/// A request must be able to outlast the calls it waits on: the provider
/// call of a tool call and an HSM signature.
fn validate_request_timeout(limits: &ListenerLimits, config: &ApiConfig) -> Result<(), String> {
    let Some(dp) = config.dataplane.as_ref() else {
        return Ok(());
    };
    let request_ms = limits.request_timeout.as_millis();
    if request_ms <= u128::from(dp.provider_timeout_ms) {
        return Err(format!(
            "--request-timeout-seconds ({} s) must exceed --provider-timeout-ms ({} ms)",
            limits.request_timeout.as_secs(),
            dp.provider_timeout_ms
        ));
    }
    if let Some(hsm) = dp.hsm.as_ref() {
        if request_ms <= hsm.call_timeout.as_millis() {
            return Err(format!(
                "--request-timeout-seconds ({} s) must exceed --hsm-timeout-ms ({} ms)",
                limits.request_timeout.as_secs(),
                hsm.call_timeout.as_millis()
            ));
        }
    }
    Ok(())
}

impl Cli {
    fn into_config(self) -> Result<(ApiConfig, Option<ConsoleLoginSettings>), String> {
        let console_login = self.console_login.into_settings()?;
        let evidence_store = match self.evidence_store {
            EvidenceStoreArg::Memory => EvidenceStoreKind::Memory,
            EvidenceStoreArg::Postgres => {
                let database_url = self.database_url.ok_or(
                    "postgres evidence store requires --database-url or KAVACH_DATABASE_URL",
                )?;
                EvidenceStoreKind::Postgres { database_url }
            }
        };

        let mode = match self.access_control {
            AccessControlArg::None => AccessControlMode::None,
            AccessControlArg::Cedar => AccessControlMode::Cedar,
        };
        let access_control = resolve_access_control(
            mode,
            self.insecure_dev,
            self.cedar_policy,
            self.cedar_entities,
        )?;
        let oidc = self.oidc.into_config()?;
        let roles = kavach_api::RolesConfig {
            tenant_id: self.agents.tenant_id.clone(),
            bootstrap_superadmins: match self.bootstrap_superadmins.as_deref() {
                None => Vec::new(),
                Some(value) => kavach_api::config::parse_bootstrap_superadmins(
                    value,
                    oidc.as_ref().map(|o| o.issuer.as_str()),
                )?,
            },
            access_review_stale_days: self.access_review_stale_days,
        };
        let dataplane = self.agents.into_config(oidc.as_ref())?;

        let tls = match (self.tls_cert, self.tls_key) {
            (Some(cert_path), Some(key_path)) => Some(TlsConfig::from_paths(
                cert_path,
                key_path,
                self.tls_client_ca,
            )),
            (None, None) => None,
            _ => {
                return Err("TLS requires both --tls-cert and --tls-key".into());
            }
        };

        let config = ApiConfig {
            pack_path: self.pack,
            model_path: self.model,
            hmac_secret: self.hmac_secret,
            evidence_store,
            access_control,
            tls,
            pack_sha256: self.pack_sha256,
            bootstrap_pack: self.bootstrap_pack,
            bootstrap_model: self.bootstrap_model,
            pack_signers: self.pack_signers,
            oidc,
            insecure_dev: self.insecure_dev,
            mtls_principal_san: self.mtls_principal_san,
            change_ttl_seconds: self.change_request_ttl_hours * 3600,
            migration_database_url: self.migration_database_url,
            database_tls: kavach_api::DatabaseTls::new(self.insecure_dev, self.database_ca),
            database_pool_size: self.database_pool_size,
            dataplane,
            require_hardening: self.require_hardening,
            review_snapshot_key_file: self.review_snapshot_key_file,
            review_snapshot_key_id: self.review_snapshot_key_id,
            review_snapshot_previous_keys: self
                .review_snapshot_previous_keys
                .into_iter()
                .map(|entry| parse_review_snapshot_previous_key(&entry))
                .collect::<Result<Vec<_>, _>>()?,
            roles,
        };
        validate_principal_sources(&config)?;
        validate_hmac_secret(config.hmac_secret.as_deref())?;
        if let Some(login) = &console_login {
            kavach_api::console_login::validate(login, &config)?;
        }
        Ok((config, console_login))
    }
}

#[cfg(test)]
mod review_snapshot_cli_tests {
    use super::*;

    #[test]
    fn ha_active_passive_is_an_explicit_opt_in() {
        let cli = Cli::try_parse_from([
            "kavach-api",
            "--pack",
            "pack.yaml",
            "--model",
            "model.yaml",
            "--ha-active-passive",
        ])
        .expect("parse HA opt-in");
        assert!(cli.ha_active_passive);
    }

    #[test]
    fn parses_repeated_previous_snapshot_keys() {
        let cli = Cli::try_parse_from([
            "kavach-api",
            "--pack",
            "pack.yaml",
            "--model",
            "model.yaml",
            "--review-snapshot-previous-key",
            "review-old=/keys/old.key",
            "--review-snapshot-previous-key",
            "review-older=/keys/older.key",
        ])
        .expect("parse CLI");
        assert_eq!(
            cli.review_snapshot_previous_keys,
            ["review-old=/keys/old.key", "review-older=/keys/older.key"]
        );
    }

    #[test]
    fn parses_key_id_and_path_and_rejects_malformed_values() {
        assert_eq!(
            parse_review_snapshot_previous_key("old=/keys/old.key").expect("key spec"),
            ("old".into(), PathBuf::from("/keys/old.key"))
        );
        for value in ["", "no-separator", "=path", "id="] {
            assert!(parse_review_snapshot_previous_key(value).is_err());
        }
    }

    #[test]
    fn parses_repeated_previous_reference_vault_keys() {
        let cli = Cli::try_parse_from([
            "kavach-api",
            "--pack",
            "pack.yaml",
            "--model",
            "model.yaml",
            "--reference-vault-previous-key",
            "vault-old=/keys/vault-old.key",
            "--reference-vault-previous-key",
            "vault-older=/keys/vault-older.key",
        ])
        .expect("parse CLI");
        assert_eq!(
            cli.agents.reference_vault_previous_keys,
            [
                "vault-old=/keys/vault-old.key",
                "vault-older=/keys/vault-older.key"
            ]
        );
    }

    #[test]
    fn parses_reference_vault_key_id_and_path_and_rejects_malformed_values() {
        assert_eq!(
            parse_reference_vault_previous_key("old=/keys/old.key").expect("key spec"),
            ("old".into(), PathBuf::from("/keys/old.key"))
        );
        for value in ["", "no-separator", "=path", "id="] {
            assert!(parse_reference_vault_previous_key(value).is_err());
        }
    }
}

#[tokio::main]
#[allow(clippy::too_many_lines)] // one startup sequence, read top to bottom
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    kavach_telemetry::init(cli.log_format)?;
    let ha_active_passive = cli.ha_active_passive;
    let http_listen = cli.listen;
    let grpc_listen = cli.grpc_listen;
    let sor_listen = cli.agents.sor_listen;
    let agent_listen = cli.agents.agent_listen;
    let grace = std::time::Duration::from_secs(cli.agents.shutdown_grace_seconds);
    let agent_only = cli.agents.agent_only;
    let invalid = |msg: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg);
    let limits = cli.listener_limits().map_err(invalid)?;
    let (config, console_login) = cli.into_config().map_err(invalid)?;
    if ha_active_passive && !matches!(&config.evidence_store, EvidenceStoreKind::Postgres { .. }) {
        return Err(invalid("--ha-active-passive requires Postgres storage".into()).into());
    }
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    validate_request_timeout(&limits, &config).map_err(invalid)?;
    let hardening_violations = |built: &[kavach_api::relaxations::Relaxation]| {
        let mut violations = kavach_api::hardening::violations(&config, built);
        violations.extend(kavach_api::hardening::console_login_violations(
            console_login.as_ref(),
        ));
        violations
    };
    if config.require_hardening {
        // Before anything is built, migrated or written.
        refuse_unless_hardened(&hardening_violations(&[]));
    }
    let mut state = AppState::from_config(&config).await?;
    if let Some(settings) = &console_login {
        let login = ConsoleLogin::start(settings, &config)
            .await
            .map_err(|msg| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))?;
        tracing::info!(
            origin = %login.origin(),
            "console sign-in enabled (ADR-018): HttpOnly session cookie, tokens kept server-side"
        );
        state = state.with_console_login(Arc::new(login));
    }
    let ha_lease_task = if ha_active_passive {
        let lease_store = state
            .active_lease_store()
            .ok_or_else(|| invalid("HA lease store is unavailable".into()))?;
        let (fence, task) = kavach_api::ha_lease::start(
            lease_store,
            config.roles.tenant_id.clone(),
            stop_rx.clone(),
        )
        .await?;
        state = state.with_ha_fence(fence);
        Some(task)
    } else {
        None
    };
    let state = Arc::new(state);
    if config.require_hardening {
        // What only the build knows (a relaxation of the agent surfaces).
        let built = state
            .dataplane()
            .map(|dp| dp.relaxations().to_vec())
            .unwrap_or_default();
        refuse_unless_hardened(&hardening_violations(&built));
    }
    kavach_api::revocation_audit::start(&state);
    let pack_sha256 = state
        .runtime()?
        .pack_sha256
        .unwrap_or_else(|| "none".into());
    let http_app = router(state.clone());
    let sor_app = state
        .dataplane()
        .is_some()
        .then(|| kavach_api::dataplane::sor_router(state.clone()));
    let agent_app = state
        .dataplane()
        .is_some()
        .then(|| kavach_api::dataplane::agent_router(state.clone()));
    let tools_sha256 = state.dataplane().map(|dp| {
        format!(
            "{}; credentials signed by {} for {}; references: {}",
            dp.core().tools().digest(),
            dp.broker().kid(),
            dp.broker().audiences().collect::<Vec<_>>().join(", "),
            dp.resolver().describe()
        )
    });
    let review_snapshot_store = state.review_snapshot_store().clone();
    let stopping = state.clone();
    let grpc_service = GrpcEvaluateService::with_limits(state, &limits);

    print_banner(&config, http_listen, grpc_listen, &pack_sha256);

    log_agent_surfaces(
        agent_only,
        tools_sha256.as_deref(),
        agent_listen,
        sor_listen,
    );

    let tls_ref = config.tls.as_ref();
    // One signal stops every listener. A listener stops accepting at once
    // and lets its requests finish.
    let _ha_lease_task = ha_lease_task;
    let _review_snapshot_cleanup =
        kavach_api::review_snapshot_cleanup::start(review_snapshot_store, stop_rx.clone());
    let _runtime_pointer_sync =
        kavach_api::runtime_pointer_sync::start(stopping.clone(), stop_rx.clone());
    let stopped = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|stop| *stop).await;
    };
    let (sor_stop, agent_stop, http_stop, grpc_stop) = (
        stopped(stop_rx.clone()),
        stopped(stop_rx.clone()),
        stopped(stop_rx.clone()),
        stopped(stop_rx),
    );
    let servers = async move {
        tokio::try_join!(
            async move {
                if let Some(app) = sor_app {
                    serve_http_until_with_limits(app, sor_listen, tls_ref, sor_stop, grace, limits)
                        .await?;
                }
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            },
            async move {
                if let Some(app) = agent_app {
                    serve_http_until_with_limits(
                        app,
                        agent_listen,
                        tls_ref,
                        agent_stop,
                        grace,
                        limits,
                    )
                    .await?;
                }
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            },
            async move {
                serve_http_until_with_limits(
                    http_app,
                    http_listen,
                    tls_ref,
                    http_stop,
                    grace,
                    limits,
                )
                .await?;
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            },
            async move {
                // The evaluate service is the credit track's: not served.
                if agent_only {
                    return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
                }
                serve_grpc_until(grpc_service, grpc_listen, tls_ref, grpc_stop, limits).await?;
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            }
        )
    };
    tokio::pin!(servers);
    let told_to_stop = tokio::select! {
        served = &mut servers => {
            served?;
            false
        }
        () = shutdown::termination() => true,
    };
    if !told_to_stop {
        return Ok(());
    }

    shutdown::stop_and_checkpoint(servers.as_mut(), &stop_tx, grace, stopping.dataplane())
        .await
        .map_err(Into::into)
}

/// Prints every violation and exits with `EX_CONFIG`; returns when there is
/// none.
fn refuse_unless_hardened(violations: &[kavach_api::hardening::Violation]) {
    if violations.is_empty() {
        return;
    }
    eprintln!(
        "{}",
        kavach_api::hardening::refusal("kavach-api", violations)
    );
    std::process::exit(kavach_api::hardening::EXIT_REFUSED);
}

/// What the agent surfaces serve, once, at startup.
fn log_agent_surfaces(
    agent_only: bool,
    tools: Option<&str>,
    agent_listen: SocketAddr,
    sor_listen: SocketAddr,
) {
    if agent_only {
        tracing::info!(
            "agent-only mode: the evaluate, pack, model, retention, incident and batch routes, \
             the console and the gRPC evaluate service are not served"
        );
    }
    if let Some(tools) = tools {
        tracing::info!(
            "agent surfaces enabled: agents on {agent_listen} (the only listener for the agent \
             network), /v1/sor/events on {sor_listen} (backend network only); tool registry \
             {tools}"
        );
    } else {
        tracing::info!("agent surfaces disabled (no --agent-oidc-audience)");
    }
}

/// Startup summary and warnings for unsafe development settings.
fn print_banner(
    config: &ApiConfig,
    http_listen: SocketAddr,
    grpc_listen: SocketAddr,
    pack_sha256: &str,
) {
    let tls_mode = if config.tls.as_ref().is_some_and(TlsConfig::is_mtls) {
        "mTLS"
    } else if config.tls.is_some() {
        "TLS"
    } else {
        "plain"
    };

    let insecure = matches!(config.access_control, AccessControlKind::None);
    let principal_sources = [
        (config.oidc.is_some(), "oidc-jwt"),
        (config.mtls_principal_san.is_some(), "mtls-san"),
        (config.insecure_dev, "insecure-header"),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, name)| *name)
    .collect::<Vec<_>>()
    .join("+");
    let principal_sources = if principal_sources.is_empty() {
        "none".to_string()
    } else {
        principal_sources
    };
    if config.insecure_dev && !insecure {
        tracing::warn!(
            "--insecure-dev accepts the self-asserted X-Kavach-Principal \
             header. Anyone who can reach this port can claim any principal. Development only."
        );
    }
    if insecure {
        tracing::warn!(
            "running with --insecure-dev: access control is DISABLED and \
             every request is allowed. Never use this outside local development."
        );
    }
    let relaxations = kavach_api::relaxations::of_config(config)
        .iter()
        .map(|r| r.as_str())
        .collect::<Vec<_>>()
        .join(",");
    if !relaxations.is_empty() {
        tracing::warn!(
            relaxations = %relaxations,
            "this process runs with guarantees relaxed (see /v1/runtime and the \
             kavach_relaxation_active metric)"
        );
    }
    tracing::info!(
        "listening http={} grpc={} transport={} evidence={:?} access_control={:?} \
         principal_sources={principal_sources} insecure_dev={} pack_sha256={}",
        http_listen,
        grpc_listen,
        tls_mode,
        config.evidence_store,
        config.access_control,
        insecure,
        pack_sha256
    );
}
