//! H2b: the verified client-certificate SAN is the principal, over real TLS
//! connections (HTTP via the peer-certificate acceptor, gRPC via
//! `peer_certs`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use kavach_api::proto::kavach::v1::evaluate_service_client::EvaluateServiceClient;
use kavach_api::proto::kavach::v1::{Consent, EvaluateRequest};
use kavach_api::{
    grpc_server_tls_config, router, serve_http_on, validate_principal_sources, AccessControlKind,
    ApiConfig, AppState, EvaluateServiceServer, EvidenceStoreKind, GrpcEvaluateService,
    MtlsSanKind, TlsConfig,
};
use prost_types::{value::Kind, Struct, Timestamp, Value};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use serde_json::json;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Server};

const LOS: &str = "spiffe://bank.test/los";
const OPS: &str = "spiffe://bank.test/ops";

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

struct Pki {
    dir: PathBuf,
    ca_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl Pki {
    fn new() -> Self {
        // Tests run in parallel and macOS clocks tick in microseconds: add a
        // counter so no two fixtures share (and overwrite) a directory.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("kavach-mtls-{}-{nanos}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let ca_pem = params.self_signed(&key).unwrap().pem();
        std::fs::write(dir.join("ca.pem"), &ca_pem).unwrap();
        Self {
            dir,
            ca_pem,
            issuer: Issuer::new(params, key),
        }
    }

    /// Issues a leaf certificate; returns (cert PEM, key PEM).
    fn leaf(&self, sans: Vec<SanType>, usage: ExtendedKeyUsagePurpose) -> (String, String) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = sans;
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn client(&self, uris: &[&str]) -> (String, String) {
        let sans = uris
            .iter()
            .map(|u| SanType::URI((*u).try_into().unwrap()))
            .collect();
        self.leaf(sans, ExtendedKeyUsagePurpose::ClientAuth)
    }

    fn tls_config(&self) -> TlsConfig {
        let (cert, key) = self.leaf(
            vec![SanType::DnsName("localhost".try_into().unwrap())],
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        std::fs::write(self.dir.join("server.pem"), cert).unwrap();
        std::fs::write(self.dir.join("server-key.pem"), key).unwrap();
        TlsConfig::from_paths(
            self.dir.join("server.pem"),
            self.dir.join("server-key.pem"),
            Some(self.dir.join("ca.pem")),
        )
    }
}

/// Static entities plus the LOS workload as an operator and viewer.
fn write_entities(dir: &Path) -> PathBuf {
    let mut entities: Vec<serde_json::Value> = serde_json::from_str(
        &std::fs::read_to_string(repo("crates/kavach-auth/policies/entities.example.json"))
            .unwrap(),
    )
    .unwrap();
    entities.push(json!({
        "uid": { "type": "Kavach::User", "id": LOS },
        "attrs": {},
        "parents": [
            { "type": "Kavach::Group", "id": "operators" },
            { "type": "Kavach::Group", "id": "viewers" },
            { "type": "Kavach::Group", "id": "change-approvers" }
        ]
    }));
    entities.push(json!({
        "uid": { "type": "Kavach::User", "id": OPS },
        "attrs": {},
        "parents": [{ "type": "Kavach::Group", "id": "admins" }]
    }));
    let path = dir.join("entities.json");
    std::fs::write(&path, serde_json::to_string(&entities).unwrap()).unwrap();
    path
}

fn config(pki: &Pki) -> ApiConfig {
    ApiConfig {
        pack_path: repo("packs/finance/v0.yaml"),
        model_path: repo("models/finance/credit-underwriting-v1.yaml"),
        hmac_secret: None,
        evidence_store: EvidenceStoreKind::Memory,
        access_control: AccessControlKind::Cedar {
            policy_path: repo("crates/kavach-auth/policies/kavach.cedar"),
            entities_path: write_entities(&pki.dir),
        },
        tls: Some(pki.tls_config()),
        pack_sha256: None,
        bootstrap_pack: false,
        bootstrap_model: false,
        pack_signers: None,
        oidc: None,
        insecure_dev: false,
        mtls_principal_san: Some(MtlsSanKind::Uri),
        change_ttl_seconds: 3600,
        migration_database_url: None,
        database_tls: kavach_api::DatabaseTls::development(),
        database_pool_size: kavach_api::DEFAULT_POOL_SIZE,
        dataplane: None,
    }
}

async fn spawn_https(pki: &Pki) -> SocketAddr {
    let config = config(pki);
    validate_principal_sources(&config).expect("valid config");
    let state = Arc::new(AppState::from_config(&config).await.expect("state"));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        serve_http_on(router(state), listener, config.tls.as_ref())
            .await
            .expect("https server");
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    addr
}

fn https_client(
    pki: &Pki,
    identity: Option<&(String, String)>,
    addr: SocketAddr,
) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap())
        .resolve("localhost", addr);
    if let Some((cert, key)) = identity {
        builder = builder
            .identity(reqwest::Identity::from_pem(format!("{cert}{key}").as_bytes()).unwrap());
    }
    builder.build().unwrap()
}

async fn get_runtime(client: &reqwest::Client, addr: SocketAddr, header: Option<&str>) -> u16 {
    let mut req = client.get(format!("https://localhost:{}/v1/runtime", addr.port()));
    if let Some(principal) = header {
        req = req.header("X-Kavach-Principal", principal);
    }
    req.send().await.expect("response").status().as_u16()
}

#[tokio::test]
async fn http_client_certificate_san_is_the_principal() {
    let pki = Pki::new();
    let addr = spawn_https(&pki).await;

    let los = https_client(&pki, Some(&pki.client(&[LOS])), addr);
    assert_eq!(get_runtime(&los, addr, None).await, 200);
    // A certificate principal plus the self-asserted header is ambiguous.
    assert_eq!(get_runtime(&los, addr, Some("admin-1")).await, 400);

    // Verified certificate, but its principal has no grants.
    let stranger = https_client(&pki, Some(&pki.client(&["spiffe://bank.test/other"])), addr);
    assert_eq!(get_runtime(&stranger, addr, None).await, 403);

    // Two URI SANs: no principal, and the header is not a fallback.
    let two = https_client(
        &pki,
        Some(&pki.client(&[LOS, "spiffe://bank.test/x"])),
        addr,
    );
    assert_eq!(get_runtime(&two, addr, None).await, 401);
    assert_eq!(get_runtime(&two, addr, Some("viewer-1")).await, 401);

    // Without a client certificate the TLS handshake fails.
    let anonymous = https_client(&pki, None, addr);
    assert!(anonymous
        .get(format!("https://localhost:{}/v1/runtime", addr.port()))
        .send()
        .await
        .is_err());
}

#[tokio::test]
async fn certificate_principals_may_propose_but_never_approve() {
    let pki = Pki::new();
    let addr = spawn_https(&pki).await;
    let base = format!("https://localhost:{}/v1/change-requests", addr.port());

    let ops = https_client(&pki, Some(&pki.client(&[OPS])), addr);
    let response = ops
        .post(&base)
        .json(&json!({ "kind": "update_retention", "params": { "evidence_retention_days": 30 } }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 201);
    let request: serde_json::Value = response.json().await.unwrap();
    assert_eq!(request["proposer_key"], format!("mtls:{OPS}"));

    // The LOS workload holds the approver group, but a certificate is a
    // workload identity, not a person.
    let los = https_client(&pki, Some(&pki.client(&[LOS])), addr);
    let response = los
        .post(format!(
            "{base}/{}/approve",
            request["id"].as_str().unwrap()
        ))
        .json(&json!({ "change_digest": request["change_digest"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 403);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("OIDC user token"),
        "{body}"
    );
}

#[tokio::test]
async fn certificate_from_another_ca_is_rejected() {
    let pki = Pki::new();
    let addr = spawn_https(&pki).await;
    let rogue = Pki::new();
    let client = https_client(&pki, Some(&rogue.client(&[LOS])), addr);
    assert!(client
        .get(format!("https://localhost:{}/v1/runtime", addr.port()))
        .send()
        .await
        .is_err());
}

#[test]
fn mtls_principals_need_client_certificate_verification() {
    let pki = Pki::new();
    let mut config = config(&pki);
    assert!(validate_principal_sources(&config).is_ok());
    config.tls = Some(TlsConfig::from_paths("c".into(), "k".into(), None));
    assert!(validate_principal_sources(&config).is_err());
    config.tls = None;
    assert!(validate_principal_sources(&config).is_err());
}

fn evaluate_request() -> EvaluateRequest {
    let now = Utc::now();
    let ts = Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos().cast_signed(),
    };
    let mut input = Struct::default();
    for (field, value) in [("debt_ratio", 0.32), ("credit_score", 740.0)] {
        input.fields.insert(
            field.into(),
            Value {
                kind: Some(Kind::NumberValue(value)),
            },
        );
    }
    EvaluateRequest {
        model_id: "credit-underwriting-v1".into(),
        model_version: "1.0.0".into(),
        purpose: "credit_decision".into(),
        consent: Some(Consent {
            purpose_id: "credit_decision".into(),
            timestamp: Some(ts),
            valid: None,
        }),
        input: Some(input),
        decision_time: Some(ts),
        ..Default::default()
    }
}

async fn grpc_client(
    pki: &Pki,
    addr: SocketAddr,
    identity: &(String, String),
) -> EvaluateServiceClient<Channel> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&pki.ca_pem))
        .identity(Identity::from_pem(&identity.0, &identity.1))
        .domain_name("localhost");
    let channel = Channel::from_shared(format!("https://127.0.0.1:{}", addr.port()))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .expect("grpc connect");
    EvaluateServiceClient::new(channel)
}

#[tokio::test]
async fn grpc_client_certificate_san_is_the_principal() {
    let pki = Pki::new();
    let config = config(&pki);
    let state = Arc::new(AppState::from_config(&config).await.expect("state"));
    let server_tls = grpc_server_tls_config(config.tls.as_ref())
        .await
        .unwrap()
        .expect("tls");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    tokio::spawn(async move {
        Server::builder()
            .tls_config(server_tls)
            .unwrap()
            .add_service(EvaluateServiceServer::new(GrpcEvaluateService::new(state)))
            .serve(addr)
            .await
            .expect("grpc server");
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut los = grpc_client(&pki, addr, &pki.client(&[LOS])).await;
    los.evaluate(evaluate_request())
        .await
        .expect("operator workload may evaluate");

    let mut stranger = grpc_client(&pki, addr, &pki.client(&["spiffe://bank.test/other"])).await;
    let status = stranger.evaluate(evaluate_request()).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}
