use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use kavach_api::proto::kavach::v1::evaluate_service_client::EvaluateServiceClient;
use kavach_api::proto::kavach::v1::{Consent, EvaluateRequest};
use kavach_api::{AppState, EvaluateServiceServer, GrpcEvaluateService};
use prost_types::{value::Kind, Struct, Timestamp, Value};
use tonic::transport::{Channel, Server};

fn fixture_paths() -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    (
        root.join("packs/finance/v0.yaml"),
        root.join("models/finance/credit-underwriting-v1.yaml"),
    )
}

async fn spawn_grpc_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let (pack, model) = fixture_paths();
    let state = Arc::new(AppState::from_paths(&pack, &model, None).expect("state"));
    let service = EvaluateServiceServer::new(GrpcEvaluateService::new(state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(service)
            .serve(addr)
            .await
            .expect("grpc server");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, handle)
}

fn sample_proto_request() -> EvaluateRequest {
    let now = Utc::now();
    let ts = Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos().cast_signed(),
    };
    let mut input = Struct::default();
    input.fields.insert(
        "debt_ratio".into(),
        Value {
            kind: Some(Kind::NumberValue(0.32)),
        },
    );
    input.fields.insert(
        "credit_score".into(),
        Value {
            kind: Some(Kind::NumberValue(740.0)),
        },
    );

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
        output: None,
        score: None,
        confidence: Some(0.89),
        decision_time: Some(ts),
        correlation_id: "grpc-golden-clean-001".into(),
        idempotency_key: None,
    }
}

#[tokio::test]
async fn grpc_evaluate_returns_pass() {
    let (addr, handle) = spawn_grpc_server().await;
    let endpoint = format!("http://{addr}");
    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = EvaluateServiceClient::new(channel);

    let response = client
        .evaluate(sample_proto_request())
        .await
        .expect("rpc")
        .into_inner();

    assert_eq!(
        response.returned_decision,
        i32::from(kavach_api::proto::kavach::v1::Decision::Pass)
    );
    assert_eq!(
        response.policy_decision,
        i32::from(kavach_api::proto::kavach::v1::Decision::Pass)
    );
    assert!(!response.evidence_id.is_empty());

    handle.abort();
}
