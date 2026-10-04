//! KMS milestone K2: the API with its signing keys in an HSM (SoftHSM2).
//!
//! Runs when `KAVACH_TEST_PKCS11_MODULE` and `SOFTHSM2_CONF` point at a
//! prepared token (`scripts/softhsm-test-token.sh`; CI does this); skipped
//! otherwise. Each test makes its own keys, with labels unique to the run.

mod agent_fixture;
mod hsm_common;

use std::time::{Duration, Instant};

use agent_fixture::gateway_with;
use axum::http::StatusCode;
use hsm_common::{hsm_config, module, runtime, serial};
use kavach_api::AppState;
use kavach_dataplane::Tick;

/// Mandate, evidence record, credential and checkpoint are all signed in
/// the HSM on a real delivered call, and `/v1/runtime` says so.
#[tokio::test(flavor = "multi_thread")]
async fn a_delivered_call_is_signed_in_the_hsm_end_to_end() {
    let Some(module) = module() else {
        eprintln!("skipped: set KAVACH_TEST_PKCS11_MODULE and SOFTHSM2_CONF");
        return;
    };
    let _serial = serial().await;
    let run = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    let (api, credential) = hsm_config(module, &run);
    // The provider trusts the HSM's credential key: it only accepts
    // credentials that key signed.
    let gw = gateway_with(api, Some("+910000000001"), true, Some(credential)).await;

    let (status, reply) = gw.remind("hsm-1").await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["outcome"], "delivered", "{reply}");

    // The writer notices uncovered records on one tick and writes the
    // checkpoint on a later one, once the interval has passed.
    let dp = gw.state.dataplane().unwrap();
    let start = Instant::now();
    dp.checkpointer().tick(start).await;
    let written = dp
        .checkpointer()
        .tick(start + Duration::from_secs(3600))
        .await;
    assert!(
        matches!(written.tick, Tick::Written { .. }),
        "{:?}",
        written.tick
    );

    let view = runtime(&gw.state).await;
    assert_eq!(view["hsm"]["healthy"], true, "{view}");
    assert_eq!(
        view["hsm"]["roles"],
        serde_json::json!(["mandate", "evidence", "checkpoint", "credential"]),
        "{view}"
    );
}

/// The key-separation rules hold for HSM keys too.
#[tokio::test(flavor = "multi_thread")]
async fn an_hsm_key_shared_between_roles_is_refused() {
    let Some(module) = module() else {
        eprintln!("skipped: set KAVACH_TEST_PKCS11_MODULE and SOFTHSM2_CONF");
        return;
    };
    let _serial = serial().await;
    let run = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    let (mut api, _) = hsm_config(module, &run);
    let dp = api.dataplane.as_mut().unwrap();
    dp.checkpoint_key_id = dp.evidence_key_id.clone();
    let err = AppState::from_config(&api).await.err().expect("refused");
    assert!(err.to_string().contains("separate key"), "{err}");
}
