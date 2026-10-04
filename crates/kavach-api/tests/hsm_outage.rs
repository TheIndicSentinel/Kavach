//! The HSM goes away in the middle of a run, then comes back.
//!
//! While it is gone, calls that need a signature are BLOCKed with
//! `dependency_unavailable` and nothing reaches the provider, and
//! `/v1/runtime` reports the HSM unhealthy. When it is back, service
//! resumes without a restart.
//!
//! The outage is made by pointing the token's configuration at an empty
//! directory and shutting the module down, so the module comes back up
//! without the token. That rewrites the configuration file `SOFTHSM2_CONF`
//! names, so this test runs only against a token of its own: set
//! `KAVACH_TEST_HSM_OUTAGE=1` (CI runs it in a separate step with a
//! separate token); it is skipped otherwise.

mod agent_fixture;
mod hsm_common;

use std::path::PathBuf;

use agent_fixture::gateway_with;
use axum::http::StatusCode;
use hsm_common::{context, hsm_config, module, runtime, serial};

/// The token directory line of the SoftHSM configuration.
fn set_token_dir(conf: &PathBuf, dir: &std::path::Path) {
    std::fs::write(
        conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\n",
            dir.display()
        ),
    )
    .unwrap();
}

fn token_dir(conf: &PathBuf) -> PathBuf {
    let text = std::fs::read_to_string(conf).unwrap();
    let line = text
        .lines()
        .find_map(|l| l.strip_prefix("directories.tokendir"))
        .expect("tokendir line");
    PathBuf::from(line.trim_start_matches([' ', '=']).trim())
}

#[tokio::test(flavor = "multi_thread")]
async fn calls_block_while_the_hsm_is_gone_and_service_resumes_after() {
    if std::env::var_os("KAVACH_TEST_HSM_OUTAGE").is_none() {
        eprintln!("skipped: set KAVACH_TEST_HSM_OUTAGE=1 with a token of its own");
        return;
    }
    let Some(module) = module() else {
        eprintln!("skipped: set KAVACH_TEST_PKCS11_MODULE and SOFTHSM2_CONF");
        return;
    };
    let _serial = serial().await;
    let conf = PathBuf::from(std::env::var_os("SOFTHSM2_CONF").unwrap());
    let tokens = token_dir(&conf);
    let run = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    let (api, credential) = hsm_config(module.clone(), &run);
    let gw = gateway_with(api, Some("+910000000001"), true, Some(credential)).await;

    let (status, reply) = gw.remind("before").await;
    assert_eq!(
        (status, reply["outcome"].clone()),
        (StatusCode::OK, "delivered".into()),
        "{reply}"
    );
    assert_eq!(gw.provider.inbox().len(), 1);

    // The HSM goes away: the module restarts without the token.
    let empty = std::env::temp_dir().join(format!("kavach-hsm-gone-{run}"));
    std::fs::create_dir_all(&empty).unwrap();
    set_token_dir(&conf, &empty);
    context(&module).finalize().unwrap();

    let (status, reply) = gw.remind("during").await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["decision"], "BLOCK", "{reply}");
    assert!(
        reply["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "dependency_unavailable"),
        "{reply}"
    );
    assert_eq!(
        gw.provider.inbox().len(),
        1,
        "nothing forwarded while the HSM is gone"
    );
    let view = runtime(&gw.state).await;
    assert_eq!(view["hsm"]["healthy"], false, "{view}");

    // The HSM comes back. No restart: the next calls reconnect.
    set_token_dir(&conf, &tokens);
    let view = runtime(&gw.state).await;
    assert_eq!(view["hsm"]["healthy"], true, "{view}");
    let (status, reply) = gw.remind("after").await;
    assert_eq!(
        (status, reply["outcome"].clone()),
        (StatusCode::OK, "delivered".into()),
        "{reply}"
    );
    assert_eq!(gw.provider.inbox().len(), 2);
}
