//! The PKCS#11 key provider recovers after its module restarts. In its own
//! test binary (its own process): shutting the module down would break the
//! other SoftHSM tests running in parallel.

mod common;

use common::{admin, config, generate};
use kavach_keys_pkcs11::Pkcs11KeyProvider;
use kavach_ports::{verify_ed25519, KeyProvider};

#[tokio::test(flavor = "multi_thread")]
async fn the_provider_recovers_after_the_module_restarts() {
    let module = require_hsm!();
    generate(&module, "reconnect-1", false);
    let provider = Pkcs11KeyProvider::open(config(module.clone(), &["reconnect-1"], true)).unwrap();
    provider.sign("reconnect-1", b"before").await.unwrap();
    // Shut the module down under the provider, as an HSM restart would:
    // every session and login of this process is gone.
    let (ctx, session) = admin(&module);
    drop(session);
    ctx.finalize().unwrap();
    let key = provider.public_key("reconnect-1").await.unwrap();
    let signature = provider
        .sign("reconnect-1", b"after")
        .await
        .expect("reconnects");
    verify_ed25519(&key, b"after", &signature).unwrap();
    provider.health().unwrap();
}
