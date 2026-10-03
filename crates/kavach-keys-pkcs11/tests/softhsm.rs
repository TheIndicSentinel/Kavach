//! The PKCS#11 key provider against a real token (SoftHSM2).
//!
//! Runs when `KAVACH_TEST_PKCS11_MODULE` names the SoftHSM2 module and
//! `softhsm2-util` is on the path (CI installs both); skipped otherwise, as
//! the Postgres tests are without a database. One throw-away token per test
//! process, in a temporary directory; each test makes its own keys.

mod common;

use std::time::{Duration, Instant};

use common::{config, generate, import};
use ed25519_dalek::Signer;
use kavach_keys_pkcs11::Pkcs11KeyProvider;
use kavach_ports::agent_evidence::EvidenceSigner;
use kavach_ports::{verify_ed25519, ErrorClass, KeyProvider};

#[tokio::test(flavor = "multi_thread")]
async fn a_key_generated_in_the_hsm_meets_the_key_provider_contract() {
    let (module, _serial) = require_hsm!();
    generate(&module, "conform-1", false);
    let provider = Pkcs11KeyProvider::open(config(module, &["conform-1"], true)).unwrap();
    kavach_ports_testkit::conformance::key_provider(&provider, "conform-1").await;
    assert_eq!(provider.public_keys().unwrap().len(), 1);
    provider.health().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_that_could_have_been_read_out_are_refused_unless_development() {
    let (module, _serial) = require_hsm!();
    generate(&module, "extractable-1", true);
    import(&module, "imported-1");
    for kid in ["extractable-1", "imported-1"] {
        let err = Pkcs11KeyProvider::open(config(module.clone(), &[kid], true)).unwrap_err();
        assert_eq!(err.class, ErrorClass::Rejected, "{kid}: {err:?}");
        assert!(err.message.contains("refused"), "{kid}: {}", err.message);
    }
    let imported = Pkcs11KeyProvider::open(config(module, &["imported-1"], false))
        .expect("development accepts an imported key");
    let key = imported.public_key("imported-1").await.unwrap();
    let signature = imported.sign("imported-1", b"m").await.unwrap();
    verify_ed25519(&key, b"m", &signature).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_key_or_token_is_refused() {
    let (module, _serial) = require_hsm!();
    let err = Pkcs11KeyProvider::open(config(module.clone(), &["no-such-key"], true)).unwrap_err();
    assert_eq!(err.class, ErrorClass::Rejected, "{err:?}");
    let mut wrong = config(module, &["no-such-key"], true);
    wrong.token_label = "no-such-token".into();
    let err = Pkcs11KeyProvider::open(wrong).unwrap_err();
    assert_eq!(err.class, ErrorClass::Unavailable, "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn evidence_is_signed_in_the_hsm_from_inside_the_runtime() {
    let (module, _serial) = require_hsm!();
    generate(&module, "evidence-1", false);
    let provider = Pkcs11KeyProvider::open(config(module, &["evidence-1"], true)).unwrap();
    let signer = provider.evidence_signer("evidence-1").unwrap();
    assert_eq!(signer.key_id(), "evidence-1");
    let key = provider.public_key("evidence-1").await.unwrap();
    // Synchronous, as the evidence commit calls it, on a runtime worker.
    let signature = signer.sign(b"record hash").unwrap();
    verify_ed25519(&key, b"record hash", &signature).unwrap();
    assert!(provider.evidence_signer("missing").is_err());
}

/// Sign latency, HSM against in-process Ed25519, for the KMS decision on
/// which keys go to the HSM (evidence and credential keys sign on every
/// recorded or delivered call). Prints figures; asserts nothing about them.
/// A trend on whatever machine runs it, not a figure to quote.
/// `cargo test -p kavach-keys-pkcs11 --test softhsm -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement; run on demand"]
async fn sign_latency() {
    let (module, _serial) = require_hsm!();
    generate(&module, "latency-1", false);
    let provider = Pkcs11KeyProvider::open(config(module, &["latency-1"], true)).unwrap();
    let signer = provider.evidence_signer("latency-1").unwrap();
    let local = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let message = [0x5Au8; 200];
    let rounds = 2_000;

    let report = |name: &str, mut samples: Vec<Duration>| {
        samples.sort();
        let at = |p: usize| samples[(samples.len() * p / 1000).min(samples.len() - 1)];
        println!(
            "{name:<34} p50 {:>8.3} ms  p99 {:>8.3} ms  max {:>8.3} ms",
            at(500).as_secs_f64() * 1e3,
            at(990).as_secs_f64() * 1e3,
            samples.last().unwrap().as_secs_f64() * 1e3
        );
    };
    let time = |f: &dyn Fn()| {
        (0..rounds)
            .map(|_| {
                let start = Instant::now();
                f();
                start.elapsed()
            })
            .collect::<Vec<_>>()
    };
    report(
        "in-process ed25519 (baseline)",
        time(&|| {
            std::hint::black_box(local.sign(&message));
        }),
    );
    report(
        "hsm evidence signer (sync)",
        time(&|| drop(signer.sign(&message).unwrap())),
    );
    let mut async_samples = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let start = Instant::now();
        provider.sign("latency-1", &message).await.unwrap();
        async_samples.push(start.elapsed());
    }
    report("hsm key provider (async)", async_samples);
    // Eight concurrent signers, as under the gateway's concurrency.
    let start = Instant::now();
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let provider = provider.clone();
            tokio::spawn(async move {
                for _ in 0..250 {
                    provider.sign("latency-1", &[1u8; 200]).await.unwrap();
                }
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }
    println!(
        "hsm key provider, 8 concurrent:    {:.0} signatures/s",
        2_000.0 / start.elapsed().as_secs_f64()
    );
}
