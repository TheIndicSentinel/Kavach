//! The mock provider over real HTTP (loopback): it accepts only Kavach
//! credentials, delivers once, replays stored results, and its status codes
//! follow the contract the gateway relies on.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use kavach_credential::{DecryptionKey, JoseCredentialBroker};
use kavach_jws::KeySet;
use kavach_keys::InMemoryKeyProvider;
use kavach_mock_provider::{
    inspect_router, router, MockProvider, ProviderConfig, ERROR_NUMBER, HANG_NUMBER, REFUSE_NUMBER,
};
use kavach_ports::{CredentialBroker, Destination};
use kavach_ports_testkit::credential_broker;
use serde_json::Value;

const SIGNER: &str = "kavach-credential-1";
const AUDIENCE: &str = "mock-messaging";
const NUMBER: &str = "+910000000001";

fn provider_key() -> DecryptionKey {
    DecryptionKey::from_bytes("mock-messaging-enc-1", [31u8; 32])
}

/// A fresh broker (fresh `jti` memory) with the trusted signing key, or an
/// untrusted one.
fn broker(seed: u8) -> JoseCredentialBroker<InMemoryKeyProvider> {
    let mut keys = InMemoryKeyProvider::new();
    keys.insert_seed(SIGNER, [seed; 32]).unwrap();
    JoseCredentialBroker::new(
        keys,
        SIGNER,
        "kavach",
        BTreeMap::from([
            (AUDIENCE.to_string(), provider_key().recipient()),
            // Encrypted to this provider, but for another audience.
            ("mock-voice".to_string(), provider_key().recipient()),
            (
                "other-provider".to_string(),
                DecryptionKey::from_bytes("other-enc-1", [32u8; 32]).recipient(),
            ),
        ]),
    )
}

struct Mint<'a> {
    jti: &'a str,
    destination: &'a str,
    template: &'a str,
    audience: &'a str,
    now: DateTime<Utc>,
    send_by: Option<DateTime<Utc>>,
    seed: u8,
}

impl Default for Mint<'_> {
    fn default() -> Self {
        Self {
            jti: "cred-1",
            destination: NUMBER,
            template: "emi_reminder_v1",
            audience: AUDIENCE,
            now: credential_broker::now(),
            send_by: Some(credential_broker::now() + Duration::hours(8)),
            seed: 30,
        }
    }
}

async fn mint(m: Mint<'_>) -> String {
    let destination = Destination::new(m.destination);
    let mut request = credential_broker::request(&destination, m.jti);
    request.template_id = m.template;
    request.audience = m.audience;
    request.now = m.now;
    request.expires_at = m.now + Duration::seconds(15);
    request.send_by = m.send_by;
    broker(m.seed)
        .issue(&request)
        .await
        .unwrap()
        .token
        .expose()
        .to_string()
}

struct World {
    api: String,
    inspect: String,
    clock: Arc<Mutex<DateTime<Utc>>>,
    client: reqwest::Client,
    bodies: Mutex<Vec<String>>,
}

impl World {
    async fn new(configure: impl FnOnce(&mut ProviderConfig)) -> Self {
        let trusted = {
            let mut keys = InMemoryKeyProvider::new();
            let public = keys.insert_seed(SIGNER, [30u8; 32]).unwrap();
            KeySet::new([public])
        };
        let mut config = ProviderConfig::new(AUDIENCE, provider_key(), trusted);
        configure(&mut config);
        let clock = Arc::new(Mutex::new(credential_broker::now()));
        let read = Arc::clone(&clock);
        let provider = MockProvider::new(config, Arc::new(move || *read.lock().unwrap()));
        let serve = |app: axum::Router| async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            format!("http://{addr}")
        };
        Self {
            api: serve(router(provider.clone())).await,
            inspect: serve(inspect_router(provider)).await,
            clock,
            client: reqwest::Client::new(),
            bodies: Mutex::new(Vec::new()),
        }
    }

    fn advance(&self, by: Duration) {
        *self.clock.lock().unwrap() += by;
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> (u16, Value) {
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        self.bodies.lock().unwrap().push(text.clone());
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn post(&self, token: &str) -> (u16, Value) {
        self.send(
            self.client
                .post(format!("{}/v1/messages", self.api))
                .header("authorization", format!("Kavach-Credential {token}")),
        )
        .await
    }

    async fn inbox(&self) -> Vec<Value> {
        self.client
            .get(format!("{}/v1/inbox", self.inspect))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    /// No provider response ever carries a destination.
    fn assert_no_destination(&self) {
        for body in self.bodies.lock().unwrap().iter() {
            assert!(!body.contains("+91"), "destination in a response: {body}");
        }
    }
}

#[tokio::test]
async fn delivers_once_and_returns_the_stored_result_for_exact_repeats() {
    let w = World::new(|_| {}).await;
    let token = mint(Mint::default()).await;
    let (status, first) = w.post(&token).await;
    assert_eq!(
        (status, first["status"].as_str()),
        (202, Some("accepted")),
        "{first}"
    );
    let message_id = first["message_id"].clone();

    let inbox = w.inbox().await;
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0]["destination"], NUMBER, "taken from the credential");
    assert_eq!(inbox[0]["jti"], "cred-1");
    assert_eq!(inbox[0]["template_id"], "emi_reminder_v1");

    // The same token, and a re-encryption of the same claims (different
    // bytes, same digest): the stored result, no second delivery.
    let again = mint(Mint::default()).await;
    assert_ne!(again, token, "every encryption differs");
    for t in [&token, &again] {
        let (status, body) = w.post(t).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["replayed"], true);
        assert_eq!(body["message_id"], message_id);
    }

    // Still recoverable after the credential expired.
    w.advance(Duration::minutes(2));
    let (status, body) = w.post(&token).await;
    assert_eq!((status, body["replayed"].as_bool()), (200, Some(true)));

    // The same jti for other claims: an anomaly, refused (gateway: unknown).
    let conflicting = mint(Mint {
        template: "other_v1",
        ..Mint::default()
    })
    .await;
    let (status, body) = w.post(&conflicting).await;
    assert_eq!(
        (status, body["reason"].as_str()),
        (409, Some("jti_conflict"))
    );
    assert_eq!(w.inbox().await.len(), 1, "delivered exactly once");
    w.assert_no_destination();
}

#[tokio::test]
async fn refuses_credentials_that_do_not_authorise_this_request_now() {
    let w = World::new(|_| {}).await;
    let now = credential_broker::now();

    // Expired on first use.
    let expired = mint(Mint {
        jti: "c-expired",
        ..Mint::default()
    })
    .await;
    w.advance(Duration::seconds(20));
    let (status, body) = w.post(&expired).await;
    assert_eq!(
        (status, body["reason"].as_str()),
        (403, Some("credential_not_current"))
    );
    w.advance(Duration::seconds(-20));

    // One second before send_by, with a 2 s leeway: refused (the leeway
    // never extends the deadline).
    let deadline = mint(Mint {
        jti: "c-deadline",
        send_by: Some(now + Duration::seconds(10)),
        ..Mint::default()
    })
    .await;
    w.advance(Duration::seconds(9));
    let (status, body) = w.post(&deadline).await;
    assert_eq!(
        (status, body["reason"].as_str()),
        (403, Some("past_send_by"))
    );
    w.advance(Duration::seconds(-9));

    // Another audience, another provider's key, an untrusted signer.
    for (what, m) in [
        (
            "audience",
            Mint {
                jti: "c-aud",
                audience: "mock-voice",
                ..Mint::default()
            },
        ),
        (
            "recipient",
            Mint {
                jti: "c-rcpt",
                audience: "other-provider",
                ..Mint::default()
            },
        ),
        (
            "signer",
            Mint {
                jti: "c-sig",
                seed: 99,
                ..Mint::default()
            },
        ),
    ] {
        let (status, body) = w.post(&mint(m).await).await;
        assert_eq!(
            (status, body["reason"].as_str()),
            (401, Some("invalid_credential")),
            "{what}"
        );
    }
    // Not a JWE at all.
    let (status, body) = w.post("a.b.c").await;
    assert_eq!(
        (status, body["reason"].as_str()),
        (400, Some("malformed_credential"))
    );
    assert_eq!(w.inbox().await.len(), 0);
    w.assert_no_destination();
}

#[tokio::test]
async fn the_request_is_the_credential_and_nothing_else() {
    let w = World::new(|_| {}).await;
    let url = format!("{}/v1/messages", w.api);
    let token = mint(Mint::default()).await;
    let auth = format!("Kavach-Credential {token}");

    // A body (with or without a content type) could add or redirect content.
    let (status, body) = w
        .send(
            w.client
                .post(&url)
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(r#"{"destination":"+919876543210"}"#),
        )
        .await;
    assert_eq!(
        (status, body["reason"].as_str()),
        (400, Some("body_not_allowed"))
    );
    // Unknown Kavach-* headers, missing, wrong-scheme or duplicated credentials.
    let (status, body) = w
        .send(
            w.client
                .post(&url)
                .header("authorization", &auth)
                .header("kavach-destination", "+919876543210"),
        )
        .await;
    assert_eq!(
        (status, body["reason"].as_str()),
        (400, Some("unknown_kavach_header"))
    );
    for request in [
        w.client.post(&url),
        w.client
            .post(&url)
            .header("authorization", format!("Bearer {token}")),
        w.client
            .post(&url)
            .header("authorization", &auth)
            .header("authorization", &auth),
    ] {
        let (status, _) = w.send(request).await;
        assert_eq!(status, 401);
    }
    assert!(w.inbox().await.is_empty(), "nothing delivered so far");

    // Standard headers are fine.
    let (status, _) = w
        .send(
            w.client
                .post(&url)
                .header("authorization", &auth)
                .header("user-agent", "kavach-gateway/test")
                .header(
                    "traceparent",
                    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
                ),
        )
        .await;
    assert_eq!(status, 202);
    w.assert_no_destination();
}

#[tokio::test]
async fn reserved_numbers_refuse_fail_or_lose_the_response() {
    let w = World::new(|c| c.hang = StdDuration::from_secs(3)).await;

    let refuse = mint(Mint {
        jti: "c-refuse",
        destination: REFUSE_NUMBER,
        ..Mint::default()
    })
    .await;
    let (status, body) = w.post(&refuse).await;
    assert_eq!(
        (status, body["reason"].as_str()),
        (422, Some("recipient_refused"))
    );
    let (status, body) = w.post(&refuse).await;
    assert_eq!(
        (status, body["replayed"].as_bool()),
        (422, Some(true)),
        "stored refusal"
    );

    let error = mint(Mint {
        jti: "c-error",
        destination: ERROR_NUMBER,
        ..Mint::default()
    })
    .await;
    let (status, _) = w.post(&error).await;
    assert_eq!(status, 500);
    assert!(w.inbox().await.is_empty(), "neither delivered");

    // Delivered, but the response does not arrive within the client's timeout.
    let hang = mint(Mint {
        jti: "c-hang",
        destination: HANG_NUMBER,
        ..Mint::default()
    })
    .await;
    let result = w
        .client
        .post(format!("{}/v1/messages", w.api))
        .header("authorization", format!("Kavach-Credential {hang}"))
        .timeout(StdDuration::from_millis(300))
        .send()
        .await;
    assert!(result.unwrap_err().is_timeout());
    let inbox = w.inbox().await;
    assert_eq!(inbox.len(), 1, "accepted although the response was lost");
    assert_eq!(inbox[0]["jti"], "c-hang");
    w.assert_no_destination();
}

#[tokio::test]
async fn a_full_idempotency_store_fails_closed() {
    let w = World::new(|c| {
        c.capacity = 1;
        c.grace_seconds = 60;
    })
    .await;
    let (status, _) = w
        .post(
            &mint(Mint {
                jti: "c-a",
                ..Mint::default()
            })
            .await,
        )
        .await;
    assert_eq!(status, 202);
    let (status, body) = w
        .post(
            &mint(Mint {
                jti: "c-b",
                ..Mint::default()
            })
            .await,
        )
        .await;
    assert_eq!(
        (status, body["reason"].as_str()),
        (503, Some("idempotency_store_full"))
    );

    // Once the first entry is past exp + grace it may be evicted.
    w.advance(Duration::seconds(15 + 60 + 1));
    let later = credential_broker::now() + Duration::seconds(15 + 60 + 1);
    let (status, _) = w
        .post(
            &mint(Mint {
                jti: "c-c",
                now: later,
                ..Mint::default()
            })
            .await,
        )
        .await;
    assert_eq!(status, 202);
}
