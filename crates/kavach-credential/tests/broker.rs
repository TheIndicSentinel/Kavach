//! The JOSE credential broker against the `CredentialBroker` contract, and
//! the checks a resource provider runs.

use std::collections::BTreeMap;
use std::future::{ready, Future};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use kavach_credential::{
    open_credential, verify_credential, CredentialClaims, DecryptionKey, Expected,
    JoseCredentialBroker, TYP_CREDENTIAL, TYP_CREDENTIAL_JWE,
};
use kavach_jws::KeySet;
use kavach_keys::InMemoryKeyProvider;
use kavach_ports::{
    CredentialBroker, CredentialRequest, Destination, ErrorClass, InternalCredentialBroker,
    KeyProvider, PortError, PublicKey, TokenSecret,
};
use kavach_ports_testkit::credential_broker::{
    self, conformance, unavailable_conformance, ClaimsView, DESTINATION,
};

const KID: &str = "kavach-credential-1";
const AUDIENCE: &str = "mock-messaging";

fn provider_key() -> DecryptionKey {
    DecryptionKey::from_bytes("mock-messaging-enc-1", [11u8; 32])
}

fn recipients() -> BTreeMap<String, kavach_credential::RecipientKey> {
    let mut map = BTreeMap::from([(AUDIENCE.to_string(), provider_key().recipient())]);
    map.insert(
        "other-provider".into(),
        DecryptionKey::from_bytes("other-enc-1", [12u8; 32]).recipient(),
    );
    map
}

fn broker() -> (JoseCredentialBroker<InMemoryKeyProvider>, KeySet) {
    let mut keys = InMemoryKeyProvider::new();
    let public = keys.generate(KID).unwrap();
    (
        JoseCredentialBroker::new(keys, KID, "kavach-test", recipients()),
        KeySet::new([public]),
    )
}

fn expected<'a>(request: &'a CredentialRequest<'a>) -> Expected<'a> {
    Expected {
        audience: request.audience,
        destination: request.destination,
        channel: request.channel,
        template_id: request.template_id,
        now: request.now,
    }
}

fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, 0).unwrap()
}

#[tokio::test]
async fn jose_broker_meets_the_contract() {
    let (broker, keys) = broker();
    let key = provider_key();
    let other = DecryptionKey::from_bytes("other-enc-1", [12u8; 32]);
    conformance(
        &broker,
        |token: &TokenSecret, request: &CredentialRequest<'_>| {
            // The provider for the request's audience opens it (another
            // audience's key cannot, which the suite also exercises).
            let key = if request.audience == AUDIENCE {
                &key
            } else {
                &other
            };
            let claims = verify_credential(token.expose(), &keys, key, &expected(request))?;
            Ok(ClaimsView {
                tenant_id: claims.tenant,
                agent_id: claims.agent,
                mandate_id: claims.mandate_id,
                record_id: claims.record_id,
                credential_id: claims.jti,
                audience: claims.aud,
                action: claims.action,
                expires_at: at(claims.exp),
                send_by: claims.send_by.map(at),
            })
        },
    )
    .await;
}

#[tokio::test]
async fn internal_credential_needs_no_provider_recipient_and_returns_no_token() {
    let mut keys = InMemoryKeyProvider::new();
    keys.generate(KID).unwrap();
    let broker = JoseCredentialBroker::new(keys, KID, "kavach-test", BTreeMap::new());
    let destination = Destination::new(DESTINATION);
    let request = credential_broker::request(&destination, "cred-internal");

    let receipt = broker.issue_internal(&request).await.unwrap();
    assert_eq!(receipt.credential_id, "cred-internal");
    assert!(receipt.expires_at <= request.expires_at);
    assert!(receipt.expires_at > request.now);
    assert!(!format!("{receipt:?}").contains(DESTINATION));
    assert!(broker.issue_internal(&request).await.is_err());
}

/// A key store that is down.
struct DownKeys;

impl KeyProvider for DownKeys {
    fn sign(
        &self,
        _kid: &str,
        _message: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send {
        ready(Err(PortError::unavailable("key store unreachable")))
    }
    fn public_key(&self, _kid: &str) -> impl Future<Output = Result<PublicKey, PortError>> + Send {
        ready(Err(PortError::unavailable("key store unreachable")))
    }
}

#[tokio::test]
async fn a_down_key_store_is_unavailable_and_does_not_consume_the_id() {
    let broker = JoseCredentialBroker::new(DownKeys, KID, "kavach-test", recipients());
    unavailable_conformance(&broker).await;
    // The reservation was released: the same id fails the same way, not
    // as "already issued".
    let destination = Destination::new(DESTINATION);
    let err = broker
        .issue(&credential_broker::request(&destination, "cred-down"))
        .await
        .unwrap_err();
    assert_eq!(err.class, ErrorClass::Unavailable);
}

fn header(token: &TokenSecret) -> serde_json::Value {
    let first = token.expose().split('.').next().unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(first).unwrap()).unwrap()
}

/// Nothing outside the provider can read the credential: no destination,
/// no claims, a fresh ephemeral key per token.
#[tokio::test]
async fn the_credential_is_opaque_outside_the_provider() {
    let (broker, keys) = broker();
    let destination = Destination::new(DESTINATION);
    let a = credential_broker::request(&destination, "cred-a");
    let b = credential_broker::request(&destination, "cred-b");
    let ta = broker.issue(&a).await.unwrap().token;
    let tb = broker.issue(&b).await.unwrap().token;

    let parts: Vec<&str> = ta.expose().split('.').collect();
    assert_eq!(parts.len(), 5, "compact JWE");
    let h = header(&ta);
    assert_eq!(h["alg"], "ECDH-ES");
    assert_eq!(h["enc"], "A256GCM");
    assert_eq!(h["typ"], TYP_CREDENTIAL_JWE);
    assert_eq!(h["cty"], TYP_CREDENTIAL);
    assert_eq!(h["epk"]["crv"], "X25519");
    for part in &parts {
        let bytes = URL_SAFE_NO_PAD.decode(part).unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes);
        for secret in [
            "0000000001",
            "m-1",
            "collections-agent",
            "whatsapp",
            "rec-1",
        ] {
            assert!(!text.contains(secret), "{secret} visible in {text}");
        }
    }
    assert_ne!(
        header(&ta)["epk"]["x"],
        header(&tb)["epk"]["x"],
        "fresh ephemeral key per token"
    );

    // The provider takes the request from the credential.
    let claims: CredentialClaims =
        open_credential(ta.expose(), &keys, &provider_key(), AUDIENCE, a.now).unwrap();
    assert_eq!(claims.req.destination.expose(), DESTINATION);
    assert_eq!(claims.req.channel, "whatsapp");
    assert!(
        !format!("{claims:?}").contains("0000000001"),
        "claims never print the destination"
    );
}

#[tokio::test]
async fn providers_refuse_other_recipients_forgeries_and_late_use() {
    let (broker, keys) = broker();
    let destination = Destination::new(DESTINATION);
    let request = credential_broker::request(&destination, "cred-v");
    let issued = broker.issue(&request).await.unwrap();
    let token = issued.token.expose();
    verify_credential(token, &keys, &provider_key(), &expected(&request)).unwrap();

    // Another provider's key cannot open it.
    let other = DecryptionKey::from_bytes("other-enc-1", [12u8; 32]);
    assert!(open_credential(token, &keys, &other, AUDIENCE, request.now).is_err());

    // Encrypted for this provider but signed by an untrusted key (e.g. the
    // mandate key, or anyone who knows the provider's public key).
    let mut rogue = InMemoryKeyProvider::new();
    let _ = rogue.generate(KID).unwrap();
    let forged_broker = JoseCredentialBroker::new(rogue, KID, "kavach-test", recipients());
    let forged = forged_broker
        .issue(&credential_broker::request(&destination, "cred-forged"))
        .await
        .unwrap();
    assert!(open_credential(
        forged.token.expose(),
        &keys,
        &provider_key(),
        AUDIENCE,
        request.now
    )
    .is_err());

    // A plain JWS (not encrypted) is refused.
    let mut own = InMemoryKeyProvider::new();
    let public = own.generate(KID).unwrap();
    let plain = kavach_jws::sign(&own, KID, TYP_CREDENTIAL, &serde_json::json!({}))
        .await
        .unwrap();
    assert!(open_credential(
        &plain,
        &KeySet::new([public]),
        &provider_key(),
        AUDIENCE,
        request.now
    )
    .is_err());

    // Expired, and presented at send_by.
    assert!(
        open_credential(token, &keys, &provider_key(), AUDIENCE, issued.expires_at)
            .unwrap_err()
            .message
            .contains("expired")
    );
    let send_by = request.now + Duration::seconds(3);
    let near = CredentialRequest {
        credential_id: "cred-near-v",
        send_by: Some(send_by),
        ..request.clone()
    };
    let near_token = broker.issue(&near).await.unwrap().token;
    assert!(open_credential(
        near_token.expose(),
        &keys,
        &provider_key(),
        AUDIENCE,
        send_by
    )
    .is_err());

    // No encryption key for an audience: nothing is issued.
    let unknown = CredentialRequest {
        credential_id: "cred-unknown-aud",
        audience: "unregistered-provider",
        ..request.clone()
    };
    assert_eq!(
        broker.issue(&unknown).await.unwrap_err().class,
        ErrorClass::Invalid
    );
}

/// A status question (ADR-017 R2) is a JWS of its own type: it names the
/// send, the tenant and the provider, lives at most a minute, holds no
/// destination, and is not a credential.
#[tokio::test]
async fn a_status_question_is_signed_bounded_and_holds_no_destination() {
    let (broker, trusted) = broker();
    let now = at(1_800_000_000);
    let token = broker
        .status_request("tenant-1", AUDIENCE, "cred-1", now)
        .await
        .unwrap();

    let claims =
        kavach_credential::verify_status_request(token.expose(), &trusted, AUDIENCE, now, 2)
            .unwrap();
    assert_eq!(
        (
            claims.tenant.as_str(),
            claims.jti.as_str(),
            claims.aud.as_str()
        ),
        ("tenant-1", "cred-1", AUDIENCE)
    );
    assert_eq!(
        claims.exp - claims.iat,
        kavach_credential::MAX_STATUS_TTL_SECONDS
    );

    // Nothing about the recipient is in it, even encoded.
    let payload = token.expose().split('.').nth(1).unwrap();
    let text = String::from_utf8(URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    for word in ["destination", "channel", "template", "+91"] {
        assert!(!text.contains(word), "{word} in {text}");
    }

    let refused = |token: &str, audience: &str, at_time: DateTime<Utc>| {
        kavach_credential::verify_status_request(token, &trusted, audience, at_time, 2).is_err()
    };
    assert!(refused(token.expose(), "other-provider", now), "audience");
    assert!(
        refused(token.expose(), AUDIENCE, now + Duration::seconds(63)),
        "expired"
    );
    assert!(
        refused(token.expose(), AUDIENCE, now - Duration::seconds(60)),
        "future"
    );
    // Another signer is not trusted.
    let (_, other_trusted) = {
        let mut keys = InMemoryKeyProvider::new();
        let public = keys.generate(KID).unwrap();
        (keys, KeySet::new([public]))
    };
    assert!(kavach_credential::verify_status_request(
        token.expose(),
        &other_trusted,
        AUDIENCE,
        now,
        2
    )
    .is_err());
    // A provider the broker has no key for is never asked.
    assert!(broker
        .status_request("tenant-1", "unregistered", "cred-1", now)
        .await
        .is_err());
}

/// A send credential is not a status question, and the reverse.
#[tokio::test]
async fn a_status_question_and_a_credential_are_not_interchangeable() {
    let (broker, trusted) = broker();
    let destination = Destination::new(DESTINATION);
    let request = credential_broker::request(&destination, "cred-1");
    let credential = broker.issue(&request).await.unwrap().token;
    assert!(kavach_credential::verify_status_request(
        credential.expose(),
        &trusted,
        AUDIENCE,
        request.now,
        2
    )
    .is_err());

    let question = broker
        .status_request("tenant-1", AUDIENCE, "cred-1", request.now)
        .await
        .unwrap();
    assert!(open_credential(
        question.expose(),
        &trusted,
        &provider_key(),
        AUDIENCE,
        request.now
    )
    .is_err());
}
