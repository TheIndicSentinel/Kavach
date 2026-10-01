//! The JWS credential broker against the `CredentialBroker` contract, and
//! the verifier a resource provider runs.

use std::future::{ready, Future};

use base64::Engine;

use chrono::{DateTime, Duration, Utc};
use kavach_credential::{
    verify_credential, CredentialClaims, Expected, JwsCredentialBroker, TYP_CREDENTIAL,
};
use kavach_jws::KeySet;
use kavach_keys::InMemoryKeyProvider;
use kavach_ports::{
    CredentialBroker, CredentialRequest, Destination, ErrorClass, KeyProvider, PortError,
    PublicKey, TokenSecret,
};
use kavach_ports_testkit::credential_broker::{
    self, conformance, unavailable_conformance, ClaimsView, DESTINATION,
};

const KID: &str = "kavach-credential-1";

fn broker() -> (JwsCredentialBroker<InMemoryKeyProvider>, KeySet) {
    let mut keys = InMemoryKeyProvider::new();
    let public = keys.generate(KID).unwrap();
    (
        JwsCredentialBroker::new(keys, KID, "kavach-test"),
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
async fn jws_broker_meets_the_contract() {
    let (broker, keys) = broker();
    conformance(
        &broker,
        |token: &TokenSecret, request: &CredentialRequest<'_>| {
            let claims = verify_credential(token.expose(), &keys, &expected(request))?;
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
    let broker = JwsCredentialBroker::new(DownKeys, KID, "kavach-test");
    unavailable_conformance(&broker).await;
    // The reservation was released: the failure did not burn the id (the
    // gateway still never retries; this keeps the broker's state honest).
    let destination = Destination::new(DESTINATION);
    let err = broker
        .issue(&credential_broker::request(&destination, "cred-down"))
        .await
        .unwrap_err();
    assert_eq!(err.class, ErrorClass::Unavailable);
}

#[tokio::test]
async fn providers_refuse_forged_expired_and_foreign_tokens() {
    let (broker, keys) = broker();
    let destination = Destination::new(DESTINATION);
    let request = credential_broker::request(&destination, "cred-v");
    let issued = broker.issue(&request).await.unwrap();
    let token = issued.token.expose();
    verify_credential(token, &keys, &expected(&request)).unwrap();

    // Tampered signature.
    let mut parts: Vec<String> = token.split('.').map(String::from).collect();
    let flipped = if parts[2].starts_with("AA") {
        "BB"
    } else {
        "AA"
    };
    parts[2].replace_range(0..2, flipped);
    assert!(verify_credential(&parts.join("."), &keys, &expected(&request)).is_err());

    // Signed by another key (e.g. the mandate or evidence key): unknown kid.
    let mut other = InMemoryKeyProvider::new();
    let _ = other.generate("kavach-mandate-1").unwrap();
    let foreign = kavach_jws::sign(&other, "kavach-mandate-1", TYP_CREDENTIAL, &{
        let (_, claims): (String, CredentialClaims) =
            kavach_jws::verify(token, TYP_CREDENTIAL, &keys).unwrap();
        claims
    })
    .await
    .unwrap();
    let err = verify_credential(&foreign, &keys, &expected(&request)).unwrap_err();
    assert_eq!(err.class, ErrorClass::Rejected, "{}", err.message);

    // Another token type with this key (a mandate-shaped JWS): wrong typ.
    let mut own = InMemoryKeyProvider::new();
    let public = own.generate(KID).unwrap();
    let wrong_typ = kavach_jws::sign(&own, KID, "kavach-mandate+jws", &serde_json::json!({}))
        .await
        .unwrap();
    assert!(verify_credential(&wrong_typ, &KeySet::new([public]), &expected(&request)).is_err());

    // Expired, and presented at send_by.
    let late = Expected {
        now: issued.expires_at,
        ..expected(&request)
    };
    assert!(verify_credential(token, &keys, &late)
        .unwrap_err()
        .message
        .contains("expired"));
    let send_by = request.now + Duration::seconds(3);
    let near = CredentialRequest {
        credential_id: "cred-near-v",
        send_by: Some(send_by),
        ..request.clone()
    };
    let near_token = broker.issue(&near).await.unwrap().token;
    let at_send_by = Expected {
        now: send_by,
        ..expected(&near)
    };
    assert!(verify_credential(near_token.expose(), &keys, &at_send_by).is_err());
}

#[tokio::test]
async fn two_credentials_for_one_request_carry_different_salts() {
    let (broker, keys) = broker();
    let destination = Destination::new(DESTINATION);
    let a = credential_broker::request(&destination, "cred-a");
    let b = credential_broker::request(&destination, "cred-b");
    let ta = broker.issue(&a).await.unwrap().token;
    let tb = broker.issue(&b).await.unwrap().token;
    let ca = verify_credential(ta.expose(), &keys, &expected(&a)).unwrap();
    let cb = verify_credential(tb.expose(), &keys, &expected(&b)).unwrap();
    assert_ne!(ca.bind.salt, cb.bind.salt);
    assert_ne!(ca.bind.digest, cb.bind.digest);
    // The token carries no destination in clear text (it is digested; see
    // the crate docs for why that is binding, not secrecy).
    let payload = ta.expose().split('.').nth(1).unwrap();
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    assert!(!String::from_utf8(json).unwrap().contains("0000000001"));
}
