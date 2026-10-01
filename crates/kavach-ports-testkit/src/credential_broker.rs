//! `CredentialBroker` contract (H5b, ADR-006). Written to the port, not to
//! one token format: the adapter's test passes an `inspect` function that
//! verifies its token *for a given request* (signature, audience, binding)
//! and returns the claims, so the suite can check what the token binds.

use chrono::{DateTime, Duration, TimeZone, Utc};
use kavach_ports::{
    CredentialBroker, CredentialRequest, Destination, ErrorClass, PortError, TokenSecret,
    MAX_CREDENTIAL_TTL_SECONDS,
};

/// A synthetic destination (never a real number).
pub const DESTINATION: &str = "+910000000001";

/// What a token says, as the adapter's verifier reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimsView {
    pub tenant_id: String,
    pub agent_id: String,
    pub mandate_id: String,
    pub record_id: String,
    pub credential_id: String,
    pub audience: String,
    pub action: String,
    pub expires_at: DateTime<Utc>,
    pub send_by: Option<DateTime<Utc>>,
}

/// 11:00 IST on 1 Oct 2026.
pub fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 1, 5, 30, 0).unwrap()
}

/// A request for a reminder via WhatsApp, allowed until 19:00 IST.
pub fn request<'a>(destination: &'a Destination, credential_id: &'a str) -> CredentialRequest<'a> {
    CredentialRequest {
        tenant_id: "conformance",
        agent_id: "collections-agent",
        mandate_id: "m-1",
        record_id: "rec-1",
        credential_id,
        audience: "mock-messaging",
        action: "send_reminder",
        destination,
        channel: "whatsapp",
        template_id: "emi_reminder_v1",
        expires_at: now() + Duration::seconds(MAX_CREDENTIAL_TTL_SECONDS),
        send_by: Some(Utc.with_ymd_and_hms(2026, 10, 1, 13, 30, 0).unwrap()),
        now: now(),
    }
}

fn no_destination(err: &PortError) {
    assert!(
        !err.message.contains(DESTINATION) && !err.message.contains("0000000001"),
        "an error must never carry the destination: {}",
        err.message
    );
}

async fn refused<B: CredentialBroker>(
    broker: &B,
    request: &CredentialRequest<'_>,
    class: ErrorClass,
) {
    let err = broker
        .issue(request)
        .await
        .expect_err("no credential may be issued");
    assert_eq!(err.class, class, "{}", err.message);
    no_destination(&err);
}

/// The contract every `CredentialBroker` adapter must meet.
pub async fn conformance<B, F>(broker: &B, inspect: F)
where
    B: CredentialBroker,
    F: Fn(&TokenSecret, &CredentialRequest<'_>) -> Result<ClaimsView, PortError>,
{
    let destination = Destination::new(DESTINATION);
    assert!(
        !broker.is_test_double(),
        "a production adapter is not a test double"
    );
    assert_eq!(
        format!("{destination:?}"),
        "Destination(<redacted>)",
        "destinations never print"
    );
    let base = request(&destination, "cred-1");
    binds_decision_audience_and_request(broker, &inspect, &base).await;
    lifetime_is_capped(
        broker,
        &inspect,
        &CredentialRequest {
            credential_id: "cred-ttl",
            ..base.clone()
        },
    )
    .await;
    refuses_after_send_by_and_expiry(broker, &base).await;
    issues_once_and_honours_revocation(broker, &base).await;
    refuses_malformed_requests(broker, &base).await;
}

async fn binds_decision_audience_and_request<B, F>(
    broker: &B,
    inspect: &F,
    base: &CredentialRequest<'_>,
) where
    B: CredentialBroker,
    F: Fn(&TokenSecret, &CredentialRequest<'_>) -> Result<ClaimsView, PortError>,
{
    // 1. Claims bind the decision, the audience and the request.
    let issued = broker.issue(base).await.expect("issue");
    assert_eq!(issued.credential_id, "cred-1");
    assert!(
        !format!("{issued:?}").contains(issued.token.expose()),
        "tokens never print"
    );
    let claims = inspect(&issued.token, base).expect("verifies for its own request");
    assert_eq!(
        claims,
        ClaimsView {
            tenant_id: "conformance".into(),
            agent_id: "collections-agent".into(),
            mandate_id: "m-1".into(),
            record_id: "rec-1".into(),
            credential_id: "cred-1".into(),
            audience: "mock-messaging".into(),
            action: "send_reminder".into(),
            expires_at: issued.expires_at,
            send_by: base.send_by,
        }
    );
    let other = Destination::new("+910000000002");
    for (what, changed) in [
        (
            "destination",
            CredentialRequest {
                destination: &other,
                ..base.clone()
            },
        ),
        (
            "channel",
            CredentialRequest {
                channel: "sms",
                ..base.clone()
            },
        ),
        (
            "template",
            CredentialRequest {
                template_id: "other_v1",
                ..base.clone()
            },
        ),
        (
            "audience",
            CredentialRequest {
                audience: "other-provider",
                ..base.clone()
            },
        ),
    ] {
        let err = inspect(&issued.token, &changed)
            .expect_err(&format!("a credential must not authorise another {what}"));
        no_destination(&err);
    }
}

async fn lifetime_is_capped<B, F>(broker: &B, inspect: &F, base: &CredentialRequest<'_>)
where
    B: CredentialBroker,
    F: Fn(&TokenSecret, &CredentialRequest<'_>) -> Result<ClaimsView, PortError>,
{
    // 2. TTL: at most MAX_CREDENTIAL_TTL_SECONDS, never past the grant or send_by.
    let issued = broker.issue(base).await.expect("issue");
    let ttl = issued.expires_at - base.now;
    assert!(
        ttl > Duration::zero() && ttl <= Duration::seconds(MAX_CREDENTIAL_TTL_SECONDS),
        "ttl {ttl}"
    );
    let long = CredentialRequest {
        credential_id: "cred-long",
        expires_at: base.now + Duration::hours(1),
        ..base.clone()
    };
    let issued = broker.issue(&long).await.expect("issue");
    assert!(issued.expires_at <= base.now + Duration::seconds(MAX_CREDENTIAL_TTL_SECONDS));
    let send_by = base.now + Duration::seconds(5);
    let near = CredentialRequest {
        credential_id: "cred-near",
        send_by: Some(send_by),
        ..base.clone()
    };
    let issued = broker.issue(&near).await.expect("issue");
    assert!(issued.expires_at <= send_by, "capped at send_by");
    assert_eq!(
        inspect(&issued.token, &near).unwrap().expires_at,
        issued.expires_at
    );
}

async fn refuses_after_send_by_and_expiry<B: CredentialBroker>(
    broker: &B,
    base: &CredentialRequest<'_>,
) {
    // 3. Nothing at or after send_by, nor for an expired grant.
    for request in [
        CredentialRequest {
            credential_id: "cred-at",
            send_by: Some(base.now),
            ..base.clone()
        },
        CredentialRequest {
            credential_id: "cred-after",
            send_by: Some(base.now - Duration::seconds(1)),
            ..base.clone()
        },
        CredentialRequest {
            credential_id: "cred-expired",
            expires_at: base.now,
            ..base.clone()
        },
    ] {
        refused(broker, &request, ErrorClass::Rejected).await;
    }
}

/// `base` must already have been issued.
async fn issues_once_and_honours_revocation<B: CredentialBroker>(
    broker: &B,
    base: &CredentialRequest<'_>,
) {
    // 4. A credential id is issued at most once.
    refused(broker, base, ErrorClass::Rejected).await;
    let retry_later = CredentialRequest {
        now: base.now + Duration::seconds(30),
        expires_at: base.now + Duration::seconds(45),
        ..base.clone()
    };
    refused(broker, &retry_later, ErrorClass::Rejected).await;

    // 5. Revocation stops issuance for that mandate only.
    assert!(broker.revoke_by_mandate("conformance", "m-1").await.is_ok());
    refused(
        broker,
        &CredentialRequest {
            credential_id: "cred-revoked",
            ..base.clone()
        },
        ErrorClass::Rejected,
    )
    .await;
    let other_mandate = CredentialRequest {
        credential_id: "cred-other-mandate",
        mandate_id: "m-2",
        ..base.clone()
    };
    broker
        .issue(&other_mandate)
        .await
        .expect("another mandate is unaffected");
}

async fn refuses_malformed_requests<B: CredentialBroker>(broker: &B, base: &CredentialRequest<'_>) {
    // 6. Malformed requests are Invalid.
    let empty = Destination::new("");
    for request in [
        CredentialRequest {
            credential_id: "",
            mandate_id: "m-3",
            ..base.clone()
        },
        CredentialRequest {
            credential_id: "cred-x",
            mandate_id: "m-3",
            audience: "",
            ..base.clone()
        },
        CredentialRequest {
            credential_id: "cred-y",
            mandate_id: "m-3",
            destination: &empty,
            ..base.clone()
        },
    ] {
        refused(broker, &request, ErrorClass::Invalid).await;
    }
}

/// With its dependency (key store, vault) down, an adapter fails with
/// `Unavailable` and issues nothing.
pub async fn unavailable_conformance<B: CredentialBroker>(broker: &B) {
    let destination = Destination::new(DESTINATION);
    refused(
        broker,
        &request(&destination, "cred-down"),
        ErrorClass::Unavailable,
    )
    .await;
}
