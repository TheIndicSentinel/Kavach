//! HMAC anti-replay reservations are shared by database-backed API replicas.

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use chrono::Utc;
use kavach_api::hmac_auth::{self, HmacNonceBackend, HmacVerification};
use kavach_storage::{DatabaseTls, StoragePool};

fn signed_headers(secret: &str, timestamp: i64, nonce: &str, body: &[u8]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let message =
        hmac_auth::string_to_sign(&timestamp.to_string(), nonce, "POST", "/v1/evaluate", body);
    headers.insert(
        "x-kavach-signature",
        HeaderValue::from_str(&hmac_auth::sign(secret, &message)).expect("signature header"),
    );
    headers.insert(
        "x-kavach-timestamp",
        HeaderValue::from_str(&timestamp.to_string()).expect("timestamp header"),
    );
    headers.insert(
        "x-kavach-nonce",
        HeaderValue::from_str(nonce).expect("nonce header"),
    );
    headers
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hmac_nonce_is_shared_across_database_backed_api_instances() {
    let Some(url) = kavach_storage::testing::isolated_database_url().await else {
        return;
    };
    let pool = StoragePool::connect(&url, &DatabaseTls::development())
        .await
        .expect("connect + migrate");
    let first = HmacNonceBackend::from_pool(Some(&pool));
    let second = HmacNonceBackend::from_pool(Some(&pool));
    let secret = "hmac test secret with sufficient entropy";
    let body = br#"{"test":true}"#;
    let now = Utc::now();
    let headers = signed_headers(
        secret,
        now.timestamp(),
        "nonce-shared-across-api-instances-1",
        body,
    );

    let (a, b) = tokio::join!(
        hmac_auth::verify(
            secret,
            &first,
            HmacVerification {
                tenant_id: "tenant-a",
                headers: &headers,
                method: "POST",
                path_and_query: "/v1/evaluate",
                body,
                now,
            },
        ),
        hmac_auth::verify(
            secret,
            &second,
            HmacVerification {
                tenant_id: "tenant-a",
                headers: &headers,
                method: "POST",
                path_and_query: "/v1/evaluate",
                body,
                now,
            },
        ),
    );

    assert_eq!(
        [a.is_ok(), b.is_ok()].into_iter().filter(|ok| *ok).count(),
        1
    );
    let refused = a.err().or_else(|| b.err()).expect("one replay refused");
    assert_eq!(refused.status_code(), StatusCode::UNAUTHORIZED);
}
