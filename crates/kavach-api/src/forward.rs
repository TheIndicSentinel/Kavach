//! The gateway's HTTP forwarder (H5b step 8b): one request per credential,
//! hardened so the credential cannot travel anywhere but the provider.
//!
//! - **No redirects** (a redirect would carry the credential header to
//!   another host); a 3xx is reported as-is and classified `unknown`.
//! - **No proxies** from the environment (`HTTP_PROXY`, `ALL_PROXY`…), so
//!   the credential never routes through an ambient proxy.
//! - **No retries**, bounded connect and total timeouts, and at most 4 KiB
//!   of response read.

use std::collections::BTreeMap;
use std::time::Duration;

use kavach_dataplane::{ForwardResult, Forwarder};
use kavach_ports::TokenSecret;
use reqwest::Url;

const MAX_RESPONSE_BYTES: usize = 4096;
pub const AUTH_SCHEME: &str = "Kavach-Credential";

pub struct HttpForwarder {
    client: reqwest::Client,
    /// Provider audience → `…/v1/messages` URL.
    endpoints: BTreeMap<String, Url>,
}

/// Parses a provider endpoint: http(s), a host, no credentials, query or
/// fragment. Returns the messages URL and whether it is plain HTTP.
pub fn messages_url(endpoint: &str) -> Result<(Url, bool), String> {
    let base = Url::parse(endpoint).map_err(|e| format!("endpoint {endpoint:?}: {e}"))?;
    let plain = match base.scheme() {
        "https" => false,
        "http" => true,
        other => return Err(format!("endpoint scheme {other} (expected http or https)")),
    };
    if base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(format!(
            "endpoint {endpoint:?} must be a plain base URL (host, optional path)"
        ));
    }
    let mut url = base;
    let path = format!("{}/v1/messages", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok((url, plain))
}

impl HttpForwarder {
    pub fn new(
        endpoints: BTreeMap<String, Url>,
        connect_timeout: Duration,
        timeout: Duration,
    ) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(connect_timeout)
            .timeout(timeout)
            .pool_max_idle_per_host(8)
            .user_agent(concat!("kavach-gateway/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("gateway http client: {e}"))?;
        Ok(Self { client, endpoints })
    }
}

impl Forwarder for HttpForwarder {
    async fn forward(&self, provider: &str, credential: &TokenSecret) -> ForwardResult {
        let Some(url) = self.endpoints.get(provider) else {
            // Startup refuses a registry provider without an endpoint.
            return ForwardResult::NotSent;
        };
        let response = self
            .client
            .post(url.clone())
            .header(
                reqwest::header::AUTHORIZATION,
                format!("{AUTH_SCHEME} {}", credential.expose()),
            )
            .send()
            .await;
        let mut response = match response {
            Ok(response) => response,
            // Connection or TLS setup failed: nothing was sent.
            Err(err) if err.is_connect() => return ForwardResult::NotSent,
            Err(_) => return ForwardResult::Lost,
        };
        let status = response.status().as_u16();
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if body.len() + chunk.len() <= MAX_RESPONSE_BYTES => {
                    body.extend_from_slice(&chunk);
                }
                // Too long or cut off: keep the status, drop the body.
                Ok(Some(_)) | Err(_) => {
                    body.clear();
                    break;
                }
                Ok(None) => break,
            }
        }
        let message_id = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("message_id")?.as_str().map(str::to_string));
        ForwardResult::Responded { status, message_id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_must_be_plain_http_or_https_base_urls() {
        let (url, plain) = messages_url("https://provider.internal:8443/api/").unwrap();
        assert_eq!(
            url.as_str(),
            "https://provider.internal:8443/api/v1/messages"
        );
        assert!(!plain);
        assert!(messages_url("http://127.0.0.1:8095").unwrap().1);
        for bad in [
            "ftp://x",
            "https://user:pw@x",
            "https://x/?a=1",
            "https://x/#f",
            "not a url",
            "file:///etc/passwd",
        ] {
            assert!(messages_url(bad).is_err(), "{bad}");
        }
    }
}
