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

use kavach_dataplane::{ForwardResult, Forwarder, ProviderStatus, StatusAnswer, StatusAsker};
use kavach_ports::TokenSecret;
use reqwest::Url;
use sha2::Digest;

const MAX_RESPONSE_BYTES: usize = 4096;
pub const AUTH_SCHEME: &str = "Kavach-Credential";
/// The scheme of a status question (ADR-017 R2).
pub const STATUS_SCHEME: &str = "Kavach-Status";

pub struct HttpForwarder {
    client: reqwest::Client,
    /// Provider audience → `…/v1/messages` URL.
    endpoints: BTreeMap<String, Url>,
}

/// Parses a provider endpoint: http(s), a host, no credentials, query or
/// fragment. Returns the messages URL and whether it is plain HTTP.
///
/// An error names the endpoint by scheme, host and port only: it reaches
/// stderr at startup, and the rest of the endpoint can carry a credential.
pub fn messages_url(endpoint: &str) -> Result<(Url, bool), String> {
    // `url::ParseError` displays a fixed phrase, never the input.
    let base = Url::parse(endpoint).map_err(|e| format!("endpoint does not parse: {e}"))?;
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
            "endpoint {} must be a plain base URL (host, optional path; no userinfo, query or \
             fragment)",
            crate::hardening::shown_endpoint(endpoint)
        ));
    }
    let mut url = base;
    let path = format!("{}/v1/messages", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok((url, plain))
}

impl HttpForwarder {
    /// `extra_roots`: CA certificates (PEM) trusted for providers in
    /// addition to the system roots (`--provider-ca`).
    pub fn new(
        endpoints: BTreeMap<String, Url>,
        connect_timeout: Duration,
        timeout: Duration,
        extra_roots: &[u8],
    ) -> Result<Self, String> {
        let mut builder = reqwest::Client::builder();
        if !extra_roots.is_empty() {
            let roots = reqwest::Certificate::from_pem_bundle(extra_roots)
                .map_err(|e| format!("provider CA: {e}"))?;
            if roots.is_empty() {
                return Err("provider CA: no certificates in the file".into());
            }
            for root in roots {
                builder = builder.add_root_certificate(root);
            }
        }
        let client = builder
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

/// At most [`MAX_RESPONSE_BYTES`] of the body; empty if it is longer or cut off.
async fn read_bounded(response: &mut reqwest::Response) -> Vec<u8> {
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
    body
}

/// The status contract's reply: exactly `{"status": <one of three words>}`.
/// Anything else (more members, another word, not JSON) is outside the
/// contract and is no answer.
fn parse_status(body: &[u8]) -> Option<ProviderStatus> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let object = value.as_object().filter(|o| o.len() == 1)?;
    match object.get("status")?.as_str()? {
        "delivered" => Some(ProviderStatus::Delivered),
        "not_delivered" => Some(ProviderStatus::NotDelivered),
        "unknown" => Some(ProviderStatus::Unknown),
        _ => None,
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
        let body = read_bounded(&mut response).await;
        let message_id = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("message_id")?.as_str().map(str::to_string));
        ForwardResult::Responded { status, message_id }
    }
}

impl StatusAsker for HttpForwarder {
    async fn status(
        &self,
        provider: &str,
        jti: &str,
        question: &TokenSecret,
    ) -> Option<StatusAnswer> {
        let mut url = self.endpoints.get(provider)?.clone();
        // The jti is one path segment, whatever it contains.
        url.path_segments_mut().ok()?.push(jti);
        let mut response = self
            .client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("{STATUS_SCHEME} {}", question.expose()),
            )
            .send()
            .await
            .ok()?;
        if response.status().as_u16() != 200 {
            return None;
        }
        let body = read_bounded(&mut response).await;
        let status = parse_status(&body)?;
        Some(StatusAnswer {
            status,
            digest: hex::encode(sha2::Sha256::digest(&body)),
        })
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

    /// A refused endpoint is named by scheme, host and port only. The
    /// secrets have no digits, so no log redactor could hide a leak.
    #[test]
    fn a_refused_endpoint_is_named_without_userinfo_path_query_or_fragment() {
        let secrets = [
            "opsuser",
            "topsecretpw",
            "letmeinplease",
            "hiddenpath",
            "hiddenanchor",
        ];
        for (endpoint, shown) in [
            (
                "https://opsuser:topsecretpw@provider.internal:8443/hiddenpath",
                "endpoint https://provider.internal:8443 must be a plain base URL",
            ),
            (
                "https://provider.internal/hiddenpath?token=letmeinplease",
                "endpoint https://provider.internal must be a plain base URL",
            ),
            (
                "http://provider.internal/#hiddenanchor",
                "endpoint http://provider.internal must be a plain base URL",
            ),
            // Unparseable (the port is not a number): nothing of it is shown.
            (
                "https://opsuser:topsecretpw@provider.internal:hiddenpath/?token=letmeinplease",
                "endpoint does not parse: invalid port number",
            ),
        ] {
            let err = messages_url(endpoint).unwrap_err();
            assert!(err.starts_with(shown), "{err}");
            for text in [err.clone(), format!("{err:?}")] {
                for secret in secrets {
                    assert!(!text.contains(secret), "{secret} in {text}");
                }
            }
        }
    }

    #[test]
    fn an_endpoint_is_shown_as_its_origin_or_unparseable() {
        use crate::hardening::shown_endpoint;
        assert_eq!(
            shown_endpoint("https://opsuser:topsecretpw@host.example:8443/p?token=letmeinplease#f"),
            "https://host.example:8443"
        );
        assert_eq!(
            shown_endpoint("http://host.example/"),
            "http://host.example"
        );
        assert_eq!(
            shown_endpoint("https://opsuser:topsecretpw@host:bad/"),
            "(unparseable)"
        );
        assert_eq!(shown_endpoint("not a url"), "(unparseable)");
    }
}
