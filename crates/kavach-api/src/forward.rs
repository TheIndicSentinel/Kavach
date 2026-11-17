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
use std::sync::Arc;
use std::time::Duration;

use kavach_dataplane::{
    ForwardRequest, ForwardResult, Forwarder, ProviderStatus, StatusAnswer, StatusAsker,
};
use kavach_ports::{ProviderSecretStore, TokenSecret};
use reqwest::Url;
use sha2::Digest;

const MAX_RESPONSE_BYTES: usize = 4096;
pub const AUTH_SCHEME: &str = "Kavach-Credential";
/// The scheme of a status question (ADR-017 R2).
pub const STATUS_SCHEME: &str = "Kavach-Status";

#[derive(Clone)]
pub enum ProviderTarget {
    CredentialAccepting {
        messages_url: Url,
    },
    TwilioWhatsApp {
        messages_url: Url,
        account_sid: String,
        api_key_sid: String,
        from: String,
        secret_ref: String,
        template_sids: BTreeMap<String, String>,
    },
}

impl ProviderTarget {
    #[must_use]
    pub fn credential_accepting(messages_url: Url) -> Self {
        Self::CredentialAccepting { messages_url }
    }

    #[must_use]
    pub fn twilio_whatsapp(
        messages_url: Url,
        account_sid: String,
        api_key_sid: String,
        from: String,
        secret_ref: String,
        template_sids: BTreeMap<String, String>,
    ) -> Self {
        Self::TwilioWhatsApp {
            messages_url,
            account_sid,
            api_key_sid,
            from,
            secret_ref,
            template_sids,
        }
    }
}

pub struct HttpForwarder {
    client: reqwest::Client,
    /// Provider audience → transport and provider endpoint.
    targets: BTreeMap<String, ProviderTarget>,
    secret_store: Option<Arc<dyn ProviderSecretStore>>,
}

/// Parses a provider endpoint: http(s), a host, no credentials, query or
/// fragment. Returns the messages URL and whether it is plain HTTP.
///
/// An error names the endpoint by scheme, host and port only: it reaches
/// stderr at startup, and the rest of the endpoint can carry a credential.
pub fn messages_url(endpoint: &str) -> Result<(Url, bool), String> {
    let (mut url, plain) = base_url(endpoint)?;
    let path = format!("{}/v1/messages", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok((url, plain))
}

/// Twilio's REST resource URL. The account id is validated before it is
/// inserted into the path so configuration cannot change the request origin.
pub fn twilio_messages_url(endpoint: &str, account_sid: &str) -> Result<(Url, bool), String> {
    if !valid_sid(account_sid, "AC") {
        return Err("Twilio account_sid must be an AC SID".into());
    }
    let (mut url, plain) = base_url(endpoint)?;
    url.set_path(&format!("/2010-04-01/Accounts/{account_sid}/Messages.json"));
    Ok((url, plain))
}

fn base_url(endpoint: &str) -> Result<(Url, bool), String> {
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
    Ok((base, plain))
}

fn valid_sid(value: &str, prefix: &str) -> bool {
    value.len() == 34
        && value.starts_with(prefix)
        && value.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn twilio_message_id(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let sid = value.get("sid")?.as_str()?;
    (sid.len() == 34 && sid.starts_with("SM") && sid.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then(|| sid.to_string())
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
        let targets = endpoints
            .into_iter()
            .map(|(audience, url)| {
                (
                    audience,
                    ProviderTarget::CredentialAccepting { messages_url: url },
                )
            })
            .collect();
        Ok(Self {
            client,
            targets,
            secret_store: None,
        })
    }

    pub fn with_targets(
        targets: BTreeMap<String, ProviderTarget>,
        connect_timeout: Duration,
        timeout: Duration,
        extra_roots: &[u8],
        secret_store: Arc<dyn ProviderSecretStore>,
    ) -> Result<Self, String> {
        let mut forwarder = Self::new(BTreeMap::new(), connect_timeout, timeout, extra_roots)?;
        forwarder.targets = targets;
        forwarder.secret_store = Some(secret_store);
        Ok(forwarder)
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
        let Some(ProviderTarget::CredentialAccepting { messages_url }) = self.targets.get(provider)
        else {
            // Startup refuses a registry provider without an endpoint.
            return ForwardResult::NotSent;
        };
        let response = self
            .client
            .post(messages_url.clone())
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

    async fn forward_request(&self, provider: &str, request: &ForwardRequest<'_>) -> ForwardResult {
        let Some(target) = self.targets.get(provider) else {
            return ForwardResult::NotSent;
        };
        let ProviderTarget::TwilioWhatsApp {
            messages_url,
            api_key_sid,
            from,
            secret_ref,
            template_sids,
            ..
        } = target
        else {
            return self.forward(provider, request.credential).await;
        };
        if request.channel != "whatsapp" || !from.starts_with("whatsapp:+") {
            return ForwardResult::NotSent;
        }
        let Some(content_sid) = template_sids.get(request.template_id) else {
            return ForwardResult::NotSent;
        };
        if !valid_sid(api_key_sid, "SK") || !valid_sid(content_sid, "HX") {
            return ForwardResult::NotSent;
        }
        let Some(secret_store) = &self.secret_store else {
            return ForwardResult::NotSent;
        };
        let Ok(secret) = secret_store.read(secret_ref).await else {
            return ForwardResult::NotSent;
        };
        let to = format!("whatsapp:{}", request.destination.expose());
        let response = self
            .client
            .post(messages_url.clone())
            .basic_auth(api_key_sid, Some(secret.expose()))
            .form(&[
                ("To", to.as_str()),
                ("From", from),
                ("ContentSid", content_sid),
            ])
            .send()
            .await;
        let mut response = match response {
            Ok(response) => response,
            Err(err) if err.is_connect() => return ForwardResult::NotSent,
            Err(_) => return ForwardResult::Lost,
        };
        let status = response.status().as_u16();
        let body = read_bounded(&mut response).await;
        let message_id = twilio_message_id(&body);
        // Twilio's 201 means the Message resource was accepted. ADR-015
        // treats a successful provider API acceptance as a delivered
        // provider outcome; downstream delivery receipts are separate.
        ForwardResult::Responded {
            status: if status == 201 && message_id.is_some() {
                202
            } else {
                status
            },
            message_id,
        }
    }
}

impl StatusAsker for HttpForwarder {
    async fn status(
        &self,
        provider: &str,
        jti: &str,
        question: &TokenSecret,
    ) -> Option<StatusAnswer> {
        let target = self.targets.get(provider)?;
        let ProviderTarget::CredentialAccepting { messages_url } = target else {
            // Twilio's fetch endpoint requires its provider SID. Unknown
            // responses without a SID are handled by the operator path.
            return None;
        };
        let mut url = messages_url.clone();
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

    #[test]
    fn twilio_resource_url_uses_a_validated_account_sid() {
        let (url, plain) = twilio_messages_url(
            "https://api.twilio.com",
            "AC12345678901234567890123456789012",
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://api.twilio.com/2010-04-01/Accounts/AC12345678901234567890123456789012/Messages.json"
        );
        assert!(!plain);
        assert!(twilio_messages_url("https://api.twilio.com", "ACbad").is_err());
        assert!(twilio_messages_url(
            "https://api.twilio.com",
            "AC1234567890123456789012345678901/"
        )
        .is_err());
    }

    #[test]
    fn twilio_message_sid_parser_accepts_only_message_sids() {
        let sid = "SM12345678901234567890123456789012";
        assert_eq!(
            twilio_message_id(format!(r#"{{"sid":"{sid}"}}"#).as_bytes()).as_deref(),
            Some(sid)
        );
        assert!(twilio_message_id(br#"{"sid":"AC12345678901234567890123456789012"}"#).is_none());
        assert!(twilio_message_id(br"not json").is_none());
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
