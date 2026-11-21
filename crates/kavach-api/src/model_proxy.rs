//! Narrow, authenticated Ollama inference proxy (ADR-007).
//!
//! The agent supplies chat messages, never an upstream URL or model name.
//! Prompts and completions are not logged. Business actions still go through
//! the mandate-authorized tool gateway.

use std::time::Duration;
use std::{net::IpAddr, str::FromStr};

use reqwest::Url;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelRole {
    Collections,
    Translation,
}

/// Strict request envelope for the future mandate-governed model route.
/// `prompt` is transient input: callers must use [`Self::prompt_digest`] for
/// authorization and evidence, and must not serialize or log this value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedModelRequest {
    pub mandate_id: String,
    pub request_id: String,
    pub subject_ref: String,
    pub prompt: String,
}

impl GovernedModelRequest {
    /// Validate fields whose grammar is already defined by the agent tool
    /// envelope, then return a digest of the exact UTF-8 prompt bytes.
    pub fn prompt_digest(&self) -> Result<String, &'static str> {
        if self.mandate_id.is_empty() || self.mandate_id.len() > 128 {
            return Err("mandate_id must be 1-128 bytes");
        }
        kavach_dataplane::authorize::validate_request_id(&self.request_id)
            .map_err(|_| "request_id is invalid")?;
        if !kavach_domain::mandate::is_capability_ref(&self.subject_ref) {
            return Err("subject_ref must be a capability reference");
        }
        if self.prompt.is_empty() {
            return Err("prompt must not be empty");
        }
        Ok(format!("{:x}", Sha256::digest(self.prompt.as_bytes())))
    }

    /// Build the existing fixed-role upstream request without exposing a
    /// caller-controlled model name or URL.
    pub fn chat_request(&self) -> ChatRequest {
        ChatRequest {
            messages: vec![json!({ "role": "user", "content": self.prompt })],
            tools: None,
            format: None,
        }
    }

    /// Adapt the transient model request to the registered tool envelope used
    /// by the mandate/Cedar authorization core. The prompt itself is omitted;
    /// only its digest is bound into the tool parameters MAC and evidence.
    pub fn tool_request(
        &self,
        role: ModelRole,
    ) -> Result<(String, kavach_dataplane::tools::ToolRequest), &'static str> {
        let prompt_digest = self.prompt_digest()?;
        let params = serde_json::Map::from_iter([
            (
                "subject_ref".to_string(),
                Value::String(self.subject_ref.clone()),
            ),
            ("prompt_digest".to_string(), Value::String(prompt_digest)),
        ]);
        Ok((
            format!("invoke_{}_model", role.as_str()),
            kavach_dataplane::tools::ToolRequest {
                mandate_id: self.mandate_id.clone(),
                request_id: self.request_id.clone(),
                approval_id: None,
                execution_id: None,
                params,
            },
        ))
    }
}

impl ModelRole {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "collections" => Some(Self::Collections),
            "translation" => Some(Self::Translation),
            _ => None,
        }
    }

    pub const fn model(self) -> &'static str {
        match self {
            Self::Collections => "granite3.3:2b",
            Self::Translation => "qwen2.5:1.5b",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Collections => "collections",
            Self::Translation => "translation",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatRequest {
    pub messages: Vec<Value>,
    #[serde(default)]
    pub tools: Option<Vec<Value>>,
    #[serde(default)]
    pub format: Option<Value>,
}

impl ChatRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.messages.is_empty() || self.messages.len() > 64 {
            return Err("messages must contain 1 to 64 entries");
        }
        if self.messages.iter().any(|message| {
            !message.is_object()
                || message
                    .get("role")
                    .and_then(Value::as_str)
                    .is_none_or(|role| !matches!(role, "system" | "user" | "assistant" | "tool"))
                || message.get("content").is_none()
        }) {
            return Err("each message needs an allowed role and content");
        }
        if self.tools.as_ref().is_some_and(|tools| tools.len() > 16) {
            return Err("at most 16 tool definitions are accepted");
        }
        Ok(())
    }

    fn upstream_body(&self, role: ModelRole) -> Value {
        let mut body = json!({
            "model": role.model(),
            "messages": self.messages,
            "stream": false,
            "options": { "num_ctx": 4096, "num_predict": 512 }
        });
        if let Some(tools) = &self.tools {
            body["tools"] = json!(tools);
        }
        if let Some(format) = &self.format {
            body["format"] = format.clone();
        }
        body
    }
}

pub struct OllamaProxy {
    endpoint: Url,
    client: reqwest::Client,
    concurrency: tokio::sync::Semaphore,
}

impl OllamaProxy {
    pub fn new(endpoint: &str) -> Result<Self, String> {
        let mut endpoint = Url::parse(endpoint)
            .map_err(|error| format!("Ollama endpoint does not parse: {error}"))?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            return Err("Ollama endpoint must be an http(s) server-root URL without credentials, path, query, or fragment".into());
        }
        if endpoint.scheme() == "http" && !is_internal_host(endpoint.host_str().unwrap_or_default())
        {
            return Err("plain HTTP is allowed only for loopback, private, or single-label internal Ollama hosts; use HTTPS otherwise".into());
        }
        endpoint.set_path("/api/chat");
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("kavach-model-gateway/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| "could not create Ollama HTTP client".to_string())?;
        Ok(Self {
            endpoint,
            client,
            concurrency: tokio::sync::Semaphore::new(2),
        })
    }

    pub async fn chat(&self, role: ModelRole, request: &ChatRequest) -> Result<Value, ProxyError> {
        let _permit = self
            .concurrency
            .try_acquire()
            .map_err(|_| ProxyError::Busy)?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .json(&request.upstream_body(role))
            .send()
            .await
            .map_err(|_| ProxyError::Unavailable)?;
        if !response.status().is_success() {
            return Err(ProxyError::Unavailable);
        }
        let mut response = response;
        let mut bytes = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if bytes.len() + chunk.len() <= MAX_RESPONSE_BYTES => {
                    bytes.extend_from_slice(&chunk);
                }
                Ok(Some(_)) | Err(_) => return Err(ProxyError::InvalidResponse),
                Ok(None) => break,
            }
        }
        serde_json::from_slice(&bytes).map_err(|_| ProxyError::InvalidResponse)
    }
}

fn is_internal_host(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") || !host.contains('.') {
        return true;
    }
    match IpAddr::from_str(host) {
        Ok(IpAddr::V4(address)) => {
            address.is_loopback() || address.is_private() || address.is_link_local()
        }
        Ok(IpAddr::V6(address)) => {
            address.is_loopback() || address.is_unique_local() || address.is_unicast_link_local()
        }
        Err(_) => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyError {
    Busy,
    Unavailable,
    InvalidResponse,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_a_fixed_model_allowlist() {
        assert_eq!(
            ModelRole::parse("collections").unwrap().model(),
            "granite3.3:2b"
        );
        assert_eq!(
            ModelRole::parse("translation").unwrap().model(),
            "qwen2.5:1.5b"
        );
        assert!(ModelRole::parse("../../api/tags").is_none());
    }

    #[test]
    fn governed_request_hashes_exact_prompt_and_builds_fixed_chat_input() {
        let request: GovernedModelRequest = serde_json::from_value(json!({
            "mandate_id": "mandate-1",
            "request_id": "req-1",
            "subject_ref": "ref:borrower:B-9382",
            "prompt": "hello"
        }))
        .unwrap();
        assert_eq!(
            request.prompt_digest().unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        let chat = request.chat_request();
        assert_eq!(chat.messages, [json!({"role":"user", "content":"hello"})]);
        let (tool, call) = request.tool_request(ModelRole::Collections).unwrap();
        assert_eq!(tool, "invoke_collections_model");
        assert_eq!(call.mandate_id, "mandate-1");
        assert_eq!(call.request_id, "req-1");
        assert_eq!(call.params["subject_ref"], "ref:borrower:B-9382");
        assert_eq!(
            call.params["prompt_digest"],
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert!(!call.params.contains_key("prompt"));
    }

    #[test]
    fn governed_request_rejects_invalid_envelope_without_echoing_prompt() {
        let invalid: GovernedModelRequest = serde_json::from_value(json!({
            "mandate_id": "mandate-1",
            "request_id": "req-1",
            "subject_ref": "raw borrower data",
            "prompt": "do not expose this"
        }))
        .unwrap();
        assert_eq!(
            invalid.prompt_digest(),
            Err("subject_ref must be a capability reference")
        );
        assert!(serde_json::from_value::<GovernedModelRequest>(json!({
            "mandate_id": "mandate-1",
            "request_id": "req-1",
            "subject_ref": "ref:borrower:B-9382",
            "prompt": "hello",
            "model": "caller-selected"
        }))
        .is_err());
    }

    #[test]
    fn request_requires_messages_and_rejects_unrecognized_fields() {
        let empty: ChatRequest = serde_json::from_value(json!({ "messages": [] })).unwrap();
        assert!(empty.validate().is_err());
        assert!(serde_json::from_value::<ChatRequest>(json!({
            "model": "unapproved", "messages": [{"role":"user", "content":"hi"}]
        }))
        .is_err());
        assert!(serde_json::from_value::<ChatRequest>(json!({
            "messages": [{"role":"user", "content":"hi"}], "stream": true
        }))
        .is_err());
    }

    #[test]
    fn upstream_body_fixes_model_and_disables_streaming() {
        let request: ChatRequest = serde_json::from_value(json!({
            "messages": [{"role":"user", "content":"hello"}]
        }))
        .unwrap();
        let body = request.upstream_body(ModelRole::Translation);
        assert_eq!(body["model"], "qwen2.5:1.5b");
        assert_eq!(body["stream"], false);
        assert_eq!(body["options"]["num_ctx"], 4096);
        assert_eq!(body["options"]["num_predict"], 512);
    }

    #[test]
    fn endpoint_is_a_base_url_only() {
        assert!(OllamaProxy::new("http://127.0.0.1:11434").is_ok());
        assert!(OllamaProxy::new("http://ollama:11434").is_ok());
        assert!(OllamaProxy::new("http://example.com:11434").is_err());
        assert!(OllamaProxy::new("https://example.com:11434").is_ok());
        assert!(OllamaProxy::new("http://user:pass@127.0.0.1:11434").is_err());
        assert!(OllamaProxy::new("http://127.0.0.1:11434/api/tags").is_err());
        assert!(OllamaProxy::new("file:///tmp/model").is_err());
    }
}
