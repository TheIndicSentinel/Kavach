//! The agent tool registry (H5b, ADR-007).
//!
//! The registry is security-critical configuration: it decides which tools an
//! agent may call, which parameters are reference-only and which values are
//! allowed. It is loaded once at startup, verified against a detached
//! signature (`tool` signer role) and an optional digest pin, and its digest
//! is recorded in every agent decision record (`policy_versions.tools`).
//!
//! Extraction turns an agent's request into a [`ToolCall`] with a fixed error
//! taxonomy:
//!
//! - **Malformed** (unknown tool, unknown or missing parameter, wrong JSON
//!   type, over-long value) → `Invalid` (HTTP 400). Nothing is recorded:
//!   there is no well-formed call to record.
//! - **Policy violation** (a raw value in a reference-only parameter, a value
//!   outside its allowlist or range) → the call carries the violation, and
//!   the core decides `BLOCK` and records it (reason and parameter name only;
//!   no parameter MAC, never the value).
//!
//! Strict grammars and allowlists are the primary control; the raw-identifier
//! detector (`detect`) is defence in depth.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use kavach_authz::AgentAction;
use kavach_domain::mandate::is_capability_ref;
use kavach_keys::{verify_tool_registry_file, TrustedSigners};
use kavach_ports::PortError;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::authorize::ToolCall;
use crate::detect::raw_identifier;

const REGISTRY_VERSION: u32 = 1;
/// Longest accepted string parameter (bytes).
pub const MAX_PARAM_BYTES: usize = 256;
const MAX_ID_BYTES: usize = 128;
/// Envelope fields; never declarable as tool parameters.
const RESERVED: [&str; 4] = ["mandate_id", "request_id", "action", "tool"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    /// Reads data; no effect outside Kavach.
    ReadOnly,
    /// Proposes a change for a human or a system of record to act on.
    Proposal,
    /// Acts on the world (messages, calls): forwarded once, with a credential.
    ExternalEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamKind {
    /// Reference-only: an opaque `ref:<type>:<id>`, never a raw value.
    CapabilityRef,
    /// One value from `values`.
    Enum,
    /// A set of values from `values`.
    FieldSet,
    /// An integer within `[min, max]`.
    Integer,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamSpec {
    pub kind: ParamKind,
    #[serde(default)]
    pub values: Vec<String>,
    pub min: Option<i64>,
    pub max: Option<i64>,
    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSpec {
    pub name: String,
    /// The Cedar agent action this tool performs.
    pub action: String,
    pub trust: Trust,
    /// The resource provider an `external_effect` tool is forwarded to
    /// (the credential audience); required for those, refused otherwise.
    pub provider: Option<String>,
    pub params: BTreeMap<String, ParamSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    version: u32,
    tools: Vec<ToolSpec>,
}

/// An agent's tool request: the envelope plus the tool's parameters.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRequest {
    pub mandate_id: String,
    pub request_id: String,
    #[serde(default)]
    pub params: serde_json::Map<String, Value>,
}

/// How the registry file must be vouched for at load.
#[derive(Debug, Clone, Copy, Default)]
pub struct RegistryTrust<'a> {
    /// Verify `<registry>.sig` against these signers (`tool` role).
    pub signers: Option<&'a TrustedSigners>,
    /// Expected file digest (`sha256:<hex>` or bare hex).
    pub pin: Option<&'a str>,
    /// Refuse a registry that is not signature-verified.
    pub require_signature: bool,
}

#[derive(Debug, Clone)]
pub struct ToolRegistry {
    digest: String,
    tools: BTreeMap<String, ToolSpec>,
}

fn file_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn normalize_digest(digest: &str) -> String {
    let hex = digest
        .trim()
        .trim_start_matches("sha256:")
        .to_ascii_lowercase();
    format!("sha256:{hex}")
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    (1..=64).contains(&name.len())
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn is_allowlist_value(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'))
        && raw_identifier(value).is_none()
}

impl ToolRegistry {
    /// Reads, vouches for and validates the registry at `path`.
    pub fn load(path: &Path, trust: RegistryTrust<'_>) -> Result<Self, PortError> {
        let bytes = std::fs::read(path).map_err(|e| {
            PortError::unavailable(format!("read tool registry {}: {e}", path.display()))
        })?;
        let digest = file_digest(&bytes);
        if let Some(pin) = trust.pin {
            let expected = normalize_digest(pin);
            if expected != digest {
                return Err(PortError::rejected(format!(
                    "tool registry digest is {digest}, pinned {expected}"
                )));
            }
        }
        match trust.signers {
            Some(signers) => verify_tool_registry_file(path, &digest, signers)?,
            None if trust.require_signature => {
                return Err(PortError::rejected(
                    "the tool registry must be signed: configure trusted signers with a \
                     \"tool\" role and sign it with `kavach-keys sign-tools`",
                ))
            }
            None => {}
        }
        Self::from_bytes(&bytes)
    }

    /// Parses and validates registry bytes (no signature check).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PortError> {
        let file: RegistryFile = serde_yaml::from_slice(bytes)
            .map_err(|e| PortError::invalid(format!("tool registry: {e}")))?;
        if file.version != REGISTRY_VERSION {
            return Err(PortError::invalid(format!(
                "tool registry version {} (expected {REGISTRY_VERSION})",
                file.version
            )));
        }
        if file.tools.is_empty() {
            return Err(PortError::invalid("tool registry declares no tools"));
        }
        let mut tools = BTreeMap::new();
        let mut actions = BTreeSet::new();
        for tool in file.tools {
            validate_tool(&tool)?;
            if !actions.insert(tool.action.clone()) {
                return Err(PortError::invalid(format!(
                    "tool registry: action {} has more than one tool",
                    tool.action
                )));
            }
            let name = tool.name.clone();
            if tools.insert(name.clone(), tool).is_some() {
                return Err(PortError::invalid(format!(
                    "tool registry: duplicate tool {name}"
                )));
            }
        }
        Ok(Self {
            digest: file_digest(bytes),
            tools,
        })
    }

    /// `sha256:<hex>` of the registry file.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn tool(&self, name: &str) -> Option<&ToolSpec> {
        self.tools.get(name)
    }

    /// The tool that performs `action`, if one is registered.
    pub fn for_action(&self, action: &str) -> Option<&ToolSpec> {
        self.tools.values().find(|t| t.action == action)
    }

    /// Providers that `external_effect` tools forward to.
    pub fn providers(&self) -> BTreeSet<&str> {
        self.tools
            .values()
            .filter_map(|t| t.provider.as_deref())
            .collect()
    }

    /// Turns a request for `tool` into a [`ToolCall`]. `Err` (`Invalid`) for
    /// a malformed request; policy violations are carried in the call.
    pub fn extract(&self, tool: &str, request: ToolRequest) -> Result<ToolCall, PortError> {
        let spec = self.tool(tool).ok_or_else(|| {
            let shown = if is_identifier(tool) {
                tool
            } else {
                "(not an identifier)"
            };
            PortError::invalid(format!("unknown tool {shown}"))
        })?;
        if request.mandate_id.is_empty() || request.mandate_id.len() > MAX_ID_BYTES {
            return Err(PortError::invalid("mandate_id must be 1-128 bytes"));
        }
        crate::authorize::validate_request_id(&request.request_id)?;
        if let Some(unknown) = request
            .params
            .keys()
            .find(|k| !spec.params.contains_key(*k))
        {
            // Echo the name only if it is a plain identifier (never a value).
            let shown = if is_identifier(unknown) {
                unknown.as_str()
            } else {
                "(not an identifier)"
            };
            return Err(PortError::invalid(format!(
                "tool {tool}: unknown parameter {shown}"
            )));
        }

        let mut call = ToolCall {
            mandate_id: request.mandate_id,
            action: spec.action.clone(),
            request_id: request.request_id,
            subject_ref: String::new(),
            channel: None,
            waiver_bps: None,
            requested_fields: BTreeSet::new(),
            extra: BTreeMap::new(),
            violations: Vec::new(),
        };
        for (name, param) in &spec.params {
            let Some(value) = request.params.get(name) else {
                if param.optional {
                    continue;
                }
                return Err(PortError::invalid(format!(
                    "tool {tool}: missing parameter {name:?}"
                )));
            };
            bind(&mut call, name, param, value)?;
        }
        Ok(call)
    }
}

fn string_param<'v>(name: &str, value: &'v Value) -> Result<&'v str, PortError> {
    let text = value
        .as_str()
        .ok_or_else(|| PortError::invalid(format!("parameter {name:?} must be a string")))?;
    if text.len() > MAX_PARAM_BYTES {
        return Err(PortError::invalid(format!(
            "parameter {name:?} exceeds {MAX_PARAM_BYTES} bytes"
        )));
    }
    Ok(text)
}

/// Checks one parameter and stores it in the call.
fn bind(
    call: &mut ToolCall,
    name: &str,
    param: &ParamSpec,
    value: &Value,
) -> Result<(), PortError> {
    match param.kind {
        ParamKind::CapabilityRef => {
            let text = string_param(name, value)?;
            if !is_capability_ref(text) {
                call.violations
                    .push(format!("reference_only_violation:{name}"));
            }
            if name == "subject_ref" {
                call.subject_ref = text.to_string();
            } else {
                call.extra.insert(name.to_string(), text.to_string());
            }
        }
        ParamKind::Enum => {
            let text = string_param(name, value)?;
            if !param.values.iter().any(|v| v == text) {
                call.violations.push(format!("value_not_allowed:{name}"));
            }
            if name == "channel" {
                call.channel = Some(text.to_string());
            } else {
                call.extra.insert(name.to_string(), text.to_string());
            }
        }
        ParamKind::FieldSet => {
            let items = value.as_array().ok_or_else(|| {
                PortError::invalid(format!("parameter {name:?} must be an array of strings"))
            })?;
            if items.len() > param.values.len() {
                return Err(PortError::invalid(format!(
                    "parameter {name:?} has more entries than allowed values"
                )));
            }
            for item in items {
                let text = string_param(name, item)?;
                if !param.values.iter().any(|v| v == text) {
                    let reason = format!("value_not_allowed:{name}");
                    if !call.violations.contains(&reason) {
                        call.violations.push(reason);
                    }
                }
                call.requested_fields.insert(text.to_string());
            }
        }
        ParamKind::Integer => {
            let number = value.as_i64().ok_or_else(|| {
                PortError::invalid(format!("parameter {name:?} must be an integer"))
            })?;
            let (min, max) = (param.min.unwrap_or(i64::MIN), param.max.unwrap_or(i64::MAX));
            if !(min..=max).contains(&number) {
                call.violations.push(format!("value_out_of_range:{name}"));
            }
            if name == "waiver_bps" {
                call.waiver_bps = Some(number);
            } else {
                call.extra.insert(name.to_string(), number.to_string());
            }
        }
    }
    Ok(())
}

/// Parameters the core reads into typed `ToolCall` fields, and the kind each
/// must have.
const TYPED: [(&str, ParamKind); 4] = [
    ("subject_ref", ParamKind::CapabilityRef),
    ("channel", ParamKind::Enum),
    ("waiver_bps", ParamKind::Integer),
    ("requested_fields", ParamKind::FieldSet),
];

/// Parameters an action cannot do without (mirrors the fail-closed Cedar
/// forbids, so a missing one is a 400 before it is a BLOCK).
fn required_for(action: AgentAction) -> &'static [&'static str] {
    match action {
        AgentAction::ReadFields => &["requested_fields"],
        AgentAction::SendReminder | AgentAction::PlaceCall => &["channel"],
        AgentAction::ProposePlan => &["waiver_bps"],
        AgentAction::UpdateStatus => &[],
    }
}

fn validate_tool(tool: &ToolSpec) -> Result<(), PortError> {
    let fail = |msg: String| Err(PortError::invalid(format!("tool {}: {msg}", tool.name)));
    if !is_identifier(&tool.name) {
        return fail("name must be [a-z][a-z0-9_]{0,63}".into());
    }
    let Some(action) = AgentAction::from_name(&tool.action) else {
        return fail(format!("unknown action {:?}", tool.action));
    };
    match (&tool.provider, tool.trust) {
        (Some(provider), Trust::ExternalEffect) if is_allowlist_value(provider) => {}
        (None, Trust::ExternalEffect) => {
            return fail("an external_effect tool must name its provider".into())
        }
        (Some(_), Trust::ExternalEffect) => {
            return fail("provider must be 1-64 of [a-z0-9_.-]".into())
        }
        (Some(_), _) => return fail("only external_effect tools have a provider".into()),
        (None, _) => {}
    }
    match tool.params.get("subject_ref") {
        Some(p) if p.kind == ParamKind::CapabilityRef && !p.optional => {}
        _ => return fail("subject_ref must be a required capability_ref".into()),
    }
    for required in required_for(action) {
        if tool.params.get(*required).is_none_or(|p| p.optional) {
            return fail(format!(
                "action {} requires parameter {required}",
                tool.action
            ));
        }
    }
    for (name, param) in &tool.params {
        if !is_identifier(name) || RESERVED.contains(&name.as_str()) {
            return fail(format!("parameter name {name:?} is not allowed"));
        }
        if let Some((_, kind)) = TYPED.iter().find(|(typed, _)| typed == name) {
            if param.kind != *kind {
                return fail(format!("parameter {name} must be of kind {kind:?}"));
            }
        } else if param.kind == ParamKind::FieldSet {
            return fail(format!(
                "only requested_fields may be a field_set (got {name})"
            ));
        }
        validate_param(name, param).or_else(&fail)?;
    }
    Ok(())
}

fn validate_param(name: &str, param: &ParamSpec) -> Result<(), String> {
    let has_values = !param.values.is_empty();
    let has_range = param.min.is_some() || param.max.is_some();
    match param.kind {
        ParamKind::CapabilityRef if has_values || has_range => {
            return Err(format!("{name}: a capability_ref takes no values or range"))
        }
        ParamKind::Enum | ParamKind::FieldSet if !has_values || has_range => {
            return Err(format!("{name}: an allowlist needs values and no range"))
        }
        ParamKind::Integer => match (param.min, param.max) {
            (Some(min), Some(max)) if min <= max && !has_values => {}
            _ => return Err(format!("{name}: an integer needs min <= max and no values")),
        },
        _ => {}
    }
    let mut seen = BTreeSet::new();
    for value in &param.values {
        if !is_allowlist_value(value) {
            return Err(format!(
                "{name}: allowlist value {value:?} must be 1-64 of [a-z0-9_.-] and not an identifier"
            ));
        }
        if !seen.insert(value) {
            return Err(format!("{name}: duplicate allowlist value {value:?}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const REFERENCE: &[u8] = include_bytes!("../../../tools/agent-tools.yaml");

    fn registry() -> ToolRegistry {
        ToolRegistry::from_bytes(REFERENCE).expect("reference registry")
    }

    fn request(params: Value) -> ToolRequest {
        let Value::Object(params) = params else {
            panic!("params must be an object")
        };
        ToolRequest {
            mandate_id: "m-1".into(),
            request_id: "r-1".into(),
            params,
        }
    }

    fn reminder() -> Value {
        json!({
            "subject_ref": "ref:borrower:B-9382",
            "channel": "whatsapp",
            "template_id": "emi_reminder_v1",
        })
    }

    #[test]
    fn reference_registry_loads_and_digest_is_of_the_file() {
        let r = registry();
        assert_eq!(r.digest(), file_digest(REFERENCE));
        assert_eq!(
            r.tool("send_reminder").unwrap().trust,
            Trust::ExternalEffect
        );
        assert_eq!(r.for_action("propose_plan").unwrap().name, "propose_plan");
        assert!(r.tool("update_status").is_none(), "not exposed to agents");
        assert_eq!(
            r.providers().into_iter().collect::<Vec<_>>(),
            vec!["mock-messaging", "mock-voice"]
        );
    }

    #[test]
    fn a_well_formed_reminder_extracts_without_violations() {
        let call = registry()
            .extract("send_reminder", request(reminder()))
            .unwrap();
        assert_eq!(call.action, "send_reminder");
        assert_eq!(call.subject_ref, "ref:borrower:B-9382");
        assert_eq!(call.channel.as_deref(), Some("whatsapp"));
        assert_eq!(call.extra["template_id"], "emi_reminder_v1");
        assert!(call.violations.is_empty(), "{:?}", call.violations);
    }

    #[test]
    fn malformed_requests_are_invalid() {
        let r = registry();
        let invalid = |tool: &str, params: Value| {
            let err = r.extract(tool, request(params)).unwrap_err();
            assert_eq!(
                err.class,
                kavach_ports::ErrorClass::Invalid,
                "{}",
                err.message
            );
        };
        invalid("delete_everything", reminder());
        // Unknown parameter, including an agent-supplied timestamp or message.
        let mut extra = reminder();
        extra["timestamp"] = json!("2026-10-01T05:00:00Z");
        invalid("send_reminder", extra);
        let mut text = reminder();
        text["message"] = json!("pay now");
        invalid("send_reminder", text);
        // Missing, wrongly typed and over-long parameters.
        let mut missing = reminder();
        missing.as_object_mut().unwrap().remove("template_id");
        invalid("send_reminder", missing);
        let mut typed = reminder();
        typed["channel"] = json!(["whatsapp"]);
        invalid("send_reminder", typed);
        let mut long = reminder();
        long["subject_ref"] = json!(format!("ref:borrower:{}", "B".repeat(300)));
        invalid("send_reminder", long);
        invalid(
            "propose_plan",
            json!({ "subject_ref": "ref:borrower:B-1", "waiver_bps": "500" }),
        );
        invalid("propose_plan", json!({ "subject_ref": "ref:borrower:B-1" }));

        // Unknown envelope fields.
        let envelope: Result<ToolRequest, _> = serde_json::from_value(json!({
            "mandate_id": "m-1", "request_id": "r-1", "params": {}, "timestamp": "now"
        }));
        assert!(envelope.is_err());
    }

    #[test]
    fn policy_violations_are_carried_for_a_recorded_block() {
        let r = registry();
        let violations =
            |tool: &str, params: Value| r.extract(tool, request(params)).unwrap().violations;
        let mut raw = reminder();
        raw["subject_ref"] = json!("+91 98765 43210");
        assert_eq!(
            violations("send_reminder", raw),
            vec!["reference_only_violation:subject_ref"]
        );
        let mut channel = reminder();
        channel["channel"] = json!("email");
        assert_eq!(
            violations("send_reminder", channel),
            vec!["value_not_allowed:channel"]
        );
        let mut template = reminder();
        template["template_id"] = json!("free_text_v1");
        assert_eq!(
            violations("send_reminder", template),
            vec!["value_not_allowed:template_id"]
        );
        assert_eq!(
            violations(
                "propose_plan",
                json!({ "subject_ref": "ref:borrower:B-1", "waiver_bps": 20000 })
            ),
            vec!["value_out_of_range:waiver_bps"]
        );
        assert_eq!(
            violations(
                "read_fields",
                json!({ "subject_ref": "ref:borrower:B-1", "requested_fields": ["name", "aadhaar"] })
            ),
            vec!["value_not_allowed:requested_fields"]
        );
    }

    fn load_err(yaml: &str) -> String {
        ToolRegistry::from_bytes(yaml.as_bytes())
            .unwrap_err()
            .message
    }

    #[test]
    fn unsafe_registries_are_refused() {
        let subject = "subject_ref: { kind: capability_ref }";
        // Plans must require a waiver (H4 carry-over).
        let e = load_err(&format!(
            "version: 1\ntools:\n- name: plan\n  action: propose_plan\n  trust: proposal\n  params:\n    {subject}\n"
        ));
        assert!(e.contains("requires parameter waiver_bps"), "{e}");
        // The subject must be reference-only.
        let e = load_err(
            "version: 1\ntools:\n- name: r\n  action: send_reminder\n  trust: external_effect\n  provider: p\n  params:\n    subject_ref: { kind: enum, values: [a] }\n    channel: { kind: enum, values: [sms] }\n",
        );
        assert!(e.contains("capability_ref"), "{e}");
        // An allowlist cannot contain a raw identifier.
        let e = load_err(&format!(
            "version: 1\ntools:\n- name: r\n  action: send_reminder\n  trust: external_effect\n  provider: p\n  params:\n    {subject}\n    channel: {{ kind: enum, values: ['9876543210'] }}\n"
        ));
        assert!(e.contains("not an identifier"), "{e}");
        // Unknown keys, unknown actions, reserved names, duplicate actions.
        assert!(load_err(&format!(
            "version: 1\ntools:\n- name: r\n  action: send_reminder\n  trust: external_effect\n  provider: p\n  free_text: true\n  params:\n    {subject}\n"
        ))
        .contains("unknown field"));
        assert!(load_err(&format!(
            "version: 1\ntools:\n- name: r\n  action: wire_money\n  trust: external_effect\n  provider: p\n  params:\n    {subject}\n"
        ))
        .contains("unknown action"));
        assert!(load_err(&format!(
            "version: 1\ntools:\n- name: r\n  action: read_fields\n  trust: read_only\n  params:\n    {subject}\n    requested_fields: {{ kind: field_set, values: [name] }}\n    request_id: {{ kind: enum, values: [x] }}\n"
        ))
        .contains("not allowed"));
        let tool = |name: &str| {
            format!(
                "- name: {name}\n  action: read_fields\n  trust: read_only\n  params:\n    {subject}\n    requested_fields: {{ kind: field_set, values: [name] }}\n"
            )
        };
        assert!(
            load_err(&format!("version: 1\ntools:\n{}{}", tool("a"), tool("b")))
                .contains("more than one tool")
        );
        assert!(load_err("version: 2\ntools: []\n").contains("version"));
        // An external effect must say where it goes; nothing else may.
        assert!(load_err(&format!(
            "version: 1\ntools:\n- name: r\n  action: send_reminder\n  trust: external_effect\n  params:\n    {subject}\n    channel: {{ kind: enum, values: [sms] }}\n"
        ))
        .contains("must name its provider"));
        assert!(load_err(&format!(
            "version: 1\ntools:\n- name: r\n  action: read_fields\n  trust: read_only\n  provider: p\n  params:\n    {subject}\n    requested_fields: {{ kind: field_set, values: [name] }}\n"
        ))
        .contains("only external_effect"));
    }

    #[test]
    fn load_enforces_pin_and_signature() {
        let dir = std::env::temp_dir().join(format!("kavach-tools-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tools.yaml");
        std::fs::write(&path, REFERENCE).unwrap();
        let digest = file_digest(REFERENCE);

        ToolRegistry::load(&path, RegistryTrust::default()).unwrap();
        ToolRegistry::load(
            &path,
            RegistryTrust {
                pin: Some(digest.trim_start_matches("sha256:")),
                ..RegistryTrust::default()
            },
        )
        .unwrap();
        let wrong = ToolRegistry::load(
            &path,
            RegistryTrust {
                pin: Some("sha256:00"),
                ..RegistryTrust::default()
            },
        )
        .unwrap_err();
        assert!(wrong.message.contains("pinned"), "{}", wrong.message);
        let unsigned = ToolRegistry::load(
            &path,
            RegistryTrust {
                require_signature: true,
                ..RegistryTrust::default()
            },
        )
        .unwrap_err();
        assert!(
            unsigned.message.contains("must be signed"),
            "{}",
            unsigned.message
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_signed_registry_loads_and_a_tampered_one_is_refused() {
        use kavach_keys::{sign_tool_registry, signature_path, InMemoryKeyProvider};
        let dir = std::env::temp_dir().join(format!("kavach-tools-sig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tools.yaml");
        std::fs::write(&path, REFERENCE).unwrap();

        let mut keys = InMemoryKeyProvider::new();
        let public = keys.generate("tool-signer").unwrap();
        let signature = sign_tool_registry(&keys, "tool-signer", &file_digest(REFERENCE))
            .await
            .unwrap();
        std::fs::write(
            signature_path(&path),
            serde_json::to_string(&signature).unwrap(),
        )
        .unwrap();
        let signers = TrustedSigners::from_json(
            &json!({ "signers": [{
                "kid": "tool-signer",
                "public_key": hex::encode(public.bytes),
                "roles": ["tool"],
            }]})
            .to_string(),
        )
        .unwrap();
        let trust = RegistryTrust {
            signers: Some(&signers),
            require_signature: true,
            ..RegistryTrust::default()
        };
        let loaded = ToolRegistry::load(&path, trust).unwrap();
        assert_eq!(loaded.digest(), file_digest(REFERENCE));

        // Widen an allowlist after signing: refused.
        let tampered = String::from_utf8(REFERENCE.to_vec())
            .unwrap()
            .replace("values: [whatsapp, sms]", "values: [whatsapp, sms, email]");
        std::fs::write(&path, tampered).unwrap();
        let err = ToolRegistry::load(&path, trust).unwrap_err();
        assert!(err.message.contains("signature covers"), "{}", err.message);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
