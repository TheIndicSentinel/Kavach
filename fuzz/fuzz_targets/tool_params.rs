//! Agent tool requests through registry extraction, for every tool in the
//! reference registry. First byte: which tool; the rest: the parameters as
//! JSON (an object, as the gateway would parse it).
//!
//! Invariant: a call extracted without violations carries no raw identifier
//! in a reference-only field. The oracle here is independent of the
//! detector: a reference-only value holds at most 8 decimal digits (ASCII,
//! fullwidth or Devanagari) and contains no PAN.

#![no_main]

use std::sync::OnceLock;

use kavach_dataplane::tools::{ParamKind, ToolRegistry};
use kavach_dataplane::ToolRequest;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fn registry() -> &'static ToolRegistry {
    static REGISTRY: OnceLock<ToolRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        ToolRegistry::from_bytes(include_bytes!("../../tools/agent-tools.yaml"))
            .expect("reference registry")
    })
}

fn digit(c: char) -> bool {
    let code = u32::from(c);
    c.is_ascii_digit() || (0xFF10..=0xFF19).contains(&code) || (0x0966..=0x096F).contains(&code)
}

/// PAN shape over ASCII letters and digits, ignoring everything else.
fn has_pan(value: &str) -> bool {
    let chars: Vec<char> = value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    chars.windows(10).any(|w| {
        w[..5].iter().all(char::is_ascii_alphabetic)
            && "PCHFATBLJG".contains(w[3])
            && w[5..9].iter().all(char::is_ascii_digit)
            && w[9].is_ascii_alphabetic()
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    let tools: Vec<_> = registry().tools().collect();
    let spec = tools[usize::from(which) % tools.len()];
    let Ok(Value::Object(params)) = serde_json::from_slice::<Value>(rest) else {
        return;
    };
    let request = ToolRequest {
        mandate_id: "m-1".into(),
        request_id: "r-1".into(),
        params: params.clone(),
    };
    let Ok(call) = registry().extract(&spec.name, request) else {
        return;
    };
    if !call.violations.is_empty() {
        return;
    }
    for (name, param) in &spec.params {
        if param.kind != ParamKind::CapabilityRef {
            continue;
        }
        let Some(Value::String(value)) = params.get(name) else {
            continue;
        };
        let digits = value.chars().filter(|c| digit(*c)).count();
        assert!(digits <= 8, "{name}: {digits} digits passed: {value:?}");
        assert!(!has_pan(value), "{name}: a PAN passed: {value:?}");
    }
});
