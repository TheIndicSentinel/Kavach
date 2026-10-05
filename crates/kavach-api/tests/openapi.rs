//! `docs/openapi.yaml` against the code (C6b): the same routes and methods
//! on each listener, the same problem codes, and every schema compiles.
//! What each response looks like is checked by `contract`, on every
//! response the integration tests see.

mod contract;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

type Routes = BTreeMap<String, BTreeSet<String>>;

fn source(file: &str) -> String {
    std::fs::read_to_string(format!("{}/src/{file}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// The body of `fn name` in `text` (to its closing brace at column 0).
fn function<'t>(text: &'t str, name: &str) -> &'t str {
    let start = text
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("fn {name}"));
    let end = text[start..].find("\n}\n").unwrap() + start;
    &text[start..end]
}

/// `.route("path", get(…).post(…))` calls: path → methods.
fn routes_in(code: &str) -> Routes {
    let mut routes = Routes::new();
    let mut rest = code;
    while let Some(at) = rest.find(".route(") {
        let call = &rest[at + ".route(".len()..];
        // The call's own parentheses.
        let mut depth = 1;
        let end = call
            .char_indices()
            .find_map(|(i, c)| {
                match c {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                (depth == 0).then_some(i)
            })
            .unwrap();
        let call = &call[..end];
        let path = call.split('"').nth(1).unwrap().to_string();
        let methods = routes.entry(path).or_default();
        for method in ["get", "post", "put", "patch", "delete"] {
            let needle = format!("{method}(");
            let mut from = 0;
            while let Some(i) = call[from..].find(&needle) {
                let i = from + i;
                let before = call[..i].chars().last().unwrap_or(' ');
                if !(before.is_alphanumeric() || before == '_') {
                    methods.insert(method.to_string());
                }
                from = i + needle.len();
            }
        }
        rest = &rest[at + 1..];
    }
    routes
}

fn code_routes() -> BTreeMap<&'static str, Routes> {
    let http = source("http.rs");
    let dataplane = source("dataplane.rs");
    BTreeMap::from([
        ("operator", routes_in(function(&http, "router"))),
        ("agent", routes_in(function(&dataplane, "agent_router"))),
        ("sor", routes_in(function(&dataplane, "sor_router"))),
    ])
}

fn spec_routes() -> BTreeMap<&'static str, Routes> {
    let mut by_listener: BTreeMap<&'static str, Routes> = BTreeMap::new();
    for (path, item) in contract::spec()["paths"].as_object().unwrap() {
        let methods: BTreeSet<String> = ["get", "post", "put", "patch", "delete"]
            .into_iter()
            .filter(|m| item.get(*m).is_some())
            .map(str::to_string)
            .collect();
        for listener in contract::listeners(item) {
            let listener = match listener {
                "operator" => "operator",
                "agent" => "agent",
                "sor" => "sor",
                other => panic!("{path}: unknown listener {other}"),
            };
            by_listener
                .entry(listener)
                .or_default()
                .insert(path.clone(), methods.clone());
        }
    }
    by_listener
}

#[test]
fn the_spec_has_exactly_the_routes_and_methods_of_each_listener() {
    let code = code_routes();
    assert!(
        code["operator"].contains_key("/v1/evaluate"),
        "the route scan works"
    );
    assert!(code["agent"].contains_key("/v1/tools/{tool}"));
    assert_eq!(
        spec_routes(),
        code,
        "docs/openapi.yaml (left) and the routers (right) differ"
    );
}

#[test]
fn the_problem_codes_are_the_catalog() {
    let spec: BTreeSet<&str> = contract::spec()["components"]["schemas"]["ProblemCode"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let code: BTreeSet<&str> = kavach_api::problem::CODES
        .iter()
        .map(|(c, _, _)| *c)
        .collect();
    assert_eq!(
        spec, code,
        "ProblemCode in docs/openapi.yaml (left) and CODES (right)"
    );
}

#[test]
fn every_reference_resolves_and_every_schema_compiles() {
    fn walk(value: &Value, refs: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                if let Some(r) = map.get("$ref").and_then(Value::as_str) {
                    refs.push(r.to_string());
                }
                map.values().for_each(|v| walk(v, refs));
            }
            Value::Array(items) => items.iter().for_each(|v| walk(v, refs)),
            _ => {}
        }
    }
    let spec = contract::spec();
    let mut refs = Vec::new();
    walk(spec, &mut refs);
    for r in &refs {
        assert!(
            r.starts_with("#/") && spec.pointer(&r[1..]).is_some(),
            "{r} does not resolve"
        );
    }
    let root = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "components": spec["components"],
        "anyOf": spec["components"]["schemas"]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| serde_json::json!({ "$ref": format!("#/components/schemas/{k}") }))
            .collect::<Vec<_>>(),
    });
    jsonschema::validator_for(&root).expect("every schema in docs/openapi.yaml compiles");
}
