use std::fs;
use std::path::Path;

use cel_interpreter::Program;
use kavach_domain::PolicyPack;

use crate::error::PolicyError;

/// A policy pack with CEL programs compiled at load time.
pub struct LoadedPolicyPack {
    pub pack: PolicyPack,
    pub compiled_rules: Vec<CompiledRule>,
}

pub struct CompiledRule {
    pub id: String,
    pub program: Program,
    pub decision: kavach_domain::Decision,
    pub reason_code: String,
}

pub struct PackLoader;

impl PackLoader {
    pub fn load_from_path(path: &Path) -> Result<LoadedPolicyPack, PolicyError> {
        let content = fs::read_to_string(path)?;
        let pack: PolicyPack = serde_yaml::from_str(&content)?;
        Self::load_from_pack(pack)
    }

    pub fn load_from_pack(pack: PolicyPack) -> Result<LoadedPolicyPack, PolicyError> {
        if pack.rules.is_empty() {
            return Err(PolicyError::Validation(
                "pack must contain at least one rule".into(),
            ));
        }

        let mut compiled_rules = Vec::with_capacity(pack.rules.len());
        for rule in &pack.rules {
            let program =
                Program::compile(&rule.expression).map_err(|e| PolicyError::CelCompile {
                    rule_id: rule.id.clone(),
                    message: e.to_string(),
                })?;
            compiled_rules.push(CompiledRule {
                id: rule.id.clone(),
                program,
                decision: rule.decision,
                reason_code: rule.reason_code.clone(),
            });
        }

        Ok(LoadedPolicyPack {
            pack,
            compiled_rules,
        })
    }
}
