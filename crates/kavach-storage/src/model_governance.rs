//! The governed model record at startup (ADR-010), shared by `kavach-api` and
//! `kavach-batch` so both evaluate with the same effective model.
//!
//! - The runtime pointer names the active model file and pins its SHA-256.
//! - Fixed fields (schema, purpose, origin, pack binding, ...) come from that
//!   pinned YAML; `status` and `governance_mode` come from `model_state`,
//!   which only approved change requests write.
//! - Only the API records baselines; batch refuses to run on anything that is
//!   not already governed.

use std::path::Path;

use chrono::Utc;
use kavach_domain::{GovernanceMode, ModelRecord, ModelStatus};

use crate::admin::{mode_str, parse_mode, parse_status, status_str, AuditInsert, ModelState};
use crate::backends::AdminBackend;
use crate::startup::same_path;

const STARTUP_PRINCIPAL: &str = "system:startup";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelStartupRole {
    /// May record baselines; `bootstrap_model` re-pins a changed model file
    /// (path and digest only — never status or mode).
    Api { bootstrap_model: bool },
    /// Never writes governance state.
    Batch,
}

#[derive(Debug, Clone)]
pub struct GovernedModel {
    /// The YAML record with governed `status` and `governance_mode`.
    pub model: ModelRecord,
    pub model_sha256: String,
    /// Set when the YAML's own status/mode differ from the governed values
    /// (they are ignored; worth a startup warning).
    pub yaml_divergence: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ModelStartupError {
    #[error("{0}")]
    NotGoverned(String),
    #[error(
        "startup model {startup} differs from the active model {active} recorded by governance; \
         start with the active model, activate the new one with an activate_model change \
         request, or use --bootstrap-model for audited recovery"
    )]
    PathMismatch { startup: String, active: String },
    #[error(
        "model file bytes differ from the pinned digest: expected {expected}, got {actual}; \
         activate the edited file with an activate_model change request, or use \
         --bootstrap-model for audited recovery"
    )]
    DigestMismatch { expected: String, actual: String },
    #[error(
        "refusing to baseline model {model_id} from its YAML ({yaml}): the last approved \
         update_model set {approved}. Start with --bootstrap-model to restore the approved \
         state, or correct the YAML"
    )]
    DivergentHistory {
        model_id: String,
        yaml: String,
        approved: String,
    },
    #[error("model governance store: {0}")]
    Store(String),
}

fn store<E: std::fmt::Display>(err: E) -> ModelStartupError {
    ModelStartupError::Store(err.to_string())
}

fn describe(status: ModelStatus, mode: GovernanceMode) -> String {
    format!("status {}, mode {}", status_str(status), mode_str(mode))
}

fn audit(action: &str, model_id: &str, payload: serde_json::Value) -> AuditInsert {
    AuditInsert {
        action: action.into(),
        resource_type: "model_record".into(),
        resource_id: model_id.into(),
        actor_principal: STARTUP_PRINCIPAL.into(),
        approver_principal: STARTUP_PRINCIPAL.into(),
        payload,
    }
}

/// Resolves the effective model for `yaml` loaded from `path` (bytes digest
/// `digest`). Postgres mode; the pack pointer must already exist.
pub async fn govern_model(
    admin: &AdminBackend,
    path: &Path,
    yaml: ModelRecord,
    digest: &str,
    role: ModelStartupRole,
) -> Result<GovernedModel, ModelStartupError> {
    pin_model_file(admin, path, &yaml.model_id, digest, role).await?;
    let state = governed_state(admin, &yaml, role).await?;

    let yaml_divergence =
        (yaml.status != state.status || yaml.governance_mode != state.governance_mode).then(|| {
            format!(
                "model {} YAML says {}; governed state is {} (the YAML values are ignored)",
                yaml.model_id,
                describe(yaml.status, yaml.governance_mode),
                describe(state.status, state.governance_mode)
            )
        });
    Ok(GovernedModel {
        model: ModelRecord {
            status: state.status,
            governance_mode: state.governance_mode,
            ..yaml
        },
        model_sha256: digest.to_string(),
        yaml_divergence,
    })
}

async fn pin_model_file(
    admin: &AdminBackend,
    path: &Path,
    model_id: &str,
    digest: &str,
    role: ModelStartupRole,
) -> Result<(), ModelStartupError> {
    let pointers = admin
        .get_runtime_pointers()
        .await
        .map_err(store)?
        .ok_or_else(|| {
            ModelStartupError::NotGoverned(
                "no governed runtime yet; start kavach-api once to record the baseline".into(),
            )
        })?;
    let path_str = path.display().to_string();
    let path_ok = same_path(&pointers.model_path, path);
    let mismatch = match (path_ok, pointers.model_sha256.as_deref()) {
        (true, Some(pinned)) if pinned == digest => return Ok(()),
        (true, None) => {
            // Pointer recorded before model pinning (upgrade from H3a).
            if role == ModelStartupRole::Batch {
                return Err(ModelStartupError::NotGoverned(
                    "the model file is not pinned yet; start kavach-api once to pin it".into(),
                ));
            }
            admin
                .set_runtime_pointers(crate::admin::RuntimePointers {
                    model_sha256: Some(digest.into()),
                    updated_at: Utc::now(),
                    ..pointers
                })
                .await
                .map_err(store)?;
            admin
                .append_audit(audit(
                    "startup_model_baseline",
                    model_id,
                    serde_json::json!({ "model_path": path_str, "model_sha256": digest }),
                ))
                .await
                .map_err(store)?;
            return Ok(());
        }
        (true, Some(pinned)) => ModelStartupError::DigestMismatch {
            expected: pinned.into(),
            actual: digest.into(),
        },
        (false, _) => ModelStartupError::PathMismatch {
            startup: path_str.clone(),
            active: pointers.model_path.clone(),
        },
    };
    if role
        != (ModelStartupRole::Api {
            bootstrap_model: true,
        })
    {
        return Err(mismatch);
    }
    // Audited recovery: re-pin path and digest only.
    admin
        .set_runtime_pointers(crate::admin::RuntimePointers {
            model_path: path_str.clone(),
            model_sha256: Some(digest.into()),
            updated_at: Utc::now(),
            ..pointers.clone()
        })
        .await
        .map_err(store)?;
    admin
        .append_audit(audit(
            "startup_model_bootstrap_override",
            model_id,
            serde_json::json!({
                "reason": mismatch.to_string(),
                "model_path": path_str,
                "model_sha256": digest,
                "previous_model_path": pointers.model_path,
                "previous_model_sha256": pointers.model_sha256,
            }),
        ))
        .await
        .map_err(store)?;
    tracing::warn!("--bootstrap-model override: {mismatch}");
    Ok(())
}

/// The last approved `update_model` status and mode for `model_id`, if the
/// audit log has one.
async fn approved_history(
    admin: &AdminBackend,
    model_id: &str,
) -> Result<Option<(ModelStatus, GovernanceMode)>, ModelStartupError> {
    let Some(entry) = admin
        .last_audit("update_model", model_id)
        .await
        .map_err(store)?
    else {
        return Ok(None);
    };
    let field = |name: &str| {
        entry
            .payload
            .get(name)
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };
    Ok(field("status")
        .and_then(|s| parse_status(&s))
        .zip(field("governance_mode").and_then(|m| parse_mode(&m))))
}

async fn governed_state(
    admin: &AdminBackend,
    yaml: &ModelRecord,
    role: ModelStartupRole,
) -> Result<ModelState, ModelStartupError> {
    if let Some(state) = admin.get_model_state(&yaml.model_id).await.map_err(store)? {
        return Ok(state);
    }
    let ModelStartupRole::Api { bootstrap_model } = role else {
        return Err(ModelStartupError::NotGoverned(format!(
            "model {} has no governed state yet; start kavach-api once to record it",
            yaml.model_id
        )));
    };

    // An approved change that was never persisted (H3a) must not silently
    // revert to the YAML.
    let (status, mode, action) = match approved_history(admin, &yaml.model_id).await? {
        Some((status, mode)) if (status, mode) != (yaml.status, yaml.governance_mode) => {
            if !bootstrap_model {
                return Err(ModelStartupError::DivergentHistory {
                    model_id: yaml.model_id.clone(),
                    yaml: describe(yaml.status, yaml.governance_mode),
                    approved: describe(status, mode),
                });
            }
            (status, mode, "startup_model_state_restored")
        }
        _ => (
            yaml.status,
            yaml.governance_mode,
            "startup_model_state_baseline",
        ),
    };
    let state = ModelState {
        model_id: yaml.model_id.clone(),
        status,
        governance_mode: mode,
        updated_at: Utc::now(),
        updated_by: STARTUP_PRINCIPAL.into(),
        approved_by: STARTUP_PRINCIPAL.into(),
    };
    if admin
        .insert_model_state_if_absent(state)
        .await
        .map_err(store)?
    {
        admin
            .append_audit(audit(
                action,
                &yaml.model_id,
                serde_json::json!({
                    "status": status_str(status),
                    "governance_mode": mode_str(mode),
                }),
            ))
            .await
            .map_err(store)?;
    }
    // Re-read: a concurrent start may have inserted first.
    admin
        .get_model_state(&yaml.model_id)
        .await
        .map_err(store)?
        .ok_or_else(|| ModelStartupError::Store("model state vanished after insert".into()))
}
