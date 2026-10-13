//! Every change of an agent's state gets its evidence-chain record
//! (ADR-013 §4).
//!
//! A tightening changes the state first and records second, so stopping an
//! agent never waits on the evidence chain. This pass closes that gap: it
//! pages through the stored changes in time order and writes any record that
//! is missing, idempotently by `(agent, change number)`. A background task
//! runs it, like the revocation reconciler.

use chrono::{DateTime, Utc};
use kavach_ports::agent_evidence::AgentEvidenceStore;
use kavach_ports::agent_state::{AgentChangeCursor, AgentStateStore};

use crate::authorize::{AuthorizeCore, MandateVerifier};
use crate::revocation_evidence::ReconcileConfig;

/// What one pass found and did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateReconcileReport {
    /// Changes old enough to be checked.
    pub checked: usize,
    /// Changes (`agent#number`) whose missing record this pass wrote.
    pub reconciled: Vec<String>,
    /// Changes still without their record after this pass, with why.
    pub missing: Vec<(String, String)>,
    /// Where the next pass starts: everything at or before it has its
    /// record. It never moves past a change still missing one.
    pub watermark: Option<DateTime<Utc>>,
    /// The history or the evidence could not be read: the pass stopped.
    pub error: Option<String>,
}

/// One reconcile pass at `now`, from `watermark` (`None`: from the start).
pub async fn reconcile_agent_states<V, S>(
    core: &AuthorizeCore<V, S>,
    watermark: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    config: ReconcileConfig,
) -> StateReconcileReport
where
    V: MandateVerifier,
    S: AgentEvidenceStore + AgentStateStore,
{
    let mut report = StateReconcileReport {
        watermark,
        ..StateReconcileReport::default()
    };
    let settled = now - config.grace;
    let mut cursor = watermark.map(|w| AgentChangeCursor {
        changed_at: w - config.overlap,
        tenant_id: String::new(),
        agent_id: String::new(),
        change_no: 0,
    });
    let mut blocked = false;
    loop {
        let page = match core
            .store()
            .changes_after(cursor.clone(), config.page)
            .await
        {
            Ok(page) => page,
            Err(err) => {
                report.error = Some(format!("agent state changes: {}", err.message));
                return report;
            }
        };
        let full = u32::try_from(page.len()).unwrap_or(u32::MAX) >= config.page;
        for change in &page {
            if change.changed_at > settled {
                return report;
            }
            report.checked += 1;
            let id = format!("{}#{}", change.agent_id, change.change_no);
            let stored = core
                .store()
                .agent_state_record(&change.tenant_id, &change.agent_id, change.change_no)
                .await;
            let recorded = match stored {
                Ok(Some(_)) => true,
                Ok(None) => match core.record_agent_change(change).await {
                    Ok(_) => {
                        report.reconciled.push(id);
                        true
                    }
                    Err(err) => {
                        report.missing.push((id, err.message));
                        false
                    }
                },
                Err(err) => {
                    report.error = Some(format!("evidence: {}", err.message));
                    return report;
                }
            };
            if recorded {
                if !blocked {
                    report.watermark = Some(
                        report
                            .watermark
                            .map_or(change.changed_at, |w| w.max(change.changed_at)),
                    );
                }
            } else {
                blocked = true;
            }
        }
        match page.last() {
            Some(last) if full => cursor = Some(last.cursor()),
            _ => return report,
        }
    }
}
