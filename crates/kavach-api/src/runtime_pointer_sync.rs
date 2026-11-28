//! Bounded background convergence of the shared governed runtime pointer.

use std::sync::Arc;
use std::time::Duration;

use crate::state::AppState;

const SYNC_INTERVAL: Duration = Duration::from_secs(1);

/// Checks and applies a newer committed runtime pointer once per second,
/// until the API's shared shutdown signal is raised.
pub fn start(
    state: Arc<AppState>,
    stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    start_with_interval(state, stop, SYNC_INTERVAL)
}

fn start_with_interval(
    state: Arc<AppState>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    cadence: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(cadence);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut unavailable = false;
        loop {
            tokio::select! {
                _ = interval.tick() => match state.ensure_runtime_pointer_current().await {
                    Ok(()) if unavailable => {
                        tracing::info!("runtime pointer synchronization recovered");
                        unavailable = false;
                    }
                    Err(error) if !unavailable => {
                        tracing::warn!(%error, "runtime pointer synchronization failed; governed evaluations remain unavailable");
                        unavailable = true;
                    }
                    Ok(()) | Err(_) => {}
                },
                result = stop.changed() => {
                    if result.is_err() || *stop.borrow() {
                        return;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use kavach_storage::RuntimePointers;

    #[tokio::test]
    async fn watcher_converges_without_waiting_for_an_evaluation() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let state = Arc::new(
            AppState::from_paths_for_tests(
                &root.join("packs/finance/v0.yaml"),
                &root.join("models/finance/credit-underwriting-v1.yaml"),
                None,
            )
            .await
            .expect("state"),
        );
        let runtime = state.runtime().expect("runtime");
        state
            .admin()
            .set_runtime_pointers(RuntimePointers {
                pack_path: runtime.pack_path.clone(),
                model_path: runtime.model_path.clone(),
                previous_pack_path: None,
                pack_sha256: runtime.pack_sha256.clone(),
                previous_pack_sha256: None,
                model_sha256: runtime.model_sha256.clone(),
                updated_at: Utc::now(),
                updated_by: "test-proposer".into(),
                approved_by: "test-approver".into(),
                version: 0,
            })
            .await
            .expect("advance stored pointer");

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let task = start_with_interval(Arc::clone(&state), stop_rx, Duration::from_millis(1));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if state.runtime().expect("runtime").pointer_version == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("background watcher converged");

        stop_tx.send(true).expect("signal shutdown");
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("watcher stopped")
            .expect("watcher joined");
    }
}
