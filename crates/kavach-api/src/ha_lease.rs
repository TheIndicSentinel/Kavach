//! Active/passive API lease lifecycle (approved HA fencing plan).

use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};

use axum::http::Request;
use axum::{
    extract::State,
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Duration;
use kavach_storage::PostgresActiveLeaseStore;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use tokio::{task::JoinHandle, time};
use zeroize::Zeroizing;

pub const RENEW_INTERVAL: time::Duration = time::Duration::from_secs(3);
pub const LEASE_TTL: Duration = Duration::seconds(10);

const DISABLED: u8 = 0;
const STANDBY: u8 = 1;
const ACTIVE: u8 = 2;
const FENCED: u8 = 3;

/// Shared process lease state consulted by HTTP readiness and request gates.
#[derive(Clone)]
pub struct HaFence(Arc<AtomicU8>);

impl Default for HaFence {
    fn default() -> Self {
        Self(Arc::new(AtomicU8::new(DISABLED)))
    }
}

impl HaFence {
    #[must_use]
    pub fn standby() -> Self {
        Self(Arc::new(AtomicU8::new(STANDBY)))
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self.0.load(Ordering::Acquire), DISABLED | ACTIVE)
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.0.load(Ordering::Acquire) != DISABLED
    }

    #[must_use]
    pub fn status(&self) -> &'static str {
        match self.0.load(Ordering::Acquire) {
            DISABLED | ACTIVE => "active",
            STANDBY => "standby",
            _ => "fenced",
        }
    }

    fn set(&self, status: u8) {
        self.0.store(status, Ordering::Release);
    }
}

/// Blocks every operator, agent, and system-of-record route while this
/// process is standby or has permanently fenced itself. Liveness/readiness
/// remain reachable for orchestration.
pub async fn http_gate(
    State(state): State<Arc<crate::state::AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if matches!(request.uri().path(), "/health" | "/ready") || state.ha_fence().is_active() {
        next.run(request).await
    } else {
        let response = crate::error::ApiError::Unavailable(format!(
            "API process is {} and cannot serve application requests",
            state.ha_fence().status()
        ))
        .into_response();
        crate::correlation::unmatched(request, response).await
    }
}

/// Starts as active when it can claim the lease, or as a warm standby when a
/// current holder exists. A standby may claim after expiry. Once an active
/// loses renewal, it becomes permanently fenced for this process run.
pub async fn start(
    store: PostgresActiveLeaseStore,
    tenant_id: String,
    stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(HaFence, JoinHandle<()>), ring::error::Unspecified> {
    let rng = SystemRandom::new();
    let mut raw_token = Zeroizing::new([0_u8; 32]);
    rng.fill(raw_token.as_mut())?;
    let token_hash: [u8; 32] = Sha256::digest(raw_token.as_ref()).into();
    let holder_id = uuid::Uuid::new_v4().to_string();
    let fence = HaFence(Arc::new(AtomicU8::new(STANDBY)));
    store.enable_write_fencing().await;
    let epoch = match store
        .claim(&tenant_id, &holder_id, &token_hash, LEASE_TTL)
        .await
    {
        Ok(Some(lease)) => {
            store
                .bind_write_identity(&tenant_id, &holder_id, lease.epoch, &token_hash)
                .await;
            fence.set(ACTIVE);
            tracing::info!(epoch = lease.epoch, "active API lease acquired");
            Some(lease.epoch)
        }
        Ok(None) => {
            tracing::info!("API is standby; waiting for active lease expiry");
            None
        }
        Err(error) => {
            tracing::warn!(error = %error, "API lease unavailable; starting not-ready standby");
            None
        }
    };
    let task_fence = fence.clone();
    let task = tokio::spawn(async move {
        let _raw_token = raw_token;
        let mut epoch = epoch;
        let mut stop = stop;
        let mut interval = time::interval(RENEW_INTERVAL);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        return;
                    }
                }
            }
            if task_fence.0.load(Ordering::Acquire) == FENCED {
                return;
            }
            if let Some(current_epoch) = epoch {
                match store
                    .renew(
                        &tenant_id,
                        &holder_id,
                        current_epoch,
                        &token_hash,
                        LEASE_TTL,
                    )
                    .await
                {
                    Ok(true) => continue,
                    Ok(false) => tracing::error!(
                        epoch = current_epoch,
                        "active API lease was lost; process is fenced until restart"
                    ),
                    Err(error) => tracing::error!(
                        epoch = current_epoch,
                        error = %error,
                        "active API lease renewal failed; process is fenced until restart"
                    ),
                }
                store.clear_write_identity().await;
                task_fence.set(FENCED);
                continue;
            }
            match store
                .claim(&tenant_id, &holder_id, &token_hash, LEASE_TTL)
                .await
            {
                Ok(Some(lease)) => {
                    store
                        .bind_write_identity(&tenant_id, &holder_id, lease.epoch, &token_hash)
                        .await;
                    epoch = Some(lease.epoch);
                    task_fence.set(ACTIVE);
                    tracing::info!(epoch = lease.epoch, "standby promoted to active API");
                }
                Ok(None) => {}
                Err(error) => tracing::debug!(error = %error, "standby lease claim unavailable"),
            }
        }
    });
    Ok((fence, task))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_and_active_are_serving_states() {
        let fence = HaFence::default();
        assert!(!fence.is_enabled());
        assert!(fence.is_active());
        fence.set(ACTIVE);
        assert!(fence.is_enabled());
        assert!(fence.is_active());
        fence.set(STANDBY);
        assert!(!fence.is_active());
        fence.set(FENCED);
        assert!(!fence.is_active());
    }
}
