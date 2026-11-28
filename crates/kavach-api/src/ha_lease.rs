//! Active/passive API lease lifecycle (approved HA fencing plan).

use std::sync::{
    atomic::{AtomicU64, AtomicU8, Ordering},
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
const MONOTONIC_LEASE_TTL: time::Duration = time::Duration::from_secs(10);

const DISABLED: u8 = 0;
const STANDBY: u8 = 1;
const ACTIVE: u8 = 2;
const FENCED: u8 = 3;

struct FenceState {
    status: AtomicU8,
    /// Process-local monotonic origin; the deadline is stored relative to it.
    origin: std::time::Instant,
    /// Nanoseconds after `origin` at which an ACTIVE lease stops being
    /// trusted unless a renewal moved it forward (REL-04).
    deadline_nanos: AtomicU64,
}

/// Shared process lease state consulted by HTTP readiness and request gates.
///
/// ACTIVE is honoured only until the monotonic deadline of the last claim
/// or renewal, so a lease task that dies (panic, abort) fences its process
/// on its own within the lease TTL.
#[derive(Clone)]
pub struct HaFence(Arc<FenceState>);

impl Default for HaFence {
    fn default() -> Self {
        Self::with_status(DISABLED)
    }
}

impl HaFence {
    fn with_status(status: u8) -> Self {
        Self(Arc::new(FenceState {
            status: AtomicU8::new(status),
            origin: std::time::Instant::now(),
            deadline_nanos: AtomicU64::new(0),
        }))
    }

    #[must_use]
    pub fn standby() -> Self {
        Self::with_status(STANDBY)
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        match self.raw_status() {
            DISABLED => true,
            ACTIVE => self.within_deadline(),
            _ => false,
        }
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.raw_status() != DISABLED
    }

    #[must_use]
    pub fn status(&self) -> &'static str {
        match self.raw_status() {
            DISABLED => "active",
            ACTIVE if self.within_deadline() => "active",
            STANDBY => "standby",
            _ => "fenced",
        }
    }

    /// Fences this process for the rest of its run. An enabled fence only:
    /// a process without HA has nothing to fence.
    pub fn fence(&self) {
        if self.is_enabled() {
            self.set(FENCED);
        }
    }

    fn raw_status(&self) -> u8 {
        self.0.status.load(Ordering::Acquire)
    }

    fn set(&self, status: u8) {
        self.0.status.store(status, Ordering::Release);
    }

    /// Becomes ACTIVE until `deadline`. The deadline is written first so a
    /// reader never sees ACTIVE with a stale bound.
    fn activate(&self, deadline: time::Instant) {
        self.extend(deadline);
        self.set(ACTIVE);
    }

    fn extend(&self, deadline: time::Instant) {
        let nanos = deadline
            .into_std()
            .saturating_duration_since(self.0.origin)
            .as_nanos();
        self.0
            .deadline_nanos
            .store(u64::try_from(nanos).unwrap_or(u64::MAX), Ordering::Release);
    }

    fn within_deadline(&self) -> bool {
        let now = u64::try_from(self.0.origin.elapsed().as_nanos()).unwrap_or(u64::MAX);
        now < self.0.deadline_nanos.load(Ordering::Acquire)
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

/// The random write token and holder id of one process run.
struct LeaseIdentity {
    /// Held for the process run and zeroed on drop.
    _raw_token: Zeroizing<[u8; 32]>,
    token_hash: [u8; 32],
    holder_id: String,
}

impl LeaseIdentity {
    fn new() -> Result<Self, ring::error::Unspecified> {
        let mut raw_token = Zeroizing::new([0_u8; 32]);
        SystemRandom::new().fill(raw_token.as_mut())?;
        let token_hash: [u8; 32] = Sha256::digest(raw_token.as_ref()).into();
        Ok(Self {
            _raw_token: raw_token,
            token_hash,
            holder_id: uuid::Uuid::new_v4().to_string(),
        })
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
    let identity = LeaseIdentity::new()?;
    let fence = HaFence::standby();
    store.enable_write_fencing().await;
    let lease = initial_claim(&store, &tenant_id, &identity, &fence).await;
    let task = tokio::spawn(maintain(
        store,
        tenant_id,
        identity,
        fence.clone(),
        lease,
        stop,
    ));
    Ok((fence, task))
}

/// The first claim, bounded by the retry interval. Returns the epoch and the
/// local deadline of a lease this process now holds.
async fn initial_claim(
    store: &PostgresActiveLeaseStore,
    tenant_id: &str,
    identity: &LeaseIdentity,
    fence: &HaFence,
) -> Option<(i64, time::Instant)> {
    let initial_lease_deadline = time::Instant::now() + MONOTONIC_LEASE_TTL;
    match time::timeout(
        RENEW_INTERVAL,
        store.claim(
            tenant_id,
            &identity.holder_id,
            &identity.token_hash,
            LEASE_TTL,
        ),
    )
    .await
    {
        Ok(Ok(Some(lease))) if time::Instant::now() < initial_lease_deadline => {
            store
                .bind_write_identity(
                    tenant_id,
                    &identity.holder_id,
                    lease.epoch,
                    &identity.token_hash,
                )
                .await;
            fence.activate(initial_lease_deadline);
            tracing::info!(epoch = lease.epoch, "active API lease acquired");
            Some((lease.epoch, initial_lease_deadline))
        }
        Ok(Ok(Some(lease))) => {
            tracing::warn!(
                epoch = lease.epoch,
                "active API lease expired before local claim confirmation; remaining standby"
            );
            None
        }
        Ok(Ok(None)) => {
            tracing::info!("API is standby; waiting for active lease expiry");
            None
        }
        Ok(Err(error)) => {
            tracing::warn!(error = %error, "API lease unavailable; starting not-ready standby");
            None
        }
        Err(_) => {
            tracing::warn!(
                "API lease claim exceeded the standby retry interval; starting not-ready standby"
            );
            None
        }
    }
}

/// Renews an active lease, or keeps trying to claim one as a standby, until
/// told to stop or fenced.
async fn maintain(
    store: PostgresActiveLeaseStore,
    tenant_id: String,
    identity: LeaseIdentity,
    fence: HaFence,
    mut lease: Option<(i64, time::Instant)>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = time::interval(RENEW_INTERVAL);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
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
        if fence.raw_status() == FENCED {
            return;
        }
        if let Some((epoch, deadline)) = lease {
            if let Some(next) = renew(&store, &tenant_id, &identity, epoch, deadline).await {
                fence.extend(next);
                lease = Some((epoch, next));
                continue;
            }
            store.clear_write_identity().await;
            fence.set(FENCED);
            continue;
        }
        lease = claim(&store, &tenant_id, &identity).await;
        if let Some((_, deadline)) = lease {
            fence.activate(deadline);
        }
    }
}

/// One renewal, bounded by the current local deadline. Returns the next
/// deadline, or `None` when the lease is lost and the process must fence.
async fn renew(
    store: &PostgresActiveLeaseStore,
    tenant_id: &str,
    identity: &LeaseIdentity,
    epoch: i64,
    deadline: time::Instant,
) -> Option<time::Instant> {
    let renewal_started = time::Instant::now();
    match time::timeout_at(
        deadline,
        store.renew(
            tenant_id,
            &identity.holder_id,
            epoch,
            &identity.token_hash,
            LEASE_TTL,
        ),
    )
    .await
    {
        // Start the local bound before the request so network and pool delay
        // can only make this fence conservative.
        Ok(Ok(true)) => return Some(renewal_started + MONOTONIC_LEASE_TTL),
        Ok(Ok(false)) => tracing::error!(
            epoch,
            "active API lease was lost; process is fenced until restart"
        ),
        Ok(Err(error)) => tracing::error!(
            epoch,
            error = %error,
            "active API lease renewal failed; process is fenced until restart"
        ),
        Err(_) => tracing::error!(
            epoch,
            "active API lease renewal did not finish before its local lease deadline; process is fenced until restart"
        ),
    }
    None
}

/// One standby claim attempt. Returns the epoch and local deadline of a
/// lease this process now holds.
async fn claim(
    store: &PostgresActiveLeaseStore,
    tenant_id: &str,
    identity: &LeaseIdentity,
) -> Option<(i64, time::Instant)> {
    let claim_deadline = time::Instant::now() + MONOTONIC_LEASE_TTL;
    match time::timeout(
        RENEW_INTERVAL,
        store.claim(
            tenant_id,
            &identity.holder_id,
            &identity.token_hash,
            LEASE_TTL,
        ),
    )
    .await
    {
        Ok(Ok(Some(lease))) => {
            if time::Instant::now() >= claim_deadline {
                tracing::warn!(
                    epoch = lease.epoch,
                    "standby lease expired before local claim confirmation; retrying"
                );
                return None;
            }
            store
                .bind_write_identity(
                    tenant_id,
                    &identity.holder_id,
                    lease.epoch,
                    &identity.token_hash,
                )
                .await;
            tracing::info!(epoch = lease.epoch, "standby promoted to active API");
            Some((lease.epoch, claim_deadline))
        }
        Ok(Ok(None)) => None,
        Ok(Err(error)) => {
            tracing::debug!(error = %error, "standby lease claim unavailable");
            None
        }
        Err(_) => {
            tracing::debug!("standby lease claim exceeded retry interval");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_and_active_are_serving_states() {
        let fence = HaFence::default();
        assert!(!fence.is_enabled());
        assert!(fence.is_active());
        fence.activate(time::Instant::now() + MONOTONIC_LEASE_TTL);
        assert!(fence.is_enabled());
        assert!(fence.is_active());
        fence.set(STANDBY);
        assert!(!fence.is_active());
        fence.set(FENCED);
        assert!(!fence.is_active());
    }

    #[test]
    fn an_active_fence_expires_at_its_deadline_without_a_renewal() {
        let fence = HaFence::standby();
        fence.activate(time::Instant::now() + time::Duration::from_millis(50));
        assert!(fence.is_active());
        assert_eq!(fence.status(), "active");
        std::thread::sleep(std::time::Duration::from_millis(80));
        assert!(!fence.is_active(), "an expired lease must not serve");
        assert_eq!(fence.status(), "fenced");
        fence.extend(time::Instant::now() + MONOTONIC_LEASE_TTL);
        assert!(fence.is_active(), "a renewal moves the deadline forward");
    }

    #[test]
    fn fencing_a_disabled_fence_changes_nothing() {
        let fence = HaFence::default();
        fence.fence();
        assert!(fence.is_active());
        let enabled = HaFence::standby();
        enabled.activate(time::Instant::now() + MONOTONIC_LEASE_TTL);
        enabled.fence();
        assert!(!enabled.is_active());
        assert_eq!(enabled.status(), "fenced");
    }
}
