//! In-memory adapters for the M1 runtime and tests (Postgres in M2).

use std::collections::HashMap;
use std::future::{ready, Future};
use std::sync::Mutex;

use kavach_domain::mandate::{ConsentRecord, MandateStatus, RevocationReason};
use kavach_ports::{
    ConsentSource, DomainEvent, EventBus, MandateStore, PortError, StoredMandate, StoredRevocation,
};

type Key = (String, String);

fn poisoned() -> PortError {
    PortError::unavailable("in-memory store lock poisoned")
}

#[derive(Debug, Default)]
pub struct InMemoryMandateStore {
    records: Mutex<HashMap<Key, StoredMandate>>,
    /// Revocations by (tenant, system, event id).
    revocations: Mutex<HashMap<(String, String, String), StoredRevocation>>,
}

impl InMemoryMandateStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Overwrites or removes a record **without** the store's checks, so tests
    /// can simulate a store that violates the invariant (tampered, revoked or
    /// missing ancestor). Never used by the service.
    pub fn overwrite_unchecked(&self, tenant_id: &str, id: &str, record: Option<StoredMandate>) {
        let mut records = self.records.lock().expect("lock");
        let key = (tenant_id.to_string(), id.to_string());
        match record {
            Some(record) => records.insert(key, record),
            None => records.remove(&key),
        };
    }

    fn insert_sync(&self, record: StoredMandate, child: bool) -> Result<(), PortError> {
        let tenant = record.mandate.tenant_id.clone();
        let key = (tenant.clone(), record.mandate.id.clone());
        let mut records = self.records.lock().map_err(|_| poisoned())?;
        if records.contains_key(&key) {
            return Err(PortError::rejected(format!("mandate {} exists", key.1)));
        }
        match (child, record.mandate.parent_id.as_deref()) {
            (false, None) => {}
            (false, Some(_)) => {
                return Err(PortError::rejected(
                    "a delegated mandate needs insert_child",
                ));
            }
            (true, None) => return Err(PortError::rejected("insert_child needs a parent")),
            (true, Some(parent)) => {
                let active = records
                    .get(&(tenant, parent.to_string()))
                    .is_some_and(|p| p.status == MandateStatus::Active);
                if !active {
                    return Err(PortError::rejected(format!(
                        "parent mandate {parent} is not active"
                    )));
                }
            }
        }
        records.insert(key, record);
        Ok(())
    }

    fn ancestors_sync(
        &self,
        tenant_id: &str,
        id: &str,
        limit: usize,
    ) -> Result<Vec<StoredMandate>, PortError> {
        let records = self.records.lock().map_err(|_| poisoned())?;
        let get = |id: &str| records.get(&(tenant_id.to_string(), id.to_string()));
        let mut chain = Vec::new();
        let mut current = get(id);
        while let Some(parent_id) = current.and_then(|r| r.mandate.parent_id.as_deref()) {
            if chain.len() >= limit {
                break;
            }
            let Some(parent) = get(parent_id) else { break };
            chain.push(parent.clone());
            current = Some(parent);
        }
        Ok(chain)
    }

    fn revoke_tree_sync(
        &self,
        tenant_id: &str,
        id: &str,
        reason: RevocationReason,
    ) -> Result<Vec<(String, RevocationReason)>, PortError> {
        let mut records = self.records.lock().map_err(|_| poisoned())?;
        if !records.contains_key(&(tenant_id.to_string(), id.to_string())) {
            return Err(PortError::rejected(format!("unknown mandate {id}")));
        }
        let mut changed = Vec::new();
        let mut pending = vec![(id.to_string(), reason)];
        while let Some((current, why)) = pending.pop() {
            let children: Vec<String> = records
                .values()
                .filter(|s| {
                    s.mandate.tenant_id == tenant_id
                        && s.mandate.parent_id.as_deref() == Some(current.as_str())
                })
                .map(|s| s.mandate.id.clone())
                .collect();
            if let Some(record) = records.get_mut(&(tenant_id.to_string(), current.clone())) {
                if record.status != MandateStatus::Revoked {
                    record.status = MandateStatus::Revoked;
                    record.revoked_reason = Some(why);
                    changed.push((current.clone(), why));
                }
            }
            pending.extend(
                children
                    .into_iter()
                    .map(|child| (child, RevocationReason::ParentRevoked)),
            );
        }
        Ok(changed)
    }
}

impl MandateStore for InMemoryMandateStore {
    fn insert(&self, record: StoredMandate) -> impl Future<Output = Result<(), PortError>> + Send {
        ready(self.insert_sync(record, false))
    }

    fn insert_child(
        &self,
        record: StoredMandate,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        ready(self.insert_sync(record, true))
    }

    fn get(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> impl Future<Output = Result<Option<StoredMandate>, PortError>> + Send {
        ready(
            self.records
                .lock()
                .map_err(|_| poisoned())
                .map(|r| r.get(&(tenant_id.to_string(), id.to_string())).cloned()),
        )
    }

    fn root_for_event(
        &self,
        tenant_id: &str,
        system: &str,
        event_id: &str,
    ) -> impl Future<Output = Result<Option<StoredMandate>, PortError>> + Send {
        ready(self.records.lock().map_err(|_| poisoned()).map(|r| {
            r.values()
                .find(|s| {
                    s.mandate.tenant_id == tenant_id
                        && s.mandate.parent_id.is_none()
                        && s.mandate.source.system == system
                        && s.mandate.source.event_id == event_id
                })
                .cloned()
        }))
    }

    fn ancestors(
        &self,
        tenant_id: &str,
        id: &str,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<StoredMandate>, PortError>> + Send {
        ready(self.ancestors_sync(tenant_id, id, limit))
    }

    fn revoke_tree(
        &self,
        tenant_id: &str,
        id: &str,
        reason: RevocationReason,
    ) -> impl Future<Output = Result<Vec<(String, RevocationReason)>, PortError>> + Send {
        ready(self.revoke_tree_sync(tenant_id, id, reason))
    }

    fn live_roots_for_record(
        &self,
        tenant_id: &str,
        system: &str,
        record_ref: &str,
    ) -> impl Future<Output = Result<Vec<StoredMandate>, PortError>> + Send {
        let result = self.records.lock().map_err(|_| poisoned()).map(|records| {
            let mut roots: Vec<StoredMandate> = records
                .values()
                .filter(|s| {
                    s.mandate.tenant_id == tenant_id
                        && s.mandate.parent_id.is_none()
                        && s.status == MandateStatus::Active
                        && s.mandate.source.system == system
                        && s.mandate.source.record_ref == record_ref
                })
                .cloned()
                .collect();
            roots.sort_by_key(|s| s.mandate.nbf);
            roots
        });
        ready(result)
    }

    fn record_revocation(
        &self,
        revocation: StoredRevocation,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        let result = self
            .revocations
            .lock()
            .map_err(|_| poisoned())
            .and_then(|mut all| {
                let key = (
                    revocation.tenant_id.clone(),
                    revocation.system.clone(),
                    revocation.event_id.clone(),
                );
                if all.contains_key(&key) {
                    return Err(PortError::rejected(format!(
                        "revocation event {} was recorded already",
                        key.2
                    )));
                }
                all.insert(key, revocation);
                Ok(())
            });
        ready(result)
    }

    fn revocation_for_event(
        &self,
        tenant_id: &str,
        system: &str,
        event_id: &str,
    ) -> impl Future<Output = Result<Option<StoredRevocation>, PortError>> + Send {
        let key = (
            tenant_id.to_string(),
            system.to_string(),
            event_id.to_string(),
        );
        ready(
            self.revocations
                .lock()
                .map_err(|_| poisoned())
                .map(|all| all.get(&key).cloned()),
        )
    }
}

/// Records published events (tests and single-process use).
#[derive(Debug, Default)]
pub struct InMemoryEventBus {
    events: Mutex<Vec<DomainEvent>>,
}

impl InMemoryEventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<DomainEvent> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }
}

impl EventBus for InMemoryEventBus {
    fn publish(&self, event: DomainEvent) -> impl Future<Output = Result<(), PortError>> + Send {
        ready(
            self.events
                .lock()
                .map_err(|_| poisoned())
                .map(|mut e| e.push(event)),
        )
    }
}

/// Consent fixture (ReBIT-shaped subset; PRD D7).
#[derive(Debug, Default)]
pub struct InMemoryConsentSource {
    records: HashMap<Key, ConsentRecord>,
}

impl InMemoryConsentSource {
    pub fn new(records: impl IntoIterator<Item = ConsentRecord>) -> Self {
        Self {
            records: records
                .into_iter()
                .map(|c| ((c.tenant_id.clone(), c.consent_id.clone()), c))
                .collect(),
        }
    }
}

impl ConsentSource for InMemoryConsentSource {
    fn get(
        &self,
        tenant_id: &str,
        consent_id: &str,
    ) -> impl Future<Output = Result<Option<ConsentRecord>, PortError>> + Send {
        ready(Ok(self
            .records
            .get(&(tenant_id.to_string(), consent_id.to_string()))
            .cloned()))
    }
}
