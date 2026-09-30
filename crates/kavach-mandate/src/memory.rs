//! In-memory adapters for the M1 runtime and tests (Postgres in M2).

use std::collections::HashMap;
use std::future::{ready, Future};
use std::sync::Mutex;

use kavach_domain::mandate::{ConsentRecord, MandateStatus, RevocationReason};
use kavach_ports::{ConsentSource, DomainEvent, EventBus, MandateStore, PortError, StoredMandate};

type Key = (String, String);

fn poisoned() -> PortError {
    PortError::unavailable("in-memory store lock poisoned")
}

#[derive(Debug, Default)]
pub struct InMemoryMandateStore {
    records: Mutex<HashMap<Key, StoredMandate>>,
}

impl InMemoryMandateStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert_sync(&self, record: StoredMandate) -> Result<(), PortError> {
        let key = (record.mandate.tenant_id.clone(), record.mandate.id.clone());
        let mut records = self.records.lock().map_err(|_| poisoned())?;
        if records.contains_key(&key) {
            return Err(PortError::rejected(format!("mandate {} exists", key.1)));
        }
        records.insert(key, record);
        Ok(())
    }

    fn revoke_sync(
        &self,
        tenant_id: &str,
        id: &str,
        reason: RevocationReason,
    ) -> Result<bool, PortError> {
        let mut records = self.records.lock().map_err(|_| poisoned())?;
        let record = records
            .get_mut(&(tenant_id.to_string(), id.to_string()))
            .ok_or_else(|| PortError::rejected(format!("unknown mandate {id}")))?;
        if record.status == MandateStatus::Revoked {
            return Ok(false);
        }
        record.status = MandateStatus::Revoked;
        record.revoked_reason = Some(reason);
        Ok(true)
    }
}

impl MandateStore for InMemoryMandateStore {
    fn insert(&self, record: StoredMandate) -> impl Future<Output = Result<(), PortError>> + Send {
        ready(self.insert_sync(record))
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

    fn revoke(
        &self,
        tenant_id: &str,
        id: &str,
        reason: RevocationReason,
    ) -> impl Future<Output = Result<bool, PortError>> + Send {
        ready(self.revoke_sync(tenant_id, id, reason))
    }

    fn children(
        &self,
        tenant_id: &str,
        parent_id: &str,
    ) -> impl Future<Output = Result<Vec<String>, PortError>> + Send {
        ready(self.records.lock().map_err(|_| poisoned()).map(|r| {
            let mut ids: Vec<String> = r
                .values()
                .filter(|s| {
                    s.mandate.tenant_id == tenant_id
                        && s.mandate.parent_id.as_deref() == Some(parent_id)
                })
                .map(|s| s.mandate.id.clone())
                .collect();
            ids.sort();
            ids
        }))
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
