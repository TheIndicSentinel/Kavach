//! The relaxations a running API can be in: every way to run with a guarantee
//! off that `docs/BYPASS_INVENTORY.md` lists as a switch of this process.
//!
//! They are a fixed vocabulary because each name is a metric label and a
//! value in `/v1/runtime`. A relaxation that is on shows in the log at
//! startup (as before), in `/v1/runtime` (`insecure_dev`, `relaxations`), in
//! the metrics `kavach_insecure_dev` and `kavach_relaxation_active{relaxation}`
//! (every name is always present, 0 or 1), and in an alert rule, so a
//! production deployment that was started with one is noticed, not just
//! logged once.

use std::collections::BTreeSet;

use crate::config::{AccessControlKind, ApiConfig, EvidenceStoreKind};

/// One way of running with a guarantee relaxed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Relaxation {
    /// `--insecure-dev` itself, whatever else it switches.
    InsecureDev,
    /// `--access-control none`: every request is allowed.
    AccessControlNone,
    /// The self-asserted `X-Kavach-Principal` header is accepted.
    PrincipalHeader,
    /// A weaker Postgres `sslmode` than `verify-full`, asked for by the URL
    /// and allowed by a development mode.
    WeakerDatabaseTls,
    /// The decision-governance evidence (the credit track's evidence, incident
    /// and audit records) lives in memory and is lost on restart.
    MemoryEvidenceStore,
    /// Agent evidence, mandates and replay protection live in memory.
    MemoryAgentStores,
    /// A test clock for the agent decisions.
    TestClock,
    /// A development clock (`--clock`, `POST /v1/dev/clock`).
    DevClock,
    /// The system clock is declared synced for agent decisions.
    SystemClockDeclaredSynced,
    /// The agent tool registry is not signature-checked.
    UnsignedToolRegistry,
    /// A development key (`dev-…`) signs mandates, evidence, checkpoints or
    /// credentials, or is a system-of-record issuer.
    DevKeys,
    /// A test-double credential broker.
    TestDoubleBroker,
}

impl Relaxation {
    /// Every relaxation, in the order they are listed.
    pub const ALL: [Self; 12] = [
        Self::InsecureDev,
        Self::AccessControlNone,
        Self::PrincipalHeader,
        Self::WeakerDatabaseTls,
        Self::MemoryEvidenceStore,
        Self::MemoryAgentStores,
        Self::TestClock,
        Self::DevClock,
        Self::SystemClockDeclaredSynced,
        Self::UnsignedToolRegistry,
        Self::DevKeys,
        Self::TestDoubleBroker,
    ];

    /// The name, a metric label and a `/v1/runtime` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InsecureDev => "insecure_dev",
            Self::AccessControlNone => "access_control_none",
            Self::PrincipalHeader => "principal_header",
            Self::WeakerDatabaseTls => "weaker_database_tls",
            Self::MemoryEvidenceStore => "memory_evidence_store",
            Self::MemoryAgentStores => "memory_agent_stores",
            Self::TestClock => "test_clock",
            Self::DevClock => "dev_clock",
            Self::SystemClockDeclaredSynced => "system_clock_declared_synced",
            Self::UnsignedToolRegistry => "unsigned_tool_registry",
            Self::DevKeys => "dev_keys",
            Self::TestDoubleBroker => "test_double_broker",
        }
    }
}

/// What `config` alone puts in a relaxed state. The agent surfaces add what
/// only they know (a development key among the mandate or issuer keys, a
/// test-double broker) in [`crate::dataplane::Dataplane::relaxations`].
#[must_use]
pub fn of_config(config: &ApiConfig) -> BTreeSet<Relaxation> {
    let mut on = BTreeSet::new();
    if config.insecure_dev {
        on.insert(Relaxation::InsecureDev);
        on.insert(Relaxation::PrincipalHeader);
    }
    if matches!(config.access_control, AccessControlKind::None) {
        on.insert(Relaxation::AccessControlNone);
    }
    if matches!(config.evidence_store, EvidenceStoreKind::Memory) {
        on.insert(Relaxation::MemoryEvidenceStore);
    }
    let urls = [
        match &config.evidence_store {
            EvidenceStoreKind::Postgres { database_url } => Some(database_url.as_str()),
            EvidenceStoreKind::Memory => None,
        },
        config.migration_database_url.as_deref(),
    ];
    if urls
        .into_iter()
        .flatten()
        .any(|url| kavach_storage::is_weakened(url, &config.database_tls))
    {
        on.insert(Relaxation::WeakerDatabaseTls);
    }
    if let Some(dp) = &config.dataplane {
        if matches!(config.evidence_store, EvidenceStoreKind::Memory) {
            on.insert(Relaxation::MemoryAgentStores);
        }
        if dp.test_clock.is_some() {
            on.insert(Relaxation::TestClock);
        }
        if dp.dev_clock.is_some() {
            on.insert(Relaxation::DevClock);
        } else if dp.test_clock.is_none() && config.insecure_dev {
            on.insert(Relaxation::SystemClockDeclaredSynced);
        }
        if config.insecure_dev && dp.tool_signers.is_none() && config.pack_signers.is_none() {
            on.insert(Relaxation::UnsignedToolRegistry);
        }
        if [
            &dp.evidence_key_id,
            &dp.checkpoint_key_id,
            &dp.credential_key_id,
        ]
        .into_iter()
        .any(|kid| kavach_ports::agent_evidence::is_dev_key(kid))
        {
            on.insert(Relaxation::DevKeys);
        }
    }
    on
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_names_are_unique_and_plain() {
        let names: BTreeSet<&str> = Relaxation::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(names.len(), Relaxation::ALL.len());
        for name in names {
            assert!(
                name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{name}"
            );
        }
    }
}
