use std::collections::BTreeMap;

use kavach_domain::mandate::{AgentPassport, MandateTemplate};
use kavach_ports::PublicKey;

use crate::jws::KeySet;

/// Governed configuration of the mandate service.
#[derive(Debug, Clone)]
pub struct MandateConfig {
    /// Identifier of this Kavach instance (`Mandate::issuer`).
    pub issuer_id: String,
    /// Key id Kavach signs mandates with (held by the `KeyProvider`).
    pub signing_kid: String,
    /// Public keys that verify Kavach-issued mandates.
    pub mandate_keys: KeySet,
    /// System-of-record issuer keys, each bound to one source system.
    pub sor_issuers: Vec<SorIssuer>,
    pub templates: Vec<MandateTemplate>,
    pub passports: Vec<AgentPassport>,
    /// Maximum age (and future skew) of a system-of-record event.
    pub event_freshness_seconds: i64,
    /// How long event ids are remembered for replay protection.
    pub replay_window_seconds: i64,
}

/// A registered system-of-record signing key. An event is accepted only if
/// it is signed by a key registered for the event's `system`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorIssuer {
    pub system: String,
    pub key: PublicKey,
}

impl MandateConfig {
    pub fn sor_keys(&self) -> KeySet {
        KeySet::new(self.sor_issuers.iter().map(|i| i.key.clone()))
    }

    pub fn sor_system_for_kid(&self, kid: &str) -> Option<&str> {
        self.sor_issuers
            .iter()
            .find(|i| i.key.kid == kid)
            .map(|i| i.system.as_str())
    }

    pub fn template(&self, tenant_id: &str, event_type: &str) -> Option<&MandateTemplate> {
        self.templates
            .iter()
            .find(|t| t.tenant_id == tenant_id && t.event_type == event_type)
    }

    pub fn passport(&self, tenant_id: &str, agent_id: &str) -> Option<&AgentPassport> {
        self.passports
            .iter()
            .find(|p| p.tenant_id == tenant_id && p.agent_id == agent_id)
    }

    /// Ceilings the template grants that the passport does not allow.
    pub fn ceilings_exceeding(
        template: &BTreeMap<String, i64>,
        passport: &BTreeMap<String, i64>,
    ) -> Vec<String> {
        template
            .iter()
            .filter(|(k, v)| passport.get(*k).is_none_or(|cap| *v > cap))
            .map(|(k, _)| k.clone())
            .collect()
    }
}
