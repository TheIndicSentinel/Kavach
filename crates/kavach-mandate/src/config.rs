use std::collections::BTreeMap;

use std::collections::BTreeSet;

use kavach_domain::mandate::{
    AgentPassport, MandateTemplate, ALLOWED_CHANNELS, MAX_BPS, MAX_DELEGATION_DEPTH,
    MAX_MANDATE_TTL_SECONDS,
};
use kavach_ports::{PortError, PublicKey};

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

    /// Rejects configuration that would let a mandate exceed its bounds
    /// (ADR-011): duplicates, lifetimes, windows outside the contact floor,
    /// contact actions without a window, unknown channels, out-of-range
    /// ceilings, delegation depth, and scopes beyond agents' passports.
    pub fn validate(&self) -> Result<(), PortError> {
        let invalid = |msg: String| Err(PortError::invalid(msg));
        let mut seen = BTreeSet::new();
        for p in &self.passports {
            if !seen.insert((&p.tenant_id, &p.agent_id)) {
                return invalid(format!("duplicate passport for {}", p.agent_id));
            }
            check_ceilings(&format!("passport {}", p.agent_id), &p.ceilings)?;
        }
        let mut seen = BTreeSet::new();
        for t in &self.templates {
            let name = format!("template {}", t.event_type);
            if !seen.insert((&t.tenant_id, &t.event_type)) {
                return invalid(format!("duplicate {name}"));
            }
            if !(1..=MAX_MANDATE_TTL_SECONDS).contains(&t.ttl_seconds) {
                return invalid(format!(
                    "{name}: ttl_seconds must be 1..={MAX_MANDATE_TTL_SECONDS}"
                ));
            }
            if let Some(unknown) = t
                .channels
                .iter()
                .find(|c| !ALLOWED_CHANNELS.contains(&c.as_str()))
            {
                return invalid(format!("{name}: unknown channel {unknown:?}"));
            }
            let contacts = crate::service::requires_window(&t.actions);
            match t.window {
                Some(w) if !w.within_floor() => {
                    return invalid(format!(
                        "{name}: contact window must fit the 08:00-19:00 IST floor with max_per_day > 0"
                    ));
                }
                None if contacts => {
                    return invalid(format!("{name}: contact actions need a contact window"));
                }
                _ => {}
            }
            if contacts && t.channels.is_empty() {
                return invalid(format!("{name}: contact actions need at least one channel"));
            }
            check_ceilings(&name, &t.ceilings)?;
            if t.delegation.max_depth > MAX_DELEGATION_DEPTH {
                return invalid(format!(
                    "{name}: delegation max_depth must be at most {MAX_DELEGATION_DEPTH}"
                ));
            }
            for agent in t.delegation.allowed_agents.iter().chain(&t.eligible_agents) {
                let passport = self.passport(&t.tenant_id, agent).ok_or_else(|| {
                    PortError::invalid(format!("{name}: agent {agent} has no passport"))
                })?;
                if t.eligible_agents.contains(agent) {
                    crate::service::check_scope_within_passport(t, passport)
                        .map_err(|e| PortError::invalid(format!("{name}: {}", e.message)))?;
                }
            }
        }
        Ok(())
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

/// Ceilings are non-negative; basis-point ceilings are at most `MAX_BPS`.
fn check_ceilings(owner: &str, ceilings: &BTreeMap<String, i64>) -> Result<(), PortError> {
    for (key, value) in ceilings {
        let max = if key.ends_with("_bps") {
            MAX_BPS
        } else {
            i64::MAX
        };
        if !(0..=max).contains(value) {
            return Err(PortError::invalid(format!(
                "{owner}: ceiling {key} = {value} is out of range"
            )));
        }
    }
    Ok(())
}
