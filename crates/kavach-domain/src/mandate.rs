//! Task Mandate domain types (ADR-004). No I/O.
//!
//! A mandate is the root of an agent's authority. It is derived from a signed
//! system-of-record event (facts: subject, record, consents, assigned agent)
//! plus a governed [`MandateTemplate`] (scope: purpose, actions, fields,
//! channels, window, ceilings, lifetime). Model output never contributes.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Mandate format version carried in every mandate (`mv`).
pub const MANDATE_FORMAT_VERSION: u32 = 1;

/// Prefix of capability references handed to agents instead of raw values.
pub const CAPABILITY_REF_PREFIX: &str = "ref:";

/// Where a mandate came from: the system-of-record event it was derived from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MandateSource {
    pub system: String,
    pub record_ref: String,
    pub event_id: String,
}

/// Business contact window, in minutes of the day in `tz`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactWindow {
    /// IANA time zone; only `Asia/Kolkata` is accepted in the MVP.
    pub tz: TimeZoneId,
    pub from_min: u16,
    pub to_min: u16,
    pub max_per_day: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeZoneId {
    #[serde(rename = "Asia/Kolkata")]
    AsiaKolkata,
}

impl ContactWindow {
    /// Intersection of two windows; `None` when they do not overlap.
    pub fn intersect(&self, other: &Self) -> Option<Self> {
        if self.tz != other.tz {
            return None;
        }
        let from_min = self.from_min.max(other.from_min);
        let to_min = self.to_min.min(other.to_min);
        (from_min < to_min).then_some(Self {
            tz: self.tz,
            from_min,
            to_min,
            max_per_day: self.max_per_day.min(other.max_per_day),
        })
    }

    pub fn is_within(&self, other: &Self) -> bool {
        self.tz == other.tz
            && self.from_min >= other.from_min
            && self.to_min <= other.to_min
            && self.max_per_day <= other.max_per_day
    }
}

/// Delegation rules of a mandate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationRules {
    pub max_depth: u8,
    /// Agents that may receive a child mandate.
    pub allowed_agents: BTreeSet<String>,
}

/// A signed, time-bound, subject-bound grant of authority (ADR-004 §1).
///
/// Sets and maps are ordered so the canonical (RFC 8785) encoding is stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mandate {
    pub mv: u32,
    pub id: String,
    pub tenant_id: String,
    pub issuer: String,
    pub source: MandateSource,
    pub principal: String,
    /// Agent holding this mandate.
    pub holder: String,
    pub subject_ref: String,
    pub purpose: String,
    pub consent_refs: BTreeSet<String>,
    pub actions: BTreeSet<String>,
    pub data_fields: BTreeSet<String>,
    pub channels: BTreeSet<String>,
    pub window: Option<ContactWindow>,
    /// Integer limits (e.g. `waiver_bps`); an action limited by a key that is
    /// absent here is not permitted.
    pub ceilings: BTreeMap<String, i64>,
    pub delegation: DelegationRules,
    pub parent_id: Option<String>,
    pub depth: u8,
    pub nbf: DateTime<Utc>,
    pub exp: DateTime<Utc>,
    pub nonce: String,
}

/// Lifecycle status, authoritative in the mandate store (ADR-004 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateStatus {
    Active,
    Revoked,
}

/// Why a mandate was revoked (ADR-004 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    Payment,
    Dispute,
    ConsentWithdrawn,
    AgentQuarantined,
    Manual,
    ParentRevoked,
}

/// A system-of-record event (facts only). Signed by a registered issuer key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SorEvent {
    pub event_id: String,
    pub tenant_id: String,
    /// Source system, e.g. `lms`.
    pub system: String,
    /// Event type, e.g. `loan.dpd30`; selects the mandate template.
    pub event_type: String,
    pub record_ref: String,
    pub subject_ref: String,
    pub principal: String,
    pub consent_refs: BTreeSet<String>,
    pub assigned_agent: String,
    pub occurred_at: DateTime<Utc>,
    pub nonce: String,
}

/// Governed scope for mandates created from one event type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MandateTemplate {
    pub tenant_id: String,
    pub event_type: String,
    pub purpose: String,
    pub actions: BTreeSet<String>,
    pub data_fields: BTreeSet<String>,
    pub channels: BTreeSet<String>,
    pub window: Option<ContactWindow>,
    pub ceilings: BTreeMap<String, i64>,
    pub ttl_seconds: i64,
    pub delegation: DelegationRules,
    pub eligible_agents: BTreeSet<String>,
}

/// Authorization attributes of an agent (ADR-003, Agent Passport). Identity
/// itself comes from the customer's identity provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPassport {
    pub agent_id: String,
    pub tenant_id: String,
    pub owner: String,
    pub allowed_purposes: BTreeSet<String>,
    pub actions: BTreeSet<String>,
    pub data_fields: BTreeSet<String>,
    pub ceilings: BTreeMap<String, i64>,
}

/// A consent the mandate relies on (fixture shaped as a subset of the ReBIT
/// consent artefact: purposes, validity, status).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRecord {
    pub consent_id: String,
    pub tenant_id: String,
    pub subject_ref: String,
    pub purposes: BTreeSet<String>,
    pub expires_at: DateTime<Utc>,
    pub active: bool,
}

/// Scope requested for a child mandate; the result is always intersected with
/// the parent and the sub-agent's passport.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationRequest {
    pub actions: BTreeSet<String>,
    pub data_fields: BTreeSet<String>,
    pub channels: BTreeSet<String>,
    pub window: Option<ContactWindow>,
    pub ceilings: BTreeMap<String, i64>,
    pub exp: Option<DateTime<Utc>>,
}

/// Returns true when `s` is a well-formed capability reference
/// (`ref:<type>:<opaque>`), with no wildcard characters.
pub fn is_capability_ref(s: &str) -> bool {
    let Some(rest) = s.strip_prefix(CAPABILITY_REF_PREFIX) else {
        return false;
    };
    let mut parts = rest.splitn(2, ':');
    let (Some(kind), Some(opaque)) = (parts.next(), parts.next()) else {
        return false;
    };
    let ok = |p: &str| {
        !p.is_empty()
            && p.len() <= 128
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    ok(kind) && ok(opaque)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_refs_are_strict() {
        assert!(is_capability_ref("ref:borrower:B-9382"));
        for bad in [
            "",
            "B-9382",
            "ref:borrower:",
            "ref::x",
            "ref:borrower:*",
            "ref:borrower:98 76",
            "ref:borrower",
        ] {
            assert!(!is_capability_ref(bad), "{bad}");
        }
    }

    #[test]
    fn window_intersection_narrows() {
        let a = ContactWindow {
            tz: TimeZoneId::AsiaKolkata,
            from_min: 8 * 60,
            to_min: 19 * 60,
            max_per_day: 3,
        };
        let b = ContactWindow {
            from_min: 10 * 60,
            to_min: 20 * 60,
            max_per_day: 5,
            ..a
        };
        let i = a.intersect(&b).expect("overlap");
        assert_eq!((i.from_min, i.to_min, i.max_per_day), (600, 1140, 3));
        assert!(i.is_within(&a) && i.is_within(&b));
        let late = ContactWindow {
            from_min: 20 * 60,
            to_min: 21 * 60,
            ..a
        };
        assert!(a.intersect(&late).is_none());
    }
}
