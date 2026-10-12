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
    /// Agents the child may delegate to in turn (intersected with the
    /// parent's). Empty — the default — means the child cannot delegate.
    #[serde(default)]
    pub allowed_agents: BTreeSet<String>,
}

/// Regulatory floor for contacting a borrower, in IST minutes of day:
/// 08:00 (inclusive) to 19:00 (exclusive). Mandates may only narrow it.
///
/// Source: RBI directions on recovery agents (contact between 08:00 and
/// 19:00); pending compliance sign-off — treat as guidance (ADR-011).
/// The shipped Cedar policy repeats these values; a test keeps them equal.
pub const CONTACT_FLOOR_FROM_MIN: u16 = 8 * 60;
pub const CONTACT_FLOOR_TO_MIN: u16 = 19 * 60;

/// Actions that contact the subject (window, floor, channel and daily cap
/// apply).
pub const CONTACT_ACTIONS: [&str; 2] = ["send_reminder", "place_call"];

/// Channels a mandate may name.
pub const ALLOWED_CHANNELS: [&str; 3] = ["sms", "voice", "whatsapp"];

/// Longest chain of delegation (a root has depth 0).
pub const MAX_DELEGATION_DEPTH: u8 = 4;

/// Longest mandate lifetime a template may ask for (30 days).
pub const MAX_MANDATE_TTL_SECONDS: i64 = 30 * 24 * 3600;

/// Basis points: ceilings and waivers are within `0..=MAX_BPS`.
pub const MAX_BPS: i64 = 10_000;

impl ContactWindow {
    /// True when the window is well formed and inside the contact floor.
    #[must_use]
    pub fn within_floor(&self) -> bool {
        self.from_min < self.to_min
            && self.from_min >= CONTACT_FLOOR_FROM_MIN
            && self.to_min <= CONTACT_FLOOR_TO_MIN
            && self.max_per_day > 0
    }
}

impl Mandate {
    /// The form rules every mandate Kavach issues satisfies
    /// (`docs/specs/mandate-and-sor-event.md` section 3). Checked again when
    /// a token is verified, so a token that breaks them is refused even
    /// though its signature is genuine. `Err` names the rule.
    pub fn check_form(&self) -> Result<(), String> {
        if self.mv != MANDATE_FORMAT_VERSION {
            return Err(format!("unknown mandate version {}", self.mv));
        }
        if !is_capability_ref(&self.subject_ref) {
            return Err("subject_ref is not a capability reference".into());
        }
        if self.depth > MAX_DELEGATION_DEPTH || self.delegation.max_depth > MAX_DELEGATION_DEPTH {
            return Err("delegation depth is above the limit".into());
        }
        if (self.depth == 0) != self.parent_id.is_none() {
            return Err("depth and parent_id disagree".into());
        }
        if let Some(c) = self
            .channels
            .iter()
            .find(|c| !ALLOWED_CHANNELS.contains(&c.as_str()))
        {
            return Err(format!("unknown channel {c:?}"));
        }
        match self.window {
            Some(w) if !w.within_floor() => {
                return Err("contact window is outside the 08:00-19:00 IST floor".into());
            }
            None if self
                .actions
                .iter()
                .any(|a| CONTACT_ACTIONS.contains(&a.as_str())) =>
            {
                return Err("contact actions without a contact window".into());
            }
            _ => {}
        }
        for (key, value) in &self.ceilings {
            let max = if key.ends_with("_bps") {
                MAX_BPS
            } else {
                i64::MAX
            };
            if !(0..=max).contains(value) {
                return Err(format!("ceiling {key} is out of range"));
            }
        }
        let life = (self.exp - self.nbf).num_seconds();
        if !(1..=MAX_MANDATE_TTL_SECONDS).contains(&life) {
            return Err("lifetime is not within 1 second to 30 days".into());
        }
        Ok(())
    }
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

    fn sample() -> Mandate {
        let at = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
        Mandate {
            mv: MANDATE_FORMAT_VERSION,
            id: "m".into(),
            tenant_id: "t".into(),
            issuer: "i".into(),
            source: MandateSource {
                system: "lms".into(),
                record_ref: "r".into(),
                event_id: "e".into(),
            },
            principal: "p".into(),
            holder: "h".into(),
            subject_ref: "ref:borrower:B-1".into(),
            purpose: "loan_recovery".into(),
            consent_refs: BTreeSet::new(),
            actions: BTreeSet::from(["send_reminder".to_string()]),
            data_fields: BTreeSet::new(),
            channels: BTreeSet::from(["sms".to_string()]),
            window: Some(ContactWindow {
                tz: TimeZoneId::AsiaKolkata,
                from_min: 9 * 60,
                to_min: 18 * 60,
                max_per_day: 2,
            }),
            ceilings: BTreeMap::from([("waiver_bps".to_string(), 500)]),
            delegation: DelegationRules {
                max_depth: 1,
                allowed_agents: BTreeSet::new(),
            },
            parent_id: None,
            depth: 0,
            nbf: at,
            exp: at + chrono::Duration::days(1),
            nonce: "n".into(),
        }
    }

    #[test]
    fn form_rules_refuse_what_an_issuer_never_writes() {
        assert_eq!(sample().check_form(), Ok(()));
        let broken: Vec<(&str, Mandate)> = vec![
            ("version", Mandate { mv: 2, ..sample() }),
            (
                "raw subject",
                Mandate {
                    subject_ref: "9876543210".into(),
                    ..sample()
                },
            ),
            (
                "depth",
                Mandate {
                    depth: 5,
                    parent_id: Some("p".into()),
                    ..sample()
                },
            ),
            (
                "orphan",
                Mandate {
                    depth: 1,
                    ..sample()
                },
            ),
            (
                "channel",
                Mandate {
                    channels: BTreeSet::from(["fax".to_string()]),
                    ..sample()
                },
            ),
            (
                "no window",
                Mandate {
                    window: None,
                    ..sample()
                },
            ),
            (
                "night",
                Mandate {
                    window: Some(ContactWindow {
                        from_min: 60,
                        ..sample().window.unwrap()
                    }),
                    ..sample()
                },
            ),
            (
                "bps",
                Mandate {
                    ceilings: BTreeMap::from([("waiver_bps".to_string(), 10_001)]),
                    ..sample()
                },
            ),
            (
                "negative",
                Mandate {
                    ceilings: BTreeMap::from([("cap".to_string(), -1)]),
                    ..sample()
                },
            ),
            (
                "backwards",
                Mandate {
                    exp: sample().nbf,
                    ..sample()
                },
            ),
            (
                "too long",
                Mandate {
                    exp: sample().nbf + chrono::Duration::days(31),
                    ..sample()
                },
            ),
        ];
        for (what, mandate) in broken {
            assert!(mandate.check_form().is_err(), "{what} was accepted");
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
