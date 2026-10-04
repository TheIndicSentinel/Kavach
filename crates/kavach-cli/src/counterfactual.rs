//! Counterfactuals for `kavach authorize`: which single change would make a
//! blocked what-if call pass, under the current policies.
//!
//! Offline and CLI-only: the API never offers them, so an agent cannot use
//! them to probe the policy boundary. They are given only when every
//! reason is a business constraint (contact window, daily cap, channel,
//! waiver ceiling); a call blocked for a safety reason (a raw identifier,
//! the mandate, the subject, the agent, trusted time) gets none, so
//! nothing here is a bypass hint. One variable changes at a time, in a
//! fixed order, and the smallest change that passes is reported. Each
//! answer is a real re-run of the authorization core, not a guess.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, DurationRound, FixedOffset, Utc};
use kavach_api::dataplane::{TestClock, WhatIf};
use kavach_dataplane::tools::{ParamKind, ToolSpec};
use kavach_dataplane::ToolRequest;
use kavach_ports::agent_evidence::is_allow;
use kavach_ports::{SyncStatus, TimeSource, TrustedNow};
use serde::Serialize;
use serde_json::{Map, Value};

/// How every suggestion is labelled.
pub const LABEL: &str = "what-if under current policies";

/// Reasons that are business constraints: the only ones that get
/// counterfactuals.
pub const BUSINESS: [&str; 5] = [
    "contact-window",
    "contact-hours-floor",
    "contact-daily-cap",
    "channel-within-mandate",
    "waiver-ceiling",
];
/// Decision words that accompany policy ids.
const WORDS: [&str; 2] = ["forbidden", "escalated"];

/// Why counterfactuals are withheld, if they are.
#[must_use]
pub fn withheld(reasons: &[String]) -> Option<String> {
    if let Some(other) = reasons
        .iter()
        .find(|r| !BUSINESS.contains(&r.as_str()) && !WORDS.contains(&r.as_str()))
    {
        return Some(format!(
            "{other} is not a business constraint: no suggestions are given for it"
        ));
    }
    if !reasons.iter().any(|r| BUSINESS.contains(&r.as_str())) {
        return Some("no business constraint to vary".into());
    }
    None
}

/// A clock the time search moves.
pub struct Movable(Mutex<DateTime<Utc>>);

impl Movable {
    #[must_use]
    pub fn new(at: DateTime<Utc>) -> Arc<Self> {
        Arc::new(Self(Mutex::new(at)))
    }

    fn set(&self, at: DateTime<Utc>) {
        if let Ok(mut t) = self.0.lock() {
            *t = at;
        }
    }
}

impl TimeSource for Movable {
    fn now(&self) -> TrustedNow {
        TrustedNow {
            utc: self.0.lock().map_or_else(|_| Utc::now(), |t| *t),
            sync: SyncStatus::Synced { max_error_ms: 0 },
        }
    }
}

/// One change that makes the call pass.
#[derive(Debug, Clone, Serialize)]
pub struct Change {
    /// What changed: `at`, `contacts_today`, or a parameter name.
    #[serde(rename = "change")]
    pub what: String,
    pub value: String,
    pub decision: String,
}

/// The call being varied: one what-if world, its clock and its mandate.
pub struct Trial<'a> {
    pub what_if: &'a WhatIf,
    pub clock: &'a Movable,
    pub agent: &'a str,
    pub tool: &'a str,
    pub spec: &'a ToolSpec,
    pub mandate_id: &'a str,
    pub at: DateTime<Utc>,
    pub params: &'a Map<String, Value>,
}

impl Trial<'_> {
    async fn decision(&self, params: &Map<String, Value>) -> Option<String> {
        let decided = self
            .what_if
            .precheck(
                self.agent,
                self.tool,
                ToolRequest {
                    mandate_id: self.mandate_id.to_string(),
                    request_id: "what-if-cf".into(),
                    params: params.clone(),
                },
            )
            .await
            .ok()?;
        is_allow(decided.decision).then(|| {
            serde_json::to_value(decided.decision)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default()
        })
    }

    /// The earliest later time, in 15-minute steps within a day, that
    /// passes.
    async fn time(&self) -> Option<Change> {
        let step = Duration::minutes(15);
        let start = self.at.duration_trunc(step).ok()? + step;
        let mut found = None;
        for k in 0..96 {
            let t = start + step * k;
            self.clock.set(t);
            if let Some(decision) = self.decision(self.params).await {
                found = Some(Change {
                    what: "at".into(),
                    value: when(self.at, t),
                    decision,
                });
                break;
            }
        }
        self.clock.set(self.at);
        found
    }

    /// The first other allowed channel, in the registry's order.
    async fn channel(&self) -> Option<Change> {
        let spec = self.spec.params.get("channel")?;
        let current = self.params.get("channel").and_then(Value::as_str);
        for value in spec.values.iter().filter(|v| Some(v.as_str()) != current) {
            let mut params = self.params.clone();
            params.insert("channel".into(), Value::from(value.as_str()));
            if let Some(decision) = self.decision(&params).await {
                return Some(Change {
                    what: "channel".into(),
                    value: value.clone(),
                    decision,
                });
            }
        }
        None
    }

    /// The largest waiver below the one asked for that passes.
    async fn waiver(&self) -> Option<Change> {
        let spec = self.spec.params.get("waiver_bps")?;
        if spec.kind != ParamKind::Integer {
            return None;
        }
        let asked = self.params.get("waiver_bps").and_then(Value::as_i64)?;
        let (mut low, mut high) = (spec.min.unwrap_or(0), asked - 1);
        let mut best = None;
        while low <= high {
            let mid = low + (high - low) / 2;
            let mut params = self.params.clone();
            params.insert("waiver_bps".into(), Value::from(mid));
            if let Some(decision) = self.decision(&params).await {
                best = Some((mid, decision));
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }
        best.map(|(value, decision)| Change {
            what: "waiver_bps".into(),
            value: value.to_string(),
            decision,
        })
    }
}

/// `HH:MM IST`, with "tomorrow" when the day changes.
fn when(from: DateTime<Utc>, t: DateTime<Utc>) -> String {
    let Some(ist) = FixedOffset::east_opt(5 * 3600 + 1800) else {
        return t.to_rfc3339();
    };
    let (a, b) = (from.with_timezone(&ist), t.with_timezone(&ist));
    let day = if a.date_naive() == b.date_naive() {
        ""
    } else {
        " tomorrow"
    };
    format!("{} IST{day}", b.format("%H:%M"))
}

/// The single changes that pass, in a fixed order: time, contacts,
/// channel, waiver. `contacts` re-runs the call with fewer contacts made
/// today (it needs a fresh what-if world) and returns the decision.
pub async fn search<F, Fut>(
    trial: &Trial<'_>,
    reasons: &[String],
    contacts_today: u32,
    contacts: F,
) -> Vec<Change>
where
    F: Fn(u32) -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
{
    let has = |r: &str| reasons.iter().any(|x| x == r);
    let mut changes = Vec::new();
    if has("contact-window") || has("contact-hours-floor") {
        changes.extend(trial.time().await);
    }
    if has("contact-daily-cap") {
        // The most contacts already made today that still pass.
        for n in (0..contacts_today).rev() {
            if let Some(decision) = contacts(n).await {
                changes.push(Change {
                    what: "contacts_today".into(),
                    value: n.to_string(),
                    decision,
                });
                break;
            }
        }
    }
    if has("channel-within-mandate") {
        changes.extend(trial.channel().await);
    }
    if has("waiver-ceiling") {
        changes.extend(trial.waiver().await);
    }
    changes
}

/// A clock handle for `WhatIf::build`.
pub fn test_clock(clock: &Arc<Movable>) -> TestClock {
    TestClock(Arc::clone(clock) as Arc<dyn TimeSource + Send + Sync>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn only_business_blocks_get_suggestions() {
        let r = |items: &[&str]| items.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert!(withheld(&r(&["forbidden", "contact-window"])).is_none());
        assert!(withheld(&r(&["escalated", "waiver-ceiling"])).is_none());
        for safety in [
            "raw_identifier:subject_ref:phone",
            "subject-binding",
            "mandate_invalid",
            "trusted_time_unavailable",
            "no_matching_permit",
            "agent-restricted",
            "value_not_allowed:channel",
        ] {
            assert!(
                withheld(&r(&["forbidden", "contact-window", safety])).is_some(),
                "{safety}"
            );
        }
        assert!(withheld(&r(&["forbidden"])).is_some());
    }

    #[test]
    fn later_times_say_when_the_day_changes() {
        let at = Utc.with_ymd_and_hms(2026, 10, 1, 15, 0, 0).unwrap(); // 20:30 IST
        assert_eq!(when(at, at + Duration::hours(12)), "08:30 IST tomorrow");
        assert_eq!(when(at, at + Duration::minutes(15)), "20:45 IST");
    }
}
