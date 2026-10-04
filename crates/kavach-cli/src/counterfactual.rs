//! Counterfactuals for `kavach authorize`: which single change would make a
//! blocked what-if call pass, under the current policies.
//!
//! Offline and CLI-only: the API never offers them, so an agent cannot use
//! them to probe the policy boundary. They are given only when every
//! reason is a business constraint (contact window, daily cap, channel,
//! waiver ceiling), and only when exactly one of those fails; a call
//! blocked for a safety reason (a raw identifier, the mandate, the subject,
//! the agent, trusted time) gets none, so nothing here is a bypass hint.
//!
//! Candidates come from the policy itself (the mandate's window, cap,
//! channels and ceiling), not from a search, and each is confirmed by one
//! real re-run of the authorization core. Suggestions state the bound
//! ("`waiver_bps` ≤ 1000", "contacts < 3"), not an example value, and say
//! what the user can do ("after the daily cap resets").

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, FixedOffset, NaiveTime, TimeZone, Utc};
use kavach_api::dataplane::{TestClock, WhatIf};
use kavach_dataplane::tools::ToolSpec;
use kavach_dataplane::ToolRequest;
use kavach_domain::mandate::{Mandate, CONTACT_FLOOR_FROM_MIN};
use kavach_ports::agent_evidence::is_allow;
use kavach_ports::{SyncStatus, TimeSource, TrustedNow};
use serde::Serialize;
use serde_json::{Map, Value};

/// How every suggestion is labelled.
pub const LABEL: &str = "what-if under current policies";

/// The business constraints, by the group a single change addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Group {
    Time,
    Cap,
    Channel,
    Waiver,
}

impl Group {
    fn of(reason: &str) -> Option<Self> {
        match reason {
            "contact-window" | "contact-hours-floor" => Some(Self::Time),
            "contact-daily-cap" => Some(Self::Cap),
            "channel-within-mandate" => Some(Self::Channel),
            "waiver-ceiling" => Some(Self::Waiver),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Time => "contact window",
            Self::Cap => "daily cap",
            Self::Channel => "channel",
            Self::Waiver => "waiver ceiling",
        }
    }
}

/// Decision words that accompany policy ids.
const WORDS: [&str; 2] = ["forbidden", "escalated"];

/// Why counterfactuals are withheld, if they are.
#[must_use]
pub fn withheld(reasons: &[String]) -> Option<String> {
    if let Some(other) = reasons
        .iter()
        .find(|r| Group::of(r).is_none() && !WORDS.contains(&r.as_str()))
    {
        return Some(format!(
            "{other} is not a business constraint: no suggestions are given for it"
        ));
    }
    let groups = groups(reasons);
    match groups.len() {
        0 => Some("no business constraint to vary".into()),
        1 => None,
        _ => Some(format!(
            "more than one business constraint fails ({}): no single change passes",
            groups
                .iter()
                .map(|g| g.name())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn groups(reasons: &[String]) -> BTreeSet<Group> {
    reasons.iter().filter_map(|r| Group::of(r)).collect()
}

/// A clock the counterfactuals move.
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

/// A clock handle for `WhatIf::build`.
pub fn test_clock(clock: &Arc<Movable>) -> TestClock {
    TestClock(Arc::clone(clock) as Arc<dyn TimeSource + Send + Sync>)
}

/// One change that makes the call pass.
#[derive(Debug, Clone, Serialize)]
pub struct Change {
    /// What to do, in words.
    pub suggestion: String,
    /// The limit that applies.
    pub bound: String,
    /// The decision the confirming re-run gave.
    pub decision: String,
}

/// The call being varied: one what-if world, its clock, its mandate.
pub struct Trial<'a> {
    pub what_if: &'a WhatIf,
    pub clock: &'a Movable,
    pub agent: &'a str,
    pub tool: &'a str,
    pub spec: &'a ToolSpec,
    pub mandate_id: &'a str,
    pub mandate: &'a Mandate,
    pub at: DateTime<Utc>,
    pub params: &'a Map<String, Value>,
}

fn ist() -> FixedOffset {
    FixedOffset::east_opt(5 * 3600 + 1800).expect("IST")
}

/// The next time at `minute` of an IST day, strictly after `after`.
fn next_at(after: DateTime<Utc>, minute: u16) -> DateTime<Utc> {
    let local = after.with_timezone(&ist());
    let time = NaiveTime::from_hms_opt(u32::from(minute / 60), u32::from(minute % 60), 0)
        .unwrap_or(NaiveTime::MIN);
    let mut day = local.date_naive();
    loop {
        if let Some(t) = ist().from_local_datetime(&day.and_time(time)).single() {
            let t = t.with_timezone(&Utc);
            if t > after {
                return t;
            }
        }
        day += Duration::days(1);
    }
}

/// `HH:MM IST`, with "tomorrow" when the day changes.
fn when(from: DateTime<Utc>, t: DateTime<Utc>) -> String {
    let (a, b) = (from.with_timezone(&ist()), t.with_timezone(&ist()));
    let day = if a.date_naive() == b.date_naive() {
        ""
    } else {
        " tomorrow"
    };
    format!("{} IST{day}", b.format("%H:%M"))
}

fn hhmm(minute: u16) -> String {
    format!("{:02}:{:02}", minute / 60, minute % 60)
}

impl Trial<'_> {
    /// The decision word if a re-run with `params` passes.
    async fn passes(&self, params: &Map<String, Value>) -> Option<String> {
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
        is_allow(decided.decision).then(|| word(decided.decision))
    }

    /// When the contact window next opens (the later of the mandate's
    /// window start and the 08:00 IST floor), and the window's bound.
    fn window(&self) -> (u16, String) {
        let (from, to) = self
            .mandate
            .window
            .map_or((CONTACT_FLOOR_FROM_MIN, 19 * 60), |w| {
                (
                    w.from_min.max(CONTACT_FLOOR_FROM_MIN),
                    w.to_min.min(19 * 60),
                )
            });
        (
            from,
            format!("contact window {}–{} IST", hhmm(from), hhmm(to)),
        )
    }

    async fn time(&self) -> Option<Change> {
        let (from, bound) = self.window();
        let t = next_at(self.at, from);
        self.clock.set(t);
        let decision = self.passes(self.params).await;
        self.clock.set(self.at);
        decision.map(|decision| Change {
            suggestion: format!("at {}", when(self.at, t)),
            bound,
            decision,
        })
    }

    /// The channels both the registry and the mandate allow, confirmed.
    async fn channel(&self) -> Option<Change> {
        let registry = self.spec.params.get("channel")?;
        let mut passing = Vec::new();
        for value in registry
            .values
            .iter()
            .filter(|v| self.mandate.channels.contains(*v))
        {
            let mut params = self.params.clone();
            params.insert("channel".into(), Value::from(value.as_str()));
            if let Some(decision) = self.passes(&params).await {
                passing.push((value.clone(), decision));
            }
        }
        let decision = passing.first()?.1.clone();
        let set = passing
            .iter()
            .map(|(v, _)| v.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        Some(Change {
            suggestion: format!("channel ∈ {{{set}}}"),
            bound: format!("channels the mandate allows: {{{set}}}"),
            decision,
        })
    }

    /// The mandate's waiver ceiling, confirmed at the ceiling.
    async fn waiver(&self) -> Option<Change> {
        let ceiling = *self.mandate.ceilings.get("waiver_bps")?;
        let max = self
            .spec
            .params
            .get("waiver_bps")
            .and_then(|p| p.max)
            .unwrap_or(i64::MAX);
        let bound = ceiling.min(max);
        let mut params = self.params.clone();
        params.insert("waiver_bps".into(), Value::from(bound));
        let decision = self.passes(&params).await?;
        Some(Change {
            suggestion: format!("waiver_bps ≤ {bound}"),
            bound: format!("the mandate's waiver ceiling: {bound} basis points"),
            decision,
        })
    }

    /// When the cap resets: the next IST day's window start, with no
    /// contacts made yet (`reset` re-runs the call in that fresh day).
    async fn cap<F, Fut>(&self, reset: F) -> Option<Change>
    where
        F: FnOnce(DateTime<Utc>) -> Fut,
        Fut: std::future::Future<Output = Option<String>>,
    {
        let (from, _) = self.window();
        let midnight = next_at(self.at, 0);
        let t = next_at(midnight - Duration::seconds(1), from);
        let decision = reset(t).await?;
        let cap = self.mandate.window.map_or(0, |w| w.max_per_day);
        Some(Change {
            suggestion: format!("after the daily cap resets ({})", when(self.at, t)),
            bound: format!("contacts < {cap} per IST day"),
            decision,
        })
    }
}

fn word(decision: kavach_domain::Decision) -> String {
    serde_json::to_value(decision)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// The one change that passes, for a call blocked by exactly one business
/// constraint (`withheld` must have returned `None`). `reset` re-runs the
/// call at a given time in a fresh day with no contacts made.
pub async fn search<F, Fut>(trial: &Trial<'_>, reasons: &[String], reset: F) -> Vec<Change>
where
    F: FnOnce(DateTime<Utc>) -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
{
    let change = match groups(reasons).into_iter().next() {
        Some(Group::Time) => trial.time().await,
        Some(Group::Cap) => trial.cap(reset).await,
        Some(Group::Channel) => trial.channel().await,
        Some(Group::Waiver) => trial.waiver().await,
        None => None,
    };
    change.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(items: &[&str]) -> Vec<String> {
        items.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn only_single_business_blocks_get_suggestions() {
        assert!(withheld(&r(&["forbidden", "contact-window"])).is_none());
        assert!(withheld(&r(&["forbidden", "contact-hours-floor", "contact-window"])).is_none());
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
        let both = withheld(&r(&["forbidden", "contact-window", "contact-daily-cap"])).unwrap();
        assert!(both.contains("no single change passes"), "{both}");
    }

    #[test]
    fn the_window_opens_next_at_its_start() {
        let at = Utc.with_ymd_and_hms(2026, 10, 1, 15, 0, 0).unwrap(); // 20:30 IST
        let t = next_at(at, 8 * 60);
        assert_eq!(t, Utc.with_ymd_and_hms(2026, 10, 2, 2, 30, 0).unwrap());
        assert_eq!(when(at, t), "08:00 IST tomorrow");
        let early = Utc.with_ymd_and_hms(2026, 10, 1, 1, 40, 0).unwrap(); // 07:10 IST
        assert_eq!(when(early, next_at(early, 8 * 60)), "08:00 IST");
    }
}
