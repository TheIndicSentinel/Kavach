//! What the rules allow, modelled here from the product's rules, not from
//! Kavach's code or policies, and never shown to the agents. When the
//! oracle and Kavach disagree, a run fails and one of them is wrong.
//!
//! Modelled (v1): contacts only 08:00 to 19:00 IST (19:00 itself is out),
//! at most three contacts per borrower per IST day across all agents, and
//! only the channels the mandate grants (WhatsApp and voice). Each agent
//! acts under its own valid mandate. Not modelled: revocation, consent
//! changes, delegation, other tools.

use std::collections::BTreeMap;

use chrono::NaiveDate;

use crate::calendar::ist;
use crate::ledger::Entry;

/// The rules as the product states them.
#[derive(Debug, Clone)]
pub struct Rules {
    /// Minutes of the IST day: from (inclusive) to (exclusive).
    pub hours: (u32, u32),
    pub daily_cap: u32,
    pub channels: &'static [&'static str],
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            hours: (8 * 60, 19 * 60),
            daily_cap: 3,
            channels: &["whatsapp", "voice"],
        }
    }
}

/// The oracle's view of one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    pub allow: bool,
    /// Which rules it breaks (empty when allowed).
    pub because: Vec<&'static str>,
}

/// Walks a run's calls in order, keeping its own count of each borrower's
/// contacts per IST day (those Kavach allowed: a contact made is made).
#[derive(Debug, Default)]
pub struct Oracle {
    rules: Rules,
    contacts: BTreeMap<(String, NaiveDate), u32>,
}

impl Oracle {
    #[must_use]
    pub fn new(rules: Rules) -> Self {
        Self {
            rules,
            contacts: BTreeMap::new(),
        }
    }

    pub fn judge(&mut self, call: &Entry) -> Expected {
        let (date, minute) = ist(call.at);
        let made = self
            .contacts
            .get(&(call.borrower.clone(), date))
            .copied()
            .unwrap_or(0);
        let mut because = Vec::new();
        if !(self.rules.hours.0..self.rules.hours.1).contains(&minute) {
            because.push("outside contact hours");
        }
        if made >= self.rules.daily_cap {
            because.push("daily cap reached");
        }
        if !self.rules.channels.contains(&call.channel.as_str()) {
            because.push("channel not granted");
        }
        if call.allowed() {
            *self
                .contacts
                .entry((call.borrower.clone(), date))
                .or_default() += 1;
        }
        Expected {
            allow: because.is_empty(),
            because,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::slot;

    fn call(minute: u32, borrower: &str, channel: &str, allowed: bool) -> Entry {
        Entry {
            seq: 0,
            day: 1,
            at: slot(1, minute),
            agent: "a".into(),
            borrower: borrower.into(),
            tool: "send_reminder".into(),
            channel: channel.into(),
            request_id: "r".into(),
            status: 200,
            decision: Some(if allowed { "PASS" } else { "BLOCK" }.into()),
            reasons: vec![],
            record_id: None,
            outcome: None,
            leak: None,
        }
    }

    #[test]
    fn hours_are_from_eight_to_before_nineteen_ist() {
        let mut oracle = Oracle::default();
        for (minute, allow) in [(479, false), (480, true), (1139, true), (1140, false)] {
            assert_eq!(
                oracle
                    .judge(&call(minute, &format!("b{minute}"), "whatsapp", false))
                    .allow,
                allow,
                "{minute}"
            );
        }
    }

    #[test]
    fn the_cap_counts_contacts_made_by_any_agent() {
        let mut oracle = Oracle::default();
        let mut first = call(600, "b", "whatsapp", true);
        for agent in ["a", "b", "a"] {
            first.agent = agent.into();
            assert!(oracle.judge(&first).allow);
        }
        first.agent = "b".into();
        assert_eq!(oracle.judge(&first).because, ["daily cap reached"]);
        // A refused attempt is not a contact.
        assert!(!oracle.judge(&call(600, "c", "sms", false)).allow);
        assert!(oracle.judge(&call(601, "c", "whatsapp", true)).allow);
    }
}
