//! What the rules allow, modelled here from the product's rules, not from
//! Kavach's code or policies, and never shown to the agents. When the
//! oracle and Kavach disagree, a run fails and one of them is wrong. It
//! judges a call only by what was sent.
//!
//! Modelled (v1):
//! - the tool registry: `send_reminder` only, with exactly `subject_ref`,
//!   `channel` (WhatsApp or SMS) and `template_id` (`emi_reminder_v1`);
//! - a subject is a plain reference: at most eight digits in total and
//!   nothing PAN-shaped (ADR-004 §7);
//! - the mandate was issued, and for that subject;
//! - contacts only 08:00 to 19:00 IST (19:00 itself is out);
//! - at most three contacts per borrower per IST day across all agents
//!   (contacts Kavach allowed; a retry is not a new contact);
//! - only the channels the mandate grants (WhatsApp and voice);
//! - a retry (same request id) is never sent again: after a final outcome
//!   (delivered, refused, failed) it gets the stored reply (`replayed`);
//!   after an unknown one, 409 `in_flight` (the forward-once contract);
//! - the provider's outcome follows the borrower's destination, by the
//!   agreed status contract (ADR-007): 2xx delivered, 4xx refused, a 5xx
//!   or a lost response unknown (a 5xx does not prove it was not sent).
//!
//! Not modelled: revocation, consent changes, delegation, other tools.

use std::collections::BTreeMap;

use chrono::NaiveDate;

use crate::calendar::ist;
use crate::ledger::Entry;
use crate::world::Delivery;

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
    /// The provider's outcome, for an allowed first send.
    pub outcome: Option<&'static str>,
    /// A retry: how it must be answered, without a second send.
    pub retry: Option<Retry>,
}

/// The answer to a call sent again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// The stored reply (`replayed`), with the first call's decision.
    Stored { allowed: bool },
    /// 409 `in_flight`: the first call has no final outcome.
    InFlight,
}

/// The first call of a request id, as Kavach answered it.
#[derive(Debug, Clone, Copy)]
struct First {
    allowed: bool,
    unknown: bool,
}

/// A plain reference: `ref:`, at most eight digits, nothing PAN-shaped.
fn plain_reference(subject: &str) -> bool {
    let digits = subject.bytes().filter(u8::is_ascii_digit).count();
    let pan = subject.as_bytes().windows(10).any(|w| {
        w[..5].iter().all(u8::is_ascii_uppercase)
            && w[5..9].iter().all(u8::is_ascii_digit)
            && w[9].is_ascii_uppercase()
    });
    subject.starts_with("ref:") && digits <= 8 && !pan
}

/// What the registry accepts for `send_reminder`.
fn registered(call: &Entry) -> bool {
    let Some(params) = call.params.as_object() else {
        return false;
    };
    let mut keys: Vec<&str> = params.keys().map(String::as_str).collect();
    keys.sort_unstable();
    call.tool == "send_reminder"
        && keys == ["channel", "subject_ref", "template_id"]
        && params.values().all(serde_json::Value::is_string)
        && matches!(params["channel"].as_str(), Some("whatsapp" | "sms"))
        && params["template_id"] == "emi_reminder_v1"
}

/// Walks a run's calls in order, keeping its own count of each borrower's
/// contacts per IST day (those Kavach allowed: a contact made is made).
#[derive(Debug, Default)]
pub struct Oracle {
    rules: Rules,
    deliveries: BTreeMap<String, Delivery>,
    contacts: BTreeMap<(String, NaiveDate), u32>,
    /// How Kavach answered each first send, for its retries.
    firsts: BTreeMap<u32, First>,
}

impl Oracle {
    #[must_use]
    pub fn new(rules: Rules, deliveries: BTreeMap<String, Delivery>) -> Self {
        Self {
            rules,
            deliveries,
            ..Self::default()
        }
    }

    pub fn judge(&mut self, call: &Entry) -> Expected {
        if let Some(first) = call.retry_of {
            let first = self.firsts.get(&first).copied().unwrap_or(First {
                allowed: false,
                unknown: false,
            });
            let retry = if first.allowed && first.unknown {
                Retry::InFlight
            } else {
                Retry::Stored {
                    allowed: first.allowed,
                }
            };
            return Expected {
                allow: matches!(retry, Retry::Stored { allowed: true }),
                because: Vec::new(),
                outcome: None,
                retry: Some(retry),
            };
        }
        self.firsts.insert(
            call.seq,
            First {
                allowed: call.allowed(),
                unknown: call.outcome.as_deref() == Some("unknown"),
            },
        );
        let subject = call.params["subject_ref"].as_str().unwrap_or_default();
        let (date, minute) = ist(call.at);
        let made = self
            .contacts
            .get(&(subject.to_string(), date))
            .copied()
            .unwrap_or(0);
        let mut because = Vec::new();
        if !registered(call) {
            because.push("not what the registry accepts");
        }
        if !plain_reference(subject) {
            because.push("not a plain reference");
        }
        if call.mandate_for.is_none() {
            because.push("no such mandate");
        } else if call.mandate_for.as_deref() != Some(subject) {
            because.push("another borrower than the mandate's");
        }
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
                .entry((subject.to_string(), date))
                .or_default() += 1;
        }
        let allow = because.is_empty();
        let outcome = allow.then(|| match self.deliveries.get(subject) {
            Some(Delivery::Refuses) => "refused",
            Some(Delivery::Errs | Delivery::Loses) => "unknown",
            _ => "delivered",
        });
        Expected {
            allow,
            because,
            outcome,
            retry: None,
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
            params: serde_json::json!({ "subject_ref": borrower, "channel": channel,
                "template_id": "emi_reminder_v1" }),
            channel: channel.into(),
            mandate_for: Some(borrower.into()),
            request_id: "r".into(),
            retry_of: None,
            attack: None,
            status: 200,
            decision: Some(if allowed { "PASS" } else { "BLOCK" }.into()),
            reasons: vec![],
            record_id: None,
            outcome: None,
            replayed: false,
            leak: None,
        }
    }

    #[test]
    fn hours_are_from_eight_to_before_nineteen_ist() {
        let mut oracle = Oracle::default();
        for (minute, allow) in [(479, false), (480, true), (1139, true), (1140, false)] {
            assert_eq!(
                oracle
                    .judge(&call(minute, &format!("ref:b-{minute}"), "whatsapp", false))
                    .allow,
                allow,
                "{minute}"
            );
        }
    }

    #[test]
    fn the_cap_counts_contacts_made_by_any_agent() {
        let mut oracle = Oracle::default();
        let mut first = call(600, "ref:b", "whatsapp", true);
        for agent in ["a", "b", "a"] {
            first.agent = agent.into();
            assert!(oracle.judge(&first).allow);
        }
        first.agent = "b".into();
        assert_eq!(oracle.judge(&first).because, ["daily cap reached"]);
        // A refused attempt is not a contact.
        assert!(!oracle.judge(&call(600, "ref:c", "sms", false)).allow);
        assert!(oracle.judge(&call(601, "ref:c", "whatsapp", true)).allow);
    }

    #[test]
    fn calls_outside_the_registry_or_the_mandate_are_refused() {
        let mut oracle = Oracle::default();
        let refused = |oracle: &mut Oracle, call: &Entry, why: &str| {
            let expected = oracle.judge(call);
            assert!(
                !expected.allow && expected.because.contains(&why),
                "{why}: {expected:?}"
            );
        };
        let ok = call(600, "ref:borrower:A-0001", "whatsapp", false);
        assert!(oracle.judge(&ok).allow);
        // The catalog's identifier payloads.
        for raw in [
            "ref:borrower:9876543210",
            "ref:borrower:ABCPE1234F",
            "ref:borrower:234567890123",
        ] {
            let mut c = ok.clone();
            c.params["subject_ref"] = raw.into();
            refused(&mut oracle, &c, "not a plain reference");
        }
        let mut c = ok.clone();
        c.params["subject_ref"] = "ref:borrower:B-1".into();
        refused(&mut oracle, &c, "another borrower than the mandate's");
        let mut c = ok.clone();
        c.mandate_for = None;
        refused(&mut oracle, &c, "no such mandate");
        let mut c = ok.clone();
        c.params["timestamp"] = "2026-10-01T00:00:00Z".into();
        refused(&mut oracle, &c, "not what the registry accepts");
        let mut c = ok.clone();
        c.params["channel"] = "voice".into();
        refused(&mut oracle, &c, "not what the registry accepts");
        let mut c = ok.clone();
        c.tool = "export_all_borrowers".into();
        refused(&mut oracle, &c, "not what the registry accepts");
    }

    #[test]
    fn retries_replay_and_outcomes_follow_the_destination() {
        let deliveries = BTreeMap::from([
            ("ref:a".to_string(), Delivery::Delivers),
            ("ref:l".to_string(), Delivery::Loses),
            ("ref:r".to_string(), Delivery::Refuses),
            ("ref:e".to_string(), Delivery::Errs),
        ]);
        let mut oracle = Oracle::new(Rules::default(), deliveries);
        for (subject, outcome) in [
            ("ref:a", "delivered"),
            ("ref:r", "refused"),
            ("ref:e", "unknown"),
        ] {
            assert_eq!(
                oracle.judge(&call(600, subject, "whatsapp", true)).outcome,
                Some(outcome)
            );
        }
        let mut lost = call(600, "ref:l", "whatsapp", true);
        (lost.seq, lost.outcome) = (7, Some("unknown".into()));
        assert_eq!(oracle.judge(&lost).outcome, Some("unknown"));
        let mut again = lost.clone();
        (again.seq, again.retry_of) = (8, Some(7));
        assert_eq!(oracle.judge(&again).retry, Some(Retry::InFlight));
        // After a final outcome, the stored reply.
        let mut done = call(600, "ref:a", "whatsapp", true);
        (done.seq, done.outcome) = (9, Some("delivered".into()));
        oracle.judge(&done);
        let mut again = done.clone();
        (again.seq, again.retry_of) = (10, Some(9));
        assert_eq!(
            oracle.judge(&again).retry,
            Some(Retry::Stored { allowed: true })
        );
        // Not a new contact: two more are allowed.
        let mut next = call(601, "ref:l", "whatsapp", true);
        assert!(oracle.judge(&next).allow);
        next.at = slot(1, 602);
        assert!(oracle.judge(&next).allow);
        assert!(!oracle.judge(&call(603, "ref:l", "whatsapp", false)).allow);
    }
}
