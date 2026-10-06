//! The scenario file, format version 1 (pre-alpha): strict (unknown keys
//! are refused), and `expect` is required, so a scenario always says what
//! passing means.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const FORMAT_VERSION: u32 = 1;
/// Mandates live 7 days: v1 runs fit inside one mandate.
pub const MAX_DAYS: u32 = 7;
pub const MAX_BORROWERS: u32 = 200;
pub const MAX_AGENTS: u32 = 20;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub version: u32,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// The SECURITY_PROPERTIES.md rows (their bold titles) it exercises.
    #[serde(default)]
    pub covers: Vec<String>,
    pub seed: u64,
    pub days: u32,
    pub borrowers: u32,
    /// Times of day (HH:MM, IST) at which agents act, ascending.
    pub schedule: Vec<String>,
    pub agents: Vec<AgentSpec>,
    #[serde(default)]
    pub assignment: Assignment,
    /// Borrowers whose destination is one of the mock provider's failure
    /// numbers (the first ones, in this order: refuse, error, lose).
    #[serde(default)]
    pub provider_failures: ProviderFailures,
    pub expect: Expect,
}

/// How many borrowers get each failure: refused by the recipient (422), a
/// provider error (500), or delivered with the response lost (outcome
/// unknown; each costs the stack's provider timeout, about 5 s).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProviderFailures {
    pub refuse: u32,
    pub error: u32,
    pub lose: u32,
}

/// Who serves which borrower.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assignment {
    /// Each borrower has one agent (round robin).
    #[default]
    Split,
    /// Every agent serves every borrower (several vendors on one book).
    Shared,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    #[serde(rename = "type")]
    pub kind: AgentKind,
    #[serde(default = "one")]
    pub count: u32,
    #[serde(default)]
    pub behaviour: Behaviour,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    /// Keeps to the hours and to its own daily limit; one channel.
    Compliant,
    /// Contacts late, too often, and on the wrong channel, by its rates.
    Eager,
    /// Tries the attack catalog's tool-call attacks, on borrowers kept for
    /// it (so it never uses up a real borrower's daily cap).
    Adversarial,
}

impl AgentKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compliant => "compliant",
            Self::Eager => "eager",
            Self::Adversarial => "adversarial",
        }
    }
}

/// Behaviour settings; unset ones take the agent type's defaults.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Behaviour {
    /// Contacts per borrower per day the agent means to make.
    pub contacts_per_day: Option<u32>,
    /// Chance of acting in a slot outside 08:00–19:00 IST.
    pub late_rate: Option<f64>,
    /// Chance of contacting again once its own daily limit is reached.
    pub extra_contact_rate: Option<f64>,
    /// Chance of using SMS, which the mandate does not allow.
    pub wrong_channel_rate: Option<f64>,
    /// Chance of sending the same request again (same request id) after an
    /// outcome that is not known.
    pub retry_rate: Option<f64>,
    /// Adversarial: chance of an attack per borrower per slot.
    pub attack_rate: Option<f64>,
    /// Adversarial: only these attack catalog ids (default: every tool-call
    /// attack an agent can make with its own token).
    pub attacks: Option<Vec<String>>,
}

/// [`Behaviour`] with the type's defaults filled in.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Resolved {
    pub contacts_per_day: u32,
    pub late_rate: f64,
    pub extra_contact_rate: f64,
    pub wrong_channel_rate: f64,
    pub retry_rate: f64,
    pub attack_rate: f64,
    /// Catalog ids; empty for agents that do not attack.
    pub attacks: Vec<&'static str>,
}

impl Behaviour {
    #[must_use]
    pub fn resolve(&self, kind: AgentKind) -> Resolved {
        let (per_day, late, extra, wrong) = match kind {
            AgentKind::Compliant => (1, 0.0, 0.0, 0.0),
            AgentKind::Eager => (3, 0.5, 0.5, 0.2),
            AgentKind::Adversarial => (0, 1.0, 0.0, 0.0),
        };
        let attacks = if kind == AgentKind::Adversarial {
            crate::agents::agent_attacks()
                .filter(|id| {
                    self.attacks
                        .as_ref()
                        .is_none_or(|only| only.iter().any(|o| o == id))
                })
                .collect()
        } else {
            Vec::new()
        };
        Resolved {
            contacts_per_day: self.contacts_per_day.unwrap_or(per_day),
            late_rate: self.late_rate.unwrap_or(late),
            extra_contact_rate: self.extra_contact_rate.unwrap_or(extra),
            wrong_channel_rate: self.wrong_channel_rate.unwrap_or(wrong),
            retry_rate: self.retry_rate.unwrap_or(0.0),
            attack_rate: self.attack_rate.unwrap_or(1.0),
            attacks,
        }
    }
}

/// What passing means.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    pub violations: u32,
    pub mismatches: u32,
    pub leaks: u32,
    /// At least this many BLOCKs with each reason (proof the scenario
    /// exercised the rule it is about).
    #[serde(default)]
    pub blocked_at_least: BTreeMap<String, u32>,
    #[serde(default)]
    pub allowed_at_least: u32,
}

/// Parses and checks a scenario file.
pub fn parse(text: &str) -> Result<Scenario, String> {
    let scenario: Scenario =
        serde_yaml::from_str(text).map_err(|e| format!("invalid scenario: {e}"))?;
    scenario.validate()?;
    Ok(scenario)
}

/// `HH:MM` as minutes of the day.
pub fn minute_of_day(hhmm: &str) -> Result<u32, String> {
    let bad = || format!("{hhmm:?} is not HH:MM");
    let (h, m) = hhmm.split_once(':').ok_or_else(bad)?;
    if h.len() != 2 || m.len() != 2 {
        return Err(bad());
    }
    let (h, m): (u32, u32) = (h.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
    if h > 23 || m > 59 {
        return Err(bad());
    }
    Ok(h * 60 + m)
}

impl Scenario {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != FORMAT_VERSION {
            return Err(format!(
                "scenario version {} is not supported (this is version {FORMAT_VERSION})",
                self.version
            ));
        }
        if self.name.trim().is_empty() {
            return Err("the scenario needs a name".into());
        }
        if !(1..=MAX_DAYS).contains(&self.days) {
            return Err(format!("days must be 1–{MAX_DAYS} (one mandate's life)"));
        }
        if !(1..=MAX_BORROWERS).contains(&self.borrowers) {
            return Err(format!("borrowers must be 1–{MAX_BORROWERS}"));
        }
        let minutes = self.slots()?;
        if minutes.is_empty() || minutes.windows(2).any(|w| w[0] >= w[1]) {
            return Err("schedule must be one or more ascending HH:MM times".into());
        }
        let total: u32 = self.agents.iter().map(|a| a.count).sum();
        if self.agents.is_empty() || self.agents.iter().any(|a| a.count == 0) {
            return Err("every agent entry needs a count of at least 1".into());
        }
        if total > MAX_AGENTS {
            return Err(format!("at most {MAX_AGENTS} agents"));
        }
        for agent in &self.agents {
            let b = &agent.behaviour;
            for rate in [
                b.late_rate,
                b.extra_contact_rate,
                b.wrong_channel_rate,
                b.retry_rate,
                b.attack_rate,
            ]
            .into_iter()
            .flatten()
            {
                if !(0.0..=1.0).contains(&rate) {
                    return Err(format!("rates are between 0 and 1, not {rate}"));
                }
            }
            if let Some(only) = &b.attacks {
                let known: Vec<&str> = crate::agents::agent_attacks().collect();
                if let Some(unknown) = only.iter().find(|a| !known.contains(&a.as_str())) {
                    return Err(format!(
                        "{unknown:?} is not an attack an agent can make (there are: {})",
                        known.join(", ")
                    ));
                }
            }
        }
        let f = self.provider_failures;
        if f.refuse + f.error + f.lose > self.borrowers {
            return Err("more provider failures than borrowers".into());
        }
        if !self.agents.iter().any(|a| a.kind != AgentKind::Adversarial) {
            return Err(
                "at least one agent that is not adversarial (the world's borrowers need one)"
                    .into(),
            );
        }
        Ok(())
    }

    /// The schedule as minutes of the day.
    pub fn slots(&self) -> Result<Vec<u32>, String> {
        self.schedule.iter().map(|s| minute_of_day(s)).collect()
    }
}

/// The built-in scenarios: name and file.
pub const BUILTINS: &[(&str, &str)] = &[
    ("normal-day", include_str!("../scenarios/normal-day.yaml")),
    ("after-hours", include_str!("../scenarios/after-hours.yaml")),
    (
        "fourth-contact",
        include_str!("../scenarios/fourth-contact.yaml"),
    ),
    (
        "two-agents-one-borrower",
        include_str!("../scenarios/two-agents-one-borrower.yaml"),
    ),
    (
        "prompt-injection-raw-number",
        include_str!("../scenarios/prompt-injection-raw-number.yaml"),
    ),
    (
        "wrong-borrower",
        include_str!("../scenarios/wrong-borrower.yaml"),
    ),
    (
        "forged-mandate",
        include_str!("../scenarios/forged-mandate.yaml"),
    ),
    (
        "provider-failures",
        include_str!("../scenarios/provider-failures.yaml"),
    ),
    (
        "retry-after-unknown",
        include_str!("../scenarios/retry-after-unknown.yaml"),
    ),
    ("mixed-week", include_str!("../scenarios/mixed-week.yaml")),
];

/// A built-in scenario by name.
pub fn builtin(name: &str) -> Result<Scenario, String> {
    let (_, text) = BUILTINS.iter().find(|(n, _)| *n == name).ok_or_else(|| {
        let names: Vec<&str> = BUILTINS.iter().map(|(n, _)| *n).collect();
        format!(
            "no built-in scenario {name:?} (there are: {})",
            names.join(", ")
        )
    })?;
    parse(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_parses_and_names_itself() {
        for (name, text) in BUILTINS {
            let scenario = parse(text).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(scenario.name, *name);
        }
    }

    #[test]
    fn scenarios_are_strict() {
        let good = BUILTINS[0].1;
        assert!(parse(good).is_ok());
        let unknown = format!("{good}\nsurprise: 1\n");
        assert!(parse(&unknown).unwrap_err().contains("surprise"));
        let without_expect = &good[..good.find("expect:").unwrap()];
        assert!(parse(without_expect).unwrap_err().contains("expect"));
        let v2 = good.replace("version: 1", "version: 2");
        assert!(parse(&v2).unwrap_err().contains("version 2"));
        let backwards = good.replace(
            "schedule: [\"09:00\", \"12:00\"]",
            "schedule: [\"12:00\", \"09:00\"]",
        );
        assert_ne!(backwards, good, "the fixture has that schedule");
        assert!(parse(&backwards).unwrap_err().contains("ascending"));
        let long = good.replace("days: 1", "days: 8");
        assert!(parse(&long).unwrap_err().contains("days"));
    }

    #[test]
    fn times_of_day_are_strict() {
        assert_eq!(minute_of_day("08:00"), Ok(480));
        assert_eq!(minute_of_day("18:59"), Ok(1139));
        for bad in ["8:00", "24:00", "12:60", "noon", "12:00:00"] {
            assert!(minute_of_day(bad).is_err(), "{bad}");
        }
    }

    /// Every built-in names the SECURITY_PROPERTIES.md rows it exercises,
    /// and each row is still there (a renamed or removed row fails here).
    #[test]
    fn every_builtin_covers_rows_that_exist() {
        let properties = include_str!("../../../docs/SECURITY_PROPERTIES.md");
        for (name, text) in BUILTINS {
            let scenario = parse(text).unwrap();
            assert!(!scenario.covers.is_empty(), "{name} covers no row");
            for row in &scenario.covers {
                assert!(
                    properties.contains(&format!("| **{row}**")),
                    "{name}: no SECURITY_PROPERTIES.md row **{row}**"
                );
            }
        }
    }
}
