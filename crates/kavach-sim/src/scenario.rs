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
    pub seed: u64,
    pub days: u32,
    pub borrowers: u32,
    /// Times of day (HH:MM, IST) at which agents act, ascending.
    pub schedule: Vec<String>,
    pub agents: Vec<AgentSpec>,
    #[serde(default)]
    pub assignment: Assignment,
    pub expect: Expect,
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
}

impl AgentKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compliant => "compliant",
            Self::Eager => "eager",
        }
    }
}

/// Behaviour settings; unset ones take the agent type's defaults.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
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
}

/// [`Behaviour`] with the type's defaults filled in.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Resolved {
    pub contacts_per_day: u32,
    pub late_rate: f64,
    pub extra_contact_rate: f64,
    pub wrong_channel_rate: f64,
}

impl Behaviour {
    #[must_use]
    pub fn resolve(self, kind: AgentKind) -> Resolved {
        let (per_day, late, extra, wrong) = match kind {
            AgentKind::Compliant => (1, 0.0, 0.0, 0.0),
            AgentKind::Eager => (3, 0.5, 0.5, 0.2),
        };
        Resolved {
            contacts_per_day: self.contacts_per_day.unwrap_or(per_day),
            late_rate: self.late_rate.unwrap_or(late),
            extra_contact_rate: self.extra_contact_rate.unwrap_or(extra),
            wrong_channel_rate: self.wrong_channel_rate.unwrap_or(wrong),
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
            let b = agent.behaviour;
            for rate in [b.late_rate, b.extra_contact_rate, b.wrong_channel_rate]
                .into_iter()
                .flatten()
            {
                if !(0.0..=1.0).contains(&rate) {
                    return Err(format!("rates are between 0 and 1, not {rate}"));
                }
            }
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
}
