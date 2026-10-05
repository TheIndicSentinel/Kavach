//! `kavach simulate` (pre-alpha): synthetic agents working over simulated
//! days against a real development stack, judged by a small oracle that
//! shares nothing with the agents.
//!
//! - [`scenario`]: the scenario file (strict, versioned).
//! - [`world`]: synthetic borrowers and agents, and who serves whom.
//! - [`agents`]: what each agent tries, from seeded behaviour settings. It
//!   never sees the oracle or its expectations.
//! - [`oracle`]: what the rules allow, modelled independently of Kavach's
//!   policies (contact window, combined daily cap, channel).
//! - [`driver`]: one run against a [`driver::Stack`] (the CLI implements it
//!   over HTTP), recorded in the [`ledger`].
//! - [`report`]: violations, mismatches and leaks; what is not covered
//!   first.
//!
//! A simulation shows these synthetic scenarios behave as expected on this
//! machine. It is not a security assessment and proves nothing about real
//! providers, networks or data.

pub mod agents;
pub mod driver;
pub mod ledger;
pub mod oracle;
pub mod report;
pub mod rng;
pub mod scenario;
pub mod world;

/// The simulated calendar: IST days from 1 October 2026 (the development
/// clock's day), as UTC instants.
pub mod calendar {
    use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};

    /// IST is UTC+05:30.
    pub const IST_OFFSET_MINUTES: i64 = 330;

    /// `hh:mm` IST on simulated `day` (1-based).
    #[must_use]
    pub fn slot(day: u32, minute_of_day: u32) -> DateTime<Utc> {
        let start = Utc
            .with_ymd_and_hms(2026, 10, 1, 0, 0, 0)
            .single()
            .unwrap_or_default();
        start + Duration::days(i64::from(day) - 1) + Duration::minutes(i64::from(minute_of_day))
            - Duration::minutes(IST_OFFSET_MINUTES)
    }

    /// The IST date and minute of day of `at`.
    #[must_use]
    pub fn ist(at: DateTime<Utc>) -> (NaiveDate, u32) {
        let local = at + Duration::minutes(IST_OFFSET_MINUTES);
        let minute = local
            .time()
            .signed_duration_since(chrono::NaiveTime::MIN)
            .num_minutes();
        (local.date_naive(), u32::try_from(minute).unwrap_or(0))
    }
}
