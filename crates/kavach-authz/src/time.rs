//! Business-window time in `Asia/Kolkata` (ADR-003 §8). Inputs are trusted
//! server time; agent-supplied timestamps are never used.

use chrono::{DateTime, NaiveDate, Timelike, Utc};
use chrono_tz::Asia::Kolkata;

/// Minutes since local midnight in IST (0..1440).
pub fn ist_minute_of_day(now: DateTime<Utc>) -> i64 {
    let local = now.with_timezone(&Kolkata);
    i64::from(local.hour()) * 60 + i64::from(local.minute())
}

/// IST calendar date; daily contact counters roll over at IST midnight.
pub fn ist_date(now: DateTime<Utc>) -> NaiveDate {
    now.with_timezone(&Kolkata).date_naive()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn ist_is_utc_plus_five_thirty_and_rolls_over_at_ist_midnight() {
        // 02:29:59 UTC = 07:59:59 IST
        let t = Utc.with_ymd_and_hms(2026, 10, 1, 2, 29, 59).unwrap();
        assert_eq!(ist_minute_of_day(t), 7 * 60 + 59);
        // 18:29:59 UTC = 23:59:59 IST on 1 Oct; 18:30:00 UTC = 00:00 IST on 2 Oct
        let before = Utc.with_ymd_and_hms(2026, 10, 1, 18, 29, 59).unwrap();
        let after = Utc.with_ymd_and_hms(2026, 10, 1, 18, 30, 0).unwrap();
        assert_eq!(
            ist_date(before),
            NaiveDate::from_ymd_opt(2026, 10, 1).unwrap()
        );
        assert_eq!(
            ist_date(after),
            NaiveDate::from_ymd_opt(2026, 10, 2).unwrap()
        );
        assert_eq!(ist_minute_of_day(after), 0);
    }
}
