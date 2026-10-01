//! Raw-identifier detection over tool parameters (PRD D11, FR-5).
//!
//! Agents pass capability references (`ref:<type>:<id>`), never personal
//! values. Every string parameter is scanned, not only declared
//! reference-only fields. The slice detects Indian mobile numbers and other
//! long digit runs (account-like numbers); PAN/UPI/IFSC/Aadhaar follow.

/// What kind of raw identifier a value contains, if any.
#[must_use]
pub fn raw_identifier(value: &str) -> Option<&'static str> {
    // Separators agents might insert to slip a number past a naive check.
    let digits: String = value
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '.' | '(' | ')' | '\u{a0}' | '_' | '/'))
        .collect();
    let mut runs = Vec::new();
    let mut current = String::new();
    for c in digits.chars() {
        if c.is_ascii_digit() {
            current.push(c);
        } else if !current.is_empty() {
            runs.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        runs.push(current);
    }
    for run in runs {
        let national = run
            .strip_prefix("91")
            .filter(|r| r.len() == 10)
            .or_else(|| run.strip_prefix('0').filter(|r| r.len() == 10))
            .unwrap_or(&run);
        if national.len() == 10 && national.starts_with(['6', '7', '8', '9']) {
            return Some("phone");
        }
        if run.len() >= 9 {
            return Some("long_number");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::raw_identifier;

    #[test]
    fn indian_mobiles_are_found_through_separators() {
        for value in [
            "9876543210",
            "+91 98765 43210",
            "098765-43210",
            "call 98 76 54 32 10 now",
            "91.9876.543.210",
        ] {
            assert_eq!(raw_identifier(value), Some("phone"), "{value}");
        }
        assert_eq!(raw_identifier("acct 123456789012"), Some("long_number"));
        for clean in [
            "ref:borrower:B-9382",
            "whatsapp",
            "emi_reminder_v1",
            "L-4471",
            "2026",
        ] {
            assert_eq!(raw_identifier(clean), None, "{clean}");
        }
    }
}
