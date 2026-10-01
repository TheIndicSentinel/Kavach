//! Raw-identifier detection over tool parameters (PRD D11, FR-5).
//!
//! Agents pass capability references (`ref:<type>:<id>`), never personal
//! values. Every string parameter is scanned, not only declared
//! reference-only fields. The slice detects Indian mobile numbers and other
//! long digit runs (account-like numbers); PAN/UPI/IFSC/Aadhaar follow.

/// Zero digits of the decimal digit blocks an agent could use to write a
/// number: fullwidth, the Indian scripts and Arabic-Indic.
const DIGIT_ZEROS: [u32; 12] = [
    0xFF10, // fullwidth
    0x0966, // Devanagari
    0x09E6, // Bengali
    0x0A66, // Gurmukhi
    0x0AE6, // Gujarati
    0x0B66, // Oriya
    0x0BE6, // Tamil
    0x0C66, // Telugu
    0x0CE6, // Kannada
    0x0D66, // Malayalam
    0x0660, // Arabic-Indic
    0x06F0, // Extended Arabic-Indic (Urdu)
];

/// The ASCII digit for any supported decimal digit.
fn ascii_digit(c: char) -> Option<char> {
    if c.is_ascii_digit() {
        return Some(c);
    }
    let code = u32::from(c);
    DIGIT_ZEROS
        .iter()
        .find(|zero| (**zero..**zero + 10).contains(&code))
        .and_then(|zero| char::from_digit(code - zero, 10))
}

/// What kind of raw identifier a value contains, if any. Digits in other
/// scripts are mapped to ASCII, and punctuation, spaces and invisible
/// characters do not split a number; only letters do.
#[must_use]
pub fn raw_identifier(value: &str) -> Option<&'static str> {
    let mut runs = Vec::new();
    let mut current = String::new();
    for c in value.chars() {
        if let Some(d) = ascii_digit(c) {
            current.push(d);
        } else if c.is_alphabetic() && !current.is_empty() {
            runs.push(std::mem::take(&mut current));
        }
        // Anything else (separators, punctuation, zero-width) is skipped.
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
            "9 8 7 6 5 4 3 2 1 0",
            "98765,43210",
            "９８７６５４３２１０",
            "९८७६५४३२१०",
            "98765\u{200b}43210",
            "+91–98765–43210",
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
