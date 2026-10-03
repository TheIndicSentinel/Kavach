//! Raw-identifier detection over tool parameters (PRD D11, FR-5).
//!
//! Agents pass capability references (`ref:<type>:<id>`), never personal
//! values. Every string parameter is scanned, not only declared
//! reference-only fields, for Indian mobile numbers, Aadhaar numbers, PANs
//! and other long digit runs (account-like numbers). UPI IDs, IFSC codes
//! and account-number formats follow (PRD FR-5).
//!
//! Reference-only fields are held to a stricter rule ([`reference_identifier`]):
//! a reference id has at most 8 digits in total, however they are spread,
//! so letters cannot split a number into short runs.
//!
//! Detection covers numbers written with digits in any supported script and
//! any separators, and PANs in either case. Identifiers spelt out in words or
//! encoded (base64, hex of the digits and similar) are not detected: see
//! docs/BYPASS_INVENTORY.md.

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

/// Most digits a reference id may hold (reference-only fields).
pub const MAX_REFERENCE_DIGITS: usize = 8;

/// The fourth character of a PAN: the holder type.
const PAN_HOLDER_TYPES: &str = "PCHFATBLJG";

/// The ASCII letter for an ASCII or fullwidth Latin letter, upper-cased.
fn latin_letter(c: char) -> Option<char> {
    if c.is_ascii_alphabetic() {
        return Some(c.to_ascii_uppercase());
    }
    let code = u32::from(c);
    let base = match code {
        0xFF21..=0xFF3A => 0xFF21,
        0xFF41..=0xFF5A => 0xFF41,
        _ => return None,
    };
    char::from_u32(u32::from('A') + code - base)
}

/// Verhoeff checksum (Aadhaar's check digit).
fn verhoeff_valid(digits: &str) -> bool {
    const D: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    const P: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 7, 8, 6, 0],
        [4, 2, 8, 6, 5, 7, 0, 3, 9, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    let mut check = 0u8;
    for (i, c) in digits.bytes().rev().enumerate() {
        let Some(digit) = c.checked_sub(b'0').filter(|d| *d < 10) else {
            return false;
        };
        check = D[usize::from(check)][usize::from(P[i % 8][usize::from(digit)])];
    }
    check == 0
}

/// What a run of ASCII digits is, if it is an identifier.
fn classify_digits(run: &str) -> Option<&'static str> {
    let national = run
        .strip_prefix("91")
        .filter(|r| r.len() == 10)
        .or_else(|| run.strip_prefix('0').filter(|r| r.len() == 10))
        .unwrap_or(run);
    if national.len() == 10 && national.starts_with(['6', '7', '8', '9']) {
        return Some("phone");
    }
    if run.len() == 12 && !run.starts_with(['0', '1']) && verhoeff_valid(run) {
        return Some("aadhaar");
    }
    if run.len() >= 9 {
        return Some("long_number");
    }
    None
}

/// Whether `value` contains a PAN (`AAAAA9999A`, the fourth letter a holder
/// type), in either case, through separators.
fn contains_pan(value: &str) -> bool {
    let chars: Vec<char> = value
        .chars()
        .filter_map(|c| latin_letter(c).or_else(|| ascii_digit(c)))
        .collect();
    chars.windows(10).any(|w| {
        w[..5].iter().all(char::is_ascii_uppercase)
            && PAN_HOLDER_TYPES.contains(w[3])
            && w[5..9].iter().all(char::is_ascii_digit)
            && w[9].is_ascii_uppercase()
    })
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
    if let Some(kind) = runs.iter().find_map(|run| classify_digits(run)) {
        return Some(kind);
    }
    contains_pan(value).then_some("pan")
}

/// As [`raw_identifier`], for a reference-only field: also refuses a value
/// with more than [`MAX_REFERENCE_DIGITS`] digits in total, wherever they
/// are. Letters do not split a number here.
#[must_use]
pub fn reference_identifier(value: &str) -> Option<&'static str> {
    raw_identifier(value).or_else(|| {
        let digits: String = value.chars().filter_map(ascii_digit).collect();
        (digits.len() > MAX_REFERENCE_DIGITS)
            .then(|| classify_digits(&digits).unwrap_or("long_number"))
    })
}

#[cfg(test)]
mod tests {
    use super::{raw_identifier, reference_identifier};

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

    #[test]
    fn aadhaar_numbers_are_named_when_the_checksum_holds() {
        // Synthetic numbers with valid Verhoeff check digits.
        for value in [
            "234567890129",
            "2345 6789 0129",
            "5544-3322-1100",
            "२३४५६७८९०१२९",
        ] {
            assert_eq!(raw_identifier(value), Some("aadhaar"), "{value}");
        }
        // A wrong check digit is still a long number, and still refused.
        assert_eq!(raw_identifier("234567890120"), Some("long_number"));
    }

    #[test]
    fn pans_are_found_in_either_case_and_through_separators() {
        for value in [
            "ABCPE1234F",
            "abcpe1234f",
            "ref:borrower:ABCPE1234F",
            "ABCPE-1234-F",
            "pan ABCPE 1234 F",
            "ＡＢＣＰＥ１２３４Ｆ",
        ] {
            assert_eq!(raw_identifier(value), Some("pan"), "{value}");
        }
        // The fourth letter must be a holder type; other shapes are not PANs.
        for clean in ["ABCDE1234F", "ABCP1234F", "ABCPE12345", "emi_reminder_v1"] {
            assert_eq!(raw_identifier(clean), None, "{clean}");
        }
    }

    #[test]
    fn reference_ids_hold_at_most_eight_digits_however_spread() {
        for clean in [
            "ref:borrower:B-9382",
            "ref:loan:L-4471",
            "ref:borrower:BENCH-000001",
            "ref:x:a1b2c3d4",
        ] {
            assert_eq!(reference_identifier(clean), None, "{clean}");
        }
        assert_eq!(
            reference_identifier("ref:x:2345a6789b0129"),
            Some("aadhaar")
        );
        assert_eq!(
            reference_identifier("ref:x:9a8b7c6d5e4f3g2h1i0"),
            Some("phone")
        );
        assert_eq!(
            reference_identifier("ref:x:a1b2c3d4e5f6g7h8i9"),
            Some("long_number")
        );
        // Outside reference-only fields, letters still split runs.
        assert_eq!(raw_identifier("ref:x:2345a6789b0129"), None);
    }
}
