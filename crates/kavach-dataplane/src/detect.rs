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
//! Detection covers numbers written with any Unicode decimal digit (general
//! category Nd: the digit block of every script in Unicode 17.0, see
//! `DIGIT_ZEROS`) and any separators, and PANs in either case. Identifiers
//! spelt out in words, written with other numeric characters (circled,
//! superscript, Roman numerals and similar) or encoded (base64, hex of the
//! digits and similar) are not detected: see docs/BYPASS_INVENTORY.md.

/// The zero of every decimal digit block in Unicode 17.0: every character of
/// general category Nd is one of the ten code points from one of these zeros,
/// and digit `n` of a block is its zero plus `n`. Sorted, for the binary
/// search in [`ascii_digit`].
///
/// Derived, not typed by hand: the 76 Nd zeros of Unicode 16.0 (Python's
/// `unicodedata`, every Nd character with decimal value 0; all 760 Nd
/// characters are exactly those 76 runs of ten), plus the one run of ten that
/// Unicode 17.0 added among the toolchain's numeric characters (Tolong Siki,
/// U+11DE0). Std's `char::is_numeric` (Nd, Nl and No together) cannot tell a
/// digit block from other numbers on its own; the tests check every block
/// against it and every character against this table.
const DIGIT_ZEROS: [u32; 77] = [
    0x0030,  // ASCII
    0x0660,  // Arabic-Indic
    0x06F0,  // Extended Arabic-Indic (Urdu)
    0x07C0,  // NKo
    0x0966,  // Devanagari
    0x09E6,  // Bengali
    0x0A66,  // Gurmukhi
    0x0AE6,  // Gujarati
    0x0B66,  // Oriya (Odia)
    0x0BE6,  // Tamil
    0x0C66,  // Telugu
    0x0CE6,  // Kannada
    0x0D66,  // Malayalam
    0x0DE6,  // Sinhala Lith
    0x0E50,  // Thai
    0x0ED0,  // Lao
    0x0F20,  // Tibetan
    0x1040,  // Myanmar
    0x1090,  // Myanmar Shan
    0x17E0,  // Khmer
    0x1810,  // Mongolian
    0x1946,  // Limbu
    0x19D0,  // New Tai Lue
    0x1A80,  // Tai Tham Hora
    0x1A90,  // Tai Tham Tham
    0x1B50,  // Balinese
    0x1BB0,  // Sundanese
    0x1C40,  // Lepcha
    0x1C50,  // Ol Chiki
    0xA620,  // Vai
    0xA8D0,  // Saurashtra
    0xA900,  // Kayah Li
    0xA9D0,  // Javanese
    0xA9F0,  // Myanmar Tai Laing
    0xAA50,  // Cham
    0xABF0,  // Meetei Mayek
    0xFF10,  // Fullwidth
    0x104A0, // Osmanya
    0x10D30, // Hanifi Rohingya
    0x10D40, // Garay
    0x11066, // Brahmi
    0x110F0, // Sora Sompeng
    0x11136, // Chakma
    0x111D0, // Sharada
    0x112F0, // Khudawadi
    0x11450, // Newa
    0x114D0, // Tirhuta
    0x11650, // Modi
    0x116C0, // Takri
    0x116D0, // Myanmar Pao
    0x116DA, // Myanmar Eastern Pwo Karen
    0x11730, // Ahom
    0x118E0, // Warang Citi
    0x11950, // Dives Akuru
    0x11BF0, // Sunuwar
    0x11C50, // Bhaiksuki
    0x11D50, // Masaram Gondi
    0x11DA0, // Gunjala Gondi
    0x11DE0, // Tolong Siki
    0x11F50, // Kawi
    0x16130, // Gurung Khema
    0x16A60, // Mro
    0x16AC0, // Tangsa
    0x16B50, // Pahawh Hmong
    0x16D70, // Kirat Rai
    0x1CCF0, // Outlined
    0x1D7CE, // Mathematical Bold
    0x1D7D8, // Mathematical Double-Struck
    0x1D7E2, // Mathematical Sans-Serif
    0x1D7EC, // Mathematical Sans-Serif Bold
    0x1D7F6, // Mathematical Monospace
    0x1E140, // Nyiakeng Puachue Hmong
    0x1E2F0, // Wancho
    0x1E4F0, // Nag Mundari
    0x1E5F1, // Ol Onal
    0x1E950, // Adlam
    0x1FBF0, // Segmented
];

/// The ASCII digit for any Unicode decimal digit (general category Nd).
fn ascii_digit(c: char) -> Option<char> {
    if c.is_ascii_digit() {
        return Some(c);
    }
    let code = u32::from(c);
    // The last zero at or below `code`, if any.
    let block = match DIGIT_ZEROS.binary_search(&code) {
        Ok(i) => i,
        Err(0) => return None,
        Err(i) => i - 1,
    };
    // `from_digit` refuses an offset of 10 or more: past the block's nine.
    char::from_digit(code - DIGIT_ZEROS[block], 10)
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
    use super::{ascii_digit, raw_identifier, reference_identifier, DIGIT_ZEROS};
    use proptest::prelude::*;

    /// The digit `c` is under the table's rule, found by a plain scan rather
    /// than the binary search: `c` is one of the ten code points from a zero.
    fn digit_by_scan(c: char) -> Option<char> {
        let code = u32::from(c);
        DIGIT_ZEROS
            .iter()
            .find(|zero| (**zero..**zero + 10).contains(&code))
            .and_then(|zero| char::from_digit(code - zero, 10))
    }

    /// Every `char` there is (about 1.1 million): a digit of any block maps
    /// to its ASCII digit, and nothing else outside ASCII maps at all.
    #[test]
    fn every_char_maps_to_ascii_exactly_when_it_is_a_decimal_digit() {
        let mut digits = 0;
        for c in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            let expected = if c.is_ascii() {
                c.is_ascii_digit().then_some(c)
            } else {
                digit_by_scan(c)
            };
            assert_eq!(ascii_digit(c), expected, "U+{:04X}", u32::from(c));
            if let Some(d) = expected {
                assert!(c.is_numeric(), "U+{:04X}", u32::from(c));
                assert_eq!(digit_by_scan(c), Some(d), "U+{:04X}", u32::from(c));
                digits += 1;
            }
        }
        assert_eq!(digits, DIGIT_ZEROS.len() * 10);
    }

    /// The table is for the Unicode version of the pinned toolchain. A
    /// toolchain bump that moves `char::UNICODE_VERSION` fails here until the
    /// table is derived again (see `DIGIT_ZEROS`).
    #[test]
    fn the_digit_table_matches_the_toolchains_unicode() {
        assert_eq!(char::UNICODE_VERSION, (17, 0, 0));
        assert_eq!(DIGIT_ZEROS.len(), 77);
    }

    /// Each block is ten numeric characters, the blocks are sorted and do not
    /// overlap, and every run of exactly ten numeric characters in std's
    /// tables is a block, except six runs that are numbers but not digits
    /// (general category No or Nl in the Unicode Character Database). A new
    /// script's digits after a Unicode bump would show up here.
    #[test]
    fn every_digit_block_is_numeric_and_every_lone_run_of_ten_is_a_block() {
        for pair in DIGIT_ZEROS.windows(2) {
            assert!(pair[0] + 10 <= pair[1], "{:04X} {:04X}", pair[0], pair[1]);
        }
        for zero in DIGIT_ZEROS {
            for code in zero..zero + 10 {
                assert!(
                    char::from_u32(code).is_some_and(char::is_numeric),
                    "U+{code:04X}"
                );
            }
        }
        for start in lone_runs_of_ten() {
            assert!(DIGIT_ZEROS.contains(&start), "U+{start:04X}");
        }
    }

    /// Where every maximal run of exactly ten numeric characters (std's
    /// `char::is_numeric`: Nd, Nl and No) starts, less six runs that are
    /// numbers but not digits (No or Nl in the Unicode Character Database).
    /// Derived from std alone, not from `DIGIT_ZEROS`.
    fn lone_runs_of_ten() -> Vec<u32> {
        let not_digits = [
            0x17F0,  // Khmer lek attak (No)
            0x2080,  // subscript digits (No)
            0x3220,  // parenthesised ideographs one to ten (No)
            0x3280,  // circled ideographs one to ten (No)
            0xA6E6,  // Bamum letters that are numerals (Nl)
            0x10F1D, // Old Sogdian numbers (No)
        ];
        let numeric = |code: u32| char::from_u32(code).is_some_and(char::is_numeric);
        let mut starts = Vec::new();
        let mut code = 0;
        while code <= u32::from(char::MAX) {
            if !numeric(code) {
                code += 1;
                continue;
            }
            let start = code;
            while numeric(code) {
                code += 1;
            }
            if code - start == 10 && !not_digits.contains(&start) {
                starts.push(start);
            }
        }
        starts
    }

    /// Thai digits were not in the table before (F1). A Thai mobile number
    /// is found alone, through separators, glued to other scripts' digits and
    /// in a reference-only field.
    #[test]
    fn a_mobile_in_thai_digits_is_found() {
        for value in [
            "๙๘๗๖๕๔๓๒๑๐",
            "+๙๑ ๙๘๗๖๕ ๔๓๒๑๐",
            "๐๙๘๗๖๕-๔๓๒๑๐",
            "๙๘๗๖๕\u{200b}๔๓๒๑๐",
            "๙.๘.๗.๖.๕.๔.๓.๒.๑.๐",
            "๙๘๗६५43２𝟏𝟎",
        ] {
            assert_eq!(raw_identifier(value), Some("phone"), "{value}");
            assert_eq!(reference_identifier(value), Some("phone"), "{value}");
        }
        assert_eq!(raw_identifier("ref:x:๒๓๔๕๖๗๘๙๐๑๒๙"), Some("aadhaar"));
        assert_eq!(
            reference_identifier("ref:x:๒๓๔๕a๖๗๘๙b๐๑๒๙"),
            Some("aadhaar")
        );
    }

    /// The zeros the property test writes numbers with: the table's and
    /// the std-derived lone runs of ten.
    fn zeros_to_test() -> Vec<u32> {
        let mut zeros = lone_runs_of_ten();
        zeros.extend(DIGIT_ZEROS);
        zeros.sort_unstable();
        zeros.dedup();
        zeros
    }

    fn separator() -> impl Strategy<Value = &'static str> {
        prop::sample::select(vec![
            "", "", " ", "-", ".", ",", "\u{200b}", "\u{2013}", "(", ")", "/", "\u{a0}",
        ])
    }

    proptest! {
        #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::with_cases(2000) })]

        /// A ten-digit Indian mobile written with any block's digits, a
        /// different block for each digit if it likes, and any separators
        /// between them, is a phone number. The blocks are the table's and
        /// the lone runs of ten that std's tables show, so a block missing
        /// from the table fails here too.
        #[test]
        fn a_mobile_in_any_digits_and_separators_is_found(
            first in 6u32..=9,
            rest in prop::collection::vec(0u32..=9, 9),
            zeros in prop::collection::vec(prop::sample::select(zeros_to_test()), 10),
            separators in prop::collection::vec(separator(), 10),
        ) {
            let mut value = String::new();
            for (i, digit) in std::iter::once(first).chain(rest).enumerate() {
                let c = char::from_u32(zeros[i] + digit).expect("a digit");
                value.push(c);
                value.push_str(separators[i]);
            }
            prop_assert_eq!(raw_identifier(&value), Some("phone"), "{}", value);
            prop_assert_eq!(reference_identifier(&value), Some("phone"), "{}", value);
        }
    }

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
