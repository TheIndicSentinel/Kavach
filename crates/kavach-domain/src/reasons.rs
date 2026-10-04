//! What each reason code means, and the usual way to a different decision.
//!
//! One catalog for every code a decision can carry: the agent policies'
//! ids and decision words, the gateway and tool registry's codes, and the
//! policy pack's codes. `kavach why` prints from it; API problem types will
//! too. A test fails when a policy, the registry or the pack can emit a
//! code that has no entry here, so renaming one is a visible change.
//!
//! Wording is factual: what was checked and what would change it. It never
//! says a decision is compliant.

/// One reason code, explained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reason {
    /// The code, or its prefix for parameterised codes
    /// (`raw_identifier:<field>:<kind>`).
    pub code: &'static str,
    /// What it means.
    pub meaning: &'static str,
    /// What would usually lead to a different decision; empty when the
    /// code describes an allow.
    pub fix: &'static str,
}

const fn r(code: &'static str, meaning: &'static str, fix: &'static str) -> Reason {
    Reason { code, meaning, fix }
}

/// Codes that take parameters after a colon (`<prefix>:<field>...`).
const PREFIXED: [Reason; 4] = [
    r(
        "raw_identifier",
        "A parameter holds what reads as a raw identifier (a phone, account, Aadhaar or PAN number) instead of a reference.",
        "Send a reference (ref:<type>:<id>) issued by the system of record; never the value itself.",
    ),
    r(
        "reference_only_violation",
        "A reference-only parameter does not hold a reference of the form ref:<type>:<id>.",
        "Send the reference the system of record issued.",
    ),
    r(
        "value_not_allowed",
        "A parameter's value is not one the signed tool registry allows.",
        "Use a value the registry lists for that parameter, or change the registry and sign it again.",
    ),
    r(
        "value_out_of_range",
        "A numeric parameter is outside the range the signed tool registry allows.",
        "Use a value within the registry's range.",
    ),
];

/// Every other code, by exact name.
const EXACT: [Reason; 37] = [
    // Agent policies: decision words.
    r("authorized", "The agent policies permit this action under the mandate.", ""),
    r("forbidden", "An agent policy forbids this action; the policy ids listed with it say which.", "See the policy ids listed alongside."),
    r("no_matching_permit", "No agent policy permits this action for this agent: the agent is not the mandate's holder, or the action is not in the mandate.", "Act under a mandate this agent holds that includes the action, or delegate the action to this agent."),
    r("escalated", "The action needs a person's approval before it may go ahead.", "Ask for approval of this exact action; the policy ids listed alongside say why."),
    // Agent policies: permits.
    r("permit-read-fields", "Permits reading fields the mandate covers.", ""),
    r("permit-send-reminder", "Permits sending a reminder under the mandate.", ""),
    r("permit-place-call", "Permits placing a call under the mandate.", ""),
    r("permit-propose-plan", "Permits proposing a repayment plan under the mandate.", ""),
    r("permit-update-status", "Permits updating the case status under the mandate.", ""),
    // Agent policies: forbids.
    r("subject-binding", "The call is about a different borrower than the mandate's.", "Act only on the mandate's own subject; another borrower needs its own mandate."),
    r("fields-within-mandate", "The call asks for fields the mandate does not cover.", "Request only the mandate's data fields."),
    r("fields-required", "Reading fields needs a list of the fields wanted.", "List the fields in requested_fields."),
    r("waiver-required", "A repayment plan needs a waiver amount (0 for none).", "Set waiver_bps."),
    r("waiver-in-range", "The waiver is outside 0–10000 basis points.", "Use a waiver between 0 and 10000 basis points."),
    r("waiver-ceiling", "The waiver is above the mandate's ceiling.", "Propose a waiver within the ceiling, or ask for approval of this one."),
    r("channel-required", "Contacting the borrower needs a channel.", "Set channel."),
    r("channel-within-mandate", "The channel is not one the mandate allows.", "Use a channel the mandate lists."),
    r("contact-count-valid", "The day's contact count is invalid.", "Report a contact count of zero or more."),
    r("contact-window-required", "Contacting the borrower needs a contact window in the mandate.", "Issue the mandate from a template with a contact window."),
    r("contact-hours-floor", "Contact is allowed only between 08:00 and 19:00 IST, whatever the mandate says.", "Try again between 08:00 and 19:00 IST."),
    r("contact-window", "The time is outside the mandate's contact window.", "Try again inside the mandate's window."),
    r("contact-daily-cap", "The borrower has had the most contacts the mandate allows today.", "Try again tomorrow (IST)."),
    r("agent-restricted", "The agent is restricted.", "Review the agent's risk state."),
    r("tainted-critical", "The task carries untrusted input, so a critical action needs approval.", "Ask for approval of this exact action."),
    // Gateway and core.
    r("mandate_invalid", "The mandate did not verify: unknown, expired, revoked, or its chain is broken.", "Act under a current mandate; check `kavach sor event` or the system of record."),
    r("trusted_time_unavailable", "Trusted time was not available or not synchronised within the limit, so nothing time-bound could be decided.", "Fix the clock synchronisation (NTP or chrony)."),
    r("dependency_unavailable", "A dependency (the evidence store, the mandate store) did not answer, so the call was blocked.", "Check the dependency and retry with the same request_id."),
    r("policy_evaluation_error", "The agent policies could not be evaluated.", "Report it: this is a fault, not a decision about the call."),
    r("request_id_conflict", "The request_id was already used for a different call.", "Use a new request_id for a different call."),
    r("connect_failed", "The resource provider could not be reached; nothing was sent.", "Check the provider and retry."),
    r("timeout_after_send", "The provider did not answer in time after the request was sent; whether it acted is unknown.", "Check with the provider before retrying: the call is never run again automatically."),
    // Policy pack (finance v0) and evaluate engine.
    r("CONSENT_OK", "A consent is present and its purpose matches the request's.", ""),
    r("CONSENT_MISMATCH", "No consent, or a consent for a different purpose than the request's.", "Send the consent given for this purpose."),
    r("RBI_DTI_EXCEEDED", "The debt-to-income ratio is above the pack's 40% limit.", "Review the application; the pack raises an alert, it does not block."),
    r("INFORMAL_ECONOMY_REVIEW", "The applicant's income is informal, which the pack sends to a person.", "A person reviews the application."),
    r("LOW_CONFIDENCE_GATE", "The model's confidence is below the pack's threshold.", "A person reviews the application."),
    r("POLICY_EVALUATION_ERROR", "A pack rule could not be evaluated; the request was blocked and an incident raised.", "Report it: this is a fault in the pack or the request."),
];

/// The explanation of `code`, if it is in the catalog.
#[must_use]
pub fn explain(code: &str) -> Option<&'static Reason> {
    EXACT.iter().find(|r| r.code == code).or_else(|| {
        let prefix = code.split(':').next()?;
        code.contains(':')
            .then(|| PREFIXED.iter().find(|r| r.code == prefix))
            .flatten()
    })
}

/// Every entry (for documentation and tests).
pub fn all() -> impl Iterator<Item = &'static Reason> {
    EXACT.iter().chain(PREFIXED.iter())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_explained() {
        let mut seen = std::collections::BTreeSet::new();
        for reason in all() {
            assert!(seen.insert(reason.code), "{} twice", reason.code);
            assert!(!reason.meaning.is_empty(), "{}", reason.code);
            for word in ["compliant", "production-grade"] {
                assert!(
                    !reason.meaning.to_lowercase().contains(word),
                    "{}",
                    reason.code
                );
                assert!(!reason.fix.to_lowercase().contains(word), "{}", reason.code);
            }
        }
    }

    #[test]
    fn prefixed_codes_need_their_parameters() {
        assert_eq!(
            explain("raw_identifier:subject_ref:phone").map(|r| r.code),
            Some("raw_identifier")
        );
        assert_eq!(explain("raw_identifier"), None);
        assert_eq!(
            explain("contact-window").map(|r| r.code),
            Some("contact-window")
        );
        assert_eq!(explain("no-such-code"), None);
    }
}
