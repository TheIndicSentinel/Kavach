//! A fixture `ReferenceResolver` (H5b): capability references to
//! destinations from a JSON file. A Postgres reference vault with
//! crypto-shredding replaces it in M2.
//!
//! **Synthetic numbers only.** Every destination must be `+910` followed by
//! nine digits: a +91 number whose first digit is 0, which is never
//! assigned to an Indian mobile (those start with 6-9). The fixture cannot
//! hold a real person's number, so it is safe in demos and pilots, and
//! loading refuses anything else without echoing the value.

use std::collections::BTreeMap;
use std::future::{ready, Future};
use std::path::Path;

use kavach_domain::mandate::is_capability_ref;
use kavach_ports::{Destination, PortError, ReferenceResolver};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureFile {
    references: Vec<FixtureEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureEntry {
    tenant_id: String,
    subject_ref: String,
    destinations: BTreeMap<String, String>,
}

/// `+910` followed by nine digits.
pub fn is_synthetic_number(value: &str) -> bool {
    value
        .strip_prefix("+910")
        .is_some_and(|rest| rest.len() == 9 && rest.bytes().all(|b| b.is_ascii_digit()))
}

fn is_channel(value: &str) -> bool {
    (1..=32).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

pub struct FixtureResolver {
    entries: BTreeMap<(String, String), BTreeMap<String, Destination>>,
}

impl FixtureResolver {
    pub fn from_json(text: &str) -> Result<Self, PortError> {
        let file: FixtureFile = serde_json::from_str(text)
            .map_err(|_| PortError::invalid("reference fixture: malformed JSON"))?;
        let mut entries = BTreeMap::new();
        for entry in file.references {
            if !is_capability_ref(&entry.subject_ref) {
                return Err(PortError::invalid(
                    "reference fixture: subject_ref must be a capability reference",
                ));
            }
            let mut destinations = BTreeMap::new();
            for (channel, value) in entry.destinations {
                if !is_channel(&channel) {
                    return Err(PortError::invalid(format!(
                        "reference fixture {}: channel names are [a-z0-9_]{{1,32}}",
                        entry.subject_ref
                    )));
                }
                if !is_synthetic_number(&value) {
                    return Err(PortError::invalid(format!(
                        "reference fixture {} {channel}: only synthetic numbers \
                         (+910 followed by 9 digits) are accepted",
                        entry.subject_ref
                    )));
                }
                destinations.insert(channel, Destination::new(value));
            }
            if destinations.is_empty() {
                return Err(PortError::invalid(format!(
                    "reference fixture {}: no destinations",
                    entry.subject_ref
                )));
            }
            let key = (entry.tenant_id, entry.subject_ref);
            if entries.contains_key(&key) {
                return Err(PortError::invalid(format!(
                    "reference fixture: {} is listed twice",
                    key.1
                )));
            }
            entries.insert(key, destinations);
        }
        Ok(Self { entries })
    }

    pub fn from_file(path: &Path) -> Result<Self, PortError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            PortError::unavailable(format!("read reference fixture {}: {e}", path.display()))
        })?;
        Self::from_json(&text)
    }

    fn lookup(
        &self,
        tenant_id: &str,
        subject_ref: &str,
        channel: &str,
    ) -> Result<Destination, PortError> {
        if !is_capability_ref(subject_ref) {
            return Err(PortError::invalid(
                "subject_ref must be a capability reference",
            ));
        }
        if !is_channel(channel) {
            return Err(PortError::invalid("channel names are [a-z0-9_]{1,32}"));
        }
        self.entries
            .get(&(tenant_id.to_string(), subject_ref.to_string()))
            .and_then(|by_channel| by_channel.get(channel))
            .cloned()
            .ok_or_else(|| {
                PortError::rejected(format!("no {channel} destination for {subject_ref}"))
            })
    }
}

impl ReferenceResolver for FixtureResolver {
    fn resolve(
        &self,
        tenant_id: &str,
        subject_ref: &str,
        channel: &str,
    ) -> impl Future<Output = Result<Destination, PortError>> + Send {
        ready(self.lookup(tenant_id, subject_ref, channel))
    }

    fn describe(&self) -> String {
        format!("synthetic fixture ({} references)", self.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kavach_ports_testkit::reference_resolver::{conformance, seed};

    fn seeded() -> FixtureResolver {
        let references: Vec<serde_json::Value> = seed()
            .into_iter()
            .map(|e| {
                serde_json::json!({
                    "tenant_id": e.tenant_id,
                    "subject_ref": e.subject_ref,
                    "destinations": e.destinations.iter().copied().collect::<BTreeMap<_, _>>(),
                })
            })
            .collect();
        FixtureResolver::from_json(&serde_json::json!({ "references": references }).to_string())
            .unwrap()
    }

    #[tokio::test]
    async fn fixture_resolver_meets_the_contract() {
        conformance(&seeded()).await;
    }

    #[test]
    fn only_synthetic_numbers_load_and_values_are_never_echoed() {
        assert!(is_synthetic_number("+910000000001"));
        for real_shaped in [
            "+919876543210",
            "9876543210",
            "+9100000000",
            "+910000000001 ",
            "+91000000000a",
        ] {
            assert!(!is_synthetic_number(real_shaped), "{real_shaped}");
        }
        let load = |destination: &str| {
            FixtureResolver::from_json(
                &serde_json::json!({ "references": [{
                    "tenant_id": "t", "subject_ref": "ref:borrower:B-1",
                    "destinations": { "whatsapp": destination }
                }]})
                .to_string(),
            )
        };
        let err = load("+919876543210")
            .err()
            .expect("a real-shaped number is refused");
        assert!(err.message.contains("synthetic"), "{}", err.message);
        assert!(!err.message.contains("9876543210"), "{}", err.message);

        // A raw value as the reference, unknown keys, duplicates.
        let raw = FixtureResolver::from_json(
            r#"{"references":[{"tenant_id":"t","subject_ref":"+910000000001","destinations":{"sms":"+910000000001"}}]}"#,
        );
        assert!(raw.is_err());
        assert!(FixtureResolver::from_json(r#"{"references":[],"extra":1}"#).is_err());
        let twice = serde_json::json!({ "references": [
            { "tenant_id": "t", "subject_ref": "ref:borrower:B-1", "destinations": { "sms": "+910000000001" } },
            { "tenant_id": "t", "subject_ref": "ref:borrower:B-1", "destinations": { "sms": "+910000000002" } },
        ]});
        assert!(FixtureResolver::from_json(&twice.to_string()).is_err());
    }
}
