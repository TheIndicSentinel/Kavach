//! What-if decisions (`kavach authorize`): the authorization core in
//! pre-check mode over a store that holds nothing.
//!
//! [`WhatIfStore`] reports a contact count the caller chooses and refuses
//! every write, so a what-if run can never record evidence or reserve a
//! contact, even if a caller asked for [`Mode::Commit`](crate::Mode).

use std::future::{ready, Future};

use chrono::NaiveDate;
use kavach_ports::agent_evidence::{
    AgentDecisionRecord, AgentEvidenceStore, CommitRequest, CommitResult, EvidenceSigner,
    OutcomeRecord,
};
use kavach_ports::chain_record::{ChainRecord, RevocationDraft, RevocationRecord};
use kavach_ports::{PortError, TimeSource};

const NOTHING_RECORDED: &str = "a what-if run records nothing";

/// An evidence store for what-if runs: no records, a fixed contact count.
#[derive(Debug, Clone, Copy, Default)]
pub struct WhatIfStore {
    /// Contacts the subject has had today (IST), as the caller supposes.
    pub contacts_today: u32,
}

impl AgentEvidenceStore for WhatIfStore {
    fn commit(
        &self,
        _request: CommitRequest,
        _clock: &dyn TimeSource,
        _signer: &dyn EvidenceSigner,
    ) -> impl Future<Output = Result<CommitResult, PortError>> + Send {
        ready(Err(PortError::invalid(NOTHING_RECORDED)))
    }

    fn get_by_request(
        &self,
        _tenant_id: &str,
        _agent_id: &str,
        _request_id: &str,
    ) -> impl Future<Output = Result<Option<AgentDecisionRecord>, PortError>> + Send {
        ready(Ok(None))
    }

    fn record_outcome(
        &self,
        _outcome: OutcomeRecord,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        ready(Err(PortError::invalid(NOTHING_RECORDED)))
    }

    fn outcome(
        &self,
        _tenant_id: &str,
        _credential_id: &str,
    ) -> impl Future<Output = Result<Option<OutcomeRecord>, PortError>> + Send {
        ready(Ok(None))
    }

    fn records(
        &self,
        _tenant_id: &str,
        _partition_id: i32,
    ) -> impl Future<Output = Result<Vec<ChainRecord>, PortError>> + Send {
        ready(Ok(Vec::new()))
    }

    fn append_revocation(
        &self,
        _draft: RevocationDraft,
        _clock: &dyn TimeSource,
        _signer: &dyn EvidenceSigner,
    ) -> impl Future<Output = Result<RevocationRecord, PortError>> + Send {
        ready(Err(PortError::invalid(NOTHING_RECORDED)))
    }

    fn revocation_record(
        &self,
        _tenant_id: &str,
        _source_system: &str,
        _event_id: &str,
    ) -> impl Future<Output = Result<Option<RevocationRecord>, PortError>> + Send {
        ready(Ok(None))
    }

    fn record(
        &self,
        _tenant_id: &str,
        _record_id: &str,
    ) -> impl Future<Output = Result<Option<AgentDecisionRecord>, PortError>> + Send {
        ready(Ok(None))
    }

    fn contacts_on(
        &self,
        _tenant_id: &str,
        _subject_pseudonym: &str,
        _ist_date: NaiveDate,
    ) -> impl Future<Output = Result<u32, PortError>> + Send {
        ready(Ok(self.contacts_today))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_reports_the_supposed_contacts_and_holds_nothing() {
        let store = WhatIfStore { contacts_today: 2 };
        let day = NaiveDate::from_ymd_opt(2026, 10, 4).unwrap();
        assert_eq!(store.contacts_on("t", "p", day).await.unwrap(), 2);
        assert!(store.records("t", 0).await.unwrap().is_empty());
        assert!(store.get_by_request("t", "a", "r").await.unwrap().is_none());
        assert!(store.outcome("t", "c").await.unwrap().is_none());
        assert!(store
            .revocation_record("t", "lms", "e")
            .await
            .unwrap()
            .is_none());
    }
}
