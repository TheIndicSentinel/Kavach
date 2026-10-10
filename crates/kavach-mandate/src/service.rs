//! Mandate issuance, verification, delegation and revocation (ADR-004).

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, DurationRound, TimeDelta, Utc};
use kavach_domain::mandate::{
    is_capability_ref, AgentPassport, DelegationRequest, Mandate, MandateSource, MandateStatus,
    MandateTemplate, RevocationReason, SorEvent, CONTACT_ACTIONS, MANDATE_FORMAT_VERSION,
    MAX_DELEGATION_DEPTH,
};
use kavach_ports::{
    ConsentSource, DomainEvent, EventBus, KeyProvider, MandateStore, PortError, ReplayGuard,
    StoredMandate, StoredRevocation, TimeSource,
};
use sha2::{Digest, Sha256};

use crate::config::MandateConfig;
use crate::delegation::{is_within, narrow_child, ChildIdentity};
use crate::jws::{self, TYP_MANDATE, TYP_SOR_EVENT};

/// A mandate and its signed token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedMandate {
    pub mandate: Mandate,
    pub token: String,
}

/// Result of a revocation. The revocation itself is committed when this is
/// returned; `publish_errors` lists mandates whose revocation event could not
/// be published, so downstream caches and credentials were not told. Until an
/// outbox exists, short credential TTLs are the backstop (ADR-011).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeOutcome {
    pub revoked: Vec<String>,
    pub publish_errors: Vec<(String, String)>,
}

/// The system-of-record event types that revoke (ADR-012), and why.
pub const REVOKING_EVENTS: [(&str, RevocationReason); 2] = [
    ("loan.paid", RevocationReason::Payment),
    ("loan.disputed", RevocationReason::Dispute),
];

/// What a revoking event did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedByEvent {
    pub event_id: String,
    pub event_type: String,
    pub record_ref: String,
    /// Every mandate whose status changed, delegations included.
    pub revoked: Vec<String>,
    /// The same event again: the stored result, nothing revoked now.
    pub replayed: bool,
    /// The revocation as stored (its evidence-chain record is made from it).
    pub stored: StoredRevocation,
}

/// Whether `event_token` names a revoking event type. Only routes the
/// request: the event is fully verified by whichever path handles it.
#[must_use]
pub fn is_revoking_event(event_token: &str) -> bool {
    use base64::Engine as _;
    event_token
        .split('.')
        .nth(1)
        .and_then(|payload| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .ok()
        })
        .and_then(|bytes: Vec<u8>| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|event| event["event_type"].as_str().map(str::to_string))
        .is_some_and(|t| REVOKING_EVENTS.iter().any(|(name, _)| *name == t))
}

/// SHA-256 of an event's content (a struct serializes in a fixed field
/// order, its sets sorted): a retry has the same, a reuse of its id for
/// Whole microseconds, as Postgres keeps a timestamp: the time stored and
/// the time read back are the same.
fn micros(t: DateTime<Utc>) -> DateTime<Utc> {
    t.duration_trunc(TimeDelta::microseconds(1)).unwrap_or(t)
}

/// other content does not.
fn content_sha256(event: &SorEvent) -> Result<String, PortError> {
    let bytes =
        serde_json::to_vec(event).map_err(|e| PortError::invalid(format!("event content: {e}")))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// Adapters the service depends on (ADR-006).
pub struct MandateDeps<K, R, C, S, E, T> {
    pub keys: K,
    pub replay: R,
    pub consents: C,
    pub store: S,
    pub events: E,
    pub clock: T,
}

pub struct MandateService<K, R, C, S, E, T> {
    deps: MandateDeps<K, R, C, S, E, T>,
    config: MandateConfig,
}

impl<K, R, C, S, E, T> MandateService<K, R, C, S, E, T>
where
    K: KeyProvider,
    R: ReplayGuard,
    C: ConsentSource,
    S: MandateStore,
    E: EventBus,
    T: TimeSource,
{
    /// Validates the governed configuration (templates, passports, windows,
    /// ceilings, delegation) before any mandate can be issued.
    pub fn new(
        deps: MandateDeps<K, R, C, S, E, T>,
        config: MandateConfig,
    ) -> Result<Self, PortError> {
        config.validate()?;
        Ok(Self { deps, config })
    }

    pub fn store(&self) -> &S {
        &self.deps.store
    }

    pub fn events(&self) -> &E {
        &self.deps.events
    }

    pub fn clock(&self) -> &T {
        &self.deps.clock
    }

    /// Creates a mandate from a signed system-of-record event (ADR-004 §4–5).
    /// Every field comes from the verified event or the governed template.
    pub async fn issue_from_event(&self, event_token: &str) -> Result<IssuedMandate, PortError> {
        let now = self.deps.clock.now().utc;
        let event = self.verify_event(event_token, now).await?;
        let template = self
            .config
            .template(&event.tenant_id, &event.event_type)
            .ok_or_else(|| {
                PortError::rejected(format!("no mandate template for {}", event.event_type))
            })?;
        let passport = self.check_holder(&event, template)?;
        check_scope_within_passport(template, passport)?;
        if requires_window(&template.actions) && template.window.is_none() {
            return Err(PortError::rejected(
                "template grants contact actions without a contact window",
            ));
        }
        let consent_exp = self.check_consents(&event, &template.purpose, now).await?;

        let exp = (now + Duration::seconds(template.ttl_seconds)).min(consent_exp);
        if template.ttl_seconds <= 0 || exp <= now {
            return Err(PortError::rejected(
                "mandate would be issued already expired",
            ));
        }
        let mandate = Mandate {
            mv: MANDATE_FORMAT_VERSION,
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: event.tenant_id.clone(),
            issuer: self.config.issuer_id.clone(),
            source: MandateSource {
                system: event.system.clone(),
                record_ref: event.record_ref.clone(),
                event_id: event.event_id.clone(),
            },
            principal: event.principal.clone(),
            holder: event.assigned_agent.clone(),
            subject_ref: event.subject_ref.clone(),
            purpose: template.purpose.clone(),
            consent_refs: event.consent_refs.clone(),
            actions: template.actions.clone(),
            data_fields: template.data_fields.clone(),
            channels: template.channels.clone(),
            window: template.window,
            ceilings: template.ceilings.clone(),
            delegation: template.delegation.clone(),
            parent_id: None,
            depth: 0,
            nbf: now,
            exp,
            nonce: uuid::Uuid::new_v4().to_string(),
        };
        self.sign_store_publish(mandate, false).await
    }

    /// For a retried system-of-record event: the root mandate it already
    /// issued, when the event (signature and issuer binding checked, not
    /// freshness or replay) carries the same content. `Ok(None)` when no
    /// mandate exists for it; `Rejected` when the event id was reused with
    /// different content.
    pub async fn existing_for_event(
        &self,
        event_token: &str,
    ) -> Result<Option<IssuedMandate>, PortError> {
        let (kid, event): (String, SorEvent) =
            jws::verify(event_token, TYP_SOR_EVENT, &self.config.sor_keys())?;
        if self.config.sor_system_for_kid(&kid) != Some(event.system.as_str()) {
            return Err(PortError::rejected(format!(
                "key {kid} is not registered for system {}",
                event.system
            )));
        }
        let Some(stored) = self
            .deps
            .store
            .root_for_event(&event.tenant_id, &event.system, &event.event_id)
            .await?
        else {
            return Ok(None);
        };
        let m = &stored.mandate;
        let same = m.subject_ref == event.subject_ref
            && m.holder == event.assigned_agent
            && m.principal == event.principal
            && m.source.record_ref == event.record_ref
            && m.consent_refs == event.consent_refs;
        if !same {
            return Err(PortError::rejected(format!(
                "event {} was already used with different content",
                event.event_id
            )));
        }
        Ok(Some(IssuedMandate {
            mandate: stored.mandate,
            token: stored.token,
        }))
    }

    /// Verifies a mandate token and its whole delegation chain (ADR-004 §3,
    /// ADR-011). For the mandate and every ancestor: signature, the stored
    /// token matches, stored status `Active`, trusted time within
    /// `[nbf, exp)`; and each link is a valid narrowing of its parent. A
    /// valid signature alone is not sufficient.
    pub async fn verify_active(&self, token: &str) -> Result<Mandate, PortError> {
        self.verify_active_chain(token)
            .await
            .map(|(mandate, _)| mandate)
    }

    /// As [`Self::verify_active`], also returning the verified chain of
    /// mandate ids from the root to this mandate (for evidence).
    pub async fn verify_active_chain(
        &self,
        token: &str,
    ) -> Result<(Mandate, Vec<String>), PortError> {
        let (_, claimed): (String, Mandate) =
            jws::verify(token, TYP_MANDATE, &self.config.mandate_keys)?;
        let stored = self
            .deps
            .store
            .get(&claimed.tenant_id, &claimed.id)
            .await?
            .ok_or_else(|| PortError::rejected(format!("unknown mandate {}", claimed.id)))?;
        if stored.token != token {
            return Err(PortError::rejected("token does not match stored mandate"));
        }
        let now = self.deps.clock.now().utc;
        let mandate = self.check_record(&stored, now)?;
        if mandate.depth == 0 {
            return if mandate.parent_id.is_none() {
                let id = mandate.id.clone();
                Ok((mandate, vec![id]))
            } else {
                Err(PortError::rejected("a root mandate cannot have a parent"))
            };
        }

        let chain = self
            .deps
            .store
            .ancestors(
                &mandate.tenant_id,
                &mandate.id,
                usize::from(MAX_DELEGATION_DEPTH) + 1,
            )
            .await?;
        if chain.len() != usize::from(mandate.depth) {
            return Err(PortError::rejected(format!(
                "mandate {} has an incomplete delegation chain",
                mandate.id
            )));
        }
        let mut child = mandate.clone();
        for stored in &chain {
            let parent = self.check_record(stored, now)?;
            if child.parent_id.as_deref() != Some(parent.id.as_str())
                || !crate::delegation::is_within(&child, &parent)
            {
                return Err(PortError::rejected(format!(
                    "mandate {} is not a valid delegation of {}",
                    child.id, parent.id
                )));
            }
            child = parent;
        }
        if child.depth != 0 || child.parent_id.is_some() {
            return Err(PortError::rejected(
                "delegation chain does not end at a root",
            ));
        }
        let mut ids: Vec<String> = chain.iter().rev().map(|s| s.mandate.id.clone()).collect();
        ids.push(mandate.id.clone());
        Ok((mandate, ids))
    }

    /// One stored mandate: its token verifies and decodes to the stored
    /// value, status `Active`, and `now` within `[nbf, exp)`.
    fn check_record(
        &self,
        stored: &StoredMandate,
        now: DateTime<Utc>,
    ) -> Result<Mandate, PortError> {
        let (_, decoded): (String, Mandate) =
            jws::verify(&stored.token, TYP_MANDATE, &self.config.mandate_keys)?;
        if decoded != stored.mandate {
            return Err(PortError::rejected(format!(
                "stored mandate {} differs from its signed token",
                stored.mandate.id
            )));
        }
        if stored.status != MandateStatus::Active {
            return Err(PortError::rejected(format!(
                "mandate {} is revoked",
                decoded.id
            )));
        }
        if now < decoded.nbf || now >= decoded.exp {
            return Err(PortError::rejected(format!(
                "mandate {} is not valid at this time",
                decoded.id
            )));
        }
        Ok(decoded)
    }

    /// Issues a narrower child mandate for `to_agent` (ADR-004 §6).
    pub async fn delegate(
        &self,
        tenant_id: &str,
        parent_id: &str,
        by_agent: &str,
        to_agent: &str,
        request: &DelegationRequest,
    ) -> Result<IssuedMandate, PortError> {
        let parent = self
            .deps
            .store
            .get(tenant_id, parent_id)
            .await?
            .ok_or_else(|| PortError::rejected(format!("unknown mandate {parent_id}")))?;
        let parent = self.verify_active(&parent.token).await?;
        if parent.holder != by_agent {
            return Err(PortError::rejected("only the mandate holder may delegate"));
        }
        if parent.depth >= parent.delegation.max_depth || parent.depth >= MAX_DELEGATION_DEPTH {
            return Err(PortError::rejected("delegation depth limit reached"));
        }
        if !parent.delegation.allowed_agents.contains(to_agent) {
            return Err(PortError::rejected(format!(
                "agent {to_agent} may not receive this mandate"
            )));
        }
        let passport = self
            .config
            .passport(tenant_id, to_agent)
            .ok_or_else(|| PortError::rejected(format!("no passport for {to_agent}")))?;
        if !passport.allowed_purposes.contains(&parent.purpose) {
            return Err(PortError::rejected(format!(
                "agent {to_agent} is not allowed purpose {}",
                parent.purpose
            )));
        }
        let child = narrow_child(
            &parent,
            request,
            passport,
            &ChildIdentity {
                id: uuid::Uuid::new_v4().to_string(),
                nonce: uuid::Uuid::new_v4().to_string(),
                holder: to_agent,
                now: self.deps.clock.now().utc,
            },
        )?;
        if !is_within(&child, &parent) {
            return Err(PortError::rejected(
                "delegated mandate would exceed its parent",
            ));
        }
        // Inserted only while the parent is still active (atomic in the store).
        self.sign_store_publish(child, true).await
    }

    /// Revokes a mandate and every mandate delegated from it, atomically in
    /// the store; then publishes one event per revoked mandate. A publish
    /// failure does not undo the revocation and is reported, not returned as
    /// an error.
    pub async fn revoke(
        &self,
        tenant_id: &str,
        id: &str,
        reason: RevocationReason,
    ) -> Result<RevokeOutcome, PortError> {
        let changed = self.deps.store.revoke_tree(tenant_id, id, reason).await?;
        let mut outcome = RevokeOutcome {
            revoked: Vec::with_capacity(changed.len()),
            publish_errors: Vec::new(),
        };
        for (mandate_id, why) in changed {
            if let Err(err) = self
                .deps
                .events
                .publish(DomainEvent::MandateRevoked {
                    tenant_id: tenant_id.to_string(),
                    mandate_id: mandate_id.clone(),
                    reason: why,
                })
                .await
            {
                outcome
                    .publish_errors
                    .push((mandate_id.clone(), err.to_string()));
            }
            outcome.revoked.push(mandate_id);
        }
        Ok(outcome)
    }

    /// ADR-012: a signed `loan.paid` or `loan.disputed` revokes the live
    /// mandates issued (by `nbf`) at or before it for the same `system` and
    /// record, with their delegations. The event is verified like an
    /// issuing one: a registered issuer key for its system, freshness, the
    /// replay guard. Its result is kept for retries.
    pub async fn revoke_from_event(&self, event_token: &str) -> Result<RevokedByEvent, PortError> {
        let now = self.deps.clock.now().utc;
        let event = self.verify_event(event_token, now).await?;
        let reason = REVOKING_EVENTS
            .iter()
            .find(|(name, _)| *name == event.event_type)
            .map(|(_, reason)| *reason)
            .ok_or_else(|| PortError::rejected(format!("{} does not revoke", event.event_type)))?;
        let roots = self
            .deps
            .store
            .live_roots_for_record(&event.tenant_id, &event.system, &event.record_ref)
            .await?;
        let mut revoked = Vec::new();
        // A revocation never reaches forward: a mandate issued after the
        // event occurred (a new default after a payment) stays. One issued
        // at the same instant is revoked: when in doubt, contact stops.
        for root in roots.iter().filter(|r| r.mandate.nbf <= event.occurred_at) {
            let outcome = self
                .revoke(&event.tenant_id, &root.mandate.id, reason)
                .await?;
            revoked.extend(outcome.revoked);
        }
        let stored = StoredRevocation {
            tenant_id: event.tenant_id.clone(),
            system: event.system.clone(),
            event_id: event.event_id.clone(),
            content_sha256: content_sha256(&event)?,
            event_type: event.event_type.clone(),
            record_ref: event.record_ref.clone(),
            occurred_at: event.occurred_at,
            revoked: revoked.clone(),
            revoked_at: micros(self.deps.clock.now().utc),
        };
        self.deps.store.record_revocation(stored.clone()).await?;
        Ok(RevokedByEvent {
            event_id: event.event_id,
            event_type: event.event_type,
            record_ref: event.record_ref,
            revoked,
            replayed: false,
            stored,
        })
    }

    /// For a retried revoking event: its stored result, when the event
    /// (signature and issuer binding checked, not freshness or replay)
    /// carries the same content. `Ok(None)` when it made none; `Rejected`
    /// when the id was reused with different content.
    pub async fn existing_revocation(
        &self,
        event_token: &str,
    ) -> Result<Option<RevokedByEvent>, PortError> {
        let (kid, event): (String, SorEvent) =
            jws::verify(event_token, TYP_SOR_EVENT, &self.config.sor_keys())?;
        if self.config.sor_system_for_kid(&kid) != Some(event.system.as_str()) {
            return Err(PortError::rejected(format!(
                "key {kid} is not registered for system {}",
                event.system
            )));
        }
        let Some(stored) = self
            .deps
            .store
            .revocation_for_event(&event.tenant_id, &event.system, &event.event_id)
            .await?
        else {
            return Ok(None);
        };
        if stored.content_sha256 != content_sha256(&event)? {
            return Err(PortError::rejected(format!(
                "event {} was already used with different content",
                event.event_id
            )));
        }
        Ok(Some(RevokedByEvent {
            event_id: stored.event_id.clone(),
            event_type: stored.event_type.clone(),
            record_ref: stored.record_ref.clone(),
            revoked: stored.revoked.clone(),
            replayed: true,
            stored,
        }))
    }

    async fn verify_event(&self, token: &str, now: DateTime<Utc>) -> Result<SorEvent, PortError> {
        let (kid, event): (String, SorEvent) =
            jws::verify(token, TYP_SOR_EVENT, &self.config.sor_keys())?;
        if self.config.sor_system_for_kid(&kid) != Some(event.system.as_str()) {
            return Err(PortError::rejected(format!(
                "key {kid} is not registered for system {}",
                event.system
            )));
        }
        let age = (now - event.occurred_at).num_seconds().abs();
        if age > self.config.event_freshness_seconds {
            return Err(PortError::rejected(format!(
                "event {} is stale or from the future ({age}s)",
                event.event_id
            )));
        }
        self.deps
            .replay
            .check_and_record(
                &event.tenant_id,
                &format!("sor:{}:{}", event.system, event.event_id),
                now,
                now + Duration::seconds(self.config.replay_window_seconds),
            )
            .await?;
        if !is_capability_ref(&event.subject_ref) {
            return Err(PortError::invalid(
                "subject_ref must be a capability reference (ref:<type>:<id>)",
            ));
        }
        Ok(event)
    }

    fn check_holder(
        &self,
        event: &SorEvent,
        template: &MandateTemplate,
    ) -> Result<&AgentPassport, PortError> {
        if !template.eligible_agents.contains(&event.assigned_agent) {
            return Err(PortError::rejected(format!(
                "agent {} is not eligible for {}",
                event.assigned_agent, template.event_type
            )));
        }
        self.config
            .passport(&event.tenant_id, &event.assigned_agent)
            .ok_or_else(|| PortError::rejected(format!("no passport for {}", event.assigned_agent)))
    }

    async fn check_consents(
        &self,
        event: &SorEvent,
        purpose: &str,
        now: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, PortError> {
        if event.consent_refs.is_empty() {
            return Err(PortError::rejected("mandate requires at least one consent"));
        }
        let mut earliest: Option<DateTime<Utc>> = None;
        for consent_id in &event.consent_refs {
            let consent = self
                .deps
                .consents
                .get(&event.tenant_id, consent_id)
                .await?
                .ok_or_else(|| PortError::rejected(format!("unknown consent {consent_id}")))?;
            if !consent.active || consent.expires_at <= now {
                return Err(PortError::rejected(format!(
                    "consent {consent_id} is not active"
                )));
            }
            if consent.subject_ref != event.subject_ref {
                return Err(PortError::rejected(format!(
                    "consent {consent_id} is for a different subject"
                )));
            }
            if !consent.purposes.contains(purpose) {
                return Err(PortError::rejected(format!(
                    "consent {consent_id} does not cover purpose {purpose}"
                )));
            }
            earliest = Some(earliest.map_or(consent.expires_at, |e| e.min(consent.expires_at)));
        }
        earliest.ok_or_else(|| PortError::rejected("no consent expiry"))
    }

    async fn sign_store_publish(
        &self,
        mandate: Mandate,
        child: bool,
    ) -> Result<IssuedMandate, PortError> {
        let token = jws::sign(
            &self.deps.keys,
            &self.config.signing_kid,
            TYP_MANDATE,
            &mandate,
        )
        .await?;
        let record = StoredMandate {
            mandate: mandate.clone(),
            token: token.clone(),
            status: MandateStatus::Active,
            revoked_reason: None,
        };
        if child {
            self.deps.store.insert_child(record).await?;
        } else {
            self.deps.store.insert(record).await?;
        }
        self.deps
            .events
            .publish(DomainEvent::MandateIssued {
                tenant_id: mandate.tenant_id.clone(),
                mandate_id: mandate.id.clone(),
            })
            .await?;
        Ok(IssuedMandate { mandate, token })
    }
}

/// True when `actions` include one that contacts the subject.
pub(crate) fn requires_window(actions: &BTreeSet<String>) -> bool {
    CONTACT_ACTIONS.iter().any(|a| actions.contains(*a))
}

/// Issuance validation against the holder's passport (ADR-004 §5): the
/// template's scope must not exceed what the agent may ever be granted.
pub(crate) fn check_scope_within_passport(
    template: &MandateTemplate,
    passport: &AgentPassport,
) -> Result<(), PortError> {
    if !passport.allowed_purposes.contains(&template.purpose) {
        return Err(PortError::rejected(format!(
            "agent {} is not allowed purpose {}",
            passport.agent_id, template.purpose
        )));
    }
    let over = |what: &str, extra: BTreeSet<&String>| -> Result<(), PortError> {
        if extra.is_empty() {
            Ok(())
        } else {
            Err(PortError::rejected(format!(
                "template {what} exceed passport of {}: {extra:?}",
                passport.agent_id
            )))
        }
    };
    over(
        "actions",
        template.actions.difference(&passport.actions).collect(),
    )?;
    over(
        "data fields",
        template
            .data_fields
            .difference(&passport.data_fields)
            .collect(),
    )?;
    let ceilings = MandateConfig::ceilings_exceeding(&template.ceilings, &passport.ceilings);
    if !ceilings.is_empty() {
        return Err(PortError::rejected(format!(
            "template ceilings exceed passport of {}: {ceilings:?}",
            passport.agent_id
        )));
    }
    Ok(())
}
