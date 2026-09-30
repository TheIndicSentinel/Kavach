//! Server-side delegation (ADR-004 §6): a child mandate is the intersection
//! of the parent, the requested scope and the sub-agent's passport, so
//! delegated authority can only narrow.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use kavach_domain::mandate::{AgentPassport, DelegationRequest, Mandate};
use kavach_ports::PortError;

fn meet(a: &BTreeSet<String>, b: &BTreeSet<String>) -> BTreeSet<String> {
    a.intersection(b).cloned().collect()
}

/// Ceilings the child may carry: only keys the parent has; each value is the
/// minimum of parent, request (if given) and passport. A key missing from the
/// passport is dropped (that limit cannot be used by the sub-agent).
fn narrow_ceilings(
    parent: &BTreeMap<String, i64>,
    requested: &BTreeMap<String, i64>,
    passport: &BTreeMap<String, i64>,
) -> BTreeMap<String, i64> {
    parent
        .iter()
        .filter_map(|(key, &pv)| {
            let cap = *passport.get(key)?;
            let rv = requested.get(key).copied().unwrap_or(pv);
            Some((key.clone(), pv.min(rv).min(cap)))
        })
        .collect()
}

/// Identity of the child being created.
pub struct ChildIdentity<'a> {
    pub id: String,
    pub nonce: String,
    pub holder: &'a str,
    pub now: DateTime<Utc>,
}

/// Builds the child mandate. Pure; the caller checks holder, depth and
/// eligibility before calling.
pub fn narrow_child(
    parent: &Mandate,
    request: &DelegationRequest,
    passport: &AgentPassport,
    child: &ChildIdentity<'_>,
) -> Result<Mandate, PortError> {
    let actions = meet(&meet(&parent.actions, &request.actions), &passport.actions);
    if actions.is_empty() {
        return Err(PortError::rejected("delegation grants no actions"));
    }
    let window = match (parent.window, request.window) {
        (Some(p), Some(r)) => Some(
            p.intersect(&r)
                .ok_or_else(|| PortError::rejected("requested window does not overlap parent"))?,
        ),
        (Some(p), None) => Some(p),
        (None, r) => r,
    };
    let exp = request.exp.map_or(parent.exp, |e| e.min(parent.exp));
    if exp <= child.now {
        return Err(PortError::rejected(
            "delegated mandate would already be expired",
        ));
    }
    Ok(Mandate {
        mv: parent.mv,
        id: child.id.clone(),
        tenant_id: parent.tenant_id.clone(),
        issuer: parent.issuer.clone(),
        source: parent.source.clone(),
        principal: parent.principal.clone(),
        holder: child.holder.to_string(),
        subject_ref: parent.subject_ref.clone(),
        purpose: parent.purpose.clone(),
        consent_refs: parent.consent_refs.clone(),
        actions,
        data_fields: meet(
            &meet(&parent.data_fields, &request.data_fields),
            &passport.data_fields,
        ),
        channels: meet(&parent.channels, &request.channels),
        window,
        ceilings: narrow_ceilings(&parent.ceilings, &request.ceilings, &passport.ceilings),
        delegation: parent.delegation.clone(),
        parent_id: Some(parent.id.clone()),
        depth: parent.depth.saturating_add(1),
        nbf: child.now.max(parent.nbf),
        exp,
        nonce: child.nonce.clone(),
    })
}

/// True when `child` grants nothing beyond `parent` (used by tests and as a
/// defensive check before signing).
pub fn is_within(child: &Mandate, parent: &Mandate) -> bool {
    child.tenant_id == parent.tenant_id
        && child.subject_ref == parent.subject_ref
        && child.purpose == parent.purpose
        && child.consent_refs == parent.consent_refs
        && child.actions.is_subset(&parent.actions)
        && child.data_fields.is_subset(&parent.data_fields)
        && child.channels.is_subset(&parent.channels)
        && match (child.window, parent.window) {
            (Some(c), Some(p)) => c.is_within(&p),
            (_, None) => true,
            (None, Some(_)) => false,
        }
        && child
            .ceilings
            .iter()
            .all(|(k, v)| parent.ceilings.get(k).is_some_and(|pv| v <= pv))
        && child.exp <= parent.exp
        && child.depth == parent.depth + 1
        && child.depth <= parent.delegation.max_depth
}
