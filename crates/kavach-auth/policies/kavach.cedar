@id("operators-may-evaluate")
permit (
  principal in Kavach::Group::"operators",
  action == Kavach::Action::"evaluate",
  resource == Kavach::System::"api"
);

@id("viewers-may-read-governance")
permit (
  principal in Kavach::Group::"viewers",
  action == Kavach::Action::"read_governance",
  resource == Kavach::System::"api"
);

@id("operators-may-read-governance")
permit (
  principal in Kavach::Group::"operators",
  action == Kavach::Action::"read_governance",
  resource == Kavach::System::"api"
);

@id("admins-may-read-governance")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"read_governance",
  resource == Kavach::System::"api"
);

@id("admins-may-read-audit")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"read_audit",
  resource == Kavach::System::"api"
);

// One agent decision record by id (`kavach why`). Every read is audited.
@id("admins-may-read-evidence")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"read_evidence",
  resource == Kavach::System::"api"
);

// Move a development clock forward. The endpoint exists only on a dev
// stack started with `kavach dev up --clock`; every change is audited.
@id("admins-may-set-dev-clock")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"set_dev_clock",
  resource == Kavach::System::"api"
);

@id("viewers-may-read-health")
permit (
  principal in Kavach::Group::"viewers",
  action == Kavach::Action::"read_health",
  resource == Kavach::System::"api"
);

@id("admins-may-read-metrics")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"read_metrics",
  resource == Kavach::System::"api"
);

@id("admins-may-evaluate")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"evaluate",
  resource == Kavach::System::"api"
);

@id("admins-may-read-health")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"read_health",
  resource == Kavach::System::"api"
);

@id("admins-may-read-retention")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"read_retention",
  resource == Kavach::System::"api"
);

@id("admins-may-read-tombstones")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"read_tombstones",
  resource == Kavach::System::"api"
);

@id("admins-may-read-incidents")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"read_incidents",
  resource == Kavach::System::"api"
);

@id("admins-may-read-batch-jobs")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"read_batch_jobs",
  resource == Kavach::System::"api"
);

// Change requests (ADR-009): admins propose, a separate change-approvers
// group approves. Keep the groups disjoint in production for separation of duties.

@id("admins-may-propose-activate-pack")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"propose_activate_pack",
  resource == Kavach::System::"api"
);

@id("admins-may-propose-rollback-pack")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"propose_rollback_pack",
  resource == Kavach::System::"api"
);

@id("admins-may-propose-update-model")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"propose_update_model",
  resource == Kavach::System::"api"
);

@id("admins-may-propose-update-retention")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"propose_update_retention",
  resource == Kavach::System::"api"
);

@id("admins-may-propose-erase-evidence")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"propose_erase_evidence",
  resource == Kavach::System::"api"
);

@id("admins-may-propose-apply-retention")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"propose_apply_retention",
  resource == Kavach::System::"api"
);

@id("admins-may-propose-activate-model")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"propose_activate_model",
  resource == Kavach::System::"api"
);

@id("change-approvers-may-approve-activate-model")
permit (
  principal in Kavach::Group::"change-approvers",
  action == Kavach::Action::"approve_activate_model",
  resource == Kavach::System::"api"
);

@id("change-approvers-may-approve-activate-pack")
permit (
  principal in Kavach::Group::"change-approvers",
  action == Kavach::Action::"approve_activate_pack",
  resource == Kavach::System::"api"
);

@id("change-approvers-may-approve-rollback-pack")
permit (
  principal in Kavach::Group::"change-approvers",
  action == Kavach::Action::"approve_rollback_pack",
  resource == Kavach::System::"api"
);

@id("change-approvers-may-approve-update-model")
permit (
  principal in Kavach::Group::"change-approvers",
  action == Kavach::Action::"approve_update_model",
  resource == Kavach::System::"api"
);

@id("change-approvers-may-approve-update-retention")
permit (
  principal in Kavach::Group::"change-approvers",
  action == Kavach::Action::"approve_update_retention",
  resource == Kavach::System::"api"
);

@id("change-approvers-may-approve-erase-evidence")
permit (
  principal in Kavach::Group::"change-approvers",
  action == Kavach::Action::"approve_erase_evidence",
  resource == Kavach::System::"api"
);

@id("change-approvers-may-approve-apply-retention")
permit (
  principal in Kavach::Group::"change-approvers",
  action == Kavach::Action::"approve_apply_retention",
  resource == Kavach::System::"api"
);

@id("admins-may-read-change-requests")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"read_change_requests",
  resource == Kavach::System::"api"
);

@id("change-approvers-may-read-change-requests")
permit (
  principal in Kavach::Group::"change-approvers",
  action == Kavach::Action::"read_change_requests",
  resource == Kavach::System::"api"
);

@id("change-approvers-may-read-governance")
permit (
  principal in Kavach::Group::"change-approvers",
  action == Kavach::Action::"read_governance",
  resource == Kavach::System::"api"
);

// Agent kill switch (ADR-013). Stopping makes things safer and takes one
// principal; bringing an agent back is a change request another principal
// approves. `stop_agent` is its own action so that who may stop an agent
// (for example an on-call incident responder who may not change packs) is a
// policy edit.
@id("admins-may-stop-agent")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"stop_agent",
  resource == Kavach::System::"api"
);

// Snapshot reconciliation (ADR-012 addendum): lists the live authority held
// for loans the lender reports closed. It reads and reports; it changes
// nothing, so it is its own action and who may run it is a policy edit.
@id("admins-may-reconcile-closed-records")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"reconcile_closed_records",
  resource == Kavach::System::"api"
);

@id("admins-may-read-agent-state")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"read_agent_state",
  resource == Kavach::System::"api"
);

@id("admins-may-propose-reinstate-agent")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"propose_reinstate_agent",
  resource == Kavach::System::"api"
);

@id("change-approvers-may-approve-reinstate-agent")
permit (
  principal in Kavach::Group::"change-approvers",
  action == Kavach::Action::"approve_reinstate_agent",
  resource == Kavach::System::"api"
);

// Operator roles (ADR-019 §2). A role is a Kavach::Role parent of the user,
// and only a role binding in Kavach creates one: an IdP group with a role's
// name is a Kavach::Group and gets nothing from these policies. The four
// groups above are kept unchanged as aliases.
//
// The `superadmin-` @id prefix is reserved for superadmin: an audit row is
// flagged acting_as_superadmin when every policy that allowed the request
// has that prefix. Maker-checker (a different approver) is checked before
// Cedar for every role, superadmin included.

@id("superadmin-may-do-everything")
permit (
  principal in Kavach::Role::"superadmin",
  action,
  resource == Kavach::System::"api"
);

@id("role-user-admin-may-read")
permit (
  principal in Kavach::Role::"user_admin",
  action in [
    Kavach::Action::"read_health",
    Kavach::Action::"read_change_requests",
    Kavach::Action::"read_principals",
    Kavach::Action::"read_access_review"
  ],
  resource == Kavach::System::"api"
);

// Only a superadmin may grant or revoke superadmin.
@id("role-user-admin-may-change-roles-except-superadmin")
permit (
  principal in Kavach::Role::"user_admin",
  action in [
    Kavach::Action::"propose_grant_role",
    Kavach::Action::"approve_grant_role",
    Kavach::Action::"propose_revoke_role",
    Kavach::Action::"approve_revoke_role"
  ],
  resource == Kavach::System::"api"
)
when { context.role != "superadmin" };

@id("role-policy-admin-may-read")
permit (
  principal in Kavach::Role::"policy_admin",
  action in [
    Kavach::Action::"read_health",
    Kavach::Action::"read_governance",
    Kavach::Action::"read_incidents",
    Kavach::Action::"read_batch_jobs",
    Kavach::Action::"read_agent_state",
    Kavach::Action::"read_retention",
    Kavach::Action::"read_tombstones",
    Kavach::Action::"read_change_requests"
  ],
  resource == Kavach::System::"api"
);

@id("role-policy-admin-may-propose-governance-changes")
permit (
  principal in Kavach::Role::"policy_admin",
  action in [
    Kavach::Action::"propose_activate_pack",
    Kavach::Action::"propose_rollback_pack",
    Kavach::Action::"propose_update_model",
    Kavach::Action::"propose_activate_model",
    Kavach::Action::"propose_update_retention",
    Kavach::Action::"propose_erase_evidence",
    Kavach::Action::"propose_apply_retention",
    Kavach::Action::"propose_reinstate_agent"
  ],
  resource == Kavach::System::"api"
);

@id("role-approver-may-read")
permit (
  principal in Kavach::Role::"approver",
  action in [
    Kavach::Action::"read_health",
    Kavach::Action::"read_governance",
    Kavach::Action::"read_retention",
    Kavach::Action::"read_tombstones",
    Kavach::Action::"read_change_requests"
  ],
  resource == Kavach::System::"api"
);

@id("role-approver-may-approve-governance-changes")
permit (
  principal in Kavach::Role::"approver",
  action in [
    Kavach::Action::"approve_activate_pack",
    Kavach::Action::"approve_rollback_pack",
    Kavach::Action::"approve_update_model",
    Kavach::Action::"approve_activate_model",
    Kavach::Action::"approve_update_retention",
    Kavach::Action::"approve_erase_evidence",
    Kavach::Action::"approve_apply_retention",
    Kavach::Action::"approve_reinstate_agent"
  ],
  resource == Kavach::System::"api"
);

@id("role-approver-may-approve-human-review")
permit (
  principal in Kavach::Role::"approver",
  action == Kavach::Action::"approve_human_review",
  resource == Kavach::System::"api"
);

@id("role-operator-may-run-the-system")
permit (
  principal in Kavach::Role::"operator",
  action in [
    Kavach::Action::"read_health",
    Kavach::Action::"read_governance",
    Kavach::Action::"read_metrics",
    Kavach::Action::"evaluate",
    Kavach::Action::"read_incidents",
    Kavach::Action::"read_batch_jobs",
    Kavach::Action::"read_agent_state",
    Kavach::Action::"stop_agent",
    Kavach::Action::"reconcile_closed_records",
    Kavach::Action::"attest_outcome_delivered",
    Kavach::Action::"attest_outcome_not_delivered",
    Kavach::Action::"resolve_outcome_conflict"
  ],
  resource == Kavach::System::"api"
);

@id("role-auditor-may-read-everything")
permit (
  principal in Kavach::Role::"auditor",
  action in [
    Kavach::Action::"read_health",
    Kavach::Action::"read_governance",
    Kavach::Action::"read_metrics",
    Kavach::Action::"read_incidents",
    Kavach::Action::"read_batch_jobs",
    Kavach::Action::"read_agent_state",
    Kavach::Action::"read_retention",
    Kavach::Action::"read_tombstones",
    Kavach::Action::"read_change_requests",
    Kavach::Action::"read_audit",
    Kavach::Action::"read_evidence",
    Kavach::Action::"read_principals",
    Kavach::Action::"read_access_review"
  ],
  resource == Kavach::System::"api"
);

@id("role-viewer-may-read-governance-and-health")
permit (
  principal in Kavach::Role::"viewer",
  action in [
    Kavach::Action::"read_health",
    Kavach::Action::"read_governance"
  ],
  resource == Kavach::System::"api"
);
