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
