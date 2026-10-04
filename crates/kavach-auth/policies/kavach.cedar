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
