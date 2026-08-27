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

@id("admins-may-activate-pack")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"activate_pack",
  resource == Kavach::System::"api"
);

@id("admins-may-rollback-pack")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"rollback_pack",
  resource == Kavach::System::"api"
);

@id("admins-may-update-model")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"update_model",
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

@id("admins-may-update-retention")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"update_retention",
  resource == Kavach::System::"api"
);

@id("admins-may-read-tombstones")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"read_tombstones",
  resource == Kavach::System::"api"
);

@id("admins-may-erase-evidence")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"erase_evidence",
  resource == Kavach::System::"api"
);

@id("admins-may-apply-retention")
permit (
  principal in Kavach::Group::"admins",
  action == Kavach::Action::"apply_retention",
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
