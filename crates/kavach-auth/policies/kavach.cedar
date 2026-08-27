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
