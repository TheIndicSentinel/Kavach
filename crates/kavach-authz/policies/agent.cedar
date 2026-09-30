// Kavach agent authorization policies (ADR-003).
// Default deny. Only the mandate holder may perform actions listed in the
// mandate. Unannotated forbids => BLOCK. Forbids annotated
// @escalate("human_review") => HUMAN_REVIEW when they are the only reason for
// the deny; they are lifted only by an approval bound to the exact action.
// Every policy must carry @id. Properties are proven in CI (M1.5b).

@id("base-permit")
permit (principal, action, resource)
when {
  principal == context.mandate_holder &&
  context.mandate_actions.contains(
    if action == Kavach::Agent::Action::"read_fields" then "read_fields"
    else if action == Kavach::Agent::Action::"send_reminder" then "send_reminder"
    else if action == Kavach::Agent::Action::"place_call" then "place_call"
    else if action == Kavach::Agent::Action::"propose_plan" then "propose_plan"
    else "update_status")
};

@id("subject-binding")
forbid (principal, action, resource)
when { resource != context.mandate_subject };

@id("fields-within-mandate")
forbid (principal, action, resource)
unless { context.mandate_fields.containsAll(context.requested_fields) };

@id("contact-window")
forbid (
  principal,
  action in [Kavach::Agent::Action::"send_reminder", Kavach::Agent::Action::"place_call"],
  resource
)
when {
  context.has_window &&
  (context.ist_minute_of_day < context.window_from ||
   context.ist_minute_of_day >= context.window_to)
};

@id("contact-daily-cap")
forbid (
  principal,
  action in [Kavach::Agent::Action::"send_reminder", Kavach::Agent::Action::"place_call"],
  resource
)
when { context.has_window && context.contacts_today >= context.max_per_day };

@id("channel-within-mandate")
forbid (
  principal,
  action in [Kavach::Agent::Action::"send_reminder", Kavach::Agent::Action::"place_call"],
  resource
)
unless { context.mandate_channels.contains(context.channel) };

@id("agent-restricted")
forbid (principal, action, resource)
when { context.agent_restricted };

@id("waiver-ceiling")
@escalate("human_review")
forbid (principal, action == Kavach::Agent::Action::"propose_plan", resource)
when {
  !context.has_waiver_ceiling ||
  context.waiver_bps > context.waiver_ceiling_bps
}
unless { context.approval_valid };

@id("tainted-critical")
@escalate("human_review")
forbid (
  principal,
  action in [Kavach::Agent::Action::"propose_plan", Kavach::Agent::Action::"update_status"],
  resource
)
when { context.task_tainted }
unless { context.approval_valid };
