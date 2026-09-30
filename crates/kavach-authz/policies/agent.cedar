// Kavach agent authorization policies (ADR-003, ADR-011).
// Default deny. Only the mandate holder may perform actions listed in the
// mandate; each action has exactly one permit, naming that action (checked at
// load and proven in CI). Unannotated forbids => BLOCK. Forbids annotated
// @escalate("human_review") => HUMAN_REVIEW when they are the only reason for
// the deny; they are lifted only by an approval bound to the exact action.
// Every policy must carry @id. Properties are proven in CI (M1.5b, H4).

@id("permit-read-fields")
permit (principal, action == Kavach::Agent::Action::"read_fields", resource)
when {
  principal == context.mandate_holder &&
  context.mandate_actions.contains("read_fields")
};

@id("permit-send-reminder")
permit (principal, action == Kavach::Agent::Action::"send_reminder", resource)
when {
  principal == context.mandate_holder &&
  context.mandate_actions.contains("send_reminder")
};

@id("permit-place-call")
permit (principal, action == Kavach::Agent::Action::"place_call", resource)
when {
  principal == context.mandate_holder &&
  context.mandate_actions.contains("place_call")
};

@id("permit-propose-plan")
permit (principal, action == Kavach::Agent::Action::"propose_plan", resource)
when {
  principal == context.mandate_holder &&
  context.mandate_actions.contains("propose_plan")
};

@id("permit-update-status")
permit (principal, action == Kavach::Agent::Action::"update_status", resource)
when {
  principal == context.mandate_holder &&
  context.mandate_actions.contains("update_status")
};

@id("subject-binding")
forbid (principal, action, resource)
when { resource != context.mandate_subject };

@id("fields-within-mandate")
forbid (principal, action, resource)
unless { context.mandate_fields.containsAll(context.requested_fields) };

// Missing or out-of-range parameters fail closed.
@id("fields-required")
forbid (principal, action == Kavach::Agent::Action::"read_fields", resource)
unless { context.has_requested_fields };

@id("waiver-required")
forbid (principal, action == Kavach::Agent::Action::"propose_plan", resource)
unless { context.has_waiver };

@id("waiver-in-range")
forbid (principal, action == Kavach::Agent::Action::"propose_plan", resource)
when { context.waiver_bps < 0 || context.waiver_bps > 10000 };

@id("channel-required")
forbid (
  principal,
  action in [Kavach::Agent::Action::"send_reminder", Kavach::Agent::Action::"place_call"],
  resource
)
unless { context.has_channel };

@id("contact-count-valid")
forbid (
  principal,
  action in [Kavach::Agent::Action::"send_reminder", Kavach::Agent::Action::"place_call"],
  resource
)
when { context.contacts_today < 0 };

// Contacting the subject needs a mandate window. The floor below applies to
// contact actions only (not read_fields or other actions): 08:00-19:00 IST,
// per RBI directions on recovery agents (pending compliance sign-off; the
// values equal CONTACT_FLOOR_* in kavach-domain, kept equal by a test).
@id("contact-window-required")
forbid (
  principal,
  action in [Kavach::Agent::Action::"send_reminder", Kavach::Agent::Action::"place_call"],
  resource
)
unless { context.has_window };

@id("contact-hours-floor")
forbid (
  principal,
  action in [Kavach::Agent::Action::"send_reminder", Kavach::Agent::Action::"place_call"],
  resource
)
when { context.ist_minute_of_day < 480 || context.ist_minute_of_day >= 1140 };

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
