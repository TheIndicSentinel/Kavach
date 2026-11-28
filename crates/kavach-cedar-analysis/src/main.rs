//! Formal analysis of the Kavach agent policies (ADR-003 §6, PRD success
//! criteria) and of the operator role policies (ADR-019 §2). CI-only:
//! requires the cvc5 1.3.1 solver at `$CVC5` and is never linked into
//! shipped binaries.
//!
//! Each property is stated as a policy that permits exactly the forbidden
//! requests. The property holds when no request can be allowed by both the
//! shipped policies and that policy (`check_disjoint`), for every request
//! environment in the schema. Sanity checks then weaken the shipped policies on
//! purpose and require the analysis to report a violation, so a vacuous pass
//! (e.g. a mis-stated property) fails the job.
//!
//! The review lift (AUTHZ-01, ADR-003) adds two checks on the agent
//! policies: (i) over requests with `approval_valid == true`, the shipped set
//! and the shipped set without its `@escalate` forbids allow exactly the same
//! requests; (ii) no policy reads `approval_valid` except in the `unless`
//! clause of an `@escalate` forbid. With "no policy can raise an evaluation
//! error", they mean an approval lifts the escalate forbids and nothing else:
//! the combiner's re-run with `approval_valid = true` is Allow exactly when a
//! permit is satisfied and no other forbid is.

use std::process::ExitCode;
use std::str::FromStr;

use cedar_policy::{Policy, PolicyId, PolicySet, Schema};
use cedar_policy_symcc::{
    solver::LocalSolver, CedarSymCompiler, CompiledPolicy, CompiledPolicySet,
};
use kavach_auth::{API_POLICIES, API_SCHEMA};
use kavach_authz::{AGENT_POLICIES, AGENT_SCHEMA};

/// (name, policy permitting exactly the requests the property forbids).
const PROPERTIES: [(&str, &str); 18] = [
    (
        "no waiver above the mandate ceiling is allowed without an action-bound approval",
        r#"permit (principal, action == Kavach::Agent::Action::"propose_plan", resource)
           when { context.has_waiver_ceiling
                  && context.waiver_bps > context.waiver_ceiling_bps
                  && !context.approval_valid };"#,
    ),
    (
        "no action is allowed on a subject other than the mandate's",
        r"permit (principal, action, resource)
           when { resource != context.mandate_subject };",
    ),
    (
        "no contact is allowed outside the mandate's IST window",
        r#"permit (principal, action in [Kavach::Agent::Action::"send_reminder", Kavach::Agent::Action::"place_call"], resource)
           when { context.has_window
                  && (context.ist_minute_of_day < context.window_from
                      || context.ist_minute_of_day >= context.window_to) };"#,
    ),
    (
        "read_fields is allowed only when the mandate lists read_fields",
        r#"permit (principal, action == Kavach::Agent::Action::"read_fields", resource)
           when { !context.mandate_actions.contains("read_fields") };"#,
    ),
    (
        "send_reminder is allowed only when the mandate lists send_reminder",
        r#"permit (principal, action == Kavach::Agent::Action::"send_reminder", resource)
           when { !context.mandate_actions.contains("send_reminder") };"#,
    ),
    (
        "place_call is allowed only when the mandate lists place_call",
        r#"permit (principal, action == Kavach::Agent::Action::"place_call", resource)
           when { !context.mandate_actions.contains("place_call") };"#,
    ),
    (
        "propose_plan is allowed only when the mandate lists propose_plan",
        r#"permit (principal, action == Kavach::Agent::Action::"propose_plan", resource)
           when { !context.mandate_actions.contains("propose_plan") };"#,
    ),
    (
        "update_status is allowed only when the mandate lists update_status",
        r#"permit (principal, action == Kavach::Agent::Action::"update_status", resource)
           when { !context.mandate_actions.contains("update_status") };"#,
    ),
    (
        "no action is allowed for anyone but the mandate holder",
        r"permit (principal, action, resource)
           when { principal != context.mandate_holder };",
    ),
    (
        "no plan is allowed without a waiver amount",
        r#"permit (principal, action == Kavach::Agent::Action::"propose_plan", resource)
           when { !context.has_waiver };"#,
    ),
    (
        "no plan is allowed with a waiver outside 0..=10000 bps",
        r#"permit (principal, action == Kavach::Agent::Action::"propose_plan", resource)
           when { context.waiver_bps < 0 || context.waiver_bps > 10000 };"#,
    ),
    (
        "no field read is allowed without requested fields",
        r#"permit (principal, action == Kavach::Agent::Action::"read_fields", resource)
           when { !context.has_requested_fields };"#,
    ),
    (
        "no contact is allowed without a channel",
        r#"permit (principal, action in [Kavach::Agent::Action::"send_reminder", Kavach::Agent::Action::"place_call"], resource)
           when { !context.has_channel };"#,
    ),
    (
        "no contact is allowed without a mandate window",
        r#"permit (principal, action in [Kavach::Agent::Action::"send_reminder", Kavach::Agent::Action::"place_call"], resource)
           when { !context.has_window };"#,
    ),
    (
        "no contact is allowed outside 08:00-19:00 IST",
        r#"permit (principal, action in [Kavach::Agent::Action::"send_reminder", Kavach::Agent::Action::"place_call"], resource)
           when { context.ist_minute_of_day < 480 || context.ist_minute_of_day >= 1140 };"#,
    ),
    (
        "a restricted agent is allowed nothing but reading fields",
        r#"permit (principal, action in [Kavach::Agent::Action::"send_reminder", Kavach::Agent::Action::"place_call", Kavach::Agent::Action::"propose_plan", Kavach::Agent::Action::"update_status"], resource)
           when { context.agent_restricted };"#,
    ),
    (
        "a quarantined or revoked agent is allowed nothing at all",
        r"permit (principal, action, resource)
           when { context.agent_stopped };",
    ),
    (
        "no contact is allowed at or above the daily cap, or with a negative count",
        r#"permit (principal, action in [Kavach::Agent::Action::"send_reminder", Kavach::Agent::Action::"place_call"], resource)
           when { context.contacts_today < 0
                  || context.contacts_today >= context.max_per_day };"#,
    ),
];

/// Weakened variants that must be caught: (label, anchor to replace, replacement).
const SANITY_VARIANTS: [(&str, &str, &str); 12] = [
    (
        "waiver ceiling relaxed by 500 bps",
        r"context.waiver_bps > context.waiver_ceiling_bps",
        r"context.waiver_bps > context.waiver_ceiling_bps + 500",
    ),
    (
        "subject binding removed",
        r"when { resource != context.mandate_subject };",
        r"when { false };",
    ),
    (
        "contact window end extended by 60 minutes",
        r"context.ist_minute_of_day >= context.window_to)",
        r"context.ist_minute_of_day >= context.window_to + 60)",
    ),
    (
        "contact floor widened by an hour",
        r"context.ist_minute_of_day >= 1140",
        r"context.ist_minute_of_day >= 1200",
    ),
    (
        "update_status permit checks another action's name",
        r#"context.mandate_actions.contains("update_status")"#,
        r#"context.mandate_actions.contains("read_fields")"#,
    ),
    (
        "missing-waiver guard removed",
        r"unless { context.has_waiver };",
        r"unless { true };",
    ),
    (
        "restricted agents unrestricted",
        r"when { context.agent_restricted };",
        r"when { false };",
    ),
    (
        "stopped agents unstopped",
        r"when { context.agent_stopped };",
        r"when { false };",
    ),
    (
        "negative contact count allowed",
        r"when { context.contacts_today < 0 };",
        r"when { false };",
    ),
    (
        "propose_plan permit drops the holder condition",
        "principal == context.mandate_holder &&\n  context.mandate_actions.contains(\"propose_plan\")",
        "context.mandate_actions.contains(\"propose_plan\")",
    ),
    (
        "a permit reads approval_valid",
        "context.mandate_actions.contains(\"propose_plan\")\n};",
        "context.mandate_actions.contains(\"propose_plan\") &&\n  !context.approval_valid\n};",
    ),
    (
        "escalate forbid without its unless",
        "when { context.task_tainted }\nunless { context.approval_valid };",
        "when { context.task_tainted };",
    ),
];

/// The four role-change actions, as a Cedar action list.
const ROLE_CHANGES: &str = r#"[Kavach::Action::"propose_grant_role", Kavach::Action::"approve_grant_role", Kavach::Action::"propose_revoke_role", Kavach::Action::"approve_revoke_role"]"#;

/// Operator policy properties (ADR-019 §2): (name, policy permitting exactly
/// the forbidden requests). `{ROLE_CHANGES}` is replaced before parsing.
const OPERATOR_PROPERTIES: [(&str, &str); 5] = [
    (
        "only superadmin may propose or approve a grant or revoke of superadmin",
        r#"permit (principal, action in {ROLE_CHANGES}, resource)
           when { context.role == "superadmin" }
           unless { principal in Kavach::Role::"superadmin" };"#,
    ),
    (
        "only superadmin and user_admin may change a role binding; no alias group may",
        r#"permit (principal, action in {ROLE_CHANGES}, resource)
           unless { principal in Kavach::Role::"superadmin"
                    || principal in Kavach::Role::"user_admin" };"#,
    ),
    (
        "only superadmin, user_admin and auditor may read the principals or the access review",
        r#"permit (principal, action in [Kavach::Action::"read_principals", Kavach::Action::"read_access_review"], resource)
           unless { principal in Kavach::Role::"superadmin"
                    || principal in Kavach::Role::"user_admin"
                    || principal in Kavach::Role::"auditor" };"#,
    ),
    (
        "only superadmin and approver may approve one HUMAN_REVIEW action",
        r#"permit (principal, action == Kavach::Action::"approve_human_review", resource)
           unless { principal in Kavach::Role::"superadmin"
                    || principal in Kavach::Role::"approver" };"#,
    ),
    (
        "viewer and auditor are allowed no change, approval, evaluation, agent stop or dev clock",
        r#"permit (principal, action in [
             Kavach::Action::"evaluate", Kavach::Action::"stop_agent", Kavach::Action::"set_dev_clock",
             Kavach::Action::"propose_activate_pack", Kavach::Action::"approve_activate_pack",
             Kavach::Action::"propose_rollback_pack", Kavach::Action::"approve_rollback_pack",
             Kavach::Action::"propose_update_model", Kavach::Action::"approve_update_model",
             Kavach::Action::"propose_activate_model", Kavach::Action::"approve_activate_model",
             Kavach::Action::"propose_update_retention", Kavach::Action::"approve_update_retention",
             Kavach::Action::"propose_erase_evidence", Kavach::Action::"approve_erase_evidence",
             Kavach::Action::"propose_apply_retention", Kavach::Action::"approve_apply_retention",
             Kavach::Action::"propose_reinstate_agent", Kavach::Action::"approve_reinstate_agent",
             Kavach::Action::"approve_human_review",
             Kavach::Action::"propose_grant_role", Kavach::Action::"approve_grant_role",
             Kavach::Action::"propose_revoke_role", Kavach::Action::"approve_revoke_role"], resource)
           when { principal in Kavach::Role::"viewer" || principal in Kavach::Role::"auditor" }
           unless { principal in Kavach::Role::"superadmin"
                    || principal in Kavach::Role::"user_admin"
                    || principal in Kavach::Role::"policy_admin"
                    || principal in Kavach::Role::"approver"
                    || principal in Kavach::Role::"operator"
                    || principal in Kavach::Group::"admins"
                    || principal in Kavach::Group::"change-approvers"
                    || principal in Kavach::Group::"operators" };"#,
    ),
];

/// Weakened operator policies that must be caught.
const OPERATOR_SANITY_VARIANTS: [(&str, &str, &str); 5] = [
    (
        "user_admin may change superadmin",
        r#"when { context.role != "superadmin" };"#,
        r"when { true };",
    ),
    (
        "an alias group may change roles",
        "  principal in Kavach::Role::\"user_admin\",\n  action in [\n    Kavach::Action::\"propose_grant_role\",",
        "  principal in Kavach::Group::\"admins\",\n  action in [\n    Kavach::Action::\"propose_grant_role\",",
    ),
    (
        "the change-approvers group may approve human review",
        "  principal in Kavach::Role::\"approver\",\n  action == Kavach::Action::\"approve_human_review\",",
        "  principal in Kavach::Group::\"change-approvers\",\n  action == Kavach::Action::\"approve_human_review\",",
    ),
    (
        "viewer may read the access review",
        "    Kavach::Action::\"read_governance\"\n  ],",
        "    Kavach::Action::\"read_governance\",\n    Kavach::Action::\"read_access_review\"\n  ],",
    ),
    (
        "auditor may approve a pack activation",
        "    Kavach::Action::\"read_evidence\",\n    Kavach::Action::\"read_principals\",",
        "    Kavach::Action::\"read_evidence\",\n    Kavach::Action::\"approve_activate_pack\",\n    Kavach::Action::\"read_principals\",",
    ),
];

type Compiler = CedarSymCompiler<LocalSolver>;

async fn property_holds(
    compiler: &mut Compiler,
    schema: &Schema,
    policies: &PolicySet,
    bad: &PolicySet,
) -> Result<bool, String> {
    for env in schema.request_envs() {
        let ours = CompiledPolicySet::compile(policies, &env, schema).map_err(|e| e.to_string())?;
        let forbidden = CompiledPolicySet::compile(bad, &env, schema).map_err(|e| e.to_string())?;
        if !compiler
            .check_disjoint_opt(&ours, &forbidden)
            .await
            .map_err(|e| e.to_string())?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn never_errors(
    compiler: &mut Compiler,
    schema: &Schema,
    policies: &PolicySet,
) -> Result<bool, String> {
    for env in schema.request_envs() {
        for policy in policies.policies() {
            let single =
                CompiledPolicy::compile(policy, &env, schema).map_err(|e| e.to_string())?;
            if !compiler
                .check_never_errors_opt(&single)
                .await
                .map_err(|e| e.to_string())?
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// (i): over requests with `approval_valid == true`, `policies` and
/// `policies` without its `@escalate` forbids allow the same requests.
async fn approval_lifts_only_escalations(
    compiler: &mut Compiler,
    schema: &Schema,
    policies: &PolicySet,
) -> Result<bool, String> {
    let guard = Policy::parse(
        Some(PolicyId::new("analysis-approval-granted")),
        "forbid (principal, action, resource) unless { context.approval_valid };",
    )
    .map_err(|e| e.to_string())?;
    let with_guard = |keep_escalate: bool| -> Result<PolicySet, String> {
        let kept = policies
            .policies()
            .filter(|p| keep_escalate || p.annotation("escalate").is_none())
            .cloned()
            .chain(std::iter::once(guard.clone()));
        PolicySet::from_policies(kept).map_err(|e| e.to_string())
    };
    let (all, lifted) = (with_guard(true)?, with_guard(false)?);
    for env in schema.request_envs() {
        let all = CompiledPolicySet::compile(&all, &env, schema).map_err(|e| e.to_string())?;
        let lifted =
            CompiledPolicySet::compile(&lifted, &env, schema).map_err(|e| e.to_string())?;
        if !compiler
            .check_equivalent_opt(&all, &lifted)
            .await
            .map_err(|e| e.to_string())?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// (ii): `approval_valid` is read only by the `unless` clause of an
/// `@escalate` forbid, once per such forbid. Syntactic, so needs no solver.
fn approval_read_only_by_escalations(policies: &PolicySet) -> bool {
    policies.policies().all(|p| {
        let text = p.to_string();
        let reads = text.matches("approval_valid").count();
        if p.annotation("escalate").is_some() {
            reads == 1 && text.contains("unless { context.approval_valid }")
        } else {
            reads == 0
        }
    })
}

/// One policy set to analyse: its schema, the shipped policies, the
/// properties and the weakened variants that must be caught.
struct Suite<'a> {
    label: &'a str,
    schema: &'a str,
    policies: &'a str,
    properties: Vec<(&'a str, String)>,
    sanity: &'a [(&'a str, &'a str, &'a str)],
    /// Whether the policies carry `@escalate` forbids lifted by an approval.
    approval_lift: bool,
}

async fn run() -> Result<bool, String> {
    let solver = LocalSolver::cvc5().map_err(|e| format!("cvc5 (set $CVC5): {e}"))?;
    let mut compiler = CedarSymCompiler::new(solver).map_err(|e| e.to_string())?;
    let suites = [
        Suite {
            label: "agent",
            schema: AGENT_SCHEMA,
            policies: AGENT_POLICIES,
            properties: PROPERTIES
                .iter()
                .map(|(name, text)| (*name, (*text).to_string()))
                .collect(),
            sanity: &SANITY_VARIANTS,
            approval_lift: true,
        },
        Suite {
            label: "operator",
            schema: API_SCHEMA,
            policies: API_POLICIES,
            properties: OPERATOR_PROPERTIES
                .iter()
                .map(|(name, text)| (*name, text.replace("{ROLE_CHANGES}", ROLE_CHANGES)))
                .collect(),
            sanity: &OPERATOR_SANITY_VARIANTS,
            approval_lift: false,
        },
    ];
    let mut ok = true;
    for suite in &suites {
        println!("-- {} policies", suite.label);
        ok &= analyse(&mut compiler, suite).await?;
    }
    Ok(ok)
}

async fn analyse(compiler: &mut Compiler, suite: &Suite<'_>) -> Result<bool, String> {
    let schema = Schema::from_cedarschema_str(suite.schema)
        .map_err(|e| e.to_string())?
        .0;
    let shipped = PolicySet::from_str(suite.policies).map_err(|e| e.to_string())?;
    let mut ok = true;

    let bad: Vec<(&str, PolicySet)> = suite
        .properties
        .iter()
        .map(|(name, text)| {
            PolicySet::from_str(text)
                .map(|p| (*name, p))
                .map_err(|e| format!("{name}: {e}"))
        })
        .collect::<Result<_, String>>()?;

    for (name, forbidden) in &bad {
        let holds = property_holds(compiler, &schema, &shipped, forbidden).await?;
        println!("{} {name}", if holds { "PROVEN  " } else { "VIOLATED" });
        ok &= holds;
    }

    let no_errors = never_errors(compiler, &schema, &shipped).await?;
    println!(
        "{} no shipped policy can raise an evaluation error",
        if no_errors { "PROVEN  " } else { "VIOLATED" }
    );
    ok &= no_errors;

    if suite.approval_lift {
        let lift = approval_lifts_only_escalations(compiler, &schema, &shipped).await?;
        println!(
            "{} an approval lifts the escalate forbids and nothing else",
            if lift { "PROVEN  " } else { "VIOLATED" }
        );
        let reads = approval_read_only_by_escalations(&shipped);
        println!(
            "{} only escalate forbids read approval_valid, in their unless clause",
            if reads { "PROVEN  " } else { "VIOLATED" }
        );
        ok &= lift && reads;
    }

    for (label, anchor, replacement) in suite.sanity {
        // Exactly once, so the variant weakens the policy it names.
        if suite.policies.matches(anchor).count() != 1 {
            println!("SANITY  anchor for '{label}' is not found exactly once; update the variants");
            ok = false;
            continue;
        }
        let weakened = PolicySet::from_str(&suite.policies.replacen(anchor, replacement, 1))
            .map_err(|e| format!("{label}: {e}"))?;
        let mut caught = false;
        for (_, forbidden) in &bad {
            caught |= !property_holds(compiler, &schema, &weakened, forbidden).await?;
        }
        if suite.approval_lift {
            caught |= !approval_read_only_by_escalations(&weakened)
                || !approval_lifts_only_escalations(compiler, &schema, &weakened).await?;
        }
        println!(
            "{} weakened variant detected: {label}",
            if caught { "CAUGHT  " } else { "MISSED  " }
        );
        ok &= caught;
    }
    Ok(ok)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(true) => {
            println!("all agent and operator policy properties proven");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("policy analysis FAILED");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("policy analysis error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Needs no solver, so it also runs outside the CI analysis job.
    #[test]
    fn every_sanity_anchor_appears_exactly_once_and_the_variant_parses() {
        for (policies, variants) in [
            (AGENT_POLICIES, &SANITY_VARIANTS[..]),
            (API_POLICIES, &OPERATOR_SANITY_VARIANTS[..]),
        ] {
            for (label, anchor, replacement) in variants {
                assert_eq!(policies.matches(anchor).count(), 1, "anchor for '{label}'");
                PolicySet::from_str(&policies.replacen(anchor, replacement, 1))
                    .unwrap_or_else(|e| panic!("'{label}' does not parse: {e}"));
            }
        }
    }

    #[test]
    fn approval_valid_is_read_only_by_escalate_unless_clauses() {
        let shipped = PolicySet::from_str(AGENT_POLICIES).unwrap();
        assert!(approval_read_only_by_escalations(&shipped));
        assert_eq!(
            shipped
                .policies()
                .filter(|p| p.annotation("escalate").is_some())
                .count(),
            2,
            "the two escalate forbids"
        );
        let (_, anchor, replacement) = SANITY_VARIANTS
            .iter()
            .find(|(label, _, _)| *label == "a permit reads approval_valid")
            .unwrap();
        let weakened =
            PolicySet::from_str(&AGENT_POLICIES.replacen(anchor, replacement, 1)).unwrap();
        assert!(!approval_read_only_by_escalations(&weakened));
    }

    #[test]
    fn every_operator_property_parses() {
        for (name, text) in OPERATOR_PROPERTIES {
            PolicySet::from_str(&text.replace("{ROLE_CHANGES}", ROLE_CHANGES))
                .unwrap_or_else(|e| panic!("'{name}' does not parse: {e}"));
        }
    }
}
