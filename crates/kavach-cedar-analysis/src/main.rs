//! Formal analysis of the Kavach agent policies (ADR-003 §6, PRD success
//! criteria). CI-only: requires the cvc5 1.3.1 solver at `$CVC5` and is never
//! linked into shipped binaries.
//!
//! Each property is stated as a policy that permits exactly the forbidden
//! requests. The property holds when no request can be allowed by both the
//! shipped policies and that policy (`check_disjoint`), for every request
//! environment in the schema. Sanity checks then weaken the shipped policies on
//! purpose and require the analysis to report a violation, so a vacuous pass
//! (e.g. a mis-stated property) fails the job.

use std::process::ExitCode;
use std::str::FromStr;

use cedar_policy::{PolicySet, Schema};
use cedar_policy_symcc::{
    solver::LocalSolver, CedarSymCompiler, CompiledPolicy, CompiledPolicySet,
};
use kavach_authz::{AGENT_POLICIES, AGENT_SCHEMA};

/// (name, policy permitting exactly the requests the property forbids).
const PROPERTIES: [(&str, &str); 16] = [
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
        "no contact is allowed at or above the daily cap, or with a negative count",
        r#"permit (principal, action in [Kavach::Agent::Action::"send_reminder", Kavach::Agent::Action::"place_call"], resource)
           when { context.contacts_today < 0
                  || context.contacts_today >= context.max_per_day };"#,
    ),
];

/// Weakened variants that must be caught: (label, anchor to replace, replacement).
const SANITY_VARIANTS: [(&str, &str, &str); 7] = [
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
        "negative contact count allowed",
        r"when { context.contacts_today < 0 };",
        r"when { false };",
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

async fn run() -> Result<bool, String> {
    let schema = Schema::from_cedarschema_str(AGENT_SCHEMA)
        .map_err(|e| e.to_string())?
        .0;
    let shipped = PolicySet::from_str(AGENT_POLICIES).map_err(|e| e.to_string())?;
    let solver = LocalSolver::cvc5().map_err(|e| format!("cvc5 (set $CVC5): {e}"))?;
    let mut compiler = CedarSymCompiler::new(solver).map_err(|e| e.to_string())?;
    let mut ok = true;

    let bad: Vec<(&str, PolicySet)> = PROPERTIES
        .iter()
        .map(|(name, text)| {
            PolicySet::from_str(text)
                .map(|p| (*name, p))
                .map_err(|e| e.to_string())
        })
        .collect::<Result<_, String>>()?;

    for (name, forbidden) in &bad {
        let holds = property_holds(&mut compiler, &schema, &shipped, forbidden).await?;
        println!("{} {name}", if holds { "PROVEN  " } else { "VIOLATED" });
        ok &= holds;
    }

    let no_errors = never_errors(&mut compiler, &schema, &shipped).await?;
    println!(
        "{} no shipped policy can raise an evaluation error",
        if no_errors { "PROVEN  " } else { "VIOLATED" }
    );
    ok &= no_errors;

    for (label, anchor, replacement) in SANITY_VARIANTS {
        if !AGENT_POLICIES.contains(anchor) {
            println!("SANITY  anchor for '{label}' not found; update SANITY_VARIANTS");
            ok = false;
            continue;
        }
        let weakened = PolicySet::from_str(&AGENT_POLICIES.replacen(anchor, replacement, 1))
            .map_err(|e| e.to_string())?;
        let mut caught = false;
        for (_, forbidden) in &bad {
            caught |= !property_holds(&mut compiler, &schema, &weakened, forbidden).await?;
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
            println!("all agent policy properties proven");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("agent policy analysis FAILED");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("agent policy analysis error: {e}");
            ExitCode::FAILURE
        }
    }
}
