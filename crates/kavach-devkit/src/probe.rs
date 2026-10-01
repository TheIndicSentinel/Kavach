//! The isolation probe the test agent runs from inside the agent network
//! (H5b-2): what an agent can reach, what it holds, and what the gateway
//! lets it do. Every check prints `PASS` or `FAIL` with a reason; the
//! process exit status is the result.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{FixedOffset, Timelike, Utc};
use serde_json::{json, Value};
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone)]
pub struct ProbeOptions {
    /// The gateway's agent listener, e.g. `http://172.30.10.10:8091`.
    pub agent_url: String,
    /// The agent listener's own `host:port` (must be reachable).
    pub agent_listener: String,
    /// `host:port` targets that must NOT be reachable from here.
    pub must_fail: Vec<String>,
    /// Names that must not resolve to anything reachable.
    pub must_not_resolve: Vec<String>,
    pub token_file: PathBuf,
    /// JSON reply of the SoR listener (`{"mandate_id": …}`).
    pub mandate_file: PathBuf,
    /// Directories the agent can read; they must hold no key material.
    pub scan_dirs: Vec<PathBuf>,
    /// The scheduled IST-midday run: anything but `delivered` fails.
    pub require_delivery: bool,
}

#[derive(Default)]
struct Report {
    failures: Vec<String>,
}

impl Report {
    fn check(&mut self, name: &str, ok: bool, detail: impl std::fmt::Display) {
        if ok {
            println!("PASS {name}");
        } else {
            println!("FAIL {name}: {detail}");
            self.failures.push(name.to_string());
        }
    }
}

async fn connects(target: &str) -> Result<bool, String> {
    let addr: SocketAddr = target
        .parse()
        .map_err(|e| format!("bad target {target}: {e}"))?;
    Ok(matches!(
        tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await,
        Ok(Ok(_))
    ))
}

/// Minutes since midnight IST.
fn ist_minute() -> u32 {
    let ist = FixedOffset::east_opt(5 * 3600 + 1800).expect("valid offset");
    let now = Utc::now().with_timezone(&ist);
    now.hour() * 60 + now.minute()
}

/// Files that look like key material (by name or content).
fn key_material(dir: &Path, found: &mut Vec<String>, depth: u8) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if depth > 0 {
                key_material(&path, found, depth - 1);
            }
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let suspicious_name = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("ed25519") || e.eq_ignore_ascii_case("key"))
            || name.ends_with("-key.pem");
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let suspicious_content = content.contains("PRIVATE KEY")
            || (content.trim().len() == 64
                && content.trim().bytes().all(|b| b.is_ascii_hexdigit()));
        if suspicious_name || suspicious_content {
            found.push(path.display().to_string());
        }
    }
}

/// Runs every check; `Ok(true)` when all pass.
pub async fn run(opts: &ProbeOptions) -> Result<bool, String> {
    let mut report = Report::default();
    reachability(opts, &mut report).await?;
    secrets(opts, &mut report);
    gateway(opts, &mut report).await?;
    println!("{} checks failed", report.failures.len());
    Ok(report.failures.is_empty())
}

async fn reachability(opts: &ProbeOptions, report: &mut Report) -> Result<(), String> {
    // 1. Reachability: only the agent listener.
    report.check(
        &format!("agent listener {} reachable", opts.agent_listener),
        connects(&opts.agent_listener).await?,
        "the agent cannot reach the gateway",
    );
    for target in &opts.must_fail {
        report.check(
            &format!("{target} unreachable"),
            !connects(target).await?,
            "connected — isolation or listener binding is wrong",
        );
    }
    for name in &opts.must_not_resolve {
        let reachable = match tokio::net::lookup_host((name.as_str(), 443)).await {
            Err(_) => Vec::new(),
            Ok(addrs) => {
                let mut open = Vec::new();
                for addr in addrs {
                    if connects(&addr.to_string()).await.unwrap_or(false) {
                        open.push(addr.to_string());
                    }
                }
                open
            }
        };
        report.check(
            &format!("{name} not reachable by name"),
            reachable.is_empty(),
            format!("reached {reachable:?}"),
        );
    }

    Ok(())
}

fn secrets(opts: &ProbeOptions, report: &mut Report) {
    // 2. Nothing worth stealing: no key material, no secrets in env.
    let mut keys = Vec::new();
    for dir in &opts.scan_dirs {
        key_material(dir, &mut keys, 3);
    }
    report.check(
        "no key material readable by the agent",
        keys.is_empty(),
        format!("found {keys:?}"),
    );
    let leaked: Vec<String> = std::env::vars()
        .filter(|(_, v)| v.contains("PRIVATE KEY") || v.starts_with("eyJ"))
        .map(|(k, _)| k)
        .collect();
    report.check(
        "no secrets in the environment",
        leaked.is_empty(),
        format!("variables {leaked:?}"),
    );
}

async fn gateway(opts: &ProbeOptions, report: &mut Report) -> Result<(), String> {
    // 3. The gateway: the only way to act.
    let token = std::fs::read_to_string(&opts.token_file)
        .map_err(|e| format!("token {}: {e}", opts.token_file.display()))?;
    let issued: Value = serde_json::from_str(
        &std::fs::read_to_string(&opts.mandate_file)
            .map_err(|e| format!("mandate {}: {e}", opts.mandate_file.display()))?,
    )
    .map_err(|e| format!("mandate file: {e}"))?;
    let mandate = issued["mandate_id"]
        .as_str()
        .ok_or("mandate file has no mandate_id")?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let call = |request_id: String, params: Value, mandate: String| {
        let client = client.clone();
        let url = format!("{}/v1/tools/send_reminder", opts.agent_url);
        let token = token.trim().to_string();
        async move {
            let response = client
                .post(url)
                .bearer_auth(token)
                .json(&json!({ "mandate_id": mandate, "request_id": request_id, "params": params }))
                .send()
                .await
                .map_err(|e| format!("gateway call: {e}"))?;
            let status = response.status().as_u16();
            let body: Value = response.json().await.unwrap_or(Value::Null);
            Ok::<_, String>((status, body))
        }
    };
    let params = json!({ "subject_ref": crate::SUBJECT, "channel": "whatsapp", "template_id": "emi_reminder_v1" });
    let run_id = format!("{}", Utc::now().timestamp());

    let (status, reply) = call(
        format!("probe-{run_id}"),
        params.clone(),
        mandate.to_string(),
    )
    .await?;
    let minute = ist_minute();
    let in_window = (8 * 60..18 * 60 + 58).contains(&minute);
    let edge = !in_window
        && ((7 * 60 + 58..8 * 60).contains(&minute) || (18 * 60 + 58..19 * 60).contains(&minute));
    let delivered = status == 200 && reply["outcome"] == "delivered";
    if opts.require_delivery {
        report.check("delivery through the gateway (required)", delivered, &reply);
    } else if in_window {
        report.check(
            "delivery through the gateway (inside 08:00–19:00 IST)",
            delivered,
            &reply,
        );
    } else if !edge {
        let reasons = reply["reasons"].to_string();
        let window_block = reply["decision"] == "BLOCK"
            && (reasons.contains("contact-window") || reasons.contains("contact-hours-floor"));
        report.check(
            "outside 08:00–19:00 IST: BLOCK by the contact window",
            status == 200 && window_block,
            &reply,
        );
    } else {
        println!("SKIP delivery: at the window edge ({minute} min IST)");
    }
    let text = reply.to_string();
    report.check(
        "the reply carries no destination or credential",
        !text.contains("+91") && !text.contains("eyJ"),
        &text,
    );

    // 4. Bypasses through the gateway fail.
    let mut timestamp = params.clone();
    timestamp["timestamp"] = json!("2026-10-01T05:30:00Z");
    let (status, _) = call(format!("probe-ts-{run_id}"), timestamp, mandate.to_string()).await?;
    report.check(
        "an agent-supplied timestamp is refused (400)",
        status == 400,
        status,
    );
    let (status, reply) =
        call(format!("probe-forged-{run_id}"), params, "ma-forged".into()).await?;
    report.check(
        "a forged mandate is refused (BLOCK)",
        status == 200 && reply["decision"] == "BLOCK",
        &reply,
    );

    Ok(())
}
