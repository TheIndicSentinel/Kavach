//! Prints the kernel clock-sync classification as JSON (deployment probe and
//! the CI container check). Exits 0 whenever the status could be classified.

fn main() {
    let reading = kavach_clocksync::read();
    let status = match reading.status {
        kavach_ports::SyncStatus::Synced { max_error_ms } => {
            serde_json::json!({ "status": "synced", "max_error_ms": max_error_ms })
        }
        kavach_ports::SyncStatus::Unsynced => serde_json::json!({ "status": "unsynced" }),
        kavach_ports::SyncStatus::Unknown => serde_json::json!({ "status": "unknown" }),
    };
    println!(
        "{}",
        serde_json::json!({ "sync": status, "detail": reading.detail })
    );
}
