//! The harness end to end on the memory store: every scenario runs and
//! gets only the replies it expects. (The figures are not checked: a
//! memory-store run on a test machine means nothing.)

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use kavach_bench::load::{run, Scenario};
use kavach_bench::stack::{Stack, StackOptions, Store};

#[tokio::test(flavor = "multi_thread")]
async fn every_scenario_runs_with_only_expected_replies() {
    let work = std::env::temp_dir().join(format!(
        "kavach-bench-test-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&work).unwrap();
    let stack = Arc::new(
        Stack::start(&StackOptions {
            store: Store::Memory,
            subjects: 5,
            provider_delay: Duration::from_millis(1),
            pool_size: 5,
            work: work.clone(),
        })
        .await
        .expect("the stack starts"),
    );
    assert_eq!(stack.subjects.len(), 5);
    let client = reqwest::Client::new();
    let sequence = Arc::new(AtomicU64::new(0));
    for (index, scenario) in Scenario::GATEWAY.into_iter().enumerate() {
        let result = run(
            &stack,
            &client,
            scenario,
            index,
            2,
            Duration::from_millis(200),
            Duration::from_millis(800),
            &sequence,
        )
        .await;
        assert!(result.requests > 0, "{result:?}");
        assert_eq!(result.errors, 0, "{result:?}");
        assert!(result.p50_ms <= result.p99_ms && result.p99_ms <= result.max_ms);
    }
    // The storage micro-benchmarks need Postgres, and say so.
    let refused = kavach_bench::micro::run_micro(
        &stack,
        Scenario::Commit,
        1,
        Duration::ZERO,
        Duration::from_millis(100),
        &sequence,
    )
    .await
    .unwrap_err();
    assert!(refused.contains("need Postgres"), "{refused}");
    std::fs::remove_dir_all(&work).unwrap();
}
