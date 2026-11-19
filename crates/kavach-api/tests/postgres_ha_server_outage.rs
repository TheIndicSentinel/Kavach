//! Shared Postgres server outage and recovery on a dedicated disposable cluster.

use std::{path::PathBuf, process::Command};

use kavach_api::{ha_lease, DatabaseTls};
use kavach_storage::{connect_runtime, testing::isolated_database_urls, StoragePool};
use tokio::sync::watch;

struct DisposablePostgres {
    data_dir: PathBuf,
    stopped: bool,
}

impl DisposablePostgres {
    fn command(&self, action: &str) -> std::process::Output {
        let mut command = Command::new("pg_ctl");
        command.arg("-D").arg(&self.data_dir);
        match action {
            "stop" => {
                command.args(["stop", "-m", "immediate"]);
            }
            "start" => {
                command
                    .arg("start")
                    .arg("-l")
                    .arg(self.data_dir.join("restart.log"));
            }
            _ => panic!("unsupported pg_ctl action"),
        }
        command.output().expect("run pg_ctl")
    }

    fn stop(&mut self) {
        let output = self.command("stop");
        assert!(
            output.status.success(),
            "stop temporary Postgres: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.stopped = true;
    }

    fn start(&mut self) {
        let output = self.command("start");
        assert!(
            output.status.success(),
            "restart temporary Postgres: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.stopped = false;
    }
}

impl Drop for DisposablePostgres {
    fn drop(&mut self) {
        if self.stopped {
            let _ = self.command("start");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apis_stay_fenced_during_shared_postgres_outage_and_recover_after_restart() {
    let Ok(data_dir) = std::env::var("KAVACH_HA_TEST_PGDATA") else {
        eprintln!("skipping server-outage test: KAVACH_HA_TEST_PGDATA is not set");
        return;
    };
    let Some((owner_url, runtime_url)) = isolated_database_urls().await else {
        return;
    };
    let mut postgres = DisposablePostgres {
        data_dir: PathBuf::from(data_dir),
        stopped: false,
    };
    assert!(
        postgres
            .data_dir
            .join(".kavach-ha-outage-test-cluster")
            .is_file(),
        "refusing to stop a Postgres cluster not created by the dedicated HA outage harness"
    );
    let tls = DatabaseTls::development();
    let owner = StoragePool::connect(&owner_url, &tls)
        .await
        .expect("migrate isolated schema");
    let connected_data_dir: String = sqlx::query_scalar("SHOW data_directory")
        .fetch_one(&owner.pool)
        .await
        .expect("read connected Postgres data directory");
    assert_eq!(
        std::fs::canonicalize(&connected_data_dir).expect("canonical connected data directory"),
        std::fs::canonicalize(&postgres.data_dir).expect("canonical test data directory"),
        "the test URL must point at the disposable cluster it will stop"
    );
    let active_pool = connect_runtime(&runtime_url, &tls)
        .await
        .expect("connect active");
    let standby_pool = connect_runtime(&runtime_url, &tls)
        .await
        .expect("connect standby");

    let (active_stop_tx, active_stop_rx) = watch::channel(false);
    let (active_fence, active_task) = ha_lease::start(
        active_pool.active_lease_store(),
        "tenant-ha-server-outage".into(),
        active_stop_rx,
    )
    .await
    .expect("start active lease lifecycle");
    assert_eq!(active_fence.status(), "active");
    let (standby_stop_tx, standby_stop_rx) = watch::channel(false);
    let (standby_fence, standby_task) = ha_lease::start(
        standby_pool.active_lease_store(),
        "tenant-ha-server-outage".into(),
        standby_stop_rx,
    )
    .await
    .expect("start standby lease lifecycle");
    assert_eq!(standby_fence.status(), "standby");

    let outage_started = tokio::time::Instant::now();
    postgres.stop();
    let server_status = Command::new("pg_ctl")
        .arg("-D")
        .arg(&postgres.data_dir)
        .arg("status")
        .output()
        .expect("check stopped Postgres");
    assert!(
        !server_status.status.success(),
        "Postgres must be stopped for this fault test"
    );
    tokio::time::timeout(std::time::Duration::from_secs(12), async {
        while active_fence.status() != "fenced" {
            assert!(
                !active_task.is_finished(),
                "active lease lifecycle exited without fencing"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("active must fence itself when Postgres stops");
    eprintln!(
        "active API self-fenced {} seconds after the shared Postgres server stopped",
        outage_started.elapsed().as_secs_f32()
    );

    // The last renewal may have happened just before the server stopped.
    // Keep the full database outage longer than that lease can remain live.
    tokio::time::sleep_until(outage_started + std::time::Duration::from_secs(14)).await;
    assert_eq!(active_fence.status(), "fenced");
    assert_eq!(standby_fence.status(), "standby");

    postgres.start();
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while standby_fence.status() != "active" {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("standby must recover and claim the expired lease");

    let current_epoch: i64 =
        sqlx::query_scalar("SELECT epoch FROM active_api_leases WHERE tenant_id = $1")
            .bind("tenant-ha-server-outage")
            .fetch_one(&owner.pool)
            .await
            .expect("owner reconnects after Postgres restart");
    assert_eq!(current_epoch, 2);

    // The pre-outage active remains permanently fenced even though its pool
    // can reconnect. A bounded retry absorbs the first broken pooled socket.
    let stale_write_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let result = sqlx::query(
            "INSERT INTO replay_guard (tenant_id, key, expires_at) \
             VALUES ('tenant-ha-server-outage', 'old-active-write', clock_timestamp() + interval '1 minute')",
        )
        .execute(&active_pool.pool)
        .await;
        match result {
            Err(error)
                if error
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::code)
                    .as_deref()
                    == Some("55000") =>
            {
                break;
            }
            Err(error) if tokio::time::Instant::now() < stale_write_deadline => {
                tracing::debug!(%error, "waiting for old API pool reconnect");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            other => panic!("old active must be rejected after reconnect: {other:?}"),
        }
    }

    let standby_write = sqlx::query(
        "INSERT INTO replay_guard (tenant_id, key, expires_at) \
         VALUES ('tenant-ha-server-outage', 'recovered-standby-write', clock_timestamp() + interval '1 minute')",
    )
    .execute(&standby_pool.pool)
    .await
    .expect("promoted standby can write after restart");
    assert_eq!(standby_write.rows_affected(), 1);

    let _ = active_stop_tx.send(true);
    let _ = standby_stop_tx.send(true);
    let _ = active_task.await;
    let _ = standby_task.await;
    drop(owner);
}
