mod args;
mod enclave_monitor;
mod http_server;
mod logging;

use anyhow::Context;
use args::Args;
use clap::Parser;
use enclave_monitor::monitor_and_capture_logs;
use logging::{clear_log_file, log_message, remove_log_file, rotated_path};
use std::sync::{atomic::AtomicU64, Arc};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let log_counter = Arc::new(AtomicU64::new(1));

    // Clear log files at startup
    for path in [&args.enclave_log_file_path, &args.script_log_file_path] {
        clear_log_file(path)
            .await
            .with_context(|| format!("failed to clear log file: {}", path))?;
    }

    // log ids start from 1 again, older logs do not belong to this run
    remove_log_file(&rotated_path(&args.enclave_log_file_path))
        .await
        .context("failed to remove rotated log file")?;

    log_message(&args.script_log_file_path, "Starting script...").await?;

    // Spawn log monitoring task
    tokio::task::spawn({
        let script_log = args.script_log_file_path.clone();
        let enclave_log = args.enclave_log_file_path.clone();
        let counter = Arc::clone(&log_counter);

        let max_log_file_size = args.max_log_file_size_mb.saturating_mul(1024 * 1024);

        async move {
            // capture should never stop for good, the http server keeps running regardless
            loop {
                if let Err(e) = monitor_and_capture_logs(
                    &enclave_log,
                    &script_log,
                    args.target_cid,
                    counter.clone(),
                    max_log_file_size,
                )
                .await
                {
                    let _ = log_message(
                        &script_log,
                        &format!("Error in monitor_and_capture_logs: {:?}. Retrying...", e),
                    )
                    .await;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    });

    // Start HTTP server
    let routes = http_server::create_routes(
        args.enclave_log_file_path.to_owned(),
        args.script_log_file_path.to_owned(),
        log_counter,
    );

    log_message(
        &args.script_log_file_path,
        "Server started. SSE endpoint: <host>/logs/stream",
    )
    .await?;
    println!("running port {}", args.port);

    warp::serve(routes).run(([0, 0, 0, 0], args.port)).await;

    Ok(())
}
