use anyhow::Context;
use serde_json::json;
use std::convert::Infallible;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};
use warp::{http::Method, Filter};

use crate::logging::{log_message, parse_log_line, rotated_path};

// most logs a single history request can ask for
const MAX_HISTORY_OFFSET: usize = 1000;

pub async fn fetch_logs_with_offset(
    enclave_log_file_path: &str,
    log_id: u64,
    offset: usize,
) -> anyhow::Result<Vec<String>> {
    // offset comes straight from the query, do not let it size anything by itself
    let offset = offset.min(MAX_HISTORY_OFFSET);
    let start_log_id = if log_id > offset as u64 {
        log_id - offset as u64
    } else {
        1
    };

    let mut logs: Vec<String> = Vec::new();

    // older logs might be in the rotated file
    for (path, required) in [
        (rotated_path(enclave_log_file_path), false),
        (enclave_log_file_path.to_owned(), true),
    ] {
        let file = match File::open(&path).await {
            Ok(file) => file,
            Err(_) if !required => continue,
            Err(e) => return Err(e).context("http server: failed to open enclave log file"),
        };
        let mut reader = BufReader::new(file).lines();

        while let Some(line) = reader.next_line().await? {
            if logs.len() >= offset {
                return Ok(logs);
            }
            // skip anything that is not a log line instead of failing the request
            let Some((current_log_id, message)) = parse_log_line(&line) else {
                continue;
            };
            if current_log_id >= start_log_id {
                let log_entry = format!("[{}] {}", current_log_id, message);
                logs.push(log_entry);
            }
        }
    }

    Ok(logs)
}

// the writer moves the log file aside once it is full and starts a new one
async fn has_rotated(path: &str, inode: Option<u64>) -> bool {
    tokio::fs::metadata(path)
        .await
        .map(|m| Some(m.ino()) != inode)
        .unwrap_or(false)
}

pub fn create_routes(
    enclave_logs: String,
    script_logs: String,
    log_counter: Arc<AtomicU64>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let logs_file = enclave_logs.clone();
    let history_script_logs = script_logs.clone();
    let log_counter1 = log_counter.clone();
    let log_counter2 = log_counter.clone();
    let home_html = include_str!("../assets/logs.html");

    let home_route = warp::path("logs")
        .and(warp::get())
        .map(move || warp::reply::html(home_html));

    let tail_log_route = warp::path("logs")
        .and(warp::path("tail-log-id"))
        .and(warp::get())
        .and_then(move || {
            let log_counter = log_counter1.clone();
            async move {
                let latest_log_id = log_counter.load(Ordering::Relaxed);
                Ok::<_, Infallible>(warp::reply::json(&json!({"log_id": latest_log_id})))
            }
        });

    let history_route = warp::path("logs")
        .and(warp::path("history"))
        .and(warp::query::<HashMap<String, String>>())
        .and_then(move |params: HashMap<String, String>| {
            let logs_file = logs_file.clone();
            let script_logs = history_script_logs.clone();
            let log_counter = log_counter2.clone();
            async move {
                let latest_log_id = log_counter.load(Ordering::Relaxed);
                let log_id = params
                    .get("log_id")
                    .and_then(|id| id.parse::<u64>().ok())
                    .unwrap_or(latest_log_id);

                let offset = params
                    .get("offset")
                    .and_then(|off| off.parse::<usize>().ok())
                    .unwrap_or(10);

                let result = fetch_logs_with_offset(&logs_file, log_id, offset).await;

                let response = match result {
                    Ok(logs) => warp::reply::json(&logs),
                    Err(err) => {
                        let _ = log_message(
                            &script_logs,
                            &err.context("failed to fetch logs with offset").to_string(),
                        )
                        .await;
                        warp::reply::json(&json!({"error": "Failed to retrieve logs."}))
                    }
                };

                Ok::<_, Infallible>(response)
            }
        });

    let sse_route = warp::path("logs")
        .and(warp::path("stream"))
        .and(warp::query::<HashMap<String, String>>())
        .and(warp::get())
        .map(move |params: HashMap<String, String>| {
            let logs_file = enclave_logs.to_string();
            let script_logs = script_logs.to_string();
            let log_counter = log_counter.clone();

            let start_from = params
                .get("start_from")
                .and_then(|id| id.parse::<u64>().ok())
                .unwrap_or_else(|| log_counter.load(Ordering::Relaxed));

            let stream = async_stream::stream! {
                // id of the next log to send
                let mut next_id = start_from;
                loop {  // Outer loop for retrying on errors and following rotations
                    match File::open(&logs_file).await {
                        Ok(file) => {
                            let inode = file.metadata().await.map(|m| m.ino()).ok();
                            let mut reader = BufReader::new(file);
                            let mut line = String::new();

                            loop {
                                match reader.read_line(&mut line).await {
                                    Ok(0) => {
                                        if has_rotated(&logs_file, inode).await {
                                            break;  // Break inner loop to open the new file
                                        }
                                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                                    }
                                    Ok(_) => {
                                        if !line.ends_with('\n') {
                                            // rest of the line is not written yet
                                            continue;
                                        }
                                        let trimmed_line = line.trim_end();
                                        // skip logs before the start and ones already sent
                                        let log_id = parse_log_line(trimmed_line).map(|x| x.0);
                                        if log_id.is_none_or(|id| id >= next_id) {
                                            if let Some(id) = log_id {
                                                next_id = id + 1;
                                            }
                                            if !trimmed_line.is_empty() {
                                                yield Ok::<_, warp::Error>(warp::sse::Event::default().data(trimmed_line));
                                            }
                                        }
                                        line.clear();
                                    }
                                    Err(e) => {
                                        let _ = log_message(&script_logs, &format!("Error reading line: {}", e)).await;
                                        break;  // Break inner loop to retry
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let _ = log_message(&script_logs, &format!("Error opening log file: {}", e)).await;
                            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;  // Wait before retry
                        }
                    }
                }
            };
            warp::sse::reply(warp::sse::keep_alive().stream(stream))
        });

    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["*"])
        .allow_methods(vec![Method::GET]);

    history_route
        .or(tail_log_route)
        .or(sse_route)
        .or(home_route)
        .with(cors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_path(name: &str) -> String {
        let path =
            std::env::temp_dir().join(format!("logger-http-test-{}-{name}", std::process::id()));
        let path = path.to_str().unwrap().to_owned();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(rotated_path(&path));
        path
    }

    fn lines(ids: std::ops::RangeInclusive<u64>) -> String {
        ids.map(|i| format!("[{i}] line {i}\n")).collect()
    }

    #[tokio::test]
    async fn history_returns_the_logs_before_an_id() {
        let path = test_path("history");
        std::fs::write(&path, lines(1..=50)).unwrap();

        let logs = fetch_logs_with_offset(&path, 21, 10).await.unwrap();

        assert_eq!(logs.len(), 10);
        assert_eq!(logs[0], "[11] line 11");
        assert_eq!(logs[9], "[20] line 20");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn history_offset_is_capped() {
        let path = test_path("cap");
        std::fs::write(&path, lines(1..=1500)).unwrap();

        // used to be passed to Vec::with_capacity as is
        let logs = fetch_logs_with_offset(&path, 1501, usize::MAX)
            .await
            .unwrap();

        assert_eq!(logs.len(), MAX_HISTORY_OFFSET);
        assert_eq!(logs[0], "[501] line 501");
        assert_eq!(logs[999], "[1500] line 1500");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn history_reads_across_a_rotation() {
        let path = test_path("rotated");
        std::fs::write(rotated_path(&path), lines(1..=30)).unwrap();
        std::fs::write(&path, lines(31..=40)).unwrap();

        let logs = fetch_logs_with_offset(&path, 41, 20).await.unwrap();

        assert_eq!(logs.len(), 20);
        assert_eq!(logs[0], "[21] line 21");
        assert_eq!(logs[19], "[40] line 40");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(rotated_path(&path));
    }

    #[tokio::test]
    async fn history_skips_lines_that_are_not_logs() {
        let path = test_path("junk");
        std::fs::write(
            &path,
            "[1] one\n[2026-11-16 10:00:00] failed to fetch logs with offset\nnot a log\n[2] two\n",
        )
        .unwrap();

        let logs = fetch_logs_with_offset(&path, 3, 10).await.unwrap();

        assert_eq!(logs, vec!["[1] one", "[2] two"]);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn rotation_is_detected_by_inode() {
        let path = test_path("inode");
        std::fs::write(&path, lines(1..=3)).unwrap();
        let inode = std::fs::metadata(&path).map(|m| m.ino()).ok();

        assert!(!has_rotated(&path, inode).await);

        std::fs::rename(&path, rotated_path(&path)).unwrap();
        // new file is not there yet
        assert!(!has_rotated(&path, inode).await);

        std::fs::write(&path, lines(4..=5)).unwrap();
        assert!(has_rotated(&path, inode).await);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(rotated_path(&path));
    }

    #[test]
    fn log_lines_are_parsed() {
        assert_eq!(
            parse_log_line("[12] hello ] there"),
            Some((12, "hello ] there"))
        );
        assert_eq!(parse_log_line("[2026-11-16 10:00:00] hello"), None);
        assert_eq!(parse_log_line("hello"), None);
        assert_eq!(parse_log_line(""), None);
    }
}
