use anyhow::Context;
use chrono::Local;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncWriteExt, ErrorKind};

pub async fn log_message(log_file: &str, message: &str) -> anyhow::Result<()> {
    // Create OpenOptions
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .await
        .context("Failed to open enclave log file")?;

    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    let log_message = format!("[{}] {}", now, message);

    file.write_all(log_message.as_bytes())
        .await
        .context("failed to write log to debug log file")?;
    file.write_all(b"\n").await?;
    file.flush()
        .await
        .context("failed to flush all changes from buffer to log file")?;
    Ok(())
}

pub async fn clear_log_file(file_path: &str) -> anyhow::Result<()> {
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(file_path)
        .await
        .map(|_| ())
        .or_else(|e| {
            if e.kind() == ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e).context("Failed to clear the log file")
            }
        })
}

/// Path of the older enclave log file kept after a rotation
pub fn rotated_path(file_path: &str) -> String {
    format!("{file_path}.1")
}

pub async fn remove_log_file(file_path: &str) -> anyhow::Result<()> {
    tokio::fs::remove_file(file_path).await.or_else(|e| {
        if e.kind() == ErrorKind::NotFound {
            Ok(())
        } else {
            Err(e).context("Failed to remove the log file")
        }
    })
}

/// Extracts the id from a line of the enclave log file, lines look like `[<id>] <message>`
pub fn parse_log_line(line: &str) -> Option<(u64, &str)> {
    let (log_id_str, message) = line.strip_prefix('[')?.split_once("] ")?;
    Some((log_id_str.parse().ok()?, message))
}
