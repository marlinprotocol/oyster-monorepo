use crate::logging::{log_message, rotated_path};
use anyhow::{bail, Context};
use serde_json::Value;
use std::{
    process::Stdio,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
};

pub async fn monitor_and_capture_logs(
    enclave_log_file_path: &str,
    script_log_file_path: &str,
    target_cid: u64,
    log_counter: Arc<AtomicU64>,
    max_log_file_size: u64,
) -> anyhow::Result<()> {
    loop {
        let enclave_id = wait_for_enclave_with_cid(target_cid)
            .await
            .context("Error in wait for enclave with cid call")?;
        let log_counter = log_counter.clone();
        log_message(
            script_log_file_path,
            &format!(
                "Enclave with CID {} detected: {}. Starting log capture.",
                target_cid, enclave_id
            ),
        )
        .await?;
        if let Err(e) = capture_logs(
            &enclave_id,
            enclave_log_file_path,
            script_log_file_path,
            log_counter,
            max_log_file_size,
        )
        .await
        {
            log_message(
                script_log_file_path,
                &format!(
                    "Error capturing logs for enclave {}: {}. Restarting capture.",
                    enclave_id, e
                ),
            )
            .await?;
        }
    }
}

async fn wait_for_enclave_with_cid(target_cid: u64) -> anyhow::Result<String> {
    loop {
        let output = Command::new("nitro-cli")
            .args(["describe-enclaves"])
            .output()
            .await
            .context("Failed to execute nitro-cli describe-enclaves")?;

        let stdout = String::from_utf8(output.stdout)
            .context("failed to typecast describe enclaves output to string")?;
        if let Some(enclave_id) = find_enclave_with_cid(&stdout, target_cid)? {
            return Ok(enclave_id);
        }

        // do not spin on nitro-cli while there is no enclave
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn find_enclave_with_cid(
    describe_enclaves: &str,
    target_cid: u64,
) -> anyhow::Result<Option<String>> {
    let enclaves: Value = serde_json::from_str(describe_enclaves)
        .context("failed to parse describe enclaves to json")?;
    if let Some(enclaves) = enclaves.as_array() {
        for enclave in enclaves {
            if let (Some(enclave_cid), Some(enclave_id)) = (
                enclave["EnclaveCID"].as_u64(),
                enclave["EnclaveID"].as_str(),
            ) {
                if enclave_cid == target_cid {
                    return Ok(Some(enclave_id.to_string()));
                }
            }
        }
    }

    Ok(None)
}

/// Appends lines to the enclave log file and moves the file aside when it gets too big.
/// At most two files exist, the current one and the one before it.
struct RotatingLog {
    path: String,
    file: tokio::fs::File,
    size: u64,
    max_size: u64,
}

impl RotatingLog {
    async fn open(path: &str, max_size: u64) -> anyhow::Result<Self> {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .context("Failed to open enclave log file")?;
        let size = file
            .metadata()
            .await
            .context("Failed to stat enclave log file")?
            .len();

        Ok(Self {
            path: path.to_owned(),
            file,
            size,
            max_size,
        })
    }

    async fn write_line(&mut self, line: &str) -> anyhow::Result<()> {
        if self.size > 0 && self.size + line.len() as u64 + 1 > self.max_size {
            tokio::fs::rename(&self.path, rotated_path(&self.path))
                .await
                .context("Failed to rotate enclave log file")?;
            *self = Self::open(&self.path, self.max_size).await?;
        }

        // single write so that readers do not see half a line
        self.file.write_all(format!("{line}\n").as_bytes()).await?;
        self.file.flush().await?;
        self.size += line.len() as u64 + 1;

        Ok(())
    }
}

async fn capture_logs(
    enclave_id: &str,
    enclave_log_file_path: &str,
    script_log_file_path: &str,
    log_counter: Arc<AtomicU64>,
    max_log_file_size: u64,
) -> anyhow::Result<()> {
    let mut child = Command::new("nitro-cli")
        .args(["console", "--enclave-id", enclave_id])
        .stdout(Stdio::piped())
        .spawn()
        .context("Failed to spawn nitro-cli process")?;

    // Open the file asynchronously
    let mut file = RotatingLog::open(enclave_log_file_path, max_log_file_size).await?;

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let mut reader = BufReader::new(stdout).lines();

    while let Some(line) = reader.next_line().await? {
        let current_count = log_counter.load(Ordering::Relaxed);
        let log_entry = format!("[{}] {}", current_count, line);

        file.write_line(&log_entry).await?;

        log_counter.fetch_add(1, Ordering::Relaxed);
    }

    let status = child.wait().await?;
    if !status.success() {
        bail!("Nitro CLI process exited with error");
    }

    log_message(script_log_file_path, "Nitro CLI process ended unexpectedly").await?;
    bail!("Nitro CLI process ended unexpectedly")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_path(name: &str) -> String {
        let path = std::env::temp_dir().join(format!("logger-test-{}-{name}", std::process::id()));
        let path = path.to_str().unwrap().to_owned();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(rotated_path(&path));
        path
    }

    #[test]
    fn finds_the_enclave_by_cid() {
        let output = r#"[
            {"EnclaveName": "a", "EnclaveID": "i-1-enc1", "EnclaveCID": 16, "State": "RUNNING"},
            {"EnclaveName": "b", "EnclaveID": "i-1-enc2", "EnclaveCID": 88, "State": "RUNNING"}
        ]"#;

        assert_eq!(
            find_enclave_with_cid(output, 88).unwrap(),
            Some("i-1-enc2".to_owned())
        );
        assert_eq!(find_enclave_with_cid(output, 18).unwrap(), None);
        assert_eq!(find_enclave_with_cid("[]", 88).unwrap(), None);
        assert!(find_enclave_with_cid("not json", 88).is_err());
    }

    #[tokio::test]
    async fn log_file_is_rotated_once_it_is_full() {
        let path = test_path("rotate");
        let mut log = RotatingLog::open(&path, 30).await.unwrap();

        for i in 1..=5 {
            // 10 bytes with the newline
            log.write_line(&format!("[{i}] hello")).await.unwrap();
        }

        assert_eq!(
            std::fs::read_to_string(rotated_path(&path)).unwrap(),
            "[1] hello\n[2] hello\n[3] hello\n"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[4] hello\n[5] hello\n"
        );

        // the file before the previous one is dropped
        for i in 6..=8 {
            log.write_line(&format!("[{i}] hello")).await.unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(rotated_path(&path)).unwrap(),
            "[4] hello\n[5] hello\n[6] hello\n"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[7] hello\n[8] hello\n"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(rotated_path(&path));
    }

    #[tokio::test]
    async fn a_line_bigger_than_the_limit_is_still_written() {
        let path = test_path("big-line");
        let mut log = RotatingLog::open(&path, 4).await.unwrap();

        log.write_line("[1] hello").await.unwrap();
        log.write_line("[2] hello").await.unwrap();

        assert_eq!(
            std::fs::read_to_string(rotated_path(&path)).unwrap(),
            "[1] hello\n"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[2] hello\n");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(rotated_path(&path));
    }

    #[tokio::test]
    async fn an_existing_file_counts_towards_the_limit() {
        let path = test_path("existing");
        std::fs::write(&path, "[1] hello\n[2] hello\n").unwrap();
        let mut log = RotatingLog::open(&path, 30).await.unwrap();

        log.write_line("[3] hello").await.unwrap();
        log.write_line("[4] hello").await.unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[4] hello\n");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(rotated_path(&path));
    }
}
