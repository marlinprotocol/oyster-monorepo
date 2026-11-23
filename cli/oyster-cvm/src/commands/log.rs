use anyhow::{Context, Result};
use clap::Args;
use futures_util::StreamExt;
use reqwest::Client;
use std::time::Duration;
use tokio::time::timeout;
use tracing::info;

const STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Stream logs from an Oyster CVM instance
#[derive(Args)]
pub struct LogArgs {
    /// IP address of the instance
    #[arg(short, long, required = true)]
    pub ip: String,

    /// Optional log ID to start streaming from
    #[arg(short, long)]
    pub start_from: Option<String>,

    /// Include log ID prefix in output
    #[arg(short, long, default_value_t = false)]
    pub with_log_id: bool,

    /// Suppress connection status message
    #[arg(short, long, default_value_t = false)]
    pub quiet: bool,
}

pub async fn stream_logs(args: LogArgs) -> Result<()> {
    let ip = args.ip;
    let start_from = args.start_from;
    let quiet = args.quiet;
    let with_log_id = args.with_log_id;

    let mut url = format!("http://{}:516/logs/stream", ip);
    if let Some(start_id) = start_from {
        url.push_str(&format!("?start_from={}", start_id));
    }

    let client = Client::new();
    let response = match timeout(STREAM_CONNECT_TIMEOUT, client.get(&url).send()).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => anyhow::bail!("Failed to connect to console stream: {}", e),
        Err(_) => anyhow::bail!(
            "Connection to console stream timed out after {} seconds",
            STREAM_CONNECT_TIMEOUT.as_secs()
        ),
    };

    let mut stream = response.bytes_stream();

    if !quiet {
        info!("Connected to log stream. Waiting for events...");
    }

    // An HTTP chunk can hold several events, part of one, or end in the middle of a character.
    // Collect the bytes and take complete events out of them.
    let mut parser = SseParser::default();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read log stream")?;
        for log in parser.push(&chunk) {
            if log.trim().is_empty() {
                continue;
            }

            println!("{}", format_log_line(&log, with_log_id).trim_end());
        }
    }

    Ok(())
}

/// Incremental parser for a `text/event-stream` body, returns the data of each complete event.
#[derive(Default)]
struct SseParser {
    // bytes of the line that is not complete yet
    line: Vec<u8>,
    // data lines of the event that is not complete yet
    data: Vec<String>,
}

impl SseParser {
    fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        let mut events = Vec::new();

        for &byte in chunk {
            if byte != b'\n' {
                self.line.push(byte);
                continue;
            }

            // a full line, only now is it safe to decode it
            if self.line.last() == Some(&b'\r') {
                self.line.pop();
            }
            let line = String::from_utf8_lossy(&self.line).into_owned();
            self.line.clear();

            if line.is_empty() {
                // a blank line ends the event
                if !self.data.is_empty() {
                    events.push(self.data.join("\n"));
                    self.data.clear();
                }
            } else if let Some(data) = line.strip_prefix("data:") {
                self.data
                    .push(data.strip_prefix(' ').unwrap_or(data).to_owned());
            }
            // comments (keep alive) and other fields are not log lines
        }

        events
    }
}

/// Log lines look like `[<log id>] <message>`, the ID is shown only when asked for.
fn format_log_line(log: &str, with_log_id: bool) -> &str {
    if with_log_id {
        return log;
    }

    match log.find("] ") {
        Some(idx) if log.starts_with('[') => &log[idx + 2..],
        // an empty message
        None if log.starts_with('[') && log.ends_with(']') => "",
        _ => log,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn several_events_in_one_chunk() {
        let mut parser = SseParser::default();
        let events = parser.push(b"data:[1] one\n\ndata:[2] two\n\ndata:[3] three\n\n");
        assert_eq!(events, ["[1] one", "[2] two", "[3] three"]);
    }

    #[test]
    fn event_split_across_chunks() {
        let mut parser = SseParser::default();
        assert!(parser.push(b"data:[1] hello ").is_empty());
        assert!(parser.push(b"world\n").is_empty());
        assert_eq!(parser.push(b"\ndata:[2] ne"), ["[1] hello world"]);
        assert_eq!(parser.push(b"xt\n\n"), ["[2] next"]);
    }

    #[test]
    fn chunk_boundary_inside_a_character() {
        let line = "data:[1] caf\u{e9} \u{1f980}\n\n".as_bytes();
        for split in 1..line.len() {
            let mut parser = SseParser::default();
            let mut events = parser.push(&line[..split]);
            events.extend(parser.push(&line[split..]));
            assert_eq!(events, ["[1] caf\u{e9} \u{1f980}"], "split at {split}");
        }
    }

    #[test]
    fn keep_alives_and_other_fields_are_skipped() {
        let mut parser = SseParser::default();
        let events = parser.push(b":\n\nevent: log\ndata: [1] spaced\r\n\r\n:keep-alive\n\n");
        assert_eq!(events, ["[1] spaced"]);
    }

    #[test]
    fn multi_line_data_is_one_event() {
        let mut parser = SseParser::default();
        assert_eq!(parser.push(b"data:[1] a\ndata:b\n\n"), ["[1] a\nb"]);
    }

    #[test]
    fn log_id_is_stripped_unless_asked_for() {
        assert_eq!(format_log_line("[12] hello] world", false), "hello] world");
        assert_eq!(format_log_line("[12] hello", true), "[12] hello");
        assert_eq!(format_log_line("[12]", false), "");
        // lines without an ID used to be dropped
        assert_eq!(format_log_line("no id here", false), "no id here");
        assert_eq!(format_log_line("a] b", false), "a] b");
    }
}
