use alloy::primitives::U256;
use anyhow::{Context, Result};
use inquire::{Select, Text};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Get current Unix timestamp in seconds
pub fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

/// Get start timestamp from user input if not provided
pub async fn get_start_timestamp(provided_timestamp: Option<u64>) -> Result<U256> {
    if let Some(timestamp) = provided_timestamp {
        return Ok(U256::from(timestamp));
    }

    let options = vec!["Start subscription now", "Start with some delay"];
    let answer = Select::new("When should the subscription start?", options)
        .prompt()
        .context("Failed to get start time preference")?;

    let current_time = get_current_timestamp();

    match answer {
        "Start subscription now" => Ok(U256::from(current_time)),
        "Start with some delay" => {
            let delay_input = Text::new("Enter delay in seconds:")
                .prompt()
                .context("Failed to get delay input")?;

            let delay = delay_input
                .parse::<u64>()
                .context("Invalid delay format. Please enter a number.")?;

            Ok(U256::from(current_time + delay))
        }
        _ => Ok(U256::from(current_time)), // Default fallback
    }
}

/// Get termination timestamp from user input if not provided
pub async fn get_termination_timestamp(
    start_timestamp: U256,
    provided_timestamp: Option<u64>,
) -> Result<U256> {
    if let Some(timestamp) = provided_timestamp {
        return Ok(U256::from(timestamp));
    }

    let options = vec!["Predefined duration", "Custom termination timestamp"];
    let answer = Select::new("Select termination option:", options)
        .prompt()
        .context("Failed to get termination option")?;

    match answer {
        "Predefined duration" => {
            let durations = vec!["10 minutes", "1 hour", "6 hours", "1 day", "7 days"];

            let selected_duration = Select::new("Select duration:", durations)
                .prompt()
                .context("Failed to get predefined duration")?;

            let duration_seconds = match selected_duration {
                "10 minutes" => 10 * 60,
                "1 hour" => 60 * 60,
                "6 hours" => 6 * 60 * 60,
                "1 day" => 24 * 60 * 60,
                "7 days" => 7 * 24 * 60 * 60,
                _ => 60 * 60, // Default to 1 hour
            };

            Ok(start_timestamp + U256::from(duration_seconds))
        }
        "Custom termination timestamp" => {
            let timestamp_input =
                Text::new("Enter termination timestamp (in seconds since epoch):")
                    .prompt()
                    .context("Failed to get custom timestamp")?;

            let timestamp = timestamp_input
                .parse::<u64>()
                .context("Invalid timestamp format. Please enter a number.")?;

            let current_time = get_current_timestamp();
            if timestamp <= current_time {
                return Err(anyhow::anyhow!(
                    "Termination timestamp must be in the future"
                ));
            }

            Ok(U256::from(timestamp))
        }
        _ => Ok(start_timestamp + U256::from(60 * 60)), // Default to 1 hour
    }
}

/// Get periodic gap from user input if not provided
pub async fn get_periodic_gap(provided_gap: Option<u64>) -> Result<U256> {
    if let Some(gap) = provided_gap {
        return Ok(U256::from(gap));
    }

    let options = vec!["Predefined interval", "Custom periodic gap (sec)"];
    let answer = Select::new("Select periodic gap option:", options)
        .prompt()
        .context("Failed to get periodic gap option")?;

    match answer {
        "Predefined interval" => {
            let intervals = vec![
                "30 seconds",
                "60 seconds",
                "10 minutes",
                "1 hour",
                "3 hours",
            ];

            let selected_interval = Select::new("Select interval:", intervals)
                .prompt()
                .context("Failed to get predefined interval")?;

            let interval_seconds = match selected_interval {
                "30 seconds" => 30,
                "60 seconds" => 60,
                "10 minutes" => 10 * 60,
                "1 hour" => 60 * 60,
                "3 hours" => 3 * 60 * 60,
                _ => 60, // Default to 60 seconds
            };

            Ok(U256::from(interval_seconds))
        }
        "Custom periodic gap (sec)" => {
            let gap_input = Text::new("Enter periodic gap in seconds:")
                .prompt()
                .context("Failed to get custom gap")?;

            let gap = gap_input
                .parse::<u64>()
                .context("Invalid gap format. Please enter a number.")?;

            if gap == 0 {
                return Err(anyhow::anyhow!("Periodic gap must be greater than zero"));
            }

            Ok(U256::from(gap))
        }
        _ => Ok(U256::from(60)), // Default to 60 seconds
    }
}
