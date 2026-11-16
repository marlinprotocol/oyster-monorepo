pub mod bandwidth;

use std::io::{IsTerminal, Write};

use alloy::primitives::U256;
use anyhow::{Context, Result, bail};

use crate::configs::global::RATE_DECIMALS;

/// Parses a decimal token amount such as `1.5` into base units of a token with `decimals` decimals.
pub fn parse_token_amount(amount: &str, decimals: u32) -> Result<U256> {
    let amount = amount.trim();
    let (whole, fraction) = amount.split_once('.').unwrap_or((amount, ""));

    if whole.is_empty() && fraction.is_empty() {
        bail!("amount is empty");
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !fraction.chars().all(|c| c.is_ascii_digit()) {
        bail!("'{amount}' is not a decimal number");
    }
    if fraction.len() > decimals as usize {
        bail!("'{amount}' has more than {decimals} decimal places");
    }

    let digits = format!("{whole}{fraction:0<width$}", width = decimals as usize);
    U256::from_str_radix(&digits, 10).with_context(|| format!("'{amount}' is too large"))
}

/// Formats base units of a token with `decimals` decimals as a decimal number,
/// exact, with at least two decimal places.
pub fn format_token_amount(value: U256, decimals: u32) -> String {
    let digits = format!("{value:0>width$}", width = decimals as usize + 1);
    let (whole, fraction) = digits.split_at(digits.len() - decimals as usize);
    let fraction = fraction.trim_end_matches('0');

    format!("{whole}.{fraction:0<2}")
}

/// Like `format_token_amount`, shortened for display: six decimal places,
/// or six significant digits for amounts below one that would otherwise show as zero.
pub fn format_token_display(value: U256, decimals: u32) -> String {
    let exact = format_token_amount(value, decimals);
    let (whole, fraction) = exact.split_once('.').unwrap_or((&exact, ""));

    let leading_zeros = fraction.chars().take_while(|c| *c == '0').count();
    let keep = if whole == "0" && leading_zeros < fraction.len() {
        (leading_zeros + 6).max(6)
    } else {
        6
    };
    if fraction.len() <= keep {
        return exact;
    }

    format!("{whole}.{:0<2}", fraction[..keep].trim_end_matches('0'))
}

/// Resolves the amount of a deposit or withdrawal, given either in base units of the token
/// (`--amount`) or as a decimal number of tokens (`--amount-usdc`), to base units.
pub fn resolve_amount(
    base_units: Option<U256>,
    tokens: Option<&str>,
    decimals: u32,
) -> Result<Option<U256>> {
    match (base_units, tokens) {
        (Some(_), Some(_)) => bail!("Specify only one of --amount and --amount-usdc"),
        (Some(amount), None) => Ok(Some(amount)),
        (None, Some(amount)) => Ok(Some(
            parse_token_amount(amount, decimals).context("Failed to parse --amount-usdc")?,
        )),
        (None, None) => Ok(None),
    }
}

/// The market charges `rate / 10^extra_decimals` token base units per second, while operators
/// publish rates in USD per second with `RATE_DECIMALS` decimals. The two only agree when
/// `token_decimals + extra_decimals == RATE_DECIMALS`. Returns a warning when they do not,
/// as on BSC (18 decimal token, EXTRA_DECIMALS 12).
pub fn mispricing_warning(token_decimals: u32, extra_decimals: i64) -> Option<String> {
    let charged_decimals = token_decimals as i64 + extra_decimals;
    let off_by = charged_decimals - RATE_DECIMALS as i64;
    if off_by == 0 {
        return None;
    }

    Some(format!(
        "The market contract of this deployment misprices jobs: operators publish rates with {RATE_DECIMALS} decimals, \
         the contract divides them by 10^{extra_decimals} and charges the result in base units of a token with {token_decimals} decimals. \
         Jobs are charged 10^{} times {} than the published price. \
         The amounts shown here are what the contract actually moves. Operators may not serve jobs at this price.",
        off_by.abs(),
        if off_by > 0 { "less" } else { "more" },
    ))
}

/// True when the command can ask the user a question.
pub fn is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// Asks a yes/no question on the terminal, anything other than y/yes is a no.
pub fn ask_yes_no(question: &str) -> Result<bool> {
    eprint!("{question} [y/N]: ");
    std::io::stderr().flush().ok();

    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("Failed to read answer")?;

    Ok(is_yes(&answer))
}

fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Amount the market takes out of a job at its next settlement, before it is capped to the
/// job balance: `ceil(rate * elapsed / 10^EXTRA_DECIMALS)` as in `MarketV1._jobSettle`.
pub fn accrued_since_settlement(
    rate: U256,
    last_settled: i64,
    now: u64,
    extra_decimals: i64,
) -> U256 {
    let elapsed = now.saturating_sub(u64::try_from(last_settled).unwrap_or(0));
    let scale = U256::from(10).pow(U256::from(extra_decimals.max(0)));

    rate.saturating_mul(U256::from(elapsed))
        .saturating_add(scale - U256::from(1))
        / scale
}

/// What a deposit into a job does once the market settles the job the next time.
///
/// The market adds a deposit to the balance without settling first, and the next settlement
/// charges the whole time since the last one, capped to the balance. A deposit into a job
/// whose balance already ran out therefore first pays for the time since the last settlement,
/// whether the enclave was running or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositImpact {
    /// Balance left in the job right now, 0 if it ran out.
    pub current_balance: U256,
    /// True if the balance on chain is already used up by the time since the last settlement.
    pub ran_out: bool,
    /// Seconds since the balance ran out, 0 if it did not.
    pub ran_out_secs_ago: u64,
    /// Part of the deposit that goes to the operator for time that already passed
    /// and that the old balance does not cover.
    pub to_gap: U256,
    /// Part of the deposit that is left for new runtime.
    pub usable: U256,
    /// Seconds of runtime the job has after the deposit, None for zero rate jobs.
    pub secs_after_deposit: Option<u64>,
}

pub fn deposit_impact(
    balance: U256,
    rate: U256,
    last_settled: i64,
    now: u64,
    extra_decimals: i64,
    amount: U256,
) -> DepositImpact {
    let accrued = accrued_since_settlement(rate, last_settled, now, extra_decimals);
    let scale = U256::from(10).pow(U256::from(extra_decimals.max(0)));

    let current_balance = balance.saturating_sub(accrued);
    let ran_out = !rate.is_zero() && accrued >= balance;
    let to_gap = accrued.saturating_sub(balance).min(amount);
    let usable = amount - to_gap;

    let ran_out_secs_ago = if ran_out {
        // seconds of runtime the balance paid for
        let covered = (balance.saturating_mul(scale) / rate).saturating_to::<u64>();
        let elapsed = now.saturating_sub(u64::try_from(last_settled).unwrap_or(0));
        elapsed.saturating_sub(covered)
    } else {
        0
    };

    let secs_after_deposit = (!rate.is_zero()).then(|| {
        (current_balance.saturating_add(usable).saturating_mul(scale) / rate).saturating_to::<u64>()
    });

    DepositImpact {
        current_balance,
        ran_out,
        ran_out_secs_ago,
        to_gap,
        usable,
        secs_after_deposit,
    }
}

/// Formats a number of seconds as e.g. `2d 3h 4m` or `45s`.
pub fn format_duration(secs: u64) -> String {
    let (days, hours, minutes) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    match (days, hours, minutes) {
        (0, 0, 0) => format!("{}s", secs),
        (0, 0, m) => format!("{}m", m),
        (0, h, m) => format!("{}h {}m", h, m),
        (d, h, m) => format!("{}d {}h {}m", d, h, m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 0.05 USDC/hour on a 6 decimal token: 0.05e18 / 3600 per second
    const RATE: u64 = 13_888_888_888_889;
    const T0: i64 = 1_700_000_000;

    fn u(x: u64) -> U256 {
        U256::from(x)
    }

    #[test]
    fn accrual_rounds_up_like_the_contract() {
        // rate * 1s = 13.88 base units, the contract charges 14
        assert_eq!(
            accrued_since_settlement(u(RATE), T0, T0 as u64 + 1, 12),
            u(14)
        );
        // one hour is 0.05 USDC and a bit from rounding the rate up
        assert_eq!(
            accrued_since_settlement(u(RATE), T0, T0 as u64 + 3600, 12),
            u(50_001)
        );
        assert_eq!(accrued_since_settlement(u(RATE), T0, T0 as u64, 12), u(0));
        assert_eq!(accrued_since_settlement(u(0), T0, T0 as u64 + 99, 12), u(0));
        // clock behind the chain
        assert_eq!(
            accrued_since_settlement(u(RATE), T0, T0 as u64 - 5, 12),
            u(0)
        );
    }

    #[test]
    fn deposit_into_running_job_is_fully_usable() {
        // 1 USDC balance, 1 hour in, deposit 1 USDC
        let impact = deposit_impact(
            u(1_000_000),
            u(RATE),
            T0,
            T0 as u64 + 3600,
            12,
            u(1_000_000),
        );
        assert!(!impact.ran_out);
        assert_eq!(impact.ran_out_secs_ago, 0);
        assert_eq!(impact.current_balance, u(949_999));
        assert_eq!(impact.to_gap, u(0));
        assert_eq!(impact.usable, u(1_000_000));
        // 1.949999 USDC at 0.05 USDC/hour is a bit under 39 hours
        assert_eq!(impact.secs_after_deposit, Some(140_399));
    }

    #[test]
    fn deposit_one_day_late_pays_for_the_downtime() {
        // review H-3: 0.05 USDC/hour job, 1 USDC balance lasts 20 hours,
        // the top-up comes 24 hours after that
        let now = T0 as u64 + 44 * 3600;
        let impact = deposit_impact(u(1_000_000), u(RATE), T0, now, 12, u(2_000_000));
        assert!(impact.ran_out);
        assert_eq!(impact.current_balance, u(0));
        // 44 hours accrued (2.200001 USDC) against a balance of 1 USDC
        assert_eq!(impact.to_gap, u(1_200_001));
        assert_eq!(impact.usable, u(799_999));
        assert_eq!(impact.ran_out_secs_ago, 24 * 3600 + 1);
    }

    #[test]
    fn deposit_into_old_job_is_lost_entirely() {
        let now = T0 as u64 + 400 * 86400;
        let impact = deposit_impact(u(1_000_000), u(RATE), T0, now, 12, u(5_000_000));
        assert!(impact.ran_out);
        assert_eq!(impact.to_gap, u(5_000_000));
        assert_eq!(impact.usable, u(0));
        assert_eq!(impact.secs_after_deposit, Some(0));
    }

    #[test]
    fn balance_used_up_exactly_counts_as_ran_out() {
        // the contract takes the whole balance when accrued == balance
        let impact = deposit_impact(u(50_001), u(RATE), T0, T0 as u64 + 3600, 12, u(100));
        assert!(impact.ran_out);
        assert_eq!(impact.to_gap, u(0));
        assert_eq!(impact.usable, u(100));
    }

    #[test]
    fn zero_rate_job_never_runs_out() {
        let impact = deposit_impact(u(0), u(0), T0, T0 as u64 + 999_999, 12, u(100));
        assert!(!impact.ran_out);
        assert_eq!(impact.usable, u(100));
        assert_eq!(impact.secs_after_deposit, None);
    }

    #[test]
    fn token_amount_parsing() {
        assert_eq!(parse_token_amount("1", 6).unwrap(), u(1_000_000));
        assert_eq!(parse_token_amount("1.5", 6).unwrap(), u(1_500_000));
        assert_eq!(parse_token_amount("0.000001", 6).unwrap(), u(1));
        assert_eq!(parse_token_amount(".5", 6).unwrap(), u(500_000));
        assert_eq!(parse_token_amount("2.", 6).unwrap(), u(2_000_000));
        assert_eq!(parse_token_amount("7", 0).unwrap(), u(7));
        // more than u64 base units on an 18 decimal token
        assert_eq!(
            parse_token_amount("100", 18).unwrap(),
            U256::from(100u128 * 10u128.pow(18))
        );

        assert!(parse_token_amount("0.0000001", 6).is_err());
        assert!(parse_token_amount("", 6).is_err());
        assert!(parse_token_amount(".", 6).is_err());
        assert!(parse_token_amount("-1", 6).is_err());
        assert!(parse_token_amount("1e6", 6).is_err());
        assert!(parse_token_amount("0x10", 6).is_err());
        assert!(parse_token_amount("1,5", 6).is_err());
        assert!(parse_token_amount(&"9".repeat(80), 6).is_err());
    }

    #[test]
    fn token_amount_formatting() {
        assert_eq!(format_token_amount(u(1_000_000), 6), "1.00");
        assert_eq!(format_token_amount(u(1_500_000), 6), "1.50");
        assert_eq!(format_token_amount(u(1), 6), "0.000001");
        assert_eq!(format_token_amount(u(0), 6), "0.00");
        assert_eq!(format_token_amount(u(123_456_789), 6), "123.456789");
        assert_eq!(format_token_amount(u(12803), 18), "0.000000000000012803");
        assert_eq!(format_token_amount(u(42), 0), "42.00");
        // does not panic on values beyond u128
        assert!(format_token_amount(U256::MAX, 18).len() > 60);
    }

    #[test]
    fn token_display_formatting() {
        // exact on a 6 decimal token
        assert_eq!(format_token_display(u(50_000), 6), "0.05");
        assert_eq!(format_token_display(u(1), 6), "0.000001");
        // hourly rate of 13888888888889 per second with 18 decimals
        assert_eq!(
            format_token_display(u(13_888_888_888_889 * 3600), 18),
            "0.05"
        );
        assert_eq!(
            format_token_display(U256::from(1_234_567_890_123_456_789u128), 18),
            "1.234567"
        );
        // too small for six places: six significant digits instead of zero
        assert_eq!(format_token_display(u(12803), 18), "0.000000000000012803");
        assert_eq!(
            format_token_display(u(51_212_517_700_194_000), 30),
            "0.0000000000000512125"
        );
        assert_eq!(format_token_display(u(1_000_000_000_001), 18), "0.000001");
        assert_eq!(format_token_display(u(1_999_999), 6), "1.999999");
        assert_eq!(format_token_display(u(0), 18), "0.00");
    }

    #[test]
    fn amount_in_base_units_or_tokens() {
        assert_eq!(
            resolve_amount(Some(u(1_000_000)), None, 6).unwrap(),
            Some(u(1_000_000))
        );
        assert_eq!(
            resolve_amount(None, Some("1"), 6).unwrap(),
            Some(u(1_000_000))
        );
        assert_eq!(resolve_amount(None, None, 6).unwrap(), None);
        assert!(resolve_amount(Some(u(1)), Some("1"), 6).is_err());
        assert!(resolve_amount(None, Some("1.0000001"), 6).is_err());

        // 20 tokens with 18 decimals do not fit in a u64 of base units
        let twenty = resolve_amount(None, Some("20"), 18).unwrap().unwrap();
        assert!(twenty > U256::from(u64::MAX));
        assert_eq!(format_token_amount(twenty, 18), "20.00");
    }

    #[test]
    fn mispricing_is_flagged_only_where_decimals_do_not_add_up() {
        // Arbitrum One and Sui: 6 decimal USDC, EXTRA_DECIMALS 12
        assert_eq!(mispricing_warning(6, 12), None);
        // BSC: 18 decimal token, EXTRA_DECIMALS 12
        let warning = mispricing_warning(18, 12).unwrap();
        assert!(warning.contains("10^12 times less"), "{warning}");
        assert!(
            mispricing_warning(6, 0)
                .unwrap()
                .contains("10^12 times more")
        );
    }

    #[test]
    fn bsc_job_from_the_review_is_not_expired() {
        // BSC job 0: rate 14225699361165, balance 12803 base units for 15 minutes.
        // Without the EXTRA_DECIMALS scaling it looks used up after one second.
        let rate = u(14_225_699_361_165);
        let balance = u(12803);
        let after_10_min = accrued_since_settlement(rate, T0, T0 as u64 + 600, 12);
        assert_eq!(after_10_min, u(8536));
        assert!(after_10_min < balance);
        assert!(accrued_since_settlement(rate, T0, T0 as u64 + 900, 12) >= balance);
    }

    #[test]
    fn yes_parsing() {
        assert!(is_yes("y\n"));
        assert!(is_yes(" YES \n"));
        assert!(!is_yes("\n"));
        assert!(!is_yes("n"));
        assert!(!is_yes("yep"));
    }

    #[test]
    fn duration_formatting() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(300), "5m");
        assert_eq!(format_duration(3 * 3600 + 120), "3h 2m");
        assert_eq!(format_duration(2 * 86400 + 60), "2d 0h 1m");
    }
}
