mod handlers;
mod schema;

use std::time::Duration;

use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::rpc::types::eth::Log;
use alloy::rpc::types::Filter;
use alloy::transports::http::reqwest::Url;
use anyhow::{anyhow, Context, Result};
use diesel::deserialize::{self, FromSql, FromSqlRow};
use diesel::expression::AsExpression;
use diesel::pg::{Pg, PgValue};
use diesel::prelude::*;
use diesel::serialize::{self, IsNull, Output, ToSql};
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use handlers::handle_log;
use std::io::Write;
use tracing::{info, instrument};

pub trait LogsProvider {
    fn latest_block(&mut self) -> Result<u64>;
    fn logs(&self, start_block: u64, end_block: u64) -> Result<impl IntoIterator<Item = Log>>;
    fn block_timestamp(&self, block_number: u64) -> Result<u64>;
}

#[derive(Clone)]
pub struct AlloyProvider {
    pub url: Url,
    pub contract: Address,
}

impl LogsProvider for AlloyProvider {
    fn latest_block(&mut self) -> Result<u64> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(rt.block_on(
            alloy::providers::ProviderBuilder::new()
                .on_http(self.url.clone())
                .get_block_number(),
        )?)
    }

    fn logs(&self, start_block: u64, end_block: u64) -> Result<impl IntoIterator<Item = Log>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let addresses = self.contract.clone();
        Ok(rt.block_on(
            alloy::providers::ProviderBuilder::new()
                .on_http(self.url.clone())
                .get_logs(
                    &Filter::new()
                        .from_block(start_block)
                        .to_block(end_block)
                        .address(addresses),
                ),
        )?)
    }

    fn block_timestamp(&self, block_number: u64) -> Result<u64> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(rt
            .block_on(
                alloy::providers::ProviderBuilder::new()
                    .on_http(self.url.clone())
                    .get_block_by_number(block_number.into(), false),
            )?
            .map(|b| b.header.timestamp)
            .unwrap_or(0)
            .into())
    }
}

#[instrument(level = "info", skip_all, parent = None)]
pub fn event_loop(
    conn: &mut PgConnection,
    mut provider: impl LogsProvider,
    range_size: u64,
) -> Result<()> {
    // fetch last updated block from the db
    let mut last_updated = schema::sync::table
        .select(schema::sync::block)
        .limit(1)
        .load::<i64>(conn)
        .context("failed to fetch last updated block")?
        .into_iter()
        .last()
        .ok_or(anyhow!(
            "no last updated block found, should never happen unless the database is corrupted"
        ))? as u64;

    info!(block = last_updated, "last updated");

    loop {
        // fetch latest block from the rpc
        let latest_block = provider.latest_block()?;

        info!(block = latest_block, "latest block");

        // should not really ever be true
        // effectively means the rpc was rolled back
        if latest_block < last_updated {
            return Err(anyhow!(
                "rpc is behind the db, should never happen unless the rpc was rolled back"
            ));
        }

        if latest_block == last_updated {
            // we are up to date, simply sleep for a bit
            std::thread::sleep(Duration::from_secs(5));
            continue;
        }

        // start from the next block to what has already been processed
        let start_block = last_updated + 1;
        // cap block range using range_size
        // might need some babysitting during initial sync
        let end_block = std::cmp::min(start_block + range_size - 1, latest_block);

        info!(start_block, end_block, "fetching range");

        let logs = provider.logs(start_block, end_block)?;

        info!(start_block, end_block, "processing range");

        // execute db writes within a transaction for consistency
        // NOTE: diesel transactions are synchronous, async is not allowed inside
        // might be limiting for certain things like making rpc queries while processing logs
        // using a temporary tokio runtime is a possibility
        conn.transaction(|conn| {
            for log in logs {
                handle_log(conn, log).context("failed to handle log")?;
            }
            diesel::update(schema::sync::table)
                .set(schema::sync::block.eq(end_block as i64))
                .execute(conn)
                .context("failed to update latest block")
        })?;

        last_updated = end_block;
    }
}

pub fn start_from(conn: &mut PgConnection, start: u64) -> Result<bool> {
    diesel::update(schema::sync::table)
        .filter(schema::sync::block.lt(start as i64 - 1))
        .set(schema::sync::block.eq(start as i64 - 1))
        .execute(conn)
        .map(|x| x > 0)
        .context("failed to set start block")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, AsExpression, FromSqlRow)]
#[diesel(sql_type = crate::schema::sql_types::ResultOutcome)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub enum ResultOutcome {
    Pending,
    Passed,
    Failed,
    Vetoed,
}

impl ResultOutcome {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            ResultOutcome::Pending => "PENDING",
            ResultOutcome::Passed => "PASSED",
            ResultOutcome::Failed => "FAILED",
            ResultOutcome::Vetoed => "VETOED",
        }
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(ResultOutcome::Pending),
            1 => Some(ResultOutcome::Passed),
            2 => Some(ResultOutcome::Failed),
            3 => Some(ResultOutcome::Vetoed),
            _ => None,
        }
    }
}

impl ToSql<crate::schema::sql_types::ResultOutcome, Pg> for ResultOutcome {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        out.write_all(self.as_db_str().as_bytes())?;
        Ok(IsNull::No)
    }
}

impl FromSql<crate::schema::sql_types::ResultOutcome, Pg> for ResultOutcome {
    fn from_sql(value: PgValue<'_>) -> deserialize::Result<Self> {
        match value.as_bytes() {
            b"PENDING" => Ok(ResultOutcome::Pending),
            b"PASSED" => Ok(ResultOutcome::Passed),
            b"FAILED" => Ok(ResultOutcome::Failed),
            b"VETOED" => Ok(ResultOutcome::Vetoed),
            other => Err(format!("unknown result_outcome value: {:?}", other).into()),
        }
    }
}
