use std::time::Duration;

use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::providers::RootProvider;
use alloy::rpc::client::RpcClient;
use alloy::rpc::types::eth::Log;
use alloy::rpc::types::Filter;
use alloy::transports::http::reqwest::Client;
use alloy::transports::http::reqwest::Url;
use alloy::transports::http::Http;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use indexer_framework::LogsProvider;
use indexer_framework::RpcError;

// limits for a single rpc request
// without them a stalled connection hangs the indexer forever
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct AlloyProvider {
    pub url: Url,
    pub contract: Address,
}

impl AlloyProvider {
    fn runtime() -> Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build runtime")
    }

    fn client(&self) -> Result<RootProvider<Http<Client>>> {
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("failed to build http client")?;
        let http = Http::with_client(client, self.url.clone());

        Ok(RootProvider::new(RpcClient::new(http, false)))
    }

    fn block_timestamp_once(&self, block_number: u64) -> Result<u64> {
        let rt = Self::runtime()?;
        let client = self.client()?;

        rt.block_on(client.get_block_by_number(block_number.into(), false))?
            .map(|b| b.header.timestamp)
            // the rpc node answering this request might not have the block yet
            .ok_or(anyhow!("block {block_number} not found on the rpc"))
    }
}

impl LogsProvider for AlloyProvider {
    fn latest_block(&mut self) -> Result<u64> {
        let rt = Self::runtime()?;
        let client = self.client()?;

        Ok(rt.block_on(client.get_block_number())?)
    }

    fn logs(&self, start_block: u64, end_block: u64) -> Result<impl IntoIterator<Item = Log>> {
        let rt = Self::runtime()?;
        let client = self.client()?;

        Ok(rt.block_on(
            client.get_logs(
                &Filter::new()
                    .from_block(start_block)
                    .to_block(end_block)
                    .address(self.contract),
            ),
        )?)
    }

    fn block_timestamp(&self, block_number: u64) -> Result<u64> {
        // this is called by handlers while a range is being processed
        // mark failures as rpc errors so the event loop retries the range instead of stopping
        self.block_timestamp_once(block_number).map_err(|err| {
            RpcError(format!(
                "failed to fetch timestamp of block {block_number}: {err:#}"
            ))
            .into()
        })
    }
}
