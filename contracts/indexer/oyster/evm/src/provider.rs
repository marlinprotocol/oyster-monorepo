use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::rpc::types::eth::Log;
use alloy::rpc::types::Filter;
use alloy::transports::http::reqwest::Url;
use anyhow::Result;
use indexer_framework::LogsProvider;

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
        Ok(rt.block_on(
            alloy::providers::ProviderBuilder::new()
                .on_http(self.url.clone())
                .get_logs(
                    &Filter::new()
                        .from_block(start_block)
                        .to_block(end_block)
                        .address(self.contract),
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

