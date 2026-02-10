use anyhow::Result;
use indexer_framework::LogsProvider;

pub struct MockProvider {
    pub timestamp: u64,
}

pub const DEFAULT_BLOCK_TIMESTAMP_OFFSET: u64 = 4;

impl LogsProvider for MockProvider {
    fn latest_block(&mut self) -> Result<u64> {
        Ok(100)
    }

    fn logs(
        &self,
        _start_block: u64,
        _end_block: u64,
    ) -> Result<impl IntoIterator<Item = alloy::rpc::types::Log>> {
        Ok(vec![])
    }

    fn block_timestamp(&self, _block_number: u64) -> Result<u64> {
        Ok(self.timestamp + DEFAULT_BLOCK_TIMESTAMP_OFFSET)
    }
}

impl MockProvider {
    pub fn new(timestamp: u64) -> Self {
        Self { timestamp }
    }
}
