use indexer_framework::LogsProvider;
use anyhow::Result;

pub struct MockProvider {
    pub timestamp: u64,
}

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
        // Return timestamp + 4 seconds
        Ok(self.timestamp + 4)
    }
}

impl MockProvider {
    pub fn new(timestamp: u64) -> Self {
        Self { timestamp }
    }
}
