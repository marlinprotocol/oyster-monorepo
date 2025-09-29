![Marlin Oyster Logo](./logo.svg)

# Indexer Framework

A generic Rust library for indexing Oyster 'market' job events from any blockchain into a Postgres database.

## Features

- Pluggable chain integration: implement the 'ChainHandler' trait for your chain (Ethereum, Sui, Solana, etc.).
- Persistence built in: use the provided 'Repository' to manage schema migrations, block tracking, and event storage in Postgres.
- Resumable sync: automatically picks up from the last processed block on restart.
- Structured tracing: integrated with tracing for debug/production observability.

## Getting Started

### Add as a dependency

Add this to your `Cargo.toml`

```
indexer-framework = { version = "0.1.0", path = "<oyster-monorepo-path>/operator/market-indexer/framework" }
```

### Implement the ChainHandler trait

The framework requires you to provide a chain-specific implementation:

```
use async_trait::async_trait;
use indexer_framework::chain::ChainHandler;
use indexer_framework::events::JobEvent;

pub struct MyChainHandler {
    // e.g., RPC client here
}

#[async_trait]
impl ChainHandler for MyChainHandler {
    async fn fetch_latest_block(&self) -> anyhow::Result<u64> {
        // Call your RPC endpoint
        Ok(12345)
    }

    async fn fetch_logs_and_group_by_block(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> anyhow::Result<std::collections::BTreeMap<u64, Vec<JobEvent>>> {
        // Query logs/events, group them by block
        Ok(std::collections::BTreeMap::new())
    }

    fn process_logs_in_block(
        &self,
        block_number: u64,
        logs: &[JobEvent],
        active_job_ids: &mut Vec<String>,
    ) -> anyhow::Result<Vec<JobEvent>> {
        // Turn raw logs into JobEvent records
        Ok(Vec::new())
    }
}
```

### Example projects

- [Arbitrum Indexer](../arb) – index logs from Arbitrum One market
- [Sui Indexer](../sui) – index events from Sui market

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
