# Provider Pattern Architecture

This document explains the architecture pattern for supporting multiple blockchain providers in the Oyster indexer framework.

## Overview

The framework uses a trait-based abstraction pattern that allows different blockchain implementations (EVM, Sui, Arbitrum, Monad, etc.) to be added without modifying existing code. Each chain has its own isolated implementation that implements the `LogsProvider` trait.

## Architecture

```txt
┌─────────────────────────────────────────────────────────────┐
│                   Framework (oyster/framework)              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         LogsProvider Trait (interface)               │   │
│  │  - latest_block(&mut self) -> Result<u64>            │   │
│  │  - logs(&self, start_block, end_block) -> Logs       │   │
│  │  - block_timestamp(&self, block_number) -> u64       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         event_loop<P: LogsProvider>(...)             │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │ implements
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────┴────────┐  ┌───────┴───────┐  ┌────────┴───────┐
│  EVM Provider  │  │  Sui Provider │  │ Monad Provider │
│ AlloyProvider  │  │  SuiProvider  │  │ MonadProvider  │
└────────────────┘  └───────────────┘  └────────────────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                            ▼
        ┌──────────────────────────────────────┐
        │     Handlers (Chain-Agnostic)        │
        │  handle_log(conn, log, &LogsProvider)│
        └──────────────────────────────────────┘
```

## Key Principles

1. **Trait-based abstraction:** All providers implement the `LogsProvider` trait defined in the framework
2. **Handler isolation:** Handlers only depend on the `LogsProvider` trait, not concrete provider types
3. **Chain independence:** Each chain's code is completely isolated in its own directory
4. **Framework neutrality:** The framework doesn't know about specific chains - it only knows the trait
5. **Extensibility:** Adding new chains requires zero changes to existing chains

## LogsProvider Trait

The `LogsProvider` trait defines three methods that all blockchain providers must implement:

```rust
pub trait LogsProvider {
    /// Get the latest block/checkpoint number from the chain
    fn latest_block(&mut self) -> Result<u64>;

    /// Fetch logs/events for a block range
    fn logs(&self, start_block: u64, end_block: u64) -> Result<impl IntoIterator<Item = Log>>;

    /// Get the timestamp for a specific block/checkpoint
    fn block_timestamp(&self, block_number: u64) -> Result<u64>;
}
```

## Adding a New Chain

To add support for a new blockchain (e.g., Monad), follow these steps:

### 1. Create Chain Directory

Create a new directory under `oyster/`:

```txt
oyster/monad/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── provider.rs
│   ├── handlers/
│   │   ├── mod.rs
│   │   └── ... (handler files)
│   └── constants.rs
```

### 2. Define Provider Struct

In `oyster/monad/src/provider.rs`, define your provider struct with chain-specific fields:

```rust
use indexer_framework::LogsProvider;
use alloy::rpc::types::eth::Log;
use anyhow::Result;

#[derive(Clone)]
pub struct MonadProvider {
    pub rpc_url: String,
    pub contract_address: String,
    // ... other Monad-specific configuration
}

impl LogsProvider for MonadProvider {
    fn latest_block(&mut self) -> Result<u64> {
        // Implement Monad-specific logic to get latest block
    }

    fn logs(&self, start_block: u64, end_block: u64) -> Result<impl IntoIterator<Item = Log>> {
        // Implement Monad-specific logic to fetch logs/events
        // Convert Monad events to Ethereum-style Log format
    }

    fn block_timestamp(&self, block_number: u64) -> Result<u64> {
        // Implement Monad-specific logic to get block timestamp
    }
}
```

### 3. Create Handlers

Create handlers in `oyster/monad/src/handlers/`. Handlers should:

- Accept `&impl LogsProvider` as a parameter (not a concrete provider type)
- Only use `LogsProvider` trait methods (`latest_block`, `logs`, `block_timestamp`)
- Never access provider-specific fields directly

Example handler:

```rust
use indexer_framework::LogsProvider;
use diesel::PgConnection;
use alloy::rpc::types::Log;
use anyhow::Result;

pub fn handle_job_closed(
    conn: &mut PgConnection,
    log: Log,
    provider: &impl LogsProvider,  // ✅ Use trait, not concrete type
) -> Result<()> {
    let block = log.block_number.ok_or(anyhow!("missing block"))?;
    let timestamp = provider.block_timestamp(block)?;  // ✅ Only use trait methods
    // ... rest of handler logic
}
```

### 4. Create main.rs

In `oyster/monad/src/main.rs`, construct your provider and call the event loop:

```rust
use indexer_framework::{event_loop, start_from, MIGRATIONS};
use provider::MonadProvider;
use handlers::handle_log;

fn run() -> Result<()> {
    let args = Args::parse();

    // ... database setup ...

    let mut provider = MonadProvider {
        rpc_url: args.rpc_url,
        contract_address: args.contract,
        // ... other fields
    };

    event_loop(&mut conn, &mut provider, args.range_size, handle_log)
}
```

### 5. Update Cargo.toml

Add dependencies to `oyster/monad/Cargo.toml`:

```toml
[dependencies]
indexer-framework = { version = "0.1.0", path = "../framework" }
# ... other dependencies
```

## Important Guidelines

### ✅ DO

- Use `&impl LogsProvider` in handler function signatures
- Only call trait methods (`latest_block`, `logs`, `block_timestamp`) in handlers
- Keep chain-specific logic isolated in the provider implementation
- Convert chain-specific event formats to Ethereum-style `Log` format

### ❌ DON'T

- Access provider-specific fields in handlers (e.g., `provider.url`, `provider.contract`)
- Use concrete provider types in handlers (e.g., `&AlloyProvider`, `&SuiProvider`)
- Modify framework code when adding a new chain
- Modify other chain implementations when adding a new chain

## Example: EVM Provider

The EVM provider (`oyster/evm/src/provider.rs`) is a simple example:

```rust
pub struct AlloyProvider {
    pub url: Url,
    pub contract: Address,
}

impl LogsProvider for AlloyProvider {
    fn latest_block(&mut self) -> Result<u64> {
        // Uses Alloy to query EVM RPC
    }

    fn logs(&self, start_block: u64, end_block: u64) -> Result<impl IntoIterator<Item = Log>> {
        // Uses Alloy to fetch EVM logs
    }

    fn block_timestamp(&self, block_number: u64) -> Result<u64> {
        // Uses Alloy to get block timestamp
    }
}
```

## Example: Sui Provider

The Sui provider (`oyster/sui/src/provider.rs`) shows how to handle non-EVM chains:

```rust
pub struct SuiProvider {
    pub remote_checkpoint_url: String,
    pub grpc_url: String,
    pub package_id: String,
    // ... authentication fields
}

impl LogsProvider for SuiProvider {
    fn latest_block(&mut self) -> Result<u64> {
        // Fetches latest checkpoint from Sui RPC
        // Converts checkpoint sequence number to block number
    }

    fn logs(&self, start_block: u64, end_block: u64) -> Result<impl IntoIterator<Item = Log>> {
        // Fetches Sui events from RPC
        // Converts Sui events to Ethereum-style Log format
    }

    fn block_timestamp(&self, block_number: u64) -> Result<u64> {
        // Fetches checkpoint timestamp from Sui RPC
    }
}
```

## Testing

Each chain should have its own test utilities. Create a mock provider for testing:

```rust
// oyster/monad/src/handlers/test_utils/test_provider.rs
use indexer_framework::LogsProvider;

pub struct MockProvider {
    pub timestamp: u64,
}

impl LogsProvider for MockProvider {
    fn latest_block(&mut self) -> Result<u64> {
        Ok(100)
    }

    fn logs(&self, _start: u64, _end: u64) -> Result<impl IntoIterator<Item = Log>> {
        Ok(vec![])
    }

    fn block_timestamp(&self, _block: u64) -> Result<u64> {
        Ok(self.timestamp)
    }
}
```

## Benefits

This architecture provides:

1. **Isolation:** Each chain's code is completely separate
2. **Extensibility:** New chains can be added without touching existing code
3. **Testability:** Each provider can be tested independently
4. **Maintainability:** Changes to one chain don't affect others
5. **Type Safety:** Rust's trait system ensures providers implement required methods

## Summary

The provider pattern enables multi-chain support through:

- A common `LogsProvider` trait interface
- Chain-specific provider implementations
- Chain-agnostic handlers that work with any provider
- Complete isolation between chains

When adding a new chain, you only need to:

1. Create a new directory
2. Implement `LogsProvider` for your chain
3. Create handlers (or reuse existing logic)
4. Create a main.rs that wires everything together

No changes to the framework or other chains are required!
