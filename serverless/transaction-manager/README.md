![Marlin Oyster Logo](./logo.svg)

# Multi-Block Transactions

A Rust library for managing multi-block transactions on EVM-compatible blockchains.

## Features

- Transaction management with automatic retries and monitoring with nonce management.
- Support for transaction resending with optimized gas prices
- Built-in timeout and error handling
- Uses Alloy for Ethereum primitives and ABI encoding

## Installation

Add this to your `Cargo.toml`

```
multi-block-txns = { path = "<oyster-monorepo-path>/serverless/transaction-manager" }
```

## Example

An example for a basic transaction can be found in `examples/basic_transaction.rs`.
Run it using -

```
cargo run --example basic_transaction -- --private-key <insert your arbitrum SepoliaEth Test Wallet Private Key>
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
