// Oyster Serverless contract addresses and endpoints. The defaults point to the
// Arbitrum One deployment, each one can be overridden with an environment variable
// to use another deployment.

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

pub fn code_contract_address() -> String {
    env_or(
        "OYSTER_SERVERLESS_CODE_CONTRACT",
        "0x061868A3387c5F6a875c111a2FDDEB70C66344F4",
    )
}

pub fn relay_contract_address() -> String {
    env_or(
        "OYSTER_SERVERLESS_RELAY",
        "0xD28179711eeCe385bc2096c5D199E15e6415A4f5",
    )
}

pub fn relay_subscriptions_contract_address() -> String {
    env_or(
        "OYSTER_SERVERLESS_RELAY_SUBSCRIPTIONS",
        "0x8Fb2C621d6E636063F0E49828f4Da7748135F3cB",
    )
}

pub fn usdc_address() -> String {
    env_or(
        "OYSTER_SERVERLESS_USDC",
        "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
    )
}

pub fn rpc_url() -> String {
    env_or("OYSTER_SERVERLESS_RPC_URL", "https://arb1.arbitrum.io/rpc")
}

pub fn indexer_url() -> String {
    env_or(
        "OYSTER_SERVERLESS_INDEXER_URL",
        "https://serverless-indexer.marlin.org/graphql",
    )
}
