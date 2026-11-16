use clap::{ValueEnum, builder::PossibleValue};
use sui_sdk_types::Address;

use crate::{
    configs::{
        arb::{ARBITRUM_ONE_RPC_URL, OYSTER_MARKET_ADDRESS, USDC_ADDRESS},
        bsc::{self, BSC_RPC_URL},
        sui::*,
    },
    deployment::{adapter::DeploymentAdapter, evm::EvmAdapter, sui::SuiAdapter},
};

pub mod adapter;
pub mod evm;
pub mod sui;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Deployment {
    Arbitrum,
    Bsc,
    Sui,
}

impl Deployment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Deployment::Arbitrum => "arb",
            Deployment::Bsc => "bsc",
            Deployment::Sui => "sui",
        }
    }
}

impl ValueEnum for Deployment {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Arbitrum, Self::Bsc, Self::Sui]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(self.as_str().into())
    }
}

pub fn get_deployment_adapter(
    chain_type: Deployment,
    rpc_url: Option<String>,
    auth_token: Option<String>,
    usdc_coin: Option<Address>,
    gas_coin: Option<Address>,
) -> Box<dyn DeploymentAdapter> {
    match chain_type {
        Deployment::Arbitrum => Box::new(EvmAdapter {
            rpc_url: rpc_url.unwrap_or(ARBITRUM_ONE_RPC_URL.to_owned()),
            market_address: OYSTER_MARKET_ADDRESS.to_owned(),
            usdc_address: USDC_ADDRESS.to_owned(),
            sender_address: None,
        }),
        Deployment::Bsc => Box::new(EvmAdapter {
            rpc_url: rpc_url.unwrap_or(BSC_RPC_URL.to_owned()),
            market_address: bsc::OYSTER_MARKET_ADDRESS.to_owned(),
            usdc_address: bsc::USDC_ADDRESS.to_owned(),
            sender_address: None,
        }),
        Deployment::Sui => Box::new(SuiAdapter {
            rpc_url: rpc_url.unwrap_or(SUI_GRPC_URL.to_owned()),
            auth_token,
            market_package_id: Address::from_static(OYSTER_MARKET_PACKAGE_ID),
            market_package_initial_version: OYSTER_MARKET_PACKAGE_INITIAL_VERSION,
            market_config_id: Address::from_static(OYSTER_MARKET_CONFIG_ID),
            market_place_id: Address::from_static(OYSTER_MARKET_PLACE_ID),
            lock_data_id: Address::from_static(OYSTER_MARKET_LOCK_DATA_ID),
            usdc_id: Address::from_static(USDC_PACKAGE_ID),
            clock_id: Address::from_static(SUI_CLOCK_ID),
            clock_initial_shared_version: SUI_CLOCK_INITIAL_VERSION,
            usdc_coin_id: usdc_coin,
            gas_coin_id: gas_coin,
            sender_address: None,
        }),
    }
}

// Read-only checks against the live deployments (eth_call / simulation only, nothing is signed or sent).
// Run with `cargo test -- --ignored live_`.
#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::deployment::adapter::RateLock;

    // throwaway keys, only needed to construct a provider
    const EVM_DUMMY_KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const SUI_DUMMY_KEY: &str = "AAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB";

    #[tokio::test]
    #[ignore = "reads Arbitrum One"]
    async fn live_arbitrum_rate_lock() {
        let mut adapter = get_deployment_adapter(Deployment::Arbitrum, None, None, None, None);
        let provider = adapter
            .create_provider_with_wallet(EVM_DUMMY_KEY)
            .await
            .unwrap();

        assert_eq!(
            adapter.get_rate_lock_wait_time(&provider).await.unwrap(),
            300
        );
        // job 0 was closed long ago, closing deletes the lock
        let job = format!("0x{:064x}", 0);
        assert_eq!(
            adapter.get_rate_lock(&job, &provider).await.unwrap(),
            RateLock::None
        );
    }

    #[tokio::test]
    #[ignore = "reads Sui mainnet"]
    async fn live_sui_rate_lock() {
        let mut adapter = get_deployment_adapter(Deployment::Sui, None, None, None, None);
        let provider = adapter
            .create_provider_with_wallet(SUI_DUMMY_KEY)
            .await
            .unwrap();

        // the mainnet package has no wait time registered for the rate lock selector
        let wait_time = adapter.get_rate_lock_wait_time(&provider).await.unwrap();
        println!("rate lock wait time: {wait_time}");
        for job in ["114", "115", "116", "121", "201"] {
            let exists = adapter
                .get_job_data_if_exists(job.into(), &provider)
                .await
                .unwrap()
                .is_some();
            let lock = adapter.get_rate_lock(job, &provider).await.unwrap();
            println!("job {job}: exists {exists}, lock {lock:?}");
        }
    }
}
