use clap::{ValueEnum, builder::PossibleValue};
use sui_sdk_types::Address;

use crate::{
    chain::{adapter::ChainAdapter, evm::EvmAdapter, sui::SuiAdapter},
    configs::{
        arb::{ARBITRUM_ONE_RPC_URL, OYSTER_MARKET_ADDRESS, USDC_ADDRESS},
        bsc::{self, BSC_RPC_URL},
        sui::*,
    },
};

pub mod adapter;
pub mod evm;
pub mod sui;

#[derive(Clone, Debug)]
pub enum ChainType {
    Arbitrum,
    BSC,
    Sui,
}

impl ChainType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChainType::Arbitrum => "arb",
            ChainType::BSC => "bsc",
            ChainType::Sui => "sui",
        }
    }
}

impl ValueEnum for ChainType {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Arbitrum, Self::BSC, Self::Sui]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(self.as_str().into())
    }
}

pub fn get_chain_adapter(
    chain_type: ChainType,
    rpc_url: Option<String>,
    auth_token: Option<String>,
    usdc_coin: Option<Address>,
    gas_coin: Option<Address>,
) -> Box<dyn ChainAdapter> {
    match chain_type {
        ChainType::Arbitrum => Box::new(EvmAdapter {
            rpc_url: rpc_url.unwrap_or(ARBITRUM_ONE_RPC_URL.to_owned()),
            market_address: OYSTER_MARKET_ADDRESS.to_owned(),
            usdc_address: USDC_ADDRESS.to_owned(),
            sender_address: None,
        }),
        ChainType::BSC => Box::new(EvmAdapter {
            rpc_url: rpc_url.unwrap_or(BSC_RPC_URL.to_owned()),
            market_address: bsc::OYSTER_MARKET_ADDRESS.to_owned(),
            usdc_address: bsc::USDC_ADDRESS.to_owned(),
            sender_address: None,
        }),
        ChainType::Sui => Box::new(SuiAdapter {
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
