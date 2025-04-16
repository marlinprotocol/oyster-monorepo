use alloy::sol;
use serde::{Deserialize, Serialize};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterMarket,
    "src/abis/oyster_market_abi.json"
);

#[derive(Serialize, Deserialize)]
pub struct Operator {
    pub allowed_regions: Vec<String>,
    pub min_rates: Vec<RateCard>,
}

#[derive(Serialize, Deserialize)]
pub struct RateCard {
    pub region: String,
    pub rate_cards: Vec<InstanceRate>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InstanceRate {
    pub instance: String,
    pub min_rate: String,
    pub cpu: u32,
    pub memory: u32,
    pub arch: String,
}
