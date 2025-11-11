use alloy::{
    network::Network,
    primitives::{Address, U256},
    providers::RootProvider,
    sol,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use url::Url;

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function balanceOf(address owner) external view override returns (uint256);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenWeight {
    delegator: Address,
    pub weight: U256,
    block: u64,
}

#[derive(Debug)]
pub struct TokenInstance<N: Network> {
    provider: RootProvider<N>,
    token_address: Address,
}

impl<N: Network> TokenInstance<N> {
    pub fn new(chain_rpc_url: &str, token_address: &str) -> Result<Self> {
        let url = Url::parse(chain_rpc_url)?;
        let provider = RootProvider::<N>::new_http(url);

        let token_address = token_address.parse()?;
        Ok(Self {
            provider,
            token_address,
        })
    }

    pub async fn get_token_weight(&self, owner: Address, block_number: u64) -> Result<TokenWeight> {
        log::debug!(
            "Fetching token balance: {} for address: {} at block_number: {}",
            self.token_address,
            owner,
            block_number
        );
        let token_instance = IERC20::new(self.token_address, &self.provider);
        let balance = token_instance
            .balanceOf(owner)
            .block(block_number.into())
            .call()
            .await?;

        log::debug!(
            "token balance: {} for address: {} at block_number: {} = {}",
            self.token_address,
            owner,
            block_number,
            balance
        );

        Ok(TokenWeight {
            delegator: owner,
            weight: balance,
            block: block_number,
        })
    }
}
