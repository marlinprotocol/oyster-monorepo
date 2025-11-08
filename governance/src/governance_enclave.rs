use alloy::{
    network::Network,
    primitives::{Address, U256},
    providers::RootProvider,
    sol,
};
use anyhow::Result;
use url::Url;

use crate::governance_enclave::IGovernanceEnclave::TokenNetworkConfig;

sol! {

    #[sol(rpc)]
    interface IGovernanceEnclave {

        #[derive(Debug)]
        struct TokenNetworkConfig {
            bytes32 chainHash;
            address tokenAddress;
            string[] rpcUrls;
        }

        #[derive(Debug)]
        function getTokenNetworkConfig(uint256 _chainId) public view returns (TokenNetworkConfig memory);

        function getAllSupportedChainIds() external view returns (uint256[] memory);
    }
}

#[derive(Debug)]
pub struct GovernanceEnclave<N: Network> {
    provider: RootProvider<N>,
    governance_enclave: Address,
}

impl<N: Network> GovernanceEnclave<N> {
    pub fn new(gov_chain_rpc_url: &str, governance_enclave_address: &str) -> Result<Self> {
        let url = Url::parse(gov_chain_rpc_url)?;
        let provider = RootProvider::<N>::new_http(url);

        let governance_enclave = governance_enclave_address.parse()?;
        Ok(Self {
            provider,
            governance_enclave,
        })
    }

    pub async fn get_token_network_config(&self, chain_id: U256) -> Result<TokenNetworkConfig> {
        let i_governance_enclave = IGovernanceEnclave::new(self.governance_enclave, &self.provider);
        return i_governance_enclave
            .getTokenNetworkConfig(chain_id)
            .call()
            .await
            .map_err(|err| anyhow::Error::new(err));
    }
}

#[cfg(test)]
mod tests {
    use alloy::{network::Ethereum, primitives::U256};
    use anyhow::Result;

    use crate::config::get_governance_enclave;

    #[tokio::test]
    async fn read_info_chain_1() -> Result<()> {
        let gov_enclave = get_governance_enclave::<Ethereum>()?;
        let info = gov_enclave
            .get_token_network_config(U256::from(421614))
            .await?;
        println!("{:?}", info);
        Ok(())
    }

    #[tokio::test]
    async fn read_info_chain_2() -> Result<()> {
        let gov_enclave = get_governance_enclave::<Ethereum>()?;
        let info = gov_enclave
            .get_token_network_config(U256::from(11155111))
            .await?;
        println!("{:?}", info);
        Ok(())
    }
}
