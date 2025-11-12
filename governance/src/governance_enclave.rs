use alloy::{
    network::Network,
    primitives::{Address, B256, U256},
    providers::RootProvider,
    signers::k256::sha2::{Digest, Sha256},
    sol,
    sol_types::SolValue,
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

        function getImageId() external view returns (bytes32);

        function getNetworkHash() external view returns (bytes32);
    }
}

#[derive(Debug, Clone)]
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

    pub async fn get_token_network_config(
        &self,
        chain_id: U256,
        block_number: u64,
    ) -> Result<TokenNetworkConfig> {
        log::debug!("Fetching token network config for chain id: {}", chain_id);
        let i_governance_enclave = IGovernanceEnclave::new(self.governance_enclave, &self.provider);
        let token_network_config = i_governance_enclave
            .getTokenNetworkConfig(chain_id)
            .call()
            .block(block_number.into())
            .await
            .map_err(|err| anyhow::Error::new(err))?;

        log::debug!(
            "token network config for chain id: {} = {:?}",
            chain_id,
            token_network_config
        );

        Ok(token_network_config)
    }

    pub async fn get_image_id(&self, block_number: u64) -> Result<B256> {
        log::debug!("Fetching image id");

        let i_governance_enclave = IGovernanceEnclave::new(self.governance_enclave, &self.provider);
        let image_id = i_governance_enclave
            .getImageId()
            .call()
            .block(block_number.into())
            .await
            .map_err(|err| anyhow::Error::new(err))?;

        log::debug!("Image ID: {}", hex::encode(image_id));
        Ok(image_id)
    }

    #[deprecated(note = "don't use this, instead compute")]
    pub async fn get_network_hash(&self, block_number: u64) -> Result<B256> {
        let i_governance_enclave = IGovernanceEnclave::new(self.governance_enclave, &self.provider);

        let network_hash = i_governance_enclave
            .getNetworkHash()
            .call()
            .block(block_number.into())
            .await
            .map_err(|err| anyhow::Error::new(err))?;

        Ok(network_hash)
    }

    pub async fn compute_network_hash(&self, block_number: u64) -> Result<B256> {
        let mut init_network_hash = B256::ZERO;

        let i_governance = IGovernanceEnclave::new(self.governance_enclave, &self.provider);
        let network_chain_ids = i_governance.getAllSupportedChainIds().call().await?;

        for chain_id in network_chain_ids {
            let token_network_config = self
                .get_token_network_config(chain_id, block_number)
                .await?;
            let chain_hash = token_network_config.chainHash;
            sol! {struct Input {bytes32 a; bytes32 b; }}
            let input = Input {
                a: init_network_hash,
                b: chain_hash,
            };
            let h = Sha256::digest(input.abi_encode());
            init_network_hash = B256::from_slice(&h);
        }

        Ok(init_network_hash)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{find_block_by_timestamp, get_governance_enclave};
    use alloy::{network::Ethereum, primitives::U256};
    use anyhow::Result;

    #[tokio::test]
    async fn read_info_chain_1() -> Result<()> {
        let block_number = find_block_by_timestamp::<Ethereum>(
            "https://sepolia-rollup.arbitrum.io/rpc",
            1762933455,
        )
        .await?;
        let gov_enclave = get_governance_enclave::<Ethereum>()?;
        let info = gov_enclave
            .get_token_network_config(U256::from(421614), block_number)
            .await?;
        println!("{:?}", info);
        Ok(())
    }

    #[tokio::test]
    async fn read_info_chain_2() -> Result<()> {
        let block_number = find_block_by_timestamp::<Ethereum>(
            "https://sepolia-rollup.arbitrum.io/rpc",
            1762933455,
        )
        .await?;

        let gov_enclave = get_governance_enclave::<Ethereum>()?;
        let info = gov_enclave
            .get_token_network_config(U256::from(11155111), block_number)
            .await?;
        println!("{:?}", info);
        Ok(())
    }
}
