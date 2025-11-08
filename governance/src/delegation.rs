use alloy::{network::Network, primitives::Address, providers::RootProvider, sol};
use anyhow::Result;
use url::Url;

sol! {
    #[sol(rpc)]
    interface IDelegation {
        function getDelegator(address delegator) external view returns (address);
        function isDelegationSet(address delegator, address delegatee) external view returns (bool);
    }
}

#[derive(Debug)]
pub struct Delegation<N: Network> {
    provider: RootProvider<N>,
    delegation: Address,
}

impl<N: Network> Delegation<N> {
    pub fn new(delegation_chain_rpc_url: &str, delegation_address: &str) -> Result<Self> {
        let url = Url::parse(delegation_chain_rpc_url)?;
        let provider = RootProvider::<N>::new_http(url);

        let delegation = delegation_address.parse()?;
        Ok(Self {
            provider,
            delegation,
        })
    }

    pub async fn get_delegatee(&self, delegator: Address, block_number: u64) -> Result<Address> {
        let i_delegation = IDelegation::new(self.delegation, &self.provider);
        let delegator = i_delegation
            .getDelegator(delegator)
            .block(block_number.into())
            .call()
            .await?;
        Ok(delegator)
    }

    pub async fn is_delegation_set(
        &self,
        delegator: Address,
        delegatee: Address,
        block_number: u64,
    ) -> Result<bool> {
        let i_delegation = IDelegation::new(self.delegation, &self.provider);
        let is_set = i_delegation
            .isDelegationSet(delegator, delegatee)
            .block(block_number.into())
            .call()
            .await?;
        Ok(is_set)
    }
}

#[cfg(test)]
mod tests {
    use alloy::{network::Ethereum, primitives::U256};
    use anyhow::Result;

    use crate::config::{get_config, get_governanace_delegation, latest_block};

    #[tokio::test]
    async fn read_info_chain_1() -> Result<()> {
        let delegation = get_governanace_delegation::<Ethereum>(
            U256::from(421614),
            "0xEa2C24a2C0ed96E162481f44fe910FA0c4bab180",
        )?;
        let info: bool = delegation
            .is_delegation_set(
                "0000000000000000000000000000000000000001".parse()?,
                "0000000000000000000000000000000000000001".parse()?,
                latest_block::<Ethereum>(&get_config()?.gov_chain_rpc_url).await?,
            )
            .await?;
        println!("{:?}", info);
        Ok(())
    }
}
