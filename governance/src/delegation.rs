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

/// Represent a delegation contract instance with provider and delegation contract address
#[derive(Debug)]
pub struct Delegation<N: Network> {
    /// Provider instance associated with delegation contract
    provider: RootProvider<N>,

    /// Address of the delegation contract
    delegation: Address,
}

impl<N: Network> Delegation<N> {
    /// Creates a new instance of delegation contract
    ///
    /// # Example
    /// ```
    /// use governance::delegation::Delegation;
    /// use alloy::network::Ethereum;
    /// let chain_rpc = "delegation chain rpc";
    /// let delegation_address = "delegation contract address";
    /// let delegation = Delegation::<Ethereum>::new(chain_rpc, delegation_address);
    /// ```
    pub fn new(delegation_chain_rpc_url: &str, delegation_address: &str) -> Result<Self> {
        let url = Url::parse(delegation_chain_rpc_url)?;
        let provider = RootProvider::<N>::new_http(url);

        let delegation = delegation_address.parse()?;
        Ok(Self {
            provider,
            delegation,
        })
    }

    /// Fetches the delegatee address for a given `delegator` at a specific `block_number`.
    ///
    /// # Examples
    ///
    /// ```
    /// use alloy::primitives::Address;
    /// use alloy::network::Ethereum;
    /// use governance::delegation::Delegation;
    ///
    /// # async fn example() -> anyhow::Result<()> {
    /// #     let chain_rpc = "https://delegation-chain-rpc.example";
    /// #     let delegation_address = "0xabcdef01abcdef01abcdef01abcdef01abcdef01";
    /// #     let delegation = Delegation::<Ethereum>::new(chain_rpc, delegation_address)?;
    /// #
    ///     let delegator: Address = "0x1111111111111111111111111111111111111111".parse().unwrap();
    ///     let block_number: u64 = 19_000_000;
    ///
    ///     let delegatee = delegation.get_delegatee(delegator, block_number).await?;
    ///     println!("Delegatee: {delegatee}");
    /// #
    /// #     Ok(())
    /// # }
    /// ```
    pub async fn get_delegatee(&self, delegator: Address, block_number: u64) -> Result<Address> {
        log::debug!("Fetching delegatee for delegator: {}", delegator);
        let i_delegation = IDelegation::new(self.delegation, &self.provider);
        let delegatee = i_delegation
            .getDelegator(delegator)
            .block(block_number.into())
            .call()
            .await?;

        log::debug!("Delegator: {} Delegatee: {}", delegator, delegatee);
        Ok(delegatee)
    }

    /// Checks whether a delegation from `delegator` to `delegatee` is set
    /// at the given `block_number`.
    ///
    /// # Examples
    ///
    /// ```
    /// use alloy::primitives::Address;
    /// use alloy::network::Ethereum;
    /// use governance::delegation::Delegation;
    ///
    /// # async fn example() -> anyhow::Result<()> {
    /// #     let chain_rpc = "https://delegation-chain-rpc.example";
    /// #     let delegation_address = "0xabcdef01abcdef01abcdef01abcdef01abcdef01";
    /// #     let delegation = Delegation::<Ethereum>::new(chain_rpc, delegation_address)?;
    /// #
    ///     let delegator: Address = "0x1111111111111111111111111111111111111111".parse().unwrap();
    ///     let delegatee: Address = "0x2222222222222222222222222222222222222222".parse().unwrap();
    ///     let block_number: u64 = 19_000_000;
    ///
    ///     let is_set = delegation
    ///         .is_delegation_set(delegator, delegatee, block_number)
    ///         .await?;
    ///     println!("Is delegation set? {is_set}");
    /// #
    /// #     Ok(())
    /// # }
    /// ```
    pub async fn is_delegation_set(
        &self,
        delegator: Address,
        delegatee: Address,
        block_number: u64,
    ) -> Result<bool> {
        log::debug!(
            "Checking delegator: {} and delegatee: {} mapping",
            delegator,
            delegatee
        );
        let i_delegation = IDelegation::new(self.delegation, &self.provider);
        let is_set = i_delegation
            .isDelegationSet(delegator, delegatee)
            .block(block_number.into())
            .call()
            .await?;
        log::debug!(
            "Delegator: {} and delegatee: {} is_set={}",
            delegator,
            delegatee,
            is_set
        );
        Ok(is_set)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{create_gov_chain_rpc_url, get_governanace_delegation, latest_block};
    use alloy::{network::Ethereum, primitives::U256};
    use anyhow::Result;

    #[tokio::test]
    async fn read_info_chain_1() -> Result<()> {
        let delegation = get_governanace_delegation::<Ethereum>(
            U256::from(421614),
            "https://arb-sepolia.g.alchemy.com/v2/".into(),
            "0xEa2C24a2C0ed96E162481f44fe910FA0c4bab180",
        )?;
        let info: bool = delegation
            .is_delegation_set(
                "0000000000000000000000000000000000000001".parse()?,
                "0000000000000000000000000000000000000001".parse()?,
                latest_block::<Ethereum>(&create_gov_chain_rpc_url()?).await?,
            )
            .await?;
        println!("{:?}", info);
        Ok(())
    }
}
