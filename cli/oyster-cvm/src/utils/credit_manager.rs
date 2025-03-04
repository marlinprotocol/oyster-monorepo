use crate::configs::global::CREDIT_MANAGER_ADDRESS;
use crate::utils::provider::OysterProvider;
use alloy::primitives::Address;
use alloy::sol;
use anyhow::Result;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    CreditManager,
    "src/abis/credit_manager_abi.json"
);

pub async fn is_job_from_credits(job_id: &str, provider: OysterProvider) -> Result<bool> {
    let credit_manager = CreditManager::new(CREDIT_MANAGER_ADDRESS.parse::<Address>()?, provider);

    let job = credit_manager.jobs(job_id.parse()?).call().await?;

    if job.user == Address::ZERO {
        return Ok(false);
    }

    Ok(true)
}
