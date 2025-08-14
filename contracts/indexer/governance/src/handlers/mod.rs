use alloy::rpc::types::Log;
use anyhow::anyhow;
use anyhow::Result;
use diesel::PgConnection;
use ethp::event;
use tracing::warn;
use tracing::{info, instrument};

use crate::LogsProvider;

mod proposal_created;
use proposal_created::handle_proposal_created;

mod result_submitted;
use result_submitted::handle_result_submitted;

// proposal logs
static PROPOSAL_CREATED: [u8; 32] = event!(
    "ProposalCreated(bytes32,address,uint256,address[],uint256[],bytes[],string,string,(uint256,uint256,uint256,uint256))"
);
static PROPOSAL_EXECUTED: [u8; 32] = event!("ProposalExecuted(bytes32)");

// deposit logs
static DEPOSIT_LOCKED: [u8; 32] = event!("DepositLocked(bytes32,address,uint256)");
static DEPOSIT_REFUNDED: [u8; 32] = event!("DepositRefunded(bytes32,address,uint256)");
static DEPOSIT_SLASHED: [u8; 32] = event!("DepositSlashed(bytes32,address,uint256)");

// vote logs
static VOTE_SUBMITTED: [u8; 32] = event!("VoteSubmitted(bytes32,uint256,address,bytes)");

// result logs
static RESULT_SUBMITTED: [u8; 32] =
    event!("ResultSubmitted(bytes32,(uint256,uint256,uint256,uint256,uint256),uint8)");

// ignored logs
static UPGRADED: [u8; 32] = event!("Upgraded(address)");
static INITIALIZED: [u8; 32] = event!("Initialized(uint8)");
static TOKEN_LOCK_AMOUNT_SET: [u8; 32] = event!("TokenLockAmountSet(address,uint256)");
static NETWORK_CONFIG_SET: [u8; 32] = event!("NetworkConfigSet(uint256,address,string[])");
static ROLE_GRANTED: [u8; 32] = event!("RoleGranted(bytes32,address,address)");
static TREASURY_SET: [u8; 32] = event!("TreasurySet(address)");
static PROPOSAL_PASS_VETO_THRESHOLD_SET: [u8; 32] = event!("ProposalPassVetoThresholdSet(uint256)");
static MIN_QUORUM_THRESHOLD_SET: [u8; 32] = event!("MinQuorumThresholdSet(uint256)");
static VOTE_ACTIVATION_DELAY_SET: [u8; 32] = event!("VoteActivationDelaySet(uint256)");
static VOTE_DURATION_SET: [u8; 32] = event!("VoteDurationSet(uint256)");
static PROPOSAL_DURATION_SET: [u8; 32] = event!("ProposalDurationSet(uint256)");
static MAX_RPC_URLS_PER_CHAIN_SET: [u8; 32] = event!("MaxRpcUrlsPerChainSet(uint256)");
static PCR_CONFIG_SET: [u8; 32] = event!("PCRConfigSet(bytes32,bytes,bytes,bytes)");
static KMS_ROOT_SERVER_PUB_KEY_SET: [u8; 32] = event!("KMSRootServerPubKeySet(bytes32)");
static KMS_PATH_SET: [u8; 32] = event!("KMSPathSet(string)");

#[instrument(
    level = "info",
    skip_all,
    parent = None,
    fields(block = log.block_number, idx = log.log_index, tx = ?log.transaction_hash)
)]
pub fn handle_log(conn: &mut PgConnection, log: Log, provider: &impl LogsProvider) -> Result<()> {
    info!(?log, "processing");

    let log_type = log
        .topic0()
        .ok_or(anyhow!("log does not have topic0, should never happen"))?;

    if log_type == PROPOSAL_CREATED {
        handle_proposal_created(conn, log)
    } else if log_type == RESULT_SUBMITTED {
        handle_result_submitted(conn, log)
    } else if log_type == UPGRADED
        || log_type == INITIALIZED
        || log_type == TOKEN_LOCK_AMOUNT_SET
        || log_type == NETWORK_CONFIG_SET
        || log_type == ROLE_GRANTED
        || log_type == TREASURY_SET
        || log_type == PROPOSAL_PASS_VETO_THRESHOLD_SET
        || log_type == MIN_QUORUM_THRESHOLD_SET
        || log_type == VOTE_ACTIVATION_DELAY_SET
        || log_type == VOTE_DURATION_SET
        || log_type == PROPOSAL_DURATION_SET
        || log_type == MAX_RPC_URLS_PER_CHAIN_SET
        || log_type == PCR_CONFIG_SET
        || log_type == KMS_ROOT_SERVER_PUB_KEY_SET
        || log_type == KMS_PATH_SET
    {
        info!(?log_type, "ignoring log type");
        Ok(())
    } else {
        warn!(?log_type, "unknown log type");
        Ok(())
    }
}

#[cfg(test)]
mod test_db;
