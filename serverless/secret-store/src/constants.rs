use alloy::dyn_abi::DynSolValue;
use alloy::primitives::{keccak256, FixedBytes};
use once_cell::sync::Lazy;

// TODO: add support for automatically determining enclave storage capacity based on system config
pub const SECRET_STORAGE_CAPACITY_BYTES: usize = 100000000; // this is roughly 96 MB
pub const INJECT_SECRET_JSON_PAYLOAD_BUFFER: usize = 2000000; // this is roughly 2 MB

// Deadline (in secs) for resending pending/dropped acknowledgement timeout txns
pub const ACKNOWLEDGEMENT_TIMEOUT_TXN_RESEND_DEADLINE_SECS: u64 = 20;
// Buffer time (in secs) for sending store alive transaction under the set timeout
pub const SEND_TRANSACTION_BUFFER_SECS: u64 = 5;
// Buffer time (in secs) for removing an expired secret
pub const SECRET_EXPIRATION_BUFFER_SECS: u64 = 5;

// Event signatures of 'SecretStore' and 'SecretManager' contracts
pub const SECRET_STORE_REGISTERED_EVENT: &str =
    "TeeNodeRegistered(address,address,uint256,uint256,uint8)";
pub const SECRET_STORE_DRAINED_EVENT: &str = "TeeNodeDrained(address)";
pub const SECRET_STORE_REVIVED_EVENT: &str = "TeeNodeRevived(address)";
pub const SECRET_STORE_DEREGISTERED_EVENT: &str = "TeeNodeDeregistered(address)";

pub const SECRET_CREATED_EVENT: &str =
    "SecretCreated(uint256,address,uint256,uint256,uint256,address[])";
pub const SECRET_STORE_ACKNOWLEDGEMENT_SUCCESS_EVENT: &str =
    "SecretStoreAcknowledgementSuccess(uint256,address)";
pub const SECRET_STORE_ACKNOWLEDGEMENT_FAILED_EVENT: &str =
    "SecretStoreAcknowledgementFailed(uint256)";
pub const SECRET_TERMINATED_EVENT: &str = "SecretTerminated(uint256,uint256)";
pub const SECRET_REMOVED_EVENT: &str = "SecretRemoved(uint256)";
pub const SECRET_STORE_REPLACED_EVENT: &str = "SecretStoreReplaced(uint256,address,address,bool)";
pub const SECRET_END_TIMESTAMP_UPDATED_EVENT: &str = "SecretEndTimestampUpdated(uint256,uint256)";

// Domain separator constant for SecretManager Transactions
pub const DOMAIN_SEPARATOR: Lazy<FixedBytes<32>> = Lazy::new(|| {
    keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(keccak256("EIP712Domain(string name,string version)"), 32),
            DynSolValue::FixedBytes(keccak256("marlin.oyster.SecretManager"), 32),
            DynSolValue::FixedBytes(keccak256("1"), 32),
        ])
        .abi_encode(),
    )
});
