use alloy::dyn_abi::Eip712Domain;
use alloy::sol_types::eip712_domain;

// TODO: add support for automatically determining enclave storage capacity based on system config
pub const SECRET_STORAGE_CAPACITY_BYTES: usize = 100000000; // this is roughly 96 MB
pub const INJECT_SECRET_JSON_PAYLOAD_SIZE_LIMIT: usize = 2500000; // this is roughly 2.5 MB

// Deadline (in secs) for resending pending/dropped acknowledgement timeout txns
pub const ACKNOWLEDGEMENT_TIMEOUT_TXN_RESEND_DEADLINE_SECS: u64 = 20;
// Buffer time (in secs) for sending store alive transaction under the set timeout
pub const SEND_TRANSACTION_BUFFER_SECS: u64 = 5;
// Buffer time (in secs) for removing an expired secret
pub const SECRET_EXPIRATION_BUFFER_SECS: u64 = 5;
pub const RPC_ERROR_RETRY_DELAY_SECS: u64 = 1;

// Domain separator constant for SecretManager Transactions
pub const DOMAIN_SEPARATOR: Eip712Domain = eip712_domain! {
    name: "marlin.oyster.SecretManager",
    version: "1",
};
