use thiserror::Error;

#[derive(Debug, Error)]
pub enum TxnManagerSendError {
    #[error("Invalid gas wallet. Error: {0}")]
    InvalidGasWallet(String),
    #[error("Invalid RPC URL. Error: {0}")]
    InvalidRpcUrl(String),
    #[error("Nonce too low. Error: {0}")]
    NonceTooLow(String),
    #[error("Nonce too high. Error: {0}")]
    NonceTooHigh(String),
    #[error("Out of gas. Error: {0}")]
    OutOfGas(String),
    #[error("Insufficient balance in wallet. Error: {0}")]
    InsufficientBalance(String),
    #[error("Gas too high. Error: {0}")]
    GasTooHigh(String),
    #[error("Gas price low. Error: {0}")]
    GasPriceLow(String),
    #[error("Contract execution failed. Error: {0}")]
    ContractExecution(String),
    #[error("Transaction already known. Error: {0}")]
    AlreadyKnown(String),
    #[error("Network connectivity issue. Error: {0}")]
    NetworkConnectivity(String),
    #[error("Other retryable error. Error: {0}")]
    OtherRetryable(String),
    #[error("Timeout. Error: {0}")]
    Timeout(String),
    #[error("Receipt not found. Error: {0}")]
    ReceiptNotFound(String),
    #[error("Gas wallet changed. Error: {0}")]
    GasWalletChanged(String),
    #[error("Invalid private signer. Error: {0}")]
    InvalidPrivateSigner(String),
}
