use alloy::network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::fillers::{FillProvider, JoinFill, WalletFiller};
use alloy::providers::{Identity, Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::transports::http::reqwest::{Client, Url};
use alloy::transports::http::Http;
use std::cmp::min;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::constants::{
    GARBAGE_COLLECT_INTERVAL_SEC, GARBAGE_REMOVAL_DURATION_SEC, GAS_INCREMENT_AMOUNT,
    HTTP_SLEEP_TIME_MS, RESEND_GAS_PRICE_INCREMENT_PERCENT, RESEND_INTERVAL_SEC,
};
use crate::errors::TxnManagerSendError;
use crate::models::{Transaction, TxnStatus};
use crate::utils::{parse_send_error, verify_private_signer, verify_rpc_url};

type HttpProvider = FillProvider<
    JoinFill<Identity, WalletFiller<EthereumWallet>>,
    RootProvider<Http<Client>>,
    Http<Client>,
    Ethereum,
>;

/// A transaction manager that handles the submission and monitoring of Ethereum transactions.
///
/// The `TxnManager` provides functionality to:
/// - Submit transactions to the Ethereum network
/// - Monitor transaction status
/// - Automatically retry failed transactions with adjusted gas prices
/// - Handle nonce management
/// - Perform garbage collection of old transactions
///
/// # Example
/// ```
/// use std::sync::{Arc, RwLock};
/// use std::time::{Duration, Instant};
/// use alloy::signers::local::PrivateKeySigner;
/// use crate::TxnManager;
///
/// let private_key_signer = String::from(
///         "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
///     );
/// let txn_manager = TxnManager::new(
///     "https://ethereum.rpc.url".to_string(),
///     421614, // chain_id
///     private_key_signer,
///     None, // default gas price increment
///     None, // default gas limit increment
///     None, // default garbage collection interval
///     None, // default garbage removal duration
/// ).await.unwrap();
///
/// txn_manager.run().await;
///
/// let txn_id = txn_manager.call_contract_function(
///     contract_address,
///     transaction_data,
///     Instant::now() + Duration::from_secs(60),
/// ).await.unwrap();
/// ```
#[derive(Debug)]
pub struct TxnManager {
    pub rpc_url: String,
    pub chain_id: u64,
    pub(crate) manager_running: Arc<Mutex<bool>>,
    pub(crate) private_signer: Arc<RwLock<PrivateKeySigner>>,
    pub(crate) nonce_to_send: Arc<RwLock<u64>>,
    pub(crate) nonce_to_send_private_signer: Arc<RwLock<PrivateKeySigner>>,
    pub(crate) transactions: Arc<RwLock<HashMap<String, Transaction>>>,
    pub(crate) gas_price_increment_percent: u128,
    pub(crate) gas_limit_increment_amount: u64,
    pub(crate) transaction_ids_queue: Arc<RwLock<VecDeque<String>>>,
    pub(crate) garbage_collect_interval_sec: u64,
    pub(crate) garbage_removal_duration_sec: u64,
}

impl TxnManager {
    /// Creates a new transaction manager instance.
    ///
    /// # Arguments
    /// * `rpc_url` - The Ethereum HTTP RPC endpoint URL
    /// * `chain_id` - The chain ID of the target network
    /// * `private_signer` - The private key signer for transaction signing
    /// * `gas_price_increment_percent` - Optional percentage to increase gas price on retries
    /// * `gas_limit_increment_amount` - Optional amount to increase gas limit on retries
    /// * `garbage_collect_interval_sec` - Optional interval for garbage collection in seconds
    /// * `garbage_removal_duration_sec` - Optional duration for garbage removal in seconds
    ///
    /// # Returns
    /// * `Result<Arc<Self>, TxnManagerSendError>` - The transaction manager instance or an
    ///                                              error
    ///
    /// # Errors
    /// * `TxnManagerSendError::InvalidRpcUrl` - If the RPC URL is invalid.
    /// * `TxnManagerSendError::InvalidPrivateSigner` - If the private signer is invalid.
    pub fn new(
        rpc_url: String,
        chain_id: u64,
        private_signer_hex: String,
        gas_price_increment_percent: Option<u128>,
        gas_limit_increment_amount: Option<u64>,
        garbage_collect_interval_sec: Option<u64>,
        garbage_removal_duration_sec: Option<u64>,
    ) -> Result<Arc<Self>, TxnManagerSendError> {
        match verify_rpc_url(&rpc_url) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }

        let parsed_private_signer = match verify_private_signer(private_signer_hex.clone()) {
            Ok(private_signer) => private_signer,
            Err(e) => return Err(e),
        };

        let private_signer = Arc::new(RwLock::new(parsed_private_signer.clone()));

        let nonce_to_send_private_signer = Arc::new(RwLock::new(parsed_private_signer));

        Ok(Arc::new(Self {
            rpc_url,
            chain_id,
            manager_running: Arc::new(Mutex::new(false)),
            private_signer,
            nonce_to_send: Arc::new(RwLock::new(0)),
            nonce_to_send_private_signer,
            transactions: Arc::new(RwLock::new(HashMap::new())),
            gas_price_increment_percent: gas_price_increment_percent
                .unwrap_or(RESEND_GAS_PRICE_INCREMENT_PERCENT),
            gas_limit_increment_amount: gas_limit_increment_amount.unwrap_or(GAS_INCREMENT_AMOUNT),
            transaction_ids_queue: Arc::new(RwLock::new(VecDeque::new())),
            garbage_collect_interval_sec: garbage_collect_interval_sec
                .unwrap_or(GARBAGE_COLLECT_INTERVAL_SEC),
            garbage_removal_duration_sec: garbage_removal_duration_sec
                .unwrap_or(GARBAGE_REMOVAL_DURATION_SEC),
        }))
    }

    /// Runs the transaction manager.
    ///
    /// This method starts two separate tasks:
    /// - One for processing transactions from the queue
    /// - One for garbage collecting old transactions
    pub async fn run(self: &Arc<Self>) {
        let mut manager_running_guard = self.manager_running.lock().unwrap();

        if *manager_running_guard {
            return;
        }

        let txn_manager_clone = self.clone();
        tokio::spawn(async move {
            let _ = txn_manager_clone._process_transaction().await;
        });

        let txn_manager_clone = self.clone();
        tokio::spawn(async move {
            txn_manager_clone._garbage_collect_transactions().await;
        });
        *manager_running_guard = true;
    }

    /// Calls a contract function by creating a Transaction object and calling it.
    ///
    /// Nonce is fixed for a specific transaction unless the private signer is changed within the
    /// timeout.
    ///
    /// # Arguments
    /// * `contract_address` - The address of the contract to call
    /// * `transaction_data` - The encoded function call data
    /// * `timeout` - The deadline for the transaction to be processed
    ///
    /// # Returns
    /// * `Result<String, TxnManagerSendError>` - Transaction ID if successful, error otherwise
    pub async fn call_contract_function(
        self: &Arc<Self>,
        contract_address: Address,
        transaction_data: Bytes,
        timeout: Instant,
    ) -> Result<String, TxnManagerSendError> {
        let mut transaction = Transaction {
            id: uuid::Uuid::new_v4().to_string(),
            contract_address,
            transaction_data: transaction_data.clone(),
            timeout,
            private_signer: self.private_signer.read().unwrap().clone(),
            nonce: None,
            txn_hash: None,
            status: TxnStatus::Sending,
            gas_price: 0,
            estimated_gas: 0,
            last_monitored: Instant::now(),
        };

        self._send_transaction(&mut transaction, false).await
    }

    /// Updates the private signer for the transaction manager.
    ///
    /// # Arguments
    /// * `private_signer` - The new private signer to use
    ///
    /// # Returns
    /// * `Result<(), TxnManagerSendError>` - Ok if successful, error otherwise
    ///
    /// # Errors
    /// * `TxnManagerSendError::InvalidPrivateSigner` - If the private signer is invalid
    pub fn update_private_signer(
        self: &Arc<Self>,
        private_signer: String,
    ) -> Result<(), TxnManagerSendError> {
        let private_signer = match verify_private_signer(private_signer.clone()) {
            Ok(private_signer) => private_signer,
            Err(e) => return Err(e),
        };

        let mut nonce_to_send_guard = self.nonce_to_send.write().unwrap();
        let mut private_signer_guard = self.private_signer.write().unwrap();
        let mut nonce_to_send_private_signer_guard =
            self.nonce_to_send_private_signer.write().unwrap();

        *nonce_to_send_guard = 0;
        *private_signer_guard = private_signer.clone();
        *nonce_to_send_private_signer_guard = private_signer;
        Ok(())
    }

    /// Retrieves the current private signer for the transaction manager.
    ///
    /// # Returns
    /// * `PrivateKeySigner` - The current private signer
    pub fn get_private_signer(self: &Arc<Self>) -> PrivateKeySigner {
        self.private_signer.read().unwrap().clone()
    }

    /// Sends a transaction to the network.
    ///
    /// This method handles the entire lifecycle of a transaction, including:
    /// - Nonce management
    /// - Gas estimation
    /// - Transaction submission
    /// - Automatic retries with increased gas price/limit if needed
    ///
    /// # Arguments
    /// * `transaction` - The transaction to send
    /// * `is_internal_call` - Whether the transaction is an internal call
    ///
    /// # Returns
    /// * `Result<String, TxnManagerSendError>` - Transaction ID if successful, error otherwise
    ///
    /// # Errors
    /// * `TxnManagerSendError::GasWalletChanged` - If the gas wallet is changed
    /// * `TxnManagerSendError::Timeout` - If the transaction is not confirmed within the timeout
    ///                                    along with the failure reason
    /// * `TxnManagerSendError::GasTooHigh` - If the gas limit is too high
    /// * `TxnManagerSendError::ContractExecution` - If the contract execution fails
    async fn _send_transaction(
        self: &Arc<Self>,
        mut transaction: &mut Transaction,
        is_internal_call: bool,
    ) -> Result<String, TxnManagerSendError> {
        let mut update_nonce = false;
        let mut failure_reason = String::new();

        if is_internal_call {
            transaction.status = TxnStatus::Sending;
            transaction.last_monitored = Instant::now();

            self.transactions
                .write()
                .unwrap()
                .insert(transaction.id.clone(), transaction.clone());
        }

        while Instant::now() < transaction.timeout {
            let provider = match self._create_provider(&transaction, false) {
                Ok(provider) => provider,
                Err(TxnManagerSendError::GasWalletChanged(_)) => {
                    transaction.private_signer = self.private_signer.read().unwrap().clone();
                    transaction.last_monitored = Instant::now();
                    update_nonce = true;
                    continue;
                }
                Err(err) => {
                    failure_reason = err.to_string();
                    continue;
                }
            };

            let res = self
                ._manage_nonce(&provider, &mut transaction, update_nonce)
                .await;
            if res.is_err() {
                let err = res.err().unwrap();
                match err {
                    TxnManagerSendError::Timeout(err) => {
                        if !err.is_empty() {
                            failure_reason = err;
                        }
                    }
                    _ => {
                        failure_reason = err.to_string();
                    }
                }
                sleep(Duration::from_millis(HTTP_SLEEP_TIME_MS)).await;
                continue;
            }

            update_nonce = false;

            let transaction_request = TransactionRequest::default()
                .with_to(transaction.contract_address)
                .with_from(transaction.private_signer.address())
                .with_input(transaction.transaction_data.clone())
                .with_nonce(transaction.nonce.unwrap());

            if transaction.gas_price == 0 || transaction.estimated_gas == 0 {
                let res = self
                    ._estimate_gas_limit_and_price(
                        &provider,
                        &mut transaction,
                        transaction_request.clone(),
                        false,
                    )
                    .await;
                if res.is_err() {
                    let err = res.err().unwrap();
                    match err {
                        TxnManagerSendError::GasTooHigh(_)
                        | TxnManagerSendError::ContractExecution(_) => {
                            self._send_dummy_transaction(transaction.to_owned()).await;
                            return Err(err);
                        }
                        TxnManagerSendError::Timeout(err) => {
                            if !err.is_empty() {
                                failure_reason = err;
                            }
                        }
                        _ => {
                            failure_reason = err.to_string();
                        }
                    }
                    continue;
                }
            }

            let transaction_request = transaction_request
                .with_gas_limit(transaction.estimated_gas + self.gas_limit_increment_amount)
                .with_gas_price(transaction.gas_price);

            let pending_txn = provider.send_transaction(transaction_request).await;
            let pending_txn = match pending_txn {
                Ok(pending_txn) => pending_txn,
                Err(err) => {
                    failure_reason = err.to_string();
                    let txn_manager_err = parse_send_error(failure_reason.clone());
                    match txn_manager_err {
                        TxnManagerSendError::NonceTooLow(_) => {
                            update_nonce = true;
                            sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                        TxnManagerSendError::NonceTooHigh(_) => {
                            update_nonce = true;
                            sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                        TxnManagerSendError::OutOfGas(_) => {
                            transaction.estimated_gas += self.gas_limit_increment_amount;
                            continue;
                        }
                        TxnManagerSendError::GasPriceLow(_) => {
                            transaction.gas_price = transaction.gas_price
                                * (100 + self.gas_price_increment_percent)
                                / 100;
                            continue;
                        }
                        // Break in case the contract execution is failing for this txn
                        // Or the gas required is way high compared to block gas limit
                        TxnManagerSendError::GasTooHigh(_)
                        | TxnManagerSendError::ContractExecution(_) => {
                            self._send_dummy_transaction(transaction.to_owned()).await;
                            return Err(txn_manager_err);
                        }
                        _ => {
                            sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                    }
                }
            };
            let txn_hash = *pending_txn.tx_hash();

            transaction.txn_hash = Some(txn_hash.to_string());
            transaction.status = TxnStatus::Pending;
            transaction.last_monitored = Instant::now();

            self.transactions
                .write()
                .unwrap()
                .insert(transaction.id.clone(), transaction.clone());

            self.transaction_ids_queue
                .write()
                .unwrap()
                .push_back(transaction.id.clone());

            return Ok(transaction.id.clone());
        }

        self._send_dummy_transaction(transaction.to_owned()).await;
        Err(TxnManagerSendError::Timeout(failure_reason))
    }

    /// Retrieves the current status of a transaction.
    ///
    /// # Arguments
    /// * `txn_id` - The transaction id to query
    ///
    /// # Returns
    /// * `Option<TxnStatus>` - The current status of the transaction, if found, else None
    pub fn get_transaction_status(self: &Arc<Self>, txn_id: String) -> Option<TxnStatus> {
        let transactions = self.transactions.read().unwrap().clone();
        transactions.get(&txn_id).map(|txn| txn.status.clone())
    }

    /// Processes pending transactions and monitors their status.
    ///
    /// A transaction is monitored every RESEND_INTERVAL_SEC since last monitored time.
    /// If the transaction is not confirmed within the timeout, it is resended.
    /// If timeout occurs, the transaction is marked as failed and
    /// a dummy transaction is sent to fill the nonce gap.
    ///
    /// This is an internal method that runs in a separate task to:
    /// - Monitor pending transactions
    /// - Retry failed transactions
    /// - Update transaction status
    async fn _process_transaction(self: &Arc<Self>) {
        loop {
            let Some(transaction_id) = self.transaction_ids_queue.write().unwrap().pop_front()
            else {
                sleep(Duration::from_millis(HTTP_SLEEP_TIME_MS)).await;
                continue;
            };

            let mut transaction = {
                let transactions = self.transactions.read().unwrap();
                transactions.get(&transaction_id).unwrap().clone()
            };

            // Calculate the time to wait before resending the transaction
            // It should be monitored every RESEND_INTERVAL_SEC
            let resend_txn_interval_sec = RESEND_INTERVAL_SEC
                - min(
                    RESEND_INTERVAL_SEC,
                    transaction.last_monitored.elapsed().as_secs(),
                );

            // Sleep for the time to wait before resending the transaction
            // Should not wait longer than the timeout
            sleep(Duration::from_secs(min(
                resend_txn_interval_sec,
                transaction.timeout.duration_since(Instant::now()).as_secs(),
            )))
            .await;

            let provider = self._create_provider(&transaction, true).unwrap();

            let txn_hash = transaction.txn_hash.clone().unwrap();

            if Retry::spawn(
                ExponentialBackoff::from_millis(2)
                    .factor(100)
                    .max_delay(Duration::from_secs(2))
                    .map(jitter)
                    .take(10),
                || async {
                    self._get_transaction_receipt(provider.clone(), txn_hash.clone())
                        .await
                },
            )
            .await
            .is_ok()
            {
                transaction.status = TxnStatus::Confirmed;
                transaction.last_monitored = Instant::now();

                let mut transactions_guard = self.transactions.write().unwrap();
                transactions_guard.insert(transaction.id.clone(), transaction);
                continue;
            }

            let resend_res = self._resend_transaction(&mut transaction).await;
            match resend_res {
                Ok(()) => continue,
                Err(
                    TxnManagerSendError::NonceTooLow(_) | TxnManagerSendError::GasWalletChanged(_),
                ) => continue,
                Err(_) => {}
            };

            self._send_dummy_transaction(transaction).await;
        }
    }

    /// Retrieves a transaction receipt from the network.
    /// Returns the receipt if it is found.
    /// If not found, it return the error.
    ///
    /// # Arguments
    /// * `provider` - The HTTP provider instance
    /// * `txn_hash` - The transaction hash to query
    ///
    /// # Returns
    /// * `Result<TransactionReceipt, TxnManagerSendError>` - The transaction receipt or an error
    ///
    /// # Errors
    /// * `TxnManagerSendError::NetworkConnectivity` - If the provider call fails
    /// * `TxnManagerSendError::ReceiptNotFound` - If the transaction receipt is not found
    async fn _get_transaction_receipt(
        self: &Arc<Self>,
        provider: HttpProvider,
        txn_hash: String,
    ) -> Result<TransactionReceipt, TxnManagerSendError> {
        let receipt = provider
            .get_transaction_receipt(txn_hash.parse().unwrap())
            .await;
        if receipt.is_err() {
            return Err(TxnManagerSendError::NetworkConnectivity(
                "Failed to get transaction receipt. Error: ".to_string()
                    + &receipt.err().unwrap().to_string(),
            ));
        }

        let receipt = receipt.unwrap();
        if receipt.is_none() {
            return Err(TxnManagerSendError::ReceiptNotFound(
                "Transaction receipt not found.".to_string(),
            ));
        }

        Ok(receipt.unwrap())
    }

    /// Attempts to resend a transaction with increased gas parameters.
    ///
    /// # Arguments:
    /// * `transaction` - The transaction to resend
    ///
    /// This method is called when a transaction is stuck or failed due to gas
    /// or rpc/network related issues.
    ///
    /// # Returns
    /// * `Result<(), TxnManagerSendError>` - An empty result
    ///
    /// # Errors
    /// * `TxnManagerSendError::Timeout` - If the transaction is not confirmed within the timeout
    ///                                    along with the failure reason
    /// * `TxnManagerSendError::GasWalletChanged` - If the gas wallet is changed
    /// * `TxnManagerSendError::ReceiptNotFound` - If the transaction receipt is not found
    /// * `TxnManagerSendError::GasTooHigh` - If the gas limit is too high
    /// * `TxnManagerSendError::ContractExecution` - If the contract execution fails
    async fn _resend_transaction(
        self: &Arc<Self>,
        transaction: &mut Transaction,
    ) -> Result<(), TxnManagerSendError> {
        transaction.status = TxnStatus::Sending;

        transaction.estimated_gas += self.gas_limit_increment_amount;
        transaction.gas_price =
            transaction.gas_price * (100 + self.gas_price_increment_percent) / 100;

        let transaction_request = TransactionRequest::default()
            .with_to(transaction.contract_address)
            .with_input(transaction.transaction_data.clone())
            .with_nonce(transaction.nonce.unwrap())
            .with_gas_limit(transaction.estimated_gas)
            .with_gas_price(transaction.gas_price);

        let mut failure_reason = String::new();

        while Instant::now() < transaction.timeout {
            let provider = self._create_provider(&transaction, false);
            let provider = match provider {
                Ok(provider) => provider,
                Err(TxnManagerSendError::GasWalletChanged(err_msg)) => {
                    let self_clone = self.clone();
                    let mut transaction_clone = transaction.clone();
                    tokio::spawn(async move {
                        let _ = self_clone
                            ._send_transaction(&mut transaction_clone, true)
                            .await;
                    });
                    return Err(TxnManagerSendError::GasWalletChanged(err_msg));
                }
                Err(err) => {
                    failure_reason = err.to_string();
                    continue;
                }
            };

            let pending_txn = provider.send_transaction(transaction_request.clone()).await;
            let pending_txn = match pending_txn {
                Ok(pending_txn) => pending_txn,
                Err(err) => {
                    failure_reason = err.to_string();
                    let err = parse_send_error(failure_reason.clone());
                    match err {
                        TxnManagerSendError::NonceTooLow(_) => {
                            let txn_receipt = self
                                ._get_transaction_receipt(
                                    provider,
                                    transaction.txn_hash.clone().unwrap(),
                                )
                                .await;

                            match txn_receipt {
                                Ok(_) => {
                                    return Ok(());
                                }
                                Err(TxnManagerSendError::ReceiptNotFound(_)) => {
                                    let self_clone = self.clone();
                                    let mut transaction_clone = transaction.clone();
                                    tokio::spawn(async move {
                                        let _ = self_clone
                                            ._send_transaction(&mut transaction_clone, true)
                                            .await;
                                    });
                                    return Err(err);
                                }
                                Err(_) => {
                                    continue;
                                }
                            }
                        }
                        TxnManagerSendError::OutOfGas(_) => {
                            transaction.estimated_gas += self.gas_limit_increment_amount;
                            continue;
                        }
                        TxnManagerSendError::GasPriceLow(_) => {
                            transaction.gas_price = transaction.gas_price
                                * (100 + self.gas_price_increment_percent)
                                / 100;
                            continue;
                        }
                        // Break in case the contract execution is failing for this txn
                        // Or the gas required is way high compared to block gas limit
                        TxnManagerSendError::GasTooHigh(_)
                        | TxnManagerSendError::ContractExecution(_) => {
                            return Err(err);
                        }
                        err => {
                            failure_reason = err.to_string();
                            sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                    }
                }
            };

            let txn_hash = pending_txn.tx_hash().to_string();

            transaction.status = TxnStatus::Pending;
            transaction.last_monitored = Instant::now();

            let mut transactions_guard = self.transactions.write().unwrap();

            transaction.txn_hash = Some(txn_hash.clone());
            transactions_guard.insert(transaction.id.clone(), transaction.clone());

            let mut transactions_queue_guard = self.transaction_ids_queue.write().unwrap();
            transactions_queue_guard.push_front(transaction.id.clone());

            return Ok(());
        }

        Err(TxnManagerSendError::Timeout(failure_reason))
    }

    /// Sends a dummy transaction to handle nonce gaps.
    ///
    /// # Arguments:
    /// * `transaction` - The transaction to send
    ///
    /// This method is used to fill nonce gaps when a transaction permanently fails.
    async fn _send_dummy_transaction(self: &Arc<Self>, mut transaction: Transaction) {
        loop {
            let dummy_txn = TransactionRequest::default()
                .with_to(transaction.private_signer.address())
                .with_value(U256::ZERO)
                .with_nonce(transaction.nonce.unwrap());

            let provider = self._create_provider(&transaction, false);
            let provider = match provider {
                Ok(provider) => provider,
                Err(TxnManagerSendError::GasWalletChanged(_)) => {
                    break;
                }
                Err(_) => {
                    continue;
                }
            };

            let res = self
                ._estimate_gas_limit_and_price(&provider, &mut transaction, dummy_txn.clone(), true)
                .await;
            if res.is_err() {
                sleep(Duration::from_millis(HTTP_SLEEP_TIME_MS)).await;
                continue;
            }

            let dummy_txn = dummy_txn
                .with_gas_limit(transaction.estimated_gas)
                .with_gas_price(transaction.gas_price);

            let pending_txn = provider.send_transaction(dummy_txn).await;
            let Ok(pending_txn) = pending_txn else {
                let err = parse_send_error(pending_txn.err().unwrap().to_string());
                match err {
                    TxnManagerSendError::NonceTooLow(_) => {
                        break;
                    }
                    TxnManagerSendError::OutOfGas(_) => {
                        transaction.estimated_gas += self.gas_limit_increment_amount;
                        continue;
                    }
                    TxnManagerSendError::GasPriceLow(_) => {
                        transaction.gas_price =
                            transaction.gas_price * (100 + self.gas_price_increment_percent) / 100;
                        continue;
                    }
                    _ => {
                        sleep(Duration::from_millis(HTTP_SLEEP_TIME_MS)).await;
                        continue;
                    }
                }
            };

            let tx_hash = pending_txn.watch().await;

            if tx_hash.is_err() {
                continue;
            }

            let tx_hash = tx_hash.unwrap();
            transaction.txn_hash = Some(tx_hash.to_string());
            transaction.status = TxnStatus::Failed;
            transaction.last_monitored = Instant::now();

            let mut transactions_guard = self.transactions.write().unwrap();
            transactions_guard.insert(transaction.id.clone(), transaction.clone());

            break;
        }
    }

    /// Creates a new HTTP provider instance for interacting with the network.
    ///
    /// # Arguments:
    /// * `transaction` - The transaction to create a provider for
    /// * `ignore_private_signer_check` - Whether to ignore the private signer check
    ///
    /// # Returns:
    /// * `Result<HttpProvider, TxnManagerSendError>` - The provider instance or an error
    ///
    /// # Errors
    /// * `TxnManagerSendError::GasWalletChanged` - If the private signer of the transaction
    ///                                             does not match the private signer of the
    ///                                             TxnManager
    ///
    /// This method is used to create a provider for a transaction.
    /// If ignore_private_signer_check is false, the private signer of the transaction
    /// must match the private signer of the TxnManager.
    fn _create_provider(
        self: &Arc<Self>,
        transaction: &Transaction,
        ignore_private_signer_check: bool,
    ) -> Result<HttpProvider, TxnManagerSendError> {
        if !ignore_private_signer_check
            && transaction.private_signer != self.private_signer.read().unwrap().clone()
        {
            return Err(TxnManagerSendError::GasWalletChanged(
                "Gas wallet changed".to_string(),
            ));
        }
        let signer: PrivateKeySigner = transaction.private_signer.clone();
        let signer = signer.with_chain_id(Some(self.chain_id));
        let signer_wallet = EthereumWallet::from(signer);

        Ok(ProviderBuilder::new()
            .wallet(signer_wallet)
            .on_http(Url::parse(&self.rpc_url).unwrap()))
    }

    /// Manages transaction nonces to ensure proper transaction ordering.
    ///
    /// # Arguments:
    /// * `provider` - The HTTP provider instance
    /// * `transaction` - The transaction to manage nonce for
    /// * `update_nonce` - Whether to update the nonce
    ///
    /// # Returns:
    /// * `Result<(), TxnManagerSendError>` - The result of the nonce management
    ///
    /// # Errors
    /// * `TxnManagerSendError::Timeout` - If the nonce is not updated within the timeout
    ///
    /// This method is used to manage the nonce for a transaction.
    /// If update_nonce is true, the nonce is updated to the current nonce of the provider.
    /// If update_nonce is false, the nonce is not updated.
    async fn _manage_nonce(
        self: &Arc<Self>,
        provider: &HttpProvider,
        transaction: &mut Transaction,
        update_nonce: bool,
    ) -> Result<(), TxnManagerSendError> {
        let mut failure_reason = String::new();

        while Instant::now() < transaction.timeout {
            let mut current_nonce: u64 = 0;
            if update_nonce {
                let private_signer = transaction.private_signer.address();
                let current_nonce_res = provider.get_transaction_count(private_signer).await;
                current_nonce = match current_nonce_res {
                    Ok(current_nonce) => current_nonce,
                    Err(err) => {
                        failure_reason = err.to_string();
                        sleep(Duration::from_millis(HTTP_SLEEP_TIME_MS)).await;
                        continue;
                    }
                };
            } else if transaction.nonce.is_some() {
                return Ok(());
            }

            let mut nonce_to_send_guard = self.nonce_to_send.write().unwrap();
            let mut nonce_to_send_private_signer_guard =
                self.nonce_to_send_private_signer.write().unwrap();

            // If the private signer of the nonce to send is different from the provider's private
            // signer, update the nonce to send.
            if nonce_to_send_private_signer_guard.address() != transaction.private_signer.address()
            {
                *nonce_to_send_private_signer_guard = transaction.private_signer.clone();
                *nonce_to_send_guard = current_nonce;
            }
            // If the private signer of the nonce to send is the same as the transaction private
            // signer, update the nonce to send if the current nonce is greater than the nonce to
            // send.
            else if current_nonce > *nonce_to_send_guard {
                *nonce_to_send_guard = current_nonce;
            }

            transaction.nonce = Some(*nonce_to_send_guard);
            *nonce_to_send_guard += 1;

            return Ok(());
        }

        Err(TxnManagerSendError::Timeout(failure_reason))
    }

    /// Estimates gas limit and price for a transaction.
    ///
    /// # Arguments:
    /// * `provider` - The HTTP provider instance
    /// * `transaction` - The transaction to estimate gas limit and price for
    /// * `transaction_request` - The transaction request to estimate gas limit and price for
    ///
    /// # Returns:
    /// * `Result<(), TxnManagerSendError>` - The result of the gas limit and price estimation
    ///
    /// # Errors
    /// * `TxnManagerSendError::Timeout` - If the gas limit and price is not estimated within the
    ///                                    timeout along with the failure reason
    /// * `TxnManagerSendError::GasTooHigh` - If the gas limit is too high
    /// * `TxnManagerSendError::ContractExecution` - If the contract execution fails
    ///
    /// This method is used to estimate the gas limit and price for a transaction.
    async fn _estimate_gas_limit_and_price(
        self: &Arc<Self>,
        provider: &HttpProvider,
        transaction: &mut Transaction,
        transaction_request: TransactionRequest,
        ignore_timeout: bool,
    ) -> Result<(), TxnManagerSendError> {
        let mut gas_price: u128 = 0;
        let mut failure_reason = String::new();
        while Instant::now() < transaction.timeout || ignore_timeout {
            let gas_price_res = provider.get_gas_price().await;
            gas_price = match gas_price_res {
                Ok(gas_price) => gas_price,
                Err(err) => {
                    failure_reason = err.to_string();
                    sleep(Duration::from_millis(HTTP_SLEEP_TIME_MS)).await;
                    continue;
                }
            };

            break;
        }

        let mut estimated_gas: u64 = 0;
        while Instant::now() < transaction.timeout || ignore_timeout {
            let estimated_gas_res = provider.estimate_gas(&transaction_request).await;
            estimated_gas = match estimated_gas_res {
                Ok(estimated_gas) => estimated_gas,
                Err(err) => {
                    let err = parse_send_error(err.to_string());
                    match err {
                        TxnManagerSendError::GasTooHigh(_)
                        | TxnManagerSendError::ContractExecution(_) => {
                            return Err(err);
                        }
                        err => {
                            failure_reason = err.to_string();
                            sleep(Duration::from_millis(HTTP_SLEEP_TIME_MS)).await;
                            continue;
                        }
                    }
                }
            };

            break;
        }

        if gas_price == 0 || estimated_gas == 0 {
            return Err(TxnManagerSendError::Timeout(failure_reason));
        }

        transaction.gas_price = gas_price;
        transaction.estimated_gas = estimated_gas;

        Ok(())
    }

    /// Performs periodic cleanup of old transactions from memory.
    ///
    /// This method is used to clean up old transactions from memory.
    async fn _garbage_collect_transactions(self: &Arc<Self>) {
        loop {
            sleep(Duration::from_secs(self.garbage_collect_interval_sec)).await;

            let mut transactions_guard = self.transactions.write().unwrap();
            let now = Instant::now();

            transactions_guard.retain(|_, transaction| {
                // Keep transaction if less than 10 minutes old
                now.duration_since(transaction.last_monitored)
                    < Duration::from_secs(self.garbage_removal_duration_sec)
            });
        }
    }
}
