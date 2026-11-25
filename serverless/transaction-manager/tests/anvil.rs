//! Tests against a local anvil chain. They are skipped when `anvil` is not in PATH.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, Bytes};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::signers::local::PrivateKeySigner;
use alloy::transports::http::{Client, Http};
use multi_block_txns::{TxnManager, TxnStatus};
use tokio::time::sleep;

struct Anvil {
    child: Child,
    url: String,
    provider: RootProvider<Http<Client>>,
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn start_anvil() -> Option<Anvil> {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = match Command::new("anvil")
        .args(["--port", &port.to_string(), "--silent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => {
            eprintln!("anvil not found in PATH, skipping");
            return None;
        }
    };

    let url = format!("http://127.0.0.1:{}", port);
    let provider = ProviderBuilder::new().on_http(url.parse().unwrap());
    let anvil = Anvil {
        child,
        url,
        provider,
    };
    for _ in 0..100 {
        if anvil.provider.get_chain_id().await.is_ok() {
            return Some(anvil);
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("anvil did not start");
}

impl Anvil {
    async fn rpc(&self, method: &'static str, params: serde_json::Value) -> serde_json::Value {
        self.provider
            .raw_request(method.into(), params)
            .await
            .unwrap()
    }

    async fn set_balance(&self, address: Address, wei: u128) {
        self.rpc(
            "anvil_setBalance",
            serde_json::json!([address, format!("{:#x}", wei)]),
        )
        .await;
    }

    async fn set_code(&self, address: Address, code: &str) {
        self.rpc("anvil_setCode", serde_json::json!([address, code]))
            .await;
    }

    fn txn_manager(&self, signer: &PrivateKeySigner) -> Arc<TxnManager> {
        TxnManager::new(
            self.url.clone(),
            31337,
            signer.to_bytes().to_string(),
            None,
            None,
            None,
            None,
        )
        .unwrap()
    }
}

const ONE_ETH: u128 = 1_000_000_000_000_000_000;

#[tokio::test]
async fn reverting_call_is_reported_as_contract_execution() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    let signer = PrivateKeySigner::random();
    anvil.set_balance(signer.address(), ONE_ETH).await;

    // PUSH1 0 PUSH1 0 REVERT
    let contract = Address::repeat_byte(0x22);
    anvil.set_code(contract, "0x60006000fd").await;

    let txn_manager = anvil.txn_manager(&signer);
    txn_manager.run().await;

    let err = txn_manager
        .call_contract_function(
            contract,
            Bytes::new(),
            Instant::now() + Duration::from_secs(30),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().starts_with("Contract execution failed"),
        "{err}"
    );
}

#[tokio::test]
async fn insufficient_funds_is_retried_until_the_deadline() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    let signer = PrivateKeySigner::random();
    let contract = Address::repeat_byte(0x33);

    let txn_manager = anvil.txn_manager(&signer);
    txn_manager.run().await;

    // Fund the wallet after the deadline so the nonce can be filled
    let anvil = Arc::new(anvil);
    let anvil_clone = anvil.clone();
    let address = signer.address();
    tokio::spawn(async move {
        sleep(Duration::from_secs(9)).await;
        anvil_clone.set_balance(address, ONE_ETH).await;
    });

    let start = Instant::now();
    let err = txn_manager
        .call_contract_function(
            contract,
            Bytes::new(),
            Instant::now() + Duration::from_secs(7),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().starts_with("Timeout"), "{err}");
    assert!(err.to_string().contains("Insufficient funds"), "{err}");
    assert!(start.elapsed() >= Duration::from_secs(7));

    // The nonce was filled by the transaction sent once the wallet was funded
    assert_eq!(
        anvil
            .provider
            .get_transaction_count(signer.address())
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn gas_price_stops_at_the_maximum_and_the_transaction_stays_pending() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    let signer = PrivateKeySigner::random();
    anvil.set_balance(signer.address(), ONE_ETH).await;
    let contract = Address::repeat_byte(0x44);

    // Keep the transaction pending so that it is resent every 5 s
    anvil
        .rpc("evm_setAutomine", serde_json::json!([false]))
        .await;

    let network_gas_price = anvil.provider.get_gas_price().await.unwrap();
    let max_gas_price = network_gas_price * 125 / 100;

    let txn_manager = anvil.txn_manager(&signer);
    txn_manager.set_max_gas_price(Some(max_gas_price));
    txn_manager.run().await;

    let txn_id = txn_manager
        .call_contract_function(
            contract,
            Bytes::new(),
            Instant::now() + Duration::from_secs(120),
        )
        .await
        .unwrap();

    // Resent at 1.1x, 1.21x, then at the maximum, then the same transaction again
    // A monitoring round takes 5 s plus the receipt retries (up to about 13 s). Watch until the
    // maximum is reached, then for one more round at the maximum.
    let mut gas_prices = vec![];
    let start = Instant::now();
    let mut at_max_since = None;
    while at_max_since
        .is_none_or(|at_max_since: Instant| at_max_since.elapsed() < Duration::from_secs(20))
    {
        assert!(start.elapsed() < Duration::from_secs(90), "{gas_prices:?}");
        let pool = anvil.rpc("txpool_content", serde_json::json!([])).await;
        let pending = &pool["pending"];
        let txn = pending
            .as_object()
            .unwrap()
            .iter()
            .find(|(address, _)| address.parse::<Address>().unwrap() == signer.address())
            .map(|(_, txns)| txns["0"].clone())
            .unwrap();
        let gas_price = u128::from_str_radix(
            txn["gasPrice"].as_str().unwrap().trim_start_matches("0x"),
            16,
        )
        .unwrap();
        if gas_prices.last() != Some(&gas_price) {
            gas_prices.push(gas_price);
        }
        if gas_price == max_gas_price && at_max_since.is_none() {
            at_max_since = Some(Instant::now());
        }
        assert!(gas_price <= max_gas_price, "{gas_prices:?}");
        assert_eq!(
            txn_manager.get_transaction_status(txn_id.clone()),
            Some(TxnStatus::Pending)
        );
        sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(gas_prices.last(), Some(&max_gas_price), "{gas_prices:?}");
    assert!(gas_prices.len() >= 3, "{gas_prices:?}");

    // Still monitored at the maximum, confirmed once included
    anvil.rpc("evm_mine", serde_json::json!([])).await;
    let start = Instant::now();
    while txn_manager.get_transaction_status(txn_id.clone()) != Some(TxnStatus::Confirmed) {
        assert!(start.elapsed() < Duration::from_secs(15));
        sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        anvil
            .provider
            .get_transaction_count(signer.address())
            .await
            .unwrap(),
        1
    );
}
