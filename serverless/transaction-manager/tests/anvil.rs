//! Tests against a local anvil chain. They are skipped when `anvil` is not in PATH.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, Bytes};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::signers::local::PrivateKeySigner;
use alloy::transports::http::{Client, Http};
use multi_block_txns::TxnManager;
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
