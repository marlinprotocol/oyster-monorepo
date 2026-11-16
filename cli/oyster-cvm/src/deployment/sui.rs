use std::{
    cmp::{Reverse, min},
    str::FromStr,
    time::Duration,
};

use alloy::primitives::{U256, keccak256};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose};
use serde::Deserialize;
use sui_crypto::{
    SuiSigner, ed25519::Ed25519PrivateKey, secp256k1::Secp256k1PrivateKey,
    secp256r1::Secp256r1PrivateKey, simple::SimpleKeypair,
};
use sui_rpc::{
    Client,
    client::{ExecuteAndWaitError, HeadersInterceptor},
    field::FieldMask,
    proto::sui::rpc::v2::{
        ExecuteTransactionRequest, GetObjectRequest, ListOwnedObjectsRequest,
        SimulateTransactionRequest, Transaction as TransactionProto,
    },
};
use sui_sdk_types::{
    Address, Argument, Command, Digest, GasPayment, Identifier, Input, MergeCoins, MoveCall,
    ObjectReference, ProgrammableTransaction, SignatureScheme, SplitCoins, Transaction,
    TransactionExpiration, TransactionKind,
};
use tracing::{error, info};

use crate::deployment::adapter::{
    ChainFunds, ChainProvider, ChainTransaction, DeploymentAdapter, JOB_ID_NOT_FOUND, JobData,
    JobTransactionKind, RateLock,
};

const SUI_PRIV_KEY_PREFIX: &str = "suiprivkey";
const GRPC_AUTH_TOKEN: &str = "x-token";
const OYSTER_MARKET_MODULE_NAME: &str = "market";
const OYSTER_LOCK_MODULE_NAME: &str = "lock";
// lock selector used by the market for rate revisions, keccak256("RATE_LOCK")
const RATE_LOCK_SELECTOR_PREIMAGE: &str = "RATE_LOCK";
const GAS_BUDGET_BUFFER: u64 = 1000;
const MAX_GAS_BUDGET: u64 = 50000000000000;
const TRANSACTION_CONFIRMATION_TIMEOUT_SECS: u64 = 120;

pub struct SuiAdapter {
    pub rpc_url: String,
    pub auth_token: Option<String>,
    pub usdc_id: Address,
    pub market_package_id: Address,
    pub market_package_initial_version: u64,
    pub market_config_id: Address,
    pub market_place_id: Address,
    pub lock_data_id: Address,
    pub clock_id: Address,
    pub clock_initial_shared_version: u64,
    pub usdc_coin_id: Option<Address>,
    pub gas_coin_id: Option<Address>,
    pub sender_address: Option<Address>,
}

#[derive(Clone)]
pub struct SuiProvider {
    pub client: Client,
    pub wallet: SimpleKeypair,
}

#[derive(Debug, Deserialize)]
struct JobOpened {
    job_id: u128,
    _owner: Address,
    _provider: Address,
    _metadata: String,
    _rate: u64,
    _balance: u64,
    _timestamp: u64,
}

#[async_trait]
impl DeploymentAdapter for SuiAdapter {
    async fn create_provider_with_wallet(
        &mut self,
        wallet_private_key: &str,
    ) -> Result<ChainProvider> {
        let mut client = Client::new(&self.rpc_url).context("Failed to initialize gRPC client")?;

        if let Some(auth_token) = &self.auth_token {
            let mut headers = HeadersInterceptor::default();
            headers
                .headers_mut()
                .insert(GRPC_AUTH_TOKEN, auth_token.clone().parse()?);
            client = client.with_headers(headers);
        }

        let (user_wallet, address) =
            decode_wallet_key(wallet_private_key).context("Failed to initialize user wallet")?;

        self.sender_address = Some(address);

        Ok(ChainProvider::Sui(Box::new(SuiProvider {
            client,
            wallet: user_wallet,
        })))
    }

    async fn get_operator_cp(&self, operator: &str, provider: &ChainProvider) -> Result<String> {
        let ChainProvider::Sui(provider) = provider else {
            return Err(anyhow!("Internal error"));
        };

        let move_call = MoveCall {
            package: self.market_package_id,
            module: Identifier::from_static(OYSTER_MARKET_MODULE_NAME),
            function: Identifier::from_static("provider_cp"),
            type_arguments: vec![],
            arguments: vec![Argument::Input(0), Argument::Input(1)],
        };

        let transaction_kind = TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
            commands: vec![Command::MoveCall(move_call)],
            inputs: vec![
                Input::Shared {
                    object_id: self.market_config_id,
                    initial_shared_version: self.market_package_initial_version,
                    mutable: false,
                },
                Input::Pure {
                    value: bcs::to_bytes(
                        &Address::from_hex(operator).context("Failed to parse operator address")?,
                    )
                    .context("Failed to bcs encode operator address")?,
                },
            ],
        });

        let mut client = provider.client.clone();

        let response = client
            .execution_client()
            .simulate_transaction(
                SimulateTransactionRequest::const_default()
                    .with_transaction(
                        TransactionProto::const_default()
                            .with_kind(transaction_kind)
                            .with_sender(Address::ZERO),
                    )
                    .with_read_mask(FieldMask {
                        paths: vec!["command_outputs".into()],
                    }),
            )
            .await?
            .into_inner();
        if response.command_outputs.is_empty() {
            return Err(anyhow!("No output received"))?;
        }

        let return_values = &response.command_outputs[0].return_values;
        if return_values.is_empty() {
            return Err(anyhow!("Empty response received"))?;
        }

        let cp_url: Option<String> = bcs::from_bytes(return_values[0].value().value())
            .context("Failed to bcs decode returned value")?;

        cp_url.ok_or_else(|| anyhow!("Operator doesn't exists"))
    }

    async fn fetch_extra_decimals(&self, provider: &ChainProvider) -> Result<i64> {
        let ChainProvider::Sui(provider) = provider else {
            return Err(anyhow!("Internal error"));
        };

        let move_call = MoveCall {
            package: self.market_package_id,
            module: Identifier::from_static(OYSTER_MARKET_MODULE_NAME),
            function: Identifier::from_static("extra_decimals"),
            type_arguments: vec![],
            arguments: vec![],
        };

        let transaction_kind = TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
            commands: vec![Command::MoveCall(move_call)],
            inputs: vec![],
        });

        let mut client = provider.client.clone();

        let response = client
            .execution_client()
            .simulate_transaction(
                SimulateTransactionRequest::const_default()
                    .with_transaction(
                        TransactionProto::const_default()
                            .with_kind(transaction_kind)
                            .with_sender(Address::ZERO),
                    )
                    .with_read_mask(FieldMask {
                        paths: vec!["command_outputs".into()],
                    }),
            )
            .await?
            .into_inner();
        if response.command_outputs.is_empty() {
            return Err(anyhow!("No output received"))?;
        }

        let return_values = &response.command_outputs[0].return_values;
        if return_values.is_empty() {
            return Err(anyhow!("Empty response received"))?;
        }

        let extra_decimals: u8 = bcs::from_bytes(return_values[0].value().value())
            .context("Failed to bcs decode returned value")?;

        Ok(extra_decimals as i64)
    }

    async fn get_job_data_if_exists(
        &self,
        job_id: String,
        provider: &ChainProvider,
    ) -> Result<Option<JobData>> {
        let ChainProvider::Sui(provider) = provider else {
            return Err(anyhow!("Internal error"));
        };

        let move_call = MoveCall {
            package: self.market_package_id,
            module: Identifier::from_static(OYSTER_MARKET_MODULE_NAME),
            function: Identifier::from_static("job_exists"),
            type_arguments: vec![],
            arguments: vec![Argument::Input(0), Argument::Input(1)],
        };

        let transaction_kind = TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
            commands: vec![Command::MoveCall(move_call)],
            inputs: vec![
                Input::Shared {
                    object_id: self.market_place_id,
                    initial_shared_version: self.market_package_initial_version,
                    mutable: false,
                },
                Input::Pure {
                    value: bcs::to_bytes(
                        &job_id.parse::<u128>().context("Failed to parse job ID")?,
                    )
                    .context("Failed to bcs encode job ID")?,
                },
            ],
        });

        let mut client = provider.client.clone();

        let response = client
            .execution_client()
            .simulate_transaction(
                SimulateTransactionRequest::const_default()
                    .with_transaction(
                        TransactionProto::const_default()
                            .with_kind(transaction_kind)
                            .with_sender(Address::ZERO),
                    )
                    .with_read_mask(FieldMask {
                        paths: vec!["command_outputs".into()],
                    }),
            )
            .await?
            .into_inner();
        if response.command_outputs.is_empty() {
            return Err(anyhow!("No output received for job_exists call"))?;
        }

        let return_values = &response.command_outputs[0].return_values;
        if return_values.is_empty() {
            return Err(anyhow!("Empty response received for job_exists call"))?;
        }

        let job_exists: bool = bcs::from_bytes(return_values[0].value().value())
            .context("Failed to bcs decode returned value")?;

        if !job_exists {
            return Ok(None);
        }

        let move_call = MoveCall {
            package: self.market_package_id,
            module: Identifier::from_static(OYSTER_MARKET_MODULE_NAME),
            function: Identifier::from_static("job_data"),
            type_arguments: vec![],
            arguments: vec![Argument::Input(0), Argument::Input(1)],
        };

        let transaction_kind = TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
            commands: vec![Command::MoveCall(move_call)],
            inputs: vec![
                Input::Shared {
                    object_id: self.market_place_id,
                    initial_shared_version: self.market_package_initial_version,
                    mutable: false,
                },
                Input::Pure {
                    value: bcs::to_bytes(
                        &job_id.parse::<u128>().context("Failed to parse job ID")?,
                    )
                    .context("Failed to bcs encode job ID")?,
                },
            ],
        });

        let mut client = provider.client.clone();

        let response = client
            .execution_client()
            .simulate_transaction(
                SimulateTransactionRequest::const_default()
                    .with_transaction(
                        TransactionProto::const_default()
                            .with_kind(transaction_kind)
                            .with_sender(Address::ZERO),
                    )
                    .with_read_mask(FieldMask {
                        paths: vec!["command_outputs".into()],
                    }),
            )
            .await?
            .into_inner();
        if response.command_outputs.is_empty() {
            return Err(anyhow!("No output received for job_data call"))?;
        }

        let return_values = &response.command_outputs[0].return_values;
        if return_values.len() != 7 {
            return Err(anyhow!("Returned job data inadequate"));
        }

        let metadata: String = bcs::from_bytes(return_values[1].value().value())
            .context("Failed to bcs decode metadata value")?;
        let rate: u64 = bcs::from_bytes(return_values[4].value().value())
            .context("Failed to bcs decode rate value")?;
        let last_settled: u64 = bcs::from_bytes(return_values[5].value().value())
            .context("Failed to bcs decode last settled value")?;
        let balance: u64 = bcs::from_bytes(return_values[6].value().value())
            .context("Failed to bcs decode balance value")?;

        Ok(Some(JobData {
            metadata,
            balance: U256::from(balance),
            rate: U256::from(rate),
            last_settled: if last_settled > i64::MAX as u64 {
                i64::MAX
            } else {
                last_settled as i64
            },
        }))
    }

    async fn get_rate_lock(&self, job_id: &str, provider: &ChainProvider) -> Result<RateLock> {
        let ChainProvider::Sui(provider) = provider else {
            return Err(anyhow!("Internal error"));
        };

        let job_id = job_id.parse::<u128>().context("Failed to parse job ID")?;
        let (selector, key) = rate_lock_selector_and_key(job_id);

        // lock::lock_status(&LockData, &vector<u8>, &vector<u8>, &Clock): LockStatus
        let return_values = self
            .simulate_view(
                provider,
                OYSTER_LOCK_MODULE_NAME,
                "lock_status",
                vec![
                    Input::Shared {
                        object_id: self.lock_data_id,
                        initial_shared_version: self.market_package_initial_version,
                        mutable: false,
                    },
                    Input::Pure {
                        value: bcs::to_bytes(&selector)
                            .context("Failed to bcs encode lock selector")?,
                    },
                    Input::Pure {
                        value: bcs::to_bytes(&key).context("Failed to bcs encode lock key")?,
                    },
                    Input::Shared {
                        object_id: self.clock_id,
                        initial_shared_version: self.clock_initial_shared_version,
                        mutable: false,
                    },
                ],
            )
            .await
            .context("Failed to fetch rate lock status")?;

        rate_lock_from_status_bytes(
            return_values
                .first()
                .ok_or_else(|| anyhow!("Empty response received for lock_status call"))?,
        )
    }

    async fn get_rate_lock_wait_time(&self, provider: &ChainProvider) -> Result<u64> {
        let ChainProvider::Sui(provider) = provider else {
            return Err(anyhow!("Internal error"));
        };

        let selector = keccak256(RATE_LOCK_SELECTOR_PREIMAGE).to_vec();

        // lock::lock_wait_time(&LockData, vector<u8>): u64
        let return_values = self
            .simulate_view(
                provider,
                OYSTER_LOCK_MODULE_NAME,
                "lock_wait_time",
                vec![
                    Input::Shared {
                        object_id: self.lock_data_id,
                        initial_shared_version: self.market_package_initial_version,
                        mutable: false,
                    },
                    Input::Pure {
                        value: bcs::to_bytes(&selector)
                            .context("Failed to bcs encode lock selector")?,
                    },
                ],
            )
            .await
            .context("Failed to fetch rate lock wait time")?;

        bcs::from_bytes(
            return_values
                .first()
                .ok_or_else(|| anyhow!("Empty response received for lock_wait_time call"))?,
        )
        .context("Failed to bcs decode lock wait time")
    }

    async fn prepare_funds(
        &self,
        amount_usdc: U256,
        provider: &ChainProvider,
    ) -> Result<ChainFunds> {
        let ChainProvider::Sui(provider) = provider else {
            return Err(anyhow!("Internal error"));
        };

        let mut client = provider.client.clone();
        if let Some(coin_id) = self.usdc_coin_id {
            let coin_object = client
                .ledger_client()
                .get_object(
                    GetObjectRequest::const_default()
                        .with_object_id(coin_id)
                        .with_read_mask(FieldMask {
                            paths: vec![
                                "balance".into(),
                                "object_id".into(),
                                "version".into(),
                                "digest".into(),
                            ],
                        }),
                )
                .await?
                .into_inner()
                .object
                .ok_or_else(|| {
                    anyhow!("Failed to retrieve details about the provided USDC coin")
                })?;

            if U256::from(coin_object.balance()) < amount_usdc {
                return Err(anyhow!("Insufficient USDC funds in the provided coin"));
            }

            return Ok(ChainFunds::Sui(ObjectReference::new(
                coin_id,
                coin_object.version(),
                Digest::from_str(coin_object.digest())?,
            )));
        }

        let owner = self
            .sender_address
            .ok_or_else(|| anyhow!("Sender address empty"))?;
        let coin_type = format!("0x2::coin::Coin<{}::usdc::USDC>", self.usdc_id.to_hex());

        let mut coins = client
            .state_client()
            .list_owned_objects(
                ListOwnedObjectsRequest::const_default()
                    .with_owner(owner)
                    .with_object_type(coin_type)
                    .with_read_mask(FieldMask {
                        paths: vec![
                            "balance".into(),
                            "object_id".into(),
                            "version".into(),
                            "digest".into(),
                        ],
                    }),
            )
            .await?
            .into_inner()
            .objects;

        coins.sort_by_key(|obj| Reverse(obj.balance()));

        let mut selected = Vec::new();
        let mut total = U256::ZERO;

        for obj in &coins {
            selected.push(obj);
            total += U256::from(obj.balance());
            if total >= amount_usdc {
                break;
            }
        }

        if total < amount_usdc {
            return Err(anyhow!("Insufficient USDC funds across all coins"));
        }

        let coin_obj = selected[0];
        let coin = ObjectReference::new(
            Address::from_str(coin_obj.object_id())?,
            coin_obj.version(),
            Digest::from_str(coin_obj.digest())?,
        );

        if selected.len() == 1 {
            return Ok(ChainFunds::Sui(coin));
        }

        let mut inputs = Vec::new();
        let mut arguments = Vec::new();
        let mut arg_idx = 0;

        inputs.push(Input::ImmutableOrOwned(coin.clone()));
        for coin in selected {
            if arg_idx == 0 {
                arg_idx += 1;
                continue;
            }

            inputs.push(Input::ImmutableOrOwned(ObjectReference::new(
                Address::from_str(coin.object_id())?,
                coin.version(),
                Digest::from_str(coin.digest())?,
            )));

            arguments.push(Argument::Input(arg_idx));
            arg_idx += 1;
        }

        let merge_coins = MergeCoins {
            coin: Argument::Input(0),
            coins_to_merge: arguments,
        };

        let transaction_kind = TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
            inputs,
            commands: vec![Command::MergeCoins(merge_coins)],
        });

        let sender = self
            .sender_address
            .ok_or_else(|| anyhow!("Sender address empty"))?;

        let mut client = provider.client.clone();

        let transaction = ChainTransaction::Sui(Box::new(
            kind_to_transaction(&mut client, transaction_kind, sender, self.gas_coin_id)
                .await
                .context("Failed to build merge coin transaction for USDC fund")?,
        ));

        let _ = self
            .send_transaction(false, transaction, &ChainProvider::Sui(provider.clone()))
            .await
            .context("Failed to send merge coins transaction for USDC fund")?;

        let merged_coin = client
            .ledger_client()
            .get_object(
                GetObjectRequest::const_default()
                    .with_object_id(coin.object_id())
                    .with_read_mask(FieldMask {
                        paths: vec![
                            "balance".into(),
                            "object_id".into(),
                            "version".into(),
                            "digest".into(),
                        ],
                    }),
            )
            .await?
            .into_inner()
            .object
            .ok_or_else(|| anyhow!("Failed to retrieve details about the provided USDC coin"))?;

        if U256::from(merged_coin.balance()) < amount_usdc {
            return Err(anyhow!(
                "Merged USDC coin still does not have enough balance"
            ));
        }

        return Ok(ChainFunds::Sui(ObjectReference::new(
            *coin.object_id(),
            merged_coin.version(),
            Digest::from_str(merged_coin.digest())?,
        )));
    }

    fn get_sender_address(&self) -> String {
        self.sender_address
            .map(|addr| addr.to_hex())
            .unwrap_or_default()
    }

    async fn create_job_transaction(
        &self,
        kind: JobTransactionKind,
        fund: Option<ChainFunds>,
        provider: &ChainProvider,
    ) -> Result<ChainTransaction> {
        let ChainProvider::Sui(provider) = provider else {
            return Err(anyhow!("Internal error"));
        };

        let transaction_kind = match kind {
            JobTransactionKind::Create {
                metadata,
                operator,
                rate,
                balance,
            } => {
                let Some(ChainFunds::Sui(usdc_fund)) = fund else {
                    return Err(anyhow!("USDC funds not available for market transaction"));
                };

                let split_coins = SplitCoins {
                    coin: Argument::Input(0),
                    amounts: vec![Argument::Input(1)],
                };

                let move_call = MoveCall {
                    package: self.market_package_id,
                    module: Identifier::from_static(OYSTER_MARKET_MODULE_NAME),
                    function: Identifier::from_static("job_open"),
                    type_arguments: vec![],
                    arguments: vec![
                        Argument::Input(2),
                        Argument::Input(3),
                        Argument::Input(4),
                        Argument::Input(5),
                        Argument::Result(0),
                        Argument::Input(6),
                    ],
                };

                TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                    commands: vec![
                        Command::SplitCoins(split_coins),
                        Command::MoveCall(move_call),
                    ],
                    inputs: vec![
                        Input::ImmutableOrOwned(usdc_fund),
                        Input::Pure {
                            value: bcs::to_bytes(&balance.saturating_to::<u64>())
                                .context("Failed to bcs encode usdc coin amount")?,
                        },
                        Input::Shared {
                            object_id: self.market_place_id,
                            initial_shared_version: self.market_package_initial_version,
                            mutable: true,
                        },
                        Input::Pure {
                            value: bcs::to_bytes(&metadata)
                                .context("Failed to bcs encode job metadata")?,
                        },
                        Input::Pure {
                            value: bcs::to_bytes(
                                &Address::from_str(&operator)
                                    .context("Failed to parse operator address")?,
                            )
                            .context("Failed to bcs encode job operator")?,
                        },
                        Input::Pure {
                            value: bcs::to_bytes(&rate.saturating_to::<u64>())
                                .context("Failed to bcs encode job rate")?,
                        },
                        Input::Shared {
                            object_id: self.clock_id,
                            initial_shared_version: self.clock_initial_shared_version,
                            mutable: false,
                        },
                    ],
                })
            }
            JobTransactionKind::Deposit { job_id, amount } => {
                let Some(ChainFunds::Sui(usdc_fund)) = fund else {
                    return Err(anyhow!("USDC funds not available for market transaction"));
                };
                let split_coins = SplitCoins {
                    coin: Argument::Input(0),
                    amounts: vec![Argument::Input(1)],
                };

                let move_call = MoveCall {
                    package: self.market_package_id,
                    module: Identifier::from_static(OYSTER_MARKET_MODULE_NAME),
                    function: Identifier::from_static("job_deposit"),
                    type_arguments: vec![],
                    arguments: vec![Argument::Input(2), Argument::Input(3), Argument::Result(0)],
                };

                TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                    commands: vec![
                        Command::SplitCoins(split_coins),
                        Command::MoveCall(move_call),
                    ],
                    inputs: vec![
                        Input::ImmutableOrOwned(usdc_fund),
                        Input::Pure {
                            value: bcs::to_bytes(&amount.saturating_to::<u64>())
                                .context("Failed to bcs encode usdc coin amount")?,
                        },
                        Input::Shared {
                            object_id: self.market_place_id,
                            initial_shared_version: self.market_package_initial_version,
                            mutable: true,
                        },
                        Input::Pure {
                            value: bcs::to_bytes(&job_id.parse::<u128>()?)
                                .context("Failed to bcs encode job ID")?,
                        },
                    ],
                })
            }
            JobTransactionKind::ReviseRateInitiate { job_id, rate } => {
                let move_call = MoveCall {
                    package: self.market_package_id,
                    module: Identifier::from_static(OYSTER_MARKET_MODULE_NAME),
                    function: Identifier::from_static("job_revise_rate_initiate"),
                    type_arguments: vec![],
                    arguments: vec![
                        Argument::Input(0),
                        Argument::Input(1),
                        Argument::Input(2),
                        Argument::Input(3),
                        Argument::Input(4),
                    ],
                };

                TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                    commands: vec![Command::MoveCall(move_call)],
                    inputs: vec![
                        Input::Shared {
                            object_id: self.market_place_id,
                            initial_shared_version: self.market_package_initial_version,
                            mutable: true,
                        },
                        Input::Shared {
                            object_id: self.lock_data_id,
                            initial_shared_version: self.market_package_initial_version,
                            mutable: true,
                        },
                        Input::Pure {
                            value: bcs::to_bytes(&job_id.parse::<u128>()?)
                                .context("Failed to bcs encode job ID")?,
                        },
                        Input::Pure {
                            value: bcs::to_bytes(&rate.saturating_to::<u64>())
                                .context("Failed to bcs encode job new rate")?,
                        },
                        Input::Shared {
                            object_id: self.clock_id,
                            initial_shared_version: self.clock_initial_shared_version,
                            mutable: false,
                        },
                    ],
                })
            }
            JobTransactionKind::Close { job_id } => {
                let move_call = MoveCall {
                    package: self.market_package_id,
                    module: Identifier::from_static(OYSTER_MARKET_MODULE_NAME),
                    function: Identifier::from_static("job_close"),
                    type_arguments: vec![],
                    arguments: vec![
                        Argument::Input(0),
                        Argument::Input(1),
                        Argument::Input(2),
                        Argument::Input(3),
                    ],
                };

                TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                    commands: vec![Command::MoveCall(move_call)],
                    inputs: vec![
                        Input::Shared {
                            object_id: self.market_place_id,
                            initial_shared_version: self.market_package_initial_version,
                            mutable: true,
                        },
                        Input::Shared {
                            object_id: self.lock_data_id,
                            initial_shared_version: self.market_package_initial_version,
                            mutable: true,
                        },
                        Input::Pure {
                            value: bcs::to_bytes(&job_id.parse::<u128>()?)
                                .context("Failed to bcs encode job ID")?,
                        },
                        Input::Shared {
                            object_id: self.clock_id,
                            initial_shared_version: self.clock_initial_shared_version,
                            mutable: false,
                        },
                    ],
                })
            }
            JobTransactionKind::Update { job_id, metadata } => {
                let move_call = MoveCall {
                    package: self.market_package_id,
                    module: Identifier::from_static(OYSTER_MARKET_MODULE_NAME),
                    function: Identifier::from_static("job_metadata_update"),
                    type_arguments: vec![],
                    arguments: vec![Argument::Input(0), Argument::Input(1), Argument::Input(2)],
                };

                TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                    commands: vec![Command::MoveCall(move_call)],
                    inputs: vec![
                        Input::Shared {
                            object_id: self.market_place_id,
                            initial_shared_version: self.market_package_initial_version,
                            mutable: true,
                        },
                        Input::Pure {
                            value: bcs::to_bytes(&job_id.parse::<u128>()?)
                                .context("Failed to bcs encode job ID")?,
                        },
                        Input::Pure {
                            value: bcs::to_bytes(&metadata)
                                .context("Failed to bcs encode job new metadata")?,
                        },
                    ],
                })
            }
            JobTransactionKind::Withdraw { job_id, amount } => {
                let move_call = MoveCall {
                    package: self.market_package_id,
                    module: Identifier::from_static(OYSTER_MARKET_MODULE_NAME),
                    function: Identifier::from_static("job_withdraw"),
                    type_arguments: vec![],
                    arguments: vec![
                        Argument::Input(0),
                        Argument::Input(1),
                        Argument::Input(2),
                        Argument::Input(3),
                        Argument::Input(4),
                    ],
                };

                TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                    commands: vec![Command::MoveCall(move_call)],
                    inputs: vec![
                        Input::Shared {
                            object_id: self.market_place_id,
                            initial_shared_version: self.market_package_initial_version,
                            mutable: true,
                        },
                        Input::Shared {
                            object_id: self.lock_data_id,
                            initial_shared_version: self.market_package_initial_version,
                            mutable: true,
                        },
                        Input::Pure {
                            value: bcs::to_bytes(&job_id.parse::<u128>()?)
                                .context("Failed to bcs encode job ID")?,
                        },
                        Input::Pure {
                            value: bcs::to_bytes(&amount.saturating_to::<u64>())
                                .context("Failed to bcs encode job withdraw amount")?,
                        },
                        Input::Shared {
                            object_id: self.clock_id,
                            initial_shared_version: self.clock_initial_shared_version,
                            mutable: false,
                        },
                    ],
                })
            }
        };

        let sender = self
            .sender_address
            .ok_or_else(|| anyhow!("Sender address empty"))?;

        let mut client = provider.client.clone();

        Ok(ChainTransaction::Sui(Box::new(
            kind_to_transaction(&mut client, transaction_kind, sender, self.gas_coin_id).await?,
        )))
    }

    async fn send_transaction(
        &self,
        is_create_job: bool,
        transaction: ChainTransaction,
        provider: &ChainProvider,
    ) -> Result<Option<String>> {
        let ChainProvider::Sui(provider) = provider else {
            return Err(anyhow!("Internal error"));
        };
        let ChainTransaction::Sui(transaction) = transaction else {
            return Err(anyhow!("Internal error"));
        };

        let mut client = provider.client.clone();

        let signature = provider
            .wallet
            .sign_transaction(&transaction)
            .context("Failed to sign transaction")?;

        let response = match client
            .execute_transaction_and_wait_for_checkpoint(
                ExecuteTransactionRequest::default()
                    .with_transaction(*transaction)
                    .with_signatures(vec![signature.into()])
                    .with_read_mask(FieldMask {
                        paths: vec!["digest".into(), "effects.status".into(), "events".into()],
                    }),
                Duration::from_secs(TRANSACTION_CONFIRMATION_TIMEOUT_SECS),
            )
            .await
        {
            Ok(response) => Ok(response),
            Err(err) => {
                if let ExecuteAndWaitError::CheckpointTimeout(resp) = err {
                    error!("Transaction executed but checkpoint wait timed out!");
                    Ok(resp)
                } else if let ExecuteAndWaitError::CheckpointStreamError {
                    response: resp,
                    error: _,
                } = err
                {
                    error!("Transaction executed but checkpoint stream had an error!");
                    Ok(resp)
                } else {
                    Err(err)
                }
            }
        }
        .context("Failed to send transaction")?
        .into_inner()
        .transaction
        .ok_or_else(|| anyhow!("Transaction result not found after submission"))?;
        info!("Transaction digest: {}", response.digest());

        if !response.effects().status().success() {
            return Err(anyhow!("Transaction failed - check contract interaction"));
        }

        if is_create_job {
            let events = &response.events().events;

            // Look for JobOpened Event
            for event in events {
                let Some(name) = event.event_type().split("::").last() else {
                    continue;
                };

                if name == "JobOpened" {
                    info!("Found JobOpened event");
                    let decoded_data: JobOpened = bcs::from_bytes(event.contents().value())
                        .context("Failed to bcs decode JobOpened event data")?;

                    return Ok(Some(decoded_data.job_id.to_string()));
                }
            }

            // If we can't find the JobOpened event
            info!("No JobOpened event found. All events:");
            for event in events {
                info!("Event type: {}", event.event_type());
            }

            return Err(anyhow!("{JOB_ID_NOT_FOUND} in transaction events"));
        }

        Ok(None)
    }
}

impl SuiAdapter {
    /// Runs a read-only function of the market package through simulation
    /// and returns its bcs encoded return values.
    async fn simulate_view(
        &self,
        provider: &SuiProvider,
        module: &'static str,
        function: &'static str,
        inputs: Vec<Input>,
    ) -> Result<Vec<Vec<u8>>> {
        let move_call = MoveCall {
            package: self.market_package_id,
            module: Identifier::from_static(module),
            function: Identifier::from_static(function),
            type_arguments: vec![],
            arguments: (0..inputs.len() as u16).map(Argument::Input).collect(),
        };

        let transaction_kind = TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
            commands: vec![Command::MoveCall(move_call)],
            inputs,
        });

        let mut client = provider.client.clone();

        let response = client
            .execution_client()
            .simulate_transaction(
                SimulateTransactionRequest::const_default()
                    .with_transaction(
                        TransactionProto::const_default()
                            .with_kind(transaction_kind)
                            .with_sender(Address::ZERO),
                    )
                    .with_read_mask(FieldMask {
                        paths: vec!["command_outputs".into()],
                    }),
            )
            .await?
            .into_inner();
        if response.command_outputs.is_empty() {
            return Err(anyhow!("No output received for {function} call"));
        }

        Ok(response.command_outputs[0]
            .return_values
            .iter()
            .map(|value| value.value().value().to_vec())
            .collect())
    }
}

/// Selector and key under which the market keeps the rate lock of a job:
/// `keccak256("RATE_LOCK")` and `keccak256(bcs(job_id))`.
fn rate_lock_selector_and_key(job_id: u128) -> (Vec<u8>, Vec<u8>) {
    (
        keccak256(RATE_LOCK_SELECTOR_PREIMAGE).to_vec(),
        keccak256(job_id.to_le_bytes()).to_vec(),
    )
}

/// Decodes `lock::LockStatus`, a bcs enum with variants None, Unlocked, Locked.
/// The unlock time and the pending rate are not exposed by the package.
fn rate_lock_from_status_bytes(bytes: &[u8]) -> Result<RateLock> {
    match bytes {
        [0] => Ok(RateLock::None),
        [1] => Ok(RateLock::Matured { new_rate: None }),
        [2] => Ok(RateLock::Pending {
            remaining_secs: None,
            new_rate: None,
        }),
        _ => Err(anyhow!("Unknown lock status returned: {:?}", bytes)),
    }
}

fn decode_wallet_key(value: &str) -> Result<(SimpleKeypair, Address)> {
    let bytes = if value.starts_with(SUI_PRIV_KEY_PREFIX) {
        let (parsed, data) =
            bech32::decode(value).context("Failed to bech32 decode the wallet key")?;
        if parsed.as_str() != SUI_PRIV_KEY_PREFIX {
            return Err(anyhow!("Invalid bech32 wallet key"));
        }
        data
    } else {
        general_purpose::STANDARD
            .decode(value)
            .context("Failed to base64 decode the wallet key")?
    };

    match SignatureScheme::from_byte(
        bytes
            .first()
            .ok_or_else(|| anyhow!("Invalid length"))?
            .to_owned(),
    ) {
        Ok(x) => match x {
            SignatureScheme::Ed25519 => {
                let key = Ed25519PrivateKey::new(
                    bytes
                        .get(1..)
                        .ok_or_else(|| anyhow!("Invalid length"))?
                        .try_into()?,
                );
                let address = key.public_key().derive_address();

                Ok((SimpleKeypair::from(key), address))
            }
            SignatureScheme::Secp256k1 => {
                let key = Secp256k1PrivateKey::new(
                    bytes
                        .get(1..)
                        .ok_or_else(|| anyhow!("Invalid length"))?
                        .try_into()?,
                )
                .context("Invalid key bytes")?;
                let address = key.public_key().derive_address();

                Ok((SimpleKeypair::from(key), address))
            }
            SignatureScheme::Secp256r1 => {
                let key = Secp256r1PrivateKey::new(
                    bytes
                        .get(1..)
                        .ok_or_else(|| anyhow!("Invalid length"))?
                        .try_into()?,
                );
                let address = key.public_key().derive_address();

                Ok((SimpleKeypair::from(key), address))
            }
            _ => Err(anyhow!("Invalid flag byte")),
        },

        _ => Err(anyhow!("Invalid bytes")),
    }
}

pub async fn kind_to_transaction(
    client: &mut Client,
    transaction_kind: TransactionKind,
    sender: Address,
    gas_coin_id: Option<Address>,
) -> Result<Transaction> {
    let gas_price = client
        .get_reference_gas_price()
        .await
        .context("Failed to fetch reference gas price")?;

    if let Some(gas_coin) = gas_coin_id {
        let coin_object = client
            .ledger_client()
            .get_object(
                GetObjectRequest::const_default()
                    .with_object_id(gas_coin)
                    .with_read_mask(FieldMask {
                        paths: vec![
                            "balance".into(),
                            "object_id".into(),
                            "version".into(),
                            "digest".into(),
                        ],
                    }),
            )
            .await?
            .into_inner()
            .object
            .ok_or_else(|| anyhow!("Failed to retrieve details about the provided gas coin"))?;

        let budget = min(coin_object.balance(), MAX_GAS_BUDGET);
        let gas = ObjectReference::new(
            gas_coin,
            coin_object.version(),
            Digest::from_str(coin_object.digest())?,
        );

        return Ok(Transaction {
            kind: transaction_kind,
            sender,
            gas_payment: GasPayment {
                objects: vec![gas],
                owner: sender,
                price: gas_price,
                budget,
            },
            expiration: TransactionExpiration::None,
        });
    }

    match estimate_gas(client, transaction_kind.clone(), sender).await {
        Ok(gas_payment) => Ok(Transaction {
            kind: transaction_kind,
            sender,
            gas_payment,
            expiration: TransactionExpiration::None,
        }),
        Err(err) => {
            error!("Failed to estimate gas for the transaction: {}", err);
            let coin_type = "0x2::coin::Coin<0x2::sui::SUI>";

            let objects = client
                .state_client()
                .list_owned_objects(
                    ListOwnedObjectsRequest::const_default()
                        .with_owner(sender)
                        .with_object_type(coin_type)
                        .with_read_mask(FieldMask {
                            paths: vec![
                                "balance".into(),
                                "object_id".into(),
                                "version".into(),
                                "digest".into(),
                            ],
                        }),
                )
                .await?
                .into_inner()
                .objects;

            let max_gas_object = objects
                .iter()
                .max_by_key(|obj| obj.balance())
                .ok_or_else(|| anyhow!("No sui gas coins found for the owner"))?;

            Ok(Transaction {
                kind: transaction_kind,
                sender,
                gas_payment: GasPayment {
                    objects: vec![ObjectReference::new(
                        Address::from_str(max_gas_object.object_id())?,
                        max_gas_object.version(),
                        Digest::from_str(max_gas_object.digest())?,
                    )],
                    owner: sender,
                    price: gas_price,
                    budget: min(max_gas_object.balance(), MAX_GAS_BUDGET),
                },
                expiration: TransactionExpiration::None,
            })
        }
    }
}

async fn estimate_gas(
    client: &mut Client,
    transaction_kind: TransactionKind,
    sender: Address,
) -> Result<GasPayment> {
    let simulate_response = client
        .execution_client()
        .simulate_transaction(
            SimulateTransactionRequest::const_default()
                .with_transaction(
                    TransactionProto::const_default()
                        .with_kind(transaction_kind)
                        .with_sender(sender),
                )
                .with_do_gas_selection(true),
        )
        .await?
        .into_inner();
    let gas_payment = simulate_response
        .transaction
        .ok_or_else(|| anyhow!("Executed transaction not found in simulation response!"))?
        .transaction
        .ok_or_else(|| anyhow!("Transaction field empty in the simulation response!"))?
        .gas_payment
        .ok_or_else(|| anyhow!("Gas payment field empty in the simulation response"))?;

    Ok(GasPayment {
        objects: gas_payment
            .objects
            .iter()
            .map(|obj| {
                Ok(ObjectReference::new(
                    Address::from_str(obj.object_id())?,
                    obj.version(),
                    Digest::from_str(obj.digest())?,
                ))
            })
            .collect::<Result<Vec<ObjectReference>>>()?,
        owner: sender,
        price: gas_payment.price(),
        budget: min(gas_payment.budget() + GAS_BUDGET_BUFFER, MAX_GAS_BUDGET),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // values taken from LockCreated events of the mainnet market package
    #[test]
    fn rate_lock_selector_and_key_match_mainnet_events() {
        let (selector, key) = rate_lock_selector_and_key(121);
        assert_eq!(
            hex::encode(selector),
            "bb00c34f1a27e23493f1bd516e88ec0af9b091cc990f207e765f5bd5af012243"
        );
        assert_eq!(
            hex::encode(key),
            "e4affb857739a8fc664e0f963eec03710fb4db4b441d5c5d97cf18043a0be3b4"
        );

        let (_, key) = rate_lock_selector_and_key(173);
        assert_eq!(
            hex::encode(key),
            "596f39b5621a6e2ef31829d33ec5ac6cee44f19ba7a4be4ac25a959052fbdb31"
        );
    }

    #[test]
    fn rate_lock_status_decoding() {
        assert_eq!(rate_lock_from_status_bytes(&[0]).unwrap(), RateLock::None);
        assert_eq!(
            rate_lock_from_status_bytes(&[1]).unwrap(),
            RateLock::Matured { new_rate: None }
        );
        assert_eq!(
            rate_lock_from_status_bytes(&[2]).unwrap(),
            RateLock::Pending {
                remaining_secs: None,
                new_rate: None
            }
        );
        assert!(rate_lock_from_status_bytes(&[3]).is_err());
        assert!(rate_lock_from_status_bytes(&[]).is_err());
    }
}
