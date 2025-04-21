use std::collections::HashMap;

use alloy::{
    hex::ToHexExt,
    primitives::{Address, U256},
    providers::ProviderBuilder,
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
};
use anyhow::{anyhow, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::{SecondsFormat, TimeDelta, Utc};
use nucypher_core::{
    ferveo::api::{combine_shares_simple, DecryptionShareSimple, FerveoVariant},
    EncryptedThresholdDecryptionResponse, ProtocolObject, SessionSharedSecret, SessionStaticKey,
    SessionStaticSecret, ThresholdDecryptionRequest, ThresholdMessageKit,
};
use rand::{distr::Alphanumeric, rng, Rng};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

use crate::Args;

// snippet from taco contracts
sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface Coordinator {
        struct G1Point {
            bytes32 word0;
            bytes16 word1;
        }

        struct Participant {
            address provider;
            bool aggregated;
            bytes transcript;
            bytes decryptionRequestStaticKey;
            // Note: Adjust __postSentinelGap size if this struct's size changes
        }

        function rituals(
            uint256 ritualId // uint256 for backward compatibility
        )
            external
            view
            returns (
                address initiator,
                uint32 initTimestamp,
                uint32 endTimestamp,
                uint16 totalTranscripts,
                uint16 totalAggregations,
                //
                address authority,
                uint16 dkgSize,
                uint16 threshold,
                bool aggregationMismatch,
                //
                address accessController,
                G1Point memory publicKey,
                bytes memory aggregatedTranscript,
                address feeModel
            );

        function getParticipants(
            uint32 ritualId,
            uint256 startIndex,
            uint256 maxParticipants,
            bool includeTranscript
        ) external view returns (Participant[] memory);
    }
}

pub async fn get_taco_nodes(args: &Args) -> Result<HashMap<Address, SessionStaticKey>> {
    let provider =
        ProviderBuilder::new().on_http(args.rpc.parse().context("failed to parse rpc url")?);
    let contract = Coordinator::new(
        args.coordinator
            .parse()
            .context("failed to parse coordinator address")?,
        provider,
    );

    let ritual = contract
        .rituals(U256::from(args.ritual))
        .call()
        .await
        .context("failed to fetch ritual")?;

    let participants = contract
        .getParticipants(args.ritual, U256::ZERO, U256::from(ritual.dkgSize), false)
        .call()
        .await
        .context("failed to get participants")?;

    Ok(HashMap::from_iter(participants._0.into_iter().filter_map(
        |p| {
            Some((
                p.provider,
                SessionStaticKey::from_bytes(&p.decryptionRequestStaticKey).ok()?,
            ))
        },
    )))
}

pub async fn decrypt(
    encrypted: &[u8],
    ritual_id: u32,
    taco_nodes: &HashMap<Address, SessionStaticKey>,
    threshold: u16,
    porter: &str,
    signer: &PrivateKeySigner,
    chain_id: u64,
) -> Result<Box<[u8]>> {
    // parse message kit
    let message_kit = ThresholdMessageKit::from_bytes(encrypted)
        .map_err(|e| anyhow!("{e}"))
        .context("failed to decode message kit")?;

    let siwe_message = format!(
        "\
root.kms.marlin.org wants you to sign in with your Ethereum account:
{}

!!!DANGER: This is used only inside Marlin KMS, you should never be seeing this!!!

URI: https://root.kms.marlin.org/dead
Version: 1
Chain ID: {}
Nonce: {}
Issued At: {}
Expiration Time: {}",
        signer.address(),
        chain_id,
        rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect::<String>(),
        Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        (Utc::now() + TimeDelta::minutes(5)).to_rfc3339_opts(SecondsFormat::Secs, true),
    );

    let siwe = signer
        .sign_message_sync(siwe_message.as_bytes())?
        .as_bytes();

    let context = nucypher_core::Context::new(&serde_json::to_string(&ContextObj {
        user_address: HashMap::from([
            (
                "address".to_owned(),
                signer.address().encode_hex_with_prefix(),
            ),
            ("scheme".to_owned(), "EIP4361".to_owned()),
            ("signature".to_owned(), siwe.encode_hex_with_prefix()),
            ("typedData".to_owned(), siwe_message),
        ]),
    })?);

    let session_secret = SessionStaticSecret::random();
    let ciphertext_header = message_kit.ciphertext_header()?;

    let mut porter_req = PorterReq {
        threshold: threshold as usize,
        encrypted_decryption_requests: HashMap::new(),
    };

    let secrets = taco_nodes
        .iter()
        .map(|(provider, static_key)| {
            let shared = session_secret.derive_shared_secret(static_key);

            let decryption_request = ThresholdDecryptionRequest::new(
                ritual_id,
                &ciphertext_header,
                &message_kit.acp,
                Some(&context),
                FerveoVariant::Simple,
            )
            .encrypt(&shared, &session_secret.public_key());

            porter_req.encrypted_decryption_requests.insert(
                provider.encode_hex_with_prefix(),
                BASE64_STANDARD.encode(decryption_request.to_bytes()),
            );

            (provider.to_owned(), shared)
        })
        .collect::<HashMap<Address, SessionSharedSecret>>();

    let resp = Client::new().post(porter).json(&porter_req).send().await?;
    if resp.status() != StatusCode::OK {
        return Err(anyhow!(resp.text().await?));
    }

    let responses = resp
        .json::<PorterResp>()
        .await?
        .result
        .decryption_results
        .encrypted_decryption_responses;

    if responses.keys().count() < threshold as usize {
        return Err(anyhow!("not enough shares"));
    }

    let decrypted_shares = responses
        .iter()
        .map(|(k, v)| -> Result<DecryptionShareSimple> {
            let address = k.parse::<Address>()?;
            let share =
                EncryptedThresholdDecryptionResponse::from_bytes(&BASE64_STANDARD.decode(v)?)
                    .ok()
                    .ok_or(anyhow!("failed to decode share"))?;

            let decrypted = share
                .decrypt(
                    secrets
                        .get(&address)
                        .ok_or(anyhow!("taco node not found"))?,
                )
                .ok()
                .ok_or(anyhow!("failed to decrypt share"))?;

            if decrypted.ritual_id != ritual_id {
                return Err(anyhow!("wrong ritual"));
            }

            Ok(bincode::serde::decode_from_slice(
                &decrypted.decryption_share[..],
                bincode::config::legacy(),
            )?
            .0)
        })
        .filter_map(Result::ok)
        .collect::<Vec<_>>();

    if decrypted_shares.len() < threshold as usize {
        return Err(anyhow!("not enough decrypted shares"));
    }

    let shared_secret = combine_shares_simple(&decrypted_shares);

    let msg = message_kit.decrypt_with_shared_secret(&shared_secret)?;

    Ok(msg.into_boxed_slice())
}

#[derive(Serialize)]
struct ContextObj {
    #[serde(rename = ":userAddress")]
    user_address: HashMap<String, String>,
}

#[derive(Serialize)]
struct PorterReq {
    threshold: usize,
    encrypted_decryption_requests: HashMap<String, String>,
}

#[derive(Deserialize, Debug)]
struct PorterRespDecryptionResults {
    encrypted_decryption_responses: HashMap<String, String>,
}

#[derive(Deserialize, Debug)]
struct PorterRespResult {
    decryption_results: PorterRespDecryptionResults,
}

#[derive(Deserialize, Debug)]
struct PorterResp {
    result: PorterRespResult,
}
