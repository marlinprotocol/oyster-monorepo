use alloy::{
    network::Network,
    primitives::{B256, Bytes, keccak256},
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::governance_enclave::GovernanceEnclave;

#[async_trait]
pub trait AttestationSource {
    async fn image_id(&self, block_number: u64) -> Result<B256>;
}

pub struct ContractAttestationSource<N: Network> {
    governance_enclave: GovernanceEnclave<N>,
}

impl<N: Network> ContractAttestationSource<N> {
    pub fn new(governance_enclave: GovernanceEnclave<N>) -> Self {
        Self { governance_enclave }
    }
}

#[async_trait]
impl<N: Network> AttestationSource for ContractAttestationSource<N> {
    async fn image_id(&self, block_number: u64) -> Result<B256> {
        self.governance_enclave.get_image_id(block_number).await
    }
}

pub struct EnclaveAttestationSource {
    enclave_ip: String,
    port: String,
}
impl EnclaveAttestationSource {
    pub fn new(enclave_ip: &str, port: &str) -> Self {
        Self {
            enclave_ip: enclave_ip.to_string(),
            port: port.to_string(),
        }
    }
}

#[async_trait]
impl AttestationSource for EnclaveAttestationSource {
    async fn image_id(&self, _: u64) -> Result<B256> {
        let attestation_endpoint =
            format!("http://{}:{}/attestation/raw", self.enclave_ip, self.port);
        let attestation_doc = build_attestation_vec(&attestation_endpoint).await?;
        let mut parsed_attestation_doc = parse_attestation_doc(&attestation_doc)?;
        let pcrs = parse_pcrs(&mut parsed_attestation_doc.1)?;

        let image_id = image_id_from_pcrs(pcrs[0].into(), pcrs[1].into(), pcrs[2].into());

        Ok(image_id.into())
    }
}

pub async fn build_attestation_vec(attestation_endpoint: &str) -> Result<Vec<u8>> {
    let client = Client::new();
    let response = client
        .get(attestation_endpoint)
        .send()
        .await
        .context("failed to send attestation request")?;

    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| String::from("No error details"));
        anyhow::bail!("failed building the attestation: {status} - {err_text}");
    }

    let bytes = response
        .bytes()
        .await
        .context("failed to read attestation body")?;

    Ok(bytes.to_vec())
}

use std::collections::BTreeMap;

use aws_nitro_enclaves_cose::{CoseSign1, crypto::Openssl};
use serde_cbor::{self, value, value::Value};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttestationData {
    pcrs: Option<BTreeMap<u32, Value>>,
    nonce: Option<Value>,
    digest: Option<Value>,
    cabundle: Option<Value>,
    module_id: Option<Value>,
    timestamp: Option<Value>,
    user_data: Option<Value>,
    public_key: Option<Value>,
    certificate: Option<Value>,
}

#[derive(thiserror::Error, Debug)]
pub enum AttestationError {
    #[error("failed to parse: {0}")]
    ParseFailed(String),
    #[error("failed to verify attestation: {0}")]
    VerifyFailed(String),
}

pub fn parse_attestation_doc(
    attestation_doc: &[u8],
) -> Result<(CoseSign1, BTreeMap<Value, Value>, AttestationData), AttestationError> {
    let cosesign1 = CoseSign1::from_bytes(&attestation_doc)
        .map_err(|e| AttestationError::ParseFailed(format!("cose: {e}")))?;
    let payload = cosesign1
        .get_payload::<Openssl>(None)
        .map_err(|e| AttestationError::ParseFailed(format!("cose payload: {e}")))?;
    let cbor = serde_cbor::from_slice::<Value>(&payload)
        .map_err(|e| AttestationError::ParseFailed(format!("cbor: {e}")))?;
    let attestation_doc = value::from_value::<BTreeMap<Value, Value>>(cbor.clone())
        .map_err(|e| AttestationError::ParseFailed(format!("doc: {e}")))?;

    let another_attestation_doc = value::from_value::<AttestationData>(cbor)
        .map_err(|e| AttestationError::ParseFailed(format!("doc: {e}")))?;

    Ok((cosesign1, attestation_doc, another_attestation_doc))
}

pub fn image_id_from_pcrs(pcr0: Bytes, pcr1: Bytes, pcr2: Bytes) -> B256 {
    let mut data = Vec::new();
    data.extend_from_slice(&pcr0);
    data.extend_from_slice(&pcr1);
    data.extend_from_slice(&pcr2);

    // Compute the keccak256 hash
    keccak256(data).into()
}

fn parse_pcrs(
    attestation_doc: &mut BTreeMap<Value, Value>,
) -> Result<[[u8; 48]; 3], AttestationError> {
    let pcrs_arr = attestation_doc
        .remove(&"pcrs".to_owned().into())
        .ok_or(AttestationError::ParseFailed("pcrs not found".into()))?;
    let mut pcrs_arr = value::from_value::<BTreeMap<Value, Value>>(pcrs_arr)
        .map_err(|e| AttestationError::ParseFailed(format!("pcrs: {e}")))?;

    let mut result = [[0; 48]; 3];
    for i in 0..3 {
        let pcr = pcrs_arr
            .remove(&(i as u32).into())
            .ok_or(AttestationError::ParseFailed(format!("pcr{i} not found")))?;
        let pcr = (match pcr {
            Value::Bytes(b) => Ok(b),
            _ => Err(AttestationError::ParseFailed(format!(
                "pcr{i} decode failure"
            ))),
        })?;
        result[i] = pcr
            .as_slice()
            .try_into()
            .map_err(|e| AttestationError::ParseFailed(format!("pcr{i} not 48 bytes: {e}")))?;
    }

    Ok(result)
}
// http://65.0.196.244:1301/attestation/raw

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::attestations::{AttestationSource, EnclaveAttestationSource};

    #[tokio::test]
    async fn test_kms_sig_generation() -> Result<()> {
        let attestation_source = EnclaveAttestationSource::new("65.0.196.244", "1301");
        let image_id = attestation_source.image_id(0).await?;
        println!("{}", image_id);
        Ok(())
    }
}
