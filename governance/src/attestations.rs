use crate::governance_enclave::GovernanceEnclave;
use alloy::{network::Network, primitives::B256};
use anyhow::{Context, Result};
use async_trait::async_trait;
use oyster;
use reqwest::Client;

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
        let attestation_doc = oyster::attestation::get(attestation_endpoint.parse()?).await?;

        let attestation_expectations = oyster::attestation::AttestationExpectations {
            age_ms: None,
            pcrs: None,
            user_data: None,
            root_public_key: None,
            timestamp_ms: None,
            public_key: None,
            image_id: None,
        };

        let attestation_verified =
            oyster::attestation::verify(&attestation_doc, attestation_expectations)?;

        let image_id: B256 = attestation_verified.image_id.into();

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

#[cfg(test)]
mod tests {
    use alloy::primitives::B256;
    use anyhow::Result;

    use crate::attestations::{AttestationSource, EnclaveAttestationSource};

    #[tokio::test]
    async fn test_kms_sig_generation() -> Result<()> {
        let attestation_source = EnclaveAttestationSource::new("65.0.196.244", "1301");
        let image_id = attestation_source.image_id(0).await?;
        assert_eq!(
            image_id,
            "2fd6a229f8e2f8e3a1da73bfdd41cf110a9e467cc6a638f113323db65bf9126e".parse::<B256>()?
        );
        Ok(())
    }
}
