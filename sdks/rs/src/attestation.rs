use std::borrow::BorrowMut;
use std::collections::BTreeMap;

use aws_nitro_enclaves_cose::{crypto::Openssl, CoseSign1};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Uri;
use hyper_util::client::legacy::{Client, Error};
use hyper_util::rt::TokioExecutor;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNumContext;
use openssl::ec::{EcKey, PointConversionForm};
use openssl::sha::Sha256;
use openssl::x509::{X509VerifyResult, X509};
use serde_cbor::{self, value, value::Value};

pub const AWS_ROOT_KEY: [u8; 96] = hex_literal::hex!("fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4");
pub const MOCK_ROOT_KEY: [u8; 96] = hex_literal::hex!("6c79411ebaae7489a4e8355545c0346784b31df5d08cb1f7c0097836a82f67240f2a7201862880a1d09a0bb326637188fbbafab47a10abe3630fcf8c18d35d96532184985e582c0dce3dace8441f37b9cc9211dff935baae69e4872cc3494410");

#[derive(Debug)]
pub struct AttestationDecoded {
    pub timestamp: usize,
    pub pcrs: [[u8; 48]; 3],
    pub root_public_key: Box<[u8]>,
    pub public_key: Box<[u8]>,
    pub user_data: Box<[u8]>,
    pub image_id: [u8; 32],
}

#[derive(thiserror::Error, Debug)]
pub enum AttestationError {
    #[error("failed to parse: {0}")]
    ParseFailed(String),
    #[error("failed to verify attestation: {0}")]
    VerifyFailed(String),
    #[error("http client error")]
    HttpClientError(#[from] Error),
    #[error("http body error")]
    HttpBodyError(#[from] hyper::Error),
}

#[derive(Debug, Default)]
pub struct AttestationExpectations<'a> {
    pub timestamp: Option<usize>,
    // (max age, current timestamp)
    pub age: Option<(usize, usize)>,
    pub pcrs: Option<[[u8; 48]; 3]>,
    pub public_key: Option<&'a [u8]>,
    pub user_data: Option<&'a [u8]>,
    pub root_public_key: Option<&'a [u8]>,
    pub image_id: Option<&'a [u8; 32]>,
}

pub fn verify(
    attestation_doc: &[u8],
    expectations: AttestationExpectations,
) -> Result<AttestationDecoded, AttestationError> {
    let mut result = AttestationDecoded {
        pcrs: [[0; 48]; 3],
        timestamp: 0,
        root_public_key: Default::default(),
        public_key: Default::default(),
        user_data: Default::default(),
        image_id: Default::default(),
    };

    // parse attestation doc
    let (cosesign1, mut attestation_doc) = parse_attestation_doc(&attestation_doc)?;

    // parse timestamp
    result.timestamp = parse_timestamp(&mut attestation_doc)?;

    // check expected timestamp if exists
    if let Some(expected_ts) = expectations.timestamp {
        if result.timestamp != expected_ts {
            return Err(AttestationError::VerifyFailed("timestamp mismatch".into()));
        }
    }

    // check age if exists
    if let Some((max_age, current_ts)) = expectations.age {
        if result.timestamp <= current_ts && current_ts - result.timestamp > max_age {
            return Err(AttestationError::VerifyFailed("too old".into()));
        }
    }

    // parse pcrs
    result.pcrs = parse_pcrs(&mut attestation_doc)?;

    // check pcrs if exists
    if let Some(pcrs) = expectations.pcrs {
        if result.pcrs != pcrs {
            return Err(AttestationError::VerifyFailed("pcrs mismatch".into()));
        }
    }

    // verify signature and cert chain
    result.root_public_key =
        verify_root_of_trust(&mut attestation_doc, &cosesign1, result.timestamp)?;

    // check root public key if exists
    if let Some(root_public_key) = expectations.root_public_key {
        if result.root_public_key.as_ref() != root_public_key {
            return Err(AttestationError::VerifyFailed(
                "root public key mismatch".into(),
            ));
        }
    }

    // return the enclave key
    result.public_key = parse_enclave_key(&mut attestation_doc)?;

    // check enclave public key if exists
    if let Some(public_key) = expectations.public_key {
        if result.public_key.as_ref() != public_key {
            return Err(AttestationError::VerifyFailed(
                "enclave public key mismatch".into(),
            ));
        }
    }

    // return the user data
    result.user_data = parse_user_data(&mut attestation_doc)?;

    // check user data if exists
    if let Some(user_data) = expectations.user_data {
        if result.user_data.as_ref() != user_data {
            return Err(AttestationError::VerifyFailed("user data mismatch".into()));
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(result.pcrs.as_flattened());
    hasher.update(
        &u16::try_from(result.user_data.len())
            .map_err(|_| {
                AttestationError::VerifyFailed("user data too big to compute image id".into())
            })?
            .to_be_bytes(),
    );
    hasher.update(result.user_data.as_ref());
    result.image_id = hasher.finish();

    // check image id if exists
    if let Some(image_id) = expectations.image_id {
        if &result.image_id != image_id {
            return Err(AttestationError::VerifyFailed("image id mismatch".into()));
        }
    }

    Ok(result)
}

fn parse_attestation_doc(
    attestation_doc: &[u8],
) -> Result<(CoseSign1, BTreeMap<Value, Value>), AttestationError> {
    let cosesign1 = CoseSign1::from_bytes(&attestation_doc)
        .map_err(|e| AttestationError::ParseFailed(format!("cose: {e}")))?;
    let payload = cosesign1
        .get_payload::<Openssl>(None)
        .map_err(|e| AttestationError::ParseFailed(format!("cose payload: {e}")))?;
    let cbor = serde_cbor::from_slice::<Value>(&payload)
        .map_err(|e| AttestationError::ParseFailed(format!("cbor: {e}")))?;
    let attestation_doc = value::from_value::<BTreeMap<Value, Value>>(cbor)
        .map_err(|e| AttestationError::ParseFailed(format!("doc: {e}")))?;

    Ok((cosesign1, attestation_doc))
}

fn parse_timestamp(
    attestation_doc: &mut BTreeMap<Value, Value>,
) -> Result<usize, AttestationError> {
    let timestamp = attestation_doc
        .remove(&"timestamp".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "timestamp not found in attestation doc".to_owned(),
        ))?;
    let timestamp = (match timestamp {
        Value::Integer(b) => Ok(b),
        _ => Err(AttestationError::ParseFailed(
            "timestamp decode failure".to_owned(),
        )),
    })?;
    let timestamp = timestamp
        .try_into()
        .map_err(|e| AttestationError::ParseFailed(format!("timestamp: {e}")))?;

    Ok(timestamp)
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

fn verify_root_of_trust(
    attestation_doc: &mut BTreeMap<Value, Value>,
    cosesign1: &CoseSign1,
    timestamp: usize,
) -> Result<Box<[u8]>, AttestationError> {
    // verify attestation doc signature
    let enclave_certificate = attestation_doc
        .remove(&"certificate".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "certificate key not found".to_owned(),
        ))?;
    let enclave_certificate = (match enclave_certificate {
        Value::Bytes(b) => Ok(b),
        _ => Err(AttestationError::ParseFailed(
            "enclave certificate decode failure".to_owned(),
        )),
    })?;
    let enclave_certificate = X509::from_der(&enclave_certificate)
        .map_err(|e| AttestationError::ParseFailed(format!("leaf der: {e}")))?;
    let pub_key = enclave_certificate
        .public_key()
        .map_err(|e| AttestationError::ParseFailed(format!("leaf pubkey: {e}")))?;
    let verify_result = cosesign1
        .verify_signature::<Openssl>(&pub_key)
        .map_err(|e| AttestationError::ParseFailed(format!("leaf signature: {e}")))?;

    if !verify_result {
        return Err(AttestationError::VerifyFailed("leaf signature".into()));
    }

    // verify certificate chain
    let cabundle = attestation_doc
        .remove(&"cabundle".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "cabundle key not found in attestation doc".to_owned(),
        ))?;
    let mut cabundle = (match cabundle {
        Value::Array(b) => Ok(b),
        _ => Err(AttestationError::ParseFailed(
            "cabundle decode failure".to_owned(),
        )),
    })?;
    cabundle.reverse();

    let root_public_key = verify_cert_chain(enclave_certificate, &cabundle, timestamp)?;

    Ok(root_public_key)
}

fn verify_cert_chain(
    cert: X509,
    cabundle: &[Value],
    timestamp: usize,
) -> Result<Box<[u8]>, AttestationError> {
    let certs = get_all_certs(cert, cabundle)?;

    for i in 0..(certs.len() - 1) {
        let pubkey = certs[i + 1]
            .public_key()
            .map_err(|e| AttestationError::ParseFailed(format!("pubkey {i}: {e}")))?;
        if !certs[i]
            .verify(&pubkey)
            .map_err(|e| AttestationError::ParseFailed(format!("signature {i}: {e}")))?
        {
            return Err(AttestationError::VerifyFailed("signature {i}".into()));
        }
        if certs[i + 1].issued(&certs[i]) != X509VerifyResult::OK {
            return Err(AttestationError::VerifyFailed(
                "issuer or subject {i}".into(),
            ));
        }
        let current_time = Asn1Time::from_unix(timestamp as i64 / 1000)
            .map_err(|e| AttestationError::ParseFailed(e.to_string()))?;
        if certs[i].not_after() < current_time || certs[i].not_before() > current_time {
            return Err(AttestationError::VerifyFailed("timestamp {i}".into()));
        }
    }

    let root_cert = certs
        .last()
        .ok_or(AttestationError::ParseFailed("root".into()))?;

    let root_public_key_der = root_cert
        .public_key()
        .map_err(|e| AttestationError::ParseFailed(format!("root pubkey: {e}")))?
        .public_key_to_der()
        .map_err(|e| AttestationError::ParseFailed(format!("root pubkey der: {e}")))?;

    let root_public_key = EcKey::public_key_from_der(&root_public_key_der)
        .map_err(|e| AttestationError::ParseFailed(format!("root pubkey der: {e}")))?;

    let root_public_key_sec1 = root_public_key
        .public_key()
        .to_bytes(
            root_public_key.group(),
            PointConversionForm::UNCOMPRESSED,
            BigNumContext::new()
                .map_err(|e| AttestationError::ParseFailed(format!("bignum context: {e}")))?
                .borrow_mut(),
        )
        .map_err(|e| AttestationError::ParseFailed(format!("sec1: {e}")))?;

    Ok(root_public_key_sec1[1..].to_vec().into_boxed_slice())
}

fn get_all_certs(cert: X509, cabundle: &[Value]) -> Result<Box<[X509]>, AttestationError> {
    let mut all_certs = vec![cert];
    for cert in cabundle {
        let cert = (match cert {
            Value::Bytes(b) => Ok(b),
            _ => Err(AttestationError::ParseFailed("cert decode".into())),
        })?;
        let cert = X509::from_der(&cert)
            .map_err(|e| AttestationError::ParseFailed(format!("der: {e}")))?;
        all_certs.push(cert);
    }
    Ok(all_certs.into_boxed_slice())
}

fn parse_enclave_key(
    attestation_doc: &mut BTreeMap<Value, Value>,
) -> Result<Box<[u8]>, AttestationError> {
    let public_key = attestation_doc
        .remove(&"public_key".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "public key not found in attestation doc".to_owned(),
        ))?;
    let public_key = (match public_key {
        Value::Bytes(b) => Ok(b),
        _ => Err(AttestationError::ParseFailed(
            "public key decode failure".to_owned(),
        )),
    })?;

    Ok(public_key.into_boxed_slice())
}

fn parse_user_data(
    attestation_doc: &mut BTreeMap<Value, Value>,
) -> Result<Box<[u8]>, AttestationError> {
    let user_data = attestation_doc
        .remove(&"user_data".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "user data not found in attestation doc".to_owned(),
        ))?;
    let user_data = (match user_data {
        Value::Bytes(b) => Ok(b),
        Value::Null => Ok(vec![]),
        _ => Err(AttestationError::ParseFailed(
            "user data decode failure".to_owned(),
        )),
    })?;

    Ok(user_data.into_boxed_slice())
}

pub async fn get(endpoint: Uri) -> Result<Box<[u8]>, AttestationError> {
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let res = client.get(endpoint).await?;
    let body = res.collect().await?.to_bytes();

    Ok(body.to_vec().into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::attestation::{AttestationExpectations, AWS_ROOT_KEY, MOCK_ROOT_KEY};

    use super::verify;

    // generated using `curl <ip>:<port>/attestation/raw`
    // on the attestation server of a real Nitro enclave
    #[test]
    fn test_aws_none_specified() {
        let attestation =
            std::fs::read(file!().rsplit_once('/').unwrap().0.to_owned() + "/testcases/aws.bin")
                .unwrap();

        let decoded = verify(&attestation, Default::default()).unwrap();

        assert_eq!(decoded.timestamp, 0x00000193bef3f3b0);
        assert_eq!(decoded.pcrs[0], hex!("189038eccf28a3a098949e402f3b3d86a876f4915c5b02d546abb5d8c507ceb1755b8192d8cfca66e8f226160ca4c7a6"));
        assert_eq!(decoded.pcrs[1], hex!("5d3938eb05288e20a981038b1861062ff4174884968a39aee5982b312894e60561883576cc7381d1a7d05b809936bd16"));
        assert_eq!(decoded.pcrs[2], hex!("6c3ef363c488a9a86faa63a44653fd806e645d4540b40540876f3b811fc1bceecf036a4703f07587c501ee45bb56a1aa"));
        assert_eq!(decoded.user_data, [0u8; 0].into());
        assert_eq!(decoded.public_key.as_ref(), hex!("e646f8b0071d5ba75931402522cc6a5c42a84a6fea238864e5ac9a0e12d83bd36d0c8109d3ca2b699fce8d082bf313f5d2ae249bb275b6b6e91e0fcd9262f4bb"));
        assert_eq!(decoded.root_public_key.as_ref(), AWS_ROOT_KEY);
        assert_eq!(
            decoded.image_id,
            hex!("10aff51b369137fcb2d71372829300c543b1f8c586d77080f00ba31140621b9c")
        );
    }

    // generated using `curl <ip>:<port>/attestation/raw`
    // on the attestation server of a real Nitro enclave
    #[test]
    fn test_aws_all_specified() {
        let attestation =
            std::fs::read(file!().rsplit_once('/').unwrap().0.to_owned() + "/testcases/aws.bin")
                .unwrap();

        let decoded = verify(
            &attestation,
            AttestationExpectations {
                timestamp: Some(0x00000193bef3f3b0),
                age: Some((
                    300000,
                    0x00000193bef3f3b0 + 300000,
                )),
                pcrs: Some([
                    hex!("189038eccf28a3a098949e402f3b3d86a876f4915c5b02d546abb5d8c507ceb1755b8192d8cfca66e8f226160ca4c7a6"),
                    hex!("5d3938eb05288e20a981038b1861062ff4174884968a39aee5982b312894e60561883576cc7381d1a7d05b809936bd16"),
                    hex!("6c3ef363c488a9a86faa63a44653fd806e645d4540b40540876f3b811fc1bceecf036a4703f07587c501ee45bb56a1aa"),
                ]),
                public_key: Some(&hex!("e646f8b0071d5ba75931402522cc6a5c42a84a6fea238864e5ac9a0e12d83bd36d0c8109d3ca2b699fce8d082bf313f5d2ae249bb275b6b6e91e0fcd9262f4bb")),
                user_data: Some(&[0; 0]),
                root_public_key: Some(&AWS_ROOT_KEY),
                image_id: Some(&hex!("10aff51b369137fcb2d71372829300c543b1f8c586d77080f00ba31140621b9c")),
            },
        )
        .unwrap();

        assert_eq!(decoded.timestamp, 0x00000193bef3f3b0);
        assert_eq!(decoded.pcrs[0], hex!("189038eccf28a3a098949e402f3b3d86a876f4915c5b02d546abb5d8c507ceb1755b8192d8cfca66e8f226160ca4c7a6"));
        assert_eq!(decoded.pcrs[1], hex!("5d3938eb05288e20a981038b1861062ff4174884968a39aee5982b312894e60561883576cc7381d1a7d05b809936bd16"));
        assert_eq!(decoded.pcrs[2], hex!("6c3ef363c488a9a86faa63a44653fd806e645d4540b40540876f3b811fc1bceecf036a4703f07587c501ee45bb56a1aa"));
        assert_eq!(decoded.user_data, [0u8; 0].into());
        assert_eq!(decoded.public_key.as_ref(), hex!("e646f8b0071d5ba75931402522cc6a5c42a84a6fea238864e5ac9a0e12d83bd36d0c8109d3ca2b699fce8d082bf313f5d2ae249bb275b6b6e91e0fcd9262f4bb"));
        assert_eq!(decoded.root_public_key.as_ref(), AWS_ROOT_KEY);
        assert_eq!(
            decoded.image_id,
            hex!("10aff51b369137fcb2d71372829300c543b1f8c586d77080f00ba31140621b9c")
        );
    }

    // generated using `curl <ip>:<port>/attestation/raw?public_key=12345678&user_data=abcdef`
    // on a custom mock attestation server running locally
    #[test]
    fn test_mock_none_specified() {
        let attestation =
            std::fs::read(file!().rsplit_once('/').unwrap().0.to_owned() + "/testcases/custom.bin")
                .unwrap();

        let decoded = verify(&attestation, Default::default()).unwrap();

        assert_eq!(decoded.timestamp, 0x00000193bf444e30);
        assert_eq!(decoded.pcrs[0], [0; 48]);
        assert_eq!(decoded.pcrs[1], [1; 48]);
        assert_eq!(decoded.pcrs[2], [2; 48]);
        assert_eq!(decoded.user_data.as_ref(), hex!("abcdef"));
        assert_eq!(decoded.public_key.as_ref(), hex!("12345678"));
        assert_eq!(decoded.root_public_key.as_ref(), MOCK_ROOT_KEY);
        assert_eq!(
            decoded.image_id,
            hex!("79fc2e5fd8deb77d38890bdb4e4b1a1bddb08b5854d81d97b24167b449ddd372")
        );
    }

    // generated using `curl <ip>:<port>/attestation/raw?public_key=12345678&user_data=abcdef`
    // on a custom mock attestation server running locally
    #[test]
    fn test_mock_all_specified() {
        let attestation =
            std::fs::read(file!().rsplit_once('/').unwrap().0.to_owned() + "/testcases/custom.bin")
                .unwrap();

        let decoded = verify(
            &attestation,
            AttestationExpectations {
                timestamp: Some(0x00000193bf444e30),
                age: Some((300000, 0x00000193bf444e30 + 300000)),
                pcrs: Some([[0; 48], [1; 48], [2; 48]]),
                public_key: Some(&hex!("12345678")),
                user_data: Some(&hex!("abcdef")),
                root_public_key: Some(&MOCK_ROOT_KEY),
                image_id: Some(&hex!(
                    "79fc2e5fd8deb77d38890bdb4e4b1a1bddb08b5854d81d97b24167b449ddd372"
                )),
            },
        )
        .unwrap();

        assert_eq!(decoded.timestamp, 0x00000193bf444e30);
        assert_eq!(decoded.pcrs[0], [0; 48]);
        assert_eq!(decoded.pcrs[1], [1; 48]);
        assert_eq!(decoded.pcrs[2], [2; 48]);
        assert_eq!(decoded.user_data.as_ref(), hex!("abcdef"));
        assert_eq!(decoded.public_key.as_ref(), hex!("12345678"));
        assert_eq!(decoded.root_public_key.as_ref(), MOCK_ROOT_KEY);
        assert_eq!(
            decoded.image_id,
            hex!("79fc2e5fd8deb77d38890bdb4e4b1a1bddb08b5854d81d97b24167b449ddd372")
        );
    }
}
