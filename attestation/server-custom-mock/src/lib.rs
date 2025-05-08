use std::time::{SystemTime, UNIX_EPOCH};

use p384::ecdsa::SigningKey;
use sec1::DecodeEcPrivateKey;
use sha2::Digest;

static ROOT_CERT: &'static [u8; 404] = include_bytes!("./certs/root.crt");
static LEAF_CERT: &'static [u8; 466] = include_bytes!("./certs/leaf.crt");
static LEAF_KEY: &'static [u8; 167] = include_bytes!("./certs/leaf.key");

pub fn get_attestation_doc(
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    if public_key.map_or(0, <[u8]>::len) > u16::MAX as usize {
        return Err("public key is too long, maximum of 65535".into());
    }

    if user_data.map_or(0, <[u8]>::len) > u16::MAX as usize {
        return Err("user_data is too long, maximum of 65535".into());
    }

    if nonce.map_or(0, <[u8]>::len) > u16::MAX as usize {
        return Err("nonce is too long, maximum of 65535".into());
    }

    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();

    // compute sizes
    // attestation/verifier-risczero is a good reference
    // 8 for COSE initial fields
    // 2 for COSE payload size
    // 1 for payload map size
    // 10 for `module_id`
    // 41 for module id
    // 7 for `digest`
    // 7 for `SHA384`
    // 10 for `timestamp`
    // 9 for timestamp
    // 5 for `pcrs`
    // 1 + 51 * 16 for standard pcrs
    // 51 for custom pcr
    // 12 for `certificate`
    // 469 for leaf cert
    // 9 for `cabundle`
    // 408 for ca bundle with root cert
    // 11 for `public_key`
    // 1/2/3 + public_key.len() for public key
    // 10 for `user_data`
    // 1/2/3 + user_data.len() for user data
    // 6 for `nonce`
    // 1/2/3 + nonce.len() for nonce
    // 98 for COSE signature

    fn encoded_len(payload: usize) -> usize {
        if payload < 24 {
            1 + payload
        } else if payload < 256 {
            2 + payload
        } else {
            3 + payload
        }
    }
    let payload_size = 1883
        + public_key.map_or(1, |x| encoded_len(x.len()))
        + user_data.map_or(1, |x| encoded_len(x.len()))
        + nonce.map_or(1, |x| encoded_len(x.len()));
    let total_size = payload_size + 108;

    if total_size > u16::MAX as usize {
        return Err("Payload too big".into());
    }

    let mut attestation = vec![0u8; total_size];

    // fill in payload fields
    attestation[10] = 0xa9;
    attestation[11] = 0x69;
    attestation[12..21].copy_from_slice(b"module_id");
    attestation[21..62].copy_from_slice(b"\x78\x27i-0d69bec447a037a2a-enc01939aab191aadd2");
    attestation[62..69].copy_from_slice(b"\x66digest");
    attestation[69..76].copy_from_slice(b"\x66SHA384");
    attestation[76..86].copy_from_slice(b"\x69timestamp");
    attestation[86] = 0x1b;
    attestation[87..95].copy_from_slice(&(timestamp_ms as u64).to_be_bytes());
    attestation[95..100].copy_from_slice(b"\x64pcrs");
    attestation[100] = 0xb1;
    for i in 0..17 {
        attestation[101 + i * 51] = i as u8;
        attestation[102 + i * 51] = 0x58;
        attestation[103 + i * 51] = 0x30;
        attestation[104 + i * 51..152 + i * 51].copy_from_slice(&[i as u8; 48]);
    }
    attestation[968..980].copy_from_slice(b"\x6bcertificate");
    attestation[980] = 0x59;
    attestation[981..983].copy_from_slice(&(LEAF_CERT.len() as u16).to_be_bytes());
    attestation[983..1449].copy_from_slice(LEAF_CERT);
    attestation[1449..1458].copy_from_slice(b"\x68cabundle");
    attestation[1458] = 0x81;
    attestation[1459] = 0x59;
    attestation[1460..1462].copy_from_slice(&(ROOT_CERT.len() as u16).to_be_bytes());
    attestation[1462..1866].copy_from_slice(ROOT_CERT);

    fn encode(to: &mut [u8], payload: Option<&[u8]>) -> usize {
        let Some(payload) = payload else {
            to[0] = 0xf6;
            return 1;
        };
        if payload.len() < 24 {
            to[0] = 0x40 + payload.len() as u8;
            to[1..1 + payload.len()].copy_from_slice(payload);
            1 + payload.len()
        } else if payload.len() < 256 {
            to[0] = 0x58;
            to[1] = payload.len() as u8;
            to[2..2 + payload.len()].copy_from_slice(payload);
            2 + payload.len()
        } else {
            to[0] = 0x59;
            to[1..3].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            to[3..3 + payload.len()].copy_from_slice(payload);
            3 + payload.len()
        }
    }

    let mut offset = 1866;
    attestation[offset..offset + 11].copy_from_slice(b"\x6apublic_key");
    offset += 11;
    offset += encode(&mut attestation[offset..], public_key);
    attestation[offset..offset + 10].copy_from_slice(b"\x69user_data");
    offset += 10;
    offset += encode(&mut attestation[offset..], user_data);
    attestation[offset..offset + 6].copy_from_slice(b"\x65nonce");
    offset += 6;
    offset += encode(&mut attestation[offset..], nonce);

    // fill in COSE fields

    attestation[0..8].copy_from_slice(&[0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0, 0x59]);
    attestation[8..10].copy_from_slice(&(payload_size as u16).to_be_bytes());
    attestation[offset] = 0x58;
    attestation[offset + 1] = 0x60;
    // signature should go after this

    // prepare COSE verification hash
    let mut hasher = sha2::Sha384::new();
    // array with 4 elements
    hasher.update(&[0x84]);
    // context field length
    hasher.update(&[0x6a]);
    // context field
    hasher.update("Signature1");
    // body_protected
    hasher.update(&[0x44, 0xa1, 0x01, 0x38, 0x22]);
    // empty aad
    hasher.update(&[0x40]);
    // payload length
    hasher.update(&[0x59, attestation[8], attestation[9]]);
    // payload
    hasher.update(&attestation[10..10 + payload_size]);
    let hash = hasher.finalize();

    let signer = SigningKey::from_sec1_der(LEAF_KEY)
        .map_err(|e| format!("failed to parse signer: {e:?}"))?;
    let signature = signer
        .sign_prehash_recoverable(&hash)
        .map_err(|e| format!("failed to sign attestation: {e:?}"))?;

    attestation[offset + 2..offset + 98].copy_from_slice(&signature.0.to_bytes());

    Ok(attestation)
}

pub fn get_hex_attestation_doc(
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Result<String, String> {
    let attestation = get_attestation_doc(public_key, user_data, nonce);
    attestation.map(hex::encode)
}
