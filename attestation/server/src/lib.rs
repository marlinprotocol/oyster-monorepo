use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver as nsm_driver;
use serde_bytes::ByteBuf;

pub fn get_attestation_doc(pub_key: &[u8], user_data: &[u8]) -> Vec<u8> {

    let user_data_vec = if user_data.is_empty() {
        None
    } else {
        Some(user_data.to_vec())
    };
    let nonce_vec = None;
    let public_key_vec = if pub_key.is_empty() {
        None
    } else {
        Some(pub_key.to_vec())
    };

    return nitro_tpm_attest::attestation_document(
        user_data_vec,
        nonce_vec,
        public_key_vec,
    ).expect("Failed to generate attestation document");
}

pub fn get_hex_attestation_doc(pub_key: &[u8], user_data: &[u8]) -> String {
    let attestation = get_attestation_doc(pub_key, user_data);
    return hex::encode(attestation);
}
