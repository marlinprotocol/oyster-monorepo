use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver as nsm_driver;
use serde_bytes::ByteBuf;

pub fn get_attestation_doc(pub_key: &[u8], user_data: &[u8]) -> Result<Vec<u8>, String> {
    let public_key = ByteBuf::from(pub_key);
    let user_data = ByteBuf::from(user_data);

    let request = Request::Attestation {
        public_key: Some(public_key),
        user_data: Some(user_data),
        nonce: None,
    };

    let nsm_fd = nsm_driver::nsm_init();
    if nsm_fd < 0 {
        return Err("failed to initialize nsm".into());
    }

    let response = nsm_driver::nsm_process_request(nsm_fd, request);
    nsm_driver::nsm_exit(nsm_fd);

    // do not panic here, a failed request should not take the server down
    match response {
        Response::Attestation { document } => Ok(document),
        _ => Err(format!(
            "nsm driver returned invalid response: {response:?}"
        )),
    }
}

pub fn get_hex_attestation_doc(pub_key: &[u8], user_data: &[u8]) -> Result<String, String> {
    get_attestation_doc(pub_key, user_data).map(hex::encode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nsm_failure_is_an_error_and_not_a_panic() {
        // only meaningful outside an enclave, where there is no nsm device
        if std::path::Path::new("/dev/nsm").exists() {
            return;
        }

        assert!(get_attestation_doc(&[1; 32], &[]).is_err());
        assert!(get_hex_attestation_doc(&[1; 32], &[]).is_err());
    }
}
