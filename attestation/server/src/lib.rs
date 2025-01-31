use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver as nsm_driver;
use serde_bytes::ByteBuf;

pub fn get_attestation_doc(pub_key: &[u8], init_params: &[u8]) -> Vec<u8> {
    let public_key = ByteBuf::from(pub_key);
    let user_data = ByteBuf::from(init_params);

    let request = Request::Attestation {
        public_key: Some(public_key),
        user_data: Some(user_data),
        nonce: None,
    };

    let nsm_fd = nsm_driver::nsm_init();
    let response = nsm_driver::nsm_process_request(nsm_fd, request);
    nsm_driver::nsm_exit(nsm_fd);

    match response {
        Response::Attestation { document } => document,
        _ => panic!("nsm driver returned invalid response: {:?}", response),
    }
}

pub fn get_hex_attestation_doc(pub_key: &[u8], init_params: &[u8]) -> String {
    let attestation = get_attestation_doc(pub_key, init_params);
    return hex::encode(attestation);
}
