use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver as nsm_driver;
use serde_bytes::ByteBuf;

pub fn get_attestation_doc(
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let public_key = public_key.map(ByteBuf::from);
    let user_data = user_data.map(ByteBuf::from);
    let nonce = nonce.map(ByteBuf::from);

    let request = Request::Attestation {
        public_key,
        user_data,
        nonce,
    };

    let nsm_fd = nsm_driver::nsm_init();
    let response = nsm_driver::nsm_process_request(nsm_fd, request);
    nsm_driver::nsm_exit(nsm_fd);

    match response {
        Response::Attestation { document } => Ok(document),
        _ => Err(format!(
            "nsm driver returned invalid response: {:?}",
            response
        )),
    }
}

pub fn get_hex_attestation_doc(
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Result<String, String> {
    let attestation = get_attestation_doc(public_key, user_data, nonce);
    attestation.map(hex::encode)
}
