use crate::handler::{
    __path_hello_handler, __path_proposal_encryption_key, __path_proposal_hashes, __path_status,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(info(
    title = "Governance Enclave",
    description = "APIs to fetch the result of proposals from the governance enclaves",
    license(name = "MIT License", url = "https://opensource.org/licenses/MIT")
))]
#[openapi(paths(hello_handler, status, proposal_encryption_key, proposal_hashes))]
struct ApiDoc;

pub fn get_swagger() -> SwaggerUi {
    SwaggerUi::new("/swagger-ui/{_:.*}").url("/api-docs/openapi.json", ApiDoc::openapi())
}
