use std::net::SocketAddr;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::market::{GBRateCard, InfraProvider, JobId, RegionalRates};

enum Error {
    GetIPFail,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, "BAD_REQUEST").into_response()
    }
}

type HandlerResult<T> = core::result::Result<T, Error>;

#[derive(Debug, Deserialize)]
struct GetIPRequest {
    id: Option<String>,
    region: Option<String>,
}

#[derive(Debug, Serialize)]
struct GetIPResponse {
    ip: String,
}

#[derive(Debug, Serialize)]
struct SpecResponse {
    allowed_regions: &'static [String],
    min_rates: &'static [RegionalRates],
}

#[derive(Debug, Serialize)]
struct BandwidthResponse {
    rates: Vec<GBRateCard>,
}

async fn handle_ip_request(
    State(state): State<(
        impl InfraProvider + Send + Sync + Clone,
        &'static [String],
        &'static [RegionalRates],
        &'static [GBRateCard],
        JobId,
    )>,
    Query(query): Query<GetIPRequest>,
) -> HandlerResult<Json<GetIPResponse>> {
    if query.id.is_none() || query.region.is_none() {
        return Err(Error::GetIPFail);
    }

    let client = &state.0;

    let ip = client
        .get_job_ip(
            &JobId {
                id: query.id.unwrap(),
                operator: state.4.operator,
                contract: state.4.contract,
                chain: state.4.chain,
            },
            &query.region.unwrap(),
        )
        .await;

    if ip.is_err() {
        return Err(Error::GetIPFail);
    }
    let ip = ip.unwrap().to_string();
    let ip = GetIPResponse { ip };

    Ok(Json(ip))
}

async fn handle_spec_request(
    State(state): State<(
        impl InfraProvider + Send + Sync + Clone,
        &'static [String],
        &'static [RegionalRates],
        &'static [GBRateCard],
        JobId,
    )>,
) -> HandlerResult<Json<SpecResponse>> {
    let regions = state.1;
    let rates = state.2;

    let res = SpecResponse {
        allowed_regions: regions,
        min_rates: rates,
    };

    Ok(Json(res))
}

async fn handle_bandwidth_request(
    State(state): State<(
        impl InfraProvider + Send + Sync + Clone,
        &'static [String],
        &'static [RegionalRates],
        &'static [GBRateCard],
        JobId,
    )>,
) -> HandlerResult<Json<BandwidthResponse>> {
    let bandwidth = state.3;
    let res = BandwidthResponse {
        rates: bandwidth.to_owned(),
    };

    Ok(Json(res))
}

fn all_routes(
    state: (
        impl InfraProvider + Send + Sync + Clone + 'static,
        &'static [String],
        &'static [RegionalRates],
        &'static [GBRateCard],
        JobId,
    ),
) -> Router {
    Router::new()
        .route("/ip", get(handle_ip_request))
        .route("/spec", get(handle_spec_request))
        .route("/bandwidth", get(handle_bandwidth_request))
        .with_state(state)
}

pub async fn serve(
    client: impl InfraProvider + Send + Sync + Clone + 'static,
    regions: &'static [String],
    rates: &'static [RegionalRates],
    bandwidth: &'static [GBRateCard],
    addr: SocketAddr,
    job_id: JobId,
) {
    let state = (client, regions, rates, bandwidth, job_id);

    let router = all_routes(state);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    info!(addr = addr.to_string(), "Listening for connections");
    axum::serve(listener, router).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::serve;

    use std::net::SocketAddr;

    use alloy::hex::ToHexExt;
    use alloy::primitives::U256;
    use anyhow;
    use serde_json::json;

    use crate::market::{GBRateCard, JobId, RateCard, RegionalRates};
    use crate::test::{InstanceMetadata, TestAws};

    #[tokio::test]
    async fn test_get_ip_happy_case() -> anyhow::Result<()> {
        let mut aws: TestAws = Default::default();

        for id in 1..4 {
            let temp_job_id = U256::from(id).to_be_bytes::<32>().encode_hex_with_prefix();
            let instance_metadata = InstanceMetadata::new(0).await;

            aws.instances
                .insert(temp_job_id.clone(), instance_metadata.clone());
        }

        let regions: &'static [String] =
            Box::leak(vec![String::from("ap-south-1")].into_boxed_slice());
        let compute_rates: &'static [RegionalRates] = Box::leak(vec![].into_boxed_slice());
        let bandwidth_rates: &'static [GBRateCard] = Box::leak(vec![].into_boxed_slice());
        let port = 8081;

        let job_id = U256::from(1).to_be_bytes::<32>().encode_hex_with_prefix();

        tokio::spawn(serve(
            aws.clone(),
            regions,
            compute_rates,
            bandwidth_rates,
            SocketAddr::from(([0, 0, 0, 0], port)),
            JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
        ));

        let hc = httpc_test::new_client(format!("http://localhost:{}", port))?;

        let res = hc
            .do_get(&format!("/ip?id={}&region=ap-south-1", job_id))
            .await?;
        assert_eq!(res.status(), 200);

        let body = res.json_body();
        assert!(body.is_ok());

        let body = body.unwrap();
        let ip = body.get("ip");
        assert!(ip.is_some());

        let ip = ip.unwrap();

        let actual_ip = &aws.instances.get_key_value(&job_id).unwrap().1.ip_address;
        assert_eq!(ip, actual_ip);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_ip_bad_case() -> anyhow::Result<()> {
        let mut aws: TestAws = Default::default();

        for id in 1..4 {
            let temp_job_id = U256::from(id).to_be_bytes::<32>().encode_hex_with_prefix();
            let instance_metadata = InstanceMetadata::new(0).await;

            aws.instances
                .insert(temp_job_id.clone(), instance_metadata.clone());
        }

        let regions: &'static [String] =
            Box::leak(vec![String::from("ap-south-1")].into_boxed_slice());
        let compute_rates: &'static [RegionalRates] = Box::leak(vec![].into_boxed_slice());
        let bandwidth_rates: &'static [GBRateCard] = Box::leak(vec![].into_boxed_slice());
        let port = 8082;

        let job_id = U256::from(5).to_be_bytes::<32>().encode_hex_with_prefix();

        tokio::spawn(serve(
            aws.clone(),
            regions,
            compute_rates,
            bandwidth_rates,
            SocketAddr::from(([0, 0, 0, 0], port)),
            JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
        ));

        let hc = httpc_test::new_client(format!("http://localhost:{}", port))?;

        let res = hc
            .do_get(&format!("/ip?id={}&region=ap-south-1", job_id))
            .await?;
        assert_eq!(res.status(), 400);

        let body = res.json_body();
        assert!(body.is_err());

        let body = res.text_body();
        assert!(body.is_ok());

        let err_message = body.unwrap();
        assert_eq!(err_message, "BAD_REQUEST");

        Ok(())
    }

    #[tokio::test]
    async fn test_get_ip_bad_case_no_instances() -> anyhow::Result<()> {
        let aws: TestAws = Default::default();
        let regions: &'static [String] =
            Box::leak(vec![String::from("ap-south-1")].into_boxed_slice());
        let compute_rates: &'static [RegionalRates] = Box::leak(vec![].into_boxed_slice());
        let bandwidth_rates: &'static [GBRateCard] = Box::leak(vec![].into_boxed_slice());
        let port = 8083;

        let job_id = U256::from(1).to_be_bytes::<32>().encode_hex_with_prefix();

        tokio::spawn(serve(
            aws.clone(),
            regions,
            compute_rates,
            bandwidth_rates,
            SocketAddr::from(([0, 0, 0, 0], port)),
            JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
        ));

        let hc = httpc_test::new_client(format!("http://localhost:{}", port))?;

        let res = hc.do_get("/spec").await?;
        assert_eq!(res.status(), 200);

        let body = res.json_body();
        assert!(body.is_ok());

        let res = hc
            .do_get(&format!("/ip?id={}&region=ap-south-1", job_id))
            .await?;
        assert_eq!(res.status(), 400);

        let body = res.json_body();
        assert!(body.is_err());

        let body = res.text_body();
        assert!(body.is_ok());

        let err_message = body.unwrap();
        assert_eq!(err_message, "BAD_REQUEST");

        Ok(())
    }

    #[tokio::test]
    async fn test_handle_spec_request() -> anyhow::Result<()> {
        let aws: TestAws = Default::default();
        let regions: &'static [String] =
            Box::leak(vec![String::from("ap-south-1")].into_boxed_slice());
        let compute_rates: &'static [RegionalRates] = Box::leak(
            vec![RegionalRates {
                region: String::from("ap-south-1"),
                rate_cards: vec![
                    RateCard {
                        instance: String::from("m5a.16xlarge"),
                        min_rate: U256::from(810833333333333_i64),
                        cpu: 64,
                        memory: 256,
                        arch: String::from("amd64"),
                    },
                    RateCard {
                        instance: String::from("c6g.16xlarge"),
                        min_rate: U256::from(640722222222222_i64),
                        cpu: 64,
                        memory: 128,
                        arch: String::from("arm64"),
                    },
                    RateCard {
                        instance: String::from("c6i.4xlarge"),
                        min_rate: U256::from(207777777777777_i64),
                        cpu: 16,
                        memory: 32,
                        arch: String::from("amd64"),
                    },
                ],
            }]
            .into_boxed_slice(),
        );

        let bandwidth_rates: &'static [GBRateCard] = Box::leak(vec![].into_boxed_slice());
        let port = 8084;

        let job_id = U256::from(1).to_be_bytes::<32>().encode_hex_with_prefix();

        tokio::spawn(serve(
            aws.clone(),
            regions,
            compute_rates,
            bandwidth_rates,
            SocketAddr::from(([0, 0, 0, 0], port)),
            JobId {
                id: job_id,
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
        ));

        let hc = httpc_test::new_client(format!("http://localhost:{}", port))?;

        let res = hc.do_get("/spec").await?;
        assert_eq!(res.status(), 200);

        let body = res.json_body();
        assert!(body.is_ok());

        let body = json!(body.unwrap());
        let body: Vec<RegionalRates> =
            serde_json::from_value(body.get("min_rates").unwrap().clone()).unwrap();

        assert_eq!(body, compute_rates);

        Ok(())
    }

    #[tokio::test]
    async fn test_handle_bandwidth_request() -> anyhow::Result<()> {
        let aws: TestAws = Default::default();
        let regions: &'static [String] =
            Box::leak(vec![String::from("ap-south-1")].into_boxed_slice());
        let compute_rates: &'static [RegionalRates] = Box::leak(vec![].into_boxed_slice());

        let bandwidth_rates: &'static [GBRateCard] = Box::leak(
            vec![
                GBRateCard {
                    region: String::from("US East (Ohio)"),
                    region_code: String::from("us-east-2"),
                    rate: U256::from(90000000000000000_i64),
                },
                GBRateCard {
                    region: String::from("US East (N. Virginia)"),
                    region_code: String::from("us-east-1"),
                    rate: U256::from(90000000000000000_i64),
                },
                GBRateCard {
                    region: String::from("US West (N. California)"),
                    region_code: String::from("us-west-1"),
                    rate: U256::from(90000000000000000_i64),
                },
            ]
            .into_boxed_slice(),
        );
        let port = 8085;

        let job_id = U256::from(1).to_be_bytes::<32>().encode_hex_with_prefix();

        tokio::spawn(serve(
            aws.clone(),
            regions,
            compute_rates,
            bandwidth_rates,
            SocketAddr::from(([0, 0, 0, 0], port)),
            JobId {
                id: job_id,
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
        ));

        let hc = httpc_test::new_client(format!("http://localhost:{}", port))?;

        let res = hc.do_get("/bandwidth").await?;
        assert_eq!(res.status(), 200);

        let body = res.json_body();
        assert!(body.is_ok());

        let body = json!(body.unwrap());
        let body: Vec<GBRateCard> =
            serde_json::from_value(body.get("rates").unwrap().clone()).unwrap_or_default();

        assert_eq!(body, bandwidth_rates);

        Ok(())
    }
}
