mod current_usage;
mod scheduled_tasks;
mod service_quotas;
mod utils;

use anyhow::{anyhow, Context, Result};
use aws_types::region::Region;
use clap::{Parser, Subcommand};

#[derive(Parser, Clone)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    // get usage and limit of specific quotas in specific regions
    Usage {
        #[clap(long, value_parser = utils::Quota::from_name, num_args = 1.., value_delimiter = ',', default_value = "vcpus,eips")]
        quotas: Vec<utils::Quota>,

        #[clap(
            long,
            value_parser,
            num_args = 1..,
            value_delimiter = ',',
            default_value = "us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,sa-east-1,eu-north-1,eu-west-3,eu-west-2,eu-west-1,eu-central-1,eu-central-2,eu-south-1,eu-south-2,me-south-1,me-central-1,af-south-1,ap-south-1,ap-south-2,ap-northeast-1,ap-northeast-2,ap-northeast-3,ap-southeast-1,ap-southeast-2,ap-southeast-3,ap-southeast-4,ap-east-1",
        )]
        regions: Vec<String>,

        #[clap(long, value_parser)]
        profile: String,
    },
    // get statuses of requests of specific quotas in specific regions
    Requests {
        #[clap(long, value_parser = utils::Quota::from_name, num_args = 1.., value_delimiter = ',', default_value = "vcpus,eips")]
        quotas: Vec<utils::Quota>,

        #[clap(
            long,
            value_parser,
            num_args = 1..,
            value_delimiter = ',',
            default_value = "us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,sa-east-1,eu-north-1,eu-west-3,eu-west-2,eu-west-1,eu-central-1,eu-central-2,eu-south-1,eu-south-2,me-south-1,me-central-1,af-south-1,ap-south-1,ap-south-2,ap-northeast-1,ap-northeast-2,ap-northeast-3,ap-southeast-1,ap-southeast-2,ap-southeast-3,ap-southeast-4,ap-east-1",
        )]
        regions: Vec<String>,

        #[clap(long, value_parser)]
        profile: String,
    },
}

// async fn limit_increase(quota_name: &str, quota_value: f64, config: &SdkConfig) {
//     let quota_code = utils::map_quota_to_code(quota_name);
//     if quota_code.is_none() {
//         eprintln!("Quota name must be one of these:\n1. vcpu\n2. elastic_ip");
//         return;
//     }
//
//     if quota_value == 0.0 {
//         eprintln!("Quota value must be greater than 0.0");
//         return;
//     }
//
//     match service_quotas::request_service_quota_increase(
//         config,
//         utils::EC2_SERVICE_CODE.to_string(),
//         quota_code.unwrap(),
//         quota_value,
//     )
//     .await
//     {
//         Ok(id) => {
//             println!(
//                 "Request ID: {}\nQuota Name: {}\nQuota Value: {}\nTime: {}\n\n",
//                 id,
//                 quota_name,
//                 quota_value,
//                 Local::now().format("%Y-%m-%d %H:%M:%S")
//             );
//
//             println!("Service quota increase requested!");
//             println!("Request ID: {}", id);
//         }
//         Err(err) => eprintln!("Failed to request limit increase: {}", err),
//     }
// }
//
// async fn schedule_monitoring(cli: Cli, region: String) {
//     let config = aws_config::from_env()
//         .profile_name(cli.aws_profile.as_str())
//         .region(Region::new(region))
//         .load()
//         .await;
//
//     let mut vcpu_request_id = scheduled_tasks::get_id(&config, utils::VCPU_QUOTA_NAME).await;
//     let mut elastic_ip_request_id =
//         scheduled_tasks::get_id(&config, utils::ELASTIC_IP_QUOTA_NAME).await;
//
//     let interval_duration = Duration::from_secs(cli.monitor_interval_secs);
//     let mut interval = interval(interval_duration);
//
//     loop {
//         interval.tick().await;
//
//         vcpu_request_id = scheduled_tasks::request_monitor(
//             &config,
//             vcpu_request_id,
//             utils::VCPU_QUOTA_NAME,
//             cli.no_update_days_threshold,
//         )
//         .await;
//         elastic_ip_request_id = scheduled_tasks::request_monitor(
//             &config,
//             elastic_ip_request_id,
//             utils::ELASTIC_IP_QUOTA_NAME,
//             cli.no_update_days_threshold,
//         )
//         .await;
//
//         vcpu_request_id = scheduled_tasks::usage_monitor(
//             &config,
//             vcpu_request_id,
//             utils::VCPU_QUOTA_NAME,
//             cli.vcpu_usage_threshold_percent,
//             cli.vcpu_quota_increment_percent,
//         )
//         .await;
//         elastic_ip_request_id = scheduled_tasks::usage_monitor(
//             &config,
//             elastic_ip_request_id,
//             utils::ELASTIC_IP_QUOTA_NAME,
//             cli.elastic_ip_usage_threshold_percent,
//             cli.elastic_ip_quota_increment_percent,
//         )
//         .await;
//     }
// }

async fn get_quota_status(
    ec2_client: &aws_sdk_ec2::Client,
    sq_client: &aws_sdk_servicequotas::Client,
    quota: &utils::Quota,
    region: &str,
) -> Result<(usize, usize)> {
    let current_usage = current_usage::get_current_usage(ec2_client, quota)
        .await
        .with_context(|| format!("failed to get current usage of {quota} in {region}"))?;

    let quota_limit = service_quotas::get_service_quota_limit(sq_client, quota)
        .await
        .with_context(|| format!("failed to get quota limit of {quota} in {region}"))?;

    Ok((current_usage, quota_limit))
}

async fn quota_status(quota: &utils::Quota, region: &str, aws_profile: &str) -> Result<()> {
    let config = aws_config::from_env()
        .profile_name(aws_profile)
        .region(Region::new(region.to_owned()))
        .load()
        .await;

    let ec2_client = aws_sdk_ec2::Client::new(&config);
    let sq_client = aws_sdk_servicequotas::Client::new(&config);

    let (current_usage, quota_limit) =
        get_quota_status(&ec2_client, &sq_client, quota, region).await?;

    println!("{region}:\t{quota}:\t{current_usage}/{quota_limit}");

    Ok(())
}

#[derive(Debug)]
enum RequestStatus {
    None,
    Unnecessary,
    Open,
    Stuck,
    Approved,
    Rejected,
}

async fn get_request_status(
    sq_client: &aws_sdk_servicequotas::Client,
    quota: &utils::Quota,
    region: &str,
) -> Result<RequestStatus> {
    let Some(last_request) = service_quotas::last_request(sq_client, quota)
        .await
        .with_context(|| format!("failed to get last request of {quota} in {region}"))?
    else {
        return Ok(RequestStatus::None);
    };

    let quota_limit = service_quotas::get_service_quota_limit(sq_client, quota)
        .await
        .with_context(|| format!("failed to get quota limit of {quota} in {region}"))?;

    let too_old = last_request
        .created
        .ok_or(anyhow!(
            "failed to get creation time of request {} while processing {quota} in {region}",
            last_request.id.clone().unwrap_or("unknown id".to_owned())
        ))?
        .secs()
        < chrono::Local::now().timestamp() - 86400;

    let is_needed = (last_request.desired_value.ok_or(anyhow!(
        "failed to get desired value of request {} while processing {quota} in {region}",
        last_request.id.clone().unwrap_or("unknown id".to_owned())
    ))? as usize)
        > quota_limit;

    let status = last_request.status.ok_or(anyhow!(
        "failed to get status of request {} while processing {quota} in {region}",
        last_request.id.unwrap_or("unknown id".to_owned())
    ))?;
    let is_open = status == aws_sdk_servicequotas::types::RequestStatus::CaseOpened
        || status == aws_sdk_servicequotas::types::RequestStatus::Pending;

    Ok(match (is_needed, is_open) {
        (true, true) => {
            if too_old {
                RequestStatus::Stuck
            } else {
                RequestStatus::Open
            }
        }
        (true, false) => RequestStatus::Rejected,
        (false, true) => RequestStatus::Unnecessary,
        (false, false) => RequestStatus::Approved,
    })
}

async fn request_status(quota: &utils::Quota, region: &str, aws_profile: &str) -> Result<()> {
    let config = aws_config::from_env()
        .profile_name(aws_profile)
        .region(Region::new(region.to_owned()))
        .load()
        .await;

    let sq_client = aws_sdk_servicequotas::Client::new(&config);

    let status = get_request_status(&sq_client, quota, region).await?;

    println!("{region}:\t{quota}:\t{status:?}");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Usage {
            quotas,
            regions,
            profile,
        } => {
            for region in regions {
                for quota in quotas.as_slice() {
                    quota_status(quota, &region, &profile).await?;
                }
            }
        }
        Commands::Requests {
            quotas,
            regions,
            profile,
        } => {
            for region in regions {
                for quota in quotas.as_slice() {
                    request_status(quota, &region, &profile).await?;
                }
            }
        }
    };

    Ok(())
}
