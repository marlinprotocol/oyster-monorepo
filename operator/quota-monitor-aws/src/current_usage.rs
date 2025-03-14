use crate::utils;

use anyhow::{anyhow, Context, Result};
use aws_sdk_ec2::types::Filter;

pub async fn get_current_usage(
    client: &aws_sdk_ec2::Client,
    quota: &utils::Quota,
) -> Result<usize> {
    use utils::Quota::*;
    match quota {
        Vcpu => get_no_of_vcpus(client).await,
        Eip => get_no_of_elastic_ips(client).await,
    }
}

async fn get_no_of_vcpus(client: &aws_sdk_ec2::Client) -> Result<usize> {
    let res = client
        .describe_instances()
        .filters(
            Filter::builder()
                .name("instance-state-name")
                .values("running")
                .build(),
        )
        .send()
        .await
        .context("Error occurred while describing instances from AWS client")?;
    let reservations = res
        .reservations()
        .ok_or(anyhow!("Could not parse reservations from AWS response"))?;

    let mut no_of_vcpus = 0;

    for reservation in reservations {
        let instances = reservation
            .instances()
            .ok_or(anyhow!("Could not parse instances from reservation"))?;

        for instance in instances {
            let cpu_options = instance
                .cpu_options()
                .ok_or(anyhow!("Could not parse cpu options from instance"))?;

            no_of_vcpus += (cpu_options
                .core_count()
                .ok_or(anyhow!("Could not parse core count from cpu options"))?)
                as usize
                * (cpu_options
                    .threads_per_core()
                    .ok_or(anyhow!("Could not parse threads per core from cpu options"))?)
                    as usize;
        }
    }

    Ok(no_of_vcpus)
}

async fn get_no_of_elastic_ips(client: &aws_sdk_ec2::Client) -> Result<usize> {
    Ok(client
        .describe_addresses()
        .send()
        .await
        .context("Error occurred while describing addresses from AWS client")?
        .addresses()
        .ok_or(anyhow!("Could not parse addresses from AWS response"))?
        .len() as usize)
}
