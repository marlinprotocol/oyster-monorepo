pub struct BandwidthUnit {
    pub id: &'static str,
    pub value: u64,
}

pub const OYSTER_BANDWIDTH_UNITS_LIST: [BandwidthUnit; 3] = [
    BandwidthUnit {
        id: "kbps",
        value: 1024 * 1024,
    },
    BandwidthUnit {
        id: "mbps",
        value: 1024,
    },
    BandwidthUnit {
        id: "gbps",
        value: 1,
    },
];

pub struct BandwidthRate {
    pub region_code: &'static str,
    pub rate: u64,
}

fn create_bandwidth_rates() -> [BandwidthRate; 27] {
    [
        BandwidthRate {
            region_code: "us-east-1",
            rate: 90_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "us-east-2",
            rate: 90_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "us-west-1",
            rate: 90_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "us-west-2",
            rate: 90_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "ca-central-1",
            rate: 90_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "sa-east-1",
            rate: 150_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "eu-north-1",
            rate: 90_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "eu-west-3",
            rate: 90_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "eu-west-2",
            rate: 90_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "eu-west-1",
            rate: 90_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "eu-central-1",
            rate: 90_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "eu-central-2",
            rate: 90_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "eu-south-1",
            rate: 90_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "eu-south-2",
            rate: 90_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "me-south-1",
            rate: 117_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "me-central-1",
            rate: 110_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "af-south-1",
            rate: 154_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "ap-south-1",
            rate: 109_300_000_000_000_000,
        },
        BandwidthRate {
            region_code: "ap-south-2",
            rate: 109_300_000_000_000_000,
        },
        BandwidthRate {
            region_code: "ap-northeast-1",
            rate: 114_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "ap-northeast-2",
            rate: 126_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "ap-northeast-3",
            rate: 114_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "ap-southeast-1",
            rate: 120_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "ap-southeast-2",
            rate: 114_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "ap-southeast-3",
            rate: 132_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "ap-southeast-4",
            rate: 114_000_000_000_000_000,
        },
        BandwidthRate {
            region_code: "ap-east-1",
            rate: 120_000_000_000_000_000,
        },
    ]
}

lazy_static::lazy_static! {
    pub static ref BANDWIDTH_RATES: [BandwidthRate; 27] = create_bandwidth_rates();
}

pub fn get_bandwidth_rate_for_region(region_code: &str) -> u64 {
    BANDWIDTH_RATES
        .iter()
        .find(|&rate| rate.region_code == region_code)
        .map(|rate| rate.rate)
        .unwrap_or(0)
}

pub fn calculate_bandwidth_cost(
    bandwidth: &str,
    bandwidth_unit: &str,
    bandwidth_rate_for_region_scaled: u64,
    duration: u64,
) -> u64 {
    let unit_conversion_divisor = OYSTER_BANDWIDTH_UNITS_LIST
        .iter()
        .find(|unit| unit.id == bandwidth_unit)
        .map(|unit| unit.value)
        .unwrap_or(1);

    let bandwidth_u64 = bandwidth.parse::<u64>().unwrap();

    ((bandwidth_u64 as u128) * (bandwidth_rate_for_region_scaled as u128) * (duration as u128)
        / (unit_conversion_divisor as u128)) as u64
}
