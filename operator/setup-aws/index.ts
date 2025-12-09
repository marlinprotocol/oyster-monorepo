import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";


let nidx = 192;

let tags = {
    manager: "pulumi",
    project: `oyster`,
}

let regions: aws.Region[] = [
    // "us-east-1",
    // "us-east-2",
    // "us-west-1",
    // "us-west-2",
    // "ca-central-1",
    // "sa-east-1",
    // "eu-north-1",
    // "eu-west-3",
    // "eu-west-2",
    // "eu-west-1",
    // "eu-central-1",
    // "eu-central-2",
    // "eu-south-1",
    // "eu-south-2",
    // "me-south-1",
    // "me-central-1",
    // "af-south-1",
    // "ap-south-1",
    // "ap-south-2",
    // "ap-northeast-1",
    // "ap-northeast-2",
    // "ap-northeast-3",
    // "ap-southeast-1",
    "ap-southeast-2",
    // "ap-southeast-3",
    // "ap-southeast-4",
    // "ap-east-1",
]

let providers: { [key: string]: aws.Provider } = {}
export let publicDNS: aws.route53.Zone;
let vpcs: { [key: string]: aws.ec2.Vpc } = {}
let subnets: { [key: string]: aws.ec2.Subnet } = {}
let igs: { [key: string]: aws.ec2.InternetGateway } = {}
let rts: { [key: string]: aws.ec2.RouteTable } = {}
let rtas: { [key: string]: aws.ec2.RouteTableAssociation } = {}
let sgs: { [key: string]: { [key: string]: aws.ec2.SecurityGroup } } = {}
let enis: { [key: string]: aws.ec2.NetworkInterface } = {}
let instances: { [key: string]: aws.ec2.Instance } = {}
let eips: { [key: string]: aws.ec2.Eip } = {}


regions.forEach((region, ridx) => {
    // providers
    providers[region] = new aws.Provider(region, {
        region: region,
        profile: new pulumi.Config('aws').get("profile"),
    })

    let keyPair = new aws.ec2.KeyPair(`${tags.project}`, {
        keyName: `${tags.project}`,
        publicKey: new pulumi.Config().require(`oysterPubKey`),
    }, {
        provider: providers[region],
    })

    // vpcs
    vpcs[region] = new aws.ec2.Vpc(`${tags.project}-${region}-vpc`, {
        cidrBlock: `10.${nidx}.${2 * ridx}.0/23`,
        enableDnsHostnames: true,
        enableDnsSupport: true,
        tags: tags,
    }, {
        provider: providers[region],
    })

    // oyster cvm subnets
    subnets[`${region}-cvm`] = new aws.ec2.Subnet(`${tags.project}-${region}-cvm`, {
        cidrBlock: `10.${nidx}.${2 * ridx}.0/24`,
        mapPublicIpOnLaunch: false,
        tags: {...tags, ...{type: "cvm"}},
        vpcId: vpcs[region].id,
    }, {
        provider: providers[region],
    });

    // rate limiter subnet
    subnets[`${region}-rl`] = new aws.ec2.Subnet(`${tags.project}-${region}-rl`, {
        cidrBlock: `10.${nidx}.${2 * ridx + 1}.0/24`,
        mapPublicIpOnLaunch: false,
        tags: {...tags, ...{type: "rate-limiter"}},
        vpcId: vpcs[region].id,
    }, {
        provider: providers[region],
    });

    // internet gateways
    igs[region] = new aws.ec2.InternetGateway(`${tags.project}-${region}-ig`, {
        vpcId: vpcs[region].id,
        tags: tags,
    }, {
        provider: providers[region],
    });

    // route table cvm
    rts[`${region}-cvm`] = new aws.ec2.RouteTable(`${tags.project}-${region}-rt-cvm`, {
        vpcId: vpcs[region].id,
        tags: tags,
    }, {
        provider: providers[region],
    });

    // route table associations
    rtas[`${region}-cvm`] = new aws.ec2.RouteTableAssociation(`${tags.project}-${region}-cvm-rta`, {
        subnetId: subnets[`${region}-cvm`].id,
        routeTableId: rts[`${region}-cvm`].id,
    }, {
        provider: providers[region],
    });

    rts[`${region}-rl`] = new aws.ec2.RouteTable(`${tags.project}-${region}-rt-rl`, {
        vpcId: vpcs[region].id,
        tags: tags,
    }, {
        provider: providers[region],
    });

    // rate limiter internet route
    new aws.ec2.Route(`${tags.project}-${region}-rl-ig-route`, {
        routeTableId: rts[`${region}-rl`].id,
        destinationCidrBlock: "0.0.0.0/0",
        gatewayId: igs[region].id,
    }, {
        provider: providers[region],
    });

    rtas[`${region}-rl`] = new aws.ec2.RouteTableAssociation(`${tags.project}-${region}-rl-rta`, {
        subnetId: subnets[`${region}-rl`].id,
        routeTableId: rts[`${region}-rl`].id,
    }, {
        provider: providers[region],
    });

    // security groups
    sgs[region] = {}
    sgs[region].oyster_cvm = new aws.ec2.SecurityGroup(`${tags.project}-${region}-oyster-cvm`, {
        vpcId: vpcs[region].id,
        egress: [{
            cidrBlocks: ['0.0.0.0/0'],
            fromPort: 0,
            toPort: 0,
            protocol: "-1",
        }],
        ingress: [{
            cidrBlocks: ['0.0.0.0/0'],
            fromPort: 0,
            toPort: 0,
            protocol: "-1",
        }],
        tags: tags,
    }, {
        provider: providers[region],
    });

    sgs[region].oyster_rate_limiter = new aws.ec2.SecurityGroup(`${tags.project}-${region}-oyster-rate-limiter`, {
        vpcId: vpcs[region].id,
        egress: [{
            cidrBlocks: ['0.0.0.0/0'],
            fromPort: 0,
            toPort: 0,
            protocol: "-1",
        }],
        ingress: [{
            cidrBlocks: ['0.0.0.0/0'],
            fromPort: 0,
            toPort: 0,
            protocol: "-1",
        }],
        tags: tags,
    }, {
        provider: providers[region],
    });

    // Rate limiter instance with multiple IPs
    // Get the number of ENIs required based on instance type
    // Using c6a.xlarge which supports 4 ENIs
    for (let eniIdx = 0; eniIdx < 4; eniIdx++) {
        enis[`${region}-rl-eni-${eniIdx}`] = new aws.ec2.NetworkInterface(`${tags.project}-${region}-rl-eni-${eniIdx}`, {
            subnetId: subnets[`${region}-rl`].id,
            securityGroups: [sgs[region].oyster_rate_limiter.id],
            sourceDestCheck: false,
            tags: tags,
        }, {
            provider: providers[region],
        });
    }

    eips[`${region}-rl-eip`] = new aws.ec2.Eip(`${tags.project}-${region}-rl-eip`, {
        networkInterface: enis[`${region}-rl-eni-0`].id,
        tags: tags,
    }, {
        provider: providers[region],
    });

    const ami = aws.ec2.getAmi({
        filters: [
            { name: "name", values: ["marlin/oyster/worker-rate-limiter-amd64*"] },
        ],
        owners: ["self"],
        mostRecent: true,
    }, { provider: providers[region] }).then(ami => ami.id );

    // cvm internet route
    new aws.ec2.Route(`${tags.project}-${region}-ig-route`, {
        routeTableId: rts[`${region}-cvm`].id,
        destinationCidrBlock: "0.0.0.0/0",
        networkInterfaceId: enis[`${region}-rl-eni-0`].id,
    }, {
        provider: providers[region],
    })

    instances[`${region}-rl`] = new aws.ec2.Instance(`${tags.project}-${region}-rl-instance`, {
        ami: ami,
        instanceType: "c6a.xlarge",
        networkInterfaces: [
            {
                deviceIndex: 0,
                networkInterfaceId: enis[`${region}-rl-eni-0`].id,
            },
            {
                deviceIndex: 1,
                networkInterfaceId: enis[`${region}-rl-eni-1`].id,
            },
            {
                deviceIndex: 2,
                networkInterfaceId: enis[`${region}-rl-eni-2`].id,
            },
            {
                deviceIndex: 3,
                networkInterfaceId: enis[`${region}-rl-eni-3`].id,
            },
        ],
        keyName: keyPair.keyName,
        tags: {...tags, ...{type: "rate-limiter"}},
    }, {
        provider: providers[region],
    });
})
