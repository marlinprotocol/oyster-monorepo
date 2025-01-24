import { ethers, upgrades } from "hardhat";

async function main() {
    // NOTE: Admin address same as address deploying the contracts, configured in environment file
    let signers = await ethers.getSigners();
    let admin_addr = await signers[0].getAddress();

    // POND Token Contract
    let staking_token_addr = "0xdA0a57B710768ae17941a9Fa33f8B720c8bD9ddD";
    console.log("Pond Deployed address: ", staking_token_addr);

    // USDC Token Contract
    let usdc_token_addr = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831";
    console.log("USDCoin Deployed address: ", usdc_token_addr);

    // Attestation Verifier
    let av_addr = "0x778c1AdeaB57DD4B5b930bbdB8c892F8d2606228";
    console.log("AttestationVerifier Deployed address: ", av_addr);

    const signMaxAge = 600;

    let overallTimeout = 570;
    let epochInterval = 60;

    // Common Chain Gateways Contract
    const Gateways = await ethers.getContractFactory("Gateways");
    console.log("Deploying Gateways...")
    let gatewayInitArgs = [
        av_addr,
        signMaxAge,
        staking_token_addr,
        epochInterval + overallTimeout,
        100, // 0.01 % // TODO
        1000000
    ];
    let gatewaysContract = await upgrades.deployProxy(
        Gateways,
        [
            admin_addr,
            []
        ],
        {
            initializer : "initialize",
            kind : "uups",
            constructorArgs : gatewayInitArgs,
        });

    let gatewaysAddress = gatewaysContract.target;
    console.log("Gateways Deployed address: ", gatewaysAddress);
    console.log("Gateways Init Args:\n", gatewayInitArgs);
    
    // Common Chain Executors Contract
    let minStake = 10n**18n;
    const Executors = await ethers.getContractFactory("Executors");
    let executorsInitArgs = [
        av_addr,
        signMaxAge,
        staking_token_addr,
        minStake,
        100, // 0.01 % // TODO
        1000000
    ];
    console.log("Deploying Executors...")
    let executorsContract = await upgrades.deployProxy(
        Executors,
        [
            admin_addr,
            []
        ],
        {
            initializer : "initialize",
            kind : "uups",
            constructorArgs : executorsInitArgs,
        });
    let executorsAddress = executorsContract.target;
    console.log("Executors Deployed address: ", executorsAddress);
    console.log("Executor Init Args:\n", executorsInitArgs);

    // Common Chain Jobs Contract
    let executionBufferTime = 60,
        noOfNodesToSelect = 3;

    const stakingPaymentPoolAddress = await signers[0].getAddress();
    const usdcPaymentPoolAddress = await signers[0].getAddress();
        
    const Jobs = await ethers.getContractFactory("Jobs");
    let jobsInitArgs = [
        staking_token_addr,
        usdc_token_addr,
        signMaxAge,
        executionBufferTime,
        noOfNodesToSelect,
        stakingPaymentPoolAddress,
        usdcPaymentPoolAddress,
        executorsAddress
    ];
    console.log("Deploying Jobs...")
    let jobsContract = await upgrades.deployProxy(
        Jobs,
        [
            admin_addr,
        ],
        {
            initializer : "initialize",
            kind : "uups",
            constructorArgs: jobsInitArgs,
        });
    let jobsAddress = jobsContract.target;
    console.log("Jobs Deployed address: ", jobsAddress);
    console.log("Jobs Init Args:\n", jobsInitArgs);

    await executorsContract.grantRole(await executorsContract.JOBS_ROLE(), jobsAddress);
    console.log("Executor's jobs role granted to Jobs Contract");
    
    // Common Chain Gateway Jobs Contract
    let relayBufferTime = 210;
    let slashCompForGateway = 10n**14n; // 0.0001 POND // TODO
    let reassignCompForReporterGateway = 10n**14n; // 0.0001 POND // TODO
    const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
    let gatewayJobsInitArgs = [
        staking_token_addr,
        usdc_token_addr,
        signMaxAge,
        relayBufferTime,
        slashCompForGateway,
        reassignCompForReporterGateway,
        jobsAddress,
        gatewaysAddress,
        stakingPaymentPoolAddress
    ];
    console.log("Deploying GatewayJobs...")
    let gatewayJobs = await upgrades.deployProxy(
        GatewayJobs,
        [
            admin_addr
        ],
        {
            initializer : "initialize",
            kind : "uups",
            constructorArgs : gatewayJobsInitArgs,
        });
    let gatewayJobsAddress = gatewayJobs.target;
    console.log("GatewayJobs Deployed address: ", gatewayJobsAddress);
    console.log("GatewayJobs Init Args:\n", gatewayInitArgs);
    await gatewaysContract.grantRole(await gatewaysContract.GATEWAY_JOBS_ROLE(), gatewayJobsAddress);
    console.log("Gateway's gateway jobs role granted to Gateway Jobs contract");

}

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });