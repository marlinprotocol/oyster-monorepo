import { ethers, upgrades } from "hardhat";

async function main() {
    // NOTE: Admin address same as address deploying the contracts, configured in environment file
    let signers = await ethers.getSigners();
    let admin_addr = await signers[0].getAddress();

    // USDC Token Contract
    let usdc_token_addr = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831";
    console.log("USDCoin Deployed address: ", usdc_token_addr);

    // Attestation Verifier
    let av_addr = "0x778c1AdeaB57DD4B5b930bbdB8c892F8d2606228";
    console.log("AttestationVerifier Deployed address: ", av_addr);

    // Request Chain Relay Contract
    const signMaxAge = 600;
    const gatewayFee = 100; // 0.1 usd // TODO
    let overallTimeout = 570;
    let minUserDeadline = 1000;
    let maxUserDeadline = 300000;
    let fixedGas = 150000;
    let callbackMeasureGas = 4530;
    const Relay = await ethers.getContractFactory("Relay");
    let relayInitArgs = [
        av_addr,
        signMaxAge,
        usdc_token_addr,
        minUserDeadline,
        maxUserDeadline,
        overallTimeout,
        gatewayFee,
        fixedGas,
        callbackMeasureGas
    ];
    console.log("Deploying Relay...")
    let relay = await upgrades.deployProxy(
        Relay,
        [
            admin_addr,
            []
        ],
        {
            initializer : "initialize",
            kind : "uups",
            constructorArgs : relayInitArgs,
        });
    let relay_addr = relay.target;
    console.log("Relay Deployed address: ", relay_addr);
    console.log("Relay Init Args:\n", relayInitArgs);

    // Request Chain Subscription Contract
    let minPeriodicGap = 30, // check product requirements
        maxPeriodicGap = 60 * 60 * 24 * 365,    // 1 year
        maxTerminationDuration = 60 * 60 * 24 * 365 * 5;    // 5 years
    const RelaySubscriptions = await ethers.getContractFactory("RelaySubscriptions");
    let relaySubInitArg = [
        relay_addr,
        minPeriodicGap,
        maxPeriodicGap,
        maxTerminationDuration
    ];
    console.log("Deploying RelaySubscriptions...")
    let relaySubscriptions = await upgrades.deployProxy(
        RelaySubscriptions,
        [
            admin_addr
        ],
        {
            initializer : "initialize",
            kind : "uups",
            constructorArgs : relaySubInitArg,
        });
    let relaySubscriptionsAddress = relaySubscriptions.target;
    console.log("RelaySubscriptions Deployed address: ", relaySubscriptionsAddress);
    console.log("RelaySubscriptions Init Args:\n", relaySubInitArg);
}

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });