// Deploys the Oyster Serverless contracts (serverless-v2) on a single chain,
// which is used as both the request chain and the common chain.
//
// Configuration is read from environment variables:
//   VERIFIER_PCR0, VERIFIER_PCR1, VERIFIER_PCR2  PCRs of the attestation verifier enclave image
//   VERIFIER_PUBKEY                              secp256k1 public key of the attestation verifier enclave
//                                                (64 bytes, hex, without the 04 prefix)
//   ATTESTATION_VERIFIER                         optional, existing AttestationVerifier, skips the two above
//   USDC_TOKEN, STAKING_TOKEN                    optional, existing tokens; test tokens are deployed if unset
//   HTTP_RPC_URL, WS_RPC_URL                     RPC urls of the chain, stored on chain for the gateways
//   NUM_SELECTED_EXECUTORS                       optional, executors selected per job (default 3)
//   OUT_FILE                                     optional, where to write the addresses (default deployment.json)
//
// Run with: npx hardhat run scripts/serverless/deploy.ts --network <network>

import { getBytes } from "ethers";
import { writeFileSync } from "fs";
import { ethers, network, upgrades } from "hardhat";

function env(name: string, fallback?: string): string {
    const value = process.env[name] ?? fallback;
    if (value === undefined) throw new Error(`${name} is not set`);
    return value;
}

async function main() {
    const signers = await ethers.getSigners();
    const admin = await signers[0].getAddress();
    const chainId = Number((await ethers.provider.getNetwork()).chainId);
    console.log(`Deploying on ${network.name} (chain id ${chainId}) from ${admin}`);

    const out: Record<string, any> = { chainId, admin };

    // Tokens
    let stakingToken = process.env.STAKING_TOKEN;
    if (stakingToken === undefined) {
        const Pond = await ethers.getContractFactory("Pond");
        const pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
        await pond.waitForDeployment();
        stakingToken = pond.target as string;
        console.log("Test POND:", stakingToken);
    }
    let usdcToken = process.env.USDC_TOKEN;
    if (usdcToken === undefined) {
        const USDCoin = await ethers.getContractFactory("USDCoin");
        const usdc = await upgrades.deployProxy(USDCoin, [admin], { kind: "uups" });
        await usdc.waitForDeployment();
        usdcToken = usdc.target as string;
        console.log("Test USDC:", usdcToken);
    }
    out.stakingToken = stakingToken;
    out.usdcToken = usdcToken;

    // Attestation verifier
    let attestationVerifier = process.env.ATTESTATION_VERIFIER;
    if (attestationVerifier === undefined) {
        const verifierImage = {
            PCR0: getBytes(env("VERIFIER_PCR0")),
            PCR1: getBytes(env("VERIFIER_PCR1")),
            PCR2: getBytes(env("VERIFIER_PCR2")),
        };
        const verifierKey = getBytes(env("VERIFIER_PUBKEY"));
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const av = await upgrades.deployProxy(AttestationVerifier, [[verifierImage], [verifierKey], admin], {
            kind: "uups",
        });
        await av.waitForDeployment();
        attestationVerifier = av.target as string;
        console.log("AttestationVerifier:", attestationVerifier);
    }
    out.attestationVerifier = attestationVerifier;

    // Parameters
    const execEnv = 1;
    const executorFeePerMs = 1; // in USDC units (6 decimals)
    const stakingRewardPerMs = 1;
    const gatewayFee = 100;
    const signMaxAge = 600;
    const overallTimeout = 120;
    const minUserDeadline = 1000;
    const maxUserDeadline = 50000;
    const fixedGas = 150000;
    const callbackMeasureGas = 4530;
    const epochInterval = 600;
    const minExecutorStake = 10n ** 18n;
    const executionBufferTime = 60;
    const numSelectedExecutors = Number(env("NUM_SELECTED_EXECUTORS", "3"));
    const relayBufferTime = 120;
    const paymentPool = admin;

    // Request chain
    const Relay = await ethers.getContractFactory("contracts/serverless-v2/Relay.sol:Relay");
    const relay = await upgrades.deployProxy(Relay, [admin, []], {
        kind: "uups",
        constructorArgs: [
            attestationVerifier, signMaxAge, usdcToken, minUserDeadline, maxUserDeadline,
            overallTimeout, gatewayFee, fixedGas, callbackMeasureGas,
        ],
    });
    await relay.waitForDeployment();
    out.relay = relay.target;
    console.log("Relay:", relay.target);
    await (await relay.addGlobalEnv(execEnv, executorFeePerMs + stakingRewardPerMs)).wait();

    const RelaySubscriptions = await ethers.getContractFactory("contracts/serverless-v2/RelaySubscriptions.sol:RelaySubscriptions");
    const relaySubscriptions = await upgrades.deployProxy(RelaySubscriptions, [admin], {
        kind: "uups",
        constructorArgs: [relay.target, 10, 60 * 60 * 24 * 365, 60 * 60 * 24 * 365 * 5],
    });
    await relaySubscriptions.waitForDeployment();
    out.relaySubscriptions = relaySubscriptions.target;
    console.log("RelaySubscriptions:", relaySubscriptions.target);

    // Common chain
    const Gateways = await ethers.getContractFactory("contracts/serverless-v2/Gateways.sol:Gateways");
    const gateways = await upgrades.deployProxy(Gateways, [admin, []], {
        kind: "uups",
        constructorArgs: [attestationVerifier, signMaxAge, stakingToken, epochInterval + overallTimeout, 100, 1000000],
    });
    await gateways.waitForDeployment();
    out.gateways = gateways.target;
    console.log("Gateways:", gateways.target);

    const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
    const executors = await upgrades.deployProxy(Executors, [admin, []], {
        kind: "uups",
        constructorArgs: [attestationVerifier, signMaxAge, stakingToken, minExecutorStake, 100, 1000000],
    });
    await executors.waitForDeployment();
    out.executors = executors.target;
    console.log("Executors:", executors.target);

    const Jobs = await ethers.getContractFactory("contracts/serverless-v2/Jobs.sol:Jobs");
    const jobs = await upgrades.deployProxy(Jobs, [admin], {
        kind: "uups",
        constructorArgs: [
            stakingToken, usdcToken, signMaxAge, executionBufferTime, numSelectedExecutors,
            paymentPool, paymentPool, executors.target,
        ],
    });
    await jobs.waitForDeployment();
    out.jobs = jobs.target;
    console.log("Jobs:", jobs.target);
    // Jobs needs JOBS_ROLE on Executors before adding the env, addGlobalEnv calls Executors.initTree
    await (await executors.grantRole(await executors.JOBS_ROLE(), jobs.target)).wait();
    await (await jobs.addGlobalEnv(execEnv, executorFeePerMs, stakingRewardPerMs)).wait();

    const GatewayJobs = await ethers.getContractFactory("contracts/serverless-v2/GatewayJobs.sol:GatewayJobs");
    const gatewayJobs = await upgrades.deployProxy(GatewayJobs, [admin], {
        kind: "uups",
        constructorArgs: [
            stakingToken, usdcToken, signMaxAge, relayBufferTime, 10n ** 16n, 10n ** 16n,
            jobs.target, gateways.target, paymentPool,
        ],
    });
    await gatewayJobs.waitForDeployment();
    out.gatewayJobs = gatewayJobs.target;
    console.log("GatewayJobs:", gatewayJobs.target);
    await (await gateways.grantRole(await gateways.GATEWAY_JOBS_ROLE(), gatewayJobs.target)).wait();
    await (await gatewayJobs.grantRole(await gatewayJobs.JOBS_ROLE(), jobs.target)).wait();
    await (await gatewayJobs.setJobAllowance()).wait();

    // Register the chain as a request chain for the gateways
    await (await gateways.addChainGlobal(
        [chainId],
        [{
            relayAddress: relay.target,
            relaySubscriptionsAddress: relaySubscriptions.target,
            httpRpcUrl: env("HTTP_RPC_URL"),
            wsRpcUrl: env("WS_RPC_URL"),
        }],
    )).wait();

    const outFile = env("OUT_FILE", "deployment.json");
    writeFileSync(outFile, JSON.stringify(out, null, 2) + "\n");
    console.log(`Addresses written to ${outFile}`);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
