import { getBytes, parseUnits, solidityPacked, Wallet } from "ethers";
import { ethers, upgrades } from "hardhat";
import { Relay, UserSample } from "../typechain-types";
import { time } from "@nomicfoundation/hardhat-network-helpers";

type EnvConfig = {
    [key: number]: {
        executorFeePerMs: number;
        stakingRewardPerMs: number;
    }
}


// TODO: Get the execution fee
const envConfig: EnvConfig = {
    1: {
        executorFeePerMs: 1,
        stakingRewardPerMs: 1
    }
};

async function main() {
    // Create Enclave Image object

    const verifier_img = {
        PCR0 : getBytes("0x189038eccf28a3a098949e402f3b3d86a876f4915c5b02d546abb5d8c507ceb1755b8192d8cfca66e8f226160ca4c7a6"),
        PCR1 : getBytes("0x5d3938eb05288e20a981038b1861062ff4174884968a39aee5982b312894e60561883576cc7381d1a7d05b809936bd16"),
        PCR2 : getBytes("0x6c3ef363c488a9a86faa63a44653fd806e645d4540b40540876f3b811fc1bceecf036a4703f07587c501ee45bb56a1aa"),
    };

    // Update the PCR values with the actual values
    const gw_img = {
        PCR0 : getBytes("0x6d40212c0e1360c4739386ce36e2e07bfd826b72eefbeccc8f524caa17df19f2084ef02c2b7caddf3acdf5bb4183164b"),
        PCR1 : getBytes("0x3c9d303f89856ec3410913381c328350c32d14d2f86a2b4a7787998bd6d76d8f60fc88fea094bf5a02b2c2df1b7ad832"),
        PCR2 : getBytes("0x58fe54ea1929ca6f80d54d01fd68c818676761c96c3c0153ec6c92dca471adfdac75cc33c524808231ae6d85dd285f62"),
    };
    const exec_img = {
        PCR0 : getBytes("0x3d94326f8a889e12b8a603174334ffc77b81a4515418aef341827015a4002f844e8c7b6a02f5609ccbc47f18bac7df0c"),
        PCR1 : getBytes("0x34c9578ce5105b9de453fe1ed082b09cc5a7587f6b1dd3304b4b2e159004b8f35d1ff2376593a2e9322b118fec3fa06f"),
        PCR2 : getBytes("0xb6546c776a76b94285c0124a1658b90fd9eaf2676efe2070ef46486b51755e76c76239755fdde5c9b0e9a6d81fc39330"),
    };


    // get enclave pub key for attestation verifier to be whitelisted
    let verifierEnclavePubKey = "0xe646f8b0071d5ba75931402522cc6a5c42a84a6fea238864e5ac9a0e12d83bd36d0c8109d3ca2b699fce8d082bf313f5d2ae249bb275b6b6e91e0fcd9262f4bb";

    // NOTE: Admin address same as address deploying the contracts, configured in environment file
    let signers = await ethers.getSigners();
    let admin_addr = await signers[0].getAddress();

    // POND Token Contract
    let staking_token_addr = "0xdA0a57B710768ae17941a9Fa33f8B720c8bD9ddD";
    console.log("Pond Deployed address: ", staking_token_addr);

    // TODO: remove after local testing
    // Deploy USDC Token Contract
    console.log("Deploying USDCoin...");
    const USDCoin = await ethers.getContractFactory("USDCoin");
    let usdc_token = await upgrades.deployProxy(USDCoin, [admin_addr], {
        kind: "uups",
    });

    let usdc_token_addr = usdc_token.target;
    console.log("USDCoin Deployed address: ", usdc_token_addr);

    // TODO: uncomment
    // // USDC Token Contract
    // let usdc_token_addr = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831";
    // console.log("USDCoin Deployed address: ", usdc_token_addr);

    // Attestation Verifier
    let av_addr = "0x778c1AdeaB57DD4B5b930bbdB8c892F8d2606228";
    console.log("AttestationVerifier Deployed address: ", av_addr);

    const env = 1;
    const executorFeePerMs = envConfig[env].executorFeePerMs; // 0.001 usd per ms
    const stakingRewardPerMs = envConfig[env].stakingRewardPerMs; // 0.001 usd per ms
    const executionFeePerMs = executorFeePerMs + stakingRewardPerMs;
    const gatewayFee = 100; // 0.1 usd // TODO
    const stakingPaymentPoolAddress = await signers[0].getAddress();
    const usdcPaymentPoolAddress = await signers[0].getAddress();
    const signMaxAge = 600;

    // Request Chain Relay Contract
    let overallTimeout = 570;
    let minUserDeadline = 1000;
    let maxUserDeadline = 300000;
    let fixedGas = 150000;
    let callbackMeasureGas = 4530;
    const Relay = await ethers.getContractFactory("Relay");
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
            constructorArgs : [
                av_addr,
                signMaxAge,
                usdc_token_addr,
                minUserDeadline,
                maxUserDeadline,
                overallTimeout,
                gatewayFee,
                fixedGas,
                callbackMeasureGas
            ]
        });
    let relay_addr = relay.target;
    console.log("Relay Deployed address: ", relay_addr);

    await relay.addGlobalEnv(env, executionFeePerMs);
    
    let minPeriodicGap = 30, // check product requirements
        maxPeriodicGap = 60 * 60 * 24 * 365,    // 1 year
        maxTerminationDuration = 60 * 60 * 24 * 365 * 5;    // 5 years
    const RelaySubscriptions = await ethers.getContractFactory("RelaySubscriptions");
    console.log("Deploying RelaySubscriptions...")
    let relaySubscriptions = await upgrades.deployProxy(
        RelaySubscriptions,
        [
            admin_addr
        ],
        {
            initializer : "initialize",
            kind : "uups",
            constructorArgs : [
                relay_addr,
                minPeriodicGap,
                maxPeriodicGap,
                maxTerminationDuration
            ]
        });
    let relaySubscriptionsAddress = relaySubscriptions.target;
    console.log("RelaySubscriptions Deployed address: ", relaySubscriptionsAddress);

    // Common Chain Gateways Contract
    let epochInterval = 60;
    const Gateways = await ethers.getContractFactory("Gateways");
    console.log("Deploying Gateways...")
    let gatewaysContract = await upgrades.deployProxy(
        Gateways,
        [
            admin_addr,
            []
        ],
        {
            initializer : "initialize",
            kind : "uups",
            constructorArgs : [
                av_addr,
                signMaxAge,
                staking_token_addr,
                epochInterval + overallTimeout,
                100, // 0.01 % // TODO
                1000000
            ]
        });

    let gatewaysAddress = gatewaysContract.target;
    console.log("Gateways Deployed address: ", gatewaysAddress);

    // Common Chain Executors Contract
    let minStake = 10n**18n;
    const Executors = await ethers.getContractFactory("Executors");
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
            constructorArgs : [
                av_addr,
                signMaxAge,
                staking_token_addr,
                minStake,
                100, // 0.01 % // TODO
                1000000
            ]
        });
    let executorsAddress = executorsContract.target;
    console.log("Executors Deployed address: ", executorsAddress);

    let executionBufferTime = 60,
        noOfNodesToSelect = 3;
    // Common Chain Jobs Contract
    const Jobs = await ethers.getContractFactory("Jobs");
    console.log("Deploying Jobs...")
    let jobsContract = await upgrades.deployProxy(
        Jobs,
        [
            admin_addr,
        ],
        {
            initializer : "initialize",
            kind : "uups",
            constructorArgs: [
                staking_token_addr,
                usdc_token_addr,
                signMaxAge,
                executionBufferTime,
                noOfNodesToSelect,
                stakingPaymentPoolAddress,
                usdcPaymentPoolAddress,
                executorsAddress
            ]
        });
    let jobsAddress = jobsContract.target;
    console.log("Jobs Deployed address: ", jobsAddress);

    await executorsContract.grantRole(await executorsContract.JOBS_ROLE(), jobsAddress);
    await jobsContract.addGlobalEnv(env, executorFeePerMs, stakingRewardPerMs);

    // Common Chain Gateway Jobs Contract
    let relayBufferTime = 210;
    let slashCompForGateway = 10n**14n; // 0.0001 POND // TODO
    let reassignCompForReporterGateway = 10n**14n; // 0.0001 POND // TODO
    const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
    console.log("Deploying GatewayJobs...")
    let gatewayJobs = await upgrades.deployProxy(
        GatewayJobs,
        [
            admin_addr
        ],
        {
            initializer : "initialize",
            kind : "uups",
            constructorArgs : [
                staking_token_addr,
                usdc_token_addr,
                signMaxAge,
                relayBufferTime,
                slashCompForGateway,
                reassignCompForReporterGateway,
                jobsAddress,
                gatewaysAddress,
                stakingPaymentPoolAddress
            ]
        });
    let gatewayJobsAddress = gatewayJobs.target;
    console.log("GatewayJobs Deployed address: ", gatewayJobsAddress);
    await gatewaysContract.grantRole(await gatewaysContract.GATEWAY_JOBS_ROLE(), gatewayJobsAddress);
}

// async function deployUserSample() {
//     let relayAddress = "0x56EC16763Ec62f4EAF9C7Cfa09E29DC557e97006",
//         relaySubscriptionsAddress = "0x6B59433387341925aE903E36d16D976053D018E1",
//         tokenAddress = "0x186A361FF2361BAbEE9344A2FeC1941d80a7a49C",
//         owner = await (await ethers.getSigners())[0].getAddress();
//     const UserSample = await ethers.getContractFactory("UserSample");
//     let userSample = await UserSample.deploy(relayAddress, relaySubscriptionsAddress, tokenAddress, owner) as unknown as UserSample;
//     console.log("UserSample : ", userSample.target);
//     // await token.transfer(userSample.target, 1000000);
// }

// async function executeUserSample() {
//     const UserSample = await ethers.getContractFactory("UserSample");
//     let userSample = await UserSample.attach("0x4a71D367b347c74B2ccaba9DFae3Ba4fC6F27229") as unknown as UserSample;
//     let input = {"num": 600};
//     let input_string = JSON.stringify(input);
//     let env = 1,
//         codeHash = '0x6516be2032b475da2a96df1eefeb1679a8032faa434f8311a1441e92f2058fe5',
//         // codeInputs = Buffer.from(input_string, 'utf-8'),
//         codeInputs = "0x",
//         userTimeout = 2000,
//         maxGasPrice = parseUnits("2", 9),
//         usdcDeposit = 5100,
//         callbackDeposit = parseUnits("0.01"),	// 0.01 eth
//         refundAccount = "0xF90e66D1452Be040Ca3A82387Bf6AD0c472f29Dd",
//         callbackContract = "0x4a71D367b347c74B2ccaba9DFae3Ba4fC6F27229",
//         callbackGasLimit = 5000;

//     const USDCoin = await ethers.getContractFactory("USDCoin");
//     let token = await USDCoin.attach("0x186A361FF2361BAbEE9344A2FeC1941d80a7a49C");
//     await token.transfer(userSample.target, 1000000);
//     console.log("USDC sent");

//     let signers = await ethers.getSigners();
//     await signers[0].sendTransaction({ to: "0x4a71D367b347c74B2ccaba9DFae3Ba4fC6F27229", value: callbackDeposit });
//     console.log("ETH sent");

//     let gas = await userSample.relayJob.estimateGas(
//         env,
//         codeHash, 
//         codeInputs, 
//         userTimeout, 
//         maxGasPrice, 
//         usdcDeposit, 
//         callbackDeposit,
//         refundAccount, 
//         callbackContract, 
//         callbackGasLimit,
//         {
//             // value: parseUnits("0.01"),
//             // gasLimit: 1000000
//         }
//     );
//     console.log("gas: ", gas, codeInputs.toString());

//     await userSample.relayJob(
//         env,
//         codeHash, 
//         codeInputs, 
//         userTimeout, 
//         maxGasPrice, 
//         usdcDeposit, 
//         callbackDeposit,
//         refundAccount, 
//         callbackContract, 
//         callbackGasLimit,
//         {
//             // value: parseUnits("0.01"),
//             // gasLimit: 3500000
//         }
//     );
//     console.log("Relayed");
//     // await token.transfer(userSample.target, 1000000);

//     // const Relay = await ethers.getContractFactory("Relay");
//     // const relay = await Relay.attach("") as unknown as Relay;

//     // let jobId: any = await relay.jobCount(),
// 	// 		output = solidityPacked(["string"], ["it is the output"]),
// 	// 		totalTime = 100,
// 	// 		errorCode = 0,
// 	// 		signTimestamp = await time.latest();

//     // let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[15]);
//     // await relay.jobResponse(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);
// }

// async function executeUserSampleStartJobSubscription() {
//     const UserSample = await ethers.getContractFactory("UserSample");
//     let userSample = await UserSample.attach("0x4a71D367b347c74B2ccaba9DFae3Ba4fC6F27229") as unknown as UserSample;

//     let jobSubsParams = {
//         startTime: 0,
//         maxGasPrice: parseUnits("2", 9),
//         usdcDeposit: 51000,
//         callbackGasLimit: 5000,
//         callbackContract: userSample.target,
//         env: 1,
//         codehash: '0x6516be2032b475da2a96df1eefeb1679a8032faa434f8311a1441e92f2058fe5',
//         codeInputs: '0x',
//         userTimeout: 2000,
//         refundAccount: "0xF90e66D1452Be040Ca3A82387Bf6AD0c472f29Dd",
//         periodicGap: 30,
//         terminationTimestamp: Math.floor(Date.now() / 1000) + 300
//     };

//     let callbackDeposit = parseUnits("0.02");

//     const USDCoin = await ethers.getContractFactory("USDCoin");
//     let token = await USDCoin.attach("0x186A361FF2361BAbEE9344A2FeC1941d80a7a49C");
//     await token.transfer(userSample.target, jobSubsParams.usdcDeposit);
//     console.log("USDC sent");

//     let signers = await ethers.getSigners();
//     await signers[0].sendTransaction({ to: "0x4a71D367b347c74B2ccaba9DFae3Ba4fC6F27229", value: callbackDeposit });
//     console.log("ETH sent");

//     await userSample.startJobSubscription(jobSubsParams, callbackDeposit);
//     console.log("Started Job Subsription");
// }

// async function createJobResponseSignature(
// 	jobId: number,
//     output: string,
// 	totalTime: number,
//     errorCode: number,
// 	signTimestamp: number,
// 	sourceEnclaveWallet: Wallet
// ): Promise<string> {
// 	const domain = {
// 		name: 'marlin.oyster.Relay',
// 		version: '1'
// 	};

// 	const types = {
// 		JobResponse: [
// 			{ name: 'jobId', type: 'uint256' },
// 			{ name: 'output', type: 'bytes' },
// 			{ name: 'totalTime', type: 'uint256' },
// 			{ name: 'errorCode', type: 'uint8' },
// 			{ name: 'signTimestamp', type: 'uint256' }
// 		]
// 	};

// 	const value = {
// 		jobId,
// 		output,
// 		totalTime,
// 		errorCode,
// 		signTimestamp
// 	};

// 	const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
// 	return ethers.Signature.from(sign).serialized;
// }

function normalize(key: string): string {
	return '0x' + key.substring(4);
}

function walletForIndex(idx: number): Wallet {
	let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

	return new Wallet(wallet.privateKey);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });

/*
    ARBITRUM SEPOLIA -
    Pond Deployed address:  0x0DA917048bfF8fc8fe5647509FB8F8049E2E7B87
    USDCoin Deployed address:  0x186A361FF2361BAbEE9344A2FeC1941d80a7a49C
    AttestationVerifier Deployed address:  0x73B7154EdBc562D4cCbdB43D515eB1C2dF46A718
    Relay Deployed address:  0x56EC16763Ec62f4EAF9C7Cfa09E29DC557e97006
    RelaySubscriptions Deployed address:  0x6B59433387341925aE903E36d16D976053D018E1
    Gateways Deployed address:  0x56Fb98c417E61609c472Aa941E0ea915Efd9615F
    Executors Deployed address:  0xa5F525145219D16763d24670DBF0E62fFbA19571
    Jobs Deployed address:  0xF14Ff55120210912Ffb32B7D48b926186168166C
    GatewayJobs Deployed address:  0x7a3406cf602aCEc0Dd1f80549171F778010C31C2
    UserSample: 0x4a71D367b347c74B2ccaba9DFae3Ba4fC6F27229
*/