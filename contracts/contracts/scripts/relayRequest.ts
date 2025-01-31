import { getBytes, Wallet } from "ethers";
import { ethers, upgrades } from "hardhat";

type EnvConfig = {
    [key: number]: {
        executorFeePerMs: number;
        stakingRewardPerMs: number;
    }
}

const envConfig: EnvConfig = {
    1: {
        executorFeePerMs: 1,
        stakingRewardPerMs: 1
    }
};

async function main() {
    //Create Enclave Image object
    const img = {
        PCR0: getBytes("0xcfa7554f87ba13620037695d62a381a2d876b74c2e1b435584fe5c02c53393ac1c5cd5a8b6f92e866f9a65af751e0462"),
        PCR1: getBytes("0xbcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f"),
        PCR2: getBytes("0x20caae8a6a69d9b1aecdf01a0b9c5f3eafd1f06cb51892bf47cef476935bfe77b5b75714b68a69146d650683a217c5b3"),
    };

    let wallet = walletForIndex(0);
    console.log("Attestation Verifer Enclave Private Key: ", wallet.signingKey.privateKey);
    let enclavePubKey = normalize(wallet.signingKey.publicKey);

    // Admin address
    let signers = await ethers.getSigners();
    let admin_addr = await signers[0].getAddress();

    // Deploy POND Token Contract
    console.log("Deploying Pond");
    const Pond = await ethers.getContractFactory("Pond");
    let staking_token = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
        kind: "uups",
    });
    let staking_token_addr = staking_token.target;
    console.log("Pond Deployed address: ", staking_token_addr);

    // Deploy USDC Token Contract
    console.log("Deploying USDCoin...");
    const USDCoin = await ethers.getContractFactory("USDCoin");
    let usdc_token = await upgrades.deployProxy(USDCoin, [admin_addr], {
        kind: "uups",
    });

    let usdc_token_addr = usdc_token.target;
    console.log("USDCoin Deployed address: ", usdc_token_addr);

    const env = 1;
    const executorFeePerMs = envConfig[env].executorFeePerMs; // 0.001 usd per ms
    const stakingRewardPerMs = envConfig[env].stakingRewardPerMs; // 0.001 usd per ms
    const executionFeePerMs = executorFeePerMs + stakingRewardPerMs;
    const gatewayFee = 100; // 0.1 usd
    const stakingPaymentPoolAddress = await signers[0].getAddress();
    const usdcPaymentPoolAddress = await signers[0].getAddress();
    const signMaxAge = 600;

    // Attestation Verifier
    const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
    console.log("Deploying AttestationVerifier")
    let attestationverifier = await upgrades.deployProxy(
        AttestationVerifier,
        [
            [img],
            [enclavePubKey],
            admin_addr
        ],
        {
            kind: "uups"
        });
    let av_addr = attestationverifier.target;
    console.log("AttestationVerifier Deployed address: ", av_addr);

    // Request Chain Relay Contract
    let overallTimeout = 120;
    let minUserDeadline = 1000;
    let maxUserDeadline = 50000;
    let fixedGas = 150000;
    let callbackMeasureGas = 4530;
    const Relay = await ethers.getContractFactory("Relay");
    console.log("Deploying Relay...")
    let relay = await upgrades.deployProxy(
        Relay,
        [
            admin_addr,
            [img]
        ],
        {
            initializer: "initialize",
            kind: "uups",
            constructorArgs: [
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
    
    let minPeriodicGap = 10,
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
    let epochInterval = 600;
    const Gateways = await ethers.getContractFactory("Gateways");
    console.log("Deploying Gateways...")
    let gatewaysContract = await upgrades.deployProxy(
        Gateways,
        [
            admin_addr,
            [img]
        ],
        {
            initializer: "initialize",
            kind: "uups",
            constructorArgs: [
                av_addr,
                signMaxAge,
                staking_token_addr,
                epochInterval + overallTimeout,
                100, // 0.01 %
                1000000
            ]
        });

    let gatewaysAddress = gatewaysContract.target;
    console.log("Gateways Deployed address: ", gatewaysAddress);

    // Common Chain Executors Contract
    let minStake = 10n ** 18n;
    const Executors = await ethers.getContractFactory("Executors");
    console.log("Deploying Executors...")
    let executorsContract = await upgrades.deployProxy(
        Executors,
        [
            admin_addr,
            [img]
        ],
        {
            initializer: "initialize",
            kind: "uups",
            constructorArgs: [
                av_addr,
                signMaxAge,
                staking_token_addr,
                minStake,
                100, // 0.01 %
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
            initializer: "initialize",
            kind: "uups",
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
    let relayBufferTime = 120;
    const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
    console.log("Deploying GatewayJobs...")
    let gatewayJobs = await upgrades.deployProxy(
        GatewayJobs,
        [
            admin_addr
        ],
        {
            initializer: "initialize",
            kind: "uups",
            constructorArgs: [
                staking_token_addr,
                usdc_token_addr,
                signMaxAge,
                relayBufferTime,
                10n ** 16n, // 0.01 POND
                10n ** 16n, // 0.01 POND
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
