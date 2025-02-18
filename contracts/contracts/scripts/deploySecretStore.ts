import { time } from "@nomicfoundation/hardhat-network-helpers";
import { BytesLike, getBytes, keccak256, parseUnits, Signer, Wallet } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationAutherUpgradeable, AttestationVerifier, Executors, Jobs, Pond, SecretManager, SecretStore, TeeManager, USDCoin } from "../typechain-types";

async function main() {
    //Create Enclave Image object
    const img = {
        PCR0: getBytes("0xcfa7554f87ba13620037695d62a381a2d876b74c2e1b435584fe5c02c53393ac1c5cd5a8b6f92e866f9a65af751e0462"),
        PCR1: getBytes("0xbcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f"),
        PCR2: getBytes("0x20caae8a6a69d9b1aecdf01a0b9c5f3eafd1f06cb51892bf47cef476935bfe77b5b75714b68a69146d650683a217c5b3"),
    };

    let wallet = walletForIndex(0);
    let enclavePubKey = normalize(wallet.signingKey.publicKey);

    // Admin address
    let signers = await ethers.getSigners();
    let adminAddress = await signers[0].getAddress();

    const Pond = await ethers.getContractFactory("Pond");
    let stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
        kind: "uups",
    });
    let stakingTokenAddr = stakingToken.target;
    console.log("Pond: ", stakingTokenAddr);

    const USDCoin = await ethers.getContractFactory("USDCoin");
    let usdcToken = await upgrades.deployProxy(USDCoin, [adminAddress], {
        kind: "uups",
    });
    let usdcTokenAddr = usdcToken.target;
    console.log("USDCoin: ", usdcTokenAddr);

    const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
    let attestationVerifier = await upgrades.deployProxy(
        AttestationVerifier,
        [
            [img],
            [enclavePubKey],
            adminAddress
        ],
        {
            kind: "uups"
        });
    let attestationVerifierAddr = attestationVerifier.target;
    console.log("AttestationVerifier: ", attestationVerifierAddr);

    let teeImages = [img],
        maxAge = 600,
        minStakeAmount = 10n ** 18n,
        slashPercentInBips = 100,
        slashMaxBips = 1000000;
    const TeeManager = await ethers.getContractFactory("TeeManager");
    let teeManager = await upgrades.deployProxy(
        TeeManager,
        [adminAddress, teeImages],
        {
            kind: "uups",
            initializer: "initialize",
            constructorArgs: [
                attestationVerifier.target,
                maxAge,
                stakingToken.target,
                minStakeAmount,
                slashPercentInBips,
                slashMaxBips
            ]
        },
    ) as unknown as TeeManager;
    console.log("TeeManager: ", teeManager.target);

    const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
    let executors = await upgrades.deployProxy(
        Executors,
        [adminAddress],
        {
            kind: "uups",
            initializer: "initialize",
            constructorArgs: [
                teeManager.target
            ]
        },
    ) as unknown as Executors;
    console.log("Executors: ", executors.target);

    const SecretStore = await ethers.getContractFactory("SecretStore");
    let secretStore = await upgrades.deployProxy(
        SecretStore,
        [adminAddress],
        {
            kind: "uups",
            initializer: "initialize",
            constructorArgs: [
                teeManager.target
            ]
        },
    ) as unknown as SecretStore;
    console.log("SecretStore: ", secretStore.target);

    await teeManager.setExecutors(executors.target);
    console.log("teeManager.setExecutors done");
    await teeManager.setSecretStore(secretStore.target);
    console.log("teeManager.setSecretStore done");

    let stakingPaymentPool = adminAddress,
        usdcPaymentPool = adminAddress;
    const Jobs = await ethers.getContractFactory("contracts/secret-storage/job-allocation/Jobs.sol:Jobs");
    let jobs = await upgrades.deployProxy(
        Jobs,
        [adminAddress],
        {
            kind: "uups",
            initializer: "initialize",
            constructorArgs: [
                stakingToken.target,
                usdcToken.target,
                100,
                100,
                3,
                stakingPaymentPool,
                usdcPaymentPool
            ]
        },
    ) as unknown as Jobs;
    console.log("Jobs deployed to:", jobs.target);

    // Grant role to jobs contract on executor
    await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), jobs.target);
    console.log("role 1 done");
    await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), jobs.target);
    console.log("role 2 done");

    await jobs.setExecutors(executors.target);
    console.log("jobs.setExecutors done");
    await jobs.setSecretStore(secretStore.target);
    console.log("jobs.setSecretStore done");
    await jobs.setTeeManager(teeManager.target);
    console.log("jobs.setTeeManager done");

    let env = 1,
        executionFeePerMs = 1,
        stakingRewardPerMs = 1;
    await jobs.addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs);
    console.log("global env added");

    let noOfNodesToSelect = 3,
        globalMaxStoreSize = 1e6,
        globalMinStoreDuration = 10,
        globalMaxStoreDuration = 1e6,
        acknowledgementTimeout = 120,
        markAliveTimeout = 500,
        secretStoreFeeRate = 10;

    const SecretManager = await ethers.getContractFactory("SecretManager");
    let secretManager = await upgrades.deployProxy(
        SecretManager,
        [adminAddress],
        {
            kind: "uups",
            initializer: "initialize",
            constructorArgs: [
                usdcToken.target,
                noOfNodesToSelect,
                globalMaxStoreSize,
                globalMinStoreDuration,
                globalMaxStoreDuration,
                acknowledgementTimeout,
                markAliveTimeout,
                secretStoreFeeRate,
                stakingPaymentPool,
                teeManager.target,
                executors.target,
                secretStore.target
            ]
        },
    ) as unknown as SecretManager;
    console.log("SecretManager: ", secretManager.target);

    await jobs.setSecretManager(secretManager.target);
    console.log("jobs.setSecretManager done");
    await secretStore.setSecretManager(secretManager.target);
    console.log("secretStore.setSecretManager done");
}

const image1: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48))
};

const image2: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48))
};

const image3: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48))
};

async function markDeadTest() {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let stakingToken: Pond;
    let usdcToken: USDCoin;
    let secretStore: SecretStore;
    let secretManager: SecretManager;

    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    wallets = signers.map((_, idx) => walletForIndex(idx));
    pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

    const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
    const attestationVerifier = await upgrades.deployProxy(
        AttestationVerifier,
        [[image1], [pubkeys[14]], addrs[0]],
        { kind: "uups" },
    ) as unknown as AttestationVerifier;

    const Pond = await ethers.getContractFactory("Pond");
    stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
        kind: "uups",
    }) as unknown as Pond;

    const USDCoin = await ethers.getContractFactory("USDCoin");
    usdcToken = await upgrades.deployProxy(
        USDCoin,
        [addrs[0]],
        {
            kind: "uups",
        }
    ) as unknown as USDCoin;

    const SecretStore = await ethers.getContractFactory("SecretStore");
    secretStore = await upgrades.deployProxy(
        SecretStore,
        [addrs[0], [image2, image3]],
        {
            kind: "uups",
            initializer: "initialize",
            constructorArgs: [
                attestationVerifier.target,
                600,
                stakingToken.target,
                10,
                10 ** 2,
                10 ** 6,
                1
            ]
        },
    ) as unknown as SecretStore;

    let noOfNodesToSelect = 3,
        globalMaxStoreSize = 1e6,
        globalMinStoreDuration = 10,
        globalMaxStoreDuration = 1e6,
        acknowledgementTimeout = 120,
        markAliveTimeout = 500,
        secretStoreFeeRate = 10,
        stakingPaymentPool = addrs[2];

    const SecretManager = await ethers.getContractFactory("SecretManager");
    secretManager = await upgrades.deployProxy(
        SecretManager,
        [addrs[0]],
        {
            kind: "uups",
            initializer: "initialize",
            constructorArgs: [
                usdcToken.target,
                noOfNodesToSelect,
                globalMaxStoreSize,
                globalMinStoreDuration,
                globalMaxStoreDuration,
                acknowledgementTimeout,
                markAliveTimeout,
                secretStoreFeeRate,
                stakingPaymentPool,
                secretStore.target
            ]
        },
    ) as unknown as SecretManager;

    console.log("SecretManager: ", secretManager.target);

    await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("SECRET_MANAGER_ROLE")), secretManager.target);
    await usdcToken.mint(addrs[0], parseUnits("100000", 6));
    await usdcToken.approve(secretManager.target, parseUnits("100000", 6));

    await stakingToken.transfer(addrs[1], 10n ** 21n);
    await stakingToken.connect(signers[1]).approve(secretStore.target, 10n ** 21n);

    // REGISTER SECRET STORE ENCLAVES
    const timestamp = await time.latest() * 1000;
    let signTimestamp = await time.latest();
    let storageCapacity = 1e9,
        stakeAmount = parseUnits("10"),	// 10 POND
        nodesToRegister = 5;
    for (let index = 0; index < nodesToRegister; index++) {
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[17 + index],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
            wallets[17 + index]);

        await secretStore.connect(signers[1]).registerSecretStore(
            attestationSign,
            attestation,
            storageCapacity,
            signTimestamp,
            signedDigest,
            stakeAmount
        );
    }

    // checking if the store doesn't exist
    // for (let index = 0; index < nodesToRegister; index++) {
    //     const store = await secretStore.secretStorage(wallets[17 + index].address);
    //     if(store.owner === ZeroAddress)
    //         console.log("store: ", index, store.owner);
    // }


    // CREATE SECRET
    let sizeLimit = 1000,
        endTimestamp = await time.latest() + 800,
        usdcDeposit = parseUnits("300", 6),
        secretCount = 3;
    let secretId = 1;
    for (let index = 0; index < secretCount; index++) {
        await secretManager.createSecret(sizeLimit, endTimestamp, usdcDeposit);
        console.log("created: ", index, (await secretManager.userStorage(secretId + index)).startTimestamp, (await secretManager.getSelectedEnclaves(secretId + index)).at(0)?.selectTimestamp);
    }

    console.log("Secrets created");

    let storeSecretCount = new Array(nodesToRegister).fill(0);
    signTimestamp = await time.latest();
    for (let i = 0; i < secretCount; i++) {
        console.log("ack :", secretId + i);
        const selectedStores = await secretManager.getSelectedEnclaves(secretId + i);
        for (let j = 0; j < 3; j++) {
            let index = addrs.indexOf(selectedStores[j].enclaveAddress);
            const wallet = wallets[index];
            ++storeSecretCount[index - 17];

            let signedDigest = await createAcknowledgeSignature(secretId + i, signTimestamp, wallet);
            let tx = await secretManager.acknowledgeStore(secretId + i, signTimestamp, signedDigest);
            let receipt = await tx.wait();
            // console.log("ackBlock: ", receipt?.blockNumber);
        }
    }
    console.log("Secrets acknowledged");

    for (let index = 0; index < secretCount; index++) {
        console.log("ackTimestamp: ", secretId + index, (await secretManager.userStorage(secretId + index)).ackTimestamp, (await secretManager.getSelectedEnclaves(secretId + index))[0].replacedAckTimestamp);
    }

    console.log("storeSecretCount: ", storeSecretCount);

    await time.increase(510);
    for (let index = 0; index < nodesToRegister; index++) {
        // if(storeSecretCount[index] > 1) {
        //     console.log("ackSecIds: ", index, await secretStore.getStoreAckSecretIds(addrs[17 + index]));
        //     const estimatedGas = await secretManager.markStoreDead.estimateGas(addrs[17 + index]);
        //     console.log("estimatedGas: ", index, estimatedGas);
        //     // const txn = await secretManager.markStoreDead(addrs[17 + index]);
        //     // const receipt = await txn.wait();
        //     // console.log("Secret Store dead: ", receipt?.gasUsed, (await receipt?.getBlock())?.gasLimit);
        // }
        // console.log("ackSecIds: ", index, await secretStore.getStoreAckSecretIds(addrs[17 + index]));
        const estimatedGas = await secretManager.markStoreDead.estimateGas(addrs[17 + index]);
        console.log("estimatedGas: ", index, estimatedGas);
        await secretManager.markStoreDead(addrs[17 + index]);
    }
}

type Attestation = {
    enclavePubKey: string,
    PCR0: BytesLike,
    PCR1: BytesLike,
    PCR2: BytesLike,
    timestampInMilliseconds: number,
}

async function createAttestation(
    enclaveKey: string,
    image: AttestationVerifier.EnclaveImageStruct,
    sourceEnclaveKey: Wallet,
    timestamp: number,
): Promise<[string, Attestation]> {
    const domain = {
        name: 'marlin.oyster.AttestationVerifier',
        version: '1',
    };

    const types = {
        Attestation: [
            { name: 'enclavePubKey', type: 'bytes' },
            { name: 'PCR0', type: 'bytes' },
            { name: 'PCR1', type: 'bytes' },
            { name: 'PCR2', type: 'bytes' },
            { name: 'timestampInMilliseconds', type: 'uint256' },
        ]
    }

    const sign = await sourceEnclaveKey.signTypedData(domain, types, {
        enclavePubKey: enclaveKey,
        PCR0: image.PCR0,
        PCR1: image.PCR1,
        PCR2: image.PCR2,
        timestampInMilliseconds: timestamp,
    });
    return [ethers.Signature.from(sign).serialized, {
        enclavePubKey: enclaveKey,
        PCR0: image.PCR0,
        PCR1: image.PCR1,
        PCR2: image.PCR2,
        timestampInMilliseconds: timestamp,
    }];
}

async function createSecretStoreSignature(
    owner: string,
    storageCapacity: number,
    signTimestamp: number,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.SecretStore',
        version: '1',
    };

    const types = {
        Register: [
            { name: 'owner', type: 'address' },
            { name: 'storageCapacity', type: 'uint256' },
            { name: 'signTimestamp', type: 'uint256' }
        ]
    };

    const value = {
        owner,
        storageCapacity,
        signTimestamp
    };

    const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
    return ethers.Signature.from(sign).serialized;
}

async function createAcknowledgeSignature(
    secretId: number,
    signTimestamp: number,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.SecretManager',
        version: '1',
    };

    const types = {
        Acknowledge: [
            { name: 'secretId', type: 'uint256' },
            { name: 'signTimestamp', type: 'uint256' }
        ]
    };

    const value = {
        secretId,
        signTimestamp
    };

    const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
    return ethers.Signature.from(sign).serialized;
}

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
