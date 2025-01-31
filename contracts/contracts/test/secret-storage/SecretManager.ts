import { time } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { BytesLike, keccak256, parseUnits, Signer, solidityPacked, Wallet, ZeroAddress } from "ethers";
import { ethers, upgrades } from "hardhat";
import {
    AttestationAutherUpgradeable,
    AttestationVerifier,
    Executors,
    Pond,
    SecretManager,
    SecretStore,
    SecretStoreMock,
    TeeManager,
    USDCoin
} from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { testERC165 } from "../helpers/erc165";

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

function getImageId(image: AttestationAutherUpgradeable.EnclaveImageStruct): string {
    return keccak256(solidityPacked(["bytes", "bytes", "bytes"], [image.PCR0, image.PCR1, image.PCR2]));
}

describe("SecretManager - Init", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let token: string;
    let noOfNodesToSelect: number;
    let globalMaxStoreSize: number;
    let globalMinStoreDuration: number;
    let globalMaxStoreDuration: number;
    let acknowledgementTimeout: number;
    let markAliveTimeout: number;
    let secretStoreFeeRate: number;
    let stakingPaymentPool: string;
    let secretStoreAddress: string;
    let teeManager: string;
    let executors: string;
    let secretStore: string;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));

        token = addrs[1],
            noOfNodesToSelect = 3,
            globalMaxStoreSize = 1e6,
            globalMinStoreDuration = 10,
            globalMaxStoreDuration = 1e6,
            acknowledgementTimeout = 120,
            markAliveTimeout = 900,
            secretStoreFeeRate = 10,
            stakingPaymentPool = addrs[2],
            teeManager = addrs[3],
            executors = addrs[4],
            secretStore = addrs[5];
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("deploys with initialization disabled", async function () {
        const SecretManager = await ethers.getContractFactory("SecretManager");
        const secretManager = await SecretManager.deploy(
            token,
            noOfNodesToSelect,
            globalMaxStoreSize,
            globalMinStoreDuration,
            globalMaxStoreDuration,
            acknowledgementTimeout,
            markAliveTimeout,
            secretStoreFeeRate,
            stakingPaymentPool,
            teeManager,
            executors,
            secretStore
        ) as unknown as SecretManager;

        expect(await secretManager.USDC_TOKEN()).to.equal(token);
        expect(await secretManager.NO_OF_NODES_TO_SELECT()).to.equal(noOfNodesToSelect);
        expect(await secretManager.GLOBAL_MAX_STORE_SIZE()).to.equal(globalMaxStoreSize);
        expect(await secretManager.GLOBAL_MIN_STORE_DURATION()).to.equal(globalMinStoreDuration);
        expect(await secretManager.GLOBAL_MAX_STORE_DURATION()).to.equal(globalMaxStoreDuration);
        expect(await secretManager.ACKNOWLEDGEMENT_TIMEOUT()).to.equal(acknowledgementTimeout);
        expect(await secretManager.MARK_ALIVE_TIMEOUT()).to.equal(markAliveTimeout);
        expect(await secretManager.SECRET_STORE_FEE_RATE()).to.equal(secretStoreFeeRate);
        expect(await secretManager.STAKING_PAYMENT_POOL()).to.equal(stakingPaymentPool);
        expect(await secretManager.TEE_MANAGER()).to.equal(teeManager);
        expect(await secretManager.EXECUTORS()).to.equal(executors);
        expect(await secretManager.SECRET_STORE()).to.equal(secretStore);

        await expect(
            secretManager.initialize(addrs[0]),
        ).to.be.revertedWithCustomError(secretManager, "InvalidInitialization");
    });

    it("deploys as proxy and initializes", async function () {
        const SecretManager = await ethers.getContractFactory("SecretManager");
        const secretManager = await upgrades.deployProxy(
            SecretManager,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    token,
                    noOfNodesToSelect,
                    globalMaxStoreSize,
                    globalMinStoreDuration,
                    globalMaxStoreDuration,
                    acknowledgementTimeout,
                    markAliveTimeout,
                    secretStoreFeeRate,
                    stakingPaymentPool,
                    teeManager,
                    executors,
                    secretStore
                ]
            },
        );

        expect(await secretManager.USDC_TOKEN()).to.equal(token);
        expect(await secretManager.NO_OF_NODES_TO_SELECT()).to.equal(noOfNodesToSelect);
        expect(await secretManager.GLOBAL_MAX_STORE_SIZE()).to.equal(globalMaxStoreSize);
        expect(await secretManager.GLOBAL_MIN_STORE_DURATION()).to.equal(globalMinStoreDuration);
        expect(await secretManager.GLOBAL_MAX_STORE_DURATION()).to.equal(globalMaxStoreDuration);
        expect(await secretManager.ACKNOWLEDGEMENT_TIMEOUT()).to.equal(acknowledgementTimeout);
        expect(await secretManager.MARK_ALIVE_TIMEOUT()).to.equal(markAliveTimeout);
        expect(await secretManager.SECRET_STORE_FEE_RATE()).to.equal(secretStoreFeeRate);
        expect(await secretManager.STAKING_PAYMENT_POOL()).to.equal(stakingPaymentPool);
        expect(await secretManager.TEE_MANAGER()).to.equal(teeManager);
        expect(await secretManager.EXECUTORS()).to.equal(executors);
        expect(await secretManager.SECRET_STORE()).to.equal(secretStore);

        expect(await secretManager.hasRole(await secretManager.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    });

    it("cannot initialize with zero address as admin", async function () {
        const SecretManager = await ethers.getContractFactory("SecretManager");
        await expect(
            upgrades.deployProxy(
                SecretManager,
                [ZeroAddress],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        token,
                        noOfNodesToSelect,
                        globalMaxStoreSize,
                        globalMinStoreDuration,
                        globalMaxStoreDuration,
                        acknowledgementTimeout,
                        markAliveTimeout,
                        secretStoreFeeRate,
                        stakingPaymentPool,
                        teeManager,
                        executors,
                        secretStore
                    ]
                },
            )
        ).to.be.revertedWithCustomError(SecretManager, "SecretManagerZeroAddressAdmin");
    });

    it("cannot initialize with zero address as usdc token", async function () {
        const SecretManager = await ethers.getContractFactory("SecretManager");
        await expect(
            upgrades.deployProxy(
                SecretManager,
                [addrs[0]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        ZeroAddress,
                        noOfNodesToSelect,
                        globalMaxStoreSize,
                        globalMinStoreDuration,
                        globalMaxStoreDuration,
                        acknowledgementTimeout,
                        markAliveTimeout,
                        secretStoreFeeRate,
                        stakingPaymentPool,
                        teeManager,
                        executors,
                        secretStore
                    ]
                },
            )
        ).to.be.revertedWithCustomError(SecretManager, "SecretManagerZeroAddressUsdcToken");
    });

    it("upgrades", async function () {
        const SecretManager = await ethers.getContractFactory("SecretManager");
        const secretManager = await upgrades.deployProxy(
            SecretManager,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    token,
                    noOfNodesToSelect,
                    globalMaxStoreSize,
                    globalMinStoreDuration,
                    globalMaxStoreDuration,
                    acknowledgementTimeout,
                    markAliveTimeout,
                    secretStoreFeeRate,
                    stakingPaymentPool,
                    teeManager,
                    executors,
                    secretStore
                ]
            },
        );

        const token2 = addrs[2],
            noOfNodesToSelect2 = 4,
            globalMaxStoreSize2 = 100,
            globalMinStoreDuration2 = 1,
            globalMaxStoreDuration2 = 10,
            acknowledgementTimeout2 = 10,
            markAliveTimeout2 = 10,
            secretStoreFeeRate2 = 20,
            stakingPaymentPool2 = addrs[3],
            teeManager2 = addrs[4],
            executors2 = addrs[5],
            secretStore2 = addrs[6];

        await upgrades.upgradeProxy(
            secretManager.target,
            SecretManager,
            {
                kind: "uups",
                constructorArgs: [
                    token2,
                    noOfNodesToSelect2,
                    globalMaxStoreSize2,
                    globalMinStoreDuration2,
                    globalMaxStoreDuration2,
                    acknowledgementTimeout2,
                    markAliveTimeout2,
                    secretStoreFeeRate2,
                    stakingPaymentPool2,
                    teeManager2,
                    executors2,
                    secretStore2
                ]
            }
        );

        expect(await secretManager.USDC_TOKEN()).to.equal(token2);
        expect(await secretManager.NO_OF_NODES_TO_SELECT()).to.equal(noOfNodesToSelect2);
        expect(await secretManager.GLOBAL_MAX_STORE_SIZE()).to.equal(globalMaxStoreSize2);
        expect(await secretManager.GLOBAL_MIN_STORE_DURATION()).to.equal(globalMinStoreDuration2);
        expect(await secretManager.GLOBAL_MAX_STORE_DURATION()).to.equal(globalMaxStoreDuration2);
        expect(await secretManager.ACKNOWLEDGEMENT_TIMEOUT()).to.equal(acknowledgementTimeout2);
        expect(await secretManager.MARK_ALIVE_TIMEOUT()).to.equal(markAliveTimeout2);
        expect(await secretManager.SECRET_STORE_FEE_RATE()).to.equal(secretStoreFeeRate2);
        expect(await secretManager.STAKING_PAYMENT_POOL()).to.equal(stakingPaymentPool2);
        expect(await secretManager.TEE_MANAGER()).to.equal(teeManager2);
        expect(await secretManager.EXECUTORS()).to.equal(executors2);
        expect(await secretManager.SECRET_STORE()).to.equal(secretStore2);

        expect(await secretManager.hasRole(await secretManager.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    });

    it("does not upgrade without admin", async function () {
        const SecretManager = await ethers.getContractFactory("SecretManager");
        const secretManager = await upgrades.deployProxy(
            SecretManager,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    token,
                    noOfNodesToSelect,
                    globalMaxStoreSize,
                    globalMinStoreDuration,
                    globalMaxStoreDuration,
                    acknowledgementTimeout,
                    markAliveTimeout,
                    secretStoreFeeRate,
                    stakingPaymentPool,
                    teeManager,
                    executors,
                    secretStore
                ]
            },
        );

        await expect(
            upgrades.upgradeProxy(secretManager.target, SecretManager.connect(signers[1]), {
                kind: "uups",
                constructorArgs: [
                    token,
                    noOfNodesToSelect,
                    globalMaxStoreSize,
                    globalMinStoreDuration,
                    globalMaxStoreDuration,
                    acknowledgementTimeout,
                    markAliveTimeout,
                    secretStoreFeeRate,
                    stakingPaymentPool,
                    teeManager,
                    executors,
                    secretStore
                ],
            }),
        ).to.be.revertedWithCustomError(secretManager, "AccessControlUnauthorizedAccount");
    });
});

testERC165(
    "SecretManager - ERC165",
    async function (_signers: Signer[], addrs: string[]) {
        let usdcToken = addrs[1],
            noOfNodesToSelect = 3,
            globalMaxStoreSize = 1e6,
            globalMinStoreDuration = 10,
            globalMaxStoreDuration = 1e6,
            acknowledgementTimeout = 120,
            markAliveTimeout = 900,
            secretStoreFeeRate = 10,
            stakingPaymentPool = addrs[2],
            teeManager = addrs[3],
            executors = addrs[4],
            secretStore = addrs[5];

        const SecretManager = await ethers.getContractFactory("SecretManager");
        const secretManager = await upgrades.deployProxy(
            SecretManager,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    usdcToken,
                    noOfNodesToSelect,
                    globalMaxStoreSize,
                    globalMinStoreDuration,
                    globalMaxStoreDuration,
                    acknowledgementTimeout,
                    markAliveTimeout,
                    secretStoreFeeRate,
                    stakingPaymentPool,
                    teeManager,
                    executors,
                    secretStore
                ]
            },
        );
        return secretManager;
    },
    {
        IAccessControl: [
            "hasRole(bytes32,address)",
            "getRoleAdmin(bytes32)",
            "grantRole(bytes32,address)",
            "revokeRole(bytes32,address)",
            "renounceRole(bytes32,address)",
        ],
    },
);

describe("SecretManager - Create secret", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let usdcToken: USDCoin;
    let teeManager: TeeManager;
    let executors: Executors;
    let secretStore: SecretStore;
    let secretManager: SecretManager;

    before(async function () {
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
        const stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
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

        const TeeManager = await ethers.getContractFactory("TeeManager");
        teeManager = await upgrades.deployProxy(
            TeeManager,
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
                    10 ** 6
                ]
            },
        ) as unknown as TeeManager;

        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as Executors;

        const SecretStore = await ethers.getContractFactory("SecretStore");
        secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as SecretStore;

        let env = 1;
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        await executors.initTree(1);
        await secretStore.initTree(1);

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

        let noOfNodesToSelect = 3,
            globalMaxStoreSize = 1e6,
            globalMinStoreDuration = 10,
            globalMaxStoreDuration = 1e6,
            acknowledgementTimeout = 120,
            markAliveTimeout = 900,
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
                    teeManager.target,
                    executors.target,
                    secretStore.target
                ]
            },
        ) as unknown as SecretManager;

        await secretStore.setSecretManager(secretManager.target);
        await usdcToken.approve(secretManager.target, parseUnits("10000", 6));

        await stakingToken.transfer(addrs[1], 10n ** 20n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 20n);

        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let jobCapacity = 20,
            storageCapacity = 1e9,
            stakeAmount = parseUnits("10");	// 10 POND
        for (let index = 0; index < 4; index++) {
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[17 + index],
                image2,
                wallets[14],
                timestamp - 540000
            );

            let signedDigest = await registerTeeNodeSignature(
                addrs[1],
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                wallets[17 + index]
            );

            await teeManager.connect(signers[1]).registerTeeNode(
                attestationSign,
                attestation,
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                signedDigest,
                stakeAmount
            );
        }
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can create secret", async function () {
        let env = 1,
            sizeLimit = 1000,
            endTimestamp = await time.latest() + 1000,
            usdcDeposit = parseUnits("30", 6);

        await expect(secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []))
            .to.emit(secretManager, "SecretCreated");
        expect(await usdcToken.balanceOf(secretManager.target)).to.eq(usdcDeposit);
    });

    it("cannot create secret with invalid size limit", async function () {
        let env = 1,
            sizeLimit = 0,
            endTimestamp = await time.latest() + 1000,
            usdcDeposit = parseUnits("30", 6);

        await expect(secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerInvalidSizeLimit");

        sizeLimit = 1e7;
        await expect(secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerInvalidSizeLimit");
    });

    it("cannot create secret with invalid end timestamp", async function () {
        let env = 1,
            sizeLimit = 1000,
            endTimestamp = await time.latest(),
            usdcDeposit = parseUnits("30", 6);

        await expect(secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerInvalidEndTimestamp");

        endTimestamp = await time.latest() + 1e7;
        await expect(secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerInvalidEndTimestamp");
    });

    it("cannot create secret with insufficient usdc deposit", async function () {
        let env = 1,
            sizeLimit = 1000,
            endTimestamp = await time.latest() + 1000,
            usdcDeposit = 10;

        await expect(secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerInsufficientUsdcDeposit");
    });

    it("cannot create secret when resources are unavailable", async function () {
        await teeManager.connect(signers[1]).drainTeeNode(addrs[17]);
        await teeManager.connect(signers[1]).drainTeeNode(addrs[18]);

        await teeManager.connect(signers[1]).deregisterTeeNode(addrs[17]);
        await teeManager.connect(signers[1]).deregisterTeeNode(addrs[18]);

        let env = 1,
            sizeLimit = 1000,
            endTimestamp = await time.latest() + 1000,
            usdcDeposit = parseUnits("30", 6);

        await expect(secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerUnavailableResources");
    });

});

describe("SecretManager - Acknowledge secret", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let usdcToken: USDCoin;
    let teeManager: TeeManager;
    let executors: Executors;
    let secretStore: SecretStore;
    let secretManager: SecretManager;

    before(async function () {
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
        const stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
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

        const TeeManager = await ethers.getContractFactory("TeeManager");
        teeManager = await upgrades.deployProxy(
            TeeManager,
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
                    10 ** 6
                ]
            },
        ) as unknown as TeeManager;

        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as Executors;

        const SecretStore = await ethers.getContractFactory("SecretStore");
        secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as SecretStore;

        let env = 1;
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        await executors.initTree(1);
        await secretStore.initTree(1);

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

        let noOfNodesToSelect = 3,
            globalMaxStoreSize = 1e6,
            globalMinStoreDuration = 10,
            globalMaxStoreDuration = 1e6,
            acknowledgementTimeout = 120,
            markAliveTimeout = 900,
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
                    teeManager.target,
                    executors.target,
                    secretStore.target
                ]
            },
        ) as unknown as SecretManager;

        await secretStore.setSecretManager(secretManager.target);
        await usdcToken.approve(secretManager.target, parseUnits("10000", 6));

        await stakingToken.transfer(addrs[1], 10n ** 20n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 20n);

        // REGISTER SECRET STORE ENCLAVES
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let jobCapacity = 20,
            storageCapacity = 1e9,
            stakeAmount = parseUnits("10");	// 10 POND
        for (let index = 0; index < 3; index++) {
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[17 + index],
                image2,
                wallets[14],
                timestamp - 540000
            );

            let signedDigest = await registerTeeNodeSignature(
                addrs[1],
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                wallets[17 + index]
            );

            await teeManager.connect(signers[1]).registerTeeNode(
                attestationSign,
                attestation,
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                signedDigest,
                stakeAmount
            );
        }

        // CREATE SECRET
        let sizeLimit = 1000,
            endTimestamp = await time.latest() + 1000,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can acknowledge secret", async function () {
        let secretId = 1;
        expect(await secretManager.getCurrentConfirmedUsdcDeposit(secretId))
            .to.eq((await secretManager.userStorage(secretId)).usdcDeposit);

        let signTimestamp = await time.latest() - 540,
            signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);

        await expect(secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest))
            .to.emit(secretManager, "SecretStoreAcknowledgementSuccess")
            .withArgs(secretId, addrs[17]);

        expect(await secretManager.getCurrentConfirmedUsdcDeposit(secretId))
            .to.eq((await secretManager.userStorage(secretId)).usdcDeposit);
    });

    it("cannot acknowledge secret if the store is draining", async function () {
        await teeManager.connect(signers[1]).drainTeeNode(addrs[17]);
        let secretId = 1,
            signTimestamp = await time.latest(),
            signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);
        await expect(secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerCantAckWhileDraining")
    });

    it("cannot acknowledge secret with non-selected store", async function () {
        // Registering a new node
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest();
        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1,
            stakeAmount = parseUnits("10");	// 10 POND
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[16],
            image2,
            wallets[14],
            timestamp
        );

        let signedDigest = await registerTeeNodeSignature(
            addrs[1],
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            wallets[16]
        );

        await teeManager.connect(signers[1]).registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            signedDigest,
            stakeAmount
        );
        
        // trying to ack secret with non-selected node
        let secretId = 1;
        signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[16]);
        await expect(secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerEnclaveNotFound")
    });

    it("cannot acknowledge secret after secret is terminated", async function () {
        await time.increase(1100);
        let secretId = 1,
            signTimestamp = await time.latest(),
            signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);
        await expect(secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerAlreadyTerminated");
    });

    it("cannot acknowledge secret with replaced node after secret is terminated", async function () {
        let secretId = 1,
            signTimestamp = await time.latest();
        for (let index = 0; index < 3; index++) {
            let signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17 + index]);
            await expect(secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest))
                .to.emit(secretManager, "SecretStoreAcknowledgementSuccess")
                .withArgs(secretId, addrs[17 + index]);
        }

        // mark dead after alive timeout
        await time.increase(910);
        await secretManager.markStoreDead(addrs[17]);

        // ack after end timestamp
        await time.increase(100);
        signTimestamp = await time.latest();
        let signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);
        await expect(secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerAlreadyTerminated");
    });

    it("can acknowledge secret with replaced node before secret is terminated", async function () {
        let secretId = 1,
            signTimestamp = await time.latest();
        for (let index = 0; index < 3; index++) {
            let signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17 + index]);
            await expect(secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest))
                .to.emit(secretManager, "SecretStoreAcknowledgementSuccess")
                .withArgs(secretId, addrs[17 + index]);
        }

        // mark dead after alive timeout
        await time.increase(910);
        await secretManager.markStoreDead(addrs[17]);

        // ack before end timestamp
        await time.increase(50);
        signTimestamp = await time.latest();
        let signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);
        await expect(secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest))
            .to.emit(secretManager, "SecretStoreAcknowledgementSuccess")
            .withArgs(secretId, addrs[17]);
    });

    it("cannot acknowledge secret after acknowledgement timeout", async function () {
        let secretId = 1,
            signTimestamp = await time.latest(),
            signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);

        await time.increase(150);
        await expect(secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerAcknowledgementTimeOver")
    });

    it("cannot acknowledge the secret twice", async function () {
        let secretId = 1,
            signTimestamp = await time.latest(),
            signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);

        await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);

        await expect(secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerAlreadyAcknowledged")
    });

    it("cannot acknowledge secret after signature expired", async function () {
        let secretId = 1,
            signTimestamp = await time.latest() - 610,
            signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);

        await expect(secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerSignatureTooOld")
    });

    it("can mark acknowledgement failed", async function () {
        let secretId = 1;
        let usdcDeposit = (await secretManager.userStorage(secretId)).usdcDeposit;
        let userInitialBal = await usdcToken.balanceOf(addrs[0]);

        await time.increase(150);

        await expect(secretManager.acknowledgeStoreFailed(secretId))
            .to.emit(secretManager, "SecretStoreAcknowledgementFailed")
            .withArgs(secretId);

        expect(await usdcToken.balanceOf(secretManager.target)).to.eq(0);

        let userFinalBal = await usdcToken.balanceOf(addrs[0]);
        expect(userFinalBal - userInitialBal).to.eq(usdcDeposit);
    });

    it("cannot mark acknowledgement failed if acknowledgement timeout is pending", async function () {
        let secretId = 1;
        await expect(secretManager.acknowledgeStoreFailed(secretId))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerAcknowledgementTimeoutPending");
    });

    it("cannot mark acknowledgement failed if secret has been already acknowledged", async function () {
        let secretId = 1,
            signTimestamp = await time.latest() - 540;
        for (let index = 0; index < 3; index++) {
            let signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17 + index]);
            await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);
        }

        await time.increase(150);
        await expect(secretManager.acknowledgeStoreFailed(secretId))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerAcknowledgedAlready");
    });

    it("can mark acknowledgement failed if all the selected stores haven't ack the secret", async function () {
        let secretId = 1,
            signTimestamp = await time.latest(),
            signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);
        await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);

        let usdcDeposit = (await secretManager.userStorage(secretId)).usdcDeposit;
        let userInitialBal = await usdcToken.balanceOf(addrs[0]);

        await time.increase(150);
        await expect(secretManager.acknowledgeStoreFailed(secretId))
            .to.emit(secretManager, "SecretStoreAcknowledgementFailed")
            .withArgs(secretId);

        expect(await (await secretManager.userStorage(secretId)).owner).to.eq(ZeroAddress);
        expect(await usdcToken.balanceOf(secretManager.target)).to.eq(0);

        let userFinalBal = await usdcToken.balanceOf(addrs[0]);
        expect(userFinalBal - userInitialBal).to.eq(usdcDeposit);
    });
});

describe("SecretManager - Alive/Dead checks for secret", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let stakingToken: Pond;
    let usdcToken: USDCoin;
    let teeManager: TeeManager;
    let executors: Executors;
    let secretStore: SecretStore;
    let secretManager: SecretManager;

    before(async function () {
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

        const TeeManager = await ethers.getContractFactory("TeeManager");
        teeManager = await upgrades.deployProxy(
            TeeManager,
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
                    10 ** 6
                ]
            },
        ) as unknown as TeeManager;

        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as Executors;

        const SecretStore = await ethers.getContractFactory("SecretStore");
        secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as SecretStore;

        let env = 1;
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        await executors.initTree(1);
        await secretStore.initTree(1);

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

        let noOfNodesToSelect = 3,
            globalMaxStoreSize = 8000,
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
                    teeManager.target,
                    executors.target,
                    secretStore.target
                ]
            },
        ) as unknown as SecretManager;

        await secretStore.setSecretManager(secretManager.target);
        await usdcToken.approve(secretManager.target, parseUnits("10000", 6));

        await stakingToken.transfer(addrs[1], 10n ** 20n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 20n);

        // REGISTER SECRET STORE ENCLAVES
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest();
        let jobCapacity = 1,
            storageCapacity = 10000,
            stakeAmount = parseUnits("10");	// 10 POND
        for (let index = 0; index < 3; index++) {
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[17 + index],
                image2,
                wallets[14],
                timestamp - 540000
            );

            let signedDigest = await registerTeeNodeSignature(
                addrs[1],
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                wallets[17 + index]
            );

            await teeManager.connect(signers[1]).registerTeeNode(
                attestationSign,
                attestation,
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                signedDigest,
                stakeAmount
            );
        }

        // CREATE SECRET
        let sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []);

        let secretId = 1;
        for (let index = 0; index < 3; index++) {
            let signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17 + index]);
            await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);
        }
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can submit alive check", async function () {
        await time.increase(10);
        let signTimestamp = await time.latest(),
            signedDigest = await createAliveSignature(signTimestamp, wallets[17]);
        let enclaveOwnerInitialBal = await usdcToken.balanceOf(addrs[1]);

        await expect(secretManager.markStoreAlive(signTimestamp, signedDigest))
            .to.emit(secretManager, "SecretStoreAlive")
            .withArgs(addrs[17]);

        let secretId = 1,
            duration = BigInt(signTimestamp) - ((await secretManager.userStorage(secretId)).ackTimestamp),
            storageTimeUsage = duration * 1000n;    // duration * sizeLimit
        let usdcPayment = storageTimeUsage * 10n; // storageTimeUsage * feeRate
        let enclaveOwnerFinalBal = await usdcToken.balanceOf(addrs[1]);
        expect(enclaveOwnerFinalBal - enclaveOwnerInitialBal).to.eq(usdcPayment);

        expect(await secretManager.getCurrentConfirmedUsdcDeposit(secretId))
            .to.eq((await secretManager.userStorage(secretId)).usdcDeposit - usdcPayment);
    });

    it("cannot submit alive check while draining", async function () {
        await teeManager.connect(signers[1]).drainTeeNode(addrs[17]);
        let signTimestamp = await time.latest(),
            signedDigest = await createAliveSignature(signTimestamp, wallets[17]);

        await expect(secretManager.markStoreAlive(signTimestamp, signedDigest))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerNodeIsDraining")
    });

    it("cannot submit alive check with expired signature", async function () {
        let signTimestamp = await time.latest(),
            signedDigest = await createAliveSignature(signTimestamp, wallets[17]);

        await time.increase(610);

        await expect(secretManager.markStoreAlive(signTimestamp, signedDigest))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerSignatureTooOld")
    });

    it("can submit alive check after end timestamp, and delete the secret data", async function () {
        await time.increase(850);
        let secretOwnerInitialBal = await usdcToken.balanceOf(addrs[0]);
        let enclaveOwnerInitialBal = await usdcToken.balanceOf(addrs[1]);
        let secretId = 1,
            userStorage = await secretManager.userStorage(secretId),
            signTimestamp = await time.latest();
        for (let index = 0; index < 3; index++) {
            let signedDigest = await createAliveSignature(signTimestamp, wallets[17 + index]);
            await secretManager.markStoreAlive(signTimestamp, signedDigest);
        }

        let duration = userStorage.endTimestamp - userStorage.ackTimestamp,
            storageTimeUsage = duration * 1000n;    // duration * sizeLimit
        let usdcPayment = storageTimeUsage * 10n * 3n; // storageTimeUsage * feeRate * noOfNodes
        let enclaveOwnerFinalBal = await usdcToken.balanceOf(addrs[1]);
        expect(enclaveOwnerFinalBal - enclaveOwnerInitialBal).to.eq(usdcPayment);

        let secretOwnerFinalBal = await usdcToken.balanceOf(addrs[0]);
        expect(secretOwnerFinalBal - secretOwnerInitialBal)
            .to.eq(parseUnits("30", 6) - usdcPayment);   // usdcDeposit - usdcPayment

        userStorage = await secretManager.userStorage(secretId);
        // secret should be removed after all stores marked alive post endTimestamp
        expect(userStorage.owner).to.eq(ZeroAddress);
    });

    it("can mark store dead to replace and acknowledge it", async function () {
        await time.increase(510);
        let storeInitialStakeAmount = (await teeManager.teeNodes(addrs[17])).stakeAmount;
        let stakingPoolInitialBal = await stakingToken.balanceOf(addrs[2]);
        let secretId = 1;
        await expect(secretManager.markStoreDead(addrs[17]))
            .to.emit(secretManager, "SecretStoreReplaced")
            .withArgs(secretId, addrs[17], addrs[17], true);

        const selectedEnclaves = await secretManager.getSelectedEnclaves(secretId);
        expect(selectedEnclaves.length).to.eq(3);

        expect(await secretStore.getStoreAckSecretIds(addrs[17])).to.deep.eq([]);
        expect(await secretStore.getSecretStoreDeadTimestamp(addrs[17])).to.eq(await time.latest());

        let slashedAmount = parseUnits("10") * 100n / 1000000n;
        let storeFinalStakeAmount = (await teeManager.teeNodes(addrs[17])).stakeAmount;
        let stakingPoolFinalBal = await stakingToken.balanceOf(addrs[2]);
        expect(storeInitialStakeAmount - storeFinalStakeAmount).to.eq(slashedAmount);
        expect(stakingPoolFinalBal - stakingPoolInitialBal).to.eq(slashedAmount);

        let signTimestamp = await time.latest(),
            signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);
        await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);

        expect(await secretManager.getCurrentConfirmedUsdcDeposit(secretId))
            .to.eq((await secretManager.userStorage(secretId)).usdcDeposit);
    });

    it("can mark store dead to replace it but fails to acknowledge it", async function () {
        await time.increase(510);
        let storeInitialStakeAmount = (await teeManager.teeNodes(addrs[17])).stakeAmount;
        let stakingPoolInitialBal = await stakingToken.balanceOf(addrs[2]);
        let secretIds = [1];
        await expect(secretManager.markStoreDead(addrs[17]))
            .to.emit(secretManager, "SecretStoreReplaced")
            .withArgs(secretIds[0], addrs[17], addrs[17], true);

        const selectedEnclaves = await secretManager.getSelectedEnclaves(secretIds[0]);
        expect(selectedEnclaves.length).to.eq(3);

        let slashedAmount = parseUnits("10") * 100n / 1000000n;
        let storeFinalStakeAmount = (await teeManager.teeNodes(addrs[17])).stakeAmount;
        let stakingPoolFinalBal = await stakingToken.balanceOf(addrs[2]);
        expect(storeInitialStakeAmount - storeFinalStakeAmount).to.eq(slashedAmount);
        expect(stakingPoolFinalBal - stakingPoolInitialBal).to.eq(slashedAmount);

        await time.increase(150);
        await secretManager.acknowledgeStoreFailed(secretIds[0]);
        expect((await secretManager.getSelectedEnclaves(secretIds[0])).length).to.eq(3);
    });

    it("cannot submit alive check with signTimestamp <= deadTimestamp", async function () {
        await time.increase(510);
        let signTimestamp = await time.latest(),
            signedDigest = await createAliveSignature(signTimestamp, wallets[17]);

        await secretManager.markStoreDead(addrs[17]);

        await expect(secretManager.markStoreAlive(signTimestamp, signedDigest))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerSignatureTooOld")
    });

    it("cannot mark ack failed for a replaced store that is already acknowledged", async function () {
        await time.increase(510);
        let storeInitialStakeAmount = (await teeManager.teeNodes(addrs[17])).stakeAmount;
        let stakingPoolInitialBal = await stakingToken.balanceOf(addrs[2]);
        let secretIds = [1];
        await expect(secretManager.markStoreDead(addrs[17]))
            .to.emit(secretManager, "SecretStoreReplaced")
            .withArgs(secretIds[0], addrs[17], addrs[17], true);

        const selectedEnclaves = await secretManager.getSelectedEnclaves(secretIds[0]);
        expect(selectedEnclaves.length).to.eq(3);

        let slashedAmount = parseUnits("10") * 100n / 1000000n;
        let storeFinalStakeAmount = (await teeManager.teeNodes(addrs[17])).stakeAmount;
        let stakingPoolFinalBal = await stakingToken.balanceOf(addrs[2]);
        expect(storeInitialStakeAmount - storeFinalStakeAmount).to.eq(slashedAmount);
        expect(stakingPoolFinalBal - stakingPoolInitialBal).to.eq(slashedAmount);

        let signTimestamp = await time.latest(),
            signedDigest = await createAcknowledgeSignature(secretIds[0], signTimestamp, wallets[17]);
        await secretManager.acknowledgeStore(secretIds[0], signTimestamp, signedDigest);

        await expect(secretManager.acknowledgeStoreFailed(secretIds[0]))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerAcknowledgedAlready");
    });

    it("can submit alive check for the replaced store after end timestamp", async function () {
        await time.increase(510);
        let secretId = 1;
        await expect(secretManager.markStoreDead(addrs[17]))
            .to.emit(secretManager, "SecretStoreReplaced")
            .withArgs(secretId, addrs[17], addrs[17], true);

        let signTimestamp = await time.latest(),
            signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);
        await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);

        await time.increase(300);

        signTimestamp = await time.latest();
        signedDigest = await createAliveSignature(signTimestamp, wallets[17]);
        let enclaveOwnerInitialBal = await usdcToken.balanceOf(addrs[1]);

        let selectedEnclaves = await secretManager.getSelectedEnclaves(secretId),
            replacedStoreIndex = 0;
        for (let index = 0; index < selectedEnclaves.length; index++) {
            if (selectedEnclaves[index].enclaveAddress === addrs[17]) {
                replacedStoreIndex = index;
                break;
            }
        }
        let ackTimestamp = selectedEnclaves[replacedStoreIndex].replacedAckTimestamp,
            endTimestamp = (await secretManager.userStorage(secretId)).endTimestamp,
            duration = endTimestamp - ackTimestamp,
            storageTimeUsage = duration * 1000n,    // duration * sizeLimit
            usdcPayment = storageTimeUsage * 10n; // storageTimeUsage * feeRate

        await expect(secretManager.markStoreAlive(signTimestamp, signedDigest))
            .to.emit(secretManager, "SecretStoreAlive")
            .withArgs(addrs[17]);

        let enclaveOwnerFinalBal = await usdcToken.balanceOf(addrs[1]);
        expect(enclaveOwnerFinalBal - enclaveOwnerInitialBal).to.eq(usdcPayment);

        expect(await secretManager.getCurrentConfirmedUsdcDeposit(secretId))
            .to.eq((await secretManager.userStorage(secretId)).usdcDeposit);
    });

    it("can mark store dead and mark acknowledgement failed for the replaced store after end timestamp", async function () {
        await time.increase(510);
        let storeInitialStakeAmount = (await teeManager.teeNodes(addrs[17])).stakeAmount;
        let stakingPoolInitialBal = await stakingToken.balanceOf(addrs[2]);
        let secretIds = [1];
        await expect(secretManager.markStoreDead(addrs[17]))
            .to.emit(secretManager, "SecretStoreReplaced")
            .withArgs(secretIds[0], addrs[17], addrs[17], true);

        const selectedEnclaves = await secretManager.getSelectedEnclaves(secretIds[0]);
        expect(selectedEnclaves.length).to.eq(3);

        let slashedAmount = parseUnits("10") * 100n / 1000000n;
        let storeFinalStakeAmount = (await teeManager.teeNodes(addrs[17])).stakeAmount;
        let stakingPoolFinalBal = await stakingToken.balanceOf(addrs[2]);
        expect(storeInitialStakeAmount - storeFinalStakeAmount).to.eq(slashedAmount);
        expect(stakingPoolFinalBal - stakingPoolInitialBal).to.eq(slashedAmount);

        await time.increase(400);
        await secretManager.acknowledgeStoreFailed(secretIds[0]);
        expect((await secretManager.getSelectedEnclaves(secretIds[0])).length).to.eq(2);
    });

    it("can mark store dead with reduced replication factor", async function () {
        await time.increase(510);
        // create secret such that occupiedStorage exceeds storageCapacity, due to which nodes will be removed from the tree
        let env = 1,
            sizeLimit = 8000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("3000", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []);
        expect(await secretStore.isNodePresentInTree(env, addrs[17])).to.be.false;
        expect(await secretStore.isNodePresentInTree(env, addrs[18])).to.be.false;
        expect(await secretStore.isNodePresentInTree(env, addrs[19])).to.be.false;

        let storeInitialStakeAmount = (await teeManager.teeNodes(addrs[18])).stakeAmount;
        let stakingPoolInitialBal = await stakingToken.balanceOf(addrs[2]);
        let secretId = 1;
        // no node would be available as a replacement since all have exceeded the storage capacity
        await expect(secretManager.markStoreDead(addrs[18]))
            .to.emit(secretManager, "SecretReplicationReduced")
            .withArgs(secretId, 2);

        expect((await secretManager.getSelectedEnclaves(secretId)).length).to.eq(2);

        let slashedAmount = parseUnits("10") * 100n / 1000000n;
        let storeFinalStakeAmount = (await teeManager.teeNodes(addrs[18])).stakeAmount;
        let stakingPoolFinalBal = await stakingToken.balanceOf(addrs[2]);
        expect(storeInitialStakeAmount - storeFinalStakeAmount).to.eq(slashedAmount);
        expect(stakingPoolFinalBal - stakingPoolInitialBal).to.eq(slashedAmount);
        expect((await secretManager.userStorage(secretId)).usdcDeposit).to.eq(parseUnits("30", 6));
    });

    it("can mark secret store dead after end timestamp of a secret", async function () {
        await time.increase(810);

        let stakingPoolInitialBal = await stakingToken.balanceOf(addrs[2]);
        let secretIds = [1];
        for (let index = 0; index < 3; index++)
            await secretManager.markStoreDead(addrs[17 + index]);

        let userStorage = await secretManager.userStorage(secretIds[0]);
        // secret should be removed after all stores marked dead post endTimestamp
        expect(userStorage.owner).to.eq(ZeroAddress);

        const selectedEnclaves = await secretManager.getSelectedEnclaves(secretIds[0]);
        expect(selectedEnclaves.length).to.eq(0);

        let slashedAmount = 3n * parseUnits("10") * 100n / 1000000n;
        let stakingPoolFinalBal = await stakingToken.balanceOf(addrs[2]);
        expect(stakingPoolFinalBal - stakingPoolInitialBal).to.eq(slashedAmount);
    });

    it("cannot mark store dead while draining", async function () {
        await teeManager.connect(signers[1]).drainTeeNode(addrs[17]);
        await expect(secretManager.markStoreDead(addrs[17]))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerNodeIsDraining")
    });

    it("cannot mark store dead before alive timeout", async function () {
        let secretIds = [1];
        await expect(secretManager.markStoreDead(addrs[17]))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerStoreIsAlive");
    });

    it("cannot mark store dead if secret is not acknowledged", async function () {
        let env = 1,
            sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []);

        let storeInitialStakeAmount = (await teeManager.teeNodes(addrs[17])).stakeAmount;
        let stakingPoolInitialBal = await stakingToken.balanceOf(addrs[2]);

        await time.increase(510);
        // secret 1 will be marked dead, while secret 2 won't as it is unackowledged
        await secretManager.markStoreDead(addrs[17]);

        let slashedAmount = parseUnits("10") * 100n / 1000000n;
        let storeFinalStakeAmount = (await teeManager.teeNodes(addrs[17])).stakeAmount;
        let stakingPoolFinalBal = await stakingToken.balanceOf(addrs[2]);

        expect(storeInitialStakeAmount - storeFinalStakeAmount).to.eq(slashedAmount);
        expect(stakingPoolFinalBal - stakingPoolInitialBal).to.eq(slashedAmount);
    });
});

describe("SecretManager - Update end timestamp of secret", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let usdcToken: USDCoin;
    let teeManager: TeeManager;
    let executors: Executors;
    let secretStore: SecretStore;
    let secretManager: SecretManager;

    before(async function () {
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
        const stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
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

        const TeeManager = await ethers.getContractFactory("TeeManager");
        teeManager = await upgrades.deployProxy(
            TeeManager,
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
                    10 ** 6
                ]
            },
        ) as unknown as TeeManager;

        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as Executors;

        const SecretStore = await ethers.getContractFactory("SecretStore");
        secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as SecretStore;

        let env = 1;
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        await executors.initTree(1);
        await secretStore.initTree(1);

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

        let noOfNodesToSelect = 3,
            globalMaxStoreSize = 1e6,
            globalMinStoreDuration = 10,
            globalMaxStoreDuration = 1e6,
            acknowledgementTimeout = 120,
            markAliveTimeout = 900,
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
                    teeManager.target,
                    executors.target,
                    secretStore.target
                ]
            },
        ) as unknown as SecretManager;

        await secretStore.setSecretManager(secretManager.target);
        await usdcToken.approve(secretManager.target, parseUnits("10000", 6));

        await stakingToken.transfer(addrs[1], 10n ** 20n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 20n);

        // REGISTER SECRET STORE ENCLAVES
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest();
        let jobCapacity = 20,
            storageCapacity = 1e9,
            stakeAmount = parseUnits("10");	// 10 POND
        for (let index = 0; index < 3; index++) {
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[17 + index],
                image2,
                wallets[14],
                timestamp - 540000
            );

            let signedDigest = await registerTeeNodeSignature(
                addrs[1],
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                wallets[17 + index]
            );

            await teeManager.connect(signers[1]).registerTeeNode(
                attestationSign,
                attestation,
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                signedDigest,
                stakeAmount
            );
        }

        // CREATE SECRET
        let sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []);

        let secretId = 1,
            signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);
        await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can increase end timestamp", async function () {
        // need to acknowledge with all enclaves before updating end timestamp
        let secretId = 1,
            signTimestamp = await time.latest(),
            signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[18]);
        await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);

        signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[19]);
        await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);

        let endTimestamp = (await secretManager.userStorage(secretId)).endTimestamp + 100n,
            usdcDeposit = parseUnits("3", 6);
        let secretManagerInitialBal = await usdcToken.balanceOf(secretManager.target);
        let secretOwnerInitialBal = await usdcToken.balanceOf(addrs[0]);
        let initialUsdcDeposit = (await secretManager.userStorage(secretId)).usdcDeposit;

        await expect(secretManager.updateSecretEndTimestamp(secretId, endTimestamp, usdcDeposit))
            .to.emit(secretManager, "SecretEndTimestampUpdated")
            .withArgs(secretId, endTimestamp);
        expect((await secretManager.userStorage(secretId)).endTimestamp).to.eq(endTimestamp);

        let secretManagerFinalBal = await usdcToken.balanceOf(secretManager.target);
        let secretOwnerFinalBal = await usdcToken.balanceOf(addrs[0]);
        let finalUsdcDeposit = (await secretManager.userStorage(secretId)).usdcDeposit;
        expect(secretManagerFinalBal - secretManagerInitialBal).to.eq(usdcDeposit);
        expect(secretOwnerInitialBal - secretOwnerFinalBal).to.eq(usdcDeposit);
        expect(finalUsdcDeposit - initialUsdcDeposit).to.eq(usdcDeposit);
    });

    it("can decrease end timestamp", async function () {
        let secretId = 1,
            signTimestamp = await time.latest(),
            signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[18]);
        await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);

        signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[19]);
        await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);

        let endTimestamp = (await secretManager.userStorage(secretId)).endTimestamp - 100n,
            usdcDeposit = 0;
        let usdcRefund = 100 * 1000 * 10 * 3; // reducedDuration * sizeLimit * feeRate * noOfNodes
        let secretManagerInitialBal = await usdcToken.balanceOf(secretManager.target);
        let secretOwnerInitialBal = await usdcToken.balanceOf(addrs[0]);
        let initialUsdcDeposit = (await secretManager.userStorage(secretId)).usdcDeposit;

        await expect(secretManager.updateSecretEndTimestamp(secretId, endTimestamp, usdcDeposit))
            .to.emit(secretManager, "SecretEndTimestampUpdated")
            .withArgs(secretId, endTimestamp);
        expect((await secretManager.userStorage(secretId)).endTimestamp).to.eq(endTimestamp);

        let secretManagerFinalBal = await usdcToken.balanceOf(secretManager.target);
        let secretOwnerFinalBal = await usdcToken.balanceOf(addrs[0]);
        let finalUsdcDeposit = (await secretManager.userStorage(secretId)).usdcDeposit;
        expect(secretManagerInitialBal - secretManagerFinalBal).to.eq(usdcRefund);
        expect(secretOwnerFinalBal - secretOwnerInitialBal).to.eq(usdcRefund);
        expect(initialUsdcDeposit - finalUsdcDeposit).to.eq(usdcRefund);
    });

    it("cannot update end timestamp without all acknowledgements", async function () {
        let secretId = 1,
            endTimestamp = (await secretManager.userStorage(secretId)).endTimestamp - 100n,
            usdcDeposit = 0;

        await expect(secretManager.updateSecretEndTimestamp(secretId, endTimestamp, usdcDeposit))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerUnacknowledged");
    });

    it("cannot update end timestamp without secret owner", async function () {
        let secretId = 1,
            endTimestamp = (await secretManager.userStorage(secretId)).endTimestamp - 100n,
            usdcDeposit = 0;

        await expect(secretManager.connect(signers[1]).updateSecretEndTimestamp(secretId, endTimestamp, usdcDeposit))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerInvalidSecretOwner");
    });

    it("cannot update end timestamp to earlier than the current timestamp", async function () {
        let secretId = 1,
            endTimestamp = (await secretManager.userStorage(secretId)).endTimestamp - 1000n,
            usdcDeposit = 0;

        await expect(secretManager.updateSecretEndTimestamp(secretId, endTimestamp, usdcDeposit))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerInvalidEndTimestamp");
    });

    it("cannot update end timestamp after the secret is terminated", async function () {
        await time.increase(1000);
        let secretId = 1,
            endTimestamp = (await secretManager.userStorage(secretId)).endTimestamp + 400n,
            usdcDeposit = parseUnits("1", 6);

        await expect(secretManager.updateSecretEndTimestamp(secretId, endTimestamp, usdcDeposit))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerAlreadyTerminated");
    });
});

describe("SecretManager - Terminate secret", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let usdcToken: USDCoin;
    let teeManager: TeeManager;
    let executors: Executors;
    let secretStore: SecretStore;
    let secretManager: SecretManager;

    before(async function () {
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
        const stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
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

        const TeeManager = await ethers.getContractFactory("TeeManager");
        teeManager = await upgrades.deployProxy(
            TeeManager,
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
                    10 ** 6
                ]
            },
        ) as unknown as TeeManager;

        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as Executors;

        const SecretStore = await ethers.getContractFactory("SecretStore");
        secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as SecretStore;

        let env = 1;
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        await executors.initTree(1);
        await secretStore.initTree(1);

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

        let noOfNodesToSelect = 3,
            globalMaxStoreSize = 1e6,
            globalMinStoreDuration = 10,
            globalMaxStoreDuration = 1e6,
            acknowledgementTimeout = 120,
            markAliveTimeout = 900,
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
                    teeManager.target,
                    executors.target,
                    secretStore.target
                ]
            },
        ) as unknown as SecretManager;

        await secretStore.setSecretManager(secretManager.target);
        await usdcToken.approve(secretManager.target, parseUnits("10000", 6));

        await stakingToken.transfer(addrs[1], 10n ** 20n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 20n);

        // REGISTER SECRET STORE ENCLAVES
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest();
        let jobCapacity = 20,
            storageCapacity = 1e9,
            stakeAmount = parseUnits("10");	// 10 POND
        for (let index = 0; index < 3; index++) {
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[17 + index],
                image2,
                wallets[14],
                timestamp - 540000
            );

            let signedDigest = await registerTeeNodeSignature(
                addrs[1],
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                wallets[17 + index]
            );

            await teeManager.connect(signers[1]).registerTeeNode(
                attestationSign,
                attestation,
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                signedDigest,
                stakeAmount
            );
        }

        // CREATE SECRET
        let sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []);

        let secretId = 1,
            signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);
        await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can terminate the secret before end timestamp", async function () {
        let secretId = 1;
        await expect(secretManager.terminateSecret(secretId))
            .to.emit(secretManager, "SecretTerminated")
            .withArgs(secretId, await time.latest());
        expect((await secretManager.userStorage(secretId)).endTimestamp).to.eq(await time.latest());
    });

    it("cannot update end timestamp without secret owner", async function () {
        let secretId = 1;
        await expect(secretManager.connect(signers[1]).terminateSecret(secretId))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerInvalidSecretOwner");
    });

    it("cannot terminate after end timestamp", async function () {
        await time.increase(810);
        let secretId = 1;
        await expect(secretManager.terminateSecret(secretId))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerAlreadyTerminated");
    });

    it("cannot terminate twice", async function () {
        let secretId = 1;
        await expect(secretManager.terminateSecret(secretId))
            .to.emit(secretManager, "SecretTerminated")
            .withArgs(secretId, await time.latest());

        await expect(secretManager.terminateSecret(secretId))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerAlreadyTerminated");
    });
});

describe("SecretManager - Remove secret", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let stakingToken: Pond;
    let usdcToken: USDCoin;
    let teeManager: TeeManager;
    let executors: Executors;
    let secretStore: SecretStore;
    let secretManager: SecretManager;

    before(async function () {
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

        const TeeManager = await ethers.getContractFactory("TeeManager");
        teeManager = await upgrades.deployProxy(
            TeeManager,
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
                    10 ** 6
                ]
            },
        ) as unknown as TeeManager;

        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as Executors;

        const SecretStore = await ethers.getContractFactory("SecretStore");
        secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as SecretStore;

        let env = 1;
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        await executors.initTree(1);
        await secretStore.initTree(1);

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

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
                    teeManager.target,
                    executors.target,
                    secretStore.target
                ]
            },
        ) as unknown as SecretManager;

        await secretStore.setSecretManager(secretManager.target);
        await usdcToken.approve(secretManager.target, parseUnits("10000", 6));

        await stakingToken.transfer(addrs[1], 10n ** 20n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 20n);

        // REGISTER SECRET STORE ENCLAVES
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest();
        let jobCapacity = 20,
            storageCapacity = 1e9,
            stakeAmount = parseUnits("10");	// 10 POND
        for (let index = 0; index < 3; index++) {
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[17 + index],
                image2,
                wallets[14],
                timestamp - 540000
            );

            let signedDigest = await registerTeeNodeSignature(
                addrs[1],
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                wallets[17 + index]
            );

            await teeManager.connect(signers[1]).registerTeeNode(
                attestationSign,
                attestation,
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                signedDigest,
                stakeAmount
            );
        }

        // CREATE SECRET
        let sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []);

        let secretId = 1;
        for (let index = 0; index < 3; index++) {
            let signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17 + index]);
            await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);
        }
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it('can remove secret if no alive/dead check is submitted post termination', async function () {
        await time.increase(1310);
        let secretOwnerInitialBal = await usdcToken.balanceOf(addrs[0]);
        let enclaveOwnerInitialBal = await usdcToken.balanceOf(addrs[1]);
        let secretId = 1,
            userStorage = await secretManager.userStorage(secretId);

        await expect(secretManager.removeSecret(secretId))
            .to.emit(secretManager, "SecretRemoved")
            .withArgs(secretId);

        userStorage = await secretManager.userStorage(secretId);
        expect(userStorage.owner).to.eq(ZeroAddress);

        let usdcPayment = 0n; // as no alive check is submitted till end timestamp
        let enclaveOwnerFinalBal = await usdcToken.balanceOf(addrs[1]);
        expect(enclaveOwnerFinalBal - enclaveOwnerInitialBal).to.eq(usdcPayment);

        let secretOwnerFinalBal = await usdcToken.balanceOf(addrs[0]);
        expect(secretOwnerFinalBal - secretOwnerInitialBal)
            .to.eq(parseUnits("30", 6) - usdcPayment);   // usdcDeposit - usdcPayment
    });

    it('cannot remove secret non-existing secret', async function () {
        let secretId = 2;
        await expect(secretManager.removeSecret(secretId))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerInvalidSecret");
    });

    it('cannot remove secret before end timestamp', async function () {
        let secretId = 1;
        await expect(secretManager.removeSecret(secretId))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerTerminationPending");
    });

    it('can remove secret if partial alive/dead checks are submitted post termination', async function () {
        let secretOwnerInitialBal = await usdcToken.balanceOf(addrs[0]);
        let enclaveOwnerInitialBal = await usdcToken.balanceOf(addrs[1]);
        let stakingPoolInitialBal = await stakingToken.balanceOf(addrs[2]);

        await time.increase(810);
        let secretId = 1,
            signTimestamp = await time.latest(),
            userStorage = await secretManager.userStorage(secretId),
            duration = userStorage.endTimestamp - userStorage.ackTimestamp,
            storageTimeUsage = duration * 1000n;    // duration * sizeLimit

        // Mark 1st store as alive post secret termination
        let signedDigest = await createAliveSignature(signTimestamp, wallets[17]);
        await secretManager.markStoreAlive(signTimestamp, signedDigest);
        let usdcPayment = storageTimeUsage * 10n;   // storageTimeUsage * feeRate

        // Mark 2nd store as dead post secret termination
        await secretManager.markStoreDead(addrs[18]);

        await time.increase(510);
        // Submit remove secret for the last store
        await expect(secretManager.removeSecret(secretId))
            .to.emit(secretManager, "SecretRemoved")
            .withArgs(secretId);

        userStorage = await secretManager.userStorage(secretId);
        expect(userStorage.owner).to.eq(ZeroAddress);

        let enclaveOwnerFinalBal = await usdcToken.balanceOf(addrs[1]);
        expect(enclaveOwnerFinalBal - enclaveOwnerInitialBal).to.eq(usdcPayment);

        let secretOwnerFinalBal = await usdcToken.balanceOf(addrs[0]);
        expect(secretOwnerFinalBal - secretOwnerInitialBal).to.eq(parseUnits("30", 6) - usdcPayment);   // usdcDeposit - usdcPayment

        let slashedAmount17 = parseUnits("10") - (parseUnits("10") * (1000000n - 100n) / 1000000n);
        let slashedAmount18 = parseUnits("10") - (parseUnits("10") * (1000000n - 100n) / 1000000n);
        let stakingPoolFinalBal = await stakingToken.balanceOf(addrs[2]);
        expect(stakingPoolFinalBal - stakingPoolInitialBal).to.eq(slashedAmount17 + slashedAmount18);
    });

    it('can remove secret after early termination of the secret', async function () {
        await time.increase(200);
        let secretId = 1;
        await secretManager.terminateSecret(secretId);

        // cannot terminate before endTimestamp + MARK_ALIVE_TIMEOUT
        await expect(secretManager.removeSecret(secretId))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerTerminationPending");

        await time.increase(510);

        let secretOwnerInitialBal = await usdcToken.balanceOf(addrs[0]);
        let enclaveOwnerInitialBal = await usdcToken.balanceOf(addrs[1]);
        let stakingPoolInitialBal = await stakingToken.balanceOf(addrs[2]);
        let userStorage = await secretManager.userStorage(secretId);

        await expect(secretManager.removeSecret(secretId))
            .to.emit(secretManager, "SecretRemoved")
            .withArgs(secretId);

        userStorage = await secretManager.userStorage(secretId);
        expect(userStorage.owner).to.eq(ZeroAddress);

        let usdcPayment = 0n; // as no alive check is submitted till end timestamp
        let enclaveOwnerFinalBal = await usdcToken.balanceOf(addrs[1]);
        expect(enclaveOwnerFinalBal - enclaveOwnerInitialBal).to.eq(usdcPayment);

        let secretOwnerFinalBal = await usdcToken.balanceOf(addrs[0]);
        expect(secretOwnerFinalBal - secretOwnerInitialBal)
            .to.eq(parseUnits("30", 6) - usdcPayment);   // usdcDeposit - usdcPayment
    });
});

describe("SecretManager - Other functions", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let stakingToken: Pond;
    let usdcToken: USDCoin;
    let teeManager: TeeManager;
    let executors: Executors;
    let secretStore: SecretStore;
    let secretManager: SecretManager;

    before(async function () {
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

        const TeeManager = await ethers.getContractFactory("TeeManager");
        teeManager = await upgrades.deployProxy(
            TeeManager,
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
                    10 ** 6
                ]
            },
        ) as unknown as TeeManager;

        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as Executors;

        const SecretStore = await ethers.getContractFactory("SecretStore");
        secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as SecretStore;

        let env = 1;
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        await executors.initTree(1);
        await secretStore.initTree(1);

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

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
                    teeManager.target,
                    executors.target,
                    secretStore.target
                ]
            },
        ) as unknown as SecretManager;

        await secretStore.setSecretManager(secretManager.target);
        await usdcToken.approve(secretManager.target, parseUnits("10000", 6));

        await stakingToken.transfer(addrs[1], 10n ** 20n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 20n);

        // REGISTER SECRET STORE ENCLAVES
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest();
        let jobCapacity = 1,
            storageCapacity = 1e9,
            stakeAmount = parseUnits("10");	// 10 POND
        for (let index = 0; index < 3; index++) {
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[17 + index],
                image2,
                wallets[14],
                timestamp - 540000
            );

            let signedDigest = await registerTeeNodeSignature(
                addrs[1],
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                wallets[17 + index]
            );

            await teeManager.connect(signers[1]).registerTeeNode(
                attestationSign,
                attestation,
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                signedDigest,
                stakeAmount
            );
        }

        // CREATE SECRET
        let sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []);

        let secretId = 1;
        for (let index = 0; index < 3; index++) {
            let signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17 + index]);
            await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);
        }
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it('can set allowed addresses for a secret', async function () {
        await expect(secretManager.setSecretAllowedAddresses(1, [addrs[1], addrs[2]]))
            .to.be.not.reverted;

        expect(await secretManager.hasSecretAllowedAddress(1, addrs[1])).to.be.true;
        expect(await secretManager.hasSecretAllowedAddress(1, addrs[2])).to.be.true;
        expect(await secretManager.hasSecretAllowedAddress(1, addrs[3])).to.be.false;
    });

    it('cannot set allowed addresses for a secret without the secret owner account', async function () {
        await expect(secretManager.connect(signers[1]).setSecretAllowedAddresses(1, [addrs[1], addrs[2]]))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerInvalidSecretOwner");
    });

    it('can verify user and get selected stores', async function () {
        const selectedStores = await secretManager.verifyUserAndGetSelectedStores(1, addrs[0]);
        expect(selectedStores.length).to.eq(3);

        await expect(secretManager.verifyUserAndGetSelectedStores(1, addrs[1]))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerUserNotAllowed");
    });

    it('cannot verify user and get selected stores for unacknowledged secret', async function () {
        // CREATE SECRET
        let env = 1,
            sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []);

        // as the secret isn't acknowledged by any store, it won't return any store
        let secretId = 2;
        await expect(secretManager.verifyUserAndGetSelectedStores(secretId, addrs[0]))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerUnacknowledged");
    });

    it('can verify user and get selected stores that have job capacity', async function () {
        // select executor node to remove it from the tree
        await executors.selectExecutionNodes(1, [addrs[17]], 1);

        // it should only return the selected stores that can accept more jobs
        const selectedStores = await secretManager.verifyUserAndGetSelectedStores(1, addrs[0]);
        expect(selectedStores.length).to.eq(2);
        expect(selectedStores).to.include.members([addrs[18], addrs[19]]);
        expect(selectedStores).to.not.include.members([addrs[17]]);
    });

    it('can verify user and get selected stores, after marking dead and replacing a store', async function () {
        // mark dead to replace a store
        await time.increase(510);
        await secretManager.markStoreDead(addrs[17]);

        // it will only return the selected stores that have ack the secret
        const selectedStores = await secretManager.verifyUserAndGetSelectedStores(1, addrs[0]);
        expect(selectedStores.length).to.eq(2);
        expect(selectedStores).to.include.members([addrs[18], addrs[19]]);
        expect(selectedStores).to.not.include.members([addrs[17]]);
    });
});

describe("SecretManager - Renounce secrets", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let usdcToken: USDCoin;
    let teeManager: TeeManager;
    let executors: Executors;
    let secretStore: SecretStoreMock;
    let secretManager: SecretManager;

    before(async function () {
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
        const stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
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

        const TeeManager = await ethers.getContractFactory("TeeManager");
        teeManager = await upgrades.deployProxy(
            TeeManager,
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
                    10 ** 6
                ]
            },
        ) as unknown as TeeManager;

        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        ) as unknown as Executors;

        const SecretStore = await ethers.getContractFactory("SecretStoreMock");
        secretStore = await SecretStore.deploy(teeManager.target) as unknown as SecretStoreMock;

        let env = 1;
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        // await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        await executors.initTree(1);
        // await secretStore.initTree(1);

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

        let noOfNodesToSelect = 3,
            globalMaxStoreSize = 1e6,
            globalMinStoreDuration = 10,
            globalMaxStoreDuration = 1e6,
            acknowledgementTimeout = 120,
            markAliveTimeout = 900,
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
                    teeManager.target,
                    executors.target,
                    secretStore.target
                ]
            },
        ) as unknown as SecretManager;

        await secretStore.setSecretManager(secretManager.target);
        await usdcToken.approve(secretManager.target, parseUnits("10000", 6));

        await stakingToken.transfer(addrs[1], 10n ** 20n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 20n);

        // REGISTER SECRET STORE ENCLAVES
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest();
        let jobCapacity = 20,
            storageCapacity = 1e9,
            stakeAmount = parseUnits("10");	// 10 POND
        for (let index = 0; index < 3; index++) {
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[17 + index],
                image2,
                wallets[14],
                timestamp - 540000
            );

            let signedDigest = await registerTeeNodeSignature(
                addrs[1],
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                wallets[17 + index]
            );

            await teeManager.connect(signers[1]).registerTeeNode(
                attestationSign,
                attestation,
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                signedDigest,
                stakeAmount
            );
        }

        await secretStore.setStoresToSelect([addrs[17], addrs[18], addrs[19]]);
        // CREATE SECRET
        let sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, []);

        await time.increase(10);
        let secretId = 1;
        signTimestamp = await time.latest();
        for (let index = 0; index < 3; index++) {
            let signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17 + index]);
            await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);
        }
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can renounce secrets", async function () {
        await time.increase(100);
        let userSecret = await secretManager.userStorage(1);
        let nodeOwnerBalInitial = await usdcToken.balanceOf(addrs[1]);

        let tx = await secretStore.renounceSecrets(addrs[17], addrs[1]);
        await tx.wait();
        await expect(tx)
            .to.be.not.reverted;

        let selectedStores = await secretManager.getSelectedEnclaves(1);
        let selectedStoresAddresses = selectedStores.map(store => store.enclaveAddress);
        expect(selectedStoresAddresses).to.deep.eq(["0x1", addrs[18], addrs[19]]);

        // calculating usdc payment to tee node
        let endTimestamp = BigInt((await tx.getBlock())?.timestamp as number),
            startTimestamp = userSecret.ackTimestamp,
            secretStoreFeeRate = 10n;

        let usdcPayment = (endTimestamp - startTimestamp) * userSecret.sizeLimit * secretStoreFeeRate;
        let nodeOwnerBalFinal = await usdcToken.balanceOf(addrs[1]);
        expect(nodeOwnerBalFinal - nodeOwnerBalInitial).to.eq(usdcPayment);

        // checking updated usdc deposit amount
        expect((await secretManager.userStorage(1)).usdcDeposit).to.eq(parseUnits("30", 6) - usdcPayment);
    });

    it("can renounce secrets after alive check", async function () {
        await time.increase(100);
        let signTimestamp = await time.latest(),
            signedDigest = await createAliveSignature(signTimestamp, wallets[17]);
        await secretManager.markStoreAlive(signTimestamp, signedDigest);

        let userSecret = await secretManager.userStorage(1);
        let nodeOwnerBalInitial = await usdcToken.balanceOf(addrs[1]);

        let tx = await secretStore.renounceSecrets(addrs[17], addrs[1]);
        await tx.wait();
        await expect(tx)
            .to.be.not.reverted;

        // calculating usdc payment to tee node
        let endTimestamp = BigInt((await tx.getBlock())?.timestamp as number),
            startTimestamp = (await secretStore.secretStores(addrs[17])).lastAliveTimestamp,
            secretStoreFeeRate = 10n;

        let usdcPayment = (endTimestamp - startTimestamp) * userSecret.sizeLimit * secretStoreFeeRate;
        let nodeOwnerBalFinal = await usdcToken.balanceOf(addrs[1]);
        expect(nodeOwnerBalFinal - nodeOwnerBalInitial).to.eq(usdcPayment);

        // calculating updated usdc deposit amount
        let ackTimestamp = userSecret.ackTimestamp;
        usdcPayment = (endTimestamp - ackTimestamp) * userSecret.sizeLimit * secretStoreFeeRate;
        expect((await secretManager.userStorage(1)).usdcDeposit).to.eq(parseUnits("30", 6) - usdcPayment);
    });

    it("cannot renounce secrets without secret store contract", async function () {
        await expect(secretManager.renounceSecrets(addrs[17], addrs[0], [1], 100))
            .to.be.revertedWithCustomError(secretManager, "SecretManagerCallerIsNotSecretStore");
    });

    it("can renounce secrets after termination", async function () {
        await time.increase(810);
        let secretId = 1;
        let userSecret = await secretManager.userStorage(1);
        let nodeOwnerBalInitial = await usdcToken.balanceOf(addrs[1]);
        let secretOwnerBalInitial = await usdcToken.balanceOf(addrs[0]);

        // renounce secret from 1st selected store
        await expect(secretStore.renounceSecrets(addrs[17], addrs[1]))
            .to.be.not.reverted;

        let selectedStores = await secretManager.getSelectedEnclaves(secretId);
        let selectedStoresAddresses = selectedStores.map(store => store.enclaveAddress);
        expect(selectedStoresAddresses).to.deep.eq([addrs[19], addrs[18]]);

        // calculating usdc payment to 1st tee node
        let endTimestamp = userSecret.endTimestamp,
            startTimestamp = userSecret.ackTimestamp,
            secretStoreFeeRate = 10n;

        let usdcPayment = (endTimestamp - startTimestamp) * userSecret.sizeLimit * secretStoreFeeRate;
        let nodeOwnerBalFinal = await usdcToken.balanceOf(addrs[1]);
        expect(nodeOwnerBalFinal - nodeOwnerBalInitial).to.eq(usdcPayment);

        // calculating updated usdc deposit amount
        let ackTimestamp = userSecret.ackTimestamp;
        usdcPayment = (endTimestamp - ackTimestamp) * userSecret.sizeLimit * secretStoreFeeRate;
        expect((await secretManager.userStorage(1)).usdcDeposit).to.eq(parseUnits("30", 6) - usdcPayment);

        nodeOwnerBalInitial = await usdcToken.balanceOf(addrs[1]);
        // renounce secret from 2nd selected store
        await expect(secretStore.renounceSecrets(addrs[18], addrs[1]))
            .to.be.not.reverted;

        selectedStores = await secretManager.getSelectedEnclaves(secretId);
        selectedStoresAddresses = selectedStores.map(store => store.enclaveAddress);
        expect(selectedStoresAddresses).to.deep.eq([addrs[19]]);

        // checking usdc payment to 2nd tee node
        nodeOwnerBalFinal = await usdcToken.balanceOf(addrs[1]);
        expect(nodeOwnerBalFinal - nodeOwnerBalInitial).to.eq(usdcPayment);

        // checking updated usdc deposit amount
        expect((await secretManager.userStorage(1)).usdcDeposit).to.eq(parseUnits("30", 6) - (2n * usdcPayment));

        nodeOwnerBalInitial = await usdcToken.balanceOf(addrs[1]);
        // renounce secret from 3rd selected store
        await expect(secretStore.renounceSecrets(addrs[19], addrs[1]))
            .to.be.not.reverted;

        selectedStores = await secretManager.getSelectedEnclaves(secretId);
        selectedStoresAddresses = selectedStores.map(store => store.enclaveAddress);    
        expect(selectedStoresAddresses).to.deep.eq([]);

        // checking usdc payment to 3rd tee node
        nodeOwnerBalFinal = await usdcToken.balanceOf(addrs[1]);
        expect(nodeOwnerBalFinal - nodeOwnerBalInitial).to.eq(usdcPayment);

        // secret data will be deleted after last selected enclave renounces the secret
        expect((await secretManager.userStorage(secretId)).owner).to.eq(ZeroAddress);        
        expect((await secretManager.userStorage(1)).usdcDeposit).to.eq(0);
        
        // checking refund amount to secret owner
        let secretOwnerBalFinal = await usdcToken.balanceOf(addrs[0]);
        expect(secretOwnerBalFinal - secretOwnerBalInitial).to.eq(parseUnits("30", 6) - (3n * usdcPayment));
    });
});

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

async function registerTeeNodeSignature(
    owner: string,
    jobCapacity: number,
    storageCapacity: number,
    env: number,
    signTimestamp: number,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.TeeManager',
        version: '1',
    };

    const types = {
        Register: [
            { name: 'owner', type: 'address' },
            { name: 'jobCapacity', type: 'uint256' },
            { name: 'storageCapacity', type: 'uint256' },
            { name: 'env', type: 'uint8' },
            { name: 'signTimestamp', type: 'uint256' }
        ]
    };

    const value = {
        owner,
        jobCapacity,
        storageCapacity,
        env,
        signTimestamp
    };

    const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
    return ethers.Signature.from(sign).serialized;
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

async function createAliveSignature(
    // storageTimeUsage: bigint,
    // terminatedSecretIds: number[] | bigint[],
    signTimestamp: number,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.SecretManager',
        version: '1',
    };

    const types = {
        Alive: [
            // { name: 'storageTimeUsage', type: 'uint256' },
            // { name: 'terminatedSecretIds', type: 'uint256[]' },
            { name: 'signTimestamp', type: 'uint256' }
        ]
    };

    const value = {
        // storageTimeUsage,
        // terminatedSecretIds,
        signTimestamp
    };
    // console.log("value: ", value);

    const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
    return ethers.Signature.from(sign).serialized;
}

function walletForIndex(idx: number): Wallet {
    let wallet = ethers.HDNodeWallet.fromPhrase(
        "test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString()
    );

    return new Wallet(wallet.privateKey);
}

function normalize(key: string): string {
    return '0x' + key.substring(4);
}
