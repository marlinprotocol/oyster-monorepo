import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, Wallet, ZeroAddress, keccak256, parseUnits, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import {
    AttestationAutherUpgradeable,
    AttestationVerifier,
    Executors,
    Jobs,
    Pond,
    USDCoin,
    SecretJobsUser,
    SecretStore,
    TeeManager,
    SecretManager
} from "../../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../../utils/testSuite";
import { testERC165 } from '../../helpers/erc165';

const image1: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48)),
};

const image2: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48)),
};

const image3: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48)),
};

const image4: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48)),
};

const image5: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48)),
};

const image6: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48)),
};

const image7: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48)),
};

describe("Jobs - Init", function () {
    let signers: Signer[];
    let addrs: string[];
    let staking_token: string;
    let usdc_token: string;
    let staking_payment_pool: string;
    let usdc_payment_pool: string;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));

        staking_token = addrs[1];
        usdc_token = addrs[1];
        staking_payment_pool = addrs[1];
        usdc_payment_pool = addrs[1];
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("deploys with initialization disabled", async function () {

        const Jobs = await ethers.getContractFactory("contracts/secret-storage/job-allocation/Jobs.sol:Jobs");
        const jobs = await Jobs.deploy(
            staking_token,
            usdc_token,
            100,
            100,
            3,
            staking_payment_pool,
            usdc_payment_pool
        );

        await expect(
            jobs.initialize(addrs[0]),
        ).to.be.revertedWithCustomError(jobs, "InvalidInitialization");
    });

    it("deploys as proxy and initializes", async function () {
        const Jobs = await ethers.getContractFactory("contracts/secret-storage/job-allocation/Jobs.sol:Jobs");
        const jobs = await upgrades.deployProxy(
            Jobs,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    staking_token,
                    usdc_token,
                    100,
                    100,
                    3,
                    staking_payment_pool,
                    usdc_payment_pool
                ]
            },
        );

        expect(await jobs.hasRole(await jobs.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    });

    it("cannot initialize with zero address as admin", async function () {
        const Jobs = await ethers.getContractFactory("contracts/secret-storage/job-allocation/Jobs.sol:Jobs");
        await expect(
            upgrades.deployProxy(
                Jobs,
                [ZeroAddress],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        staking_token,
                        usdc_token,
                        100,
                        100,
                        3,
                        staking_payment_pool,
                        usdc_payment_pool
                    ]
                },
            )
        ).to.be.revertedWithCustomError(Jobs, "JobsZeroAddressAdmin");
    });

    it("cannot initialize with zero address as staking token", async function () {
        const Jobs = await ethers.getContractFactory("contracts/secret-storage/job-allocation/Jobs.sol:Jobs");
        await expect(
            upgrades.deployProxy(
                Jobs,
                [addrs[0]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        ZeroAddress,
                        usdc_token,
                        100,
                        100,
                        3,
                        staking_payment_pool,
                        usdc_payment_pool
                    ]
                },
            )
        ).to.be.revertedWithCustomError(Jobs, "JobsZeroAddressStakingToken");
    });

    it("cannot initialize with zero address as usdc token", async function () {
        const Jobs = await ethers.getContractFactory("contracts/secret-storage/job-allocation/Jobs.sol:Jobs");
        await expect(
            upgrades.deployProxy(
                Jobs,
                [addrs[0]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        staking_token,
                        ZeroAddress,
                        100,
                        100,
                        3,
                        staking_payment_pool,
                        usdc_payment_pool
                    ]
                },
            )
        ).to.be.revertedWithCustomError(Jobs, "JobsZeroAddressUsdcToken");
    });

    it("upgrades", async function () {
        const Jobs = await ethers.getContractFactory("contracts/secret-storage/job-allocation/Jobs.sol:Jobs");
        const jobs = await upgrades.deployProxy(
            Jobs,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    staking_token,
                    usdc_token,
                    100,
                    100,
                    3,
                    staking_payment_pool,
                    usdc_payment_pool
                ]
            },
        );

        await upgrades.upgradeProxy(
            jobs.target,
            Jobs,
            {
                kind: "uups",
                constructorArgs: [
                    addrs[2],
                    addrs[2],
                    200,
                    200,
                    5,
                    addrs[2],
                    addrs[2]
                ]
            }
        );

        expect(await jobs.hasRole(await jobs.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        expect(await jobs.STAKING_TOKEN()).to.be.eq(addrs[2]);
        expect(await jobs.USDC_TOKEN()).to.be.eq(addrs[2]);
        expect(await jobs.SIGN_MAX_AGE()).to.be.eq(200);
        expect(await jobs.EXECUTION_BUFFER_TIME()).to.be.eq(200);
        expect(await jobs.NO_OF_NODES_TO_SELECT()).to.be.eq(5);
        expect(await jobs.STAKING_PAYMENT_POOL()).to.be.eq(addrs[2]);
        expect(await jobs.USDC_PAYMENT_POOL()).to.be.eq(addrs[2]);
    });

    it("does not upgrade without admin", async function () {
        const Jobs = await ethers.getContractFactory("contracts/secret-storage/job-allocation/Jobs.sol:Jobs");
        const jobs = await upgrades.deployProxy(
            Jobs,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    staking_token,
                    usdc_token,
                    100,
                    100,
                    3,
                    staking_payment_pool,
                    usdc_payment_pool
                ]
            },
        );

        await expect(
            upgrades.upgradeProxy(jobs.target, Jobs.connect(signers[1]), {
                kind: "uups",
                constructorArgs: [
                    staking_token,
                    usdc_token,
                    100,
                    100,
                    3,
                    staking_payment_pool,
                    usdc_payment_pool
                ]
            }),
        ).to.be.revertedWithCustomError(Jobs, "AccessControlUnauthorizedAccount");
    });

});

testERC165(
    "Jobs - ERC165",
    async function (_signers: Signer[], addrs: string[]) {
        const Jobs = await ethers.getContractFactory("contracts/secret-storage/job-allocation/Jobs.sol:Jobs");
        const jobs = await upgrades.deployProxy(
            Jobs,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    addrs[1],
                    addrs[1],
                    100,
                    100,
                    3,
                    addrs[1],
                    addrs[1]
                ]
            },
        );
        return jobs;
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

describe("Jobs - Global Execution Env", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let teeManager: TeeManager;
    let executors: Executors;
    let secretStore: SecretStore;
    let jobs: Jobs;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        const Pond = await ethers.getContractFactory("Pond");
        token = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        }) as unknown as Pond;

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
                    token.target,
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

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

        let usdcToken = addrs[2],
            signMaxAge = 100,
            executionBufferTime = 100,
            noOfNodesToSelect = 3,
            stakingPaymentPoolAddress = addrs[3],
            usdcPaymentPoolAddress = addrs[4];
        const Jobs = await ethers.getContractFactory("contracts/secret-storage/job-allocation/Jobs.sol:Jobs");
        jobs = await upgrades.deployProxy(
            Jobs,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    usdcToken,
                    signMaxAge,
                    executionBufferTime,
                    noOfNodesToSelect,
                    stakingPaymentPoolAddress,
                    usdcPaymentPoolAddress
                ]
            },
        ) as unknown as Jobs;

        await executors.grantRole(await executors.JOBS_ROLE(), jobs.target);
        await secretStore.grantRole(await secretStore.JOBS_ROLE(), jobs.target);

        await jobs.setExecutors(executors.target);
        await jobs.setSecretStore(secretStore.target);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it('can add global execution env', async function () {
        let env = 1,
            executionFeePerMs = 100,
            stakingRewardPerMs = 100;
        await expect(jobs.addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs)).to.emit(jobs, "GlobalEnvAdded");

        let executionEnv = await jobs.executionEnv(env);
        expect(executionEnv.executionFeePerMs).to.eq(executionFeePerMs);
        expect(executionEnv.stakingRewardPerMs).to.eq(stakingRewardPerMs);
        expect(await executors.isTreeInitialized(env)).to.be.true;
        expect(await executors.nodesInTree(env)).to.eq(0);
        expect(await secretStore.isTreeInitialized(env)).to.be.true;
        expect(await secretStore.nodesInTree(env)).to.eq(0);
    });

    it('cannot add global execution env without admin account', async function () {
        let env = 1,
            executionFeePerMs = 100,
            stakingRewardPerMs = 100;
        await expect(jobs.connect(signers[1]).addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs))
            .to.be.revertedWithCustomError(jobs, "AccessControlUnauthorizedAccount");
    });

    it('cannot add already supported global execution env again', async function () {
        let env = 1,
            executionFeePerMs = 100,
            stakingRewardPerMs = 100;
        await jobs.addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs);

        await expect(jobs.addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs))
            .to.be.revertedWithCustomError(executors, "ExecutorsGlobalEnvAlreadySupported");
    });

    it('can remove global execution env', async function () {
        let env = 1,
            executionFeePerMs = 100,
            stakingRewardPerMs = 100;
        await jobs.addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs);
        await expect(jobs.removeGlobalEnv(env)).to.emit(jobs, "GlobalEnvRemoved");

        let executionEnv = await jobs.executionEnv(env);
        expect(executionEnv.executionFeePerMs).to.eq(0);
        expect(executionEnv.stakingRewardPerMs).to.eq(0);
        expect(await executors.isTreeInitialized(env)).to.be.false;
        expect(await secretStore.isTreeInitialized(env)).to.be.false;
    });

    it('cannot remove global execution env without admin account', async function () {
        let env = 1;
        await expect(jobs.connect(signers[1]).removeGlobalEnv(env))
            .to.be.revertedWithCustomError(jobs, "AccessControlUnauthorizedAccount");
    });

    it('cannot remove unsupported global execution env', async function () {
        let env = 1;
        await expect(jobs.removeGlobalEnv(env))
            .to.be.revertedWithCustomError(executors, "ExecutorsGlobalEnvAlreadyUnsupported");
    });

    it('can add multiple envs and remove them', async function () {
        let env = 1,
            executionFeePerMs = 100,
            stakingRewardPerMs = 150;
        await jobs.addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs);

        let executionEnv = await jobs.executionEnv(env);
        expect(executionEnv.executionFeePerMs).to.eq(executionFeePerMs);
        expect(executionEnv.stakingRewardPerMs).to.eq(stakingRewardPerMs);
        expect(await executors.isTreeInitialized(env)).to.be.true;
        expect(await executors.nodesInTree(env)).that.eq(0);
        expect(await secretStore.isTreeInitialized(env)).to.be.true;
        expect(await secretStore.nodesInTree(env)).that.eq(0);

        await token.transfer(addrs[1], 100000);
        await token.connect(signers[1]).approve(teeManager.target, 10000);

        let jobCapacity = 20,
            storageCapacity = 1e9,
            stakeAmount = 10,
            timestamp = await time.latest() * 1000;
        for (let index = 0; index < 2; index++) {
            let signTimestamp = await time.latest() - 540;
            // Executor index using wallet 10 + index as enclave address
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[10 + index],
                image2,
                wallets[14],
                timestamp - 540000
            );

            let signedDigest = await registerTeeNodeSignature(
                addrs[1], jobCapacity, storageCapacity, env, signTimestamp, wallets[10 + index]
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

        env = 2,
        executionFeePerMs = 200,
        stakingRewardPerMs = 250;
        await jobs.addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs);

        executionEnv = await jobs.executionEnv(env);
        expect(executionEnv.executionFeePerMs).to.eq(executionFeePerMs);
        expect(executionEnv.stakingRewardPerMs).to.eq(stakingRewardPerMs);
        expect(await executors.isTreeInitialized(env)).to.be.true;
        expect(await executors.nodesInTree(env)).that.eq(0);
        expect(await secretStore.isTreeInitialized(env)).to.be.true;
        expect(await secretStore.nodesInTree(env)).that.eq(0);

        for (let index = 0; index < 3; index++) {
            let signTimestamp = await time.latest() - 540;
            // Executor index using wallet 12 + index as enclave address
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[12 + index],
                image2,
                wallets[14],
                timestamp - 540000
            );

            let signedDigest = await registerTeeNodeSignature(
                addrs[1], jobCapacity, storageCapacity, env, signTimestamp, wallets[12 + index]
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

        expect(await executors.nodesInTree(1)).that.eq(2);
        expect(await executors.nodesInTree(2)).that.eq(3);
        expect(await secretStore.nodesInTree(1)).that.eq(2);
        expect(await secretStore.nodesInTree(2)).that.eq(3);

        await jobs.removeGlobalEnv(1);

        executionEnv = await jobs.executionEnv(1);
        expect(executionEnv.executionFeePerMs).to.eq(0);
        expect(executionEnv.stakingRewardPerMs).to.eq(0);
        expect(await executors.isTreeInitialized(1)).to.be.false;
        expect(await executors.isTreeInitialized(2)).to.be.true;
        expect(await secretStore.isTreeInitialized(1)).to.be.false;
        expect(await secretStore.isTreeInitialized(2)).to.be.true;

        await jobs.removeGlobalEnv(2);

        executionEnv = await jobs.executionEnv(2);
        expect(executionEnv.executionFeePerMs).to.eq(0);
        expect(executionEnv.stakingRewardPerMs).to.eq(0);
        expect(await executors.isTreeInitialized(2)).to.be.false;
        expect(await secretStore.isTreeInitialized(2)).to.be.false;
    });

    it('can set tee manager', async function () {
        await expect(jobs.setTeeManager(addrs[1])).to.be.not.reverted;
        expect(await jobs.TEE_MANAGER()).to.eq(addrs[1]);
    });

    it('cannot set tee manager without DEFAULT_ADMIN_ROLE', async function () {
        await expect(jobs.connect(signers[1]).setTeeManager(addrs[1]))
            .to.be.revertedWithCustomError(jobs, "AccessControlUnauthorizedAccount");
    });

    it('can set executors', async function () {
        await expect(jobs.setExecutors(addrs[1])).to.be.not.reverted;
        expect(await jobs.EXECUTORS()).to.eq(addrs[1]);
    });

    it('cannot set executors without DEFAULT_ADMIN_ROLE', async function () {
        await expect(jobs.connect(signers[1]).setExecutors(addrs[1]))
            .to.be.revertedWithCustomError(jobs, "AccessControlUnauthorizedAccount");
    });

    it('can set secret store', async function () {
        await expect(jobs.setSecretStore(addrs[1])).to.be.not.reverted;
        expect(await jobs.SECRET_STORE()).to.eq(addrs[1]);
    });

    it('cannot set secret store without DEFAULT_ADMIN_ROLE', async function () {
        await expect(jobs.connect(signers[1]).setSecretStore(addrs[1]))
            .to.be.revertedWithCustomError(jobs, "AccessControlUnauthorizedAccount");
    });

    it('can set secret manager', async function () {
        await expect(jobs.setSecretManager(addrs[1])).to.be.not.reverted;
        expect(await jobs.SECRET_MANAGER()).to.eq(addrs[1]);
    });

    it('cannot set secret manager without DEFAULT_ADMIN_ROLE', async function () {
        await expect(jobs.connect(signers[1]).setSecretManager(addrs[1]))
            .to.be.revertedWithCustomError(jobs, "AccessControlUnauthorizedAccount");
    });
});

describe("Jobs - Create", function () {
    let signers: Signer[];
    let addrs: string[];
    let staking_token: Pond;
    let usdc_token: USDCoin;
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let teeManager: TeeManager;
    let executors: Executors;
    let jobs: Jobs;
    let secretManager: SecretManager;
    let staking_payment_pool: string;
    let usdc_payment_pool: string;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));
        staking_payment_pool = addrs[1];
        usdc_payment_pool = addrs[1];

        const Pond = await ethers.getContractFactory("Pond");
        staking_token = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        }) as unknown as Pond;

        const USDCoin = await ethers.getContractFactory("USDCoin");
        usdc_token = await upgrades.deployProxy(USDCoin, [addrs[0]], {
            kind: "uups",
        }) as unknown as USDCoin;

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        let teeImages = [image4, image5, image6, image7];
        const TeeManager = await ethers.getContractFactory("TeeManager");
        teeManager = await upgrades.deployProxy(
            TeeManager,
            [addrs[0], teeImages],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    staking_token.target,
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
        let secretStore = await upgrades.deployProxy(
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

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

        const Jobs = await ethers.getContractFactory("contracts/secret-storage/job-allocation/Jobs.sol:Jobs");
        jobs = await upgrades.deployProxy(
            Jobs,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    staking_token.target,
                    usdc_token.target,
                    100,
                    100,
                    3,
                    staking_payment_pool,
                    usdc_payment_pool
                ]
            },
        ) as unknown as Jobs;

        // Grant role to jobs contract on executor
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), jobs.target);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), jobs.target);

        await jobs.setExecutors(executors.target);
        await jobs.setSecretStore(secretStore.target);

        let env = 1,
            executionFeePerMs = 1,
            stakingRewardPerMs = 1;
        await jobs.addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs);

        // Register Executors. Owner is addrs[1]
        await staking_token.transfer(addrs[1], 10n ** 20n);
        await staking_token.connect(signers[1]).approve(teeManager.target, 10n ** 20n);

        const timestamp = await time.latest() * 1000;
        let jobCapacity = 3,
            storageCapacity = 1e9,
            stakeAmount = 10n ** 19n;

        let signTimestamp = await time.latest() - 540;
        for (let index = 0; index < 4; index++) {
            // Executor index using wallet 17 + index as enclave address
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[17 + index],
                teeImages[index],
                wallets[14],
                timestamp - 540000
            );

            let signedDigest = await registerTeeNodeSignature(
                addrs[1], jobCapacity, storageCapacity, env, signTimestamp, wallets[17 + index]
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

        await usdc_token.transfer(addrs[1], 10n ** 6n);
        await usdc_token.connect(signers[1]).approve(jobs.target, 10n ** 6n);

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
                    usdc_token.target,
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

        await usdc_token.approve(secretManager.target, parseUnits("10000", 6));
        await jobs.setSecretManager(secretManager.target);
        await secretStore.setSecretManager(secretManager.target);

        // CREATE SECRET
        let sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, [addrs[1]]);

        // ACKNOWLEDGE SECRET
        let secretId = 1;
        let selectedStores = await secretManager.getSelectedEnclaves(secretId);
        for (let i = 0; i < selectedStores.length; i++) {
            let index = addrs.indexOf(selectedStores[i].enclaveAddress);
            const wallet = wallets[index];
            let signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallet);
            await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);
        }
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can relay job with secret", async function () {
        let env = 1,
            secretId = 1,
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobOwner = addrs[1];
        let tx = await jobs.connect(signers[1]).createJob(env, secretId, codeHash, codeInputs, deadline);
        await tx.wait();

        // Since it is a first job.
        let jobId = 0;
        let selectedExecutors = await jobs.getSelectedExecutors(jobId);
        await expect(tx)
            .to.emit(jobs, "JobCreated")
            .withArgs(jobId, env, jobOwner, secretId, codeHash, codeInputs, deadline, selectedExecutors);

        let job = await jobs.jobs(jobId);
        expect(job.jobOwner).to.eq(jobOwner);
        expect(job.deadline).to.eq(deadline);
        expect(job.execStartTime).to.eq((await tx.getBlock())?.timestamp);
        expect(job.env).to.eq(env);
        expect(selectedExecutors.length).to.eq(3);
        expect(new Set(selectedExecutors).size).to.eq(selectedExecutors.length);

        for (let index = 0; index < selectedExecutors.length; index++) {
            const executor = selectedExecutors[index];
            expect([addrs[17], addrs[18], addrs[19], addrs[20]]).to.contain(executor);
        }
    });

    // it("can relay job without secret", async function () {
    //     let env = 1,
    //         secretId = 0,
    //         codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
    //         codeInputs = solidityPacked(["string"], ["codeInput"]),
    //         deadline = 10000,
    //         jobOwner = addrs[1];
    //     let tx = await jobs.connect(signers[1]).createJob(env, secretId, codeHash, codeInputs, deadline);
    //     await tx.wait();
    //     await expect(tx).to.emit(jobs, "JobCreated");

    //     // Since it is a first job.
    //     let jobId = 0;
    //     let job = await jobs.jobs(jobId);

    //     expect(job.jobOwner).to.eq(jobOwner);
    //     expect(job.deadline).to.eq(deadline);
    //     expect(job.execStartTime).to.eq((await tx.getBlock())?.timestamp);
    //     expect(job.env).to.eq(env);

    //     let selectedExecutors = await jobs.getSelectedExecutors(jobId);
    //     console.log("select: ", selectedExecutors, selectedExecutors.length);
    //     for (let index = 0; index < selectedExecutors.length; index++) {
    //         const executor = selectedExecutors[index];
    //         expect([addrs[17], addrs[18], addrs[19], addrs[20]]).to.contain(executor);
    //     }
    // });

    it("cannot relay job without secret", async function () {
        let env = 1,
            secretId = 0,
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000;

        await expect(jobs.connect(signers[1]).createJob(env, secretId, codeHash, codeInputs, deadline))
            .to.revertedWithCustomError(jobs, "JobsInvalidSecretId");
    });

    it("cannot relay job with unsupported execution env", async function () {
        let env = 2,
            secretId = 1,
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000;

        await expect(jobs.connect(signers[1]).createJob(env, secretId, codeHash, codeInputs, deadline))
            .to.revertedWithCustomError(executors, "ExecutorsUnsupportedEnv");
    });

    // it("cannot relay job when a minimum no. of executor nodes are not available", async function () {
    //     let secretId = 1;
    //     // remove the unselected store
    //     let selectedStores = await secretManager.getSelectedEnclaves(secretId);
    //     let stores = [addrs[17], addrs[18], addrs[19], addrs[20]];
    //     for (let i = 0; i < selectedStores.length; i++) {
    //         let index = stores.indexOf(selectedStores[i].enclaveAddress);
    //         stores.splice(index, 1);
    //     }
    //     let unselectedStore = stores[0];
    //     await teeManager.connect(signers[1]).drainTeeNode(unselectedStore);

    //     let env = 1,
    //         codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
    //         codeInputs = solidityPacked(["string"], ["codeInput"]),
    //         deadline = 10000;

    //     // max 3 jobs can be assigned
    //     await jobs.connect(signers[1]).createJob(env, secretId, codeHash, codeInputs, deadline);
    //     await jobs.connect(signers[1]).createJob(env, secretId, codeHash, codeInputs, deadline);
    //     await jobs.connect(signers[1]).createJob(env, secretId, codeHash, codeInputs, deadline);
    //     await expect(jobs.connect(signers[1]).createJob(env, secretId, codeHash, codeInputs, deadline))
    //         .to.revertedWithCustomError(executors, "ExecutorsUnavailableStores");
    // });

    it("cannot relay job after all the executors are fully occupied", async function () {
        let secretId = 1;
        // remove the unselected store
        let selectedStores = await secretManager.getSelectedEnclaves(secretId);
        let stores = [addrs[17], addrs[18], addrs[19], addrs[20]];
        for (let i = 0; i < selectedStores.length; i++) {
            let index = stores.indexOf(selectedStores[i].enclaveAddress);
            stores.splice(index, 1);
        }
        let unselectedStore = stores[0];
        await teeManager.connect(signers[1]).drainTeeNode(unselectedStore);

        let env = 1,
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000;

        for (let index = 1; index <= 3; index++) {
            await expect(jobs.connect(signers[1]).createJob(env, secretId, codeHash, codeInputs, deadline))
                .to.emit(jobs, "JobCreated");
        }
        await expect(jobs.connect(signers[1]).createJob(env, secretId, codeHash, codeInputs, deadline))
            .to.revertedWithCustomError(executors, "ExecutorsUnavailableStores");
    });
});

describe("Jobs - Output", function () {
    let signers: Signer[];
    let addrs: string[];
    let staking_token: Pond;
    let usdc_token: USDCoin;
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let teeManager: TeeManager;
    let executors: Executors;
    let jobs: Jobs;
    let secretManager: SecretManager;
    let staking_payment_pool: string;
    let usdc_payment_pool: string;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));
        staking_payment_pool = addrs[4];
        usdc_payment_pool = addrs[4];

        const Pond = await ethers.getContractFactory("Pond");
        staking_token = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        }) as unknown as Pond;

        const USDCoin = await ethers.getContractFactory("USDCoin");
        usdc_token = await upgrades.deployProxy(USDCoin, [addrs[0]], {
            kind: "uups",
        }) as unknown as USDCoin;

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        let teeImages = [image4, image5, image6, image7];
        const TeeManager = await ethers.getContractFactory("TeeManager");
        teeManager = await upgrades.deployProxy(
            TeeManager,
            [addrs[0], teeImages],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    staking_token.target,
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
        let secretStore = await upgrades.deployProxy(
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

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

        const Jobs = await ethers.getContractFactory("contracts/secret-storage/job-allocation/Jobs.sol:Jobs");
        jobs = await upgrades.deployProxy(
            Jobs,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    staking_token.target,
                    usdc_token.target,
                    600,
                    100,
                    3,
                    staking_payment_pool,
                    usdc_payment_pool
                ]
            },
        ) as unknown as Jobs;

        // Grant role to jobs contract on executor
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), jobs.target);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), jobs.target);

        await jobs.setExecutors(executors.target);
        await jobs.setSecretStore(secretStore.target);

        let env = 1,
            executionFeePerMs = 1,
            stakingRewardPerMs = 1;
        await jobs.addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs);

        // Register Executors. Owner is addrs[1]
        await staking_token.transfer(addrs[1], 10n ** 20n);
        await staking_token.connect(signers[1]).approve(teeManager.target, 10n ** 20n);

        let jobCapacity = 20,
            storageCapacity = 1e9,
            stakeAmount = 10n ** 19n;
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        for (let index = 0; index < 3; index++) {
            // Executor index using wallet 17 + index as enclave address
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[17 + index],
                teeImages[index],
                wallets[14],
                timestamp - 540000
            );

            let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
                wallets[17 + index]);

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
        // RELAY JOB
        await usdc_token.transfer(addrs[3], 10n ** 6n);
        await usdc_token.connect(signers[3]).approve(jobs.target, 10n ** 6n);

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
                    usdc_token.target,
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
        await usdc_token.approve(secretManager.target, parseUnits("10000", 6));
        await jobs.setSecretManager(secretManager.target);
        await jobs.setTeeManager(teeManager.target);

        // CREATE SECRET
        let sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, [addrs[3]]);

        // ACKNOWLEDGE SECRET
        let secretId = 1;
        let selectedStores = await secretManager.getSelectedEnclaves(secretId);
        for (let i = 0; i < selectedStores.length; i++) {
            let index = addrs.indexOf(selectedStores[i].enclaveAddress);
            const wallet = wallets[index];
            let signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallet);
            await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);
        }

        let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000;
        await jobs.connect(signers[3]).createJob(env, secretId, codeHash, codeInputs, deadline);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    // submit 1 output
    it("can submit output by selected executor node", async function () {
        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest() - 540;

        let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
        let tx = await jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );
        await expect(tx).to.emit(jobs, "JobResponded")
            .and.to.emit(jobs, "JobResultCallbackCalled").withArgs(jobId, true);
        // check active jobs and reputation for submitter
        let executor = await executors.executors(addrs[17]);
        expect(executor.activeJobs).to.eq(0);
        expect(executor.reputation).to.eq(1010);
        // check active jobs and reputation for pending submitter
        executor = await executors.executors(addrs[18]);
        expect(executor.activeJobs).to.eq(1);
        expect(executor.reputation).to.eq(1000);

        executor = await executors.executors(addrs[19]);
        expect(executor.activeJobs).to.eq(1);
        expect(executor.reputation).to.eq(1000);

        // check usdc balance of executor
        expect(await usdc_token.balanceOf(addrs[1])).to.eq(100n * 4n / 9n);
        // check usdc balance of payment pool
        expect(await usdc_token.balanceOf(usdc_payment_pool)).to.eq(100n);
        // check usdc balance of job owner
        expect(await usdc_token.balanceOf(addrs[3])).to.eq(10n ** 6n - 100n * 2n);
        // check stakes of all executors
        for (let index = 17; index < 20; index++) {
            const teeNode = await teeManager.teeNodes(addrs[index]);
            expect(teeNode.stakeAmount).to.eq(10n ** 19n);
        }
    });

    // submit 2 output
    it("two output submits by selected executor nodes", async function () {
        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest() - 540;

        let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
        let tx = await jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );
        await expect(tx).to.emit(jobs, "JobResponded")
            .and.to.emit(jobs, "JobResultCallbackCalled").withArgs(jobId, true);

        // submit 2nd output
        output = solidityPacked(["string"], ["it is the output"]);
        signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[18]);
        tx = await jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );
        await expect(tx).to.emit(jobs, "JobResponded").to.not.emit(jobs, "JobResultCallbackCalled");

        // check active jobs and reputation for submitter
        let executor = await executors.executors(addrs[17]);
        expect(executor.activeJobs).to.eq(0);
        expect(executor.reputation).to.eq(1010);
        executor = await executors.executors(addrs[18]);
        expect(executor.activeJobs).to.eq(0);
        expect(executor.reputation).to.eq(995);

        // check active jobs and reputation for pending submitter
        executor = await executors.executors(addrs[19]);
        expect(executor.activeJobs).to.eq(1);
        expect(executor.reputation).to.eq(1000);

        // check usdc balance of executor
        expect(await usdc_token.balanceOf(addrs[1])).to.eq(100n * 7n / 9n);
        // check usdc balance of payment pool
        expect(await usdc_token.balanceOf(usdc_payment_pool)).to.eq(100n);
        // check usdc balance of job owner
        expect(await usdc_token.balanceOf(addrs[3])).to.eq(10n ** 6n - 100n * 2n);
        // check stakes of all executors
        for (let index = 17; index < 20; index++) {
            const teeNode = await teeManager.teeNodes(addrs[index]);
            expect(teeNode.stakeAmount).to.eq(10n ** 19n);
        }
    });

    // submit 3 output
    it("three output submits by selected executor nodes", async function () {
        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest() - 540;

        let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
        let tx = await jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );
        await expect(tx).to.emit(jobs, "JobResponded")
            .and.to.emit(jobs, "JobResultCallbackCalled").withArgs(jobId, true);

        // submit 2nd output
        signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[18]);
        tx = await jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );
        await expect(tx).to.emit(jobs, "JobResponded")
            .and.to.not.emit(jobs, "JobResultCallbackCalled");

        // submit 3rd output
        signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[19]);
        tx = await jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );
        await expect(tx).to.emit(jobs, "JobResponded").to.not.emit(jobs, "JobResultCallbackCalled");

        // check active jobs and reputation for submitter
        let executor = await executors.executors(addrs[17]);
        expect(executor.activeJobs).to.eq(0);
        expect(executor.reputation).to.eq(1010);

        executor = await executors.executors(addrs[18]);
        expect(executor.activeJobs).to.eq(0);
        expect(executor.reputation).to.eq(995);

        executor = await executors.executors(addrs[19]);
        expect(executor.activeJobs).to.eq(0);
        expect(executor.reputation).to.eq(995);

        // check usdc balance of executor
        expect(await usdc_token.balanceOf(addrs[1])).to.eq(100n);
        // check usdc balance of payment pool
        expect(await usdc_token.balanceOf(usdc_payment_pool)).to.eq(100n);
        // check usdc balance of job owner
        expect(await usdc_token.balanceOf(addrs[3])).to.eq(10n ** 6n - 100n * 2n);
        // check stakes of all executors
        for (let index = 17; index < 20; index++) {
            const teeNode = await teeManager.teeNodes(addrs[index]);
            expect(teeNode.stakeAmount).to.eq(10n ** 19n);
        }
    });

    it("verify job result callback", async function () {
        // deploy job user
        const SecretJobsUser = await ethers.getContractFactory("SecretJobsUser");
        let jobsUser = await SecretJobsUser.deploy(jobs.target, usdc_token.target) as unknown as SecretJobsUser;
        let env = 1,
            secretId = 1,
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            usdcDeposit = 1000000,
            deadline = 10000;
        await usdc_token.transfer(jobsUser.target, 10n ** 6n);
        await secretManager.setSecretAllowedAddresses(secretId, [jobsUser.target]);
        await jobsUser.createJob(env, secretId, codeHash, codeInputs, deadline, usdcDeposit);

        let jobId = 1,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest() - 540;

        let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
        let tx = await jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );
        await expect(tx).to.emit(jobs, "JobResponded")
            .and.to.emit(jobs, "JobResultCallbackCalled").withArgs(jobId, true)
            .and.to.emit(jobsUser, "CalledBack").withArgs(jobId, output, errorCode, totalTime);
    });

    it("cannot submit output with expired signature", async function () {
        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest() - 800;

        let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
        await expect(jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        )).to.revertedWithCustomError(jobs, "JobsSignatureTooOld");
    });

    it("cannot submit output after execution time is over", async function () {
        await time.increase(20000);

        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest() - 540;

        let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);

        await expect(jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        ))
            .to.be.revertedWithCustomError(jobs, "JobsExecutionTimeOver");
    });

    it("cannot submit output twice", async function () {
        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest() - 540;

        let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
        let tx = await jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );
        await expect(tx).to.emit(jobs, "JobResponded");

        await expect(jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        ))
            .to.revertedWithCustomError(jobs, "JobsExecutorAlreadySubmittedOutput");
    });

    it("cannot submit output from unselected executor node", async function () {
        let jobCapacity = 20,
            storageCapacity = 1e9,
            stakeAmount = 10,
            timestamp = await time.latest() * 1000,
            env = 1;

        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[20],
            image4,
            wallets[14],
            timestamp - 540000
        );

        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[20]);

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

        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0;
        signTimestamp = await time.latest() - 540;
        signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[20]);
        await expect(jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        ))
            .to.revertedWithCustomError(jobs, "JobsNotSelectedExecutor");
    });

    it("can submit output after executor initiates draining", async function () {
        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest() - 540;

        await teeManager.connect(signers[1]).drainTeeNode(addrs[17]);

        let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
        await expect(jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        ))
            .to.emit(jobs, "JobResponded");

        let teeNode = await teeManager.teeNodes(addrs[17]);
        expect(teeNode.draining).to.be.true;
    });

    it("can submit output by selected executor node with totalTime > deadline", async function () {
        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100000,
            errorCode = 0,
            signTimestamp = await time.latest() - 540;

        let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
        let tx = jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );
        await expect(tx).to.emit(jobs, "JobResponded").withArgs(jobId, wallets[17], output, 10000, errorCode, 1)
            .and.to.emit(jobs, "JobResultCallbackCalled").withArgs(jobId, true);

        // check usdc balance of executor
        expect(await usdc_token.balanceOf(addrs[1])).to.eq(10000n * 4n / 9n);
        // check usdc balance of payment pool
        expect(await usdc_token.balanceOf(usdc_payment_pool)).to.eq(10000n);
        // check usdc balance of job owner
        expect(await usdc_token.balanceOf(addrs[3])).to.eq(10n ** 6n - 10000n * 2n);
    });
});

describe("Jobs - Slashing", function () {
    let signers: Signer[];
    let addrs: string[];
    let staking_token: Pond;
    let usdc_token: USDCoin;
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let teeManager: TeeManager;
    let executors: Executors;
    let jobs: Jobs;
    let secretManager: SecretManager;
    let staking_payment_pool: string;
    let usdc_payment_pool: string;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));
        staking_payment_pool = addrs[2];
        usdc_payment_pool = addrs[2];

        const Pond = await ethers.getContractFactory("Pond");
        staking_token = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        }) as unknown as Pond;

        const USDCoin = await ethers.getContractFactory("USDCoin");
        usdc_token = await upgrades.deployProxy(USDCoin, [addrs[0]], {
            kind: "uups",
        }) as unknown as USDCoin;

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        let teeImages = [image4, image5, image6, image7];
        const TeeManager = await ethers.getContractFactory("TeeManager");
        teeManager = await upgrades.deployProxy(
            TeeManager,
            [addrs[0], teeImages],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    staking_token.target,
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
        let secretStore = await upgrades.deployProxy(
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

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

        const Jobs = await ethers.getContractFactory("contracts/secret-storage/job-allocation/Jobs.sol:Jobs");
        jobs = await upgrades.deployProxy(
            Jobs,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    staking_token.target,
                    usdc_token.target,
                    600,
                    100,
                    3,
                    staking_payment_pool,
                    usdc_payment_pool
                ]
            },
        ) as unknown as Jobs;

        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), jobs.target);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), jobs.target);

        await jobs.setExecutors(executors.target);
        await jobs.setSecretStore(secretStore.target);

        let env = 1,
            executionFeePerMs = 1,
            stakingRewardPerMs = 1;
        await jobs.addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs);

        // Grant role to jobs contract on executor
        await staking_token.transfer(addrs[1], 10n ** 20n);
        await staking_token.connect(signers[1]).approve(teeManager.target, 10n ** 20n);

        let jobCapacity = 20,
            storageCapacity = 1e9,
            stakeAmount = 10n ** 19n;
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        for (let index = 0; index < 3; index++) {
            // Executor index using wallet 17 + index as enclave address
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[17 + index],
                teeImages[index],
                wallets[14],
                timestamp - 540000
            );

            let signedDigest = await registerTeeNodeSignature(
                addrs[1], jobCapacity, storageCapacity, env, signTimestamp, wallets[17 + index]
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

        // RELAY JOB, caller address 3
        await usdc_token.transfer(addrs[3], 10n ** 6n);
        await usdc_token.connect(signers[3]).approve(jobs.target, 10n ** 6n);

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
                    usdc_token.target,
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
        await usdc_token.approve(secretManager.target, parseUnits("10000", 6));
        await jobs.setSecretManager(secretManager.target);
        await jobs.setTeeManager(teeManager.target);

        // CREATE SECRET
        let sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, [addrs[3]]);

        // ACKNOWLEDGE SECRET
        let secretId = 1;
        let selectedStores = await secretManager.getSelectedEnclaves(secretId);
        for (let i = 0; i < selectedStores.length; i++) {
            let index = addrs.indexOf(selectedStores[i].enclaveAddress);
            const wallet = wallets[index];
            let signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallet);
            await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);
        }

        let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000;
        await jobs.connect(signers[3]).createJob(env, secretId, codeHash, codeInputs, deadline);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can slash after deadline over", async function () {
        await time.increase(await time.latest() + 100000);
        let jobId = 0;
        let tx = await jobs.slashOnExecutionTimeout(jobId);
        await expect(tx).to.emit(jobs, "SlashedOnExecutionTimeout").withArgs(jobId, addrs[17])
            .and.to.emit(jobs, "SlashedOnExecutionTimeout").withArgs(jobId, addrs[18])
            .and.to.emit(jobs, "SlashedOnExecutionTimeout").withArgs(jobId, addrs[19])
            .and.to.emit(jobs, "JobFailureCallbackCalled").withArgs(jobId, true);
        // check job does not exists
        let job = await jobs.jobs(jobId);
        expect(job.execStartTime).to.be.eq(0);
        expect(await (await executors.executors(addrs[17])).reputation).to.eq(990);

        // check slashed amount that job owner is getting
        expect(await staking_token.balanceOf(addrs[3])).to.be.eq(3n * 10n ** 15n);
        // check USDC balance of owner should be same
        expect(await usdc_token.balanceOf(addrs[3])).to.be.eq(10n ** 6n);
    });

    it("cannot slash non-existing job with id greater than total job count", async function () {
        let jobId = 2;
        let tx = jobs.slashOnExecutionTimeout(jobId);
        await expect(tx).to.revertedWithPanic(0x32);
    });

    it("cannot slash before deadline over", async function () {
        let jobId = 0;
        let tx = jobs.slashOnExecutionTimeout(jobId);
        await expect(tx).to.revertedWithCustomError(jobs, "JobsDeadlineNotOver");
    });

    it("cannot slash twice", async function () {
        await time.increase(await time.latest() + 100000);
        let jobId = 0;
        let tx = await jobs.slashOnExecutionTimeout(jobId);
        await expect(tx).to.emit(jobs, "SlashedOnExecutionTimeout");

        let tx2 = jobs.slashOnExecutionTimeout(jobId);
        await expect(tx2).to.revertedWithCustomError(jobs, "JobsInvalidJob");
    });

    it("can slash after executor initiates drain", async function () {
        await teeManager.connect(signers[1]).drainTeeNode(addrs[17]);

        await time.increase(await time.latest() + 100000);
        let jobId = 0;

        await expect(jobs.slashOnExecutionTimeout(jobId))
            .to.emit(jobs, "SlashedOnExecutionTimeout");

        let teeNode = await teeManager.teeNodes(addrs[17]);
        expect(teeNode.draining).to.be.true;
        expect(await (await executors.executors(addrs[17])).reputation).to.eq(990);
    });

    it("slash after only one executor submits output", async function () {
        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest() - 540;

        let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
        await jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );

        await time.increase(await time.latest() + 100000);
        await expect(jobs.slashOnExecutionTimeout(jobId))
            .to.emit(jobs, "SlashedOnExecutionTimeout").withArgs(jobId, addrs[18])
            .and.to.emit(jobs, "SlashedOnExecutionTimeout").withArgs(jobId, addrs[19]);
        // check job does not exists
        let job = await jobs.jobs(jobId);
        expect(job.execStartTime).to.be.eq(0);

        // check slashed amount payment pool is getting
        expect(await staking_token.balanceOf(staking_payment_pool)).to.be.eq(2n * 10n ** 15n);
        // check payments received by payment pool in USDC
        let expected_balance = 100n * 2n - 100n * 1n * 4n / 9n;
        expect(await usdc_token.balanceOf(usdc_payment_pool)).to.be.eq((expected_balance));
    });

    it("slash after two executors submits output", async function () {
        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest() - 540;

        let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
        await jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );

        signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[18]);
        await jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );

        await time.increase(await time.latest() + 100000);
        await expect(jobs.slashOnExecutionTimeout(jobId))
            .to.emit(jobs, "SlashedOnExecutionTimeout").withArgs(jobId, addrs[19]);
        // check job does not exists
        let job = await jobs.jobs(jobId);
        expect(job.execStartTime).to.be.eq(0);

        // check slashed amount payment pool is getting
        expect(await staking_token.balanceOf(staking_payment_pool)).to.be.eq(1n * 10n ** 15n);
        // check payments received by payment pool in USDC
        let expected_balance = 100n * 2n - 100n * 1n * 7n / 9n;
        expect(await usdc_token.balanceOf(usdc_payment_pool)).to.be.eq((expected_balance));
    });

    it("slash after all executors submits output", async function () {
        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest() - 540;

        let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
        await jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );

        signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[18]);
        await jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );

        signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[19]);
        await jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );

        await time.increase(await time.latest() + 100000);
        await expect(jobs.slashOnExecutionTimeout(jobId))
            .to.revertedWithCustomError(jobs, "JobsInvalidJob");
    });

    it("verify job failed callback", async function () {
        // deploy job user
        const SecretJobsUser = await ethers.getContractFactory("SecretJobsUser");
        let jobsUser = await SecretJobsUser.deploy(jobs.target, usdc_token.target) as unknown as SecretJobsUser;
        let env = 1,
            secretId = 1,
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            usdcDeposit = 1000000,
            deadline = 10000;
        await usdc_token.transfer(jobsUser.target, 10n ** 6n);
        await secretManager.setSecretAllowedAddresses(secretId, [jobsUser.target]);
        await jobsUser.createJob(env, secretId, codeHash, codeInputs, deadline, usdcDeposit);

        await time.increase(await time.latest() + 100000);
        let jobId = 1;
        let tx = await jobs.slashOnExecutionTimeout(jobId);
        await expect(tx).to.emit(jobs, "SlashedOnExecutionTimeout").withArgs(jobId, addrs[17])
            .and.to.emit(jobs, "SlashedOnExecutionTimeout").withArgs(jobId, addrs[18])
            .and.to.emit(jobs, "SlashedOnExecutionTimeout").withArgs(jobId, addrs[19])
            .and.to.emit(jobs, "JobFailureCallbackCalled").withArgs(jobId, true)
            .and.to.emit(jobsUser, "FailedCallback").withArgs(jobId, 3n * 10n ** 15n);
    });

});

function normalize(key: string): string {
    return '0x' + key.substring(4);
}

type Attestation = {
    enclavePubKey: string,
    PCR0: BytesLike,
    PCR1: BytesLike,
    PCR2: BytesLike,
    timestampInMilliseconds: number,
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

async function createExecutorSignature(
    owner: string,
    jobCapacity: number,
    env: number,
    signTimestamp: number,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.Executors',
        version: '1',
    };

    const types = {
        Register: [
            { name: 'owner', type: 'address' },
            { name: 'jobCapacity', type: 'uint256' },
            { name: 'env', type: 'uint8' },
            { name: 'signTimestamp', type: 'uint256' }
        ]
    };

    const value = {
        owner,
        jobCapacity,
        env,
        signTimestamp
    };

    const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
    return ethers.Signature.from(sign).serialized;
}

async function createOutputSignature(
    jobId: number,
    output: string,
    totalTime: number,
    errorCode: number,
    signTimestamp: number,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.Jobs',
        version: '1',
    };

    const types = {
        SubmitOutput: [
            { name: 'jobId', type: 'uint256' },
            { name: 'output', type: 'bytes' },
            { name: 'totalTime', type: 'uint256' },
            { name: 'errorCode', type: 'uint8' },
            { name: 'signTimestamp', type: 'uint256' }
        ]
    };

    const value = {
        jobId,
        output,
        totalTime,
        errorCode,
        signTimestamp
    };

    const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
    return ethers.Signature.from(sign).serialized;
}

function walletForIndex(idx: number): Wallet {
    let wallet = ethers.HDNodeWallet.fromPhrase(
        "test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString()
    );

    return new Wallet(wallet.privateKey);
}
