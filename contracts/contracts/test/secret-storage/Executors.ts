import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, Wallet, ZeroAddress, keccak256, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationAutherUpgradeable, AttestationVerifier, Executors, TeeManagerMock } from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { testERC165 } from '../helpers/erc165';

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

const image4: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48))
};

const image5: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48))
};

const image6: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48))
};

function getImageId(image: AttestationAutherUpgradeable.EnclaveImageStruct): string {
    return keccak256(solidityPacked(["bytes", "bytes", "bytes"], [image.PCR0, image.PCR1, image.PCR2]));
}

describe("Executors - Init", function () {
    let signers: Signer[];
    let addrs: string[];
    let teeManager: TeeManagerMock;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));

        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("deploys with initialization disabled", async function () {
        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        const executors = await Executors.deploy(
            teeManager.target
        );

        expect(await executors.TEE_MANAGER()).to.equal(teeManager.target);

        await expect(
            executors.initialize(addrs[0]),
        ).to.be.revertedWithCustomError(executors, "InvalidInitialization");
    });

    it("deploys as proxy and initializes", async function () {
        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        const executors = await upgrades.deployProxy(
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

        expect(await executors.TEE_MANAGER()).to.equal(teeManager.target);
        expect(await executors.MIN_STAKE_AMOUNT()).to.equal(10 ** 10);

        expect(await executors.hasRole(await executors.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    });

    it("cannot initialize with zero address as admin", async function () {
        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        await expect(
            upgrades.deployProxy(
                Executors,
                [ZeroAddress],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        teeManager.target
                    ]
                },
            )
        ).to.be.revertedWithCustomError(Executors, "ExecutorsZeroAddressAdmin");
    });

    it("cannot initialize with zero address as tee manager", async function () {
        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        await expect(
            upgrades.deployProxy(
                Executors,
                [addrs[0]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        ZeroAddress
                    ]
                },
            )
        ).to.be.revertedWithCustomError(Executors, "ExecutorsZeroAddressTeeManager");
    });

    it("upgrades", async function () {
        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        const executors = await upgrades.deployProxy(
            Executors,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        );

        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        let teeManager2 = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

        await upgrades.upgradeProxy(
            executors.target,
            Executors,
            {
                kind: "uups",
                constructorArgs: [
                    teeManager2.target
                ]
            }
        );

        expect(await executors.TEE_MANAGER()).to.equal(teeManager2.target);

        expect(await executors.hasRole(await executors.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    });

    it("does not upgrade without admin", async function () {
        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        const executors = await upgrades.deployProxy(
            Executors,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        );

        await expect(
            upgrades.upgradeProxy(executors.target, Executors.connect(signers[1]), {
                kind: "uups",
                constructorArgs: [
                    addrs[1]
                ],
            }),
        ).to.be.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });
});

testERC165(
    "Executors - ERC165",
    async function (_signers: Signer[], addrs: string[]) {
        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        const teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

        const Executors = await ethers.getContractFactory("contracts/secret-storage/Executors.sol:Executors");
        const executors = await upgrades.deployProxy(
            Executors,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        );
        return executors;
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

describe("Executors - TreeMap functions", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let teeManager: TeeManagerMock;
    let executors: Executors;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

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

        await teeManager.setExecutors(executors.target);
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can initialize tree", async function () {
        let env = 1;
        await expect(executors.initTree(env)).to.be.not.reverted;
        expect(await executors.isTreeInitialized(env)).to.be.true;
        expect(await executors.nodesInTree(env)).that.eq(0);
    });

    it("cannot init tree with already supported execution env", async function () {
        let env = 1;
        await executors.initTree(env);

        await expect(executors.initTree(env)).to.be
            .revertedWithCustomError(executors, "ExecutorsGlobalEnvAlreadySupported");
    });

    it("cannot init tree without JOBS_ROLE account", async function () {
        let env = 1;
        await expect(executors.connect(signers[1]).initTree(env)).to.be
            .revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });

    it("can remove tree", async function () {
        let env = 1;
        await executors.initTree(env);

        await expect(executors.removeTree(env)).to.be.not.reverted;
        expect(await executors.isTreeInitialized(env)).to.be.false;
    });

    it("cannot remove tree whose execution env hasn't been initialized", async function () {
        let env = 1;
        await expect(executors.removeTree(env)).to.be
            .revertedWithCustomError(executors, "ExecutorsGlobalEnvAlreadyUnsupported");
    });

    it("cannot remove tree without JOBS_ROLE account", async function () {
        let env = 1;
        await executors.initTree(env);

        await expect(executors.connect(signers[1]).removeTree(env)).to.be
            .revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });

    it('can add multiple envs and remove them', async function () {
        let env = 1;
        await executors.initTree(env);

        expect(await executors.isTreeInitialized(env)).to.be.true;
        expect(await executors.nodesInTree(env)).that.eq(0);

        let storageCapacity = 1e9,
            jobCapacity = 20,
            stakeAmount = 10n ** 19n,
            timestamp = await time.latest() * 1000,
            signTimestamp = await time.latest() - 540;
        for (let index = 0; index < 2; index++) {
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[15 + index],
                image2,
                wallets[14],
                timestamp - 540000
            );
            await teeManager.registerTeeNode(
                attestationSign,
                attestation,
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                "0x",
                stakeAmount
            );
        }

        env = 2;
        await executors.initTree(env);

        expect(await executors.isTreeInitialized(env)).to.be.true;
        expect(await executors.nodesInTree(env)).that.eq(0);

        for (let index = 0; index < 3; index++) {
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[15 + index],
                image2,
                wallets[14],
                timestamp - 540000
            );
            await teeManager.registerTeeNode(
                attestationSign,
                attestation,
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                "0x",
                stakeAmount
            );
        }

        expect(await executors.nodesInTree(1)).that.eq(2);
        expect(await executors.nodesInTree(2)).that.eq(3);

        await executors.removeTree(1);
        expect(await executors.isTreeInitialized(1)).to.be.false;
        expect(await executors.isTreeInitialized(2)).to.be.true;

        await executors.removeTree(2);
        expect(await executors.isTreeInitialized(2)).to.be.false;
    });
});

describe("Executors - Register/deregister executor", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let teeManager: TeeManagerMock;
    let executors: Executors;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

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

        await teeManager.setExecutors(executors.target);
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        let env = 1;
        await executors.initTree(env);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can register executor", async function () {
        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1,
            stakeAmount = 10,
            timestamp = await time.latest() * 1000,
            signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );
        await expect(teeManager.registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            "0x",
            stakeAmount
        )).to.be.not.reverted;

        expect((await executors.executors(addrs[15])).jobCapacity).to.equal(jobCapacity);
    });

    it("cannot register executor without tee manager contract", async function () {
        let jobCapacity = 20,
            env = 1,
            stakeAmount = 10;
        await expect(executors.registerExecutor(
            addrs[15],
            jobCapacity,
            env,
            stakeAmount
        )).to.be.revertedWithCustomError(executors, "ExecutorsNotTeeManager");
    });

    it("cannot register executor with unsupported execution env", async function () {
        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 2,
            stakeAmount = 10,
            timestamp = await time.latest() * 1000,
            signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );
        await expect(teeManager.registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            "0x",
            stakeAmount
        )).to.be.revertedWithCustomError(executors, "ExecutorsUnsupportedEnv");
    });

    it('can deregister executor without active jobs', async function () {
        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1,
            stakeAmount = 10,
            timestamp = await time.latest() * 1000,
            signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );
        await teeManager.registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            "0x",
            stakeAmount
        );

        await expect(teeManager.deregisterTeeNode(addrs[15]))
            .to.be.not.reverted;
        expect((await executors.executors(addrs[15])).activeJobs).to.be.eq(0);
    });

    it('cannot deregister executor with active jobs', async function () {
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1,
            stakeAmount = 10n ** 19n,
            timestamp = await time.latest() * 1000,
            signTimestamp = await time.latest() - 540;
        // register a enclave
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );
        await teeManager.registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            "0x",
            stakeAmount
        );

        // select nodes
        await executors.selectExecutionNodes(env, [addrs[15]], 1);
        // deregister
        await expect(teeManager.deregisterTeeNode(addrs[15]))
            .to.revertedWithCustomError(executors, "ExecutorsHasPendingJobs");
    });

    it('cannot deregister executor without tee manager contract', async function () {
        await expect(executors.deregisterExecutor(addrs[15]))
            .to.revertedWithCustomError(executors, "ExecutorsNotTeeManager");
    });

});

describe("Executors - Staking/Unstaking", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let teeManager: TeeManagerMock;
    let executors: Executors;
    let STAKE_ADJUSTMENT_FACTOR: bigint;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

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
        STAKE_ADJUSTMENT_FACTOR = await executors.STAKE_ADJUSTMENT_FACTOR();

        await teeManager.setExecutors(executors.target);
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        let env = 1;
        await executors.initTree(env);

        let jobCapacity = 1,
            storageCapacity = 1e9,
            stakeAmount = 10n ** 19n,
            timestamp = await time.latest() * 1000,
            signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );
        await teeManager.registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            "0x",
            stakeAmount
        );
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can stake", async function () {
        let env = 1,
            amount = 2n * (10n ** 19n);
        await expect(teeManager.addTeeNodeStake(addrs[15], amount))
            .to.be.not.reverted;
        expect(await executors.getNodeValue(env, addrs[15])).to.eq((10n ** 19n + amount) / STAKE_ADJUSTMENT_FACTOR);

        // case when max job capacity is reached
        await executors.selectExecutionNodes(1, [addrs[15]], 1);
        await expect(teeManager.addTeeNodeStake(addrs[15], amount))
            .to.be.not.reverted;
        expect(await executors.isNodePresentInTree(env, addrs[15])).to.be.false;
    });

    it("cannot stake without tee manager contract", async function () {
        let amount = 20;
        await expect(executors.addExecutorStake(addrs[15], 1, amount))
            .to.be.revertedWithCustomError(executors, "ExecutorsNotTeeManager");
    });

    it("can unstake if no active jobs", async function () {
        let amount = 100n;
        await expect(teeManager.removeTeeNodeStake(addrs[15], amount))
            .to.be.not.reverted;
    });

    it('cannot unstake with active jobs', async function () {
        // select nodes
        let env = 1;
        await executors.selectExecutionNodes(env, [addrs[15]], 1);

        await expect(teeManager.removeTeeNodeStake(addrs[15], 100))
            .to.be.revertedWithCustomError(executors, "ExecutorsHasPendingJobs");

    });

    it("cannot unstake without tee manager contract", async function () {
        await expect(executors.removeExecutorStake(addrs[15]))
            .to.be.revertedWithCustomError(executors, "ExecutorsNotTeeManager");
    });
});

describe("Executors - Drain/Revive executor", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let teeManager: TeeManagerMock;
    let executors: Executors;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

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

        await teeManager.setExecutors(executors.target);
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        let env = 1;
        await executors.initTree(env);

        let jobCapacity = 1,
            storageCapacity = 1e9,
            stakeAmount = 10n ** 19n,
            timestamp = await time.latest() * 1000,
            signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );
        await teeManager.registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            "0x",
            stakeAmount
        );
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it('can drain executor', async function () {
        await expect(teeManager.drainTeeNode(addrs[15]))
            .to.be.not.reverted;

        let env = 1;
        expect(await executors.isNodePresentInTree(env, addrs[15])).to.be.false;
    });

    it("cannot drain without tee manager contract", async function () {
        await expect(executors.drainExecutor(addrs[15], 1))
            .to.be.revertedWithCustomError(executors, "ExecutorsNotTeeManager");
    });

    it("can revive secret store", async function () {
        await teeManager.drainTeeNode(addrs[15]);
        await expect(teeManager.reviveTeeNode(addrs[15]))
            .to.be.not.reverted;

        let env = 1;
        expect(await executors.isNodePresentInTree(env, addrs[15])).to.be.true;

        // case 2: revive after unstaking
        await teeManager.drainTeeNode(addrs[15]);
        await teeManager.removeTeeNodeStake(addrs[15], 9n * (10n ** 18n));
        await expect(teeManager.reviveTeeNode(addrs[15]))
            .to.be.not.reverted;

        expect(await executors.isNodePresentInTree(env, addrs[15])).to.be.true;
        // remaining stake = 10 POND - 9 POND = 1 POND
        expect(await executors.getNodeValue(env, addrs[15]))
            .to.eq((10n ** 18n) / await executors.STAKE_ADJUSTMENT_FACTOR());
    });

    it("can revive secret store with max job capacity reached", async function () {
        let env = 1;
        await executors.selectExecutionNodes(env, [addrs[15]], 1);
        await teeManager.drainTeeNode(addrs[15]);

        await expect(teeManager.reviveTeeNode(addrs[15]))
            .to.be.not.reverted;
        expect(await executors.isNodePresentInTree(env, addrs[15])).to.be.false;
    });

    it("cannot revive secret store without tee manager contract", async function () {
        let env = 1,
            stakeAmount = 10;
        await expect(executors.reviveExecutor(addrs[15], env, stakeAmount))
            .to.revertedWithCustomError(executors, "ExecutorsNotTeeManager");
    });
});

describe("Executors - Select/Release/Slash", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let teeManager: TeeManagerMock;
    let executors: Executors;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

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

        await teeManager.setExecutors(executors.target);
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        let env = 1;
        await executors.initTree(env);

        // REGISTER NODES
        let jobCapacity = 20,
            storageCapacity = 1e9,
            stakeAmount = 10n ** 19n,
            timestamp = await time.latest() * 1000,
            signTimestamp = await time.latest() - 540;
        for (let index = 0; index < 3; index++) {
            // stake for 1st node is different than the other 2 nodes
            if (index != 0)
                stakeAmount = 10n ** 20n;
            let [attestationSign, attestation] = await createAttestation(
                pubkeys[15 + index],
                image2,
                wallets[14],
                timestamp - 540000
            );
            await teeManager.registerTeeNode(
                attestationSign,
                attestation,
                jobCapacity,
                storageCapacity,
                env,
                signTimestamp,
                "0x",
                stakeAmount
            );
        }
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can select executors", async function () {
        let env = 1;
        // can select 1 node
        await expect(executors.selectExecutionNodes(env, [addrs[15]], 1))
            .to.be.not.reverted;
        expect((await executors.executors(addrs[15])).activeJobs).to.be.eq(1);
        expect(await executors.isNodePresentInTree(env, addrs[15])).to.be.true;

        // can select multiple nodes
        await expect(executors.selectExecutionNodes(env, [addrs[15], addrs[16]], 2))
            .to.be.not.reverted;
        expect((await executors.executors(addrs[15])).activeJobs).to.be.eq(2);
        expect(await executors.isNodePresentInTree(env, addrs[15])).to.be.true;
        expect((await executors.executors(addrs[16])).activeJobs).to.be.eq(1);
        expect(await executors.isNodePresentInTree(env, addrs[16])).to.be.true;

        // can select topN nodes out of multiple nodes (here 16th and 17th nodes will be selcted as they have higher stakes)
        await expect(executors.selectExecutionNodes(env, [addrs[15], addrs[16], addrs[17]], 2))
            .to.be.not.reverted;

        expect((await executors.executors(addrs[15])).activeJobs).to.be.eq(2);
        expect(await executors.isNodePresentInTree(env, addrs[15])).to.be.true;
        expect((await executors.executors(addrs[16])).activeJobs).to.be.eq(2);
        expect(await executors.isNodePresentInTree(env, addrs[16])).to.be.true;
        expect((await executors.executors(addrs[17])).activeJobs).to.be.eq(1);
        expect(await executors.isNodePresentInTree(env, addrs[17])).to.be.true;
    });

    it("cannot select executors other than selected stores", async function () {
        await expect(executors.selectExecutionNodes(1, [], 1))
            .to.be.revertedWithCustomError(executors, "ExecutorsUnavailableStores");

        await expect(executors.selectExecutionNodes(1, [addrs[15]], 2))
            .to.be.revertedWithCustomError(executors, "ExecutorsUnavailableStores");
    });

    it("cannot select executors without JOBS_ROLE", async function () {
        await expect(executors.connect(signers[1]).selectExecutionNodes(1, [], 1))
            .to.be.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });

    it("cannot select executor with unsupported execution env", async function () {
        let env = 2;
        await expect(executors.selectExecutionNodes(env, [], 1))
            .to.revertedWithCustomError(executors, "ExecutorsUnsupportedEnv");
    });

    // TODO: will be required once we enable executor selection along with secret stores
    // it("can select executors along with the already selected stores", async function () {
    //     let jobCapacity = 20,
    //         env = 1,
    //         stakeAmount = 10n ** 19n;
    //     await teeManager.registerExecutor(
    //         addrs[16],
    //         jobCapacity,
    //         env,
    //         stakeAmount
    //     );

    //     let noOfNodesToSelect = 2;
    //     await expect(executors.selectExecutionNodes(env, [addrs[15]], noOfNodesToSelect))
    //         .to.be.not.reverted;

    //     expect((await executors.executors(addrs[15])).activeJobs).to.be.eq(1);
    //     expect((await executors.executors(addrs[16])).activeJobs).to.be.eq(1);
    // });

    it("can release executor", async function () {
        await executors.selectExecutionNodes(1, [addrs[15]], 1);

        await expect(executors.releaseExecutor(addrs[15]))
            .to.be.not.reverted;

        expect((await executors.executors(addrs[15])).activeJobs).to.be.eq(0);

        // case 2: release executor post draining
        await executors.selectExecutionNodes(1, [addrs[15]], 1);
        await teeManager.drainTeeNode(addrs[15]);
        await expect(executors.releaseExecutor(addrs[15]))
            .to.be.not.reverted;
        expect((await executors.executors(addrs[15])).activeJobs).to.be.eq(0);

        // case 3: release executor post stake removal
        await teeManager.reviveTeeNode(addrs[15]);
        await teeManager.removeTeeNodeStake(addrs[15], 10n ** 19n);
        await executors.selectExecutionNodes(1, [addrs[15]], 1);
        await expect(executors.releaseExecutor(addrs[15]))
            .to.be.not.reverted;
        expect((await executors.executors(addrs[15])).activeJobs).to.be.eq(0);
        expect(await executors.isNodePresentInTree(1, addrs[15])).to.be.false;
    });

    it("cannot release executors without JOBS_ROLE", async function () {
        await expect(executors.connect(signers[1]).releaseExecutor(addrs[15]))
            .to.be.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });

    it("can slash executor", async function () {
        await executors.selectExecutionNodes(1, [addrs[15]], 1);

        await expect(executors.slashExecutor(addrs[15]))
            .to.be.not.reverted;

        const executor = await executors.executors(addrs[15]);
        expect(executor.activeJobs).to.eq(0);
        expect(executor.reputation).to.eq(990);
    });

    it("cannot slash executor without JOB ROLE", async function () {
        await expect(executors.connect(signers[1]).slashExecutor(addrs[15]))
            .to.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });
});

describe("Executors - Reputation and other functions", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let teeManager: TeeManagerMock;
    let executors: Executors;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

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

        await teeManager.setExecutors(executors.target);
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        let env = 1;
        await executors.initTree(env);

        let jobCapacity = 20,
            storageCapacity = 1e9,
            stakeAmount = 10n ** 19n,
            timestamp = await time.latest() * 1000,
            signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );
        await teeManager.registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            "0x",
            stakeAmount
        );
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can increase reputation", async function () {
        await expect(executors.increaseReputation(addrs[15], 10))
            .to.be.not.reverted;

        expect((await executors.executors(addrs[15])).reputation).to.be.eq(1010);
    });

    it("cannot increase reputation without JOBS_ROLE", async function () {
        await expect(executors.connect(signers[1]).increaseReputation(addrs[15], 10))
            .to.be.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });

    it("can decrease reputation", async function () {
        await expect(executors.decreaseReputation(addrs[15], 10))
            .to.be.not.reverted;

        expect((await executors.executors(addrs[15])).reputation).to.be.eq(990);
    });

    it("cannot decrease reputation without JOBS_ROLE", async function () {
        await expect(executors.connect(signers[1]).decreaseReputation(addrs[15], 10))
            .to.be.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });

    it("can upsert node in tree", async function () {
        await expect(teeManager.updateTreeState(addrs[15])).to.be.not.reverted;
        expect(await executors.isNodePresentInTree(1, addrs[15])).to.be.true;
        expect(await executors.getNodeValue(1, addrs[15]))
            .to.eq((10n ** 19n) / await executors.STAKE_ADJUSTMENT_FACTOR());
    });

    it("cannot upsert node in tree without TeeManager contract", async function () {
        await expect(executors.upsertTreeNode(1, addrs[15], 10n ** 20n))
            .to.be.revertedWithCustomError(executors, "ExecutorsNotTeeManager");
    });

    it("can delete node in tree", async function () {
        await teeManager.removeTeeNodeStake(addrs[15], 10n ** 19n);

        // as stake < minStake, it will delete the node
        await expect(teeManager.updateTreeState(addrs[15])).to.be.not.reverted;
        expect(await executors.isNodePresentInTree(1, addrs[15])).to.be.false;
    });

    it("cannot delete node in tree without TeeManager contract", async function () {
        await expect(executors.deleteTreeNodeIfPresent(1, addrs[15]))
            .to.be.revertedWithCustomError(executors, "ExecutorsNotTeeManager");
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

async function createGatewaySignature(
    operator: string,
    chainIds: number[],
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.Gateways',
        version: '1',
    };

    const types = {
        Register: [
            { name: 'operator', type: 'address' },
            { name: 'chainIds', type: 'uint256[]' }
        ]
    };

    const value = {
        operator,
        chainIds
    };

    const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
    return ethers.Signature.from(sign).serialized;
}

async function createRelayJobSignature(
    operator: string,
    jobId: number,
    codeHash: string,
    codeInputs: string,
    deadline: number,
    jobRequestTimestamp: number,
    sequenceId: number,
    jobOwner: string,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.Jobs',
        version: '1',
    };

    const types = {
        RelayJob: [
            { name: 'operator', type: 'address' },
            { name: 'jobId', type: 'uint256' },
            { name: 'codeHash', type: 'bytes32' },
            { name: 'codeInputs', type: 'bytes' },
            { name: 'deadline', type: 'uint256' },
            { name: 'jobRequestTimestamp', type: 'uint256' },
            { name: 'sequenceId', type: 'uint8' },
            { name: 'jobOwner', type: 'address' }
        ]
    };

    const value = {
        operator,
        jobId,
        codeHash,
        codeInputs,
        deadline,
        jobRequestTimestamp,
        sequenceId,
        jobOwner
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
