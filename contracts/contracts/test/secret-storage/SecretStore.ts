import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, Wallet, ZeroAddress, keccak256, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import {
    AttestationAutherUpgradeable,
    AttestationVerifier,
    Executors,
    SecretManagerMock,
    SecretStore,
    TeeManager,
    TeeManagerMock,
    USDCoin 
} from "../../typechain-types";
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

function getImageId(image: AttestationAutherUpgradeable.EnclaveImageStruct): string {
    return keccak256(solidityPacked(["bytes", "bytes", "bytes"], [image.PCR0, image.PCR1, image.PCR2]));
}

describe("SecretStore - Init", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let token: string;
    let teeManager: TeeManager;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[13]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        token = addrs[1];

        const TeeManager = await ethers.getContractFactory("TeeManager");
        teeManager = await upgrades.deployProxy(
            TeeManager,
            [addrs[0], [image1]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    token,
                    10 ** 10,
                    10 ** 2,
                    10 ** 6
                ]
            },
        ) as unknown as TeeManager;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("deploys with initialization disabled", async function () {
        const SecretStore = await ethers.getContractFactory("SecretStore");
        const secretStore = await SecretStore.deploy(
            addrs[1]
        );

        expect(await secretStore.TEE_MANAGER()).to.equal(addrs[1]);

        await expect(
            secretStore.initialize(addrs[0]),
        ).to.be.revertedWithCustomError(secretStore, "InvalidInitialization");
    });

    it("deploys as proxy and initializes", async function () {
        const SecretStore = await ethers.getContractFactory("SecretStore");
        const secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        );

        expect(await secretStore.TEE_MANAGER()).to.equal(teeManager.target);
        expect(await secretStore.MIN_STAKE_AMOUNT()).to.equal(10 ** 10);

        expect(await secretStore.hasRole(await secretStore.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    });

    it("cannot initialize with zero address as admin", async function () {
        const SecretStore = await ethers.getContractFactory("SecretStore");
        await expect(
            upgrades.deployProxy(
                SecretStore,
                [ZeroAddress],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        addrs[1]
                    ]
                },
            )
        ).to.be.revertedWithCustomError(SecretStore, "SecretStoreZeroAddressAdmin");
    });

    it("cannot initialize with zero address as tee manager", async function () {
        const SecretStore = await ethers.getContractFactory("SecretStore");
        await expect(
            upgrades.deployProxy(
                SecretStore,
                [addrs[0]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        ZeroAddress
                    ]
                },
            )
        ).to.be.revertedWithCustomError(SecretStore, "SecretStoreZeroAddressTeeManager");
    });

    it("upgrades", async function () {
        const SecretStore = await ethers.getContractFactory("SecretStore");
        const secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        );

        const TeeManager = await ethers.getContractFactory("TeeManager");
        let teeManager2 = await upgrades.deployProxy(
            TeeManager,
            [addrs[0], [image1]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    token,
                    10,
                    10 ** 2,
                    10 ** 6
                ]
            },
        ) as unknown as TeeManager;

        await upgrades.upgradeProxy(
            secretStore.target,
            SecretStore,
            {
                kind: "uups",
                constructorArgs: [
                    teeManager2.target
                ]
            }
        );

        expect(await secretStore.TEE_MANAGER()).to.equal(teeManager2.target);

        expect(await secretStore.hasRole(await secretStore.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    });

    it("does not upgrade without admin", async function () {
        const SecretStore = await ethers.getContractFactory("SecretStore");
        const secretStore = await upgrades.deployProxy(
            SecretStore,
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
            upgrades.upgradeProxy(secretStore.target, SecretStore.connect(signers[1]), {
                kind: "uups",
                constructorArgs: [
                    addrs[1]
                ],
            }),
        ).to.be.revertedWithCustomError(secretStore, "AccessControlUnauthorizedAccount");
    });
});

testERC165(
    "SecretStore - ERC165",
    async function (_signers: Signer[], addrs: string[]) {
        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        const teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

        const SecretStore = await ethers.getContractFactory("SecretStore");
        const secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    teeManager.target
                ]
            },
        );
        return secretStore;
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

describe("SecretStore - TreeMap related and other functions", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let teeManager: TeeManagerMock;
    let secretStore: SecretStore;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

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

        await teeManager.setSecretStore(secretStore.target);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can init tree", async function () {
        let env = 1;
        await expect(secretStore.initTree(env)).to.be.not.reverted;

        expect(await secretStore.isTreeInitialized(env)).to.be.true;
        expect(await secretStore.nodesInTree(env)).that.eq(0);
    });

    it("cannot init tree without JOBS_ROLE", async function () {
        await expect(secretStore.connect(signers[1]).initTree(1))
            .to.be.revertedWithCustomError(secretStore, "AccessControlUnauthorizedAccount");
    });

    it("cannot init tree for the already supported env", async function () {
        await secretStore.initTree(1);
        await expect(secretStore.initTree(1))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreGlobalEnvAlreadySupported");
    });

    it("can remove tree", async function () {
        await secretStore.initTree(1);
        await expect(secretStore.removeTree(1)).to.be.not.reverted;

        expect(await secretStore.isTreeInitialized(1)).to.be.false;
    });

    it("cannot remove tree without JOBS_ROLE", async function () {
        await expect(secretStore.connect(signers[1]).removeTree(1))
            .to.be.revertedWithCustomError(secretStore, "AccessControlUnauthorizedAccount");
    });

    it("cannot remove tree for the unsupported env", async function () {
        await expect(secretStore.removeTree(1))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreGlobalEnvAlreadyUnsupported");
    });

    it('can add multiple envs and remove them', async function () {
        let env = 1;
        await secretStore.initTree(env);

        expect(await secretStore.isTreeInitialized(env)).to.be.true;
        expect(await secretStore.nodesInTree(env)).that.eq(0);

        let jobCapacity = 20,
            storageCapacity = 1e9,
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
        await secretStore.initTree(env);

        expect(await secretStore.isTreeInitialized(env)).to.be.true;
        expect(await secretStore.nodesInTree(env)).that.eq(0);

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

        expect(await secretStore.nodesInTree(1)).that.eq(2);
        expect(await secretStore.nodesInTree(2)).that.eq(3);

        await secretStore.removeTree(1);
        expect(await secretStore.isTreeInitialized(1)).to.be.false;
        expect(await secretStore.isTreeInitialized(2)).to.be.true;

        await secretStore.removeTree(2);
        expect(await secretStore.isTreeInitialized(2)).to.be.false;
    });

    it('can set secret manager with DEFAULT_ADMIN_ROLE', async function () {
        await expect(secretStore.setSecretManager(addrs[2])).to.be.not.reverted;

        expect(await secretStore.SECRET_MANAGER()).to.eq(addrs[2]);
    });

    it('cannot set secret manager without DEFAULT_ADMIN_ROLE', async function () {
        await expect(secretStore.connect(signers[1]).setSecretManager(addrs[2]))
            .to.be.revertedWithCustomError(secretStore, "AccessControlUnauthorizedAccount");
    });

});

describe("SecretStore - Register/Deregister secret store", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let teeManager: TeeManagerMock;
    let secretStore: SecretStore;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

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

        await teeManager.setSecretStore(secretStore.target);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        await secretStore.initTree(1);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can register secret store", async function () {
        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1,
            stakeAmount = 10n ** 19n,
            timestamp = await time.latest() * 1000,
            signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );
        let tx = await teeManager.registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            "0x",
            stakeAmount
        );
        await tx.wait();
        await expect(tx).to.be.not.reverted;

        expect((await secretStore.secretStores(addrs[15])).storageCapacity).to.eq(storageCapacity);
        expect((await secretStore.secretStores(addrs[15])).lastAliveTimestamp)
            .to.eq((await tx.getBlock())?.timestamp);
        expect(await secretStore.getNodeValue(env, addrs[15]))
            .to.eq(stakeAmount / await secretStore.STAKE_ADJUSTMENT_FACTOR());
    });

    it("cannot register secret store without tee manager contract", async function () {
        let storageCapacity = 1e9,
            env = 1,
            stakeAmount = 10;
        await expect(secretStore.registerSecretStore(
            addrs[15],
            storageCapacity,
            env,
            stakeAmount
        )).to.be.revertedWithCustomError(secretStore, "SecretStoreNotTeeManager");
    });

    it("cannot register secret store with invalid env", async function () {
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
        )).to.be.revertedWithCustomError(secretStore, "SecretStoreUnsupportedEnv");
    });

    it('can deregister secret store without occupied storage', async function () {
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
        expect((await secretStore.secretStores(addrs[15])).storageOccupied).to.be.eq(0);
        expect((await secretStore.secretStores(addrs[15])).lastAliveTimestamp).to.eq(0);
    });

    it('cannot deregister secret store with occupied storage', async function () {
        const SecretManagerMock = await ethers.getContractFactory("SecretManagerMock");
        const secretManager = await SecretManagerMock.deploy(secretStore.target);
        await secretStore.setSecretManager(secretManager.target);

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
        await secretManager.selectStores(env, 1, 100);
        // deregister
        await expect(teeManager.deregisterTeeNode(addrs[15]))
            .to.revertedWithCustomError(secretStore, "SecretStoreHasOccupiedStorage");
    });

    it('cannot deregister secret store without tee manager contract', async function () {
        await expect(secretStore.deregisterSecretStore(addrs[15]))
            .to.revertedWithCustomError(secretStore, "SecretStoreNotTeeManager");
    });

});

describe("SecretStore - Staking/Unstaking", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let teeManager: TeeManagerMock;
    let secretStore: SecretStore;
    let secretManager: SecretManagerMock;
    let STAKE_ADJUSTMENT_FACTOR: bigint;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

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
        STAKE_ADJUSTMENT_FACTOR = await secretStore.STAKE_ADJUSTMENT_FACTOR();

        await teeManager.setSecretStore(secretStore.target);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        let env = 1;
        await secretStore.initTree(env);

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

        const SecretManagerMock = await ethers.getContractFactory("SecretManagerMock");
        secretManager = await SecretManagerMock.deploy(secretStore.target) as unknown as SecretManagerMock;
        await secretStore.setSecretManager(secretManager.target);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can stake", async function () {
        let env = 1,
            amount = 2n * (10n ** 19n);
        await expect(teeManager.addTeeNodeStake(addrs[15], amount))
            .to.be.not.reverted;
        expect(await secretStore.getNodeValue(env, addrs[15])).to.eq((10n ** 19n + amount) / STAKE_ADJUSTMENT_FACTOR);

        // case when max storage capacity is exceeded
        await secretManager.selectStores(env, 1, 1e10);
        await expect(teeManager.addTeeNodeStake(addrs[15], amount))
            .to.be.not.reverted;
        expect(await secretStore.isNodePresentInTree(env, addrs[15])).to.be.false;
    });

    it("cannot stake without tee manager contract", async function () {
        let amount = 20;
        await expect(secretStore.addSecretStoreStake(addrs[15], 1, amount))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreNotTeeManager");
    });

    it("can unstake if no occupied storage", async function () {
        let amount = 100n;
        await expect(teeManager.removeTeeNodeStake(addrs[15], amount))
            .to.be.not.reverted;
    });

    it("cannot unstake with occupied storage", async function () {
        const SecretManagerMock = await ethers.getContractFactory("SecretManagerMock");
        const secretManager = await SecretManagerMock.deploy(secretStore.target);
        await secretStore.setSecretManager(secretManager.target);

        // select nodes
        let env = 1;
        await secretManager.selectStores(env, 1, 100);

        // remove stake
        await expect(teeManager.removeTeeNodeStake(addrs[15], 100))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreHasOccupiedStorage");
    });

    it("cannot unstake without tee manager contract", async function () {
        await expect(secretStore.removeSecretStoreStake(addrs[15]))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreNotTeeManager");
    });
});

describe("SecretStore - Drain/Revive secret store", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let teeManager: TeeManagerMock;
    let secretStore: SecretStore;
    let secretManager: SecretManagerMock;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const USDCoin = await ethers.getContractFactory("USDCoin");
        const usdcToken = await upgrades.deployProxy(
            USDCoin,
            [addrs[0]],
            {
                kind: "uups",
            }
        ) as unknown as USDCoin;

        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

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

        await teeManager.setSecretStore(secretStore.target);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        let env = 1;
        await secretStore.initTree(env);

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

        const SecretManagerMock = await ethers.getContractFactory("SecretManagerMock");
        secretManager = await SecretManagerMock.deploy(secretStore.target) as unknown as SecretManagerMock;
        await secretStore.setSecretManager(secretManager.target);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it('can drain secret store', async function () {
        let env = 1;
        let tx = await teeManager.drainTeeNode(addrs[15]);
        await tx.wait();
        await expect(tx).to.be.not.reverted;

        expect(await secretStore.isNodePresentInTree(env, addrs[15])).to.be.false;
        expect((await secretStore.secretStores(addrs[15])).lastAliveTimestamp).to.eq((await tx.getBlock())?.timestamp);
    });

    it('can drain secret store with renounce secret slashing', async function () {
        await time.increase(510);
        let env = 1;
        let tx = await teeManager.drainTeeNode(addrs[15]);
        await tx.wait();
        await expect(tx)
            .to.emit(teeManager, "TeeManagerMockStoreSlashed")
            .withArgs(addrs[15], 1, await secretManager.STAKING_PAYMENT_POOL()); // recipient set in the SecretManagerMock contract

        expect(await secretStore.isNodePresentInTree(env, addrs[15])).to.be.false;
        expect((await secretStore.secretStores(addrs[15])).lastAliveTimestamp).to.eq((await tx.getBlock())?.timestamp);
    });

    it("cannot drain without tee manager contract", async function () {
        await expect(secretStore.drainSecretStore(addrs[15], 1, addrs[0]))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreNotTeeManager");
    });

    it("can revive secret store", async function () {
        let env = 1,
            stakeAmount = 10n ** 19n;
        await teeManager.drainTeeNode(addrs[15]);
        let tx = await teeManager.reviveTeeNode(addrs[15]);
        await tx.wait();
        await expect(tx)
            .to.be.not.reverted;
        expect(await secretStore.getNodeValue(env, addrs[15]))
            .to.eq(stakeAmount / await secretStore.STAKE_ADJUSTMENT_FACTOR());
        expect(await secretStore.getSecretStoreLastAliveTimestamp(addrs[15]))
            .to.eq(await (await tx.getBlock())?.timestamp)

        // case when max storage capacity is exceeded
        await secretManager.selectStores(env, 1, 1e10);
        await teeManager.drainTeeNode(addrs[15]);
        tx = await teeManager.reviveTeeNode(addrs[15]);
        await tx.wait();
        await expect(tx)
            .to.be.not.reverted;
        expect(await secretStore.isNodePresentInTree(env, addrs[15])).to.be.false;
        expect(await secretStore.getSecretStoreLastAliveTimestamp(addrs[15]))
            .to.eq(await (await tx.getBlock())?.timestamp)
    });

    it("cannot revive secret store without tee manager contract", async function () {
        let env = 1,
            stakeAmount = 10;
        await expect(secretStore.reviveSecretStore(addrs[15], env, stakeAmount))
            .to.revertedWithCustomError(secretStore, "SecretStoreNotTeeManager");
    });
});

describe("SecretStore - Select/Release", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let teeManager: TeeManagerMock;
    let secretStore: SecretStore;
    let secretManager: SecretManagerMock;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

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

        await teeManager.setSecretStore(secretStore.target);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        let env = 1;
        await secretStore.initTree(env);

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

        const SecretManagerMock = await ethers.getContractFactory("SecretManagerMock");
        secretManager = await SecretManagerMock.deploy(secretStore.target) as unknown as SecretManagerMock;
        await secretStore.setSecretManager(secretManager.target);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can select secret stores", async function () {
        await expect(secretManager.selectStores(1, 1, 100))
            .to.be.not.reverted;

        expect((await secretStore.secretStores(addrs[15])).storageOccupied).to.be.eq(100);
        expect(await secretStore.isNodePresentInTree(1, addrs[15])).to.be.true;

        // case 2: store is removed from the tree as storageOccupied exceeds storageCapacity
        await expect(secretManager.selectStores(1, 1, 1e9))
            .to.be.not.reverted;

        expect((await secretStore.secretStores(addrs[15])).storageOccupied).to.be.eq(100 + 1e9);
        expect(await secretStore.isNodePresentInTree(1, addrs[15])).to.be.false;
    });

    it("cannot select secret stores without SecretManager contract", async function () {
        await expect(secretStore.connect(signers[1]).selectStores(1, 1, 100))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreNotSecretManager");

        await expect(secretStore.connect(signers[1]).selectNonAssignedSecretStore(1, 1, 100, [addrs[15]]))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreNotSecretManager");
    });

    it("cannot select secret store with unsupported execution env", async function () {
        let env = 2;
        await expect(secretManager.selectStores(env, 1, 100))
            .to.revertedWithCustomError(secretStore, "SecretStoreUnsupportedEnv");

        await expect(secretManager.selectNonAssignedSecretStore(env, 1, 100, []))
            .to.revertedWithCustomError(secretStore, "SecretStoreUnsupportedEnv");
    });

    it("can select secret stores ignoring the already selected ones", async function () {
        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1,
            stakeAmount = 10n ** 19n,
            timestamp = await time.latest() * 1000,
            signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[16],
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

        await expect(secretManager.selectNonAssignedSecretStore(1, 1, 100, [addrs[15]]))
            .to.be.not.reverted;

        expect((await secretStore.secretStores(addrs[15])).storageOccupied).to.be.eq(0);
        expect((await secretStore.secretStores(addrs[16])).storageOccupied).to.be.eq(100);
    });

    it("can release secret store", async function () {
        let secretSize = 100;
        await secretManager.selectStores(1, 1, secretSize);

        await expect(secretManager.releaseStore(addrs[15], secretSize))
            .to.be.not.reverted;

        expect((await secretStore.secretStores(addrs[15])).storageOccupied).to.be.eq(0);

        // case 2: occupying the entire storage to remove the node from tree. On release, node is added back to the tree.
        secretSize = 1e9;
        await secretManager.selectStores(1, 1, secretSize);
        expect(await secretStore.isNodePresentInTree(1, addrs[15])).to.be.false;

        await expect(secretManager.releaseStore(addrs[15], secretSize))
            .to.be.not.reverted;

        expect((await secretStore.secretStores(addrs[15])).storageOccupied).to.be.eq(0);
        expect(await secretStore.isNodePresentInTree(1, addrs[15])).to.be.true;


        // case 3: release store post draining
        secretSize = 100;
        await secretManager.selectStores(1, 1, secretSize);
        await teeManager.drainTeeNode(addrs[15]);
        await expect(secretManager.releaseStore(addrs[15], secretSize))
            .to.be.not.reverted;
        expect((await secretStore.secretStores(addrs[15])).storageOccupied).to.be.eq(0);
    });

    it("cannot release secret stores without SecretManager contract", async function () {
        await expect(secretStore.connect(signers[1]).releaseStore(addrs[15], 100))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreNotSecretManager");
    });
});

describe("SecretStore - Other only secret manager functions", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let teeManager: TeeManagerMock;
    let secretStore: SecretStore;
    let secretManager: SecretManagerMock;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const TeeManagerMock = await ethers.getContractFactory("TeeManagerMock");
        teeManager = await TeeManagerMock.deploy(addrs[1], 600, 1e10) as unknown as TeeManagerMock;

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

        await teeManager.setSecretStore(secretStore.target);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        let env = 1;
        await secretStore.initTree(env);

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

        const SecretManagerMock = await ethers.getContractFactory("SecretManagerMock");
        secretManager = await SecretManagerMock.deploy(secretStore.target) as unknown as SecretManagerMock;
        await secretStore.setSecretManager(secretManager.target);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can add acknowledged secretId to ackSecretIds list", async function () {
        // Select one enclave
        let secretId = 1;
        await expect(secretManager.addAckSecretIdToStore(addrs[15], secretId))
            .to.not.be.reverted;

        expect(await secretStore.getStoreAckSecretIds(addrs[15])).to.deep.eq([1n]);
    });

    it("cannot add ack secretId to ackSecretIds list without SecretManager contract", async function () {
        await expect(secretStore.addAckSecretIdToStore(addrs[15], 1))
            .to.revertedWithCustomError(secretStore, "SecretStoreNotSecretManager");
    });

    it("can do mark alive updates", async function () {
        let currentCheckTimestamp = await time.latest();
        await expect(secretManager.markAliveUpdate(addrs[15], currentCheckTimestamp, 500, addrs[2]))
            .to.not.be.reverted;

        expect(await secretStore.getSecretStoreLastAliveTimestamp(addrs[15])).to.eq(currentCheckTimestamp);

        // case 2: mark alive post draining
        await teeManager.drainTeeNode(addrs[15]);
        currentCheckTimestamp = await time.latest();
        await expect(secretManager.markAliveUpdate(addrs[15], currentCheckTimestamp, 500, addrs[2]))
            .to.be.not.reverted;
        expect(await secretStore.getSecretStoreLastAliveTimestamp(addrs[15])).to.eq(currentCheckTimestamp);

        // case 3: mark alive post stake removal
        await teeManager.removeTeeNodeStake(addrs[15], 10n ** 19n);
        await teeManager.reviveTeeNode(addrs[15]);
        await expect(secretManager.markAliveUpdate(addrs[15], currentCheckTimestamp, 500, addrs[2]))
            .to.be.not.reverted;
        expect(await secretStore.getSecretStoreLastAliveTimestamp(addrs[15])).to.eq(currentCheckTimestamp);
        expect(await secretStore.isNodePresentInTree(1, addrs[15])).to.be.false;
    });

    it("can do mark alive updates with slashing", async function () {
        await time.increase(510);
        let currentCheckTimestamp = await time.latest(),
            recipient = addrs[2];
        await expect(secretManager.markAliveUpdate(addrs[15], currentCheckTimestamp, 500, recipient))
            .to.emit(teeManager, "TeeManagerMockStoreSlashed")
            .withArgs(addrs[15], 1, recipient);

        expect(await secretStore.getSecretStoreLastAliveTimestamp(addrs[15])).to.eq(currentCheckTimestamp);
    });

    it("cannot do mark alive updates without SecretManager contract", async function () {
        await expect(secretStore.markAliveUpdate(addrs[15], await time.latest(), 500, addrs[2]))
            .to.revertedWithCustomError(secretStore, "SecretStoreNotSecretManager");
    });

    it("can do mark dead updates", async function () {
        // Select one enclave
        let storageOccupied = 100;
        await secretManager.selectStores(1, 1, storageOccupied);

        // marking dead to relase 50 units of storage
        let currentCheckTimestamp = await time.latest();
        storageOccupied = 50;
        let tx = await secretManager.markDeadUpdate(addrs[15], currentCheckTimestamp, 500, storageOccupied, addrs[2]);
        await tx.wait();
        await expect(tx).to.be.not.reverted;
        await expect(tx).to.not.emit(teeManager, "TeeManagerMockStoreSlashed");

        expect(await secretStore.getSecretStoreDeadTimestamp(addrs[15])).to.eq(currentCheckTimestamp);
        expect(await secretStore.getStoreAckSecretIds(addrs[15])).to.deep.eq([]);
        // since we have released 50 units of storage, storageOccupied should be 100 - 50 = 50
        expect((await secretStore.secretStores(addrs[15])).storageOccupied).to.eq(50);

        // can mark dead again after some delay, to relase the remaining 50 units of storage
        await time.increase(100);
        currentCheckTimestamp = await time.latest();
        tx = await secretManager.markDeadUpdate(addrs[15], currentCheckTimestamp, 500, storageOccupied, addrs[2]);
        await tx.wait();
        await expect(tx).to.not.be.reverted;
        await expect(tx).to.not.emit(teeManager, "TeeManagerMockStoreSlashed");

        expect(await secretStore.getSecretStoreDeadTimestamp(addrs[15])).to.eq(currentCheckTimestamp);
        expect(await secretStore.getStoreAckSecretIds(addrs[15])).to.deep.eq([]);
        // since we have released 50 units of storage, storageOccupied should be 50 - 50 = 0
        expect((await secretStore.secretStores(addrs[15])).storageOccupied).to.eq(0);
    });

    it("can do mark dead updates with slashing", async function () {
        // Select one enclave
        let storageOccupied = 100;
        await secretManager.selectStores(1, 1, storageOccupied);

        await time.increase(1010);  // 2 epochs passed
        let currentCheckTimestamp = BigInt(await time.latest()),
            markAliveTimeout = 500n,
            recipient = addrs[2];
        await expect(
            secretManager.markDeadUpdate(
                addrs[15],
                currentCheckTimestamp,
                markAliveTimeout,
                storageOccupied,
                recipient
            )
        ).to.emit(teeManager, "TeeManagerMockStoreSlashed")
        .withArgs(addrs[15], 2, recipient);

        expect(await secretStore.getSecretStoreDeadTimestamp(addrs[15])).to.eq(currentCheckTimestamp);
        expect(await secretStore.getStoreAckSecretIds(addrs[15])).to.deep.eq([]);
        expect((await secretStore.secretStores(addrs[15])).storageOccupied).to.eq(0);

        // can mark dead after dead with slashing
        await secretManager.selectStores(1, 1, storageOccupied);

        await time.increase(510);  // 1 epoch passed
        currentCheckTimestamp = BigInt(await time.latest());
        await expect(
            secretManager.markDeadUpdate(
                addrs[15],
                currentCheckTimestamp,
                markAliveTimeout,
                storageOccupied,
                recipient
            )
        ).to.emit(teeManager, "TeeManagerMockStoreSlashed")
        .withArgs(addrs[15], 1, recipient);

        expect(await secretStore.getSecretStoreDeadTimestamp(addrs[15])).to.eq(currentCheckTimestamp);
        expect(await secretStore.getStoreAckSecretIds(addrs[15])).to.deep.eq([]);
        expect((await secretStore.secretStores(addrs[15])).storageOccupied).to.eq(0);

        // can mark alive after dead, for the lastest epoch
        await time.increase(510); // 1 epoch passed
        currentCheckTimestamp = BigInt(await time.latest());
        await expect(secretManager.markAliveUpdate(addrs[15], currentCheckTimestamp, markAliveTimeout, recipient))
            .to.emit(teeManager, "TeeManagerMockStoreSlashed")
            .withArgs(addrs[15], 1, recipient);

        expect(await secretStore.getSecretStoreLastAliveTimestamp(addrs[15])).to.eq(currentCheckTimestamp);
    });

    it("cannot do mark dead updates without SecretManager contract", async function () {
        await expect(secretStore.markDeadUpdate(addrs[15], await time.latest(), 500, 100, addrs[2]))
            .to.revertedWithCustomError(secretStore, "SecretStoreNotSecretManager");
    });

    it("can do secret termination updates", async function () {
        // Select one enclave
        let secretId = 1,
            sizeLimit = 100;
        await secretManager.selectStores(1, 1, sizeLimit);
        await secretManager.addAckSecretIdToStore(addrs[15], secretId);

        await expect(secretManager.secretTerminationUpdate(addrs[15], sizeLimit, secretId))
            .to.not.be.reverted;

        expect((await secretStore.secretStores(addrs[15])).storageOccupied).to.be.eq(0);
        expect(await secretStore.getStoreAckSecretIds(addrs[15])).to.deep.eq([]);
    });

    it("can do secret termination updates with multiple ack secrets", async function () {
        // Select one enclave
        let secretId = 1,
            sizeLimit = 100;
        await secretManager.selectStores(1, 1, sizeLimit);
        // adding multiple ack secrets
        await secretManager.addAckSecretIdToStore(addrs[15], secretId++);
        await secretManager.addAckSecretIdToStore(addrs[15], secretId++);
        await secretManager.addAckSecretIdToStore(addrs[15], secretId);

        // terminating 2nd ack secret
        secretId = 2;
        await expect(secretManager.secretTerminationUpdate(addrs[15], 30, secretId))
            .to.not.be.reverted;

        expect((await secretStore.secretStores(addrs[15])).storageOccupied).to.be.eq(sizeLimit - 30);
        expect(await secretStore.getStoreAckSecretIds(addrs[15])).to.deep.eq([1n, 3n]);

        // cannot remove non existing secret
        secretId = 4;
        await expect(secretManager.secretTerminationUpdate(addrs[15], 30, secretId))
            .to.not.be.reverted;
        expect(await secretStore.getStoreAckSecretIds(addrs[15])).to.deep.eq([1n, 3n]);
    });

    it("cannot do secret termination updates without SecretManager contract", async function () {
        await expect(secretStore.secretTerminationUpdate(addrs[15], 100, 1))
            .to.revertedWithCustomError(secretStore, "SecretStoreNotSecretManager");
    });

    it("can upsert node in tree", async function () {
        await expect(teeManager.updateTreeState(addrs[15])).to.be.not.reverted;
        expect(await secretStore.isNodePresentInTree(1, addrs[15])).to.be.true;
        expect(await secretStore.getNodeValue(1, addrs[15]))
            .to.eq((10n ** 19n) / await secretStore.STAKE_ADJUSTMENT_FACTOR());
    });

    it("cannot upsert node in tree without TeeManager contract", async function () {
        await expect(secretStore.upsertTreeNode(1, addrs[15], 10n ** 20n))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreNotTeeManager");
    });

    it("can delete node in tree", async function () {
        await teeManager.removeTeeNodeStake(addrs[15], 10n ** 19n);

        // as stake < minStake, it will delete the node
        await expect(teeManager.updateTreeState(addrs[15])).to.be.not.reverted;
        expect(await secretStore.isNodePresentInTree(1, addrs[15])).to.be.false;
    });

    it("cannot delete node in tree without TeeManager contract", async function () {
        await expect(secretStore.deleteTreeNodeIfPresent(1, addrs[15]))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreNotTeeManager");
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

function walletForIndex(idx: number): Wallet {
    let wallet = ethers.HDNodeWallet.fromPhrase(
        "test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString()
    );

    return new Wallet(wallet.privateKey);
}
