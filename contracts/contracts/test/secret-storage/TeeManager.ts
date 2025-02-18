import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import {
    BytesLike,
    Signer,
    Wallet,
    ZeroAddress,
    ZeroHash,
    keccak256,
    parseUnits,
    solidityPacked
} from "ethers";
import { ethers, upgrades } from "hardhat";
import {
    AttestationAutherUpgradeable,
    AttestationVerifier,
    Executors,
    ExecutorsMock,
    Jobs,
    Pond,
    SecretManager,
    SecretStore,
    SecretStoreMock,
    TeeManager,
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

describe("TeeManager - Init", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let token: string;

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
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("deploys with initialization disabled", async function () {
        const TeeManager = await ethers.getContractFactory("TeeManager");
        const teeManager = await TeeManager.deploy(
            attestationVerifier.target,
            600,
            token,
            10 ** 10,
            10 ** 2,
            10 ** 6
        );

        expect(await teeManager.ATTESTATION_VERIFIER()).to.equal(attestationVerifier.target);
        expect(await teeManager.ATTESTATION_MAX_AGE()).to.equal(600);
        expect(await teeManager.STAKING_TOKEN()).to.equal(token);
        expect(await teeManager.MIN_STAKE_AMOUNT()).to.equal(10 ** 10);
        expect(await teeManager.SLASH_PERCENT_IN_BIPS()).to.equal(10 ** 2);
        expect(await teeManager.SLASH_MAX_BIPS()).to.equal(10 ** 6);

        await expect(
            teeManager.initialize(addrs[0], []),
        ).to.be.revertedWithCustomError(teeManager, "InvalidInitialization");

        await expect(
            teeManager.initialize(addrs[0], [image1, image2]),
        ).to.be.revertedWithCustomError(teeManager, "InvalidInitialization");
    });

    it("deploys as proxy and initializes", async function () {
        const TeeManager = await ethers.getContractFactory("TeeManager");
        const teeManager = await upgrades.deployProxy(
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
        );

        expect(await teeManager.ATTESTATION_VERIFIER()).to.equal(attestationVerifier.target);
        expect(await teeManager.ATTESTATION_MAX_AGE()).to.equal(600);
        expect(await teeManager.STAKING_TOKEN()).to.equal(token);
        expect(await teeManager.MIN_STAKE_AMOUNT()).to.equal(10 ** 10);
        expect(await teeManager.SLASH_PERCENT_IN_BIPS()).to.equal(10 ** 2);
        expect(await teeManager.SLASH_MAX_BIPS()).to.equal(10 ** 6);

        expect(await teeManager.hasRole(await teeManager.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        {
            const { PCR0, PCR1, PCR2 } = await teeManager.getWhitelistedImage(getImageId(image1));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
        }
    });

    it("cannot initialize with zero address as admin", async function () {
        const TeeManager = await ethers.getContractFactory("TeeManager");
        await expect(
            upgrades.deployProxy(
                TeeManager,
                [ZeroAddress, [image1, image2, image3]],
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
            )
        ).to.be.revertedWithCustomError(TeeManager, "TeeManagerZeroAddressAdmin");
    });

    it("cannot initialize with zero address as staking token", async function () {
        const TeeManager = await ethers.getContractFactory("TeeManager");
        await expect(
            upgrades.deployProxy(
                TeeManager,
                [addrs[0], [image1, image2, image3]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        attestationVerifier.target,
                        600,
                        ZeroAddress,
                        10 ** 10,
                        10 ** 2,
                        10 ** 6
                    ]
                },
            )
        ).to.be.revertedWithCustomError(TeeManager, "TeeManagerZeroAddressStakingToken");
    });

    it("cannot initialize with zero minimum stakes", async function () {
        const TeeManager = await ethers.getContractFactory("TeeManager");
        await expect(
            upgrades.deployProxy(
                TeeManager,
                [addrs[0], [image1, image2, image3]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        attestationVerifier.target,
                        600,
                        token,
                        0,
                        10 ** 2,
                        10 ** 6
                    ]
                },
            )
        ).to.be.revertedWithCustomError(TeeManager, "TeeManagerZeroMinStakeAmount");
    });

    it("cannot initialize with invalid slash params", async function () {
        const TeeManager = await ethers.getContractFactory("TeeManager");
        await expect(
            upgrades.deployProxy(
                TeeManager,
                [addrs[0], [image1, image2, image3]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        attestationVerifier.target,
                        600,
                        token,
                        10 ** 10,
                        10 ** 7,
                        10 ** 6
                    ]
                },
            )
        ).to.be.revertedWithCustomError(TeeManager, "TeeManagerInvalidSlashParams");

        await expect(
            upgrades.deployProxy(
                TeeManager,
                [addrs[0], [image1, image2, image3]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        attestationVerifier.target,
                        600,
                        token,
                        10 ** 10,
                        10 ** 2,
                        10 ** 7
                    ]
                },
            )
        ).to.be.revertedWithCustomError(TeeManager, "TeeManagerInvalidSlashParams");
    });

    it("upgrades", async function () {
        const TeeManager = await ethers.getContractFactory("TeeManager");
        const teeManager = await upgrades.deployProxy(
            TeeManager,
            [addrs[0], [image1, image2, image3]],
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
        );
        // Deploy new attestation verifier
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifier2 = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        const token2 = addrs[2];

        await upgrades.upgradeProxy(
            teeManager.target,
            TeeManager,
            {
                kind: "uups",
                constructorArgs: [
                    attestationVerifier2.target,
                    100,
                    token2,
                    10,
                    10,
                    1000
                ]
            }
        );

        expect(await teeManager.ATTESTATION_VERIFIER()).to.equal(attestationVerifier2.target);
        expect(await teeManager.ATTESTATION_MAX_AGE()).to.equal(100);
        expect(await teeManager.STAKING_TOKEN()).to.equal(token2);
        expect(await teeManager.MIN_STAKE_AMOUNT()).to.equal(10);
        expect(await teeManager.SLASH_PERCENT_IN_BIPS()).to.equal(10);
        expect(await teeManager.SLASH_MAX_BIPS()).to.equal(1000);

        expect(await teeManager.hasRole(await teeManager.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        {
            const { PCR0, PCR1, PCR2 } = await teeManager.getWhitelistedImage(getImageId(image1));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
        }
        {
            const { PCR0, PCR1, PCR2 } = await teeManager.getWhitelistedImage(getImageId(image2));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image2);
        }
        {
            const { PCR0, PCR1, PCR2 } = await teeManager.getWhitelistedImage(getImageId(image3));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
        }
    });

    it("does not upgrade without admin", async function () {
        const TeeManager = await ethers.getContractFactory("TeeManager");
        const teeManager = await upgrades.deployProxy(
            TeeManager,
            [addrs[0], [image1, image2, image3]],
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
        );

        await expect(
            upgrades.upgradeProxy(teeManager.target, TeeManager.connect(signers[1]), {
                kind: "uups",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    token,
                    10 ** 10,
                    10 ** 2,
                    10 ** 6
                ],
            }),
        ).to.be.revertedWithCustomError(teeManager, "AccessControlUnauthorizedAccount");
    });
});

testERC165(
    "TeeManager - ERC165",
    async function (_signers: Signer[], addrs: string[]) {
        const TeeManager = await ethers.getContractFactory("TeeManager");
        const teeManager = await upgrades.deployProxy(
            TeeManager,
            [addrs[0], [image2, image3]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    addrs[1],
                    600,
                    addrs[2],
                    10,
                    10 ** 2,
                    10 ** 6
                ]
            },
        ) as unknown as TeeManager;
        return teeManager;
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

describe("TeeManager - Whitelist/Revoke enclave images and other setter functions", function () {
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
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        token = addrs[1];

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
                    token,
                    10 ** 10,
                    10 ** 2,
                    10 ** 6
                ]
            },
        ) as unknown as TeeManager;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can whitelist enclave image with admin account", async function () {
        await expect(teeManager.connect(signers[0]).whitelistEnclaveImage(image1.PCR0, image1.PCR1, image1.PCR2))
            .to.emit(teeManager, "EnclaveImageWhitelisted")
            .withArgs(getImageId(image1), image1.PCR0, image1.PCR1, image1.PCR2);

        const { PCR0, PCR1, PCR2 } = await teeManager.getWhitelistedImage(getImageId(image1));
        expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
    });

    it("cannot whitelist enclave image without admin account", async function () {
        await expect(teeManager.connect(signers[1]).whitelistEnclaveImage(image1.PCR0, image1.PCR1, image1.PCR2))
            .to.be.revertedWithCustomError(teeManager, "AccessControlUnauthorizedAccount");
    });

    it("can revoke enclave image with admin account", async function () {
        await expect(teeManager.connect(signers[0]).revokeEnclaveImage(getImageId(image2)))
            .to.emit(teeManager, "EnclaveImageRevoked").withArgs(getImageId(image2));

        const { PCR0 } = await teeManager.getWhitelistedImage(getImageId(image2));
        expect(PCR0).to.equal("0x");
    });

    it("cannot revoke enclave image without admin account", async function () {
        await expect(teeManager.connect(signers[1]).revokeEnclaveImage(getImageId(image2)))
            .to.be.revertedWithCustomError(teeManager, "AccessControlUnauthorizedAccount");
    });

    it('can set executors with DEFAULT_ADMIN_ROLE', async function () {
        await expect(teeManager.setExecutors(addrs[2])).to.be.not.reverted;

        expect(await teeManager.EXECUTORS()).to.eq(addrs[2]);
    });

    it('cannot set executors without DEFAULT_ADMIN_ROLE', async function () {
        await expect(teeManager.connect(signers[1]).setExecutors(addrs[2]))
            .to.be.revertedWithCustomError(teeManager, "AccessControlUnauthorizedAccount");
    });

    it('can set secret store with DEFAULT_ADMIN_ROLE', async function () {
        await expect(teeManager.setSecretStore(addrs[2])).to.be.not.reverted;

        expect(await teeManager.SECRET_STORE()).to.eq(addrs[2]);
    });

    it('cannot set secret store without DEFAULT_ADMIN_ROLE', async function () {
        await expect(teeManager.connect(signers[1]).setSecretStore(addrs[2]))
            .to.be.revertedWithCustomError(teeManager, "AccessControlUnauthorizedAccount");
    });
});

describe("TeeManager - Register/Deregister tee node", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let stakingToken: Pond;
    let attestationVerifier: AttestationVerifier;
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
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        const USDCoin = await ethers.getContractFactory("USDCoin");
        let usdcToken = await upgrades.deployProxy(
            USDCoin,
            [addrs[0]],
            {
                kind: "uups",
            }
        ) as unknown as USDCoin;

        const Pond = await ethers.getContractFactory("Pond");
        stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
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

        let noOfNodesToSelect = 1,
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

        // approval for create secret
        await usdcToken.approve(secretManager.target, parseUnits("10000", 6));
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can register tee node", async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1;
        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[15]);

        await expect(teeManager.connect(signers[1]).registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            signedDigest,
            0
        )).to.emit(teeManager, "EnclaveKeyVerified").withArgs(addrs[15], getImageId(image2), pubkeys[15]);
        expect(await teeManager.getVerifiedKey(addrs[15])).to.equal(getImageId(image2));
        expect(await teeManager.getTeeNodeOwner(addrs[15])).to.eq(addrs[1]);
        expect(await teeManager.allowOnlyVerified(addrs[15])).to.be.not.reverted;
        await expect(teeManager.allowOnlyVerified(addrs[16]))
            .to.be.revertedWithCustomError(teeManager, "AttestationAutherKeyNotVerified");
    });

    it("cannot register tee node with old signature timestamp", async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 700;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1;
        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[15]);

        await expect(teeManager.connect(signers[1]).registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            signedDigest,
            0
        )).to.revertedWithCustomError(teeManager, "TeeManagerSignatureTooOld");
    });

    it("cannot register tee node with different attestation pubkey and digest signing key", async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1;
        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[16]);

        await expect(teeManager.connect(signers[1]).registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            signedDigest,
            0
        )).to.revertedWithCustomError(teeManager, "TeeManagerInvalidSigner");
    });

    it("cannot register tee node with same enclave key twice", async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1;
        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[15]);
        await teeManager.connect(signers[1]).registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            signedDigest,
            0
        )
        await expect(teeManager.connect(signers[1]).registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            signedDigest,
            0
        )).to.revertedWithCustomError(teeManager, "TeeManagerEnclaveAlreadyExists");
    });

    // drain then deregister with no occupied storage and assigned jobs
    it('can deregister tee node without occupied storage and assigned jobs', async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1;
        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[15]);

        await teeManager.connect(signers[1]).registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            signedDigest,
            0
        );

        await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);
        await expect(teeManager.connect(signers[1]).deregisterTeeNode(addrs[15]))
            .to.emit(teeManager, "TeeNodeDeregistered").withArgs(addrs[15]);
        expect(await teeManager.getVerifiedKey(addrs[15])).to.equal(ZeroHash);
        expect((await teeManager.teeNodes(addrs[15])).owner).to.be.eq(ZeroAddress);
    });

    // fail to deregister if no draining
    it('Failed deregistration without draining', async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1;
        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[15]);


        await teeManager.connect(signers[1]).registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            signedDigest,
            0
        );

        await expect(teeManager.connect(signers[1]).deregisterTeeNode(addrs[15]))
            .to.revertedWithCustomError(teeManager, "TeeManagerEnclaveNotDraining");
    });

    // drain then deregister failed with occupied storage != 0
    it('cannot deregister secret store with occupied storage (due to unack secret)', async function () {
        await stakingToken.transfer(addrs[1], 10n ** 19n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 19n);

        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1;
        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[15]);

        // register a enclave
        await teeManager.connect(signers[1]).registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            signedDigest,
            10n ** 19n
        )

        // CREATE SECRET
        let sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, [addrs[3]]);
        // drain
        await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);
        // deregister
        await expect(teeManager.connect(signers[1]).deregisterTeeNode(addrs[15]))
            .to.revertedWithCustomError(secretStore, "SecretStoreHasOccupiedStorage");
    });

    it('can deregister secret store after drain', async function () {
        await stakingToken.transfer(addrs[1], 10n ** 19n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 19n);

        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1;
        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[15]);

        // register a enclave
        await teeManager.connect(signers[1]).registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            signedDigest,
            10n ** 19n
        )

        // CREATE SECRET
        let sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, [addrs[3]]);

        // ACKNOWLEDGE SECRET
        let secretId = 1;
        signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[15]);
        await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);

        // drain
        await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);
        // deregister
        await expect(teeManager.connect(signers[1]).deregisterTeeNode(addrs[15]))
            .to.emit(teeManager, "TeeNodeDeregistered")
            .withArgs(addrs[15]);
    });

    it('can deregister secret store when assigned secret not ack after ackTimeout', async function () {
        await stakingToken.transfer(addrs[1], 10n ** 19n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 19n);

        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1;
        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[15]);

        // register a enclave
        await teeManager.connect(signers[1]).registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            signedDigest,
            10n ** 19n
        )

        // CREATE SECRET
        let sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, [addrs[3]]);

        // drain
        await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);
        // deregister can only be done after ack fail is marked after ackTimeout
        await time.increase(130);
        // mark ack failed
        await secretManager.acknowledgeStoreFailed(1);
        // deregister
        await expect(teeManager.connect(signers[1]).deregisterTeeNode(addrs[15]))
            .to.emit(teeManager, "TeeNodeDeregistered")
            .withArgs(addrs[15]);
    });

    // drain then deregister failed with active jobs != 0
    it('cannot deregister secret store with active jobs', async function () {
        await stakingToken.transfer(addrs[1], 10n ** 19n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 19n);

        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1;
        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[15]);

        // register a enclave
        await teeManager.connect(signers[1]).registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            signedDigest,
            10n ** 19n
        )

        // select nodes
        await executors.selectExecutionNodes(env, [addrs[15]], 1);
        // drain
        await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);
        // deregister
        await expect(teeManager.connect(signers[1]).deregisterTeeNode(addrs[15]))
            .to.revertedWithCustomError(executors, "ExecutorsHasPendingJobs");
    });

    it('cannot deregister tee node without the owner account', async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            storageCapacity = 20,
            env = 1;
        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[15]);

        // register a enclave
        await teeManager.connect(signers[1]).registerTeeNode(
            attestationSign,
            attestation,
            jobCapacity,
            storageCapacity,
            env,
            signTimestamp,
            signedDigest,
            0
        );
        // deregister with signer 0
        await expect(teeManager.deregisterTeeNode(addrs[15]))
            .to.revertedWithCustomError(teeManager, "TeeManagerInvalidEnclaveOwner");
    });

});

describe("TeeManager - Staking/Unstaking", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let stakingToken: Pond;
    let attestationVerifier: AttestationVerifier;
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
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        const USDCoin = await ethers.getContractFactory("USDCoin");
        let usdcToken = await upgrades.deployProxy(
            USDCoin,
            [addrs[0]],
            {
                kind: "uups",
            }
        ) as unknown as USDCoin;

        const Pond = await ethers.getContractFactory("Pond");
        stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
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

        let noOfNodesToSelect = 1,
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

        let env = 1;
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        await executors.initTree(1);
        await secretStore.initTree(1);

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

        await stakingToken.transfer(addrs[1], 100000);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10000);
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            storageCapacity = 1e9,
            stakeAmount = 10;
        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[15]);

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

        // approval for create secret
        await usdcToken.approve(secretManager.target, parseUnits("10000", 6));
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can stake", async function () {
        let amount = 20;
        await expect(teeManager.connect(signers[1]).addTeeNodeStake(addrs[15], amount))
            .to.emit(teeManager, "TeeNodeStakeAdded");

        let teeNode = await teeManager.teeNodes(addrs[15]);
        expect(teeNode.stakeAmount).to.be.eq(30);
        expect(await stakingToken.balanceOf(teeManager.target)).to.be.eq(30);
        expect(await stakingToken.balanceOf(addrs[1])).to.be.eq(99970);
        expect(await teeManager.getTeeNodesStake([addrs[15]])).to.deep.eq([30n]);
    });

    it("can stake if draining", async function () {
        await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);

        let amount = 20;
        await expect(teeManager.connect(signers[1]).addTeeNodeStake(addrs[15], amount))
            .to.emit(teeManager, "TeeNodeStakeAdded");

        let secretStorage = await teeManager.teeNodes(addrs[15]);
        expect(secretStorage.stakeAmount).to.be.eq(30);
        expect(await stakingToken.balanceOf(teeManager.target)).to.be.eq(30);
        expect(await stakingToken.balanceOf(addrs[1])).to.be.eq(99970);
        expect(await teeManager.getTeeNodesStake([addrs[15]])).to.deep.eq([30n]);

    });

    it("cannot stake without secret store owner", async function () {
        let amount = 20;
        await expect(teeManager.addTeeNodeStake(addrs[15], amount))
            .to.be.revertedWithCustomError(teeManager, "TeeManagerInvalidEnclaveOwner");
    });

    it("can unstake with draining if no occupied storage", async function () {
        let amount = 10;
        await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);
        await expect(teeManager.connect(signers[1]).removeTeeNodeStake(addrs[15], amount))
            .to.emit(teeManager, "TeeNodeStakeRemoved");

        let secretStorage = await teeManager.teeNodes(addrs[15]);
        expect(secretStorage.stakeAmount).to.be.eq(0);
        expect(await stakingToken.balanceOf(teeManager.target)).to.be.eq(0);
        expect(await stakingToken.balanceOf(addrs[1])).to.be.eq(100000);
        expect(await teeManager.getTeeNodesStake([addrs[15]])).to.deep.eq([0]);

    });

    it("Failed to unstake without draining", async function () {
        let amount = 0;
        await expect(teeManager.connect(signers[1]).removeTeeNodeStake(addrs[15], amount))
            .to.revertedWithCustomError(teeManager, "TeeManagerEnclaveNotDraining");
    });

    it("cannot unstake without secret store operator", async function () {
        let amount = 10;
        await expect(teeManager.removeTeeNodeStake(addrs[15], amount))
            .to.be.revertedWithCustomError(teeManager, "TeeManagerInvalidEnclaveOwner");
    });

    it('cannot unstake with occupied storage after draining started (due to unack secret)', async function () {
        await stakingToken.transfer(addrs[1], 10n ** 19n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 19n);

        // add stake to get node added to tree
        await teeManager.connect(signers[1]).addTeeNodeStake(addrs[15], 10n ** 19n);

        // CREATE SECRET
        let env = 1,
            sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, [addrs[3]]);
        // drain
        await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);

        let amount = 5;
        await expect(teeManager.connect(signers[1]).removeTeeNodeStake(addrs[15], amount))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreHasOccupiedStorage");
    });

    it('can unstake store after drain', async function () {
        let stakeAmount = 10n ** 19n;
        await stakingToken.transfer(addrs[1], stakeAmount);
        await stakingToken.connect(signers[1]).approve(teeManager.target, stakeAmount);

        // add stake to get node added to tree
        await teeManager.connect(signers[1]).addTeeNodeStake(addrs[15], stakeAmount);

        // CREATE SECRET
        let env = 1,
            sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, [addrs[3]]);
        // ACKNOWLEDGE SECRET
        let secretId = 1,
            signTimestamp = await time.latest() - 540;
        let signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[15]);
        await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);

        // drain
        await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);

        let amount = 5;
        await expect(teeManager.connect(signers[1]).removeTeeNodeStake(addrs[15], amount))
            .to.emit(teeManager, "TeeNodeStakeRemoved")
            .withArgs(addrs[15], amount);
        expect(await teeManager.getTeeNodesStake([addrs[15]])).to.deep.eq([5n + stakeAmount]);
    });

    it('can unstake when assigned secret not ack after ackTimeout', async function () {
        let stakeAmount = 10n ** 19n;
        await stakingToken.transfer(addrs[1], stakeAmount);
        await stakingToken.connect(signers[1]).approve(teeManager.target, stakeAmount);

        // add stake to get node added to tree
        await teeManager.connect(signers[1]).addTeeNodeStake(addrs[15], stakeAmount);

        // CREATE SECRET
        let env = 1,
            sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, [addrs[3]]);
        // drain
        await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);
        // stake withdrawal can only be done after ack fail is marked after ackTimeout
        await time.increase(130);
        // mark ack failed
        await secretManager.acknowledgeStoreFailed(1);

        let amount = 5;
        await expect(teeManager.connect(signers[1]).removeTeeNodeStake(addrs[15], amount))
            .to.emit(teeManager, "TeeNodeStakeRemoved")
            .withArgs(addrs[15], amount);
        expect(await teeManager.getTeeNodesStake([addrs[15]])).to.deep.eq([5n + stakeAmount]);
    });

    it('cannot unstake with active jobs after draining started', async function () {
        await stakingToken.transfer(addrs[1], 10n ** 19n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 19n);

        // add stake to get node added to tree
        await teeManager.connect(signers[1]).addTeeNodeStake(addrs[15], 10n ** 19n);
        // select nodes
        await executors.selectExecutionNodes(1, [addrs[15]], 1);
        // drain
        await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);

        let amount = 5;
        await expect(teeManager.connect(signers[1]).removeTeeNodeStake(addrs[15], amount))
            .to.be.revertedWithCustomError(executors, "ExecutorsHasPendingJobs");

    });
});

describe("TeeManager - Drain/Revive secret store", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let stakingToken: Pond;
    let usdcToken: USDCoin;
    let attestationVerifier: AttestationVerifier;
    let teeManager: TeeManager;
    let executors: Executors;
    let secretStore: SecretStore;
    let secretManager: SecretManager;
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

        let noOfNodesToSelect = 1,
            globalMaxStoreSize = 1500,
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

        const Jobs = await ethers.getContractFactory("contracts/secret-storage/job-allocation/Jobs.sol:Jobs");
        jobs = await upgrades.deployProxy(
            Jobs,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    stakingToken.target,
                    usdcToken.target,
                    600,
                    100,
                    3,
                    stakingPaymentPool,
                    addrs[2]
                ]
            },
        ) as unknown as Jobs;

        // Grant role to jobs contract on executor
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), jobs.target);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), jobs.target);

        await jobs.setExecutors(executors.target);
        await jobs.setSecretStore(secretStore.target);
        await jobs.setSecretManager(secretManager.target);

        let env = 1,
            executionFeePerMs = 1,
            stakingRewardPerMs = 1;
        await jobs.addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs);

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

        // approval for tee node regitration
        await stakingToken.transfer(addrs[1], 10n ** 19n);
        await stakingToken.connect(signers[1]).approve(teeManager.target, 10n ** 19n);

        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );
        let jobCapacity = 20,
            storageCapacity = 2100,
            stakeAmount = 10n ** 19n;
        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[15]);
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

        // approval for create secret
        await usdcToken.approve(secretManager.target, parseUnits("10000", 6));

        // CREATE SECRET
        let sizeLimit = 1000,
            endTimestamp = await time.latest() + 800,
            usdcDeposit = parseUnits("30", 6);
        await secretManager.createSecret(env, sizeLimit, endTimestamp, usdcDeposit, [addrs[3]]);

        // ACKNOWLEDGE SECRET
        let secretId = 1;
        signTimestamp = await time.latest();
        signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[15]);
        await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);

        // approval for create job
        await usdcToken.transfer(addrs[3], 10n ** 6n);
        await usdcToken.connect(signers[3]).approve(jobs.target, 10n ** 6n);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it('can drain tee node', async function () {
        let nodeOwnerPondBalInitial = await stakingToken.balanceOf(addrs[0]);
        let tx = await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);
        await tx.wait();
        await expect(tx)
            .to.emit(teeManager, "TeeNodeDrained").withArgs(addrs[15]);

        let nodeOwnerPondBalFinal = await stakingToken.balanceOf(addrs[0]);
        expect(nodeOwnerPondBalFinal).to.eq(nodeOwnerPondBalInitial);
        expect((await teeManager.teeNodes(addrs[15])).draining).to.be.eq(true);
        expect(await executors.isNodePresentInTree(1, addrs[15])).to.be.false;
        expect(await secretStore.isNodePresentInTree(1, addrs[15])).to.be.false;
        expect(await secretStore.getStoreAckSecretIds(addrs[15])).to.deep.eq([]);
        expect((await secretStore.secretStores(addrs[15])).lastAliveTimestamp).to.eq((await tx.getBlock())?.timestamp);
    });

    it('can drain tee node with renounced secret slashing', async function () {
        await time.increase(510);

        let userSecret = await secretManager.userStorage(1);
        let nodeOwnerBalInitial = await usdcToken.balanceOf(addrs[1]);

        let tx = await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);
        await tx.wait();
        await expect(tx).to.emit(teeManager, "TeeNodeDrained").withArgs(addrs[15]);

        expect((await teeManager.teeNodes(addrs[15])).draining).to.be.eq(true);
        expect(await executors.isNodePresentInTree(1, addrs[15])).to.be.false;
        expect(await secretStore.isNodePresentInTree(1, addrs[15])).to.be.false;
        expect(await secretStore.getStoreAckSecretIds(addrs[15])).to.deep.eq([]);
        expect((await secretStore.secretStores(addrs[15])).lastAliveTimestamp).to.eq((await tx.getBlock())?.timestamp);

        // calculating slashed amount payment
        let stakeAmount = 10n ** 19n,
            missedEpochs = 1n,
            slashMaxBips = 10n ** 6n,
            slashPercentInBips = 10n ** 2n;
        const remainingStakeAmount = stakeAmount * ((slashMaxBips - slashPercentInBips) ** missedEpochs) / 
            (slashMaxBips ** missedEpochs);
        const slashedAmount = stakeAmount - remainingStakeAmount;

        expect(await stakingToken.balanceOf(addrs[2])).to.eq(slashedAmount);
        expect(await (await teeManager.teeNodes(addrs[15])).stakeAmount).to.be.eq(remainingStakeAmount);
        expect(await stakingToken.balanceOf(teeManager.target)).to.be.eq(remainingStakeAmount);

        // calculating usdc payment to tee node
        let endTimestamp = BigInt((await tx.getBlock())?.timestamp as number),
            startTimestamp = userSecret.ackTimestamp,
            secretStoreFeeRate = 10n;

        let usdcPayment = (endTimestamp - startTimestamp) * userSecret.sizeLimit * secretStoreFeeRate;
        let nodeOwnerBalFinal = await usdcToken.balanceOf(addrs[1]);
        expect(nodeOwnerBalFinal - nodeOwnerBalInitial).to.eq(usdcPayment);

        // calculating updated usdc deposit amount
        let ackTimestamp = userSecret.ackTimestamp;
        usdcPayment = (endTimestamp - ackTimestamp) * userSecret.sizeLimit * secretStoreFeeRate;
        expect((await secretManager.userStorage(1)).usdcDeposit).to.eq(parseUnits("30", 6) - usdcPayment);
    });

    it("cannot drain without tee node owner", async function () {
        await expect(teeManager.drainTeeNode(addrs[15]))
            .to.be.revertedWithCustomError(teeManager, "TeeManagerInvalidEnclaveOwner");
    });

    it('cannot drain tee node twice consecutively', async function () {
        await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);
        await expect(teeManager.connect(signers[1]).drainTeeNode(addrs[15]))
            .to.revertedWithCustomError(teeManager, "TeeManagerEnclaveAlreadyDraining");
    });

    it("can revive tee node after draining", async function () {
        // Drain tee node
        await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);

        await expect(teeManager.connect(signers[1]).reviveTeeNode(addrs[15]))
            .to.emit(teeManager, "TeeNodeRevived").withArgs(addrs[15]);

        expect((await teeManager.teeNodes(addrs[15])).draining).to.be.eq(false);
        expect(await executors.isNodePresentInTree(1, addrs[15])).to.be.true;
        expect(await secretStore.isNodePresentInTree(1, addrs[15])).to.be.true;
    });

    it("can revive tee node after draining with stake < minStake", async function () {
        // Drain tee node
        await teeManager.connect(signers[1]).drainTeeNode(addrs[15]);

        // Remove stake
        await teeManager.connect(signers[1]).removeTeeNodeStake(addrs[15], 10n ** 19n);

        await expect(teeManager.connect(signers[1]).reviveTeeNode(addrs[15]))
            .to.emit(teeManager, "TeeNodeRevived").withArgs(addrs[15]);

        expect((await teeManager.teeNodes(addrs[15])).draining).to.be.eq(false);
        expect(await executors.isNodePresentInTree(1, addrs[15])).to.be.false;
        expect(await secretStore.isNodePresentInTree(1, addrs[15])).to.be.false;
    });

    it("cannot revive tee node without draining", async function () {
        await expect(teeManager.connect(signers[1]).reviveTeeNode(addrs[15]))
            .to.revertedWithCustomError(teeManager, "TeeManagerEnclaveAlreadyRevived");
    });

    it("cannot revive tee node without tee node owner", async function () {
        await expect(teeManager.reviveTeeNode(addrs[15]))
            .to.revertedWithCustomError(teeManager, "TeeManagerInvalidEnclaveOwner");
    });
});

describe("TeeManager - Slash Store/Executor", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let teeManager: TeeManager;
    let executors: Executors;
    let secretStore: SecretStore;

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

        let env = 1;
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        await executors.initTree(1);
        await secretStore.initTree(1);

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

        await token.transfer(addrs[1], 10n ** 28n);
        await token.connect(signers[1]).approve(teeManager.target, 10n ** 28n);
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            storageCapacity = 1e9,
            stakeAmount = 10n ** 28n;
        let signedDigest = await registerTeeNodeSignature(addrs[1], jobCapacity, storageCapacity, env, signTimestamp,
            wallets[15]);

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
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can slash store", async function () {
        let stakeAmount = 10n ** 28n,
            missedEpochs = 14n,
            slashMaxBips = 10n ** 6n,
            slashPercentInBips = 10n ** 2n;

        await teeManager.setSecretStore(addrs[0]);
        await expect(teeManager.slashStore(addrs[15], missedEpochs, addrs[2]))
            .to.be.not.reverted;

        const remainingStakeAmount = stakeAmount * ((slashMaxBips - slashPercentInBips) ** missedEpochs) / 
            (slashMaxBips ** missedEpochs);
        const slashedAmount = stakeAmount - remainingStakeAmount;

        let teeNode = await teeManager.teeNodes(addrs[15]);
        expect(teeNode.stakeAmount).to.be.eq(remainingStakeAmount);
        expect(await teeManager.getTeeNodesStake([addrs[15]])).to.deep.eq([remainingStakeAmount]);
        expect(await token.balanceOf(teeManager.target)).to.be.eq(remainingStakeAmount);
        expect(await token.balanceOf(addrs[2])).to.be.eq(slashedAmount);

        // case when missedEpochs = 0, nothing should be slashed
        missedEpochs = 0n;
        await expect(teeManager.slashStore(addrs[15], missedEpochs, addrs[2]))
            .to.be.not.reverted;
        expect(teeNode.stakeAmount).to.be.eq((await teeManager.teeNodes(addrs[15])).stakeAmount);
        expect(await teeManager.getTeeNodesStake([addrs[15]])).to.deep.eq([teeNode.stakeAmount]);
    });

    it("cannot slash store without valid secret store", async function () {
        await expect(teeManager.connect(signers[1]).slashStore(addrs[15], 1, addrs[2]))
            .to.be.revertedWithCustomError(teeManager, "TeeManagerInvalidSecretStoreManager");
    });

    it("can slash executor", async function () {
        await teeManager.setExecutors(addrs[0]);
        await expect(teeManager.slashExecutor(addrs[15], addrs[2]))
            .to.not.be.reverted;

        let stakeAmount = 10n ** 28n;
        let slashedAmount = stakeAmount * (10n ** 2n) / (10n ** 6n);

        let teeNode = await teeManager.teeNodes(addrs[15]);
        expect(teeNode.stakeAmount).to.be.eq(stakeAmount - slashedAmount);
        expect(await teeManager.getTeeNodesStake([addrs[15]])).to.deep.eq([stakeAmount - slashedAmount]);
        expect(await token.balanceOf(teeManager.target)).to.be.eq(stakeAmount - slashedAmount);
        expect(await token.balanceOf(addrs[2])).to.be.eq(slashedAmount);
    });

    it("cannot slash executor without valid executors", async function () {
        await expect(teeManager.connect(signers[1]).slashExecutor(addrs[15], addrs[2]))
            .to.be.revertedWithCustomError(teeManager, "TeeManagerInvalidExecutors");
    });
});

describe("TeeManager - Update tree state functions", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let teeManager: TeeManager;
    let executors: ExecutorsMock;
    let secretStore: SecretStoreMock;

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
        const stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
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
                    stakingToken.target,
                    10 ** 10,
                    10 ** 2,
                    10 ** 6
                ]
            },
        ) as unknown as TeeManager;

        const Executors = await ethers.getContractFactory("ExecutorsMock");
        executors = await Executors.deploy(teeManager.target) as unknown as ExecutorsMock;

        const SecretStore = await ethers.getContractFactory("SecretStoreMock");
        secretStore = await SecretStore.deploy(teeManager.target) as unknown as SecretStoreMock;

        await teeManager.setExecutors(executors.target);
        await teeManager.setSecretStore(secretStore.target);

        await stakingToken.transfer(addrs[1], parseUnits("10"));
        // approval for registration stake amount
        await stakingToken.connect(signers[1]).approve(teeManager.target, parseUnits("10"));

        // REGISTER NODE
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            storageCapacity = 1e9,
            env = 1,
            stakeAmount = 0;
        let signedDigest = await registerTeeNodeSignature(
            addrs[1], jobCapacity, storageCapacity, env, signTimestamp, wallets[15]
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
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it('can update tree state by upserting node', async function () {
        let env = 1,
            stakeAmount = parseUnits("10");
        await teeManager.connect(signers[1]).addTeeNodeStake(addrs[15], stakeAmount);

        // calling with executors contract
        await expect(executors.updateTreeState(addrs[15]))
            .to.emit(executors, "ExecutorsMockNodeUpserted")
            .withArgs(env, addrs[15], stakeAmount)
            .to.emit(secretStore, "SecretStoreMockNodeUpserted")
            .withArgs(env, addrs[15], stakeAmount);

        // calling with secret store contract
        await expect(secretStore.updateTreeState(addrs[15]))
            .to.emit(executors, "ExecutorsMockNodeUpserted")
            .withArgs(env, addrs[15], stakeAmount)
            .to.emit(secretStore, "SecretStoreMockNodeUpserted")
            .withArgs(env, addrs[15], stakeAmount);

    });

    it('can update tree state by deleting node', async function () {
        let env = 1;
        // calling with executors contract
        await expect(executors.updateTreeState(addrs[15]))
            .to.emit(executors, "ExecutorsMockNodeDeleted")
            .withArgs(env, addrs[15])
            .to.emit(secretStore, "SecretStoreMockNodeDeleted")
            .withArgs(env, addrs[15]);

        // calling with secret store contract
        await expect(secretStore.updateTreeState(addrs[15]))
            .to.emit(executors, "ExecutorsMockNodeDeleted")
            .withArgs(env, addrs[15])
            .to.emit(secretStore, "SecretStoreMockNodeDeleted")
            .withArgs(env, addrs[15]);
    });

    it('cannot update tree state without Executors or SecretStore contract', async function () {
        await expect(teeManager.updateTreeState(addrs[15]))
            .to.be.revertedWithCustomError(teeManager, "TeeManagerInvalidCaller");
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

function walletForIndex(idx: number): Wallet {
    let wallet = ethers.HDNodeWallet.fromPhrase(
        "test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString()
    );

    return new Wallet(wallet.privateKey);
}
