import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, Wallet, ZeroAddress, ZeroHash, keccak256, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationAutherUpgradeable, AttestationVerifier, Executors, Jobs, Pond } from "../../typechain-types";
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

        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        const executors = await Executors.deploy(
            attestationVerifier.target,
            600,
            token,
            10 ** 10,
            10 ** 2,
            10 ** 6
        );

        expect(await executors.ATTESTATION_VERIFIER()).to.equal(attestationVerifier.target);
        expect(await executors.ATTESTATION_MAX_AGE()).to.equal(600);
        expect(await executors.MIN_STAKE_AMOUNT()).to.equal(10 ** 10);
        expect(await executors.SLASH_PERCENT_IN_BIPS()).to.equal(10 ** 2);
        expect(await executors.SLASH_MAX_BIPS()).to.equal(10 ** 6);

        await expect(
            executors.initialize(addrs[0], []),
        ).to.be.revertedWithCustomError(executors, "InvalidInitialization");

        await expect(
            executors.initialize(addrs[0], [image1, image2]),
        ).to.be.revertedWithCustomError(executors, "InvalidInitialization");
    });

    it("deploys as proxy and initializes", async function () {
        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        const executors = await upgrades.deployProxy(
            Executors,
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
        ) as unknown as Executors;

        expect(await executors.ATTESTATION_VERIFIER()).to.equal(attestationVerifier.target);
        expect(await executors.ATTESTATION_MAX_AGE()).to.equal(600);
        expect(await executors.MIN_STAKE_AMOUNT()).to.equal(10 ** 10);
        expect(await executors.SLASH_PERCENT_IN_BIPS()).to.equal(10 ** 2);
        expect(await executors.SLASH_MAX_BIPS()).to.equal(10 ** 6);

        expect(await executors.hasRole(await executors.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        {
            const { PCR0, PCR1, PCR2 } = await executors.getWhitelistedImage(getImageId(image1));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
        }
    });

    it("cannot initialize with zero address as admin", async function () {
        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        await expect(
            upgrades.deployProxy(
                Executors,
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
        ).to.be.revertedWithCustomError(Executors, "ExecutorsZeroAddressAdmin");
    });

    it("cannot initialize with zero address as staking token", async function () {
        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        await expect(
            upgrades.deployProxy(
                Executors,
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
        ).to.be.revertedWithCustomError(Executors, "ExecutorsZeroAddressToken");
    });

    it("cannot initialize with zero minimum stakes", async function () {
        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        await expect(
            upgrades.deployProxy(
                Executors,
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
        ).to.be.revertedWithCustomError(Executors, "ExecutorsZeroMinStakeAmount");
    });

    it("upgrades", async function () {
        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        const executors = await upgrades.deployProxy(
            Executors,
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
            executors.target,
            Executors,
            {
                kind: "uups",
                constructorArgs: [
                    attestationVerifier2.target,
                    100,
                    token2,
                    10,
                    10,
                    1000,
                ]
            }
        );

        expect(await executors.ATTESTATION_VERIFIER()).to.equal(attestationVerifier2.target);
        expect(await executors.ATTESTATION_MAX_AGE()).to.equal(100);
        expect(await executors.MIN_STAKE_AMOUNT()).to.equal(10);
        expect(await executors.SLASH_PERCENT_IN_BIPS()).to.equal(10);
        expect(await executors.SLASH_MAX_BIPS()).to.equal(1000);

        expect(await executors.hasRole(await executors.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        {
            const { PCR0, PCR1, PCR2 } = await executors.getWhitelistedImage(getImageId(image1));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
        }
        {
            const { PCR0, PCR1, PCR2 } = await executors.getWhitelistedImage(getImageId(image2));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image2);
        }
        {
            const { PCR0, PCR1, PCR2 } = await executors.getWhitelistedImage(getImageId(image3));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
        }
    });

    it("does not upgrade without admin", async function () {
        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        const executors = await upgrades.deployProxy(
            Executors,
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
            upgrades.upgradeProxy(executors.target, Executors.connect(signers[1]), {
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
        ).to.be.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });
});

testERC165(
    "Executors - ERC165",
    async function (_signers: Signer[], addrs: string[]) {
        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        const executors = await upgrades.deployProxy(
            Executors,
            [addrs[0], [image1]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    addrs[1],
                    600,
                    addrs[2],
                    10 ** 10,
                    10 ** 2,
                    10 ** 6
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
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let executors: Executors;

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

        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
            [addrs[0], [image2, image3, image4, image5, image6]],
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
        ) as unknown as Executors;

        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can initialize tree", async function () {
        let env = 1;
        await expect(executors.initTree(env)).to.be.fulfilled;
        expect(await executors.isTreeInitialized(env)).to.be.true;
        expect(await executors.nodesInTree(env)).that.eq(0);
    });

    it("cannot init tree with already existing execution env", async function () {
        let env = 1;
        await executors.initTree(env);

        await expect(executors.initTree(env)).to.be
            .revertedWithCustomError(executors, "TreeInvalidInitState");
    });

    it("cannot init tree without JOBS_ROLE account", async function () {
        let env = 1;
        await expect(executors.connect(signers[1]).initTree(env)).to.be
            .revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });

    it("can remove tree", async function () {
        let env = 1;
        await executors.initTree(env);

        await expect(executors.removeTree(env)).to.be.fulfilled;
        expect(await executors.isTreeInitialized(env)).to.be.false;
    });

    it("cannot remove tree whose execution env hasn't been initialized", async function () {
        let env = 1;
        await expect(executors.removeTree(env)).to.be
            .revertedWithCustomError(executors, "TreeInvalidDeleteState");
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

        await token.transfer(addrs[1], 100000);
        await token.connect(signers[1]).approve(executors.target, 10000);

        let jobCapacity = 20,
            stakeAmount = 10,
            executorImages = [image2, image3],
            timestamp = await time.latest() * 1000;
        for (let index = 0; index < 2; index++) {
            let signTimestamp = await time.latest() - 540;
            // Executor index using wallet 10 + index as enclave address
            let [attestationSign, attestation] = await createAttestation(pubkeys[10 + index], executorImages[index],
                wallets[14], timestamp - 540000);
            let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[10 + index]);
            await executors.connect(signers[1]).registerExecutor(
                attestationSign,
                attestation,
                jobCapacity,
                signTimestamp,
                signedDigest,
                stakeAmount,
                env
            );
        }

        env = 2;
        await executors.initTree(env);

        expect(await executors.isTreeInitialized(env)).to.be.true;
        expect(await executors.nodesInTree(env)).that.eq(0);

        executorImages = [image4, image5, image6];
        for (let index = 0; index < 3; index++) {
            let signTimestamp = await time.latest() - 540;
            // Executor index using wallet 12 + index as enclave address
            let [attestationSign, attestation] = await createAttestation(pubkeys[12 + index], executorImages[index],
                wallets[14], timestamp - 540000);
            let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[12 + index]);
            await executors.connect(signers[1]).registerExecutor(
                attestationSign,
                attestation,
                jobCapacity,
                signTimestamp,
                signedDigest,
                stakeAmount,
                env
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

describe("Executors - Verify", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let token: string;
    let executors: Executors;

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

        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
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
        ) as unknown as Executors;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can whitelist enclave image with admin account", async function () {
        await expect(executors.connect(signers[0]).whitelistEnclaveImage(image1.PCR0, image1.PCR1, image1.PCR2))
            .to.emit(executors, "EnclaveImageWhitelisted").withArgs(getImageId(image1), image1.PCR0, image1.PCR1, image1.PCR2);

        const { PCR0, PCR1, PCR2 } = await executors.getWhitelistedImage(getImageId(image1));
        expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
    });

    it("cannot whitelist enclave image without admin account", async function () {
        await expect(executors.connect(signers[1]).whitelistEnclaveImage(image1.PCR0, image1.PCR1, image1.PCR2))
            .to.be.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });

    it("can revoke enclave image with admin account", async function () {
        await expect(executors.connect(signers[0]).revokeEnclaveImage(getImageId(image2)))
            .to.emit(executors, "EnclaveImageRevoked").withArgs(getImageId(image2));

        const { PCR0 } = await executors.getWhitelistedImage(getImageId(image2));
        expect(PCR0).to.equal("0x");
    });

    it("cannot revoke enclave image without admin account", async function () {
        await expect(executors.connect(signers[1]).revokeEnclaveImage(getImageId(image2)))
            .to.be.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });
});

describe("Executors - Register executor", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let executors: Executors;

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

        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
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
        ) as unknown as Executors;

        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        let env = 1;
        await executors.initTree(env);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can register executor", async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            env = 1;
        let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[15]);

        await expect(executors.connect(signers[1]).registerExecutor(
            attestationSign,
            attestation,
            jobCapacity,
            signTimestamp,
            signedDigest,
            0,
            env
        )).to.emit(executors, "EnclaveKeyVerified").withArgs(addrs[15], getImageId(image2), pubkeys[15]);
        expect(await executors.getVerifiedKey(addrs[15])).to.equal(getImageId(image2));
        expect(await executors.getOwner(addrs[15])).to.eq(addrs[1]);
        expect(await executors.allowOnlyVerified(addrs[15])).to.be.not.reverted;
        await expect(executors.allowOnlyVerified(addrs[16]))
            .to.be.revertedWithCustomError(executors, "AttestationAutherKeyNotVerified");
    });

    it("cannot register executor with unsupported execution env", async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 700;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540
        );

        let jobCapacity = 20,
            env = 2;
        let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp,
            wallets[15]);

        await expect(executors.connect(signers[1]).registerExecutor(
            attestationSign,
            attestation,
            jobCapacity,
            signTimestamp,
            signedDigest,
            0,
            env
        )).to.revertedWithCustomError(executors, "ExecutorsUnsupportedEnv");
    });

    it("cannot register executor with old signature timestamp", async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 700;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            env = 1;
        let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp,
            wallets[15]);

        await expect(executors.connect(signers[1]).registerExecutor(
            attestationSign,
            attestation,
            jobCapacity,
            signTimestamp,
            signedDigest,
            0,
            env
        )).to.revertedWithCustomError(executors, "ExecutorsSignatureTooOld");
    });

    it("cannot register executor with different attestation pubkey and digest signing key", async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            env = 1;
        let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[16]);

        await expect(executors.connect(signers[1]).registerExecutor(
            attestationSign,
            attestation,
            jobCapacity,
            signTimestamp,
            signedDigest,
            0,
            env
        )).to.revertedWithCustomError(executors, "ExecutorsInvalidSigner");
    });

    it("cannot register executor with same enclave key twice", async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            env = 1;
        let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[15]);
        await executors.connect(signers[1]).registerExecutor(
            attestationSign,
            attestation,
            jobCapacity,
            signTimestamp,
            signedDigest,
            0,
            env
        )
        await expect(executors.connect(signers[1]).registerExecutor(
            attestationSign,
            attestation,
            jobCapacity,
            signTimestamp,
            signedDigest,
            0,
            env
        )).to.revertedWithCustomError(executors, "ExecutorsExecutorAlreadyExists");
    });

    // drain then deregister with active jobs 0
    it('can deregister executor without active jobs', async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            env = 1;
        let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[15]);


        await executors.connect(signers[1]).registerExecutor(
            attestationSign,
            attestation,
            jobCapacity,
            signTimestamp,
            signedDigest,
            0,
            env
        )

        await executors.connect(signers[1]).drainExecutor(addrs[15]);
        await expect(executors.connect(signers[1]).deregisterExecutor(addrs[15]))
            .to.emit(executors, "ExecutorDeregistered").withArgs(addrs[15]);
        expect(await executors.getVerifiedKey(addrs[15])).to.equal(ZeroHash);
        expect((await executors.executors(addrs[15])).owner).to.be.eq(ZeroAddress);
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
            env = 1;
        let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[15]);


        await executors.connect(signers[1]).registerExecutor(
            attestationSign,
            attestation,
            jobCapacity,
            signTimestamp,
            signedDigest,
            0,
            env
        )

        await expect(executors.connect(signers[1]).deregisterExecutor(addrs[15]))
            .to.revertedWithCustomError(executors, "ExecutorsNotDraining");
    });

    // drain then deregister failed with active jobs != 0
    it('cannot deregister executor with active jobs', async function () {
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        await token.transfer(addrs[1], 10n ** 19n);
        await token.connect(signers[1]).approve(executors.target, 10n ** 19n);

        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            env = 1;
        let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[15]);

        // register a enclave
        await executors.connect(signers[1]).registerExecutor(
            attestationSign,
            attestation,
            jobCapacity,
            signTimestamp,
            signedDigest,
            10n ** 19n,
            env
        )

        // select nodes
        await executors.connect(signers[0]).selectExecutors(env, 1);
        // drain
        await executors.connect(signers[1]).drainExecutor(addrs[15]);
        // deregister
        await expect(executors.connect(signers[1]).deregisterExecutor(addrs[15]))
            .to.revertedWithCustomError(executors, "ExecutorsHasPendingJobs");
    });

    it('cannot deregister executor without the owner account', async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            env = 1;
        let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[15]);

        // register a enclave
        await executors.connect(signers[1]).registerExecutor(
            attestationSign,
            attestation,
            jobCapacity,
            signTimestamp,
            signedDigest,
            0,
            env
        )
        // deregister with signer 0
        await expect(executors.deregisterExecutor(addrs[15]))
            .to.revertedWithCustomError(executors, "ExecutorsInvalidOwner");
    });

    it('cannot drain executor twice', async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            env = 1;
        let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[15]);

        await executors.connect(signers[1]).registerExecutor(
            attestationSign,
            attestation,
            jobCapacity,
            signTimestamp,
            signedDigest,
            0,
            env
        )

        await executors.connect(signers[1]).drainExecutor(addrs[15]);
        await expect(executors.connect(signers[1]).drainExecutor(addrs[15]))
            .to.revertedWithCustomError(executors, "ExecutorsAlreadyDraining");
    });

});

describe("Executors - Staking", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let executors: Executors;

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

        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
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
        ) as unknown as Executors;

        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        let env = 1;
        await executors.initTree(env);

        await token.transfer(addrs[1], 100000);
        await token.connect(signers[1]).approve(executors.target, 10000);
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let jobCapacity = 20,
            stakeAmount = 10;
        let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[15]);

        await executors.connect(signers[1]).registerExecutor(
            attestationSign,
            attestation,
            jobCapacity,
            signTimestamp,
            signedDigest,
            stakeAmount,
            env
        );
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can stake", async function () {
        let amount = 20;
        await expect(executors.connect(signers[1]).addExecutorStake(addrs[15], amount))
            .to.emit(executors, "ExecutorStakeAdded");

        let executor = await executors.executors(addrs[15]);
        expect(executor.stakeAmount).to.be.eq(30);
        expect(await token.balanceOf(executors.target)).to.be.eq(30);
        expect(await token.balanceOf(addrs[1])).to.be.eq(99970);
    });

    it("can stake if draining", async function () {
        await executors.connect(signers[1]).drainExecutor(addrs[15]);

        let amount = 20;
        await expect(executors.connect(signers[1]).addExecutorStake(addrs[15], amount))
            .to.emit(executors, "ExecutorStakeAdded");

        let executor = await executors.executors(addrs[15]);
        expect(executor.stakeAmount).to.be.eq(30);
        expect(await token.balanceOf(executors.target)).to.be.eq(30);
        expect(await token.balanceOf(addrs[1])).to.be.eq(99970);
    });

    it("cannot stake without executor owner", async function () {
        let amount = 20;
        await expect(executors.addExecutorStake(addrs[15], amount))
            .to.be.revertedWithCustomError(executors, "ExecutorsInvalidOwner");
    });

    it("cannot drain without executor owner", async function () {
        let amount = 20;
        await expect(executors.drainExecutor(addrs[15]))
            .to.be.revertedWithCustomError(executors, "ExecutorsInvalidOwner");
    });

    it("can unstake with draining if no active jobs", async function () {
        let amount = 10;
        await executors.connect(signers[1]).drainExecutor(addrs[15]);
        await expect(executors.connect(signers[1]).removeExecutorStake(addrs[15], amount))
            .to.emit(executors, "ExecutorStakeRemoved");

        let executor = await executors.executors(addrs[15]);
        expect(executor.stakeAmount).to.be.eq(0);
        expect(await token.balanceOf(executors.target)).to.be.eq(0);
        expect(await token.balanceOf(addrs[1])).to.be.eq(100000);
    });

    it("Failed to unstake without draining", async function () {
        let amount = 0;
        await expect(executors.connect(signers[1]).removeExecutorStake(addrs[15], amount))
            .to.revertedWithCustomError(executors, "ExecutorsNotDraining");
    });

    it("cannot unstake without executor operator", async function () {
        let amount = 10;
        await expect(executors.removeExecutorStake(addrs[15], amount))
            .to.be.revertedWithCustomError(executors, "ExecutorsInvalidOwner");
    });

    it('cannot unstake with active jobs after draining started', async function () {
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        await token.transfer(addrs[1], 10n ** 19n);
        await token.connect(signers[1]).approve(executors.target, 10n ** 19n);

        // add stake to get node added to tree
        await executors.connect(signers[1]).addExecutorStake(addrs[15], 10n ** 19n);
        let env = 1;
        // select nodes
        await executors.connect(signers[0]).selectExecutors(env, 1);
        // drain
        await executors.connect(signers[1]).drainExecutor(addrs[15]);

        let amount = 5;
        await expect(executors.connect(signers[1]).removeExecutorStake(addrs[15], amount))
            .to.be.revertedWithCustomError(executors, "ExecutorsHasPendingJobs");

    });
});

describe("Executors - Revive", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let executors: Executors;

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

        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
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
        ) as unknown as Executors;

        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        let env = 1;
        await executors.initTree(env);

        await token.transfer(addrs[1], 10n ** 19n);
        await token.connect(signers[1]).approve(executors.target, 10n ** 19n);
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );
        let jobCapacity = 1,
            stakeAmount = 10n ** 19n;
        let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[15]);
        await executors.connect(signers[1]).registerExecutor(
            attestationSign,
            attestation,
            jobCapacity,
            signTimestamp,
            signedDigest,
            stakeAmount,
            env
        );
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can revive executor after draining", async function () {
        // Drain executor
        await executors.connect(signers[1]).drainExecutor(addrs[15]);

        let env = 1;
        // Try to select one executor
        await executors.selectExecutors(env, 1);

        // No executor should be selected
        let executor = await executors.executors(addrs[15]);
        expect(executor.activeJobs).to.be.eq(0);
        expect(executor.draining).to.be.true;

        // Case 1: Executor should get selected for job after revival because it has capacity available and
        // minimum stake
        await expect(executors.connect(signers[1]).reviveExecutor(addrs[15]))
            .to.emit(executors, "ExecutorRevived").withArgs(addrs[15]);

        // check executor can be selected again
        await executors.selectExecutors(env, 1);
        executor = await executors.executors(addrs[15]);
        expect(executor.draining).to.be.false;
        expect(executor.activeJobs).to.be.eq(1);

        // drain executor again
        await executors.connect(signers[1]).drainExecutor(addrs[15]);

        // Case 2: Executor should not get selected for job after revival because it has no capacity available
        // Revive executor
        await executors.connect(signers[1]).reviveExecutor(addrs[15]);

        // select one executor
        await executors.selectExecutors(env, 1);

        // No executor should be selected
        executor = await executors.executors(addrs[15]);
        expect(executor.activeJobs).to.be.eq(1);

        // release executor
        await executors.releaseExecutor(addrs[15]);

        // check active jobs 0
        executor = await executors.executors(addrs[15]);
        expect(executor.activeJobs).to.be.eq(0);

        // Drain executor
        await executors.connect(signers[1]).drainExecutor(addrs[15]);

        // Remove stake
        await executors.connect(signers[1]).removeExecutorStake(addrs[15], 10n ** 19n);

        // Case 3: Executor should not get selected for job after revival because it has no minimum stake
        // Revive executor
        await executors.connect(signers[1]).reviveExecutor(addrs[15]);

        // executor should not be added to the tree because it dosent have minimum stake
        // select one executor
        await executors.selectExecutors(env, 1);

        // No executor should be selected
        executor = await executors.executors(addrs[15]);
        expect(executor.activeJobs).to.be.eq(0);
    });

    it("cannot revive executor without draining", async function () {
        await expect(executors.connect(signers[1]).reviveExecutor(addrs[15]))
            .to.revertedWithCustomError(executors, "ExecutorsAlreadyRevived");
    });

    it("cannot revive executor without executor owner", async function () {
        await expect(executors.reviveExecutor(addrs[15]))
            .to.revertedWithCustomError(executors, "ExecutorsInvalidOwner");
    });
});

describe("Executors - Select/Release/Slash", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let executors: Executors;

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

        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
            [addrs[0], [image2, image3]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    token.target,
                    10,
                    10 ** 6,
                    10 ** 6
                ]
            },
        ) as unknown as Executors;

        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), addrs[0]);

        let env = 1;
        await executors.initTree(env);

        await token.transfer(addrs[1], 10n ** 19n);
        await token.connect(signers[1]).approve(executors.target, 10n ** 19n);
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );
        let jobCapacity = 1,
            stakeAmount = 10n ** 19n;
        let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[15]);
        await executors.connect(signers[1]).registerExecutor(
            attestationSign,
            attestation,
            jobCapacity,
            signTimestamp,
            signedDigest,
            stakeAmount,
            env
        );
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("select executor after releasing", async function () {
        let env = 1;
        // Select one executor
        await executors.selectExecutors(env, 1);

        // Check active jobs 1
        let executor = await executors.executors(addrs[15]);
        expect(executor.activeJobs).to.be.eq(1);

        // Release executor
        await executors.releaseExecutor(addrs[15]);

        // Check active jobs 0
        executor = await executors.executors(addrs[15]);
        expect(executor.activeJobs).to.be.eq(0);

        // Select one executor
        await executors.selectExecutors(env, 1);

        // Check active jobs 1
        executor = await executors.executors(addrs[15]);
        expect(executor.activeJobs).to.be.eq(1);
    });

    it("releasing while draining executor", async function () {
        let env = 1;
        // Select one executor
        await executors.selectExecutors(env, 1);

        // Check active jobs 1
        let executor = await executors.executors(addrs[15]);
        expect(executor.activeJobs).to.be.eq(1);

        // Drain executor
        await executors.connect(signers[1]).drainExecutor(addrs[15]);

        // Release executor
        await executors.releaseExecutor(addrs[15]);

        // Check active jobs 0
        executor = await executors.executors(addrs[15]);
        expect(executor.activeJobs).to.be.eq(0);

        // Select one executor
        await executors.selectExecutors(env, 1);

        // Check active jobs 0
        executor = await executors.executors(addrs[15]);
        expect(executor.activeJobs).to.be.eq(0);
    });

    it("low stakes while releasing executor", async function () {
        let env = 1;
        // Select one executor
        await executors.selectExecutors(env, 1);

        // Check active jobs 1
        let executor = await executors.executors(addrs[15]);
        expect(executor.activeJobs).to.be.eq(1);

        // Slash Executor (executor will be released within slashExecutor)
        await executors.connect(signers[0]).slashExecutor(addrs[15]);

        // Check active jobs 0
        executor = await executors.executors(addrs[15]);
        expect(executor.activeJobs).to.be.eq(0);

        // Select one executor
        await executors.selectExecutors(env, 1);

        // Check active jobs 0
        executor = await executors.executors(addrs[15]);
        expect(executor.activeJobs).to.be.eq(0);
    });

    it("cannot release executor without JOB ROLE", async function () {
        await expect(executors.connect(signers[1]).releaseExecutor(addrs[15]))
            .to.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });

    it("cannot select executor without JOB ROLE", async function () {
        let env = 1;
        await expect(executors.connect(signers[1]).selectExecutors(env, 1))
            .to.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });

    it("cannot slash executor without JOB ROLE", async function () {
        await expect(executors.connect(signers[1]).slashExecutor(addrs[15]))
            .to.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
    });

    it("cannot select executor with unsupported execution env", async function () {
        let env = 2;
        await expect(executors.selectExecutors(env, 1))
            .to.revertedWithCustomError(executors, "ExecutorsUnsupportedEnv");
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
    let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

    return new Wallet(wallet.privateKey);
}
