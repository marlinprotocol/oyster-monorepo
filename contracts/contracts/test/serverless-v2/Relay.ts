import { setNextBlockBaseFeePerGas, time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, Wallet, ZeroAddress, keccak256, parseUnits, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationAutherUpgradeable, AttestationVerifier, Relay, USDCoin, UserSample } from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { testERC165 } from '../helpers/erc165';

const image1: string = ethers.hexlify(ethers.randomBytes(32));
const image2: string = ethers.hexlify(ethers.randomBytes(32));
const image3: string = ethers.hexlify(ethers.randomBytes(32));

describe("Relay - Init", function () {
    let signers: Signer[];
    let addrs: string[];
    let attestationVerifier: string;
    let token: string;

    let maxAge: number;
    let globalMinTimeout: number;  // in milliseconds
    let globalMaxTimeout: number;  // in milliseconds
    let overallTimeout: number;
    let gatewayFeePerJob: number;
    let fixedGas: number;
    let callbackMeasureGas: number;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));

        attestationVerifier = addrs[1];
        token = addrs[1];
        maxAge = 600;
        globalMinTimeout = 10 * 1000;  // in milliseconds
        globalMaxTimeout = 100 * 1000;  // in milliseconds
        overallTimeout = 100;
        gatewayFeePerJob = 10;
        fixedGas = 150000;
        callbackMeasureGas = 4530;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("deploys with initialization disabled", async function () {
        const Relay = await ethers.getContractFactory("Relay");
        const relay = await Relay.deploy(
            attestationVerifier,
            maxAge,
            token,
            globalMinTimeout,
            globalMaxTimeout,
            overallTimeout,
            gatewayFeePerJob,
            fixedGas,
            callbackMeasureGas
        );

        await expect(
            relay.initialize(addrs[0], [image1]),
        ).to.be.revertedWithCustomError(Relay, "InvalidInitialization");
    });

    it("deploys as proxy and initializes", async function () {
        const Relay = await ethers.getContractFactory("Relay");
        const relay = await upgrades.deployProxy(
            Relay,
            [addrs[0], [image1]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier,
                    maxAge,
                    token,
                    globalMinTimeout,
                    globalMaxTimeout,
                    overallTimeout,
                    gatewayFeePerJob,
                    fixedGas,
                    callbackMeasureGas
                ]
            },
        );

        expect(await relay.hasRole(await relay.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    });

    it("cannot deploy with zero address as token", async function () {
        const Relay = await ethers.getContractFactory("Relay");
        await expect(
            upgrades.deployProxy(
                Relay,
                [addrs[0], [image1]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        attestationVerifier,
                        maxAge,
                        ZeroAddress,
                        globalMinTimeout,
                        globalMaxTimeout,
                        overallTimeout,
                        gatewayFeePerJob,
                        fixedGas,
                        callbackMeasureGas
                    ]
                },
            )
        ).to.be.revertedWithCustomError(Relay, "RelayInvalidToken");
    });

    it("cannot initialize with zero address as admin", async function () {
        const Relay = await ethers.getContractFactory("Relay");
        await expect(
            upgrades.deployProxy(
                Relay,
                [
                    ZeroAddress,
                    [image1]
                ],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        attestationVerifier,
                        maxAge,
                        token,
                        globalMinTimeout,
                        globalMaxTimeout,
                        overallTimeout,
                        gatewayFeePerJob,
                        fixedGas,
                        callbackMeasureGas
                    ]
                },
            )
        ).to.be.revertedWithCustomError(Relay, "RelayZeroAddressAdmin");
    });

    it("cannot deploy with globalMaxTimeout smaller than globalMinTimeout", async function () {
        const Relay = await ethers.getContractFactory("Relay");
        await expect(
            upgrades.deployProxy(
                Relay,
                [addrs[0], [image1]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        attestationVerifier,
                        maxAge,
                        token,
                        globalMaxTimeout,
                        globalMinTimeout,
                        overallTimeout,
                        gatewayFeePerJob,
                        fixedGas,
                        callbackMeasureGas
                    ]
                },
            )
        ).to.be.revertedWithCustomError(Relay, "RelayInvalidGlobalTimeouts");
    });

    it("upgrades", async function () {
        const Relay = await ethers.getContractFactory("Relay");
        const relay = await upgrades.deployProxy(
            Relay,
            [
                addrs[0],
                [image1]
            ],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier,
                    maxAge,
                    token,
                    globalMinTimeout,
                    globalMaxTimeout,
                    overallTimeout,
                    gatewayFeePerJob,
                    fixedGas,
                    callbackMeasureGas
                ]
            },
        );
        await upgrades.upgradeProxy(
            relay.target,
            Relay,
            {
                kind: "uups",
                constructorArgs: [
                    attestationVerifier,
                    maxAge,
                    token,
                    globalMinTimeout,
                    globalMaxTimeout,
                    overallTimeout,
                    gatewayFeePerJob,
                    fixedGas,
                    callbackMeasureGas
                ]
            }
        );

        expect(await relay.hasRole(await relay.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    });

    it("does not upgrade without admin", async function () {
        const Relay = await ethers.getContractFactory("Relay");
        const relay = await upgrades.deployProxy(
            Relay,
            [addrs[0], [image1]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier,
                    maxAge,
                    token,
                    globalMinTimeout,
                    globalMaxTimeout,
                    overallTimeout,
                    gatewayFeePerJob,
                    fixedGas,
                    callbackMeasureGas
                ]
            }
        );

        await expect(
            upgrades.upgradeProxy(
                relay.target, Relay.connect(signers[1]),
                {
                    kind: "uups",
                    constructorArgs: [
                        attestationVerifier,
                        maxAge,
                        token,
                        globalMinTimeout,
                        globalMaxTimeout,
                        overallTimeout,
                        gatewayFeePerJob,
                        fixedGas,
                        callbackMeasureGas
                    ]
                }
            )
        ).to.be.revertedWithCustomError(Relay, "AccessControlUnauthorizedAccount");
    });
});

testERC165(
    "Relay - ERC165",
    async function (_signers: Signer[], addrs: string[]) {
        let attestationVerifier = addrs[1],
            token = addrs[1],
            maxAge = 600,
            globalMinTimeout = 10 * 1000,  // in milliseconds
            globalMaxTimeout = 100 * 1000,  // in milliseconds
            overallTimeout = 100,
            gatewayFeePerJob = 10;
        let fixedGas = 150000;
        let callbackMeasureGas = 4530;
        const Relay = await ethers.getContractFactory("Relay");
        const relay = await upgrades.deployProxy(
            Relay,
            [addrs[0], [image1]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier,
                    maxAge,
                    token,
                    globalMinTimeout,
                    globalMaxTimeout,
                    overallTimeout,
                    gatewayFeePerJob,
                    fixedGas,
                    callbackMeasureGas
                ]
            }
        );
        return relay;
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

describe("Relay - Whitelist/Revoke enclave", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let relay: Relay;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        let attestationVerifier = addrs[1],
            token = addrs[1];

        let admin = addrs[0],
            images = [image2],
            maxAge = 600,
            globalMinTimeout = 10 * 1000,  // in milliseconds
            globalMaxTimeout = 100 * 1000,  // in milliseconds
            overallTimeout = 100,
            gatewayFeePerJob = 10,
            fixedGas = 150000,
            callbackMeasureGas = 4530;
        const Relay = await ethers.getContractFactory("Relay");
        relay = await upgrades.deployProxy(
            Relay,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier,
                    maxAge,
                    token,
                    globalMinTimeout,
                    globalMaxTimeout,
                    overallTimeout,
                    gatewayFeePerJob,
                    fixedGas,
                    callbackMeasureGas
                ]
            },
        ) as unknown as Relay;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can whitelist enclave image with admin account", async function () {
        await expect(relay.connect(signers[0]).whitelistEnclaveImage(image1))
            .to.emit(relay, "EnclaveImageWhitelisted").withArgs(image1);

        expect(await relay.isImageWhitelisted(image1)).to.be.true;
    });

    it("cannot whitelist enclave image without admin account", async function () {
        await expect(relay.connect(signers[1]).whitelistEnclaveImage(image1))
            .to.be.revertedWithCustomError(relay, "AccessControlUnauthorizedAccount");
    });

    it("can revoke enclave image with admin account", async function () {
        await expect(relay.connect(signers[0]).revokeEnclaveImage(image2))
            .to.emit(relay, "EnclaveImageRevoked").withArgs(image2);

        expect(await relay.isImageWhitelisted(image2)).to.be.false;
    });

    it("cannot revoke enclave image without admin account", async function () {
        await expect(relay.connect(signers[1]).revokeEnclaveImage(image2))
            .to.be.revertedWithCustomError(relay, "AccessControlUnauthorizedAccount");
    });
});

describe("Relay - Global Execution Env", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: USDCoin;
    let attestationVerifier: AttestationVerifier;
    let relay: Relay;

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
        token = await upgrades.deployProxy(
            USDCoin,
            [addrs[0]],
            {
                kind: "uups",
            }
        ) as unknown as USDCoin;

        let admin = addrs[0],
            images = [image1, image2],
            maxAge = 600,
            globalMinTimeout = 10 * 1000,  // in milliseconds
            globalMaxTimeout = 100 * 1000,  // in milliseconds
            overallTimeout = 100,
            gatewayFeePerJob = 10,
            fixedGas = 150000,
            callbackMeasureGas = 4530;
        const Relay = await ethers.getContractFactory("Relay");
        relay = await upgrades.deployProxy(
            Relay,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    maxAge,
                    token.target,
                    globalMinTimeout,
                    globalMaxTimeout,
                    overallTimeout,
                    gatewayFeePerJob,
                    fixedGas,
                    callbackMeasureGas
                ]
            },
        ) as unknown as Relay;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it('can add global execution env', async function () {
        let env = 1,
            executionFeePerMs = 100;
        await expect(relay.addGlobalEnv(env, executionFeePerMs)).to.emit(relay, "GlobalEnvAdded");

        let executionEnv = await relay.executionEnv(env);
        expect(executionEnv.executionFeePerMs).to.eq(executionFeePerMs);
        expect(executionEnv.status).to.be.true;
        expect(await relay.getJobExecutionFeePerMs(env)).to.eq(executionFeePerMs);
        expect(await relay.isEnvSupported(env)).to.be.true;
    });

    it('cannot add global execution env without admin account', async function () {
        let env = 1,
            executionFeePerMs = 100;
        await expect(relay.connect(signers[1]).addGlobalEnv(env, executionFeePerMs))
            .to.be.revertedWithCustomError(relay, "AccessControlUnauthorizedAccount");
    });

    it('cannot add already supported global execution env again', async function () {
        let env = 1,
            executionFeePerMs = 100;
        await relay.addGlobalEnv(env, executionFeePerMs);

        await expect(relay.addGlobalEnv(env, executionFeePerMs))
            .to.be.revertedWithCustomError(relay, "RelayGlobalEnvAlreadySupported");
    });

    it('can remove global execution env', async function () {
        let env = 1,
            executionFeePerMs = 100;
        await relay.addGlobalEnv(env, executionFeePerMs);
        await expect(relay.removeGlobalEnv(env)).to.emit(relay, "GlobalEnvRemoved");

        let executionEnv = await relay.executionEnv(env);
        expect(executionEnv.executionFeePerMs).to.eq(0);
        expect(executionEnv.status).to.be.false;
    });

    it('cannot remove global execution env without admin account', async function () {
        let env = 1;
        await expect(relay.connect(signers[1]).removeGlobalEnv(env))
            .to.be.revertedWithCustomError(relay, "AccessControlUnauthorizedAccount");
    });

    it('cannot remove unsupported global execution env', async function () {
        let env = 1;
        await expect(relay.removeGlobalEnv(env))
            .to.be.revertedWithCustomError(relay, "RelayGlobalEnvAlreadyUnsupported");
    });
});

describe("Relay - Register gateway", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: USDCoin;
    let attestationVerifier: AttestationVerifier;
    let relay: Relay;

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
        token = await upgrades.deployProxy(
            USDCoin,
            [addrs[0]],
            {
                kind: "uups",
            }
        ) as unknown as USDCoin;

        let admin = addrs[0],
            images = [image1, image2],
            maxAge = 600,
            globalMinTimeout = 10 * 1000,  // in milliseconds
            globalMaxTimeout = 100 * 1000,  // in milliseconds
            overallTimeout = 100,
            gatewayFeePerJob = 10,
            fixedGas = 150000,
            callbackMeasureGas = 4530;
        const Relay = await ethers.getContractFactory("Relay");
        relay = await upgrades.deployProxy(
            Relay,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    maxAge,
                    token.target,
                    globalMinTimeout,
                    globalMaxTimeout,
                    overallTimeout,
                    gatewayFeePerJob,
                    fixedGas,
                    callbackMeasureGas
                ]
            },
        ) as unknown as Relay;

    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can register gateway", async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], signTimestamp, wallets[15]);

        await expect(relay.connect(signers[1]).registerGateway(signature, attestation, signedDigest, signTimestamp))
            .to.emit(relay, "GatewayRegistered").withArgs(addrs[1], addrs[15]);
        expect(await relay.getVerifiedKey(addrs[15])).to.equal(image2);
        expect(await relay.allowOnlyVerified(addrs[15])).to.be.not.reverted;
        await expect(relay.allowOnlyVerified(addrs[16]))
            .to.be.revertedWithCustomError(relay, "AttestationAutherKeyNotVerified");
    });

    it("cannot register gateway with expired signature", async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let signTimestamp = await time.latest() - 700;
        let signedDigest = await createGatewaySignature(addrs[1], signTimestamp, wallets[15]);

        await expect(relay.connect(signers[1]).registerGateway(signature, attestation, signedDigest, signTimestamp))
            .to.revertedWithCustomError(relay, "RelaySignatureTooOld");
    });

    it("cannot register gateway with invalid signer", async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], signTimestamp, wallets[16]);

        await expect(relay.connect(signers[1]).registerGateway(signature, attestation, signedDigest, signTimestamp))
            .to.revertedWithCustomError(relay, "RelayInvalidSigner");
    });

    it("cannot register gateway with same enclaveAddress twice", async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], signTimestamp, wallets[15]);

        await expect(relay.connect(signers[1]).registerGateway(signature, attestation, signedDigest, signTimestamp))
            .to.emit(relay, "GatewayRegistered").withArgs(addrs[1], addrs[15]);

        await expect(relay.connect(signers[1]).registerGateway(signature, attestation, signedDigest, signTimestamp))
            .to.revertedWithCustomError(relay, "RelayGatewayAlreadyExists");
    });

    it('can deregister gateway', async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], signTimestamp, wallets[15]);

        await relay.connect(signers[1]).registerGateway(signature, attestation, signedDigest, signTimestamp);

        await expect(relay.connect(signers[1]).deregisterGateway(addrs[15]))
            .to.emit(relay, "GatewayDeregistered").withArgs(addrs[15]);
    });

    it('cannot deregister gateway without gateway owner', async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], signTimestamp, wallets[15]);

        await relay.connect(signers[1]).registerGateway(signature, attestation, signedDigest, signTimestamp);

        await expect(relay.connect(signers[2]).deregisterGateway(addrs[15]))
            .to.revertedWithCustomError(relay, "RelayInvalidGatewayOwner");
    });

});

describe("Relay - Relay Job", function () {
    let signers: Signer[];
    let addrs: string[];
    let token: USDCoin;
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let relay: Relay;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const USDCoin = await ethers.getContractFactory("USDCoin");
        token = await upgrades.deployProxy(
            USDCoin,
            [addrs[0]],
            {
                kind: "uups",
            }
        ) as unknown as USDCoin;

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        let admin = addrs[0],
            images = [image1, image2],
            maxAge = 600,
            globalMinTimeout = 10 * 1000,  // in milliseconds
            globalMaxTimeout = 100 * 1000,  // in milliseconds
            overallTimeout = 100,
            gatewayFeePerJob = 10,
            fixedGas = 150000,
            callbackMeasureGas = 4530;
        const Relay = await ethers.getContractFactory("Relay");
        relay = await upgrades.deployProxy(
            Relay,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    maxAge,
                    token.target,
                    globalMinTimeout,
                    globalMaxTimeout,
                    overallTimeout,
                    gatewayFeePerJob,
                    fixedGas,
                    callbackMeasureGas
                ]
            },
        ) as unknown as Relay;

        await token.transfer(addrs[2], 1000000);
        await token.connect(signers[2]).approve(relay.target, 1000000);

        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], signTimestamp, wallets[15]);

        await relay.connect(signers[1]).registerGateway(signature, attestation, signedDigest, signTimestamp);

        let env = 1,
            executionFeePerMs = 10;
        await relay.addGlobalEnv(env, executionFeePerMs);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can relay job", async function () {
        let env = 1,
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            userTimeout = 50000,
            maxGasPrice = 100,
            callbackDeposit = parseUnits("1"),
            refundAccount = addrs[1],
            callbackContract = addrs[1],
            callbackGasLimit = 10000;
        await setNextBlockBaseFeePerGas(1);
        let tx = await relay.connect(signers[2])
            .relayJob(
                env, codeHash, codeInputs, userTimeout, maxGasPrice, refundAccount, callbackContract, callbackGasLimit,
                { value: callbackDeposit }
            );
        await expect(tx).to.emit(relay, "JobRelayed");

        let key = await relay.jobCount();
        let job = await relay.jobs(key);

        expect(job.jobOwner).to.eq(addrs[2]);
    });

    it("cannot relay job with unsupported execution env", async function () {
        let env = 2,
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            userTimeout = 50000,
            maxGasPrice = 100,
            callbackDeposit = 100,
            refundAccount = addrs[1],
            callbackContract = addrs[1],
            callbackGasLimit = 10000;
        let tx = relay.connect(signers[2])
            .relayJob(
                env, codeHash, codeInputs, userTimeout, maxGasPrice, refundAccount, callbackContract, callbackGasLimit,
                { value: callbackDeposit }
            );
        await expect(tx).to.revertedWithCustomError(relay, "RelayEnvUnsupported");
    });

    it("cannot relay job with invalid user timeout", async function () {
        let env = 1,
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            userTimeout = 500,
            maxGasPrice = 100,
            callbackDeposit = 100,
            refundAccount = addrs[1],
            callbackContract = addrs[1],
            callbackGasLimit = 10000;
        let tx = relay.connect(signers[2])
            .relayJob(
                env, codeHash, codeInputs, userTimeout, maxGasPrice, refundAccount, callbackContract, callbackGasLimit,
                { value: callbackDeposit }
            );
        await expect(tx).to.revertedWithCustomError(relay, "RelayInvalidUserTimeout");

        userTimeout = 1000 * 1000;	// 1000ms
        tx = relay.connect(signers[2])
            .relayJob(
                env, codeHash, codeInputs, userTimeout, maxGasPrice, refundAccount, callbackContract, callbackGasLimit,
                { value: callbackDeposit }
            );
        await expect(tx).to.revertedWithCustomError(relay, "RelayInvalidUserTimeout");
    });

    it("cannot relay job with insufficient callback deposit", async function () {
        let env = 1,
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            userTimeout = 50000,
            maxGasPrice = 100,
            callbackDeposit = 0,
            refundAccount = addrs[1],
            callbackContract = addrs[1],
            callbackGasLimit = 10000;

        await setNextBlockBaseFeePerGas(1);

        let tx = relay.connect(signers[2])
            .relayJob(
                env, codeHash, codeInputs, userTimeout, maxGasPrice, refundAccount, callbackContract, callbackGasLimit,
                { value: callbackDeposit }
            );
        await expect(tx).to.revertedWithCustomError(relay, "RelayInsufficientCallbackDeposit");
    });

    it("cannot relay job with invalid max gas price", async function () {
        let env = 1,
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            userTimeout = 50000,
            maxGasPrice = 0,
            callbackDeposit = 100,
            refundAccount = addrs[1],
            callbackContract = addrs[1],
            callbackGasLimit = 10000;
        let tx = relay.connect(signers[2])
            .relayJob(
                env, codeHash, codeInputs, userTimeout, maxGasPrice, refundAccount, callbackContract, callbackGasLimit,
                { value: callbackDeposit }
            );
        await expect(tx).to.revertedWithCustomError(relay, "RelayInsufficientMaxGasPrice");
    });
});

describe("Relay - Job Response", function () {
    let signers: Signer[];
    let addrs: string[];
    let token: USDCoin;
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let relay: Relay;
    let callbackDeposit: bigint;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const USDCoin = await ethers.getContractFactory("USDCoin");
        token = await upgrades.deployProxy(
            USDCoin,
            [addrs[0]],
            {
                kind: "uups",
            }
        ) as unknown as USDCoin;

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        let admin = addrs[0],
            images = [image1, image2],
            maxAge = 600,
            globalMinTimeout = 10 * 1000,  // in milliseconds
            globalMaxTimeout = 100 * 1000,  // in milliseconds
            overallTimeout = 100,
            gatewayFeePerJob = 10,
            fixedGas = 150000,
            callbackMeasureGas = 4530;
        const Relay = await ethers.getContractFactory("Relay");
        relay = await upgrades.deployProxy(
            Relay,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    maxAge,
                    token.target,
                    globalMinTimeout,
                    globalMaxTimeout,
                    overallTimeout,
                    gatewayFeePerJob,
                    fixedGas,
                    callbackMeasureGas
                ]
            },
        ) as unknown as Relay;

        await token.transfer(addrs[2], 1000000);
        await token.connect(signers[2]).approve(relay.target, 1000000);

        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], signTimestamp, wallets[15]);

        await relay.connect(signers[1]).registerGateway(signature, attestation, signedDigest, signTimestamp);

        let env = 1,
            executionFeePerMs = 10;
        await relay.addGlobalEnv(env, executionFeePerMs);

        let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            userTimeout = 50000,
            maxGasPrice = 10,
            refundAccount = addrs[1],
            callbackContract = addrs[1],
            callbackGasLimit = 0;
        callbackDeposit = 1545300n;
        await setNextBlockBaseFeePerGas(1);
        await relay.connect(signers[2])
            .relayJob(
                env, codeHash, codeInputs, userTimeout, maxGasPrice, refundAccount, callbackContract, callbackGasLimit,
                { value: callbackDeposit }
            );
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can submit response", async function () {
        let jobId: any = await relay.jobCount(),
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest();

        let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[15]);
        let tx = relay.connect(signers[1]).jobResponse(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);
        await expect(tx).to.emit(relay, "JobResponded");
    });

    it("cannot submit response with expired signature", async function () {
        let jobId: any = await relay.jobCount(),
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest() - 700;

        let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[15]);

        let tx = relay.connect(signers[1]).jobResponse(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);
        await expect(tx).to.revertedWithCustomError(relay, "RelaySignatureTooOld");
    });

    it("cannot submit response twice", async function () {
        let jobId: any = await relay.jobCount(),
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest();

        let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[15]);
        let tx = relay.connect(signers[1]).jobResponse(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);
        await expect(tx).to.emit(relay, "JobResponded");

        let tx2 = relay.connect(signers[1]).jobResponse(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);
        await expect(tx2).to.revertedWithCustomError(relay, "RelayJobNotExists");
    });

    it("cannot submit output from unverified gateway", async function () {
        let jobId: any = await relay.jobCount(),
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest();

        let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[16]);
        let tx = relay.connect(signers[1]).jobResponse(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);
        await expect(tx).to.revertedWithCustomError(relay, "AttestationAutherKeyNotVerified");
    });

    it("cannot submit response after overall timeout is over", async function () {
        await time.increase(1100);
        let jobId: any = await relay.jobCount(),
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest();

        let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[15]);
        let tx = relay.connect(signers[1]).jobResponse(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);
        await expect(tx).to.revertedWithCustomError(relay, "RelayOverallTimeoutOver");
    });

    it("callback cost is greater than the deposit", async function () {
        let jobId: any = await relay.jobCount(),
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest();

        let initBalance1 = await ethers.provider.getBalance(addrs[1]);
        let initBalance2 = await ethers.provider.getBalance(addrs[2]);
        await setNextBlockBaseFeePerGas(100);
        let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[15]);
        let tx = await relay.connect(signers[3]).jobResponse(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);
        expect(await ethers.provider.getBalance(addrs[1])).to.equal(initBalance1 + callbackDeposit);
        expect(await ethers.provider.getBalance(addrs[2])).to.equal(initBalance2);
    });

});

describe("Relay - Job Cancel", function () {
    let signers: Signer[];
    let addrs: string[];
    let token: USDCoin;
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let relay: Relay;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const USDCoin = await ethers.getContractFactory("USDCoin");
        token = await upgrades.deployProxy(
            USDCoin,
            [addrs[0]],
            {
                kind: "uups",
            }
        ) as unknown as USDCoin;

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        let admin = addrs[0],
            images = [image1, image2],
            maxAge = 600,
            globalMinTimeout = 10 * 1000,  // in milliseconds
            globalMaxTimeout = 100 * 1000,  // in milliseconds
            overallTimeout = 100,
            gatewayFeePerJob = 10,
            fixedGas = 150000,
            callbackMeasureGas = 4530;
        const Relay = await ethers.getContractFactory("Relay");
        relay = await upgrades.deployProxy(
            Relay,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    maxAge,
                    token.target,
                    globalMinTimeout,
                    globalMaxTimeout,
                    overallTimeout,
                    gatewayFeePerJob,
                    fixedGas,
                    callbackMeasureGas
                ]
            },
        ) as unknown as Relay;

        await token.transfer(addrs[2], 1000000);
        await token.connect(signers[2]).approve(relay.target, 1000000);

        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], signTimestamp, wallets[15]);

        await relay.connect(signers[1]).registerGateway(signature, attestation, signedDigest, signTimestamp);

        let env = 1,
            executionFeePerMs = 10;
        await relay.addGlobalEnv(env, executionFeePerMs);

        let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            userTimeout = 50000,
            maxGasPrice = 100,
            callbackDeposit = parseUnits("1"),
            refundAccount = addrs[1],
            callbackContract = addrs[1],
            callbackGasLimit = 10000;

        await setNextBlockBaseFeePerGas(1);
        await relay.connect(signers[2])
            .relayJob(
                env, codeHash, codeInputs, userTimeout, maxGasPrice, refundAccount, callbackContract, callbackGasLimit,
                { value: callbackDeposit }
            );
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("cannot cancel after job response", async function () {
        let jobId: any = await relay.jobCount(),
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest();

        let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[15]);
        await expect(
            relay.connect(signers[1]).jobResponse(signedDigest, jobId, output, totalTime, errorCode, signTimestamp)
        ).to.emit(relay, "JobResponded");

        await expect(
            relay.connect(signers[2]).jobCancel(jobId)
        ).to.be.revertedWithCustomError(relay, "RelayJobNotExists");
    });

    it("cannot cancel before overall timeout", async function () {
        let jobId: any = await relay.jobCount();

        await expect(
            relay.connect(signers[2]).jobCancel(jobId)
        ).to.revertedWithCustomError(relay, "RelayOverallTimeoutNotOver");
    });

    it("can cancel from job owner account after overall timeout", async function () {
        let jobId: any = await relay.jobCount();
        await time.increase(1100);

        await expect(
            relay.connect(signers[2]).jobCancel(jobId)
        ).to.emit(relay, "JobCancelled").withArgs(jobId);

        let job = await relay.jobs(jobId);
        expect(job.jobOwner).to.eq(ZeroAddress);
    });

    it("can cancel from any other account except job owner after overall timeout", async function () {
        let jobId: any = await relay.jobCount();
        await time.increase(1100);

        await expect(
            relay.jobCancel(jobId)
        ).to.emit(relay, "JobCancelled").withArgs(jobId);

        let job = await relay.jobs(jobId);
        expect(job.jobOwner).to.eq(ZeroAddress);
    });

});

describe("Relay - Job sent by UserSample contract", function () {
    let signers: Signer[];
    let addrs: string[];
    let token: USDCoin;
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let relay: Relay;
    let userSample: UserSample;
    let fixedGas: number;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const USDCoin = await ethers.getContractFactory("USDCoin");
        token = await upgrades.deployProxy(
            USDCoin,
            [addrs[0]],
            {
                kind: "uups",
            }
        ) as unknown as USDCoin;

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        let admin = addrs[0],
            images = [image1, image2],
            maxAge = 600,
            globalMinTimeout = 10 * 1000,  // in milliseconds
            globalMaxTimeout = 100 * 1000,  // in milliseconds
            overallTimeout = 100,
            gatewayFeePerJob = 10,
            callbackMeasureGas = 4530;
        fixedGas = 150000;
        const Relay = await ethers.getContractFactory("Relay");
        relay = await upgrades.deployProxy(
            Relay,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    maxAge,
                    token.target,
                    globalMinTimeout,
                    globalMaxTimeout,
                    overallTimeout,
                    gatewayFeePerJob,
                    fixedGas,
                    callbackMeasureGas
                ]
            },
        ) as unknown as Relay;

        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], signTimestamp, wallets[15]);

        await relay.connect(signers[1]).registerGateway(signature, attestation, signedDigest, signTimestamp);

        let env = 1,
            executionFeePerMs = 10;
        await relay.addGlobalEnv(env, executionFeePerMs);

        const UserSample = await ethers.getContractFactory("UserSample");
        userSample = await UserSample.deploy(relay.target, addrs[9], token.target, addrs[10]) as unknown as UserSample;

        await token.transfer(userSample.target, 1000000);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can submit response and execute callback", async function () {
        let env = 1,
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            userTimeout = 50000,
            maxGasPrice = (await signers[0].provider?.getFeeData())?.gasPrice || parseUnits("1", 9),
            usdcDeposit = 1000000,
            callbackDeposit = parseUnits("1"),	// 1 eth
            refundAccount = addrs[1],
            callbackContract = userSample.target,
            callbackGasLimit = 20000;
        // deposit eth in UserSample contract before relaying jobs
        await signers[4].sendTransaction({ to: userSample.target, value: callbackDeposit });
        await userSample.relayJob(
            env, codeHash, codeInputs, userTimeout, maxGasPrice, usdcDeposit, callbackDeposit, refundAccount, callbackContract, callbackGasLimit
        );

        let jobId: any = await relay.jobCount(),
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest();

        // set tx.gasprice for next block
        await setNextBlockBaseFeePerGas(1);
        let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[15]);
        let initBalance = await ethers.provider.getBalance(addrs[1]);
        let tx = relay.connect(signers[2]).jobResponse(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);
        await expect(tx).to.emit(relay, "JobResponded")
            .and.to.emit(userSample, "CalledBack").withArgs(
                jobId, callbackContract, codeHash, codeInputs, output, errorCode
            );

        let jobOwner = userSample.target;
        let txReceipt = await (await tx).wait();
        // console.log("FIXED_GAS : ", txReceipt?.gasUsed);
        // validate callback cost and refund
        let txGasPrice = txReceipt?.gasPrice || 0n;
        let callbackGas = 9317; // calculated using console.log
        // console.log("txGasPrice: ", txGasPrice);
        let callbackCost = txGasPrice * (ethers.toBigInt(callbackGas + fixedGas));
        expect(await ethers.provider.getBalance(addrs[1])).to.equal(initBalance + callbackCost);
        expect(await ethers.provider.getBalance(jobOwner)).to.equal(callbackDeposit - callbackCost);

        let userSampleBal = await ethers.provider.getBalance(jobOwner),
            initBalAddrs10 = await ethers.provider.getBalance(addrs[10]),
            withdrawalTxn = await userSample.connect(signers[10]).withdrawEth(),
            withdrawalReceipt = await withdrawalTxn.wait(),
            gasCost = 0n;
        if (withdrawalReceipt)
            gasCost = withdrawalReceipt?.gasPrice * withdrawalReceipt?.gasUsed;
        let finalBalAddrs10 = await ethers.provider.getBalance(addrs[10]);
        // console.log("user sample owner bal: ", formatUnits(finalBalAddrs10), formatUnits(initBalAddrs10))
        expect(finalBalAddrs10).to.eq(initBalAddrs10 + userSampleBal - gasCost);
    });

    it("can submit response with gas price higher than maxGasPrice", async function () {
        let env = 1,
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            userTimeout = 50000,
            maxGasPrice = (await signers[0].provider?.getFeeData())?.gasPrice || parseUnits("1", 9),
            usdcDeposit = 1000000,
            callbackDeposit = parseUnits("101"),	// 1 eth
            refundAccount = addrs[1],
            callbackContract = userSample.target,
            callbackGasLimit = 20000;
        await signers[0].sendTransaction({ to: userSample.target, value: callbackDeposit });
        await userSample.relayJob(
            env, codeHash, codeInputs, userTimeout, maxGasPrice, usdcDeposit, callbackDeposit, refundAccount, callbackContract, callbackGasLimit
        );

        let jobId: any = await relay.jobCount(),
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest();

        let initBalance = await ethers.provider.getBalance(addrs[1]);

        // set tx.gasprice for next block
        await setNextBlockBaseFeePerGas(maxGasPrice + 10n);
        let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[15]);
        let tx = relay.connect(signers[2]).jobResponse(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);
        await expect(tx).to.emit(relay, "JobResponded")
            .and.to.not.emit(userSample, "CalledBack");

        // validate callback cost and refund
        let jobOwner = userSample.target;
        let txGasPrice = (await (await tx).wait())?.gasPrice || 0n;
        let callbackCost = txGasPrice * (ethers.toBigInt(fixedGas));
        expect(await ethers.provider.getBalance(addrs[1])).to.equal(initBalance + callbackCost);
        expect(await ethers.provider.getBalance(jobOwner)).to.equal(callbackDeposit - callbackCost);

    });

    // TODO
    // it("can submit response but fails to execute callback due to less callbackDeposit", async function () {
    // 	let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
    // 		codeInputs = solidityPacked(["string"], ["codeInput"]),
    // 		userTimeout = 50000,
    // 		maxGasPrice = 100,
    // 		callbackDeposit = 1,	// 1 wei
    // 		refundAccount = addrs[1];
    // 	await userSample.relayJob(
    // 		codeHash, codeInputs, userTimeout, maxGasPrice, refundAccount,
    // 		{value: callbackDeposit}
    // 	);

    // 	let jobId: any = await relay.jobCount(),
    // 		output = solidityPacked(["string"], ["it is the output"]),
    // 		totalTime = 100,
    // 		errorCode = 0,
    // 		signTimestamp = await time.latest();

    // 	console.log("job: ", jobId, await relay.jobs(jobId));

    // 	let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[15]);
    // 	let tx = relay.connect(signers[1]).jobResponse(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);
    // 	await expect(tx).to.emit(relay, "JobResponded").and.to.not.emit(userSample, "CalledBack");
    // });

});

function normalize(key: string): string {
    return '0x' + key.substring(4);
}

type Attestation = {
    imageId: BytesLike,
    timestampMs: number,
    publicKey: string,
    userData: BytesLike,
}

async function createAttestation(
    enclaveKey: string,
    image: string,
    sourceEnclaveKey: Wallet,
    timestamp: number,
    userData: BytesLike = "0x",
): Promise<[string, Attestation]> {
    const domain = {
        name: 'marlin.oyster.AttestationVerifier',
        version: '1',
    };

    const types = {
        Attestation: [
            { name: 'imageId', type: 'bytes32' },
            { name: 'timestampMs', type: 'uint64' },
            { name: 'publicKey', type: 'bytes' },
            { name: 'userData', type: 'bytes' },
        ]
    }

    const attestation: Attestation = {
        imageId: image,
        timestampMs: timestamp,
        publicKey: enclaveKey,
        userData: userData,
    };
    const sign = await sourceEnclaveKey.signTypedData(domain, types, attestation);
    return [ethers.Signature.from(sign).serialized, attestation];
}

async function createGatewaySignature(
    owner: string,
    signTimestamp: number,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.Relay',
        version: '1',
    };

    const types = {
        Register: [
            { name: 'owner', type: 'address' },
            { name: 'signTimestamp', type: 'uint256' }
        ]
    };

    const value = {
        owner,
        signTimestamp
    };

    const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
    return ethers.Signature.from(sign).serialized;
}

async function createJobResponseSignature(
    jobId: number | bigint,
    output: string,
    totalTime: number,
    errorCode: number,
    signTimestamp: number,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.Relay',
        version: '1'
    };

    const types = {
        JobResponse: [
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
    let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

    return new Wallet(wallet.privateKey);
}
