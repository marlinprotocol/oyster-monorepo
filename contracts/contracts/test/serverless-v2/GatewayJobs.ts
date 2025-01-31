import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, Wallet, ZeroAddress, keccak256, parseUnits, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationAutherUpgradeable, AttestationVerifier, Executors, GatewayJobs, Gateways, Jobs, Pond, USDCoin } from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { testERC165 } from '../helpers/erc165';

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

describe("GatewayJobs - Init", function () {
    let signers: Signer[];
    let addrs: string[];
    let stakingToken: string;
    let usdcToken: USDCoin;
    let gateways: string;

    let jobs: string;
    let signMaxAge: number;
    let relayBufferTime: number;
    let slashCompForGateway: number;
    let reassignCompForReporterGateway: number;
    let stakingPaymentPool: string;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));

        stakingToken = addrs[1];
        gateways = addrs[1];
        jobs = addrs[1];
        signMaxAge = 600;
        relayBufferTime = 100;
        slashCompForGateway = 10;
        reassignCompForReporterGateway = 100;
        stakingPaymentPool = addrs[1];

        const USDCoin = await ethers.getContractFactory("USDCoin");
        usdcToken = await upgrades.deployProxy(
            USDCoin,
            [addrs[0]],
            {
                kind: "uups",
            }
        ) as unknown as USDCoin;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("deploys with initialization disabled", async function () {

        const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
        const gatewayJobs = await GatewayJobs.deploy(
            stakingToken,
            usdcToken,
            signMaxAge,
            relayBufferTime,
            slashCompForGateway,
            reassignCompForReporterGateway,
            jobs,
            gateways,
            stakingPaymentPool
        );

        await expect(
            gatewayJobs.initialize(addrs[0]),
        ).to.be.revertedWithCustomError(gatewayJobs, "InvalidInitialization");
    });

    it("deploys as proxy and initializes", async function () {
        const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
        const gatewayJobs = await upgrades.deployProxy(
            GatewayJobs,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    stakingToken,
                    usdcToken.target,
                    signMaxAge,
                    relayBufferTime,
                    slashCompForGateway,
                    reassignCompForReporterGateway,
                    jobs,
                    gateways,
                    stakingPaymentPool
                ]
            },
        );

        expect(await gatewayJobs.hasRole(await gatewayJobs.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    });

    it("cannot initialize with zero address as admin", async function () {
        const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
        await expect(
            upgrades.deployProxy(
                GatewayJobs,
                [ZeroAddress],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        stakingToken,
                        usdcToken.target,
                        signMaxAge,
                        relayBufferTime,
                        slashCompForGateway,
                        reassignCompForReporterGateway,
                        jobs,
                        gateways,
                        stakingPaymentPool
                    ]
                }
            )
        ).to.be.revertedWithCustomError(GatewayJobs, "GatewayJobsZeroAddressAdmin");
    });

    it("cannot deploy with zero address as staking token", async function () {
        const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
        await expect(
            upgrades.deployProxy(
                GatewayJobs,
                [addrs[1]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        ZeroAddress,
                        usdcToken.target,
                        signMaxAge,
                        relayBufferTime,
                        slashCompForGateway,
                        reassignCompForReporterGateway,
                        jobs,
                        gateways,
                        stakingPaymentPool
                    ]
                }
            )
        ).to.be.revertedWithCustomError(GatewayJobs, "GatewayJobsZeroAddressStakingToken");
    });

    it("cannot deploy with zero address as usdc token", async function () {
        const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
        await expect(
            upgrades.deployProxy(
                GatewayJobs,
                [addrs[1]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        stakingToken,
                        ZeroAddress,
                        signMaxAge,
                        relayBufferTime,
                        slashCompForGateway,
                        reassignCompForReporterGateway,
                        jobs,
                        gateways,
                        stakingPaymentPool
                    ]
                }
            )
        ).to.be.revertedWithCustomError(GatewayJobs, "GatewayJobsZeroAddressUsdcToken");
    });

    it("upgrades", async function () {
        const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
        const gatewayJobs = await upgrades.deployProxy(
            GatewayJobs,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    stakingToken,
                    usdcToken.target,
                    signMaxAge,
                    relayBufferTime,
                    slashCompForGateway,
                    reassignCompForReporterGateway,
                    jobs,
                    gateways,
                    stakingPaymentPool
                ]
            }
        );
        await upgrades.upgradeProxy(
            gatewayJobs.target,
            GatewayJobs,
            {
                kind: "uups",
                constructorArgs: [
                    stakingToken,
                    usdcToken.target,
                    signMaxAge,
                    relayBufferTime,
                    slashCompForGateway,
                    reassignCompForReporterGateway,
                    jobs,
                    gateways,
                    stakingPaymentPool
                ]
            }
        );

        expect(await gatewayJobs.hasRole(await gatewayJobs.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    });

    it("does not upgrade without admin", async function () {
        const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
        const gatewayJobs = await upgrades.deployProxy(
            GatewayJobs,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    stakingToken,
                    usdcToken.target,
                    signMaxAge,
                    relayBufferTime,
                    slashCompForGateway,
                    reassignCompForReporterGateway,
                    jobs,
                    gateways,
                    stakingPaymentPool
                ]
            },
        );

        await expect(
            upgrades.upgradeProxy(gatewayJobs.target, GatewayJobs.connect(signers[1]), {
                kind: "uups",
                constructorArgs: [
                    stakingToken,
                    usdcToken.target,
                    signMaxAge,
                    relayBufferTime,
                    slashCompForGateway,
                    reassignCompForReporterGateway,
                    jobs,
                    gateways,
                    stakingPaymentPool
                ]
            }),
        ).to.be.revertedWithCustomError(GatewayJobs, "AccessControlUnauthorizedAccount");
    });

});

testERC165(
    "GatewayJobs - ERC165",
    async function (_signers: Signer[], addrs: string[]) {
        const USDCoin = await ethers.getContractFactory("USDCoin");
        const usdcToken = await upgrades.deployProxy(
            USDCoin,
            [addrs[0]],
            {
                kind: "uups",
            }
        ) as unknown as USDCoin;

        let stakingToken = addrs[1],
            gateways = addrs[1],
            jobs = addrs[1],
            signMaxAge = 600,
            relayBufferTime = 100,
            slashCompForGateway = 10,
            reassignCompForReporterGateway = 100,
            stakingPaymentPool = addrs[1];
        const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
        const gatewayJobs = await upgrades.deployProxy(
            GatewayJobs,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    stakingToken,
                    usdcToken.target,
                    signMaxAge,
                    relayBufferTime,
                    slashCompForGateway,
                    reassignCompForReporterGateway,
                    jobs,
                    gateways,
                    stakingPaymentPool
                ]
            },
        );
        return gatewayJobs;
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

describe("GatewayJobs - Admin functions", function () {
    let signers: Signer[];
    let addrs: string[];
    let stakingToken: string;
    let usdcToken: USDCoin;
    let gateways: string;
    let gatewayJobs: GatewayJobs;

    let jobs: string;
    let signMaxAge: number;
    let relayBufferTime: number;
    let slashCompForGateway: number;
    let reassignCompForReporterGateway: number;
    let stakingPaymentPool: string;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));

        stakingToken = addrs[1];
        gateways = addrs[1];
        jobs = addrs[1];
        signMaxAge = 600;
        relayBufferTime = 100;
        slashCompForGateway = 10;
        reassignCompForReporterGateway = 100;
        stakingPaymentPool = addrs[1];

        const USDCoin = await ethers.getContractFactory("USDCoin");
        usdcToken = await upgrades.deployProxy(
            USDCoin,
            [addrs[0]],
            {
                kind: "uups",
            }
        ) as unknown as USDCoin;

        const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
        gatewayJobs = await upgrades.deployProxy(
            GatewayJobs,
            [addrs[0]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    stakingToken,
                    usdcToken.target,
                    signMaxAge,
                    relayBufferTime,
                    slashCompForGateway,
                    reassignCompForReporterGateway,
                    jobs,
                    gateways,
                    stakingPaymentPool
                ]
            },
        ) as unknown as GatewayJobs;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can set job allowance with admin account", async function () {
        await expect(
            gatewayJobs.setJobAllowance()
        ).to.be.fulfilled;
    });

    it("cannot set job allowance without admin", async function () {
        await expect(
            gatewayJobs.connect(signers[1]).setJobAllowance()
        ).to.be.revertedWithCustomError(gatewayJobs, "AccessControlUnauthorizedAccount");
    });

});

describe("GatewayJobs - Relay", function () {
    let signers: Signer[];
    let addrs: string[];
    let stakingToken: Pond;
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let gateways: Gateways;
    let executors: Executors;
    let jobs: Jobs;
    let gatewayJobs: GatewayJobs;
    let usdcToken: USDCoin;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

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

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        let admin = addrs[0],
            images = [image2, image3],
            paymentPoolAddress = addrs[1],
            maxAge = 600,
            deregisterOrUnstakeTimeout = 600,
            reassignCompForReporterGateway = 100,
            slashPercentInBips = 1,
            slashMaxBips = 100;
        const Gateways = await ethers.getContractFactory("Gateways");
        gateways = await upgrades.deployProxy(
            Gateways,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [attestationVerifier.target, maxAge, stakingToken.target, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        ) as unknown as Gateways;

        images = [image4, image5, image6, image7];
        let minStakeAmount = 1;
        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [attestationVerifier.target, maxAge, stakingToken.target, minStakeAmount, slashPercentInBips, slashMaxBips]
            },
        ) as unknown as Executors;

        let signMaxAge = 600,
            executionBufferTime = 100,
            noOfNodesToSelect = 3,
            stakingPaymentPoolAddress = addrs[0],
            usdcPaymentPoolAddress = addrs[0];
        const Jobs = await ethers.getContractFactory("contracts/serverless-v2/Jobs.sol:Jobs");
        jobs = await upgrades.deployProxy(
            Jobs,
            [admin],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    stakingToken.target,
                    usdcToken.target,
                    signMaxAge,
                    executionBufferTime,
                    noOfNodesToSelect,
                    stakingPaymentPoolAddress,
                    usdcPaymentPoolAddress,
                    executors.target
                ]
            },
        ) as unknown as Jobs;

        let relayBufferTime = 100,
            slashCompForGateway = 10;
        const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
        gatewayJobs = await upgrades.deployProxy(
            GatewayJobs,
            [admin],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    stakingToken.target,
                    usdcToken.target,
                    signMaxAge,
                    relayBufferTime,
                    slashCompForGateway,
                    reassignCompForReporterGateway,
                    jobs.target,
                    gateways.target,
                    stakingPaymentPoolAddress
                ]
            },
        ) as unknown as GatewayJobs;

        await executors.grantRole(await executors.JOBS_ROLE(), jobs.target);

        let env = 1,
            executionFeePerMs = 10,
            stakingRewardPerMs = 10;
        await jobs.addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs);

        let chainIds = [1];
        let reqChains = [
            {
                relayAddress: addrs[1],
                relaySubscriptionsAddress: addrs[2],
                httpRpcUrl: "https://eth.rpc",
                wsRpcUrl: "wss://eth.rpc"
            }
        ]
        await gateways.addChainGlobal(chainIds, reqChains);

        let amount = parseUnits("1000");	// 1000 POND
        await stakingToken.transfer(addrs[1], amount);
        await stakingToken.connect(signers[1]).approve(gateways.target, amount);
        await stakingToken.connect(signers[1]).approve(executors.target, amount);

        amount = parseUnits("1000", 6);
        await usdcToken.transfer(addrs[1], amount);
        await usdcToken.connect(signers[1]).approve(gatewayJobs.target, amount);

        // REGISTER GATEWAYS
        let timestamp = await time.latest() * 1000,
            stakeAmount = 10,
            signTimestamp = await time.latest();
        // 1st gateway
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);
        let signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[15]);
        await gateways.connect(signers[1]).registerGateway(signature, attestation, chainIds, signedDigest, stakeAmount, signTimestamp);

        // 2nd gateway
        [signature, attestation] = await createAttestation(pubkeys[16], image3, wallets[14], timestamp - 540000);
        signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[16]);
        await gateways.connect(signers[1]).registerGateway(signature, attestation, chainIds, signedDigest, stakeAmount, signTimestamp);

        // REGISTER EXECUTORS
        let execStakeAmount = parseUnits("10"),	// 10 POND
            jobCapacity = 3;
        // 1st executor
        [signature, attestation] = await createAttestation(pubkeys[17], image4, wallets[14], timestamp - 540000);
        signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[17]);
        await executors.connect(signers[1]).registerExecutor(signature, attestation, jobCapacity, signTimestamp, signedDigest, execStakeAmount, env);

        // 2nd executor
        [signature, attestation] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
        signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[18]);
        await executors.connect(signers[1]).registerExecutor(signature, attestation, jobCapacity, signTimestamp, signedDigest, execStakeAmount, env);

        // 3rd executor
        [signature, attestation] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
        signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[19]);
        await executors.connect(signers[1]).registerExecutor(signature, attestation, jobCapacity, signTimestamp, signedDigest, execStakeAmount, env);

        // 4th executor
        [signature, attestation] = await createAttestation(pubkeys[20], image7, wallets[14], timestamp - 540000);
        signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[20]);
        await executors.connect(signers[1]).registerExecutor(signature, attestation, jobCapacity, signTimestamp, signedDigest, execStakeAmount, env);

    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can relay job", async function () {
        // let reqChainId = (await ethers.provider.getNetwork()).chainId;
        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobRequestTimestamp = await time.latest(),
            sequenceId = 1,
            jobOwner = addrs[1],
            env = 1,
            signTimestamp = await time.latest();
        let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);

        let tx = await gatewayJobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp);
        await expect(tx).to.emit(gatewayJobs, "JobRelayed");

        let job = await gatewayJobs.relayJobs(jobId);
        expect(job.jobOwner).to.eq(jobOwner);

        let execJobId = 0;
        expect(await gatewayJobs.execJobs(execJobId)).to.eq(jobId);

        let selectedExecutors = await jobs.getSelectedExecutors(execJobId);
        for (let index = 0; index < selectedExecutors.length; index++) {
            const executor = selectedExecutors[index];
            expect([addrs[17], addrs[18], addrs[19], addrs[20]]).to.contain(executor);
        }
    });

    it("cannot relay job after relay time is over", async function () {
        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobRequestTimestamp = await time.latest(),
            sequenceId = 1,
            jobOwner = addrs[1],
            env = 1,
            signTimestamp = await time.latest();
        let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);

        await time.increase(1000);
        await expect(gatewayJobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp))
            .to.be.revertedWithCustomError(gatewayJobs, "GatewayJobsRelayTimeOver");
    });

    it("cannot relay job with wrong sequence id", async function () {
        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobRequestTimestamp = await time.latest(),
            sequenceId = 2,
            jobOwner = addrs[1],
            env = 1,
            signTimestamp = await time.latest();
        let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);

        await expect(gatewayJobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp))
            .to.be.revertedWithCustomError(gatewayJobs, "GatewayJobsInvalidRelaySequenceId");
    });

    it("cannot relay job with expired signature", async function () {
        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobRequestTimestamp = await time.latest(),
            sequenceId = 1,
            jobOwner = addrs[1],
            env = 1,
            signTimestamp = await time.latest() - 700;
        let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);

        await expect(gatewayJobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp))
            .to.be.revertedWithCustomError(gatewayJobs, "GatewayJobsSignatureTooOld");
    });

    it("cannot relay a job twice with same job id", async function () {
        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobRequestTimestamp = await time.latest(),
            sequenceId = 1,
            jobOwner = addrs[1],
            env = 1,
            signTimestamp = await time.latest();
        let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);
        await gatewayJobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp);

        await expect(gatewayJobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp))
            .to.be.revertedWithCustomError(gatewayJobs, "GatewayJobsAlreadyRelayed");
    });

    it("cannot relay job with unsupported chain id", async function () {
        let jobId: any = (BigInt(2) << BigInt(192)) + BigInt(1),
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobRequestTimestamp = await time.latest(),
            sequenceId = 1,
            jobOwner = addrs[1],
            env = 1,
            signTimestamp = await time.latest();
        let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);

        await expect(gatewayJobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp))
            .to.be.revertedWithCustomError(gatewayJobs, "GatewayJobsUnsupportedChain");
    });

    it("cannot relay job with unsupported execution env", async function () {
        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobRequestTimestamp = await time.latest(),
            sequenceId = 1,
            jobOwner = addrs[1],
            env = 2,
            signTimestamp = await time.latest();
        let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);

        await expect(gatewayJobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp))
            .to.be.revertedWithCustomError(gatewayJobs, "GatewayJobsCreateFailed");
    });

    it("cannot relay job when a minimum no. of executor nodes are not available", async function () {
        await executors.connect(signers[1]).drainExecutor(addrs[19]);
        await executors.connect(signers[1]).deregisterExecutor(addrs[19]);

        await executors.connect(signers[1]).drainExecutor(addrs[20]);
        await executors.connect(signers[1]).deregisterExecutor(addrs[20]);

        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobRequestTimestamp = await time.latest(),
            sequenceId = 1,
            jobOwner = addrs[1],
            env = 1,
            signTimestamp = await time.latest();
        let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);

        await expect(gatewayJobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp))
            .to.emit(gatewayJobs, "JobResourceUnavailable").withArgs(jobId, addrs[15]);

        expect((await gatewayJobs.relayJobs(jobId)).isResourceUnavailable).to.be.true;
    });

    it("cannot relay job again if it's marked as ended due to unavailable executors", async function () {
        await executors.connect(signers[1]).drainExecutor(addrs[19]);
        await executors.connect(signers[1]).deregisterExecutor(addrs[19]);

        await executors.connect(signers[1]).drainExecutor(addrs[20]);
        await executors.connect(signers[1]).deregisterExecutor(addrs[20]);

        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobRequestTimestamp = await time.latest(),
            sequenceId = 1,
            jobOwner = addrs[1],
            env = 1,
            signTimestamp = await time.latest();
        let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);

        await expect(gatewayJobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp))
            .to.emit(gatewayJobs, "JobResourceUnavailable").withArgs(jobId, addrs[15]);

        // relay again
        await expect(gatewayJobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp))
            .to.be.revertedWithCustomError(gatewayJobs, "GatewayJobsResourceUnavailable");
    });

    it("cannot relay job after all the executors are fully occupied", async function () {
        await executors.connect(signers[1]).drainExecutor(addrs[20]);
        await executors.connect(signers[1]).deregisterExecutor(addrs[20]);

        for (let index = 1; index <= 3; index++) {
            let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(index),
                codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
                codeInputs = solidityPacked(["string"], ["codeInput"]),
                deadline = 10000,
                jobRequestTimestamp = await time.latest(),
                sequenceId = 1,
                jobOwner = addrs[1],
                env = 1,
                signTimestamp = await time.latest();
            let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);

            await expect(await gatewayJobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp))
                .to.emit(gatewayJobs, "JobRelayed");
        }

        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(4),
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobRequestTimestamp = await time.latest(),
            sequenceId = 1,
            jobOwner = addrs[1],
            env = 1,
            signTimestamp = await time.latest();
        let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);

        await expect(gatewayJobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp))
            .to.emit(gatewayJobs, "JobResourceUnavailable").withArgs(jobId, addrs[15]);

        expect((await gatewayJobs.relayJobs(jobId)).isResourceUnavailable).to.be.true;

        // SUBMIT OUTPUT AND THEN RELAY JOB WILL WORK
        jobId = 0;
        let output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0;

        signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
        await jobs.connect(signers[1]).submitOutput(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);

        signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[18]);
        await jobs.connect(signers[1]).submitOutput(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);

        signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[19]);
        await jobs.connect(signers[1]).submitOutput(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);

        // RELAY AGAIN WORKS
        jobId = (BigInt(1) << BigInt(192)) + BigInt(5);
        signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);

        await expect(gatewayJobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp))
            .to.emit(gatewayJobs, "JobRelayed");
    });

    it("cannot relay job if Jobs contract reverts due to some unexpected error", async function () {
        const JobsMock = await ethers.getContractFactory("JobsMock");
        let env = 1,
            executionFeePerMs = 10,
            stakingRewardPerMs = 10;
        let jobsMock = await JobsMock.deploy(env, executionFeePerMs, stakingRewardPerMs);

        // upgrading the contract to update immutable jobs contract
        let signMaxAge = 600,
            relayBufferTime = 100,
            slashCompForGateway = 10,
            reassignCompForReporterGateway = 100,
            stakingPaymentPoolAddress = addrs[0];
        const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
        gatewayJobs = await upgrades.upgradeProxy(
            gatewayJobs.target,
            GatewayJobs,
            {
                kind: "uups",
                constructorArgs: [
                    stakingToken.target,
                    usdcToken.target,
                    signMaxAge,
                    relayBufferTime,
                    slashCompForGateway,
                    reassignCompForReporterGateway,
                    jobsMock.target,
                    gateways.target,
                    stakingPaymentPoolAddress
                ]
            },
        ) as unknown as GatewayJobs;

        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobRequestTimestamp = await time.latest(),
            sequenceId = 1,
            jobOwner = addrs[1],
            signTimestamp = await time.latest();
        let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);

        await expect(
            gatewayJobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp)
        ).to.be.revertedWithCustomError(gatewayJobs, "GatewayJobsCreateFailed").withArgs(ethers.id('JobsMockError()').substring(0, 10));
    });
});

describe("GatewayJobs - Reassign Gateway", function () {
    let signers: Signer[];
    let addrs: string[];
    let stakingToken: Pond;
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let gateways: Gateways;
    let executors: Executors;
    let jobs: Jobs;
    let usdcToken: USDCoin;
    let gatewayJobs: GatewayJobs;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

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

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        let admin = addrs[0],
            images = [image2, image3],
            paymentPoolAddress = addrs[1],
            maxAge = 600,
            deregisterOrUnstakeTimeout = 600,
            reassignCompForReporterGateway = 10,
            slashPercentInBips = 1,
            slashMaxBips = 100;
        const Gateways = await ethers.getContractFactory("Gateways");
        gateways = await upgrades.deployProxy(
            Gateways,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [attestationVerifier.target, maxAge, stakingToken.target, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        ) as unknown as Gateways;

        images = [image4, image5, image6, image7];
        let minStakeAmount = 1;
        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [attestationVerifier.target, maxAge, stakingToken.target, minStakeAmount, slashPercentInBips, slashMaxBips]
            },
        ) as unknown as Executors;

        let signMaxAge = 600,
            executionBufferTime = 100,
            noOfNodesToSelect = 3,
            stakingPaymentPoolAddress = addrs[4],
            usdcPaymentPoolAddress = addrs[0];
        const Jobs = await ethers.getContractFactory("contracts/serverless-v2/Jobs.sol:Jobs");
        jobs = await upgrades.deployProxy(
            Jobs,
            [admin],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    stakingToken.target,
                    usdcToken.target,
                    signMaxAge,
                    executionBufferTime,
                    noOfNodesToSelect,
                    stakingPaymentPoolAddress,
                    usdcPaymentPoolAddress,
                    executors.target
                ]
            },
        ) as unknown as Jobs;

        let relayBufferTime = 100,
            slashCompForGateway = 10;
        const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
        gatewayJobs = await upgrades.deployProxy(
            GatewayJobs,
            [admin],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    stakingToken.target,
                    usdcToken.target,
                    signMaxAge,
                    relayBufferTime,
                    slashCompForGateway,
                    reassignCompForReporterGateway,
                    jobs.target,
                    gateways.target,
                    stakingPaymentPoolAddress
                ]
            },
        ) as unknown as GatewayJobs;

        await gateways.grantRole(await gateways.GATEWAY_JOBS_ROLE(), gatewayJobs.target);
        await executors.grantRole(await executors.JOBS_ROLE(), jobs.target);

        let env = 1,
            executionFeePerMs = 10,
            stakingRewardPerMs = 10;
        await jobs.addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs);

        let chainIds = [1];
        let reqChains = [
            {
                relayAddress: addrs[1],
                relaySubscriptionsAddress: addrs[2],
                httpRpcUrl: "https://eth.rpc",
                wsRpcUrl: "ws://eth.rpc"
            }
        ]
        await gateways.addChainGlobal(chainIds, reqChains);

        let amount = parseUnits("1000");	// 1000 POND
        await stakingToken.transfer(addrs[1], amount);
        await stakingToken.connect(signers[1]).approve(gateways.target, amount);
        await stakingToken.transfer(addrs[2], amount);
        await stakingToken.connect(signers[2]).approve(gateways.target, amount);
        await stakingToken.connect(signers[1]).approve(executors.target, amount);

        amount = parseUnits("1000", 6);		// 1000 USDC
        await usdcToken.transfer(addrs[1], amount);
        await usdcToken.connect(signers[1]).approve(gatewayJobs.target, amount);

        // REGISTER GATEWAYS
        let timestamp = await time.latest() * 1000,
            stakeAmount = 10000,
            signTimestamp = await time.latest();
        // 1st gateway
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);
        let signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[15]);
        await gateways.connect(signers[1]).registerGateway(signature, attestation, chainIds, signedDigest, stakeAmount, signTimestamp);

        // 2nd gateway
        [signature, attestation] = await createAttestation(pubkeys[16], image3, wallets[14], timestamp - 540000);
        signedDigest = await createGatewaySignature(addrs[2], chainIds, signTimestamp, wallets[16]);
        await gateways.connect(signers[2]).registerGateway(signature, attestation, chainIds, signedDigest, stakeAmount, signTimestamp);

        // REGISTER EXECUTORS
        let execStakeAmount = parseUnits("10"),	// 10 POND
            jobCapacity = 3;
        // 1st executor
        [signature, attestation] = await createAttestation(pubkeys[17], image4, wallets[14], timestamp - 540000);
        signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[17]);
        await executors.connect(signers[1]).registerExecutor(signature, attestation, jobCapacity, signTimestamp, signedDigest, execStakeAmount, env);

        // 2nd executor
        [signature, attestation] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
        signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[18]);
        await executors.connect(signers[1]).registerExecutor(signature, attestation, jobCapacity, signTimestamp, signedDigest, execStakeAmount, env);

        // 3rd executor
        [signature, attestation] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
        signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[19]);
        await executors.connect(signers[1]).registerExecutor(signature, attestation, jobCapacity, signTimestamp, signedDigest, execStakeAmount, env);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can reassign if job not relayed", async function () {
        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            gatewayKeyOld = addrs[15],
            sequenceId = 1,
            jobRequestTimestamp = await time.latest() + 100,
            jobOwner = addrs[3],
            signTimestamp = await time.latest();

        let stakingPoolInitialBal = await stakingToken.balanceOf(addrs[4]);
        let reporterGatewayInitialBal = await stakingToken.balanceOf(addrs[2]);
        let failedGatewayStakedAmt = (await gateways.gateways(addrs[15])).stakeAmount;

        let signedDigest = await createReassignGatewaySignature(jobId, gatewayKeyOld, jobOwner, sequenceId, jobRequestTimestamp, signTimestamp, wallets[16]);
        let tx = await gatewayJobs.connect(signers[2]).reassignGatewayRelay(gatewayKeyOld, jobId, signedDigest, sequenceId, jobRequestTimestamp, jobOwner, signTimestamp);
        await expect(tx).to.emit(gatewayJobs, "GatewayReassigned");

        let stakingPoolFinalBal = await stakingToken.balanceOf(addrs[4]);
        let reporterGatewayFinalBal = await stakingToken.balanceOf(addrs[2]);
        let reassignCompForReporterGateway = await gatewayJobs.REASSIGN_COMP_FOR_REPORTER_GATEWAY();
        let slashedAmount = failedGatewayStakedAmt * await gateways.SLASH_PERCENT_IN_BIPS() / await gateways.SLASH_MAX_BIPS();

        expect(reporterGatewayFinalBal - reporterGatewayInitialBal).to.eq(reassignCompForReporterGateway);
        expect(stakingPoolFinalBal - stakingPoolInitialBal).to.eq(slashedAmount - reassignCompForReporterGateway);
    });

    it("cannot reassign if job already relayed", async function () {
        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobRequestTimestamp = await time.latest(),
            sequenceId = 1,
            jobOwner = addrs[1],
            env = 1,
            signTimestamp = await time.latest();
        let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);
        await gatewayJobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp);

        let gatewayKeyOld = addrs[15];
        signedDigest = await createReassignGatewaySignature(jobId, gatewayKeyOld, jobOwner, sequenceId, jobRequestTimestamp, signTimestamp, wallets[16]);

        await expect(
            gatewayJobs.connect(signers[16]).reassignGatewayRelay(gatewayKeyOld, jobId, signedDigest, sequenceId, jobRequestTimestamp, jobOwner, signTimestamp)
        ).to.revertedWithCustomError(gatewayJobs, "GatewayJobsAlreadyRelayed");
    });

    it("cannot reassign for wrong sequenceId", async function () {
        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            gatewayKeyOld = addrs[15],
            sequenceId = 2,
            jobRequestTimestamp = await time.latest() + 10,
            jobOwner = addrs[1],
            signTimestamp = await time.latest();

        let signedDigest = await createReassignGatewaySignature(jobId, gatewayKeyOld, jobOwner, sequenceId, jobRequestTimestamp, signTimestamp, wallets[16]);
        let tx = gatewayJobs.connect(signers[16]).reassignGatewayRelay(gatewayKeyOld, jobId, signedDigest, sequenceId, jobRequestTimestamp, jobOwner, signTimestamp);
        await expect(tx).to.revertedWithCustomError(gatewayJobs, "GatewayJobsInvalidRelaySequenceId");
    });

    it("cannot reassign with expired signature", async function () {
        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            gatewayKeyOld = addrs[15],
            sequenceId = 1,
            jobRequestTimestamp = await time.latest() + 10,
            jobOwner = addrs[1],
            signTimestamp = await time.latest() - 700;

        let signedDigest = await createReassignGatewaySignature(jobId, gatewayKeyOld, jobOwner, sequenceId, jobRequestTimestamp, signTimestamp, wallets[16]);
        let tx = gatewayJobs.connect(signers[16]).reassignGatewayRelay(gatewayKeyOld, jobId, signedDigest, sequenceId, jobRequestTimestamp, jobOwner, signTimestamp);
        await expect(tx).to.revertedWithCustomError(gatewayJobs, "GatewayJobsSignatureTooOld");
    });

    it("cannot reassign after relay time is over", async function () {
        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            gatewayKeyOld = addrs[15],
            sequenceId = 1,
            jobRequestTimestamp = await time.latest() + 10,
            jobOwner = addrs[1],
            signTimestamp = await time.latest();

        let signedDigest = await createReassignGatewaySignature(jobId, gatewayKeyOld, jobOwner, sequenceId, jobRequestTimestamp, signTimestamp, wallets[16]);

        await time.increase(1000);
        let tx = gatewayJobs.connect(signers[16]).reassignGatewayRelay(gatewayKeyOld, jobId, signedDigest, sequenceId, jobRequestTimestamp, jobOwner, signTimestamp);
        await expect(tx).to.revertedWithCustomError(gatewayJobs, "GatewayJobsRelayTimeOver");
    });

    it("cannot reassign new gateway if job is marked as ended due to unavailable executors", async function () {
        await executors.connect(signers[1]).drainExecutor(addrs[19]);
        await executors.connect(signers[1]).deregisterExecutor(addrs[19]);

        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobRequestTimestamp = await time.latest(),
            sequenceId = 1,
            jobOwner = addrs[1],
            env = 1,
            signTimestamp = await time.latest();
        let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);

        await expect(gatewayJobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp))
            .to.emit(gatewayJobs, "JobResourceUnavailable").withArgs(jobId, addrs[15]);

        let gatewayKeyOld = addrs[15];
        jobRequestTimestamp = await time.latest() + 10;
        signedDigest = await createReassignGatewaySignature(jobId, gatewayKeyOld, jobOwner, sequenceId, jobRequestTimestamp, signTimestamp, wallets[16]);

        // reassign new gateway
        await expect(gatewayJobs.connect(signers[1]).reassignGatewayRelay(gatewayKeyOld, jobId, signedDigest, sequenceId, jobRequestTimestamp, jobOwner, signTimestamp))
            .to.be.revertedWithCustomError(gatewayJobs, "GatewayJobsResourceUnavailable");
    });

    it("can reassign 2nd time if job still not relayed by previous reassigned gateway", async function () {
        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            gatewayKeyOld = addrs[15],
            sequenceId = 1,
            jobRequestTimestamp = await time.latest() + 100,
            jobOwner = addrs[3],
            signTimestamp = await time.latest();

        let signedDigest = await createReassignGatewaySignature(jobId, gatewayKeyOld, jobOwner, sequenceId, jobRequestTimestamp, signTimestamp, wallets[16]);
        let tx = await gatewayJobs.connect(signers[2]).reassignGatewayRelay(gatewayKeyOld, jobId, signedDigest, sequenceId, jobRequestTimestamp, jobOwner, signTimestamp);
        await expect(tx).to.emit(gatewayJobs, "GatewayReassigned");

        // Reassign 2nd time
        let jobOwnerInitialBal = await stakingToken.balanceOf(jobOwner);
        let reporterGatewayInitialBal = await stakingToken.balanceOf(addrs[2]);
        let failedGatewayStakedAmt = (await gateways.gateways(addrs[15])).stakeAmount;

        sequenceId = 2;
        signedDigest = await createReassignGatewaySignature(jobId, gatewayKeyOld, jobOwner, sequenceId, jobRequestTimestamp, signTimestamp, wallets[16]);
        tx = await gatewayJobs.connect(signers[2]).reassignGatewayRelay(gatewayKeyOld, jobId, signedDigest, sequenceId, jobRequestTimestamp, jobOwner, signTimestamp);
        await expect(tx).to.emit(gatewayJobs, "GatewayReassigned");

        let jobOwnerFinalBal = await stakingToken.balanceOf(jobOwner);
        let reporterGatewayFinalBal = await stakingToken.balanceOf(addrs[2]);
        let reassignCompForReporterGateway = await gatewayJobs.REASSIGN_COMP_FOR_REPORTER_GATEWAY();
        let slashedAmount = failedGatewayStakedAmt * await gateways.SLASH_PERCENT_IN_BIPS() / await gateways.SLASH_MAX_BIPS();

        expect(reporterGatewayFinalBal - reporterGatewayInitialBal).to.eq(reassignCompForReporterGateway);
        expect(jobOwnerFinalBal - jobOwnerInitialBal).to.eq(slashedAmount - reassignCompForReporterGateway);
    });

    it("cannot reassign 3rd time if job still not relayed by previously reassigned gateways", async function () {
        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            gatewayKeyOld = addrs[15],
            sequenceId = 1,
            jobRequestTimestamp = await time.latest() + 100,
            jobOwner = addrs[1],
            signTimestamp = await time.latest();

        let signedDigest = await createReassignGatewaySignature(jobId, gatewayKeyOld, jobOwner, sequenceId, jobRequestTimestamp, signTimestamp, wallets[16]);
        let tx = gatewayJobs.connect(signers[1]).reassignGatewayRelay(gatewayKeyOld, jobId, signedDigest, sequenceId, jobRequestTimestamp, jobOwner, signTimestamp);
        await expect(tx).to.emit(gatewayJobs, "GatewayReassigned");

        sequenceId = 2;
        signedDigest = await createReassignGatewaySignature(jobId, gatewayKeyOld, jobOwner, sequenceId, jobRequestTimestamp, signTimestamp, wallets[16]);
        tx = gatewayJobs.connect(signers[1]).reassignGatewayRelay(gatewayKeyOld, jobId, signedDigest, sequenceId, jobRequestTimestamp, jobOwner, signTimestamp);
        await expect(tx).to.emit(gatewayJobs, "GatewayReassigned");

        sequenceId = 3;
        signedDigest = await createReassignGatewaySignature(jobId, gatewayKeyOld, jobOwner, sequenceId, jobRequestTimestamp, signTimestamp, wallets[16]);
        tx = gatewayJobs.connect(signers[1]).reassignGatewayRelay(gatewayKeyOld, jobId, signedDigest, sequenceId, jobRequestTimestamp, jobOwner, signTimestamp);
        await expect(tx).to.be.revertedWithCustomError(gatewayJobs, "GatewayJobsInvalidRelaySequenceId");
    });

});

describe("GatewayJobs - oyster callback in GatewayJobs", function () {
    let signers: Signer[];
    let addrs: string[];
    let stakingToken: Pond;
    let usdcToken: USDCoin;
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let executors: Executors;
    let jobs: Jobs;
    let gateways: Gateways;
    let gatewayJobs: GatewayJobs;
    let stakingPaymentPool: string;
    let usdcPaymentPool: string;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));
        stakingPaymentPool = addrs[4];
        usdcPaymentPool = addrs[4];

        const Pond = await ethers.getContractFactory("Pond");
        stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        }) as unknown as Pond;

        const USDCoin = await ethers.getContractFactory("USDCoin");
        usdcToken = await upgrades.deployProxy(USDCoin, [addrs[0]], {
            kind: "uups",
        }) as unknown as USDCoin;

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        let admin = addrs[0],
            images = [image2, image3],
            maxAge = 600,
            deregisterOrUnstakeTimeout = 600,
            slashPercentInBips = 1,
            slashMaxBips = 100;
        const Gateways = await ethers.getContractFactory("Gateways");
        gateways = await upgrades.deployProxy(
            Gateways,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [attestationVerifier.target, maxAge, stakingToken.target, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        ) as unknown as Gateways;

        let executor_images = [image4, image5, image6, image7];
        const Executors = await ethers.getContractFactory("contracts/serverless-v2/Executors.sol:Executors");
        executors = await upgrades.deployProxy(
            Executors,
            [addrs[0], executor_images],
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
        ) as unknown as Executors;

        const Jobs = await ethers.getContractFactory("contracts/serverless-v2/Jobs.sol:Jobs");
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
                    usdcPaymentPool,
                    executors.target
                ]
            },
        ) as unknown as Jobs;

        let signMaxAge = 600,
            relayBufferTime = 100,
            slashCompForGateway = 10,
            reassignCompForReporterGateway = 100,
            stakingPaymentPoolAddress = addrs[1];
        const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
        gatewayJobs = await upgrades.deployProxy(
            GatewayJobs,
            [admin],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    stakingToken.target,
                    usdcToken.target,
                    signMaxAge,
                    relayBufferTime,
                    slashCompForGateway,
                    reassignCompForReporterGateway,
                    jobs.target,
                    gateways.target,
                    stakingPaymentPoolAddress
                ]
            },
        ) as unknown as GatewayJobs;

        // Grant role to jobs contract
        await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), jobs.target);

        let env = 1,
            executionFeePerMs = 1,
            stakingRewardPerMs = 1;
        await jobs.addGlobalEnv(env, executionFeePerMs, stakingRewardPerMs);

        let chainIds = [1];
        let reqChains = [
            {
                relayAddress: addrs[1],
                relaySubscriptionsAddress: addrs[2],
                httpRpcUrl: "https://eth.rpc",
                wsRpcUrl: "wss://eth.rpc"
            }
        ]
        await gateways.addChainGlobal(chainIds, reqChains);

        // Register Executors. Owner is addrs[1]
        let amount = 10n ** 20n;	// 100 POND
        await stakingToken.transfer(addrs[0], amount);
        await stakingToken.connect(signers[0]).approve(gateways.target, amount);
        await stakingToken.transfer(addrs[1], amount);
        await stakingToken.connect(signers[1]).approve(gateways.target, amount);
        await stakingToken.connect(signers[1]).approve(executors.target, amount);

        amount = parseUnits("1000", 6);	// 100 USDC
        await usdcToken.transfer(addrs[0], amount);
        await usdcToken.connect(signers[0]).approve(gatewayJobs.target, amount);

        let jobCapacity = 20, stakeAmount = 10n ** 19n;
        const timestamp = await time.latest() * 1000;

        // REGISTER GATEWAYS
        let signTimestamp = await time.latest();
        // 1st gateway
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);
        let signedDigest = await createGatewaySignature(addrs[0], chainIds, signTimestamp, wallets[15]);
        await gateways.connect(signers[0]).registerGateway(signature, attestation, chainIds, signedDigest, stakeAmount, signTimestamp);

        // 2nd gateway
        [signature, attestation] = await createAttestation(pubkeys[16], image3, wallets[14], timestamp - 540000);
        signedDigest = await createGatewaySignature(addrs[0], chainIds, signTimestamp, wallets[16]);
        await gateways.connect(signers[0]).registerGateway(signature, attestation, chainIds, signedDigest, stakeAmount, signTimestamp);

        // REGISTER EXECUTORS
        for (let index = 0; index < 3; index++) {
            let signTimestamp = await time.latest() - 540;
            // Executor index using wallet 17 + index as enclave address
            let [attestationSign, attestation] = await createAttestation(pubkeys[17 + index], executor_images[index], wallets[14], timestamp - 540000);
            let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, env, signTimestamp, wallets[17 + index]);
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

        // RELAY JOB
        let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
            codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
            codeInputs = solidityPacked(["string"], ["codeInput"]),
            deadline = 10000,
            jobRequestTimestamp = await time.latest(),
            sequenceId = 1,
            jobOwner = addrs[3];
        signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp, wallets[15]);
        await gatewayJobs.connect(signers[0]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, env, signTimestamp);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can call oysterResultCall on first output submit", async function () {
        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0,
            signTimestamp = await time.latest() - 540;

        let executorInitialBal = await usdcToken.balanceOf(addrs[1]);
        // let jobOwnerInitialBal = await usdcToken.balanceOf(gatewayJobs.target);

        let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
        let tx = jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );
        await expect(tx).to.emit(jobs, "JobResponded")
            .and.to.emit(jobs, "JobResultCallbackCalled").withArgs(jobId, true)
            .and.to.emit(gatewayJobs, "JobResponded");

        let executorFinalBal = await usdcToken.balanceOf(addrs[1]);
        // let jobOwnerFinalBal = await usdcToken.balanceOf(gatewayJobs.target);

        // check usdc balance of executor
        expect(executorFinalBal - executorInitialBal).to.eq(100n * 4n / 9n);
        // check usdc balance of payment pool
        expect(await usdcToken.balanceOf(usdcPaymentPool)).to.eq(100n);
        // // check usdc balance of job owner
        // expect(jobOwnerFinalBal - jobOwnerInitialBal).to.eq(100n*2n);
    });

    it("cannot call oysterResultCall on second output submit", async function () {
        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
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
        await expect(tx).to.emit(jobs, "JobResponded")
            .and.to.emit(jobs, "JobResultCallbackCalled").withArgs(jobId, true)
            .and.to.emit(gatewayJobs, "JobResponded");

        // submit 2nd ouput
        signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[18]);
        tx = jobs.connect(signers[1]).submitOutput(
            signedDigest,
            jobId,
            output,
            totalTime,
            errorCode,
            signTimestamp
        );
        await expect(tx).to.emit(jobs, "JobResponded")
            .and.to.not.emit(jobs, "JobResultCallbackCalled")
            .and.to.not.emit(gatewayJobs, "JobResponded");
    });

    it("can call oysterResultCall with any account having JOBS_ROLE", async function () {
        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 2000,
            errorCode = 0;

        await gatewayJobs.grantRole(await gatewayJobs.JOBS_ROLE(), addrs[0]);
        // as we haven't called submitOutput on Jobs contract, so USDC hasn't been transferred to GatewayJobs 
        await usdcToken.transfer(gatewayJobs.target, 1e5);

        await expect(gatewayJobs.oysterResultCall(jobId, output, errorCode, totalTime))
            .and.to.emit(gatewayJobs, "JobResponded");
    });

    it("cannot call oysterResultCall without Jobs contract", async function () {
        let jobId = 0,
            output = solidityPacked(["string"], ["it is the output"]),
            totalTime = 100,
            errorCode = 0;

        await expect(gatewayJobs.oysterResultCall(jobId, output, errorCode, totalTime))
            .to.be.revertedWithCustomError(gatewayJobs, "AccessControlUnauthorizedAccount");
    });

    it("can slash after deadline over", async function () {
        await time.increase(await time.latest() + 100000);
        let jobId = 0;
        let tx = jobs.slashOnExecutionTimeout(jobId);
        await expect(tx).to.emit(jobs, "SlashedOnExecutionTimeout").withArgs(jobId, addrs[17])
            .and.to.emit(jobs, "SlashedOnExecutionTimeout").withArgs(jobId, addrs[18])
            .and.to.emit(jobs, "SlashedOnExecutionTimeout").withArgs(jobId, addrs[19])
            .and.to.emit(jobs, "JobFailureCallbackCalled").withArgs(jobId, true)
            .and.to.emit(gatewayJobs, "JobFailed").withArgs((BigInt(1) << BigInt(192)) + BigInt(1));
        // check job does not exists
        let job = await jobs.jobs(jobId);
        expect(job.execStartTime).to.be.eq(0);
    });

    it("cannot call oysterFailureCall without Jobs contract", async function () {
        let jobId = 0,
            slashAmount = 0;

        await expect(gatewayJobs.oysterFailureCall(jobId, slashAmount))
            .to.be.revertedWithCustomError(gatewayJobs, "AccessControlUnauthorizedAccount");
    });

    it("can call oysterFailureCall with any account having JOBS_ROLE", async function () {
        let jobId = 0,
            slashAmount = 100;

        await usdcToken.transfer(gatewayJobs.target, 100000);
        await stakingToken.transfer(gatewayJobs.target, 100000);
        await gatewayJobs.grantRole(await gatewayJobs.JOBS_ROLE(), addrs[0]);

        await expect(gatewayJobs.oysterFailureCall(jobId, slashAmount))
            .and.to.emit(gatewayJobs, "JobFailed");
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

async function createGatewaySignature(
    owner: string,
    chainIds: number[],
    signTimestamp: number,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.Gateways',
        version: '1',
    };

    const types = {
        Register: [
            { name: 'owner', type: 'address' },
            { name: 'chainIds', type: 'uint256[]' },
            { name: 'signTimestamp', type: 'uint256' }
        ]
    };

    const value = {
        owner,
        chainIds,
        signTimestamp
    };

    const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
    return ethers.Signature.from(sign).serialized;
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

async function createRelayJobSignature(
    jobId: number,
    codeHash: string,
    codeInputs: string,
    deadline: number,
    jobRequestTimestamp: number,
    sequenceId: number,
    jobOwner: string,
    env: number,
    signTimestamp: number,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.GatewayJobs',
        version: '1',
    };

    const types = {
        RelayJob: [
            { name: 'jobId', type: 'uint256' },
            { name: 'codeHash', type: 'bytes32' },
            { name: 'codeInputs', type: 'bytes' },
            { name: 'deadline', type: 'uint256' },
            { name: 'jobRequestTimestamp', type: 'uint256' },
            { name: 'sequenceId', type: 'uint8' },
            { name: 'jobOwner', type: 'address' },
            { name: 'env', type: 'uint8' },
            { name: 'signTimestamp', type: 'uint256' },
        ]
    };

    const value = {
        jobId,
        codeHash,
        codeInputs,
        deadline,
        jobRequestTimestamp,
        sequenceId,
        jobOwner,
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

async function createReassignGatewaySignature(
    jobId: number,
    gatewayOld: string,
    jobOwner: string,
    sequenceId: number,
    jobRequestTimestamp: number,
    signTimestamp: number,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.GatewayJobs',
        version: '1',
    };

    const types = {
        ReassignGateway: [
            { name: 'jobId', type: 'uint256' },
            { name: 'gatewayOld', type: 'address' },
            { name: 'jobOwner', type: 'address' },
            { name: 'sequenceId', type: 'uint8' },
            { name: 'jobRequestTimestamp', type: 'uint256' },
            { name: 'signTimestamp', type: 'uint256' }
        ]
    };

    const value = {
        jobId,
        gatewayOld,
        jobOwner,
        sequenceId,
        jobRequestTimestamp,
        signTimestamp
    };

    const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
    return ethers.Signature.from(sign).serialized;
}

function walletForIndex(idx: number): Wallet {
    let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

    return new Wallet(wallet.privateKey);
}
