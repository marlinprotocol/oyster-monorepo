import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, Wallet, ZeroAddress, keccak256, parseUnits, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationAutherUpgradeable, AttestationVerifier, GatewayJobs, Gateways, Pond, USDCoin } from "../../typechain-types";
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

describe("Gateways - Init", function () {
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
        let maxAge = 600,
            deregisterOrUnstakeTimeout = 600,
            slashPercentInBips = 1,
            slashMaxBips = 100;
        const Gateways = await ethers.getContractFactory("Gateways");
        const gateways = await Gateways.deploy(
            attestationVerifier.target,
            maxAge,
            token,
            deregisterOrUnstakeTimeout,
            slashPercentInBips,
            slashMaxBips
        );

        expect(await gateways.ATTESTATION_VERIFIER()).to.equal(attestationVerifier.target);
        expect(await gateways.ATTESTATION_MAX_AGE()).to.equal(600);

        let admin = addrs[0],
            images: any = [];
        await expect(
            gateways.initialize(admin, images),
        ).to.be.revertedWithCustomError(gateways, "InvalidInitialization");

        images = [image1, image2];
        await expect(
            gateways.initialize(addrs[0], images),
        ).to.be.revertedWithCustomError(gateways, "InvalidInitialization");
    });

    it("deploys as proxy and initializes", async function () {
        let admin = addrs[0],
            images = [image1],
            maxAge = 600,
            deregisterOrUnstakeTimeout = 600,
            slashPercentInBips = 1,
            slashMaxBips = 100;
        const Gateways = await ethers.getContractFactory("Gateways");
        const gateways = await upgrades.deployProxy(
            Gateways,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [attestationVerifier.target, maxAge, token, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        );

        expect(await gateways.ATTESTATION_VERIFIER()).to.equal(attestationVerifier.target);
        expect(await gateways.ATTESTATION_MAX_AGE()).to.equal(600);

        expect(await gateways.hasRole(await gateways.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        {
            const { PCR0, PCR1, PCR2 } = await gateways.getWhitelistedImage(getImageId(image1));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
        }
    });

    it("cannot deploy with zero address as token", async function () {
        let admin = addrs[1],
            images = [image1],
            maxAge = 600,
            deregisterOrUnstakeTimeout = 600,
            slashPercentInBips = 1,
            slashMaxBips = 100;
        const Gateways = await ethers.getContractFactory("Gateways");
        await expect(upgrades.deployProxy(
            Gateways,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [attestationVerifier.target, maxAge, ZeroAddress, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        )).to.be.revertedWithCustomError(Gateways, "GatewaysZeroAddressToken");
    });

    it("cannot initialize with zero address as admin", async function () {
        let admin = ZeroAddress,
            images = [image1],
            maxAge = 600,
            deregisterOrUnstakeTimeout = 600,
            slashPercentInBips = 1,
            slashMaxBips = 100;
        const Gateways = await ethers.getContractFactory("Gateways");
        await expect(upgrades.deployProxy(
            Gateways,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [attestationVerifier.target, maxAge, token, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        )).to.be.revertedWithCustomError(Gateways, "GatewaysZeroAddressAdmin");
    });

    it("upgrades", async function () {
        let admin = addrs[0],
            images = [image1, image2, image3],
            maxAge = 600,
            deregisterOrUnstakeTimeout = 600,
            slashPercentInBips = 1,
            slashMaxBips = 100;
        const Gateways = await ethers.getContractFactory("Gateways");
        const gateways = await upgrades.deployProxy(
            Gateways,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [attestationVerifier.target, maxAge, token, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        );
        await upgrades.upgradeProxy(
            gateways.target,
            Gateways,
            {
                kind: "uups",
                constructorArgs: [attestationVerifier.target, maxAge, token, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            }
        );

        expect(await gateways.ATTESTATION_VERIFIER()).to.equal(attestationVerifier.target);
        expect(await gateways.ATTESTATION_MAX_AGE()).to.equal(600);

        expect(await gateways.hasRole(await gateways.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        {
            const { PCR0, PCR1, PCR2 } = await gateways.getWhitelistedImage(getImageId(image1));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
        }
        {
            const { PCR0, PCR1, PCR2 } = await gateways.getWhitelistedImage(getImageId(image2));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image2);
        }
        {
            const { PCR0, PCR1, PCR2 } = await gateways.getWhitelistedImage(getImageId(image3));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
        }
    });

    it("does not upgrade without admin", async function () {
        let admin = addrs[0],
            images = [image1, image2, image3],
            maxAge = 600,
            deregisterOrUnstakeTimeout = 600,
            slashPercentInBips = 1,
            slashMaxBips = 100;
        const Gateways = await ethers.getContractFactory("Gateways");
        const gateways = await upgrades.deployProxy(
            Gateways,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [attestationVerifier.target, maxAge, token, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        );

        await expect(
            upgrades.upgradeProxy(gateways.target, Gateways.connect(signers[1]), {
                kind: "uups",
                constructorArgs: [attestationVerifier.target, maxAge, token, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            }),
        ).to.be.revertedWithCustomError(gateways, "AccessControlUnauthorizedAccount");
    });

});

testERC165(
    "Gateways - ERC165",
    async function (_signers: Signer[], addrs: string[]) {
        let admin = addrs[0],
            images = [image1],
            attestationVerifier = addrs[1],
            token = addrs[1],
            maxAge = 600,
            deregisterOrUnstakeTimeout = 600,
            slashPercentInBips = 1,
            slashMaxBips = 100;
        const Gateways = await ethers.getContractFactory("Gateways");
        const gateways = await upgrades.deployProxy(
            Gateways,
            [admin, images],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [attestationVerifier, maxAge, token, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        );
        return gateways;
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

describe("Gateways - Whitelist/Revoke enclave", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let gateways: Gateways;

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
                constructorArgs: [attestationVerifier, maxAge, token, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        ) as unknown as Gateways;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can whitelist enclave image with admin account", async function () {
        await expect(gateways.connect(signers[0]).whitelistEnclaveImage(image1.PCR0, image1.PCR1, image1.PCR2))
            .to.emit(gateways, "EnclaveImageWhitelisted").withArgs(getImageId(image1), image1.PCR0, image1.PCR1, image1.PCR2);

        const { PCR0, PCR1, PCR2 } = await gateways.getWhitelistedImage(getImageId(image1));
        expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
    });

    it("cannot whitelist enclave image without admin account", async function () {
        await expect(gateways.connect(signers[1]).whitelistEnclaveImage(image1.PCR0, image1.PCR1, image1.PCR2))
            .to.be.revertedWithCustomError(gateways, "AccessControlUnauthorizedAccount");
    });

    it("can revoke enclave image with admin account", async function () {
        await expect(gateways.connect(signers[0]).revokeEnclaveImage(getImageId(image2)))
            .to.emit(gateways, "EnclaveImageRevoked").withArgs(getImageId(image2));

        const { PCR0 } = await gateways.getWhitelistedImage(getImageId(image2));
        expect(PCR0).to.equal("0x");
    });

    it("cannot revoke enclave image without admin account", async function () {
        await expect(gateways.connect(signers[1]).revokeEnclaveImage(getImageId(image2)))
            .to.be.revertedWithCustomError(gateways, "AccessControlUnauthorizedAccount");
    });
});

describe("Gateways - Verify", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let token: string;
    let gateways: Gateways;

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
                constructorArgs: [attestationVerifier.target, maxAge, token, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        ) as unknown as Gateways;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can verify enclave key", async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

        await expect(gateways.connect(signers[1]).verifyEnclaveKey(signature, attestation))
            .to.emit(gateways, "EnclaveKeyVerified").withArgs(addrs[15], getImageId(image3), pubkeys[15]);
        expect(await gateways.getVerifiedKey(addrs[15])).to.equal(getImageId(image3));
    });
});

describe("Gateways - Global chains", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let gateways: Gateways;

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
                constructorArgs: [attestationVerifier.target, maxAge, token.target, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        ) as unknown as Gateways;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can add global chain", async function () {
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

        let { relayAddress, relaySubscriptionsAddress, httpRpcUrl, wsRpcUrl } = await gateways.requestChains(1);
        expect({ relayAddress, relaySubscriptionsAddress, httpRpcUrl, wsRpcUrl }).to.deep.eq(reqChains[0]);
        expect(await gateways.isChainSupported(chainIds[0])).to.be.true;
    });

    it("cannot add global chain without admin", async function () {
        let chainIds = [1];
        let reqChains = [
            {
                relayAddress: addrs[1],
                relaySubscriptionsAddress: addrs[2],
                httpRpcUrl: "https://eth.rpc",
                wsRpcUrl: "wss://eth.rpc"
            }
        ]
        await expect(gateways.connect(signers[1]).addChainGlobal(chainIds, reqChains))
            .to.be.revertedWithCustomError(gateways, "AccessControlUnauthorizedAccount");
    });

    it("cannot execute add global chain with empty chain array", async function () {
        let chainIds: any = [];
        let reqChains: any = [];
        await expect(gateways.addChainGlobal(chainIds, reqChains))
            .to.be.revertedWithCustomError(gateways, "GatewaysInvalidLength");

        chainIds = [1];
        await expect(gateways.addChainGlobal(chainIds, reqChains))
            .to.be.revertedWithCustomError(gateways, "GatewaysInvalidLength");
    });

    it("cannot add already existing global chain again", async function () {
        let chainIds = [1, 1];
        let reqChains = [
            {
                relayAddress: addrs[1],
                relaySubscriptionsAddress: addrs[2],
                httpRpcUrl: "https://eth.rpc",
                wsRpcUrl: "wss://eth.rpc"
            },
            {
                relayAddress: addrs[3],
                relaySubscriptionsAddress: addrs[4],
                httpRpcUrl: "https://eth.rpc",
                wsRpcUrl: "wss://eth.rpc"
            }
        ]
        await expect(gateways.addChainGlobal(chainIds, reqChains))
            .to.be.revertedWithCustomError(gateways, "GatewaysGlobalChainAlreadyExists")
            .withArgs(1);
    });

    it("can remove global chain", async function () {
        let chainIds = [1];
        await gateways.removeChainGlobal(chainIds);

        let { relayAddress, relaySubscriptionsAddress, httpRpcUrl } = await gateways.requestChains(1);
        expect(relayAddress).to.be.eq(ZeroAddress);
        expect(relaySubscriptionsAddress).to.be.eq(ZeroAddress);
        expect(httpRpcUrl).to.be.eq("");
    });

    it("cannot remove global chain without admin", async function () {
        let chainIds = [1];
        await expect(gateways.connect(signers[1]).removeChainGlobal(chainIds))
            .to.be.revertedWithCustomError(gateways, "AccessControlUnauthorizedAccount");
    });

    it("cannot execute remove global chain with empty chain array", async function () {
        let chainIds: any = [];
        await expect(gateways.removeChainGlobal(chainIds))
            .to.be.revertedWithCustomError(gateways, "GatewaysInvalidLength");
    });

});

describe("Gateways - Add/Remove chains", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let gateways: Gateways;
    let reqChains: {
        relayAddress: string,
        relaySubscriptionsAddress: string,
        httpRpcUrl: string,
        wsRpcUrl: string
    }[];

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
                constructorArgs: [attestationVerifier.target, maxAge, token.target, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        ) as unknown as Gateways;

        let chainIds = [1, 56, 137];
        reqChains = [
            {
                relayAddress: addrs[1],
                relaySubscriptionsAddress: addrs[4],
                httpRpcUrl: "https://eth.rpc",
                wsRpcUrl: "wss://eth.rpc"
            },
            {
                relayAddress: addrs[2],
                relaySubscriptionsAddress: addrs[5],
                httpRpcUrl: "https://bsc.rpc",
                wsRpcUrl: "wss://bsc.rpc"
            },
            {
                relayAddress: addrs[3],
                relaySubscriptionsAddress: addrs[6],
                httpRpcUrl: "https://polygon.rpc",
                wsRpcUrl: "wss://polygon.rpc"
            }
        ]
        await gateways.addChainGlobal(chainIds, reqChains);

        await token.transfer(addrs[1], 100000);
        await token.connect(signers[1]).approve(gateways.target, 10000);

        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let signTimestamp = await time.latest(),
            stakeAmount = 10;
        let signedDigest = await createGatewaySignature(addrs[1], [1, 137], signTimestamp, wallets[15]);
        await gateways.connect(signers[1]).registerGateway(signature, attestation, [1, 137], signedDigest, stakeAmount, signTimestamp);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can add chains", async function () {
        let chainIds = [56],
            signTimestamp = await time.latest();
        let signedDigest = await createAddChainsSignature(chainIds, signTimestamp, wallets[15]);

        await expect(gateways.connect(signers[1]).addChains(signedDigest, chainIds, signTimestamp, addrs[15]))
            .to.emit(gateways, "ChainAdded").withArgs(addrs[15], 56);

        let gatewayChainIds = await gateways.getGatewayChainIds(addrs[15]);
        expect(gatewayChainIds.length).equals(3);
        expect(gatewayChainIds).contains(BigInt(56));
    });

    it("cannot add chains without gateway owner", async function () {
        let chainIds = [56],
            signTimestamp = await time.latest();
        let signedDigest = await createAddChainsSignature(chainIds, signTimestamp, wallets[15])
        await expect(gateways.addChains(signedDigest, chainIds, signTimestamp, addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysNotGatewayOwner");
    });

    it("cannot add chains with invalid signer", async function () {
        let chainIds = [56],
            signTimestamp = await time.latest();
        let signedDigest = await createAddChainsSignature(chainIds, signTimestamp, wallets[16])
        await expect(gateways.connect(signers[1]).addChains(signedDigest, chainIds, signTimestamp, addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysInvalidSigner");
    });

    it("cannot add chains with expired signature", async function () {
        let chainIds = [56],
            signTimestamp = await time.latest() - 700;
        let signedDigest = await createAddChainsSignature(chainIds, signTimestamp, wallets[15])
        await expect(gateways.connect(signers[1]).addChains(signedDigest, chainIds, signTimestamp, addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysSignatureTooOld");
    });

    it("cannot execute add chains with empty chain array", async function () {
        let chainIds: any = [],
            signTimestamp = await time.latest();
        let signedDigest = await createAddChainsSignature(chainIds, signTimestamp, wallets[15])
        await expect(gateways.connect(signers[1]).addChains(signedDigest, chainIds, signTimestamp, addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysEmptyRequestedChains");
    });

    it("cannot add chains that are not supported globally", async function () {
        let chainIds = [250],
            signTimestamp = await time.latest();
        let signedDigest = await createAddChainsSignature(chainIds, signTimestamp, wallets[15])
        await expect(gateways.connect(signers[1]).addChains(signedDigest, chainIds, signTimestamp, addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysUnsupportedChain");
    });

    it("cannot add chains that already exists", async function () {
        let chainIds = [1],
            signTimestamp = await time.latest();
        let signedDigest = await createAddChainsSignature(chainIds, signTimestamp, wallets[15])
        await expect(gateways.connect(signers[1]).addChains(signedDigest, chainIds, signTimestamp, addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysChainAlreadyExists").withArgs(1);
    });

    it("can remove chain", async function () {
        let chainIds = [1],
            signTimestamp = await time.latest();
        let signedDigest = await createRemoveChainsSignature(chainIds, signTimestamp, wallets[15])
        await expect(gateways.connect(signers[1]).removeChains(signedDigest, chainIds, signTimestamp, addrs[15]))
            .to.emit(gateways, "ChainRemoved").withArgs(addrs[15], 1);

        let gatewayChainIds = await gateways.getGatewayChainIds(addrs[15]);
        expect(gatewayChainIds.length).equals(1);
    });

    it("cannot remove chain without gateway owner", async function () {
        let chainIds = [1],
            signTimestamp = await time.latest();
        let signedDigest = await createRemoveChainsSignature(chainIds, signTimestamp, wallets[15])
        await expect(gateways.removeChains(signedDigest, chainIds, signTimestamp, addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysNotGatewayOwner");
    });

    it("cannot remove chain with invalid signer", async function () {
        let chainIds = [1],
            signTimestamp = await time.latest();
        let signedDigest = await createRemoveChainsSignature(chainIds, signTimestamp, wallets[16])
        await expect(gateways.connect(signers[1]).removeChains(signedDigest, chainIds, signTimestamp, addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysInvalidSigner");
    });

    it("cannot remove chain with expired signature", async function () {
        let chainIds = [1],
            signTimestamp = await time.latest() - 700;
        let signedDigest = await createRemoveChainsSignature(chainIds, signTimestamp, wallets[15])
        await expect(gateways.connect(signers[1]).removeChains(signedDigest, chainIds, signTimestamp, addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysSignatureTooOld");
    });

    it("cannot execute remove chains with empty chain array", async function () {
        let chainIds: any = [],
            signTimestamp = await time.latest();
        let signedDigest = await createRemoveChainsSignature(chainIds, signTimestamp, wallets[15])
        await expect(gateways.connect(signers[1]).removeChains(signedDigest, chainIds, signTimestamp, addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysEmptyRequestedChains");
    });

    it("cannot remove chain if no chain is added previously", async function () {
        let chainIds = [1, 137],
            signTimestamp = await time.latest();
        let signedDigest = await createRemoveChainsSignature(chainIds, signTimestamp, wallets[15]);
        await gateways.connect(signers[1]).removeChains(signedDigest, chainIds, signTimestamp, addrs[15]);

        await expect(gateways.connect(signers[1]).removeChains(signedDigest, chainIds, signTimestamp, addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysEmptyChainlist");
    });

    it("cannot remove chain that hasn't been added", async function () {
        let chainIds = [56],
            signTimestamp = await time.latest();
        let signedDigest = await createRemoveChainsSignature(chainIds, signTimestamp, wallets[15])
        await expect(gateways.connect(signers[1]).removeChains(signedDigest, chainIds, signTimestamp, addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysChainNotFound").withArgs(56);
    });

});

describe("Gateways - Draining gateway", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let gateways: Gateways;

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
                constructorArgs: [attestationVerifier.target, maxAge, token.target, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        ) as unknown as Gateways;

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

        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[15]);

        await gateways.connect(signers[1]).registerGateway(signature, attestation, chainIds, signedDigest, 0, signTimestamp);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it('can start draining gateway', async function () {
        await expect(gateways.connect(signers[1]).drainGateway(addrs[15]))
            .to.emit(gateways, "GatewayDrained").withArgs(addrs[15]);

        expect((await gateways.gateways(addrs[15])).draining).to.be.eq(true);
    });

    it('cannot drain without gateway owner', async function () {
        await expect(gateways.connect(signers[0]).drainGateway(addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysNotGatewayOwner");
    });

    it('cannot drain twice consecutively', async function () {
        await gateways.connect(signers[1]).drainGateway(addrs[15]);

        await expect(gateways.connect(signers[1]).drainGateway(addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysAlreadyDraining");
    });

    it('can revive gateway', async function () {
        await gateways.connect(signers[1]).drainGateway(addrs[15]);

        await expect(gateways.connect(signers[1]).reviveGateway(addrs[15]))
            .to.emit(gateways, "GatewayRevived").withArgs(addrs[15]);

        expect((await gateways.gateways(addrs[15])).draining).to.be.eq(false);
    });

    it('cannot revive without gateway owner', async function () {
        await expect(gateways.connect(signers[0]).reviveGateway(addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysNotGatewayOwner");
    });

    it('cannot revive when not draining', async function () {
        await gateways.connect(signers[1]).drainGateway(addrs[15]);
        await gateways.connect(signers[1]).reviveGateway(addrs[15]);

        await expect(gateways.connect(signers[1]).reviveGateway(addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysAlreadyRevived");
    });
});

describe("Gateways - Register gateway", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let gateways: Gateways;

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
                constructorArgs: [attestationVerifier.target, maxAge, token.target, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        ) as unknown as Gateways;

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

    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can register gateway", async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let chainIds = [1],
            signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[15]);

        await expect(gateways.connect(signers[1]).registerGateway(signature, attestation, [1], signedDigest, 0, signTimestamp))
            .to.emit(gateways, "EnclaveKeyVerified").withArgs(addrs[15], getImageId(image2), pubkeys[15]);
        expect(await gateways.getVerifiedKey(addrs[15])).to.equal(getImageId(image2));

    });

    it("cannot register gateway with invalid signer", async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let chainIds = [1],
            signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[16]);

        await expect(gateways.connect(signers[1]).registerGateway(signature, attestation, [1], signedDigest, 0, signTimestamp))
            .to.be.revertedWithCustomError(gateways, "GatewaysInvalidSigner");
    });

    it("cannot register gateway with expired signature", async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let chainIds = [1],
            signTimestamp = await time.latest() - 700;
        let signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[15]);

        await expect(gateways.connect(signers[1]).registerGateway(signature, attestation, [1], signedDigest, 0, signTimestamp))
            .to.be.revertedWithCustomError(gateways, "GatewaysSignatureTooOld");
    });

    it("cannot register gateway with same enclave key twice", async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let chainIds = [1],
            signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[15]);

        await gateways.connect(signers[1]).registerGateway(signature, attestation, [1], signedDigest, 0, signTimestamp);

        await expect(gateways.connect(signers[1]).registerGateway(signature, attestation, [1], signedDigest, 0, signTimestamp))
            .to.be.revertedWithCustomError(gateways, "GatewaysGatewayAlreadyExists");
    });

    it("cannot register gateway with chain id not added globally", async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let chainIds = [1, 2],
            signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[15]);

        await expect(gateways.connect(signers[1]).registerGateway(signature, attestation, chainIds, signedDigest, 0, signTimestamp))
            .to.be.revertedWithCustomError(gateways, "GatewaysUnsupportedChain");
    });

    it('cannot deregister gateway without draining', async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let chainIds = [1],
            signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[15]);

        await gateways.connect(signers[1]).registerGateway(signature, attestation, chainIds, signedDigest, 0, signTimestamp);

        await expect(gateways.connect(signers[1]).deregisterGateway(addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysNotDraining");
    });

    it('cannot deregister without gateway owner', async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let chainIds = [1],
            signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[15]);

        await gateways.connect(signers[1]).registerGateway(signature, attestation, chainIds, signedDigest, 0, signTimestamp);
        await gateways.connect(signers[1]).drainGateway(addrs[15]);

        await expect(gateways.connect(signers[0]).deregisterGateway(addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysNotGatewayOwner");
    });

    it('cannot deregister gateway before drain timeout', async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let chainIds = [1],
            signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[15]);

        await gateways.connect(signers[1]).registerGateway(signature, attestation, chainIds, signedDigest, 0, signTimestamp);
        await gateways.connect(signers[1]).drainGateway(addrs[15]);

        await expect(gateways.connect(signers[1]).deregisterGateway(addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysDrainPending");
    });

    it('can deregister gateway', async function () {
        await token.transfer(addrs[1], 100);
        await token.connect(signers[1]).approve(gateways.target, 100);

        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let chainIds = [1],
            signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[15]);

        let stakeAmount = 10;
        await gateways.connect(signers[1]).registerGateway(signature, attestation, chainIds, signedDigest, stakeAmount, signTimestamp);

        expect(await token.balanceOf(gateways.target)).to.be.eq(10);
        expect(await token.balanceOf(addrs[1])).to.be.eq(90);

        await gateways.connect(signers[1]).drainGateway(addrs[15]);

        await time.increase(700);
        await expect(gateways.connect(signers[1]).deregisterGateway(addrs[15]))
            .to.emit(gateways, "GatewayDeregistered").withArgs(addrs[15]);

        let gateway = await gateways.gateways(addrs[15]);
        expect(gateway.owner).to.be.eq(ZeroAddress);
        expect(await token.balanceOf(gateways.target)).to.be.eq(0);
        expect(await token.balanceOf(addrs[1])).to.be.eq(100);
    });

    it('cannot deregister without gateway owner', async function () {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let chainIds = [1],
            signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[15]);

        await gateways.connect(signers[1]).registerGateway(signature, attestation, chainIds, signedDigest, 0, signTimestamp);

        await gateways.connect(signers[1]).drainGateway(addrs[15]);

        await time.increase(700);
        await expect(gateways.connect(signers[0]).deregisterGateway(addrs[15]))
            .to.be.revertedWithCustomError(gateways, "GatewaysNotGatewayOwner");
    });

});

describe("Gateways - Staking", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let gateways: Gateways;

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
                constructorArgs: [attestationVerifier.target, maxAge, token.target, deregisterOrUnstakeTimeout, slashPercentInBips, slashMaxBips]
            },
        ) as unknown as Gateways;

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

        await token.transfer(addrs[1], 100000);
        await token.connect(signers[1]).approve(gateways.target, 10000);

        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

        let stakeAmount = 10,
            signTimestamp = await time.latest();
        let signedDigest = await createGatewaySignature(addrs[1], chainIds, signTimestamp, wallets[15]);

        await gateways.connect(signers[1]).registerGateway(signature, attestation, [1], signedDigest, stakeAmount, signTimestamp);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("cannot stake without gateway owner", async function () {
        let amount = 20;
        await expect(gateways.connect(signers[0]).addGatewayStake(addrs[15], amount))
            .to.be.revertedWithCustomError(gateways, "GatewaysNotGatewayOwner");
    });

    it("can stake", async function () {
        let amount = 20;
        await expect(gateways.connect(signers[1]).addGatewayStake(addrs[15], amount))
            .to.emit(gateways, "GatewayStakeAdded");

        let executor = await gateways.gateways(addrs[15]);
        expect(executor.stakeAmount).to.be.eq(30);
    });

    it("cannot unstake without gateway owner", async function () {
        await expect(gateways.connect(signers[0]).removeGatewayStake(addrs[15], 10))
            .to.be.revertedWithCustomError(gateways, "GatewaysNotGatewayOwner");
    });

    it("cannot unstake without draining", async function () {
        await expect(gateways.connect(signers[1]).removeGatewayStake(addrs[15], 10))
            .to.be.revertedWithCustomError(gateways, "GatewaysNotDraining");
    });

    it("cannot complete unstake before timeout", async function () {
        await gateways.connect(signers[1]).drainGateway(addrs[15]);

        await expect(gateways.connect(signers[1]).removeGatewayStake(addrs[15], 10))
            .to.be.revertedWithCustomError(gateways, "GatewaysDrainPending");
    });

    it("can complete unstake", async function () {
        await gateways.connect(signers[1]).drainGateway(addrs[15]);

        await time.increase(700);
        await expect(gateways.connect(signers[1]).removeGatewayStake(addrs[15], 5))
            .to.emit(gateways, "GatewayStakeRemoved");

        let gateway = await gateways.gateways(addrs[15]);
        expect(gateway.stakeAmount).to.be.eq(5);
        expect(await token.balanceOf(gateways.target)).to.be.eq(5);
        expect(await token.balanceOf(addrs[1])).to.be.eq(99995);
    });

});

describe("Gateways - Slash on reassign gateway", function () {
    let signers: Signer[];
    let addrs: string[];
    let stakingToken: Pond;
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let gateways: Gateways;
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
        let usdcToken = await upgrades.deployProxy(
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

        let relayBufferTime = 100,
            slashCompForGateway = 10,
            signMaxAge = 600,
            jobs = addrs[1],
            stakingPaymentPoolAddress = addrs[4];
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
                    jobs,
                    gateways.target,
                    stakingPaymentPoolAddress
                ]
            },
        ) as unknown as GatewayJobs;

        await gateways.grantRole(await gateways.GATEWAY_JOBS_ROLE(), gatewayJobs.target);

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
        let tx = await gatewayJobs.reassignGatewayRelay(gatewayKeyOld, jobId, signedDigest, sequenceId, jobRequestTimestamp, jobOwner, signTimestamp);
        await expect(tx).to.emit(gatewayJobs, "GatewayReassigned");

        let stakingPoolFinalBal = await stakingToken.balanceOf(addrs[4]);
        let reporterGatewayFinalBal = await stakingToken.balanceOf(addrs[2]);
        let reassignCompForReporterGateway = await gatewayJobs.REASSIGN_COMP_FOR_REPORTER_GATEWAY();
        let slashedAmount = failedGatewayStakedAmt * await gateways.SLASH_PERCENT_IN_BIPS() / await gateways.SLASH_MAX_BIPS();

        expect(reporterGatewayFinalBal - reporterGatewayInitialBal).to.eq(reassignCompForReporterGateway);
        expect(stakingPoolFinalBal - stakingPoolInitialBal).to.eq(slashedAmount - reassignCompForReporterGateway);
    });

    it("cannot reassign if not called by GatewayJobs contract", async function () {
        let gatewayKeyOld = addrs[15];

        let tx = gateways.slashOnReassignGateway(gatewayKeyOld);
        await expect(tx).to.be.revertedWithCustomError(gatewayJobs, "AccessControlUnauthorizedAccount");
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

async function createAddChainsSignature(
    chainIds: number[],
    signTimestamp: number,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.Gateways',
        version: '1',
    };

    const types = {
        AddChains: [
            { name: 'chainIds', type: 'uint256[]' },
            { name: 'signTimestamp', type: 'uint256' }
        ]
    };

    const value = {
        chainIds,
        signTimestamp
    };

    const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
    return ethers.Signature.from(sign).serialized;
}

async function createRemoveChainsSignature(
    chainIds: number[],
    signTimestamp: number,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.Gateways',
        version: '1',
    };

    const types = {
        RemoveChains: [
            { name: 'chainIds', type: 'uint256[]' },
            { name: 'signTimestamp', type: 'uint256' }
        ]
    };

    const value = {
        chainIds,
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
