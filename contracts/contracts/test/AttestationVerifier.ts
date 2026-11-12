import { expect } from "chai";
import { BytesLike, Signer, Wallet } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationVerifier } from "../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../utils/testSuite";
import { keccak256, solidityPacked } from "ethers";
import { testERC165 } from "./helpers/erc165";
import { testAdminRole } from "./helpers/rbac";
import { time } from '@nomicfoundation/hardhat-network-helpers';

const image1: string = ethers.hexlify(ethers.randomBytes(32));
const image2: string = ethers.hexlify(ethers.randomBytes(32));
const image3: string = ethers.hexlify(ethers.randomBytes(32));

describe("AttestationVerifier - Init", function() {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("deploys with initialization disabled", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifier = await AttestationVerifier.deploy();

        await expect(
            attestationVerifier.initialize([], [], addrs[0]),
        ).to.be.revertedWithCustomError(attestationVerifier, "InvalidInitialization");

        await expect(
            attestationVerifier.initialize([image1, image2], [pubkeys[13], pubkeys[14]], addrs[0]),
        ).to.be.revertedWithCustomError(attestationVerifier, "InvalidInitialization");
    });

    it("deploys as proxy and initializes", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[13]], addrs[0]],
            { kind: "uups" },
        );

        expect(await attestationVerifier.hasRole(await attestationVerifier.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        expect(await attestationVerifier.verifiedKeys(addrs[13])).to.equal(image1);
        expect(await attestationVerifier.whitelistedImages(image1)).to.be.true;
    });

    it("deploys as proxy and initializes with multiple images", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2, image3], [pubkeys[13], pubkeys[14], pubkeys[15]], addrs[0]],
            { kind: "uups" },
        );

        expect(await attestationVerifier.hasRole(await attestationVerifier.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        expect(await attestationVerifier.verifiedKeys(addrs[13])).to.equal(image1);
        expect(await attestationVerifier.whitelistedImages(image1)).to.be.true;
        expect(await attestationVerifier.verifiedKeys(addrs[14])).to.equal(image2);
        expect(await attestationVerifier.whitelistedImages(image2)).to.be.true;
        expect(await attestationVerifier.verifiedKeys(addrs[15])).to.equal(image3);
        expect(await attestationVerifier.whitelistedImages(image3)).to.be.true;
    });

    it("cannot initialize with mismatched lengths", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        await expect(
            upgrades.deployProxy(
                AttestationVerifier,
                [[image1, image2], [pubkeys[13], pubkeys[14], pubkeys[15]], addrs[0]],
                { kind: "uups" },
            )
        ).to.be.revertedWithCustomError(AttestationVerifier, "AttestationVerifierInitLengthMismatch");
        await expect(
            upgrades.deployProxy(
                AttestationVerifier,
                [[image1, image2, image3], [pubkeys[13], pubkeys[14]], addrs[0]],
                { kind: "uups" },
            )
        ).to.be.revertedWithCustomError(AttestationVerifier, "AttestationVerifierInitLengthMismatch");
    });

    it("cannot initialize with no whitelisted images", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        await expect(
            upgrades.deployProxy(
                AttestationVerifier,
                [[], [], addrs[0]],
                { kind: "uups" },
            )
        ).to.be.revertedWithCustomError(AttestationVerifier, "AttestationVerifierNoImageProvided");
    });

    it("cannot initialize with zero address as admin", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        await expect(
            upgrades.deployProxy(
                AttestationVerifier,
                [[image1, image2, image3], [pubkeys[13], pubkeys[14], pubkeys[15]], ethers.ZeroAddress],
                { kind: "uups" },
            )
        ).to.be.revertedWithCustomError(AttestationVerifier, "AttestationVerifierInvalidAdmin");
    });

    it("upgrades", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2, image3], [pubkeys[13], pubkeys[14], pubkeys[15]], addrs[0]],
            { kind: "uups" },
        );
        await upgrades.upgradeProxy(await attestationVerifier.getAddress(), AttestationVerifier, { kind: "uups" });

        expect(await attestationVerifier.hasRole(await attestationVerifier.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        expect(await attestationVerifier.verifiedKeys(addrs[13])).to.equal(image1);
        expect(await attestationVerifier.whitelistedImages(image1)).to.be.true;
        expect(await attestationVerifier.verifiedKeys(addrs[14])).to.equal(image2);
        expect(await attestationVerifier.whitelistedImages(image2)).to.be.true;
        expect(await attestationVerifier.verifiedKeys(addrs[15])).to.equal(image3);
        expect(await attestationVerifier.whitelistedImages(image3)).to.be.true;
    });

    it("does not upgrade without admin", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2, image3], [pubkeys[13], pubkeys[14], pubkeys[15]], addrs[0]],
            { kind: "uups" },
        );

        await expect(
            upgrades.upgradeProxy(await attestationVerifier.getAddress(), AttestationVerifier.connect(signers[1]), {
                kind: "uups",
            }),
        ).to.be.revertedWithCustomError(attestationVerifier, "AccessControlUnauthorizedAccount");
    });
});

testERC165(
    "AttestationVerifier - ERC165",
    async function(signers: Signer[], addrs: string[]) {
        let wallets = signers.map((_, idx) => walletForIndex(idx));
        let pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey))
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2, image3], [pubkeys[13], pubkeys[14], pubkeys[15]], addrs[0]],
            { kind: "uups" },
        );
        return attestationVerifier;
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

testAdminRole("AttestationVerifier - Admin", async function(signers: Signer[], addrs: string[]) {
    let wallets = signers.map((_, idx) => walletForIndex(idx));
    let pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey))
    const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
    const attestationVerifier = await upgrades.deployProxy(
        AttestationVerifier,
        [[image1, image2, image3], [pubkeys[13], pubkeys[14], pubkeys[15]], addrs[0]],
        { kind: "uups" },
    );
    return attestationVerifier;
});

describe("AttestationVerifier - Whitelist enclave image", function() {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];

    let attestationVerifier: AttestationVerifier;

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey))

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2], [pubkeys[13], pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("non admin cannot whitelist enclave image", async function() {
        await expect(attestationVerifier.connect(signers[1]).whitelistEnclaveImage(image3)).to.be.revertedWithCustomError(attestationVerifier, "AccessControlUnauthorizedAccount");
    });

    it("admin can whitelist enclave image", async function() {
        expect(await attestationVerifier.whitelistedImages(image3)).to.be.false;

        expect(await attestationVerifier.whitelistEnclaveImage.staticCall(image3)).to.equal(true);
        await expect(attestationVerifier.whitelistEnclaveImage(image3))
            .to.emit(attestationVerifier, "EnclaveImageWhitelisted").withArgs(image3);
        expect(await attestationVerifier.whitelistedImages(image3)).to.be.true;
    });



    it("admin can rewhitelist enclave image", async function() {
        expect(await attestationVerifier.whitelistEnclaveImage.staticCall(image3)).to.equal(true);
        await expect(attestationVerifier.whitelistEnclaveImage(image3))
            .to.emit(attestationVerifier, "EnclaveImageWhitelisted").withArgs(image3);
        expect(await attestationVerifier.whitelistedImages(image3)).to.be.true;

        expect(await attestationVerifier.whitelistEnclaveImage.staticCall(image3)).to.equal(false);
        await expect(attestationVerifier.whitelistEnclaveImage(image3))
            .to.not.emit(attestationVerifier, "EnclaveImageWhitelisted");
    });
});

describe("AttestationVerifier - Revoke enclave image", function() {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];

    let attestationVerifier: AttestationVerifier;

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey))

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2], [pubkeys[13], pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("non admin cannot revoke enclave image", async function() {
        await expect(attestationVerifier.connect(signers[1]).revokeEnclaveImage(image1)).to.be.revertedWithCustomError(attestationVerifier, "AccessControlUnauthorizedAccount");
    });

    it("admin can revoke enclave image", async function() {
        expect(await attestationVerifier.whitelistedImages(image1)).to.be.true;

        expect(await attestationVerifier.revokeEnclaveImage.staticCall(image1)).to.be.true;
        await expect(attestationVerifier.revokeEnclaveImage(image1))
            .to.emit(attestationVerifier, "EnclaveImageRevoked").withArgs(image1);
        expect(await attestationVerifier.whitelistedImages(image1)).to.be.false;
    });

    it("admin can revoke unwhitelisted enclave image", async function() {
        expect(await attestationVerifier.revokeEnclaveImage.staticCall(image3)).to.be.false;
        await expect(attestationVerifier.revokeEnclaveImage(image3))
            .to.not.emit(attestationVerifier, "EnclaveImageRevoked");
    });
});

describe("AttestationVerifier - Whitelist enclave key", function() {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];

    let attestationVerifier: AttestationVerifier;

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey))

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2], [pubkeys[13], pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("non admin cannot whitelist enclave key", async function() {
        await expect(attestationVerifier.connect(signers[1]).whitelistEnclaveKey(pubkeys[15], image1)).to.be.revertedWithCustomError(attestationVerifier, "AccessControlUnauthorizedAccount");
    });

    it("admin can whitelist enclave key", async function() {
        expect(await attestationVerifier.verifiedKeys(addrs[15])).to.equal(ethers.ZeroHash);

        expect(await attestationVerifier.whitelistEnclaveKey.staticCall(pubkeys[15], image1)).to.be.true;
        await expect(attestationVerifier.whitelistEnclaveKey(pubkeys[15], image1))
            .to.emit(attestationVerifier, "EnclaveKeyWhitelisted").withArgs(addrs[15], image1, pubkeys[15]);
        expect(await attestationVerifier.verifiedKeys(addrs[15])).to.equal(image1);
    });

    it("admin cannot whitelist enclave key with unwhitelisted enclave image", async function() {
        await expect(attestationVerifier.whitelistEnclaveKey(pubkeys[15], image3)).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierImageNotWhitelisted");
    });

    it("admin can rewhitelist enclave key", async function() {
        expect(await attestationVerifier.verifiedKeys(addrs[15])).to.equal(ethers.ZeroHash);

        expect(await attestationVerifier.whitelistEnclaveKey.staticCall(pubkeys[15], image1)).to.be.true;
        await expect(attestationVerifier.whitelistEnclaveKey(pubkeys[15], image1))
            .to.emit(attestationVerifier, "EnclaveKeyWhitelisted").withArgs(addrs[15], image1, pubkeys[15]);
        expect(await attestationVerifier.verifiedKeys(addrs[15])).to.equal(image1);

        expect(await attestationVerifier.whitelistEnclaveKey.staticCall(pubkeys[15], image1)).to.be.false;
        await expect(attestationVerifier.whitelistEnclaveKey(pubkeys[15], image1))
            .to.not.emit(attestationVerifier, "EnclaveKeyWhitelisted");
    });
});

describe("AttestationVerifier - Revoke enclave key", function() {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];

    let attestationVerifier: AttestationVerifier;

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey))

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2], [pubkeys[13], pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("non admin cannot revoke enclave key", async function() {
        await expect(attestationVerifier.connect(signers[1]).revokeEnclaveKey(addrs[14])).to.be.revertedWithCustomError(attestationVerifier, "AccessControlUnauthorizedAccount");
    });

    it("admin can revoke enclave key", async function() {
        expect(await attestationVerifier.verifiedKeys(addrs[14])).to.equal(image2);

        expect(await attestationVerifier.revokeEnclaveKey.staticCall(addrs[14])).to.be.true;
        await expect(attestationVerifier.revokeEnclaveKey(addrs[14]))
            .to.emit(attestationVerifier, "EnclaveKeyRevoked").withArgs(addrs[14]);
        expect(await attestationVerifier.verifiedKeys(addrs[14])).to.equal(ethers.ZeroHash);
    });

    it("admin cannot revoke unwhitelisted enclave key", async function() {
        expect(await attestationVerifier.revokeEnclaveKey.staticCall(addrs[15])).to.be.false;
        await expect(attestationVerifier.revokeEnclaveKey(addrs[15]))
            .to.not.emit(attestationVerifier, "EnclaveKeyRevoked");
    });
});

describe("AttestationVerifier - Verify enclave key", function() {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];

    let attestationVerifier: AttestationVerifier;

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey))

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2], [pubkeys[13], pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can verify enclave key", async function() {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image1, wallets[14], timestamp - 240000);

        expect(await attestationVerifier.connect(signers[1]).verifyEnclaveKey.staticCall(signature, attestation)).to.be.true;
        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(signature, attestation))
            .to.emit(attestationVerifier, "EnclaveKeyVerified").withArgs(addrs[15], image1, pubkeys[15]);
        expect(await attestationVerifier.verifiedKeys(addrs[15])).to.equal(image1);
    });

    it("cannot verify enclave key with too old attestation", async function() {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image1, wallets[14], timestamp - 360000);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(signature, attestation))
            .to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierAttestationTooOld");
    });

    it("cannot verify enclave key with invalid data", async function() {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image1, wallets[14], timestamp - 240000);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, publicKey: pubkeys[16] }))
            .to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, imageId: image3 }))
            .to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierImageNotWhitelisted");
        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, userData: "0x1234" }))
            .to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, imageId: image2 }))
            .to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, timestampMs: timestamp - 200000 }))
            .to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
    });

    it("cannot verify enclave key with invalid public key", async function() {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(ethers.ZeroAddress, image1, wallets[14], timestamp - 240000);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(signature, attestation))
            .to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierPubkeyLengthInvalid");
    });

    it("cannot verify enclave key with unwhitelisted enclave image", async function() {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 240000);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(signature, attestation))
            .to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierImageNotWhitelisted");
    });

    it("can reverify enclave key", async function() {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image1, wallets[14], timestamp - 240000);

        expect(await attestationVerifier.connect(signers[1]).verifyEnclaveKey.staticCall(signature, attestation)).to.be.true;
        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(signature, attestation))
            .to.emit(attestationVerifier, "EnclaveKeyVerified").withArgs(addrs[15], image1, pubkeys[15]);
        expect(await attestationVerifier.verifiedKeys(addrs[15])).to.equal(image1);

        expect(await attestationVerifier.connect(signers[1]).verifyEnclaveKey.staticCall(signature, attestation)).to.be.false;
        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(signature, attestation))
            .to.not.emit(attestationVerifier, "EnclaveKeyVerified");
    });

    it("cannot verify enclave key with unwhitelisted enclave key", async function() {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image1, wallets[16], timestamp - 240000);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(signature, attestation))
            .to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
    });

    it("cannot verify enclave key with revoked enclave key", async function() {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image1, wallets[14], timestamp - 240000);

        await attestationVerifier.revokeEnclaveKey(addrs[14]);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(signature, attestation))
            .to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
    });

    it("cannot verify enclave key with revoked enclave image", async function() {
        const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image1, wallets[14], timestamp - 240000);

        await attestationVerifier.revokeEnclaveImage(image2);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(signature, attestation))
            .to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierImageNotWhitelisted");
    });
});

describe("AttestationVerifier - Verify with params", function() {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];

    let attestationVerifier: AttestationVerifier;

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey))

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2], [pubkeys[13], pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can verify", async function() {
        let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], 300000);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes,(bytes32,uint64,bytes,bytes))'](
            signature, attestation,
        )).to.not.be.reverted;
    });

    it("cannot verify with invalid data", async function() {
        let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], 300000);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes,(bytes32,uint64,bytes,bytes))'](
            signature, { ...attestation, publicKey: pubkeys[16] },
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes,(bytes32,uint64,bytes,bytes))'](
            signature, { ...attestation, imageId: image1 },
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes,(bytes32,uint64,bytes,bytes))'](
            signature, { ...attestation, userData: "0x1234" },
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes,(bytes32,uint64,bytes,bytes))'](
            signature, { ...attestation, imageId: image2 },
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes,(bytes32,uint64,bytes,bytes))'](
            signature, { ...attestation, timestampMs: 200000 },
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
    });

    it("cannot verify with unwhitelisted enclave key", async function() {
        let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[16], 300000);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes,(bytes32,uint64,bytes,bytes))'](
            signature, attestation,
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
    });

    it("cannot verify with revoked enclave key", async function() {
        let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], 300000);

        await attestationVerifier.revokeEnclaveKey(addrs[14]);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes,(bytes32,uint64,bytes,bytes))'](
            signature, attestation,
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
    });

    it("cannot verify with revoked enclave image", async function() {
        let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], 300000);

        await attestationVerifier.revokeEnclaveImage(image2);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes,(bytes32,uint64,bytes,bytes))'](
            signature, attestation,
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierImageNotWhitelisted");
    });
});

describe("AttestationVerifier - Verify with bytes", function() {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];

    let attestationVerifier: AttestationVerifier;

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey))

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2], [pubkeys[13], pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can verify", async function() {
        let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], 300000);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.AbiCoder.defaultAbiCoder().encode(
                ["bytes", "(bytes32,uint64,bytes,bytes)"],
                [signature, Object.values(attestation)],
            ),
        )).to.not.be.reverted;
    });

    it("cannot verify with invalid data", async function() {
        let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], 300000);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.AbiCoder.defaultAbiCoder().encode(
                ["bytes", "(bytes32,uint64,bytes,bytes)"],
                [signature, Object.values({ ...attestation, publicKey: pubkeys[16] })],
            ),
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.AbiCoder.defaultAbiCoder().encode(
                ["bytes", "(bytes32,uint64,bytes,bytes)"],
                [signature, Object.values({ ...attestation, imageId: image1 })],
            ),
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.AbiCoder.defaultAbiCoder().encode(
                ["bytes", "(bytes32,uint64,bytes,bytes)"],
                [signature, Object.values({ ...attestation, userData: "0x1234" })],
            ),
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.AbiCoder.defaultAbiCoder().encode(
                ["bytes", "(bytes32,uint64,bytes,bytes)"],
                [signature, Object.values({ ...attestation, imageId: image2 })],
            ),
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.AbiCoder.defaultAbiCoder().encode(
                ["bytes", "(bytes32,uint64,bytes,bytes)"],
                [signature, Object.values({ ...attestation, timestampMs: 200000 })],
            ),
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
    });

    it("cannot verify with unwhitelisted enclave key", async function() {
        let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[16], 300000);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.AbiCoder.defaultAbiCoder().encode(
                ["bytes", "(bytes32,uint64,bytes,bytes)"],
                [signature, Object.values(attestation)],
            ),
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
    });

    it("cannot verify with revoked enclave key", async function() {
        let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], 300000);

        await attestationVerifier.revokeEnclaveKey(addrs[14]);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.AbiCoder.defaultAbiCoder().encode(
                ["bytes", "(bytes32,uint64,bytes,bytes)"],
                [signature, Object.values(attestation)],
            ),
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
    });

    it("cannot verify with revoked enclave image", async function() {
        let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], 300000);

        await attestationVerifier.revokeEnclaveImage(image2);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.AbiCoder.defaultAbiCoder().encode(
                ["bytes", "(bytes32,uint64,bytes,bytes)"],
                [signature, Object.values(attestation)],
            ),
        )).to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierImageNotWhitelisted");
    });
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

function walletForIndex(idx: number): Wallet {
    let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

    return new Wallet(wallet.privateKey);
}
