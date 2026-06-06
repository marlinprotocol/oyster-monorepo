import { expect } from "chai";
import { Signer, Wallet, BigNumber as BN } from "ethers";
import { ethers, network, upgrades } from "hardhat";
import { AttestationVerifier } from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { keccak256, parseUnits, solidityPack } from "ethers/lib/utils";
import { testERC165 } from "../helpers/erc165";
import { testAdminRole } from "../helpers/rbac";
import { getAttestationVerifier } from "../../utils/typechainConvertor";
import { time } from '@nomicfoundation/hardhat-network-helpers';

const image1: AttestationVerifier.EnclaveImageStruct = {
    PCR0: parseUnits("1", 115).toHexString(),
    PCR1: parseUnits("2", 114).toHexString(),
    PCR2: parseUnits("3", 114).toHexString(),
};

const image2: AttestationVerifier.EnclaveImageStruct = {
    PCR0: parseUnits("4", 114).toHexString(),
    PCR1: parseUnits("5", 114).toHexString(),
    PCR2: parseUnits("6", 114).toHexString(),
};

const image3: AttestationVerifier.EnclaveImageStruct = {
    PCR0: parseUnits("7", 114).toHexString(),
    PCR1: parseUnits("8", 114).toHexString(),
    PCR2: parseUnits("9", 114).toHexString(),
};

const ATTESTATION_PREFIX = "Enclave Attestation Verified";

describe("AttestationVerifier - Init", function() {
    let signers: Signer[];
    let addrs: string[];

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("deploys with initialization disabled", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifier = await AttestationVerifier.deploy();

        await expect(
            attestationVerifier.initialize([], [], addrs[0]),
        ).to.be.revertedWith("Initializable: contract is already initialized");

        await expect(
            attestationVerifier.initialize([image1, image2], [addrs[13], addrs[14]], addrs[0]),
        ).to.be.revertedWith("Initializable: contract is already initialized");
    });

    it("deploys as proxy and initializes", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [addrs[13]], addrs[0]],
            { kind: "uups" },
        );

        expect(await attestationVerifier.hasRole(await attestationVerifier.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        expect(await attestationVerifier.getRoleMemberCount(await attestationVerifier.DEFAULT_ADMIN_ROLE())).to.equal(1);
        expect(await attestationVerifier.isVerified(addrs[13])).to.equal(getImageId(image1));
        {
            const { PCR0, PCR1, PCR2 } = await attestationVerifier.whitelistedImages(getImageId(image1));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
        }
    });

    it("deploys as proxy and initializes with multiple images", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2, image3], [addrs[13], addrs[14], addrs[15]], addrs[0]],
            { kind: "uups" },
        );

        expect(await attestationVerifier.hasRole(await attestationVerifier.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        expect(await attestationVerifier.getRoleMemberCount(await attestationVerifier.DEFAULT_ADMIN_ROLE())).to.equal(1);
        expect(await attestationVerifier.isVerified(addrs[13])).to.equal(getImageId(image1));
        {
            const { PCR0, PCR1, PCR2 } = await attestationVerifier.whitelistedImages(getImageId(image1));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
        }
        expect(await attestationVerifier.isVerified(addrs[14])).to.equal(getImageId(image2));
        {
            const { PCR0, PCR1, PCR2 } = await attestationVerifier.whitelistedImages(getImageId(image2));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image2);
        }
        expect(await attestationVerifier.isVerified(addrs[15])).to.equal(getImageId(image3));
        {
            const { PCR0, PCR1, PCR2 } = await attestationVerifier.whitelistedImages(getImageId(image3));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
        }
    });

    it("cannot initialize with mismatched lengths", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        await expect(
            upgrades.deployProxy(
                AttestationVerifier,
                [[image1, image2], [addrs[13], addrs[14], addrs[15]], addrs[0]],
                { kind: "uups" },
            )
        ).to.be.revertedWith("AV:I-Image and key length mismatch");
        await expect(
            upgrades.deployProxy(
                AttestationVerifier,
                [[image1, image2, image3], [addrs[13], addrs[14]], addrs[0]],
                { kind: "uups" },
            )
        ).to.be.revertedWith("AV:I-Image and key length mismatch");
    });

    it("cannot initialize with no whitelisted images", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        await expect(
            upgrades.deployProxy(
                AttestationVerifier,
                [[], [], addrs[0]],
                { kind: "uups" },
            )
        ).to.be.revertedWith("AV:I-At least one image must be provided");
    });

    it("cannot initialize with zero address as admin", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        await expect(
            upgrades.deployProxy(
                AttestationVerifier,
                [[image1, image2, image3], [addrs[13], addrs[14], addrs[15]], ethers.constants.AddressZero],
                { kind: "uups" },
            )
        ).to.be.revertedWith("AV:I-At least one admin necessary");
    });

    it("upgrades", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2, image3], [addrs[13], addrs[14], addrs[15]], addrs[0]],
            { kind: "uups" },
        );
        await upgrades.upgradeProxy(attestationVerifier.address, AttestationVerifier, { kind: "uups" });

        expect(await attestationVerifier.hasRole(await attestationVerifier.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        expect(await attestationVerifier.getRoleMemberCount(await attestationVerifier.DEFAULT_ADMIN_ROLE())).to.equal(1);
        expect(await attestationVerifier.isVerified(addrs[13])).to.equal(getImageId(image1));
        {
            const { PCR0, PCR1, PCR2 } = await attestationVerifier.whitelistedImages(getImageId(image1));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
        }
        expect(await attestationVerifier.isVerified(addrs[14])).to.equal(getImageId(image2));
        {
            const { PCR0, PCR1, PCR2 } = await attestationVerifier.whitelistedImages(getImageId(image2));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image2);
        }
        expect(await attestationVerifier.isVerified(addrs[15])).to.equal(getImageId(image3));
        {
            const { PCR0, PCR1, PCR2 } = await attestationVerifier.whitelistedImages(getImageId(image3));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
        }
    });

    it("does not upgrade without admin", async function() {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2, image3], [addrs[13], addrs[14], addrs[15]], addrs[0]],
            { kind: "uups" },
        );

        await expect(
            upgrades.upgradeProxy(attestationVerifier.address, AttestationVerifier.connect(signers[1]), {
                kind: "uups",
            }),
        ).to.be.revertedWith("only admin");
    });
});

testERC165(
    "AttestationVerifier - ERC165",
    async function(_signers: Signer[], addrs: string[]) {
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2, image3], [addrs[13], addrs[14], addrs[15]], addrs[0]],
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
        IAccessControlEnumerable: [
            "getRoleMember(bytes32,uint256)",
            "getRoleMemberCount(bytes32)",
        ],
    },
);

testAdminRole("AttestationVerifier - Admin", async function(_signers: Signer[], addrs: string[]) {
    const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
    const attestationVerifier = await upgrades.deployProxy(
        AttestationVerifier,
        [[image1, image2, image3], [addrs[13], addrs[14], addrs[15]], addrs[0]],
        { kind: "uups" },
    );
    return attestationVerifier;
});

describe("AttestationVerifier - Whitelist image", function() {
    let signers: Signer[];
    let addrs: string[];
    let attestationVerifier: AttestationVerifier;

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifierContract = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2], [addrs[13], addrs[14]], addrs[0]],
            { kind: "uups" },
        );
        attestationVerifier = getAttestationVerifier(attestationVerifierContract.address, signers[0]);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("non admin cannot whitelist image", async function() {
        await expect(attestationVerifier.connect(signers[1]).whitelistImage(image3.PCR0, image3.PCR1, image3.PCR2)).to.be.revertedWith("only admin");
    });

    it("admin can whitelist image", async function() {
        {
            const { PCR0, PCR1, PCR2 } = await attestationVerifier.whitelistedImages(getImageId(image3));
            expect([PCR0, PCR1, PCR2]).to.deep.equal(["0x", "0x", "0x"]);
        }

        await expect(attestationVerifier.whitelistImage(image3.PCR0, image3.PCR1, image3.PCR2))
            .to.emit(attestationVerifier, "EnclaveImageWhitelisted").withArgs(getImageId(image3), image3.PCR0, image3.PCR1, image3.PCR2);
        {
            const { PCR0, PCR1, PCR2 } = await attestationVerifier.whitelistedImages(getImageId(image3));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
        }
    });

    it("admin cannot whitelist image with empty PCRs", async function() {
        await expect(attestationVerifier.whitelistImage("0x", "0x", "0x")).to.be.revertedWith("AV:IWI-PCR values must be 48 bytes");
    });

    it("admin cannot whitelist image with invalid PCRs", async function() {
        await expect(attestationVerifier.whitelistImage("0x1111111111", image3.PCR1, image3.PCR2)).to.be.revertedWith("AV:IWI-PCR values must be 48 bytes");
        await expect(attestationVerifier.whitelistImage(image3.PCR0, "0x1111111111", image3.PCR2)).to.be.revertedWith("AV:IWI-PCR values must be 48 bytes");
        await expect(attestationVerifier.whitelistImage(image3.PCR0, image3.PCR1, "0x1111111111")).to.be.revertedWith("AV:IWI-PCR values must be 48 bytes");
    });

    it("admin cannot rewhitelist image", async function() {
        await expect(attestationVerifier.whitelistImage(image3.PCR0, image3.PCR1, image3.PCR2))
            .to.emit(attestationVerifier, "EnclaveImageWhitelisted").withArgs(getImageId(image3), image3.PCR0, image3.PCR1, image3.PCR2);
        {
            const { PCR0, PCR1, PCR2 } = await attestationVerifier.whitelistedImages(getImageId(image3));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
        }

        await expect(attestationVerifier.whitelistImage(image3.PCR0, image3.PCR1, image3.PCR2)).to.be.revertedWith("AV:IWI-image already whitelisted");
    });
});

describe("AttestationVerifier - Revoke image", function() {
    let signers: Signer[];
    let addrs: string[];
    let attestationVerifier: AttestationVerifier;

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifierContract = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2], [addrs[13], addrs[14]], addrs[0]],
            { kind: "uups" },
        );
        attestationVerifier = getAttestationVerifier(attestationVerifierContract.address, signers[0]);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("non admin cannot revoke image", async function() {
        await expect(attestationVerifier.connect(signers[1]).revokeWhitelistedImage(getImageId(image1))).to.be.revertedWith("only admin");
    });

    it("admin can revoke image", async function() {
        {
            const { PCR0, PCR1, PCR2 } = await attestationVerifier.whitelistedImages(getImageId(image1));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
        }

        await expect(attestationVerifier.revokeWhitelistedImage(getImageId(image1)))
            .to.emit(attestationVerifier, "WhitelistedImageRevoked").withArgs(getImageId(image1));
        {
            const { PCR0, PCR1, PCR2 } = await attestationVerifier.whitelistedImages(getImageId(image1));
            expect([PCR0, PCR1, PCR2]).to.deep.equal(["0x", "0x", "0x"]);
        }
    });

    it("admin cannot revoke unwhitelisted image", async function() {
        await expect(attestationVerifier.revokeWhitelistedImage(getImageId(image3))).to.be.revertedWith("AV:RWI-Image not whitelisted");
    });
});

describe("AttestationVerifier - Whitelist enclave", function() {
    let signers: Signer[];
    let addrs: string[];
    let attestationVerifier: AttestationVerifier;

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifierContract = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2], [addrs[13], addrs[14]], addrs[0]],
            { kind: "uups" },
        );
        attestationVerifier = getAttestationVerifier(attestationVerifierContract.address, signers[0]);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("non admin cannot whitelist enclave", async function() {
        await expect(attestationVerifier.connect(signers[1]).whitelistEnclave(getImageId(image1), addrs[15])).to.be.revertedWith("only admin");
    });

    it("admin can whitelist enclave", async function() {
        expect(await attestationVerifier.isVerified(addrs[15])).to.equal(ethers.constants.HashZero);

        await expect(attestationVerifier.whitelistEnclave(getImageId(image1), addrs[15]))
            .to.emit(attestationVerifier, "EnclaveKeyWhitelisted").withArgs(getImageId(image1), addrs[15]);
        expect(await attestationVerifier.isVerified(addrs[15])).to.equal(getImageId(image1));
    });

    it("admin cannot whitelist enclave with unwhitelisted image", async function() {
        await expect(attestationVerifier.whitelistEnclave(getImageId(image3), addrs[15])).to.be.revertedWith("AV:WE-Image not whitelisted");
    });

    it("admin cannot whitelist enclave with zero address", async function() {
        await expect(attestationVerifier.whitelistEnclave(getImageId(image1), ethers.constants.AddressZero)).to.be.revertedWith("AV:WE-Invalid enclave key");
    });

    it("admin cannot rewhitelist enclave", async function() {
        expect(await attestationVerifier.isVerified(addrs[15])).to.equal(ethers.constants.HashZero);

        await expect(attestationVerifier.whitelistEnclave(getImageId(image1), addrs[15]))
            .to.emit(attestationVerifier, "EnclaveKeyWhitelisted").withArgs(getImageId(image1), addrs[15]);
        expect(await attestationVerifier.isVerified(addrs[15])).to.equal(getImageId(image1));

        await expect(attestationVerifier.whitelistEnclave(getImageId(image1), addrs[15])).to.be.revertedWith("AV:WE-Enclave key already verified");
    });
});

describe("AttestationVerifier - Revoke enclave", function() {
    let signers: Signer[];
    let addrs: string[];
    let attestationVerifier: AttestationVerifier;

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifierContract = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2], [addrs[13], addrs[14]], addrs[0]],
            { kind: "uups" },
        );
        attestationVerifier = getAttestationVerifier(attestationVerifierContract.address, signers[0]);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("non admin cannot revoke enclave", async function() {
        await expect(attestationVerifier.connect(signers[1]).revokeWhitelistedEnclave(addrs[14])).to.be.revertedWith("only admin");
    });

    it("admin can revoke enclave", async function() {
        expect(await attestationVerifier.isVerified(addrs[14])).to.equal(getImageId(image2));

        await expect(attestationVerifier.revokeWhitelistedEnclave(addrs[14]))
            .to.emit(attestationVerifier, "WhitelistedEnclaveKeyRevoked").withArgs(getImageId(image2), addrs[14]);
        expect(await attestationVerifier.isVerified(addrs[14])).to.equal(ethers.constants.HashZero);
    });

    it("admin cannot revoke unwhitelisted enclave", async function() {
        await expect(attestationVerifier.revokeWhitelistedEnclave(addrs[15])).to.be.revertedWith("AV:RWE-Enclave key not verified");
    });
});

describe("AttestationVerifier - Verify enclave key", function() {
    let signers: Signer[];
    let addrs: string[];
    let attestationVerifier: AttestationVerifier;

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifierContract = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2], [addrs[13], addrs[14]], addrs[0]],
            { kind: "uups" },
        );
        attestationVerifier = getAttestationVerifier(attestationVerifierContract.address, signers[0]);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    function normalize(key: string): string {
        return '0x' + key.substring(4);
    }

    it("can verify enclave key", async function() {
        const timestamp = await time.latest() * 1000;
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image1, wallet14, 2, 4096, timestamp - 240000);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(attestation, normalize(wallet15.publicKey), getImageId(image1), 2, 4096, timestamp - 240000))
            .to.emit(attestationVerifier, "EnclaveKeyVerified").withArgs(getImageId(image1), normalize(wallet15.publicKey));
        expect(await attestationVerifier.isVerified(addrs[15])).to.equal(getImageId(image1));
    });

    it("cannot verify enclave key with too old attestation", async function() {
        const timestamp = await time.latest() * 1000;
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image1, wallet14, 2, 4096, timestamp - 360000);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(attestation, normalize(wallet15.publicKey), getImageId(image1), 2, 4096, timestamp - 360000))
            .to.be.revertedWith("AV:V-Attestation too old");
    });

    it("cannot verify enclave key with invalid data", async function() {
        const timestamp = await time.latest() * 1000;
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let wallet16 = walletForIndex(16).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image1, wallet14, 2, 4096, timestamp - 240000);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(attestation, normalize(wallet15.publicKey), getImageId(image2), 2, 4096, timestamp - 240000))
            .to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(attestation, normalize(wallet15.publicKey), getImageId(image1), 1, 4096, timestamp - 240000))
            .to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(attestation, normalize(wallet15.publicKey), getImageId(image1), 2, 4095, timestamp - 240000))
            .to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(attestation, normalize(wallet16.publicKey), getImageId(image1), 2, 4096, timestamp - 240000))
            .to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(attestation, normalize(wallet15.publicKey), getImageId(image1), 2, 4096, timestamp - 200000))
            .to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
    });

    it("cannot verify enclave key with invalid public key", async function() {
        const timestamp = await time.latest() * 1000;
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let attestation = createAttestation(ethers.constants.AddressZero, image1, wallet14, 2, 4096, timestamp - 240000);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(attestation, ethers.constants.AddressZero, getImageId(image1), 2, 4096, timestamp - 240000))
            .to.be.revertedWith("Invalid public key length");
    });

    it("cannot verify enclave key with unwhitelisted image", async function() {
        const timestamp = await time.latest() * 1000;
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, timestamp - 240000);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(attestation, normalize(wallet15.publicKey), getImageId(image3), 2, 4096, timestamp - 240000))
            .to.be.revertedWith("AV:V-Enclave image to verify not whitelisted");
    });

    it("cannot reverify enclave key", async function() {
        const timestamp = await time.latest() * 1000;
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image1, wallet14, 2, 4096, timestamp - 240000);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(attestation, normalize(wallet15.publicKey), getImageId(image1), 2, 4096, timestamp - 240000))
            .to.emit(attestationVerifier, "EnclaveKeyVerified").withArgs(getImageId(image1), normalize(wallet15.publicKey));
        expect(await attestationVerifier.isVerified(addrs[15])).to.equal(getImageId(image1));

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(attestation, normalize(wallet15.publicKey), getImageId(image1), 2, 4096, timestamp - 240000))
            .to.be.revertedWith("AV:V-Enclave key already verified");
    });

    it("cannot verify enclave key with unwhitelisted key", async function() {
        const timestamp = await time.latest() * 1000;
        let wallet16 = walletForIndex(16).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image1, wallet16, 2, 4096, timestamp - 240000);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(attestation, normalize(wallet15.publicKey), getImageId(image1), 2, 4096, timestamp - 240000))
            .to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
    });

    it("cannot verify enclave key with revoked key", async function() {
        const timestamp = await time.latest() * 1000;
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image1, wallet14, 2, 4096, timestamp - 240000);

        await attestationVerifier.revokeWhitelistedEnclave(addrs[14]);

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(attestation, normalize(wallet15.publicKey), getImageId(image1), 2, 4096, timestamp - 240000))
            .to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
    });

    it("cannot verify enclave key with revoked image", async function() {
        const timestamp = await time.latest() * 1000;
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image1, wallet14, 2, 4096, timestamp - 240000);

        await attestationVerifier.revokeWhitelistedImage(getImageId(image2));

        await expect(attestationVerifier.connect(signers[1]).verifyEnclaveKey(attestation, normalize(wallet15.publicKey), getImageId(image1), 2, 4096, timestamp - 240000))
            .to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
    });
});

describe("AttestationVerifier - Safe verify with params", function() {
    let signers: Signer[];
    let addrs: string[];
    let attestationVerifier: AttestationVerifier;

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifierContract = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2], [addrs[13], addrs[14]], addrs[0]],
            { kind: "uups" },
        );
        attestationVerifier = getAttestationVerifier(attestationVerifierContract.address, signers[0]);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    function normalize(key: string): string {
        return '0x' + key.substring(4);
    }

    it("can verify", async function() {
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, 300000);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes,bytes,bytes,bytes,bytes,uint256,uint256,uint256)'](
            attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 2, 4096, 300000,
        )).to.not.be.reverted;
    });

    it("cannot verify with invalid data", async function() {
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, 300000);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes,bytes,bytes,bytes,bytes,uint256,uint256,uint256)'](
            attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR0, 2, 4096, 300000,
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes,bytes,bytes,bytes,bytes,uint256,uint256,uint256)'](
            attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR0, image3.PCR2, 2, 4096, 300000,
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes,bytes,bytes,bytes,bytes,uint256,uint256,uint256)'](
            attestation, normalize(wallet15.publicKey), image3.PCR1, image3.PCR1, image3.PCR2, 2, 4096, 300000,
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes,bytes,bytes,bytes,bytes,uint256,uint256,uint256)'](
            attestation, normalize(wallet14.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 2, 4096, 300000,
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes,bytes,bytes,bytes,bytes,uint256,uint256,uint256)'](
            attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 1, 4096, 300000,
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes,bytes,bytes,bytes,bytes,uint256,uint256,uint256)'](
            attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 2, 4095, 300000,
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes,bytes,bytes,bytes,bytes,uint256,uint256,uint256)'](
            attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 2, 4096, 200000,
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
    });

    it("cannot verify with unwhitelisted key", async function() {
        let wallet16 = walletForIndex(16).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet16, 2, 4096, 300000);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes,bytes,bytes,bytes,bytes,uint256,uint256,uint256)'](
            attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 2, 4096, 300000,
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
    });

    it("cannot verify with revoked key", async function() {
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, 300000);

        await attestationVerifier.revokeWhitelistedEnclave(addrs[14]);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes,bytes,bytes,bytes,bytes,uint256,uint256,uint256)'](
            attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 2, 4096, 300000,
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
    });

    it("cannot verify with revoked image", async function() {
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, 300000);

        await attestationVerifier.revokeWhitelistedImage(getImageId(image2));

        await expect(attestationVerifier.connect(signers[1])['verify(bytes,bytes,bytes,bytes,bytes,uint256,uint256,uint256)'](
            attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 2, 4096, 300000,
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
    });
});

describe("AttestationVerifier - Safe verify with bytes", function() {
    let signers: Signer[];
    let addrs: string[];
    let attestationVerifier: AttestationVerifier;

    before(async function() {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifierContract = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1, image2], [addrs[13], addrs[14]], addrs[0]],
            { kind: "uups" },
        );
        attestationVerifier = getAttestationVerifier(attestationVerifierContract.address, signers[0]);
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    function normalize(key: string): string {
        return '0x' + key.substring(4);
    }

    it("can verify", async function() {
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, 300000);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.utils.defaultAbiCoder.encode(
                ["bytes", "bytes", "bytes", "bytes", "bytes", "uint256", "uint256", "uint256"],
                [attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 2, 4096, 300000],
            ),
        )).to.not.be.reverted;
    });

    it("cannot verify with invalid data", async function() {
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, 300000);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.utils.defaultAbiCoder.encode(
                ["bytes", "bytes", "bytes", "bytes", "bytes", "uint256", "uint256", "uint256"],
                [attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR0, 2, 4096, 300000],
            ),
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.utils.defaultAbiCoder.encode(
                ["bytes", "bytes", "bytes", "bytes", "bytes", "uint256", "uint256", "uint256"],
                [attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR0, image3.PCR2, 2, 4096, 300000],
            ),
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.utils.defaultAbiCoder.encode(
                ["bytes", "bytes", "bytes", "bytes", "bytes", "uint256", "uint256", "uint256"],
                [attestation, normalize(wallet15.publicKey), image3.PCR1, image3.PCR1, image3.PCR2, 2, 4096, 300000],
            ),
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.utils.defaultAbiCoder.encode(
                ["bytes", "bytes", "bytes", "bytes", "bytes", "uint256", "uint256", "uint256"],
                [attestation, normalize(wallet14.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 2, 4096, 300000],
            ),
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.utils.defaultAbiCoder.encode(
                ["bytes", "bytes", "bytes", "bytes", "bytes", "uint256", "uint256", "uint256"],
                [attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 1, 4096, 300000],
            ),
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.utils.defaultAbiCoder.encode(
                ["bytes", "bytes", "bytes", "bytes", "bytes", "uint256", "uint256", "uint256"],
                [attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 2, 4095, 300000],
            ),
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.utils.defaultAbiCoder.encode(
                ["bytes", "bytes", "bytes", "bytes", "bytes", "uint256", "uint256", "uint256"],
                [attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 2, 4096, 200000],
            ),
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
    });

    it("cannot verify with unwhitelisted key", async function() {
        let wallet16 = walletForIndex(16).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet16, 2, 4096, 300000);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.utils.defaultAbiCoder.encode(
                ["bytes", "bytes", "bytes", "bytes", "bytes", "uint256", "uint256", "uint256"],
                [attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 2, 4096, 300000],
            ),
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
    });

    it("cannot verify with revoked key", async function() {
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, 300000);

        await attestationVerifier.revokeWhitelistedEnclave(addrs[14]);

        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.utils.defaultAbiCoder.encode(
                ["bytes", "bytes", "bytes", "bytes", "bytes", "uint256", "uint256", "uint256"],
                [attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 2, 4096, 300000],
            ),
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
    });

    it("cannot verify with revoked image", async function() {
        let wallet14 = walletForIndex(14).connect(attestationVerifier.provider);
        let wallet15 = walletForIndex(15).connect(attestationVerifier.provider);
        let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, 300000);

        await attestationVerifier.revokeWhitelistedImage(getImageId(image2));

        await expect(attestationVerifier.connect(signers[1])['verify(bytes)'](
            ethers.utils.defaultAbiCoder.encode(
                ["bytes", "bytes", "bytes", "bytes", "bytes", "uint256", "uint256", "uint256"],
                [attestation, normalize(wallet15.publicKey), image3.PCR0, image3.PCR1, image3.PCR2, 2, 4096, 300000],
            ),
        )).to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
    });
});

function getImageId(image: AttestationVerifier.EnclaveImageStruct): string {
    return keccak256(solidityPack(["bytes", "bytes", "bytes"], [image.PCR0, image.PCR1, image.PCR2]));
}

function createAttestation(
    enclaveKey: string,
    image: AttestationVerifier.EnclaveImageStruct,
    sourceEnclaveKey: Wallet,
    CPU: number,
    memory: number,
    timestamp: number,
): string {
    const message = ethers.utils.defaultAbiCoder.encode(
        ["string", "bytes", "bytes", "bytes", "bytes", "uint256", "uint256", "uint256"],
        [ATTESTATION_PREFIX, enclaveKey, image.PCR0, image.PCR1, image.PCR2, CPU, memory, timestamp]
    );
    const digest = ethers.utils.keccak256(message);
    const sign = sourceEnclaveKey._signingKey().signDigest(digest);
    return ethers.utils.joinSignature(sign);
}

function walletForIndex(idx: number): Wallet {
    let wallet = ethers.Wallet.fromMnemonic("test test test test test test test test test test test junk", "m/44'/60'/0'/0/" + idx.toString());

    return wallet;
}
