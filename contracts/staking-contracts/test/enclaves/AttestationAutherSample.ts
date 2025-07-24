import { expect } from "chai";
import { Signer, Wallet, BigNumber as BN } from "ethers";
import { ethers, network, upgrades } from "hardhat";
import { AttestationAutherSample, AttestationAutherUpgradeable } from "../../typechain-types/contracts/enclaves/AttestationAutherSample";
import { AttestationVerifier } from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { keccak256, parseUnits, solidityPack } from "ethers/lib/utils";
import { testERC165 } from "../helpers/erc165";
import { testAdminRole } from "../helpers/rbac";
import { getAttestationAutherSample, getAttestationVerifier } from "../../utils/typechainConvertor";
import { time } from '@nomicfoundation/hardhat-network-helpers';


const image1: AttestationAutherUpgradeable.EnclaveImageStruct = {
	PCR0: parseUnits("1", 115).toHexString(),
	PCR1: parseUnits("2", 114).toHexString(),
	PCR2: parseUnits("3", 114).toHexString(),
};

const image2: AttestationAutherUpgradeable.EnclaveImageStruct = {
	PCR0: parseUnits("4", 114).toHexString(),
	PCR1: parseUnits("5", 114).toHexString(),
	PCR2: parseUnits("6", 114).toHexString(),
};

const image3: AttestationAutherUpgradeable.EnclaveImageStruct = {
	PCR0: parseUnits("7", 114).toHexString(),
	PCR1: parseUnits("8", 114).toHexString(),
	PCR2: parseUnits("9", 114).toHexString(),
};

function getImageId(image: AttestationAutherUpgradeable.EnclaveImageStruct): string {
	return keccak256(solidityPack(["bytes", "bytes", "bytes"], [image.PCR0, image.PCR1, image.PCR2]));
}

describe("AttestationAutherSample - Init", function() {
	let signers: Signer[];
	let addrs: string[];

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("deploys with initialization disabled", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600);

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);

		await expect(
			attestationAutherSample.initialize([], addrs[0]),
		).to.be.revertedWith("Initializable: contract is already initialized");

		await expect(
			attestationAutherSample.initialize([image1, image2], addrs[0]),
		).to.be.revertedWith("Initializable: contract is already initialized");
	});

	it("deploys as proxy and initializes", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await attestationAutherSample.hasRole(await attestationAutherSample.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		expect(await attestationAutherSample.getRoleMemberCount(await attestationAutherSample.DEFAULT_ADMIN_ROLE())).to.equal(1);
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
	});

	it("deploys as proxy and initializes with multiple images", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await attestationAutherSample.hasRole(await attestationAutherSample.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		expect(await attestationAutherSample.getRoleMemberCount(await attestationAutherSample.DEFAULT_ADMIN_ROLE())).to.equal(1);
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image2));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image2);
		}
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image3));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
		}
	});

	it("cannot initialize with no whitelisted images", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		await expect(
			upgrades.deployProxy(
				AttestationAutherSample,
				[[], addrs[0]],
				{ kind: "uups", constructorArgs: [addrs[10], 600] },
			)
		).to.be.revertedWith("AAS:I-At least one image necessary");
	});

	it("cannot initialize with zero address as admin", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		await expect(
			upgrades.deployProxy(
				AttestationAutherSample,
				[[image1, image2, image3], ethers.constants.AddressZero],
				{ kind: "uups", constructorArgs: [addrs[10], 600] },
			)
		).to.be.revertedWith("AAS:I-At least one admin necessary");
	});

	it("upgrades", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);
		await upgrades.upgradeProxy(attestationAutherSample.address, AttestationAutherSample, { kind: "uups", constructorArgs: [addrs[10], 600] });

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await attestationAutherSample.hasRole(await attestationAutherSample.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		expect(await attestationAutherSample.getRoleMemberCount(await attestationAutherSample.DEFAULT_ADMIN_ROLE())).to.equal(1);
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image2));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image2);
		}
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image3));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
		}
	});

	it("does not upgrade without admin", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);

		await expect(
			upgrades.upgradeProxy(attestationAutherSample.address, AttestationAutherSample.connect(signers[1]), {
				kind: "uups",
				constructorArgs: [addrs[10], 600],
			}),
		).to.be.revertedWith("only admin");
	});
});

testERC165(
	"AttestationAutherSample - ERC165",
	async function(_signers: Signer[], addrs: string[]) {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);
		return attestationAutherSample;
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

testAdminRole("AttestationAutherSample - Admin", async function(_signers: Signer[], addrs: string[]) {
	const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
	const attestationAutherSample = await upgrades.deployProxy(
		AttestationAutherSample,
		[[image1, image2, image3], addrs[0]],
		{ kind: "uups", constructorArgs: [addrs[10], 600] },
	);
	return attestationAutherSample;
});

describe("AttestationAutherSample - Whitelist image", function() {
	let signers: Signer[];
	let addrs: string[];
	let attestationAutherSample: AttestationAutherSample;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSampleContract = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);
		attestationAutherSample = getAttestationAutherSample(attestationAutherSampleContract.address, signers[0]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot whitelist image", async function() {
		await expect(attestationAutherSample.connect(signers[1]).whitelistEnclaveImage(image3.PCR0, image3.PCR1, image3.PCR2)).to.be.revertedWith("only admin");
	});

	it("admin can whitelist image", async function() {
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image3));
			expect([PCR0, PCR1, PCR2]).to.deep.equal(["0x", "0x", "0x"]);
		}

		await expect(attestationAutherSample.whitelistEnclaveImage(image3.PCR0, image3.PCR1, image3.PCR2))
			.to.emit(attestationAutherSample, "EnclaveImageWhitelisted").withArgs(getImageId(image3), image3.PCR0, image3.PCR1, image3.PCR2);
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image3));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
		}
	});

	it("admin cannot whitelist image with empty PCRs", async function() {
		await expect(attestationAutherSample.whitelistEnclaveImage("0x", "0x", "0x")).to.be.revertedWith("AA:WI-PCR values must be 48 bytes");
	});

	it("admin cannot whitelist image with invalid PCRs", async function() {
		await expect(attestationAutherSample.whitelistEnclaveImage("0x1111111111", image3.PCR1, image3.PCR2)).to.be.revertedWith("AA:WI-PCR values must be 48 bytes");
		await expect(attestationAutherSample.whitelistEnclaveImage(image3.PCR0, "0x1111111111", image3.PCR2)).to.be.revertedWith("AA:WI-PCR values must be 48 bytes");
		await expect(attestationAutherSample.whitelistEnclaveImage(image3.PCR0, image3.PCR1, "0x1111111111")).to.be.revertedWith("AA:WI-PCR values must be 48 bytes");
	});

	it("admin cannot rewhitelist image", async function() {
		await expect(attestationAutherSample.whitelistEnclaveImage(image3.PCR0, image3.PCR1, image3.PCR2))
			.to.emit(attestationAutherSample, "EnclaveImageWhitelisted").withArgs(getImageId(image3), image3.PCR0, image3.PCR1, image3.PCR2);
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image3));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
		}

		await expect(attestationAutherSample.whitelistEnclaveImage(image3.PCR0, image3.PCR1, image3.PCR2)).to.be.revertedWith("AA:WI-image already whitelisted");
	});
});

describe("AttestationAutherSample - Revoke image", function() {
	let signers: Signer[];
	let addrs: string[];
	let attestationAutherSample: AttestationAutherSample;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSampleContract = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);
		attestationAutherSample = getAttestationAutherSample(attestationAutherSampleContract.address, signers[0]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot revoke image", async function() {
		await expect(attestationAutherSample.connect(signers[1]).revokeEnclaveImage(getImageId(image1))).to.be.revertedWith("only admin");
	});

	it("admin can revoke image", async function() {
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}

		await expect(attestationAutherSample.revokeEnclaveImage(getImageId(image1)))
			.to.emit(attestationAutherSample, "EnclaveImageRevoked").withArgs(getImageId(image1));
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image1));
			expect([PCR0, PCR1, PCR2]).to.deep.equal(["0x", "0x", "0x"]);
		}
	});

	it("admin cannot revoke unwhitelisted image", async function() {
		await expect(attestationAutherSample.revokeEnclaveImage(getImageId(image3))).to.be.revertedWith("AA:RI-Image not whitelisted");
	});
});

describe("AttestationAutherSample - Whitelist enclave", function() {
	let signers: Signer[];
	let addrs: string[];
	let attestationAutherSample: AttestationAutherSample;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSampleContract = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);
		attestationAutherSample = getAttestationAutherSample(attestationAutherSampleContract.address, signers[0]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot whitelist enclave", async function() {
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		await expect(attestationAutherSample.connect(signers[1]).whitelistEnclaveKey(normalize(wallet15.publicKey), getImageId(image1))).to.be.revertedWith("only admin");
	});

	it("admin can whitelist enclave", async function() {
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(ethers.constants.HashZero);

		await expect(attestationAutherSample.whitelistEnclaveKey(normalize(wallet15.publicKey), getImageId(image1)))
			.to.emit(attestationAutherSample, "EnclaveKeyWhitelisted").withArgs(normalize(wallet15.publicKey), getImageId(image1));
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(getImageId(image1));
	});

	it("admin cannot whitelist enclave with unwhitelisted image", async function() {
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		await expect(attestationAutherSample.whitelistEnclaveKey(normalize(wallet15.publicKey), getImageId(image3))).to.be.revertedWith("AA:WK-Image not whitelisted");
	});

	it("admin cannot rewhitelist enclave", async function() {
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(ethers.constants.HashZero);

		await expect(attestationAutherSample.whitelistEnclaveKey(normalize(wallet15.publicKey), getImageId(image1)))
			.to.emit(attestationAutherSample, "EnclaveKeyWhitelisted").withArgs(normalize(wallet15.publicKey), getImageId(image1));
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(getImageId(image1));

		await expect(attestationAutherSample.whitelistEnclaveKey(normalize(wallet15.publicKey), getImageId(image1))).to.be.revertedWith("AA:WK-Enclave key already verified");
	});
});

describe("AttestationAutherSample - Revoke enclave", function() {
	let signers: Signer[];
	let addrs: string[];
	let attestationAutherSample: AttestationAutherSample;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSampleContract = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);
		attestationAutherSample = getAttestationAutherSample(attestationAutherSampleContract.address, signers[0]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot revoke enclave", async function() {
		let wallet14 = walletForIndex(14).connect(attestationAutherSample.provider);
		await expect(attestationAutherSample.connect(signers[1]).revokeEnclaveKey(normalize(wallet14.publicKey))).to.be.revertedWith("only admin");
	});

	it("admin can revoke enclave", async function() {
		let wallet14 = walletForIndex(14).connect(attestationAutherSample.provider);
		await attestationAutherSample.whitelistEnclaveKey(normalize(wallet14.publicKey), getImageId(image2));
		expect(await attestationAutherSample.getVerifiedKey(addrs[14])).to.equal(getImageId(image2));

		await expect(attestationAutherSample.revokeEnclaveKey(normalize(wallet14.publicKey)))
			.to.emit(attestationAutherSample, "EnclaveKeyRevoked").withArgs(normalize(wallet14.publicKey));
		expect(await attestationAutherSample.getVerifiedKey(addrs[14])).to.equal(ethers.constants.HashZero);
	});

	it("admin cannot revoke unwhitelisted enclave", async function() {
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		await expect(attestationAutherSample.revokeEnclaveKey(normalize(wallet15.publicKey))).to.be.revertedWith("AA:RK-Enclave key not verified");
	});
});

describe("AttestationAutherSample - Verify enclave key", function() {
	let signers: Signer[];
	let addrs: string[];
	let attestationAutherSample: AttestationAutherSample;
	let attestationVerifier: AttestationVerifier;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifierContract = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [addrs[14]], addrs[0]],
			{ kind: "uups" },
		);
		attestationVerifier = getAttestationVerifier(attestationVerifierContract.address, signers[0]);

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSampleContract = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [attestationVerifierContract.address, 600] },
		);
		attestationAutherSample = getAttestationAutherSample(attestationAutherSampleContract.address, signers[0]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	function normalize(key: string): string {
		return '0x' + key.substring(4);
	}

	it("can verify enclave key", async function() {
		const timestamp = await time.latest() * 1000;
		let wallet14 = walletForIndex(14).connect(attestationAutherSample.provider);
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet15.publicKey), getImageId(image3), 2, 4096, timestamp - 540000))
			.to.emit(attestationAutherSample, "EnclaveKeyVerified").withArgs(normalize(wallet15.publicKey), getImageId(image3));
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(getImageId(image3));
	});

	it("cannot verify enclave key with too old attestation", async function() {
		const timestamp = await time.latest() * 1000;
		let wallet14 = walletForIndex(14).connect(attestationAutherSample.provider);
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, timestamp - 660000);

		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet15.publicKey), getImageId(image3), 2, 4096, timestamp - 660000))
			.to.be.revertedWith("AA:VK-Attestation too old");
	});

	it("cannot verify enclave key with invalid data", async function() {
		const timestamp = await time.latest() * 1000;
		let wallet14 = walletForIndex(14).connect(attestationAutherSample.provider);
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		let wallet16 = walletForIndex(16).connect(attestationAutherSample.provider);
		let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet15.publicKey), getImageId(image2), 2, 4096, timestamp - 540000))
			.to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet15.publicKey), getImageId(image3), 1, 4096, timestamp - 540000))
			.to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet15.publicKey), getImageId(image3), 2, 4095, timestamp - 540000))
			.to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet16.publicKey), getImageId(image3), 2, 4096, timestamp - 540000))
			.to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet15.publicKey), getImageId(image3), 2, 4096, timestamp - 200000))
			.to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
	});

	it("cannot verify enclave key with invalid public key", async function() {
		const timestamp = await time.latest() * 1000;
		let wallet14 = walletForIndex(14).connect(attestationAutherSample.provider);
		let attestation = createAttestation(ethers.constants.AddressZero, image3, wallet14, 2, 4096, timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, ethers.constants.AddressZero, getImageId(image3), 2, 4096, timestamp - 540000))
			.to.be.revertedWith("Invalid public key length");
	});

	it("cannot verify enclave key with unwhitelisted image", async function() {
		const timestamp = await time.latest() * 1000;
		let wallet14 = walletForIndex(14).connect(attestationAutherSample.provider);
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		let attestation = createAttestation(normalize(wallet15.publicKey), image1, wallet14, 2, 4096, timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet15.publicKey), getImageId(image1), 2, 4096, timestamp - 540000))
			.to.be.revertedWith("AA:VK-Enclave image to verify not whitelisted");
	});

	it("cannot reverify enclave key", async function() {
		const timestamp = await time.latest() * 1000;
		let wallet14 = walletForIndex(14).connect(attestationAutherSample.provider);
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet15.publicKey), getImageId(image3), 2, 4096, timestamp - 540000))
			.to.emit(attestationAutherSample, "EnclaveKeyVerified").withArgs(normalize(wallet15.publicKey), getImageId(image3));
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(getImageId(image3));

		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet15.publicKey), getImageId(image3), 2, 4096, timestamp - 540000))
			.to.be.revertedWith("AA:VK-Enclave key already verified");
	});

	it("cannot verify enclave key with unwhitelisted key", async function() {
		const timestamp = await time.latest() * 1000;
		let wallet16 = walletForIndex(16).connect(attestationAutherSample.provider);
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet16, 2, 4096, timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet15.publicKey), getImageId(image3), 2, 4096, timestamp - 540000))
			.to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
	});

	it("cannot verify enclave key with revoked key", async function() {
		const timestamp = await time.latest() * 1000;
		let wallet14 = walletForIndex(14).connect(attestationAutherSample.provider);
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, timestamp - 540000);

		await attestationVerifier.revokeWhitelistedEnclave(addrs[14]);

		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet15.publicKey), getImageId(image3), 2, 4096, timestamp - 540000))
			.to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
	});

	it("cannot verify enclave key with revoked sample image", async function() {
		const timestamp = await time.latest() * 1000;
		let wallet14 = walletForIndex(14).connect(attestationAutherSample.provider);
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, timestamp - 540000);

		await attestationAutherSample.revokeEnclaveImage(getImageId(image3));

		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet15.publicKey), getImageId(image3), 2, 4096, timestamp - 540000))
			.to.be.revertedWith("AA:VK-Enclave image to verify not whitelisted");
	});

	it("cannot verify enclave key with revoked verifier image", async function() {
		const timestamp = await time.latest() * 1000;
		let wallet14 = walletForIndex(14).connect(attestationAutherSample.provider);
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, timestamp - 540000);

		await attestationVerifier.revokeWhitelistedImage(getImageId(image1));

		await expect(attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet15.publicKey), getImageId(image3), 2, 4096, timestamp - 540000))
			.to.be.revertedWith("AV:V-invalid attestation or unwhitelisted image/signer");
	});
});

describe("AttestationAutherSample - Safe verify with params", function() {
	let signers: Signer[];
	let addrs: string[];
	let attestationAutherSample: AttestationAutherSample;
	let attestationVerifier: AttestationVerifier;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));


		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifierContract = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [addrs[14]], addrs[0]],
			{ kind: "uups" },
		);
		attestationVerifier = getAttestationVerifier(attestationVerifierContract.address, signers[0]);

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSampleContract = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [attestationVerifierContract.address, 600] },
		);
		attestationAutherSample = getAttestationAutherSample(attestationAutherSampleContract.address, signers[0]);

		const timestamp = await time.latest() * 1000;
		let wallet14 = walletForIndex(14).connect(attestationAutherSample.provider);
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		let attestation = createAttestation(normalize(wallet15.publicKey), image3, wallet14, 2, 4096, timestamp - 540000);

		await attestationAutherSample.connect(signers[1]).verifyKey(attestation, normalize(wallet15.publicKey), getImageId(image3), 2, 4096, timestamp - 540000);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can verify", async function() {
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		let signature = createSignature("testmsg", wallet15);

		await expect(attestationAutherSample.connect(signers[1]).verify(signature, "testmsg")).to.not.be.reverted;
	});

	it("cannot verify with invalid data", async function() {
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		let signature = createSignature("testmsg", wallet15);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "randommsg",
		)).to.be.revertedWith("AA:AOV-Enclave key must be verified");
	});

	it("cannot verify with unwhitelisted key", async function() {
		let wallet14 = walletForIndex(14).connect(attestationAutherSample.provider);
		let signature = createSignature("testmsg", wallet14);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "randommsg",
		)).to.be.revertedWith("AA:AOV-Enclave key must be verified");
	});

	it("cannot verify with revoked key", async function() {
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		let signature = createSignature("testmsg", wallet15);

		await attestationAutherSample.revokeEnclaveKey(normalize(wallet15.publicKey));

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWith("AA:AOV-Enclave key must be verified");
	});

	it("cannot verify with revoked image", async function() {
		let wallet15 = walletForIndex(15).connect(attestationAutherSample.provider);
		let signature = createSignature("testmsg", wallet15);

		await attestationAutherSample.revokeEnclaveImage(getImageId(image3));

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWith("AA:AOV-Source image must be whitelisted");
	});
});

function normalize(key: string): string {
	return '0x' + key.substring(4);
}

function createAttestation(
	enclaveKey: string,
	image: AttestationAutherUpgradeable.EnclaveImageStruct,
	sourceEnclaveKey: Wallet,
	CPU: number,
	memory: number,
	timestamp: number,
): string {
	const ATTESTATION_PREFIX = "Enclave Attestation Verified";
	const message = ethers.utils.defaultAbiCoder.encode(
		["string", "bytes", "bytes", "bytes", "bytes", "uint256", "uint256", "uint256"],
		[ATTESTATION_PREFIX, enclaveKey, image.PCR0, image.PCR1, image.PCR2, CPU, memory, timestamp]
	);
	const digest = ethers.utils.keccak256(message);
	const sign = sourceEnclaveKey._signingKey().signDigest(digest);
	return ethers.utils.joinSignature(sign);
}

function createSignature(
	msg: string,
	sourceEnclaveKey: Wallet,
): string {
	const ATTESTATION_PREFIX = "attestation-auther-sample-";
	const message = ethers.utils.solidityPack(
		["string", "string"],
		[ATTESTATION_PREFIX, msg],
	);
	const digest = ethers.utils.keccak256(message);
	const sign = sourceEnclaveKey._signingKey().signDigest(digest);
	return ethers.utils.joinSignature(sign);
}

function walletForIndex(idx: number): Wallet {
	let wallet = ethers.Wallet.fromMnemonic("test test test test test test test test test test test junk", "m/44'/60'/0'/0/" + idx.toString());

	return wallet;
}
