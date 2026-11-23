import { expect } from "chai";
import { BytesLike, Signer, Wallet } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationVerifier, AttestationAutherUpgradeable, AttestationAutherSampleUpgradeable } from "../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../utils/testSuite";
import { keccak256, solidityPacked } from "ethers";
import { testERC165 } from "./helpers/erc165";
import { testAdminRole } from "./helpers/rbac";
import { time } from '@nomicfoundation/hardhat-network-helpers';


const image1: string = ethers.hexlify(ethers.randomBytes(32));
const image2: string = ethers.hexlify(ethers.randomBytes(32));
const image3: string = ethers.hexlify(ethers.randomBytes(32));

const FIRST_FAMILY = ethers.id("FIRST_FAMILY");
const SECOND_FAMILY = ethers.id("SECOND_FAMILY");
const THIRD_FAMILY = ethers.id("THIRD_FAMILY");

describe("AttestationAutherSampleUpgradeable - Init", function() {
	let signers: Signer[];
	let addrs: string[];

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("deploys with initialization disabled", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		const attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600);

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);

		await expect(
			attestationAutherSample.initialize([], addrs[0]),
		).to.be.revertedWithCustomError(attestationAutherSample, "InvalidInitialization");

		await expect(
			attestationAutherSample.initialize([image1, image2], addrs[0]),
		).to.be.revertedWithCustomError(attestationAutherSample, "InvalidInitialization");

		await expect(
			attestationAutherSample.initializeWithFamilies([], [], addrs[0]),
		).to.be.revertedWithCustomError(attestationAutherSample, "InvalidInitialization");

		await expect(
			attestationAutherSample.initializeWithFamilies([image1, image2], [FIRST_FAMILY, SECOND_FAMILY], addrs[0]),
		).to.be.revertedWithCustomError(attestationAutherSample, "InvalidInitialization");
	});

	it("deploys as proxy and initializes", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await attestationAutherSample.hasRole(await attestationAutherSample.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		{
			expect(await attestationAutherSample.isImageWhitelisted(image1)).to.be.true;
		}
	});

	it("deploys as proxy and initializes with multiple images", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await attestationAutherSample.hasRole(await attestationAutherSample.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		{
			expect(await attestationAutherSample.isImageWhitelisted(image1)).to.be.true;
		}
		{
			expect(await attestationAutherSample.isImageWhitelisted(image2)).to.be.true;
		}
		{
			expect(await attestationAutherSample.isImageWhitelisted(image3)).to.be.true;
		}
	});

	it("cannot initialize with no whitelisted images", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		await expect(
			upgrades.deployProxy(
				AttestationAutherSample,
				[[], addrs[0]],
				{ kind: "uups", constructorArgs: [addrs[10], 600] },
			)
		).to.be.revertedWithCustomError(AttestationAutherSample, "AttestationAutherSampleNoImageProvided");
	});

	it("cannot initialize with zero address as admin", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		await expect(
			upgrades.deployProxy(
				AttestationAutherSample,
				[[image1, image2, image3], ethers.ZeroAddress],
				{ kind: "uups", constructorArgs: [addrs[10], 600] },
			)
		).to.be.revertedWithCustomError(AttestationAutherSample, "AttestationAutherSampleInvalidAdmin");
	});

	it("upgrades", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);
		await upgrades.upgradeProxy(await attestationAutherSample.getAddress(), AttestationAutherSample, { kind: "uups", constructorArgs: [addrs[10], 600] });

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await attestationAutherSample.hasRole(await attestationAutherSample.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		{
			expect(await attestationAutherSample.isImageWhitelisted(image1)).to.be.true;
		}
		{
			expect(await attestationAutherSample.isImageWhitelisted(image2)).to.be.true;
		}
		{
			expect(await attestationAutherSample.isImageWhitelisted(image3)).to.be.true;
		}
	});

	it("does not upgrade without admin", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);

		await expect(
			upgrades.upgradeProxy(await attestationAutherSample.getAddress(), AttestationAutherSample.connect(signers[1]), {
				kind: "uups",
				constructorArgs: [addrs[10], 600],
			}),
		).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});

	it("deploys as proxy and initializes with families", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2, image3], [FIRST_FAMILY, SECOND_FAMILY, THIRD_FAMILY], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600], initializer: "initializeWithFamilies" },
		);

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await attestationAutherSample.hasRole(await attestationAutherSample.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		{
			expect(await attestationAutherSample.isImageWhitelisted(image1)).to.be.true;
		}
		{
			expect(await attestationAutherSample.isImageWhitelisted(image2)).to.be.true;
		}
		{
			expect(await attestationAutherSample.isImageWhitelisted(image3)).to.be.true;
		}
		expect(await attestationAutherSample.isImageInFamily(image1, FIRST_FAMILY)).to.be.true;
		expect(await attestationAutherSample.isImageInFamily(image2, FIRST_FAMILY)).to.be.false;
		expect(await attestationAutherSample.isImageInFamily(image3, FIRST_FAMILY)).to.be.false;
		expect(await attestationAutherSample.isImageInFamily(image1, SECOND_FAMILY)).to.be.false;
		expect(await attestationAutherSample.isImageInFamily(image2, SECOND_FAMILY)).to.be.true;
		expect(await attestationAutherSample.isImageInFamily(image3, SECOND_FAMILY)).to.be.false;
		expect(await attestationAutherSample.isImageInFamily(image1, THIRD_FAMILY)).to.be.false;
		expect(await attestationAutherSample.isImageInFamily(image2, THIRD_FAMILY)).to.be.false;
		expect(await attestationAutherSample.isImageInFamily(image3, THIRD_FAMILY)).to.be.true;
	});

	it("cannot initialize with families with no whitelisted images", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		await expect(
			upgrades.deployProxy(
				AttestationAutherSample,
				[[], [], addrs[0]],
				{ kind: "uups", constructorArgs: [addrs[10], 600], initializer: "initializeWithFamilies" },
			)
		).to.be.revertedWithCustomError(AttestationAutherSample, "AttestationAutherSampleNoImageProvided");
	});

	it("cannot initialize with families with zero address as admin", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		await expect(
			upgrades.deployProxy(
				AttestationAutherSample,
				[[image1, image2, image3], [FIRST_FAMILY, SECOND_FAMILY, THIRD_FAMILY], ethers.ZeroAddress],
				{ kind: "uups", constructorArgs: [addrs[10], 600], initializer: "initializeWithFamilies" },
			)
		).to.be.revertedWithCustomError(AttestationAutherSample, "AttestationAutherSampleInvalidAdmin");
	});

	it("cannot initialize with families with mismatched lengths", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		await expect(
			upgrades.deployProxy(
				AttestationAutherSample,
				[[image1, image2, image3], [SECOND_FAMILY, THIRD_FAMILY], addrs[0]],
				{ kind: "uups", constructorArgs: [addrs[10], 600], initializer: "initializeWithFamilies" },
			)
		).to.be.revertedWithCustomError(AttestationAutherSample, "AttestationAutherMismatchedLengths");
	});
});

testERC165(
	"AttestationAutherSampleUpgradeable - ERC165",
	async function(_signers: Signer[], addrs: string[]) {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
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
	},
);

testAdminRole("AttestationAutherSampleUpgradeable - Admin", async function(_signers: Signer[], addrs: string[]) {
	const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
	const attestationAutherSample = await upgrades.deployProxy(
		AttestationAutherSample,
		[[image1, image2, image3], addrs[0]],
		{ kind: "uups", constructorArgs: [addrs[10], 600] },
	);
	return attestationAutherSample;
});

describe("AttestationAutherSampleUpgradeable - Whitelist image", function() {
	let signers: Signer[];
	let addrs: string[];
	let attestationAutherSample: AttestationAutherSampleUpgradeable;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		) as unknown as AttestationAutherSampleUpgradeable;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot whitelist image", async function() {
		await expect(attestationAutherSample.connect(signers[1]).whitelistEnclaveImage(image3)).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});

	it("admin can whitelist image", async function() {
		expect(await attestationAutherSample.isImageWhitelisted(image3)).to.be.false;

		expect(await attestationAutherSample.whitelistEnclaveImage.staticCall(image3)).to.equal(true);
		await expect(attestationAutherSample.whitelistEnclaveImage(image3))
			.to.emit(attestationAutherSample, "EnclaveImageWhitelisted").withArgs(image3);
		{
			expect(await attestationAutherSample.isImageWhitelisted(image3)).to.be.true;
		}
	});



	it("admin can rewhitelist image", async function() {
		expect(await attestationAutherSample.whitelistEnclaveImage.staticCall(image3)).to.equal(true);
		await expect(attestationAutherSample.whitelistEnclaveImage(image3))
			.to.emit(attestationAutherSample, "EnclaveImageWhitelisted").withArgs(image3);
		{
			expect(await attestationAutherSample.isImageWhitelisted(image3)).to.be.true;
		}

		expect(await attestationAutherSample.whitelistEnclaveImage.staticCall(image3)).to.equal(false);
		await expect(attestationAutherSample.whitelistEnclaveImage(image3))
			.to.not.emit(attestationAutherSample, "EnclaveImageWhitelisted");
	});
});

describe("AttestationAutherSampleUpgradeable - Revoke image", function() {
	let signers: Signer[];
	let addrs: string[];
	let attestationAutherSample: AttestationAutherSampleUpgradeable;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		) as unknown as AttestationAutherSampleUpgradeable;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot revoke image", async function() {
		await expect(attestationAutherSample.connect(signers[1]).revokeEnclaveImage(image1)).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});

	it("admin can revoke image", async function() {
		{
			expect(await attestationAutherSample.isImageWhitelisted(image1)).to.be.true;
		}

		expect(await attestationAutherSample.revokeEnclaveImage.staticCall(image1)).to.be.true;
		await expect(attestationAutherSample.revokeEnclaveImage(image1))
			.to.emit(attestationAutherSample, "EnclaveImageRevoked").withArgs(image1);
		expect(await attestationAutherSample.isImageWhitelisted(image1)).to.be.false;
	});

	it("admin can revoke unwhitelisted image", async function() {
		expect(await attestationAutherSample.revokeEnclaveImage.staticCall(image3)).to.be.false;
		await expect(attestationAutherSample.revokeEnclaveImage(image3))
			.to.not.emit(attestationAutherSample, "EnclaveImageRevoked");
	});
});

describe("AttestationAutherSampleUpgradeable - Add image to family", function() {
	let signers: Signer[];
	let addrs: string[];
	let attestationAutherSample: AttestationAutherSampleUpgradeable;
	const TEST_FAMILY = ethers.id("TEST_FAMILY");

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		) as unknown as AttestationAutherSampleUpgradeable;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot add image to family", async function() {
		await expect(attestationAutherSample.connect(signers[1]).addEnclaveImageToFamily(image1, TEST_FAMILY)).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});

	it("admin can add image to family", async function() {
		expect(await attestationAutherSample.isImageInFamily(image1, TEST_FAMILY)).to.be.false;

		expect(await attestationAutherSample.addEnclaveImageToFamily.staticCall(image1, TEST_FAMILY)).to.be.true;
		await expect(attestationAutherSample.addEnclaveImageToFamily(image1, TEST_FAMILY))
			.to.emit(attestationAutherSample, "EnclaveImageAddedToFamily").withArgs(image1, TEST_FAMILY);

		expect(await attestationAutherSample.isImageInFamily(image1, TEST_FAMILY)).to.be.true;
	});

	it("admin can readd image to family", async function() {
		expect(await attestationAutherSample.isImageInFamily(image1, TEST_FAMILY)).to.be.false;

		expect(await attestationAutherSample.addEnclaveImageToFamily.staticCall(image1, TEST_FAMILY)).to.be.true;
		await expect(attestationAutherSample.addEnclaveImageToFamily(image1, TEST_FAMILY))
			.to.emit(attestationAutherSample, "EnclaveImageAddedToFamily").withArgs(image1, TEST_FAMILY);

		expect(await attestationAutherSample.isImageInFamily(image1, TEST_FAMILY)).to.be.true;

		expect(await attestationAutherSample.addEnclaveImageToFamily.staticCall(image1, TEST_FAMILY)).to.be.false;
		await expect(attestationAutherSample.addEnclaveImageToFamily(image1, TEST_FAMILY))
			.to.not.emit(attestationAutherSample, "EnclaveImageAddedToFamily");
	});
});

describe("AttestationAutherSampleUpgradeable - Remove image from family", function() {
	let signers: Signer[];
	let addrs: string[];
	let attestationAutherSample: AttestationAutherSampleUpgradeable;
	const TEST_FAMILY = ethers.id("TEST_FAMILY");

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		) as unknown as AttestationAutherSampleUpgradeable;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot add image to family", async function() {
		await attestationAutherSample.addEnclaveImageToFamily(image1, TEST_FAMILY);
		expect(await attestationAutherSample.isImageInFamily(image1, TEST_FAMILY)).to.be.true;

		await expect(attestationAutherSample.connect(signers[1]).removeEnclaveImageFromFamily(image1, TEST_FAMILY)).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});

	it("admin can add image to family", async function() {
		await attestationAutherSample.addEnclaveImageToFamily(image1, TEST_FAMILY);
		expect(await attestationAutherSample.isImageInFamily(image1, TEST_FAMILY)).to.be.true;

		expect(await attestationAutherSample.removeEnclaveImageFromFamily.staticCall(image1, TEST_FAMILY)).to.be.true;
		await expect(attestationAutherSample.removeEnclaveImageFromFamily(image1, TEST_FAMILY))
			.to.emit(attestationAutherSample, "EnclaveImageRemovedFromFamily").withArgs(image1, TEST_FAMILY);

		expect(await attestationAutherSample.isImageInFamily(image1, TEST_FAMILY)).to.be.false;
	});

	it("admin can readd image to family", async function() {
		await attestationAutherSample.addEnclaveImageToFamily(image1, TEST_FAMILY);
		expect(await attestationAutherSample.isImageInFamily(image1, TEST_FAMILY)).to.be.true;

		expect(await attestationAutherSample.removeEnclaveImageFromFamily.staticCall(image1, TEST_FAMILY)).to.be.true;
		await expect(attestationAutherSample.removeEnclaveImageFromFamily(image1, TEST_FAMILY))
			.to.emit(attestationAutherSample, "EnclaveImageRemovedFromFamily").withArgs(image1, TEST_FAMILY);

		expect(await attestationAutherSample.isImageInFamily(image1, TEST_FAMILY)).to.be.false;

		expect(await attestationAutherSample.removeEnclaveImageFromFamily.staticCall(image1, TEST_FAMILY)).to.be.false;
		await expect(attestationAutherSample.removeEnclaveImageFromFamily(image1, TEST_FAMILY))
			.to.not.emit(attestationAutherSample, "EnclaveImageRemovedFromFamily");
	});
});

describe("AttestationAutherSampleUpgradeable - Whitelist enclave", function() {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];

	let attestationAutherSample: AttestationAutherSampleUpgradeable;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		) as unknown as AttestationAutherSampleUpgradeable;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot whitelist enclave", async function() {
		await expect(attestationAutherSample.connect(signers[1]).whitelistEnclaveKey(pubkeys[15], image1)).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});

	it("admin can whitelist enclave", async function() {
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(ethers.ZeroHash);

		await expect(attestationAutherSample.whitelistEnclaveKey(pubkeys[15], image1))
			.to.emit(attestationAutherSample, "EnclaveKeyWhitelisted").withArgs(addrs[15], image1, pubkeys[15]);
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(image1);
	});

	it("admin cannot whitelist enclave with unwhitelisted image", async function() {
		await expect(attestationAutherSample.whitelistEnclaveKey(pubkeys[15], image3)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});

	it("admin can rewhitelist enclave", async function() {
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(ethers.ZeroHash);

		expect(await attestationAutherSample.whitelistEnclaveKey.staticCall(pubkeys[15], image1)).to.be.true;
		await expect(attestationAutherSample.whitelistEnclaveKey(pubkeys[15], image1))
			.to.emit(attestationAutherSample, "EnclaveKeyWhitelisted").withArgs(addrs[15], image1, pubkeys[15]);
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(image1);

		expect(await attestationAutherSample.whitelistEnclaveKey.staticCall(pubkeys[15], image1)).to.be.false;
		await expect(attestationAutherSample.whitelistEnclaveKey(pubkeys[15], image1))
			.to.not.emit(attestationAutherSample, "EnclaveKeyWhitelisted");
	});
});

describe("AttestationAutherSampleUpgradeable - Revoke enclave", function() {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];

	let attestationAutherSample: AttestationAutherSampleUpgradeable;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		) as unknown as AttestationAutherSampleUpgradeable;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot revoke enclave", async function() {
		await expect(attestationAutherSample.connect(signers[1]).revokeEnclaveKey(addrs[14])).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});

	it("admin can revoke enclave", async function() {
		await attestationAutherSample.whitelistEnclaveKey(pubkeys[14], image2);
		expect(await attestationAutherSample.getVerifiedKey(addrs[14])).to.equal(image2);

		expect(await attestationAutherSample.revokeEnclaveKey.staticCall(addrs[14])).to.be.true;
		await expect(attestationAutherSample.revokeEnclaveKey(addrs[14]))
			.to.emit(attestationAutherSample, "EnclaveKeyRevoked").withArgs(addrs[14]);
		expect(await attestationAutherSample.getVerifiedKey(addrs[14])).to.equal(ethers.ZeroHash);
	});

	it("admin can revoke unwhitelisted enclave", async function() {
		expect(await attestationAutherSample.revokeEnclaveKey.staticCall(addrs[15])).to.be.false;
		await expect(attestationAutherSample.revokeEnclaveKey(addrs[14]))
			.to.not.emit(attestationAutherSample, "EnclaveKeyRevoked");
	});
});

describe("AttestationAutherSampleUpgradeable - Verify enclave key", function() {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];

	let attestationAutherSample: AttestationAutherSampleUpgradeable;
	let attestationVerifier: AttestationVerifier;

	before(async function() {
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

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [await attestationVerifier.getAddress(), 600] },
		) as unknown as AttestationAutherSampleUpgradeable;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can verify enclave key", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		expect(await attestationAutherSample.connect(signers[1]).verifyEnclaveKey.staticCall(signature, attestation)).to.be.true;
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.emit(attestationAutherSample, "EnclaveKeyVerified").withArgs(addrs[15], image3, pubkeys[15]);
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(image3);
	});

	it("cannot verify enclave key with too old attestation", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 660000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherAttestationTooOld");
	});

	it("cannot verify enclave key with invalid data", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, publicKey: pubkeys[16] }))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, imageId: image1 }))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, userData: "0x1234" }))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, imageId: image2 }))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, timestampMs: timestamp - 200000 }))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
	});

	it("cannot verify enclave key with invalid public key", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(ethers.ZeroAddress, image3, wallets[14], timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherPubkeyLengthInvalid");
	});

	it("cannot verify enclave key with unwhitelisted image", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image1, wallets[14], timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});

	it("can reverify enclave key", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		expect(await attestationAutherSample.connect(signers[1]).verifyEnclaveKey.staticCall(signature, attestation)).to.be.true;
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.emit(attestationAutherSample, "EnclaveKeyVerified").withArgs(addrs[15], image3, pubkeys[15]);
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(image3);

		expect(await attestationAutherSample.connect(signers[1]).verifyEnclaveKey.staticCall(signature, attestation)).to.be.false;
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.not.emit(attestationAutherSample, "EnclaveKeyVerified");
	});

	it("cannot verify enclave key with unwhitelisted key", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[16], timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
	});

	it("cannot verify enclave key with revoked key", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await attestationVerifier.revokeEnclaveKey(addrs[14]);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
	});

	it("cannot verify enclave key with revoked sample image", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await attestationAutherSample.revokeEnclaveImage(image3);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});

	it("cannot verify enclave key with revoked verifier image", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await attestationVerifier.revokeEnclaveImage(image1);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierImageNotWhitelisted");
	});
});

describe("AttestationAutherSampleUpgradeable - Safe verify with params", function() {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];

	let attestationAutherSample: AttestationAutherSampleUpgradeable;
	let attestationVerifier: AttestationVerifier;

	before(async function() {
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

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [await attestationVerifier.getAddress(), 600] },
		) as unknown as AttestationAutherSampleUpgradeable;

		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can verify", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(signature, "testmsg")).to.not.be.reverted;
	});

	it("cannot verify with invalid data", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "randommsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with unwhitelisted key", async function() {
		let signature = await createSignature("testmsg", wallets[14]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with revoked key", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await attestationAutherSample.revokeEnclaveKey(addrs[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with revoked image", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await attestationAutherSample.revokeEnclaveImage(image3);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});
});

describe("AttestationAutherSampleUpgradeable - Verify with family", function() {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];

	let attestationAutherSample: AttestationAutherSampleUpgradeable;
	let attestationVerifier: AttestationVerifier;

	before(async function() {
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

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSampleUpgradeable");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image2, image3], [SECOND_FAMILY, THIRD_FAMILY], addrs[0]],
			{ kind: "uups", constructorArgs: [await attestationVerifier.getAddress(), 600], initializer: "initializeWithFamilies" },
		) as unknown as AttestationAutherSampleUpgradeable;

		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can verify", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(signature, "testmsg")).to.not.be.reverted;
	});

	it("cannot verify with invalid data", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "randommsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with unwhitelisted key", async function() {
		let signature = await createSignature("testmsg", wallets[14]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with revoked key", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await attestationAutherSample.revokeEnclaveKey(addrs[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with revoked image", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await attestationAutherSample.revokeEnclaveImage(image3);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});

	it("can verify family", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verifyFamily(signature, "testmsg", THIRD_FAMILY)).to.not.be.reverted;
	});

	it("cannot verify family with invalid data", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verifyFamily(
			signature, "randommsg", THIRD_FAMILY,
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify family with unwhitelisted key", async function() {
		let signature = await createSignature("testmsg", wallets[14]);

		await expect(attestationAutherSample.connect(signers[1]).verifyFamily(
			signature, "testmsg", THIRD_FAMILY,
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify family with revoked key", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await attestationAutherSample.revokeEnclaveKey(addrs[15]);

		await expect(attestationAutherSample.connect(signers[1]).verifyFamily(
			signature, "testmsg", THIRD_FAMILY,
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify family with revoked image", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await attestationAutherSample.revokeEnclaveImage(image3);

		await expect(attestationAutherSample.connect(signers[1]).verifyFamily(
			signature, "testmsg", THIRD_FAMILY,
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});

	it("cannot verify family with wrong family", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verifyFamily(
			signature, "testmsg", SECOND_FAMILY,
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotInFamily");
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

async function createSignature(
	msg: string,
	sourceEnclaveKey: Wallet,
): Promise<string> {
	const domain = {
		name: 'marlin.oyster.AttestationAutherSample',
		version: '1',
	};

	const types = {
		Message: [
			{ name: 'message', type: 'string' },
		]
	}

	const sign = await sourceEnclaveKey.signTypedData(domain, types, {
		message: msg,
	});
	return ethers.Signature.from(sign).serialized;
}

function walletForIndex(idx: number): Wallet {
	let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

	return new Wallet(wallet.privateKey);
}
