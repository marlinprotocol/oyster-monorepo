import { deployMockContract } from "@ethereum-waffle/mock-contract";
import { expect } from "chai";
import { BigNumber as BN, Contract as MockContract, Signer } from "ethers";
import { ethers, upgrades } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

import { MPond, Pond, StakeManager } from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { getMpond, getPond, getStakeManager } from "../../utils/typechainConvertor";
import { testERC165 } from "../helpers/erc165";
import { testAdminRole, testRole } from "../helpers/rbac";

declare module "ethers" {
  interface BigNumber {
    e18(this: BigNumber): BigNumber;
  }
}
BN.prototype.e18 = function() {
  return this.mul(BN.from(10).pow(18));
};

const UNDELEGATION_WAIT_TIME = 604800;
const REDELEGATION_WAIT_TIME = 21600;
const REDELEGATION_LOCK = ethers.utils.id("REDELEGATION_LOCK");
const UNDELEGATION_LOCK = ethers.utils.id("UNDELEGATION_LOCK");

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("deploys with initialization disabled", async function() {
    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManager = await StakeManager.deploy();

    await expect(
      stakeManager.initialize(
        [ethers.utils.id(addrs[1]), ethers.utils.id(addrs[2])],
        [addrs[1], addrs[2]],
        [false, true],
        addrs[3],
        REDELEGATION_WAIT_TIME,
        UNDELEGATION_WAIT_TIME
      )
    ).to.be.reverted;
  });

  it("deploys as proxy and initializes", async function() {
    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManager = await upgrades.deployProxy(
      StakeManager,
      [
        [ethers.utils.id(addrs[1]), ethers.utils.id(addrs[2])],
        [addrs[1], addrs[2]],
        [false, true],
        addrs[3],
        REDELEGATION_WAIT_TIME,
        UNDELEGATION_WAIT_TIME,
      ],
      { kind: "uups" }
    );

    expect(await stakeManager.hasRole(await stakeManager.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    expect(await stakeManager.tokens(ethers.utils.id(addrs[1]))).to.equal(addrs[1]);
    expect(await stakeManager.tokens(ethers.utils.id(addrs[2]))).to.equal(addrs[2]);
    expect(await stakeManager.tokenIndex(ethers.utils.id(addrs[1]))).to.equal(0);
    expect(await stakeManager.tokenIndex(ethers.utils.id(addrs[2]))).to.equal(1);
    expect(await stakeManager.tokenList(0)).to.equal(ethers.utils.id(addrs[1]));
    expect(await stakeManager.tokenList(1)).to.equal(ethers.utils.id(addrs[2]));
    expect(await stakeManager.hasRole(await stakeManager.ACTIVE_TOKEN_ROLE(), addrs[1])).to.be.true;
    expect(await stakeManager.hasRole(await stakeManager.ACTIVE_TOKEN_ROLE(), addrs[2])).to.be.true;
    expect(await stakeManager.hasRole(await stakeManager.DELEGATABLE_TOKEN_ROLE(), addrs[1])).to.be.false;
    expect(await stakeManager.hasRole(await stakeManager.DELEGATABLE_TOKEN_ROLE(), addrs[2])).to.be.true;
    expect(await stakeManager.rewardDelegators()).to.equal(addrs[3]);
    expect(await stakeManager.lockWaitTime(ethers.utils.id("REDELEGATION_LOCK"))).to.equal(REDELEGATION_WAIT_TIME);
    expect(await stakeManager.lockWaitTime(ethers.utils.id("UNDELEGATION_LOCK"))).to.equal(UNDELEGATION_WAIT_TIME);
  });

  it("upgrades", async function() {
    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManager = await upgrades.deployProxy(
      StakeManager,
      [
        [ethers.utils.id(addrs[1]), ethers.utils.id(addrs[2])],
        [addrs[1], addrs[2]],
        [false, true],
        addrs[3],
        REDELEGATION_WAIT_TIME,
        UNDELEGATION_WAIT_TIME,
      ],
      { kind: "uups" }
    );
    await upgrades.upgradeProxy(stakeManager.address, StakeManager, { kind: "uups" });

    expect(await stakeManager.hasRole(await stakeManager.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    expect(await stakeManager.tokens(ethers.utils.id(addrs[1]))).to.equal(addrs[1]);
    expect(await stakeManager.tokens(ethers.utils.id(addrs[2]))).to.equal(addrs[2]);
    expect(await stakeManager.tokenIndex(ethers.utils.id(addrs[1]))).to.equal(0);
    expect(await stakeManager.tokenIndex(ethers.utils.id(addrs[2]))).to.equal(1);
    expect(await stakeManager.tokenList(0)).to.equal(ethers.utils.id(addrs[1]));
    expect(await stakeManager.tokenList(1)).to.equal(ethers.utils.id(addrs[2]));
    expect(await stakeManager.hasRole(await stakeManager.ACTIVE_TOKEN_ROLE(), addrs[1])).to.be.true;
    expect(await stakeManager.hasRole(await stakeManager.ACTIVE_TOKEN_ROLE(), addrs[2])).to.be.true;
    expect(await stakeManager.hasRole(await stakeManager.DELEGATABLE_TOKEN_ROLE(), addrs[1])).to.be.false;
    expect(await stakeManager.hasRole(await stakeManager.DELEGATABLE_TOKEN_ROLE(), addrs[2])).to.be.true;
    expect(await stakeManager.rewardDelegators()).to.equal(addrs[3]);
    expect(await stakeManager.lockWaitTime(ethers.utils.id("REDELEGATION_LOCK"))).to.equal(REDELEGATION_WAIT_TIME);
    expect(await stakeManager.lockWaitTime(ethers.utils.id("UNDELEGATION_LOCK"))).to.equal(UNDELEGATION_WAIT_TIME);
  });

  it("does not upgrade without admin", async () => {
    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManager = await upgrades.deployProxy(
      StakeManager,
      [
        [ethers.utils.id(addrs[1]), ethers.utils.id(addrs[2])],
        [addrs[1], addrs[2]],
        [false, true],
        addrs[3],
        REDELEGATION_WAIT_TIME,
        UNDELEGATION_WAIT_TIME,
      ],
      { kind: "uups" }
    );

    await expect(upgrades.upgradeProxy(stakeManager.address, StakeManager.connect(signers[1]), { kind: "uups" })).to.be.reverted;
  });
});

testERC165(
  "StakeManager",
  async function(_: Signer[], addrs: string[]) {
    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManager = await upgrades.deployProxy(
      StakeManager,
      [
        [ethers.utils.id(addrs[1]), ethers.utils.id(addrs[2])],
        [addrs[1], addrs[2]],
        [false, true],
        addrs[3],
        REDELEGATION_WAIT_TIME,
        UNDELEGATION_WAIT_TIME,
      ],
      { kind: "uups" }
    );
    return stakeManager;
  },
  {
    IAccessControl: [
      "hasRole(bytes32,address)",
      "getRoleAdmin(bytes32)",
      "grantRole(bytes32,address)",
      "revokeRole(bytes32,address)",
      "renounceRole(bytes32,address)",
    ],
    IAccessControlEnumerable: ["getRoleMember(bytes32,uint256)", "getRoleMemberCount(bytes32)"],
  }
);

testAdminRole("StakeManager", async function(_: Signer[], addrs: string[]) {
  const StakeManager = await ethers.getContractFactory("StakeManager");
  let stakeManager = await upgrades.deployProxy(
    StakeManager,
    [
      [ethers.utils.id(addrs[1]), ethers.utils.id(addrs[2])],
      [addrs[1], addrs[2]],
      [false, true],
      addrs[3],
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME,
    ],
    { kind: "uups" }
  );
  return stakeManager;
});

testRole(
  "StakeManager",
  async function(_: Signer[], addrs: string[]) {
    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManager = await upgrades.deployProxy(
      StakeManager,
      [
        [ethers.utils.id(addrs[1]), ethers.utils.id(addrs[2])],
        [addrs[1], addrs[2]],
        [false, true],
        addrs[3],
        REDELEGATION_WAIT_TIME,
        UNDELEGATION_WAIT_TIME,
      ],
      { kind: "uups" }
    );
    return stakeManager;
  },
  "DELEGATABLE_TOKEN_ROLE"
);

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;

  before(async () => {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManagerContract = await upgrades.deployProxy(
      StakeManager,
      [
        [ethers.utils.id(addrs[1]), ethers.utils.id(addrs[2])],
        [addrs[1], addrs[2]],
        [false, true],
        addrs[3],
        REDELEGATION_WAIT_TIME,
        UNDELEGATION_WAIT_TIME,
      ],
      { kind: "uups" }
    );

    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("non admin cannot update lockWaitTime", async () => {
    await expect(stakeManager.connect(signers[1]).updateLockWaitTime(REDELEGATION_LOCK, 10)).to.be.reverted;
    await expect(stakeManager.connect(signers[1]).updateLockWaitTime(UNDELEGATION_LOCK, 10)).to.be.reverted;
  });

  it("admin can update lockWaitTime", async () => {
    await stakeManager.updateLockWaitTime(REDELEGATION_LOCK, 10);
    expect(await stakeManager.lockWaitTime(REDELEGATION_LOCK)).to.equal(10);

    await stakeManager.updateLockWaitTime(UNDELEGATION_LOCK, 100);
    expect(await stakeManager.lockWaitTime(UNDELEGATION_LOCK)).to.equal(100);
  });

  it("non admin cannot update RewardDelegatorsAddress", async () => {
    await expect(stakeManager.connect(signers[1]).updateRewardDelegators(addrs[13])).to.be.reverted;
  });

  it("admin can update RewardDelegatorsAddress", async () => {
    await stakeManager.updateRewardDelegators(addrs[13]);
    expect(await stakeManager.rewardDelegators()).to.equal(addrs[13]);
  });

  it("cannot add already added token", async () => {
    await expect(stakeManager.addToken(ethers.utils.id(addrs[1]), addrs[11])).to.be.reverted;
  });

  it("cannot add token with zero address", async () => {
    await expect(stakeManager.addToken(ethers.utils.id(ethers.constants.AddressZero), ethers.constants.AddressZero)).to.be.reverted;
  });

  it("non admin cannot add token", async () => {
    await expect(stakeManager.connect(signers[1]).addToken(ethers.utils.id(addrs[11]), addrs[11])).to.be.reverted;
  });

  it("admin can add token", async () => {
    await expect(await stakeManager.addToken(ethers.utils.id(addrs[11]), addrs[11])).to.emit(stakeManager, "TokenAdded");
    expect(await stakeManager.tokens(ethers.utils.id(addrs[11]))).to.equal(addrs[11]);
    expect(await stakeManager.hasRole(ethers.utils.id("ACTIVE_TOKEN_ROLE"), addrs[11])).to.be.true;
  });

  it("cannot enable active token", async () => {
    await expect(stakeManager.enableToken(ethers.utils.id(addrs[1]))).to.be.reverted;
  });

  it("non admin cannot enable token", async () => {
    await stakeManager.disableToken(ethers.utils.id(addrs[1]));
    expect(await stakeManager.hasRole(ethers.utils.id("ACTIVE_TOKEN_ROLE"), addrs[1])).to.be.false;
    await expect(stakeManager.connect(signers[1]).enableToken(ethers.utils.id(addrs[1]))).to.be.reverted;
  });

  it("admin can enable token", async () => {
    await stakeManager.disableToken(ethers.utils.id(addrs[1]));
    expect(await stakeManager.hasRole(ethers.utils.id("ACTIVE_TOKEN_ROLE"), addrs[1])).to.be.false;
    await stakeManager.enableToken(ethers.utils.id(addrs[1]));
    expect(await stakeManager.hasRole(ethers.utils.id("ACTIVE_TOKEN_ROLE"), addrs[1])).to.be.true;
  });

  it("cannot disable inactive token", async () => {
    await stakeManager.disableToken(ethers.utils.id(addrs[1]));
    expect(await stakeManager.hasRole(ethers.utils.id("ACTIVE_TOKEN_ROLE"), addrs[1])).to.be.false;
    await expect(stakeManager.disableToken(ethers.utils.id(addrs[1]))).to.be.reverted;
  });

  it("non admin cannot disable token", async () => {
    await expect(stakeManager.connect(signers[1]).disableToken(ethers.utils.id(addrs[1]))).to.be.reverted;
  });

  it("admin can disable token", async () => {
    await stakeManager.disableToken(ethers.utils.id(addrs[1]));
    expect(await stakeManager.hasRole(ethers.utils.id("ACTIVE_TOKEN_ROLE"), addrs[1])).to.be.false;
  });

  it("cannot update token address to zero", async () => {
    await expect(stakeManager.updateToken(ethers.utils.id(addrs[1]), ethers.constants.AddressZero)).to.be.reverted;
  });

  it("cannot update non existent token", async () => {
    await expect(stakeManager.updateToken(ethers.utils.id(addrs[11]), addrs[11])).to.be.reverted;
  });

  it("non admin cannot update token", async () => {
    await expect(stakeManager.connect(signers[1]).updateToken(ethers.utils.id(addrs[1]), addrs[11])).to.be.reverted;
  });

  it("admin can update token", async () => {
    await expect(await stakeManager.updateToken(ethers.utils.id(addrs[1]), addrs[11])).to.emit(stakeManager, "TokenUpdated");
    expect(await stakeManager.tokens(ethers.utils.id(addrs[1]))).to.equal(addrs[11]);
  });
});

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;
  let pond: Pond;
  let mpond: MPond;
  let pondTokenId: String;
  let mpondTokenId: String;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);
    await stakeManager.initialize(
      ["" + pondTokenId, "" + mpondTokenId],
      [pond.address, mpond.address],
      [false, true],
      addrs[10],
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME
    );
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);

    await mpond.grantRole(ethers.utils.id("WHITELIST_ROLE"), stakeManager.address);
    await mpond.approve(stakeManager.address, 10000);
    await pond.approve(stakeManager.address, 10000);
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can create stash with pond", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId], [100]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18());
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);
  });

  it("can create stash with zero pond", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId], [0]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18());
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18());
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);
  });

  it("can create stash with mpond", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + mpondTokenId], [200]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18());
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can create stash with zero mpond", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + mpondTokenId], [0]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18());
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18());
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);
  });

  it("can create stash with pond and mpond", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can create stash with pond and zero mpond", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 0]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18());
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);
  });

  it("can create stash with mpond and zero pond", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [0, 200]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18());
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can create stash with zero pond and zero mpond", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [0, 0]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18());
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18());
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);
  });

  it("cannot create stash with mismatched token and amount lengths", async () => {
    await expect(stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [0])).to.be.reverted;
    await expect(stakeManager.createStash(["" + pondTokenId], [0, 0])).to.be.reverted;
  });

  it("cannot create empty stash", async () => {
    await expect(stakeManager.createStash([], [])).to.be.reverted;
  });

  it("cannot create stash with random token id", async () => {
    await expect(stakeManager.createStash([ethers.utils.id(addrs[11])], [100])).to.be.reverted;
  });
});

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;
  let rewardDelegators: MockContract;
  let pond: Pond;
  let mpond: MPond;
  let pondTokenId: String;
  let mpondTokenId: String;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());

    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);
    await stakeManager.initialize(
      ["" + pondTokenId, "" + mpondTokenId],
      [pond.address, mpond.address],
      [false, true],
      rewardDelegators.address,
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME
    );
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);

    await mpond.grantRole(ethers.utils.id("WHITELIST_ROLE"), stakeManager.address);
    await mpond.approve(stakeManager.address, 10000);
    await pond.approve(stakeManager.address, 10000);
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can delegate stash with pond", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId], [100]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(0));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);

    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [100, 0]).returns();

    await stakeManager.delegateStash(stashId, addrs[11]);

    stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(0));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);
  });

  it("can delegate stash with mpond", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + mpondTokenId], [200]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(0));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);

    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [0, 200]).returns();

    await stakeManager.delegateStash(stashId, addrs[11]);

    stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(0));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can delegate stash with pond and mpond", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);

    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [100, 200]).returns();

    await stakeManager.delegateStash(stashId, addrs[11]);

    stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can delegate empty stash", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + mpondTokenId], [0]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(0));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(0));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);

    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [0, 0]).returns();

    await stakeManager.delegateStash(stashId, addrs[11]);

    stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(0));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(0));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);
  });

  it("can delegate stash again after undelegation", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + mpondTokenId], [0]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);
    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(0));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(0));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);

    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [0, 0]).returns();

    await stakeManager.delegateStash(stashId, addrs[11]);

    stashInfo = await stakeManager.stashes(stashId);
    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(0));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(0));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);

    await rewardDelegators.mock.undelegate.returns();
    await stakeManager.undelegateStash(stashId);
    await time.increase(UNDELEGATION_WAIT_TIME);

    stashInfo = await stakeManager.stashes(stashId);
    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(0));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(0));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);

    await stakeManager.delegateStash(stashId, addrs[11]);

    stashInfo = await stakeManager.stashes(stashId);
    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(0));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(0));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);
  });

  it("cannot delegate stash to zero address", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.delegateStash(stashId, ethers.constants.AddressZero)).to.be.reverted;
  });

  it("cannot delegate stash that is already delegated", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    await rewardDelegators.mock.delegate.returns();

    await stakeManager.delegateStash(stashId, addrs[11]);
    await expect(stakeManager.delegateStash(stashId, addrs[11])).to.be.reverted;
  });

  it("cannot delegate stash that is being undelegated", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    await rewardDelegators.mock.delegate.returns();

    await stakeManager.delegateStash(stashId, addrs[11]);
    await rewardDelegators.mock.undelegate.returns();
    await stakeManager.undelegateStash(stashId);
    await expect(stakeManager.delegateStash(stashId, addrs[11])).to.be.reverted;
  });

  it("cannot delegate third party stash", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.connect(signers[1]).delegateStash(stashId, addrs[11])).to.be.reverted;
  });
});

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;
  let rewardDelegators: MockContract;
  let pond: Pond;
  let mpond: MPond;
  let pondTokenId: String;
  let mpondTokenId: String;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());

    const StakeManager = await ethers.getContractFactory("StakeManager");
    const stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);
    await stakeManager.initialize(
      ["" + pondTokenId, "" + mpondTokenId],
      [pond.address, mpond.address],
      [false, true],
      rewardDelegators.address,
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME
    );

    await mpond.grantRole(ethers.utils.id("WHITELIST_ROLE"), stakeManager.address);
    await mpond.approve(stakeManager.address, 10000);
    await pond.approve(stakeManager.address, 10000);
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can create and delegate stash with pond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [100, 0]).returns();

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStashAndDelegate(["" + pondTokenId], [100], addrs[11]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18());
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);
  });

  it("can create and delegate stash with zero pond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [0, 0]).returns();

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStashAndDelegate(["" + pondTokenId], [0], addrs[11]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18());
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18());
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);
  });

  it("can create and delegate stash with mpond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [0, 200]).returns();

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStashAndDelegate(["" + mpondTokenId], [200], addrs[11]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18());
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can create and delegate stash with zero mpond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [0, 0]).returns();

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStashAndDelegate(["" + mpondTokenId], [0], addrs[11]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18());
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18());
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);
  });

  it("can create and delegate stash with pond and mpond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [100, 200]).returns();

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [100, 200], addrs[11]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can create and delegate stash with pond and zero mpond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [100, 0]).returns();

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [100, 0], addrs[11]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18());
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);
  });

  it("can create and delegate stash with mpond and zero pond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [0, 200]).returns();

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [0, 200], addrs[11]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18());
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can create and delegate stash with zero pond and zero mpond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [0, 0]).returns();

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [0, 0], addrs[11]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes(stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts(stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18());
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18());
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);
  });

  it("cannot create and delegate stash with pond to zero address", async () => {
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.createStashAndDelegate(["" + pondTokenId], [100], ethers.constants.AddressZero)).to.be.reverted;
  });

  it("cannot create and delegate stash with zero pond to zero address", async () => {
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.createStashAndDelegate(["" + pondTokenId], [0], ethers.constants.AddressZero)).to.be.reverted;
  });

  it("cannot create and delegate stash with mpond to zero address", async () => {
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.createStashAndDelegate(["" + mpondTokenId], [200], ethers.constants.AddressZero)).to.be.reverted;
  });

  it("cannot create and delegate stash with zero mpond to zero address", async () => {
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.createStashAndDelegate(["" + mpondTokenId], [0], ethers.constants.AddressZero)).to.be.reverted;
  });

  it("cannot create and delegate stash with pond and mpond to zero address", async () => {
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [100, 200], ethers.constants.AddressZero)).to.be
      .reverted;
  });

  it("cannot create and delegate stash with pond and zero mpond to zero address", async () => {
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [100, 0], ethers.constants.AddressZero)).to.be
      .reverted;
  });

  it("cannot create and delegate stash with mpond and zero pond to zero address", async () => {
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [0, 200], ethers.constants.AddressZero)).to.be
      .reverted;
  });

  it("cannot create and delegate stash with zero pond and zero mpond to zero address", async () => {
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [0, 0], ethers.constants.AddressZero)).to.be
      .reverted;
  });

  it("cannot create and delegate stash with mismatched token and amount lengths", async () => {
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [0], addrs[11])).to.be.reverted;
    await expect(stakeManager.createStash(["" + pondTokenId], [0, 0])).to.be.reverted;
  });

  it("cannot create and delegate empty stash", async () => {
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.createStashAndDelegate([], [], addrs[11])).to.be.reverted;
  });

  it("cannot create and delegate stash with random token id", async () => {
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.createStashAndDelegate([ethers.utils.id(addrs[11])], [100], addrs[11])).to.be.reverted;
  });
});

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;
  let pond: Pond;
  let mpond: MPond;
  let pondTokenId: String;
  let mpondTokenId: String;
  let stashId: String;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);
    await stakeManager.initialize(
      ["" + pondTokenId, "" + mpondTokenId],
      [pond.address, mpond.address],
      [false, true],
      addrs[10],
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME
    );

    await mpond.grantRole(ethers.utils.id("WHITELIST_ROLE"), stakeManager.address);
    await mpond.approve(stakeManager.address, 10000);
    await pond.approve(stakeManager.address, 10000);

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can add to undelegated stash with pond", async () => {
    await stakeManager.addToStash("" + stashId, ["" + pondTokenId], [50]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(150);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(150);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(150));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can add to undelegated stash with zero pond", async () => {
    await stakeManager.addToStash("" + stashId, ["" + pondTokenId], [0]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can add to undelegated stash with mpond", async () => {
    await stakeManager.addToStash("" + stashId, ["" + mpondTokenId], [150]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(350);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(350);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(350));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(350);
  });

  it("can add to undelegated stash with zero mpond", async () => {
    await stakeManager.addToStash("" + stashId, ["" + mpondTokenId], [0]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can add to undelegated stash with pond and mpond", async () => {
    await stakeManager.addToStash("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [50, 150]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(150);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(350);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(150);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(350);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(150));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(350));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(350);
  });

  it("can add to undelegated stash with pond and zero mpond", async () => {
    await stakeManager.addToStash("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [50, 0]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(150);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(150);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(150));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can add to undelegated stash with mpond and zero pond", async () => {
    await stakeManager.addToStash("" + stashId, ["" + mpondTokenId, "" + pondTokenId], [150, 0]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(350);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(350);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(350));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(350);
  });

  it("can add to undelegated stash with zero pond and zero mpond", async () => {
    await stakeManager.addToStash("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [0, 0]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("cannot add to undelegated stash with mismatched token and amount lengths", async () => {
    await expect(stakeManager.addToStash("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [0])).to.be.reverted;
    await expect(stakeManager.addToStash("" + stashId, ["" + pondTokenId], [0, 0])).to.be.reverted;
  });

  // it("cannot add to undelegated stash with nothing", async () => {
  //   await expect(stakeManager.addToStash(""+stashId, [], [])).to.be.reverted;
  // });

  it("cannot add to undelegated stash with random token id", async () => {
    await expect(stakeManager.addToStash("" + stashId, [ethers.utils.id(addrs[11])], [100])).to.be.reverted;
  });

  it("cannot add to third party stash", async () => {
    await expect(stakeManager.connect(signers[1]).addToStash("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [0, 0])).to.be.reverted;
  });
});

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;
  let rewardDelegators: MockContract;
  let pond: Pond;
  let mpond: MPond;
  let pondTokenId: String;
  let mpondTokenId: String;
  let stashId: String;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());
    await rewardDelegators.mock.delegate.returns();
    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);
    await stakeManager.initialize(
      ["" + pondTokenId, "" + mpondTokenId],
      [pond.address, mpond.address],
      [false, true],
      rewardDelegators.address,
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME
    );
    await mpond.grantRole(ethers.utils.id("WHITELIST_ROLE"), stakeManager.address);
    await mpond.approve(stakeManager.address, 10000);
    await pond.approve(stakeManager.address, 10000);

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    await stakeManager.delegateStash("" + stashId, addrs[11]);
    await rewardDelegators.mock.delegate.reverts();

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can add to delegated stash with pond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId], [50]).returns();

    await stakeManager.addToStash("" + stashId, ["" + pondTokenId], [50]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(150);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(150);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(150));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can add to delegated stash with zero pond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], [pondTokenId], [0]).returns();

    await stakeManager.addToStash("" + stashId, ["" + pondTokenId], [0]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can add to delegated stash with mpond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], ["" + mpondTokenId], [150]).returns();

    await stakeManager.addToStash("" + stashId, ["" + mpondTokenId], [150]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(350);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(350);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(350));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(350);
  });

  it("can add to delegated stash with zero mpond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], ["" + mpondTokenId], [0]).returns();

    await stakeManager.addToStash("" + stashId, ["" + mpondTokenId], [0]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can add to delegated stash with pond and mpond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], ["" + pondTokenId, "" + mpondTokenId], [50, 150]).returns();

    await stakeManager.addToStash("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [50, 150]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(150);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(350);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(150);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(350);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(150));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(350));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(350);
  });

  it("can add to delegated stash with pond and zero mpond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], ["" + pondTokenId, "" + mpondTokenId], [50, 0]).returns();

    await stakeManager.addToStash("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [50, 0]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(150);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(150);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(150));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can add to delegated stash with mpond and zero pond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], ["" + mpondTokenId, "" + pondTokenId], [150, 0]).returns();

    await stakeManager.addToStash("" + stashId, ["" + mpondTokenId, "" + pondTokenId], [150, 0]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(350);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(350);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(350));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(350);
  });

  it("can add to delegated stash with zero pond and zero mpond", async () => {
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[11], ["" + pondTokenId, "" + mpondTokenId], [0, 0]).returns();

    await stakeManager.addToStash("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [0, 0]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("cannot add to delegated stash with mismatched token and amount lengths", async () => {
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.addToStash("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [0])).to.be.reverted;
    await expect(stakeManager.addToStash("" + stashId, ["" + pondTokenId], [0, 0])).to.be.reverted;
  });

  // it("cannot add to delegated stash with nothing", async () => {
  //   await rewardDelegators.mock.delegate.returns();

  //   await expect(stakeManager.addToStash(stashId, [], [])).to.be.reverted;
  // });

  it("cannot add to delegated stash with random token id", async () => {
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.addToStash("" + stashId, [ethers.utils.id(addrs[11])], [100])).to.be.reverted;
  });

  it("cannot add to third party stash", async () => {
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.connect(signers[1]).addToStash("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [0, 0])).to.be.reverted;
  });
});

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;
  let rewardDelegators: MockContract;
  let pond: Pond;
  let mpond: MPond;
  let pondTokenId: String;
  let mpondTokenId: String;
  let stashId: String;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());
    await rewardDelegators.mock.delegate.returns();
    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);

    await stakeManager.initialize(
      ["" + pondTokenId, "" + mpondTokenId],
      [pond.address, mpond.address],
      [false, true],
      rewardDelegators.address,
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME
    );
    await mpond.grantRole(ethers.utils.id("WHITELIST_ROLE"), stakeManager.address);
    await mpond.approve(stakeManager.address, 10000);
    await pond.approve(stakeManager.address, 10000);

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    await stakeManager.delegateStash("" + stashId, addrs[11]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);

    await rewardDelegators.mock.delegate.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can request stash redelegation", async () => {
    await stakeManager.requestStashRedelegation("" + stashId, addrs[21]);
  });

  it("cannot request redelegation to zero address", async () => {
    await expect(stakeManager.requestStashRedelegation("" + stashId, ethers.constants.AddressZero)).to.be.reverted;
  });

  it("cannot request redelegation if already requested", async () => {
    await stakeManager.requestStashRedelegation("" + stashId, addrs[21]);
    await expect(stakeManager.requestStashRedelegation("" + stashId, addrs[21])).to.be.reverted;
  });

  it("cannot request redelegation if never delegated", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    let newStashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));

    await expect(stakeManager.requestStashRedelegation(newStashId, addrs[21])).to.be.reverted;
  });

  it("cannot request redelegation if undelegation initiated", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await stakeManager.undelegateStash("" + stashId);
    await rewardDelegators.mock.undelegate.reverts();

    await expect(stakeManager.requestStashRedelegation("" + stashId, addrs[21])).to.be.reverted;
  });

  it("cannot request redelegation if undelegated", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await stakeManager.undelegateStash("" + stashId);
    await time.increase(UNDELEGATION_WAIT_TIME);
    await rewardDelegators.mock.undelegate.reverts();

    await expect(stakeManager.requestStashRedelegation("" + stashId, addrs[21])).to.be.reverted;
  });

  it("cannot request redelegation for third party stash", async () => {
    await expect(stakeManager.connect(signers[1]).requestStashRedelegation("" + stashId, addrs[21])).to.be.reverted;
  });
});

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;
  let rewardDelegators: MockContract;
  let pond: Pond;
  let mpond: MPond;
  let pondTokenId: String;
  let mpondTokenId: String;
  let stashId: String;
  let otherStashId: String;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());
    await rewardDelegators.mock.delegate.returns();
    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);

    await stakeManager.initialize(
      ["" + pondTokenId, "" + mpondTokenId],
      [pond.address, mpond.address],
      [false, true],
      rewardDelegators.address,
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME
    );
    await mpond.grantRole(ethers.utils.id("WHITELIST_ROLE"), stakeManager.address);
    await mpond.approve(stakeManager.address, 10000);
    await pond.approve(stakeManager.address, 10000);

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [100, 200], addrs[11]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));
    stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);

    await stakeManager.createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [100, 200], addrs[12]);
    otherStashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex.add(1)]));

    await rewardDelegators.mock.delegate.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can request multiple redelegations", async () => {
    await stakeManager.requestStashRedelegations(["" + stashId, "" + otherStashId], [addrs[21], addrs[22]]);
  });

  it("cannot request multiple redelegations to zero address", async () => {
    await expect(stakeManager.requestStashRedelegations(["" + stashId, "" + otherStashId], [addrs[21], ethers.constants.AddressZero])).to.be
      .reverted;
    await expect(stakeManager.requestStashRedelegations(["" + stashId, "" + otherStashId], [ethers.constants.AddressZero, addrs[22]])).to.be
      .reverted;
    await expect(
      stakeManager.requestStashRedelegations(
        ["" + stashId, "" + otherStashId],
        [ethers.constants.AddressZero, ethers.constants.AddressZero]
      )
    ).to.be.reverted;
  });

  it("cannot request multiple redelegations if never delegated", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    let newStashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));

    await expect(stakeManager.requestStashRedelegations(["" + stashId, newStashId], [addrs[21], addrs[22]])).to.be.reverted;
  });

  it("cannot request multiple redelegations if undelegation initiated", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await stakeManager.undelegateStash("" + stashId);
    await rewardDelegators.mock.undelegate.reverts();

    await expect(stakeManager.requestStashRedelegations(["" + stashId, "" + otherStashId], [addrs[21], addrs[22]])).to.be.reverted;
  });

  it("cannot request multiple redelegations if undelegated", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await stakeManager.undelegateStash("" + stashId);
    await time.increase(UNDELEGATION_WAIT_TIME);
    await rewardDelegators.mock.undelegate.reverts();

    await expect(stakeManager.requestStashRedelegations(["" + stashId, "" + otherStashId], [addrs[21], addrs[22]])).to.be.reverted;
  });

  it("cannot request multiple redelegations for third party stash", async () => {
    await expect(stakeManager.connect(signers[1]).requestStashRedelegations(["" + stashId, "" + otherStashId], [addrs[21], addrs[22]])).to
      .be.reverted;
  });

  it("cannot request multiple redelegations with mismatched lengths", async () => {
    await expect(stakeManager.requestStashRedelegations(["" + stashId, "" + otherStashId], [addrs[21]])).to.be.reverted;
    await expect(stakeManager.requestStashRedelegations(["" + stashId], [addrs[21], addrs[22]])).to.be.reverted;
  });
});

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;
  let rewardDelegators: MockContract;
  let pond: Pond;
  let mpond: MPond;
  let pondTokenId: String;
  let mpondTokenId: String;
  let stashId: String;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());
    await rewardDelegators.mock.delegate.returns();
    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);

    await stakeManager.initialize(
      ["" + pondTokenId, "" + mpondTokenId],
      [pond.address, mpond.address],
      [false, true],
      rewardDelegators.address,
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME
    );
    await mpond.grantRole(ethers.utils.id("WHITELIST_ROLE"), stakeManager.address);
    await mpond.approve(stakeManager.address, 10000);
    await pond.approve(stakeManager.address, 10000);

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    await stakeManager.delegateStash("" + stashId, addrs[11]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);

    await rewardDelegators.mock.delegate.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can redelegate after redelegation time", async () => {
    await rewardDelegators.mock.undelegate.reverts();
    await rewardDelegators.mock.undelegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [100, 200]).returns();
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[21], [pondTokenId, mpondTokenId], [100, 200]).returns();

    await stakeManager.requestStashRedelegation("" + stashId, addrs[21]);

    await time.increase(REDELEGATION_WAIT_TIME);

    await stakeManager.redelegateStash("" + stashId);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[21]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("cannot redelegate before redelegation time", async () => {
    await rewardDelegators.mock.undelegate.reverts();
    await rewardDelegators.mock.undelegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [100, 200]).returns();
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[21], [pondTokenId, mpondTokenId], [100, 200]).returns();

    await stakeManager.requestStashRedelegation("" + stashId, addrs[21]);

    await time.increase(REDELEGATION_WAIT_TIME - 5);

    await expect(stakeManager.redelegateStash("" + stashId)).to.be.reverted;
  });

  it("cannot redelegate without request", async () => {
    await rewardDelegators.mock.undelegate.reverts();
    await rewardDelegators.mock.undelegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [100, 200]).returns();
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[21], [pondTokenId, mpondTokenId], [100, 200]).returns();

    await time.increase(REDELEGATION_WAIT_TIME);

    await expect(stakeManager.redelegateStash("" + stashId)).to.be.reverted;
  });

  it("cannot redelegate if undelegated after request", async () => {
    await rewardDelegators.mock.undelegate.reverts();
    await rewardDelegators.mock.undelegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [100, 200]).returns();
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[21], [pondTokenId, mpondTokenId], [100, 200]).returns();

    await stakeManager.requestStashRedelegation("" + stashId, addrs[21]);
    await stakeManager.undelegateStash("" + stashId);

    await time.increase(REDELEGATION_WAIT_TIME);

    await expect(stakeManager.redelegateStash("" + stashId)).to.be.reverted;
  });

  it("cannot redelegate if request is cancelled", async () => {
    await rewardDelegators.mock.undelegate.reverts();
    await rewardDelegators.mock.undelegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [100, 200]).returns();
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[21], [pondTokenId, mpondTokenId], [100, 200]).returns();

    await stakeManager.requestStashRedelegation("" + stashId, addrs[21]);
    await stakeManager.cancelRedelegation("" + stashId);

    await time.increase(REDELEGATION_WAIT_TIME);

    await expect(stakeManager.redelegateStash("" + stashId)).to.be.reverted;
  });

  it("cannot redelegate third party stash", async () => {
    await rewardDelegators.mock.undelegate.reverts();
    await rewardDelegators.mock.undelegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [100, 200]).returns();
    await rewardDelegators.mock.delegate.reverts();
    await rewardDelegators.mock.delegate.withArgs(addrs[0], addrs[21], [pondTokenId, mpondTokenId], [100, 200]).returns();

    await stakeManager.requestStashRedelegation("" + stashId, addrs[21]);

    await time.increase(REDELEGATION_WAIT_TIME);

    await expect(stakeManager.connect(signers[1]).redelegateStashes(["" + stashId])).to.be.reverted;
  });
});

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;
  let rewardDelegators: MockContract;
  let pond: Pond;
  let mpond: MPond;
  let pondTokenId: String;
  let mpondTokenId: String;
  let stashId: String;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());
    await rewardDelegators.mock.delegate.returns();
    const StakeManager = await ethers.getContractFactory("StakeManager");
    const stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);
    await stakeManager.initialize(
      ["" + pondTokenId, "" + mpondTokenId],
      [pond.address, mpond.address],
      [false, true],
      rewardDelegators.address,
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME
    );
    await mpond.grantRole(ethers.utils.id("WHITELIST_ROLE"), stakeManager.address);
    await mpond.approve(stakeManager.address, 10000);
    await pond.approve(stakeManager.address, 10000);

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    await stakeManager.delegateStash("" + stashId, addrs[11]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);

    await rewardDelegators.mock.delegate.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can cancel redelegation after redelegation time", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await rewardDelegators.mock.delegate.returns();

    await stakeManager.requestStashRedelegation("" + stashId, addrs[21]);

    await time.increase(REDELEGATION_WAIT_TIME);

    await stakeManager.cancelRedelegation("" + stashId);

    await expect(stakeManager.redelegateStash("" + stashId)).to.be.reverted;
  });

  it("can cancel redelegation before redelegation time", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await rewardDelegators.mock.delegate.returns();

    await stakeManager.requestStashRedelegation("" + stashId, addrs[21]);

    await time.increase(REDELEGATION_WAIT_TIME - 10);

    await stakeManager.cancelRedelegation("" + stashId);

    await time.increase(10);

    await expect(stakeManager.redelegateStash("" + stashId)).to.be.reverted;
  });

  it("cannot cancel redelegation without request", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await rewardDelegators.mock.delegate.returns();

    await time.increase(REDELEGATION_WAIT_TIME);

    await expect(stakeManager.cancelRedelegation("" + stashId)).to.be.reverted;
  });

  it("cannot cancel redelegation for third party stash", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await rewardDelegators.mock.delegate.returns();

    await stakeManager.requestStashRedelegation("" + stashId, addrs[21]);

    await time.increase(REDELEGATION_WAIT_TIME);

    await expect(stakeManager.connect(signers[1]).cancelRedelegation("" + stashId)).to.be.reverted;
  });
});

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;
  let rewardDelegators: MockContract;
  let pond: Pond;
  let mpond: MPond;
  let pondTokenId: String;
  let mpondTokenId: String;
  let stashId: String;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());
    await rewardDelegators.mock.delegate.returns();
    const StakeManager = await ethers.getContractFactory("StakeManager");
    const stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);

    await stakeManager.initialize(
      ["" + pondTokenId, "" + mpondTokenId],
      [pond.address, mpond.address],
      [false, true],
      rewardDelegators.address,
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME
    );
    await mpond.grantRole(ethers.utils.id("WHITELIST_ROLE"), stakeManager.address);
    await mpond.approve(stakeManager.address, 10000);
    await pond.approve(stakeManager.address, 10000);

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    await stakeManager.delegateStash("" + stashId, addrs[11]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);

    await rewardDelegators.mock.delegate.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can split stash", async () => {
    const stashIndex = await stakeManager.stashIndex();

    await stakeManager.splitStash("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [75, 150]);

    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    let newStashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(25);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(50);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);

    let newStashInfo = await stakeManager.stashes(newStashId);

    expect(newStashInfo.staker).to.equal(addrs[0]);
    expect(newStashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts(newStashId, "" + pondTokenId)).to.equal(75);
    expect(await stakeManager.stashes__amounts(newStashId, "" + mpondTokenId)).to.equal(150);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("cannot split stash with nothing", async () => {
    await expect(stakeManager.splitStash("" + stashId, [], [])).to.be.reverted;
  });

  it("cannot split stash with mismatched lengths", async () => {
    await expect(stakeManager.splitStash("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [75])).to.be.reverted;
    await expect(stakeManager.splitStash("" + stashId, ["" + pondTokenId], [75, 150])).to.be.reverted;
  });

  it("cannot split stash with more tokens than in stash", async () => {
    await expect(stakeManager.splitStash("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [101, 201])).to.be.reverted;
  });

  it("cannot split third party stash", async () => {
    await expect(stakeManager.connect(signers[1]).splitStash("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [75, 150])).to.be
      .reverted;
  });
});

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;
  let rewardDelegators: MockContract;
  let pond: Pond;
  let mpond: MPond;
  let pondTokenId: String;
  let mpondTokenId: String;
  let stashId: String;
  let otherStashId: String;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());
    await rewardDelegators.mock.delegate.returns();
    const StakeManager = await ethers.getContractFactory("StakeManager");
    const stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);

    await stakeManager.initialize(
      ["" + pondTokenId, "" + mpondTokenId],
      [pond.address, mpond.address],
      [false, true],
      rewardDelegators.address,
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME
    );
    await mpond.grantRole(ethers.utils.id("WHITELIST_ROLE"), stakeManager.address);
    await mpond.approve(stakeManager.address, 10000);
    await pond.approve(stakeManager.address, 10000);

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [100, 200], addrs[11]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));
    stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);

    await stakeManager.createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [75, 150], addrs[11]);
    otherStashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex.add(1)]));

    await rewardDelegators.mock.delegate.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can merge", async () => {
    await stakeManager.mergeStash("" + stashId, "" + otherStashId);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(175);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(350);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(175);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(350);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(175));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(350));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(350);

    let otherStashInfo = await stakeManager.stashes("" + otherStashId);

    expect(otherStashInfo.staker).to.equal(ethers.constants.AddressZero);
    expect(otherStashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts("" + otherStashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts("" + otherStashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(175);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(350);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(175));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(350));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(350);
  });

  it("cannot merge stash with itself", async () => {
    await expect(stakeManager.mergeStash("" + stashId, "" + stashId)).to.be.reverted;
  });

  it("cannot merge stashes delegated to different clusters", async () => {
    await rewardDelegators.mock.delegate.returns();
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [100, 200], addrs[12]);
    let newStashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));

    await expect(stakeManager.mergeStash("" + stashId, newStashId)).to.be.reverted;
    await expect(stakeManager.mergeStash(newStashId, "" + stashId)).to.be.reverted;
  });

  it("cannot merge if one is never delegated", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    let newStashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));

    await expect(stakeManager.mergeStash("" + stashId, newStashId)).to.be.reverted;
    await expect(stakeManager.mergeStash(newStashId, "" + stashId)).to.be.reverted;
  });

  it("cannot merge if one is being undelegated", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await stakeManager.undelegateStash("" + stashId);

    await expect(stakeManager.mergeStash("" + stashId, "" + otherStashId)).to.be.reverted;
    await expect(stakeManager.mergeStash("" + otherStashId, "" + stashId)).to.be.reverted;
  });

  it("cannot merge if one is being redelegated", async () => {
    await stakeManager.requestStashRedelegation("" + stashId, addrs[12]);

    await expect(stakeManager.mergeStash("" + stashId, "" + otherStashId)).to.be.reverted;
    await expect(stakeManager.mergeStash("" + otherStashId, "" + stashId)).to.be.reverted;
  });

  it("cannot merge if one is third party", async () => {
    await rewardDelegators.mock.delegate.returns();
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.connect(signers[1]).createStashAndDelegate(["" + pondTokenId, "" + mpondTokenId], [0, 0], addrs[11]);
    let newStashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));

    await expect(stakeManager.mergeStash("" + stashId, "" + newStashId)).to.be.reverted;
    await expect(stakeManager.mergeStash("" + newStashId, "" + stashId)).to.be.reverted;
  });
});

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;
  let rewardDelegators: MockContract;
  let pond: Pond;
  let mpond: MPond;
  let pondTokenId: String;
  let mpondTokenId: String;
  let stashId: String;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());
    await rewardDelegators.mock.delegate.returns();
    const StakeManager = await ethers.getContractFactory("StakeManager");
    const stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);
    await stakeManager.initialize(
      ["" + pondTokenId, "" + mpondTokenId],
      [pond.address, mpond.address],
      [false, true],
      rewardDelegators.address,
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME
    );
    await mpond.grantRole(ethers.utils.id("WHITELIST_ROLE"), stakeManager.address);
    await mpond.approve(stakeManager.address, 10000);
    await pond.approve(stakeManager.address, 10000);

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    await stakeManager.delegateStash("" + stashId, addrs[11]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);

    await rewardDelegators.mock.delegate.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can request undelegation", async () => {
    await rewardDelegators.mock.undelegate.reverts();
    await rewardDelegators.mock.undelegate.withArgs(addrs[0], addrs[11], [pondTokenId, mpondTokenId], [100, 200]).returns();
    await stakeManager.undelegateStash("" + stashId);
  });

  it("cannot request undelegation if already requested", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await stakeManager.undelegateStash("" + stashId);
    await expect(stakeManager.undelegateStash("" + stashId)).to.be.reverted;
  });

  it("cannot request undelegation if never delegated", async () => {
    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    let newStashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));

    await rewardDelegators.mock.undelegate.returns();
    await expect(stakeManager.undelegateStash(newStashId)).to.be.reverted;
  });

  it("cannot request undelegation if undelegated", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await stakeManager.undelegateStash("" + stashId);
    await time.increase(UNDELEGATION_WAIT_TIME);

    await expect(stakeManager.undelegateStash("" + stashId)).to.be.reverted;
  });

  it("cannot request undelegation for third party stash", async () => {
    await expect(stakeManager.connect(signers[1]).undelegateStashes(["" + stashId])).to.be.reverted;
  });
});

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;
  let rewardDelegators: MockContract;
  let pond: Pond;
  let mpond: MPond;
  let pondTokenId: String;
  let mpondTokenId: String;
  let stashId: String;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());
    await rewardDelegators.mock.delegate.returns();
    const StakeManager = await ethers.getContractFactory("StakeManager");
    const stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);
    await stakeManager.initialize(
      ["" + pondTokenId, "" + mpondTokenId],
      [pond.address, mpond.address],
      [false, true],
      rewardDelegators.address,
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME
    );
    await mpond.grantRole(ethers.utils.id("WHITELIST_ROLE"), stakeManager.address);
    await mpond.approve(stakeManager.address, 10000);
    await pond.approve(stakeManager.address, 10000);

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    await stakeManager.delegateStash("" + stashId, addrs[11]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);

    await rewardDelegators.mock.delegate.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can cancel undelegation before undelegation time", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await rewardDelegators.mock.delegate.returns();

    await stakeManager.undelegateStash("" + stashId);

    await time.increase(UNDELEGATION_WAIT_TIME - 10);

    await stakeManager.cancelUndelegation("" + stashId);

    await time.increase(10);

    await expect(stakeManager["withdrawStash(bytes32)"]("" + stashId)).to.be.reverted;
  });

  it("cannot cancel undelegation after undelegation time", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await rewardDelegators.mock.delegate.returns();

    await stakeManager.undelegateStash("" + stashId);

    await time.increase(UNDELEGATION_WAIT_TIME);

    await expect(stakeManager.cancelUndelegation("" + stashId)).to.be.reverted;
  });

  it("cannot cancel undelegation without request", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await rewardDelegators.mock.delegate.returns();

    await expect(stakeManager.cancelUndelegation("" + stashId)).to.be.reverted;
  });

  it("cannot cancel undelegation for third party stash", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await rewardDelegators.mock.delegate.returns();

    await stakeManager.undelegateStash("" + stashId);

    await expect(stakeManager.connect(signers[1]).cancelUndelegation("" + stashId)).to.be.reverted;
  });
});

describe("StakeManager", function() {
  let signers: Signer[];
  let addrs: string[];
  let stakeManager: StakeManager;
  let rewardDelegators: MockContract;
  let pond: Pond;
  let mpond: MPond;
  let pondTokenId: String;
  let mpondTokenId: String;
  let stashId: String;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    const Pond = await ethers.getContractFactory("Pond");
    let pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], { kind: "uups" });
    pond = getPond(pondContract.address, signers[0]);

    const MPond = await ethers.getContractFactory("MPond");
    let mpondContract = await upgrades.deployProxy(MPond, { kind: "uups" });
    mpond = getMpond(mpondContract.address, signers[0]);

    pondTokenId = ethers.utils.keccak256(pond.address);
    mpondTokenId = ethers.utils.keccak256(mpond.address);

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());
    await rewardDelegators.mock.delegate.returns();
    const StakeManager = await ethers.getContractFactory("StakeManager");
    let stakeManagerContract = await upgrades.deployProxy(StakeManager, { kind: "uups", initializer: false });
    stakeManager = getStakeManager(stakeManagerContract.address, signers[0]);
    await stakeManager.initialize(
      ["" + pondTokenId, "" + mpondTokenId],
      [pond.address, mpond.address],
      [false, true],
      rewardDelegators.address,
      REDELEGATION_WAIT_TIME,
      UNDELEGATION_WAIT_TIME
    );
    await mpond.grantRole(ethers.utils.id("WHITELIST_ROLE"), stakeManager.address);
    await mpond.approve(stakeManager.address, 10000);
    await pond.approve(stakeManager.address, 10000);

    const stashIndex = await stakeManager.stashIndex();
    await stakeManager.createStash(["" + pondTokenId, "" + mpondTokenId], [100, 200]);
    expect(await stakeManager.stashIndex()).to.equal(BN.from(stashIndex).add(1));

    stashId = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["uint256"], [stashIndex]));
    await stakeManager.delegateStash("" + stashId, addrs[11]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(addrs[11]);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);

    await rewardDelegators.mock.delegate.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can withdraw all after undelegation time", async () => {
    await rewardDelegators.mock.undelegate.returns();

    await stakeManager.undelegateStash("" + stashId);

    await time.increase(UNDELEGATION_WAIT_TIME);

    await stakeManager["withdrawStash(bytes32)"]("" + stashId);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(0);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(0);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(0);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(0));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(0));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(0);
  });

  it("can withdraw all after undelegation time", async () => {
    await rewardDelegators.mock.undelegate.returns();

    await stakeManager.undelegateStash("" + stashId);

    await time.increase(UNDELEGATION_WAIT_TIME);

    await stakeManager["withdrawStash(bytes32,bytes32[],uint256[])"]("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [0, 0]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can withdraw pond after undelegation time", async () => {
    await rewardDelegators.mock.undelegate.returns();

    await stakeManager.undelegateStash("" + stashId);

    await time.increase(UNDELEGATION_WAIT_TIME);

    await stakeManager["withdrawStash(bytes32,bytes32[],uint256[])"]("" + stashId, ["" + pondTokenId], [50]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(50);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(200);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(50);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(200);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(50));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(200));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(200);
  });

  it("can withdraw mpond after undelegation time", async () => {
    await rewardDelegators.mock.undelegate.returns();

    await stakeManager.undelegateStash("" + stashId);

    await time.increase(UNDELEGATION_WAIT_TIME);

    await stakeManager["withdrawStash(bytes32,bytes32[],uint256[])"]("" + stashId, ["" + mpondTokenId], [150]);

    let stashInfo = await stakeManager.stashes("" + stashId);

    expect(stashInfo.staker).to.equal(addrs[0]);
    expect(stashInfo.delegatedCluster).to.equal(ethers.constants.AddressZero);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + pondTokenId)).to.equal(100);
    expect(await stakeManager.stashes__amounts("" + stashId, "" + mpondTokenId)).to.equal(50);
    expect(await pond.balanceOf(stakeManager.address)).to.equal(100);
    expect(await mpond.balanceOf(stakeManager.address)).to.equal(50);
    expect(await pond.balanceOf(addrs[0])).to.equal(BN.from(1e10).e18().sub(100));
    expect(await mpond.balanceOf(addrs[0])).to.equal(BN.from(1e4).e18().sub(50));
    expect(await mpond.getDelegates(stakeManager.address, addrs[0])).to.equal(50);
  });

  it("cannot withdraw with mismtached lengths", async () => {
    await rewardDelegators.mock.undelegate.returns();

    await stakeManager.undelegateStash("" + stashId);

    await time.increase(UNDELEGATION_WAIT_TIME);

    await expect(stakeManager["withdrawStash(bytes32,bytes32[],uint256[])"]("" + stashId, ["" + mpondTokenId], [100, 150])).to.be.reverted;
    await expect(stakeManager["withdrawStash(bytes32,bytes32[],uint256[])"]("" + stashId, ["" + pondTokenId, "" + mpondTokenId], [150])).to
      .be.reverted;
  });

  it("cannot withdraw before undelegation time", async () => {
    await rewardDelegators.mock.undelegate.returns();

    await stakeManager.undelegateStash("" + stashId);

    await time.increase(UNDELEGATION_WAIT_TIME - 10);

    await expect(stakeManager["withdrawStash(bytes32)"]("" + stashId)).to.be.reverted;
    await expect(stakeManager["withdrawStash(bytes32,bytes32[],uint256[])"]("" + stashId, ["" + pondTokenId], [50])).to.be.reverted;
    await expect(stakeManager["withdrawStash(bytes32,bytes32[],uint256[])"]("" + stashId, ["" + mpondTokenId], [50])).to.be.reverted;
  });

  it("cannot withdraw without request", async () => {
    await rewardDelegators.mock.undelegate.returns();

    await time.increase(UNDELEGATION_WAIT_TIME);

    await expect(stakeManager["withdrawStash(bytes32)"]("" + stashId)).to.be.reverted;
    await expect(stakeManager["withdrawStash(bytes32,bytes32[],uint256[])"]("" + stashId, ["" + pondTokenId], [50])).to.be.reverted;
    await expect(stakeManager["withdrawStash(bytes32,bytes32[],uint256[])"]("" + stashId, ["" + mpondTokenId], [50])).to.be.reverted;
  });

  it("cannot withdraw if request is cancelled", async () => {
    await rewardDelegators.mock.undelegate.returns();
    await rewardDelegators.mock.delegate.returns();

    await stakeManager.undelegateStash("" + stashId);
    await stakeManager.cancelUndelegation("" + stashId);

    await time.increase(UNDELEGATION_WAIT_TIME);

    await expect(stakeManager["withdrawStash(bytes32)"]("" + stashId)).to.be.reverted;
    await expect(stakeManager["withdrawStash(bytes32,bytes32[],uint256[])"]("" + stashId, ["" + pondTokenId], [50])).to.be.reverted;
    await expect(stakeManager["withdrawStash(bytes32,bytes32[],uint256[])"]("" + stashId, ["" + mpondTokenId], [50])).to.be.reverted;
  });

  it("cannot withdraw third party stash", async () => {
    await rewardDelegators.mock.undelegate.returns();

    await stakeManager.undelegateStash("" + stashId);

    await time.increase(UNDELEGATION_WAIT_TIME);

    await expect(stakeManager.connect(signers[1])["withdrawStash(bytes32)"]("" + stashId)).to.be.reverted;
    await expect(stakeManager.connect(signers[1])["withdrawStash(bytes32,bytes32[],uint256[])"]("" + stashId, ["" + pondTokenId], [50])).to
      .be.reverted;
    await expect(stakeManager.connect(signers[1])["withdrawStash(bytes32,bytes32[],uint256[])"]("" + stashId, ["" + mpondTokenId], [50])).to
      .be.reverted;
  });
});
