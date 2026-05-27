import { deployMockContract } from "@ethereum-waffle/mock-contract";
import { expect } from "chai";
import { BigNumber as BN, Contract, Signer } from "ethers";
import { ethers, upgrades } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

import {
  ClusterRegistry,
} from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import {
  getClusterRegistry,
} from "../../utils/typechainConvertor";
import { testERC165 } from "../helpers/erc165";
import { testAdminRole } from "../helpers/rbac";

declare module "ethers" {
  interface BigNumber {
    e18(this: BigNumber): BigNumber;
  }
}
BN.prototype.e18 = function() {
  return this.mul(BN.from(10).pow(18));
};

const COMMISSION_LOCK = "0x7877e81172e1242eb265a9ff5a14c913d44197a6e15e0bc1d984f40be9096403";
const SWITCH_NETWORK_LOCK = "0x18981a75d138782f14f3fbd4153783a0dc1558f28dc5538bf045e7de84cb2ae2";
const UNREGISTER_LOCK = "0x027b176aae0bed270786878cbabc238973eac20b1957aae44b82a73cc8c7080c";
const SELECTORS = [COMMISSION_LOCK, SWITCH_NETWORK_LOCK, UNREGISTER_LOCK];
const WAIT_TIMES: number[] = [120, 300, 600];

describe("ClusterRegistry", function() {
  let signers: Signer[];
  let addrs: string[];

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("deploys with initialization disabled", async function() {
    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    let clusterRegistry = await ClusterRegistry.deploy();

    await expect(clusterRegistry.initialize(WAIT_TIMES, addrs[11])).to.be.revertedWith("Initializable: contract is already initialized");
  });

  it("deploys as proxy and initializes", async function() {
    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    const clusterRegistry = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, addrs[11]], { kind: "uups" });

    await Promise.all(
      SELECTORS.map(async (s, idx) => {
        expect(await clusterRegistry.lockWaitTime(s)).to.equal(WAIT_TIMES[idx]);
      })
    );
    expect(await clusterRegistry.hasRole(await clusterRegistry.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    expect(await clusterRegistry.rewardDelegators()).to.equal(addrs[11]);
  });

  it("upgrades", async function() {
    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    const clusterRegistry = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, addrs[11]], { kind: "uups" });
    await upgrades.upgradeProxy(clusterRegistry.address, ClusterRegistry, { kind: "uups" });

    await Promise.all(
      SELECTORS.map(async (s, idx) => {
        expect(await clusterRegistry.lockWaitTime(s)).to.equal(WAIT_TIMES[idx]);
      })
    );
    expect(await clusterRegistry.hasRole(await clusterRegistry.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
    expect(await clusterRegistry.rewardDelegators()).to.equal(addrs[11]);
  });

  it("does not upgrade without admin", async function() {
    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    const clusterRegistry = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, addrs[11]], { kind: "uups" });

    await expect(upgrades.upgradeProxy(clusterRegistry.address, ClusterRegistry.connect(signers[1]), { kind: "uups" })).to.be.revertedWith("only admin");
  });
});

testERC165(
  "ClusterRegistry",
  async function(_: Signer[], addrs: string[]) {
    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    let clusterRegistry = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, addrs[11]], { kind: "uups" });
    return clusterRegistry;
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

testAdminRole("ClusterRegistry", async function(_: Signer[], addrs: string[]) {
  const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
  let clusterRegistry = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, addrs[11]], { kind: "uups" });
  return clusterRegistry;
});

describe("ClusterRegistry", function() {
  let signers: Signer[];
  let addrs: string[];
  let clusterRegistry: ClusterRegistry;
  let rewardDelegators: Contract;

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());

    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    let clusterRegistryContract = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, rewardDelegators.address], { kind: "uups" });
    clusterRegistry = getClusterRegistry(clusterRegistryContract.address, signers[0]);
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("non admin cannot update lockWaitTime", async () => {
    await expect(clusterRegistry.connect(signers[1]).updateLockWaitTime(COMMISSION_LOCK, 10)).to.be.revertedWith("only admin");
    await expect(clusterRegistry.connect(signers[1]).updateLockWaitTime(SWITCH_NETWORK_LOCK, 10)).to.be.revertedWith("only admin");
    await expect(clusterRegistry.connect(signers[1]).updateLockWaitTime(UNREGISTER_LOCK, 10)).to.be.revertedWith("only admin");
  });

  it("admin can update lockWaitTime", async () => {
    await clusterRegistry.updateLockWaitTime(COMMISSION_LOCK, 10);
    expect(await clusterRegistry.lockWaitTime(COMMISSION_LOCK)).to.equal(10);

    await clusterRegistry.updateLockWaitTime(SWITCH_NETWORK_LOCK, 100);
    expect(await clusterRegistry.lockWaitTime(SWITCH_NETWORK_LOCK)).to.equal(100);

    await clusterRegistry.updateLockWaitTime(UNREGISTER_LOCK, 1000);
    expect(await clusterRegistry.lockWaitTime(UNREGISTER_LOCK)).to.equal(1000);
  });

  it("non admin cannot update RewardDelegatorsAddress", async () => {
    await expect(clusterRegistry.connect(signers[1]).updateRewardDelegators(addrs[13])).to.be.revertedWith("only admin");
  });

  it("admin can update RewardDelegatorsAddress", async () => {
    await clusterRegistry.updateRewardDelegators(addrs[13]);
    expect(await clusterRegistry.rewardDelegators()).to.equal(addrs[13]);
  });
});

describe("ClusterRegistry", function() {
  let signers: Signer[];
  let addrs: string[];

  let clusterRegistry: ClusterRegistry;
  let rewardDelegators: Contract;
  const DOTHASH = ethers.utils.id("DOT");

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());

    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    let clusterRegistryContract = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, rewardDelegators.address], { kind: "uups" });
    clusterRegistry = getClusterRegistry(clusterRegistryContract.address, signers[0]);
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can register new cluster", async () => {
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], DOTHASH).returns();

    await clusterRegistry.register(DOTHASH, 7, addrs[11], addrs[12]);
    const clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
    expect(await clusterRegistry.clientKeys(addrs[12])).to.equal(addrs[0]);
  });

  it("cannot register new cluster with commission over 100", async () => {
    await rewardDelegators.mock.updateClusterDelegation.returns();

    await expect(clusterRegistry.register(DOTHASH, 101, addrs[11], addrs[12])).to.be.revertedWith("CR:R-Commission more than 100%");
  });

  it("cannot register new cluster with existing client key", async () => {
    await rewardDelegators.mock.updateClusterDelegation.returns();

    await clusterRegistry.connect(signers[1]).register(DOTHASH, 7, addrs[11], addrs[12]);
    const clusterData = await clusterRegistry.getCluster(addrs[1]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await expect(clusterRegistry.register(DOTHASH, 7, addrs[13], addrs[12])).to.be.revertedWith("CR:R-Client key is already used");
  });

  it("cannot register existing cluster again", async () => {
    await rewardDelegators.mock.updateClusterDelegation.returns();

    await clusterRegistry.register(DOTHASH, 7, addrs[11], addrs[12]);
    const clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await expect(clusterRegistry.register(DOTHASH, 7, addrs[13], addrs[14])).to.be.revertedWith("CR:R-Cluster is already registered");
  });

  it("cannot register existing cluster while unregistering", async () => {
    await rewardDelegators.mock.updateClusterDelegation.returns();
    await rewardDelegators.mock.removeClusterDelegation.returns();

    await clusterRegistry.register(DOTHASH, 7, addrs[11], addrs[12]);
    const clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await clusterRegistry.requestUnregister();

    await expect(clusterRegistry.register(DOTHASH, 7, addrs[13], addrs[14])).to.be.revertedWith("CR:R-Cluster is already registered");
  });

  it("can register existing cluster after unregistering", async () => {
    await rewardDelegators.mock.updateClusterDelegation.returns();
    await rewardDelegators.mock.removeClusterDelegation.returns();

    await clusterRegistry.register(DOTHASH, 7, addrs[11], addrs[12]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await clusterRegistry.requestUnregister();

    await time.increase(WAIT_TIMES[2]);
    await clusterRegistry.unregister();

    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], ethers.utils.id("NEAR")).returns();
    await clusterRegistry.register(ethers.utils.id("NEAR"), 17, addrs[21], addrs[22]);
    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(ethers.utils.id("NEAR"));
    expect(clusterData.commission).to.equal(17);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;
  });
});

describe("ClusterRegistry", function() {
  let signers: Signer[];
  let addrs: string[];
  let clusterRegistry: ClusterRegistry;
  let rewardDelegators: Contract;
  const DOTHASH = ethers.utils.id("DOT");
  const NEARHASH = ethers.utils.id("NEAR");

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());

    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    let clusterRegistryContract = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, rewardDelegators.address], { kind: "uups" });
    clusterRegistry = getClusterRegistry(clusterRegistryContract.address, signers[0]);

    await rewardDelegators.mock.updateClusterDelegation.returns();
    await clusterRegistry.register(DOTHASH, 7, addrs[11], addrs[12]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
    await rewardDelegators.mock.updateClusterDelegation.reverts();

    let clusterRewardData = await clusterRegistry.getRewardInfo(addrs[0]);
    expect(clusterRewardData[0]).to.equal(7);
    expect(clusterRewardData[1]).to.equal(addrs[11]);
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can update commission, network, reward address, client key", async () => {
    await clusterRegistry.updateCluster(70, NEARHASH, addrs[21], addrs[22]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await clusterRegistry.updateCommission();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await clusterRegistry.switchNetwork();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(NEARHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update commission, network, reward address", async () => {
    await clusterRegistry.updateCluster(70, NEARHASH, addrs[21], ethers.constants.AddressZero);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await clusterRegistry.updateCommission();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await clusterRegistry.switchNetwork();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(NEARHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update commission, network, client key", async () => {
    await clusterRegistry.updateCluster(70, NEARHASH, ethers.constants.AddressZero, addrs[22]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await clusterRegistry.updateCommission();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await clusterRegistry.switchNetwork();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(NEARHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update commission, reward address, client key", async () => {
    await clusterRegistry.updateCluster(70, ethers.constants.HashZero, addrs[21], addrs[22]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await clusterRegistry.updateCommission();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await expect(clusterRegistry.switchNetwork()).to.be.revertedWith("CR:SN-No switch network request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update network, reward address, client key", async () => {
    await clusterRegistry.updateCluster(ethers.constants.MaxUint256, NEARHASH, addrs[21], addrs[22]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await expect(clusterRegistry.updateCommission()).to.be.revertedWith("CR:UCM-No commission update request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await clusterRegistry.switchNetwork();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(NEARHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update commission, network", async () => {
    await clusterRegistry.updateCluster(70, NEARHASH, ethers.constants.AddressZero, ethers.constants.AddressZero);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await clusterRegistry.updateCommission();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await clusterRegistry.switchNetwork();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(NEARHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update commission, reward address", async () => {
    await clusterRegistry.updateCluster(70, ethers.constants.HashZero, addrs[21], ethers.constants.AddressZero);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await clusterRegistry.updateCommission();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await expect(clusterRegistry.switchNetwork()).to.be.revertedWith("CR:SN-No switch network request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update commission, client key", async () => {
    await clusterRegistry.updateCluster(70, ethers.constants.HashZero, ethers.constants.AddressZero, addrs[22]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await clusterRegistry.updateCommission();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await expect(clusterRegistry.switchNetwork()).to.be.revertedWith("CR:SN-No switch network request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update network, reward address", async () => {
    await clusterRegistry.updateCluster(ethers.constants.MaxUint256, NEARHASH, addrs[21], ethers.constants.AddressZero);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await expect(clusterRegistry.updateCommission()).to.be.revertedWith("CR:UCM-No commission update request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await clusterRegistry.switchNetwork();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(NEARHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update network, client key", async () => {
    await clusterRegistry.updateCluster(ethers.constants.MaxUint256, NEARHASH, ethers.constants.AddressZero, addrs[22]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await expect(clusterRegistry.updateCommission()).to.be.revertedWith("CR:UCM-No commission update request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await clusterRegistry.switchNetwork();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(NEARHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update reward address, client key", async () => {
    await clusterRegistry.updateCluster(ethers.constants.MaxUint256, ethers.constants.HashZero, addrs[21], addrs[22]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await expect(clusterRegistry.updateCommission()).to.be.revertedWith("CR:UCM-No commission update request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await expect(clusterRegistry.switchNetwork()).to.be.revertedWith("CR:SN-No switch network request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update commission", async () => {
    await clusterRegistry.updateCluster(70, ethers.constants.HashZero, ethers.constants.AddressZero, ethers.constants.AddressZero);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await clusterRegistry.updateCommission();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await expect(clusterRegistry.switchNetwork()).to.be.revertedWith("CR:SN-No switch network request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update network", async () => {
    await clusterRegistry.updateCluster(ethers.constants.MaxUint256, NEARHASH, ethers.constants.AddressZero, ethers.constants.AddressZero);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await expect(clusterRegistry.updateCommission()).to.be.revertedWith("CR:UCM-No commission update request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await clusterRegistry.switchNetwork();

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(NEARHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update reward address", async () => {
    await clusterRegistry.updateCluster(ethers.constants.MaxUint256, ethers.constants.HashZero, addrs[21], ethers.constants.AddressZero);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await expect(clusterRegistry.updateCommission()).to.be.revertedWith("CR:UCM-No commission update request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await expect(clusterRegistry.switchNetwork()).to.be.revertedWith("CR:SN-No switch network request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update client key", async () => {
    await clusterRegistry.updateCluster(ethers.constants.MaxUint256, ethers.constants.HashZero, ethers.constants.AddressZero, addrs[22]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await expect(clusterRegistry.updateCommission()).to.be.revertedWith("CR:UCM-No commission update request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await expect(clusterRegistry.switchNetwork()).to.be.revertedWith("CR:SN-No switch network request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("can update nothing", async () => {
    await clusterRegistry.updateCluster(ethers.constants.MaxUint256, ethers.constants.HashZero, ethers.constants.AddressZero, ethers.constants.AddressZero);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await time.increase(WAIT_TIMES[0]);
    await expect(clusterRegistry.updateCommission()).to.be.revertedWith("CR:UCM-No commission update request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await time.increase(WAIT_TIMES[1] - WAIT_TIMES[0]);
    await expect(clusterRegistry.switchNetwork()).to.be.revertedWith("CR:SN-No switch network request");

    clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
  });
});

describe("ClusterRegistry", function() {
  let signers: Signer[];
  let addrs: string[];
  let clusterRegistry: Contract;
  let rewardDelegators: Contract;
  const DOTHASH = ethers.utils.id("DOT");

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());

    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    clusterRegistry = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, rewardDelegators.address], { kind: "uups" });

    await rewardDelegators.mock.updateClusterDelegation.returns();
    await clusterRegistry.register(DOTHASH, 7, addrs[11], addrs[12]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
    await rewardDelegators.mock.updateClusterDelegation.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can request commission update", async () => {
    await clusterRegistry.requestCommissionUpdate(70);
  });

  it("cannot request commission update to over 100", async () => {
    await expect(clusterRegistry.requestCommissionUpdate(101)).to.be.revertedWith("CR:RCU-Commission more than 100%");
  });

  it("cannot request commission update if already requested", async () => {
    await clusterRegistry.requestCommissionUpdate(70);
    await expect(clusterRegistry.requestCommissionUpdate(70)).to.be.revertedWith("CR:RCU-Commission update in progress");
  });

  it("cannot request commission update if never registered", async () => {
    await expect(clusterRegistry.connect(signers[1]).requestCommissionUpdate(70)).to.be.revertedWith("CR:RCU-Cluster not registered");
  });

  it("cannot request commission update if unregistered", async () => {
    await clusterRegistry.requestUnregister();

    await rewardDelegators.mock.removeClusterDelegation.returns();
    await time.increase(WAIT_TIMES[2]);
    await clusterRegistry.unregister();
    await rewardDelegators.mock.removeClusterDelegation.reverts();

    await expect(clusterRegistry.requestCommissionUpdate(70)).to.be.revertedWith("CR:RCU-Cluster not registered");
  });
});

describe("ClusterRegistry", function() {
  let signers: Signer[];
  let addrs: string[];
  let clusterRegistry: Contract;
  let rewardDelegators: Contract;
  const DOTHASH = ethers.utils.id("DOT");

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());

    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    clusterRegistry = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, rewardDelegators.address], { kind: "uups" });

    await rewardDelegators.mock.updateClusterDelegation.returns();
    await clusterRegistry.register(DOTHASH, 7, addrs[11], addrs[12]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
    await rewardDelegators.mock.updateClusterDelegation.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can update commission after wait time", async () => {
    await clusterRegistry.requestCommissionUpdate(70);

    await time.increase(WAIT_TIMES[0]);

    await clusterRegistry.updateCommission();

    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("cannot update commission again after update", async () => {
    await clusterRegistry.requestCommissionUpdate(70);

    await time.increase(WAIT_TIMES[0]);

    await clusterRegistry.updateCommission();

    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(70);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await expect(clusterRegistry.updateCommission()).to.be.revertedWith("CR:UCM-No commission update request");
  });

  it("cannot update commission before wait time", async () => {
    await clusterRegistry.requestCommissionUpdate(70);

    await time.increase(WAIT_TIMES[0] - 10);

    await expect(clusterRegistry.updateCommission()).to.be.revertedWith("CR:UCM-Commission update in progress");
  });

  it("cannot update commission without request", async () => {
    await time.increase(WAIT_TIMES[0]);

    await expect(clusterRegistry.updateCommission()).to.be.revertedWith("CR:UCM-No commission update request");
  });

  it("cannot update commission if unregistered after request", async () => {
    await clusterRegistry.requestCommissionUpdate(70);

    await time.increase(WAIT_TIMES[0]);

    await clusterRegistry.requestUnregister();

    await rewardDelegators.mock.removeClusterDelegation.returns();
    await time.increase(WAIT_TIMES[2]);
    await clusterRegistry.unregister();
    await rewardDelegators.mock.removeClusterDelegation.reverts();

    await expect(clusterRegistry.updateCommission()).to.be.revertedWith("CR:UCM-No commission update request");
  });
});

describe("ClusterRegistry", function() {
  let signers: Signer[];
  let addrs: string[];
  let clusterRegistry: Contract;
  let rewardDelegators: Contract;
  const DOTHASH = ethers.utils.id("DOT");
  const NEARHASH = ethers.utils.id("NEAR");

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());

    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    clusterRegistry = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, rewardDelegators.address], { kind: "uups" });

    await rewardDelegators.mock.updateClusterDelegation.returns();
    await clusterRegistry.register(DOTHASH, 7, addrs[11], addrs[12]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
    await rewardDelegators.mock.updateClusterDelegation.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can request network switch", async () => {
    await clusterRegistry.requestNetworkSwitch(NEARHASH);
  });

  it("cannot request network switch if already requested", async () => {
    await clusterRegistry.requestNetworkSwitch(NEARHASH);
    await expect(clusterRegistry.requestNetworkSwitch(NEARHASH)).to.be.revertedWith("CR:RNS-Network switch in progress");
  });

  it("cannot request network switch if never registered", async () => {
    await expect(clusterRegistry.connect(signers[1]).requestNetworkSwitch(NEARHASH)).to.be.revertedWith("CR:RNS-Cluster not registered");
  });

  it("cannot request network switch if unregistered", async () => {
    await clusterRegistry.requestUnregister();

    await rewardDelegators.mock.removeClusterDelegation.returns();
    await time.increase(WAIT_TIMES[2]);
    await clusterRegistry.unregister();
    await rewardDelegators.mock.removeClusterDelegation.reverts();

    await expect(clusterRegistry.requestNetworkSwitch(NEARHASH)).to.be.revertedWith("CR:RNS-Cluster not registered");
  });
});

describe("ClusterRegistry", function() {
  let signers: Signer[];
  let addrs: string[];
  let clusterRegistry: Contract;
  let rewardDelegators: Contract;
  const DOTHASH = ethers.utils.id("DOT");
  const NEARHASH = ethers.utils.id("NEAR");

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());

    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    clusterRegistry = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, rewardDelegators.address], { kind: "uups" });

    await rewardDelegators.mock.updateClusterDelegation.returns();
    await clusterRegistry.register(DOTHASH, 7, addrs[11], addrs[12]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
    await rewardDelegators.mock.updateClusterDelegation.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can switch network after wait time", async () => {
    await clusterRegistry.requestNetworkSwitch(NEARHASH);

    await time.increase(WAIT_TIMES[1]);

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await clusterRegistry.switchNetwork();

    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(NEARHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("cannot switch network again after update", async () => {
    await clusterRegistry.requestNetworkSwitch(NEARHASH);

    await time.increase(WAIT_TIMES[1]);

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await clusterRegistry.switchNetwork();

    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(NEARHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;

    await expect(clusterRegistry.switchNetwork()).to.be.revertedWith("CR:SN-No switch network request");
  });

  it("cannot switch network before wait time", async () => {
    await clusterRegistry.requestNetworkSwitch(NEARHASH);

    await time.increase(WAIT_TIMES[1] - 10);

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await expect(clusterRegistry.switchNetwork()).to.be.revertedWith("CR:SN-Network switch in progress");
  });

  it("cannot switch network without request", async () => {
    await time.increase(WAIT_TIMES[1]);

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await expect(clusterRegistry.switchNetwork()).to.be.revertedWith("CR:SN-No switch network request");
  });

  it("cannot switch network if unregistered after request", async () => {
    await clusterRegistry.requestNetworkSwitch(NEARHASH);

    await time.increase(WAIT_TIMES[1]);

    await clusterRegistry.requestUnregister();

    await rewardDelegators.mock.removeClusterDelegation.returns();
    await time.increase(WAIT_TIMES[2]);
    await clusterRegistry.unregister();
    await rewardDelegators.mock.removeClusterDelegation.reverts();

    await rewardDelegators.mock.removeClusterDelegation.reverts();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await rewardDelegators.mock.updateClusterDelegation.reverts();
    await rewardDelegators.mock.updateClusterDelegation.withArgs(addrs[0], NEARHASH).returns();
    await expect(clusterRegistry.switchNetwork()).to.be.revertedWith("CR:SN-No switch network request");
  });
});

describe("ClusterRegistry", function() {
  let signers: Signer[];
  let addrs: string[];
  let clusterRegistry: Contract;
  let rewardDelegators: Contract;
  const DOTHASH = ethers.utils.id("DOT");

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());

    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    clusterRegistry = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, rewardDelegators.address], { kind: "uups" });

    await rewardDelegators.mock.updateClusterDelegation.returns();
    await clusterRegistry.register(DOTHASH, 7, addrs[11], addrs[12]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
    await rewardDelegators.mock.updateClusterDelegation.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can update client key", async () => {
    await clusterRegistry.updateClientKey(addrs[22]);

    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[22]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("cannot update client key to zero address", async () => {
    await expect(clusterRegistry.updateClientKey(ethers.constants.AddressZero)).to.be.revertedWith("CR:UCK - Client key cannot be zero");
  });

  it("cannot update client key to already used key", async () => {
    await rewardDelegators.mock.updateClusterDelegation.returns();
    await clusterRegistry.connect(signers[1]).register(ethers.utils.id("NEAR"), 15, addrs[13], addrs[14]);
    let clusterData = await clusterRegistry.getCluster(addrs[1]);
    expect(clusterData.networkId).to.equal(ethers.utils.id("NEAR"));
    expect(clusterData.commission).to.equal(15);
    expect(clusterData.rewardAddress).to.equal(addrs[13]);
    expect(clusterData.clientKey).to.equal(addrs[14]);
    expect(clusterData.isValidCluster).to.be.true;
    await rewardDelegators.mock.updateClusterDelegation.reverts();

    await expect(clusterRegistry.updateClientKey(addrs[14])).to.be.revertedWith("CR:UCK - Client key is already used");
  });

  it("cannot update client key if never registered", async () => {
    await expect(clusterRegistry.connect(signers[1]).updateClientKey(addrs[22])).to.be.revertedWith("CR:UCK-Cluster not registered");
  });

  it("cannot update client key if unregistered", async () => {
    await clusterRegistry.requestUnregister();

    await rewardDelegators.mock.removeClusterDelegation.returns();
    await time.increase(WAIT_TIMES[2]);
    await clusterRegistry.unregister();
    await rewardDelegators.mock.removeClusterDelegation.reverts();

    await expect(clusterRegistry.updateClientKey(addrs[22])).to.be.revertedWith("CR:UCK-Cluster not registered");
  });
});

describe("ClusterRegistry", function() {
  let signers: Signer[];
  let addrs: string[];
  let clusterRegistry: Contract;
  let rewardDelegators: Contract;
  const DOTHASH = ethers.utils.id("DOT");

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());

    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    clusterRegistry = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, rewardDelegators.address], { kind: "uups" });

    await rewardDelegators.mock.updateClusterDelegation.returns();
    await clusterRegistry.register(DOTHASH, 7, addrs[11], addrs[12]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
    await rewardDelegators.mock.updateClusterDelegation.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can update reward address", async () => {
    await clusterRegistry.updateRewardAddress(addrs[21]);

    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[21]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
  });

  it("cannot update reward address if never registered", async () => {
    await expect(clusterRegistry.connect(signers[1]).updateRewardAddress(addrs[21])).to.be.revertedWith("CR:URA-Cluster not registered");
  });

  it("cannot update reward address if unregistered", async () => {
    await clusterRegistry.requestUnregister();

    await rewardDelegators.mock.removeClusterDelegation.returns();
    await time.increase(WAIT_TIMES[2]);
    await clusterRegistry.unregister();
    await rewardDelegators.mock.removeClusterDelegation.reverts();

    await expect(clusterRegistry.updateRewardAddress(addrs[21])).to.be.revertedWith("CR:URA-Cluster not registered");
  });
});

describe("ClusterRegistry", function() {
  let signers: Signer[];
  let addrs: string[];
  let clusterRegistry: Contract;
  let rewardDelegators: Contract;
  const DOTHASH = ethers.utils.id("DOT");

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());

    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    clusterRegistry = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, rewardDelegators.address], { kind: "uups" });

    await rewardDelegators.mock.updateClusterDelegation.returns();
    await clusterRegistry.register(DOTHASH, 7, addrs[11], addrs[12]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
    await rewardDelegators.mock.updateClusterDelegation.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can request unregister", async () => {
    await clusterRegistry.requestUnregister();
  });

  it("cannot request unregister if already requested", async () => {
    await clusterRegistry.requestUnregister();
    await expect(clusterRegistry.requestUnregister()).to.be.revertedWith("CR:RU-Unregistration already in progress");
  });

  it("cannot request unregister if never registered", async () => {
    await expect(clusterRegistry.connect(signers[1]).requestUnregister()).to.be.revertedWith("CR:RU-Cluster not registered");
  });

  it("cannot request unregister if unregistered", async () => {
    await clusterRegistry.requestUnregister();
    await rewardDelegators.mock.removeClusterDelegation.returns();
    await time.increase(WAIT_TIMES[2]);
    await clusterRegistry.unregister();
    await rewardDelegators.mock.removeClusterDelegation.reverts();

    await expect(clusterRegistry.requestUnregister()).to.be.revertedWith("CR:RU-Cluster not registered");
  });
});

describe("ClusterRegistry", function() {
  let signers: Signer[];
  let addrs: string[];
  let clusterRegistry: Contract;
  let rewardDelegators: Contract;
  const DOTHASH = ethers.utils.id("DOT");

  before(async function() {
    signers = await ethers.getSigners();
    addrs = await Promise.all(signers.map((a) => a.getAddress()));

    // mock reward delegators
    const RewardDelegators = await ethers.getContractFactory("RewardDelegators");
    rewardDelegators = await deployMockContract(signers[0], RewardDelegators.interface.format());

    const ClusterRegistry = await ethers.getContractFactory("ClusterRegistry");
    clusterRegistry = await upgrades.deployProxy(ClusterRegistry, [WAIT_TIMES, rewardDelegators.address], { kind: "uups" });

    await rewardDelegators.mock.updateClusterDelegation.returns();
    await clusterRegistry.register(DOTHASH, 7, addrs[11], addrs[12]);
    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.networkId).to.equal(DOTHASH);
    expect(clusterData.commission).to.equal(7);
    expect(clusterData.rewardAddress).to.equal(addrs[11]);
    expect(clusterData.clientKey).to.equal(addrs[12]);
    expect(clusterData.isValidCluster).to.be.true;
    await rewardDelegators.mock.updateClusterDelegation.reverts();
  });

  takeSnapshotBeforeAndAfterEveryTest(async () => { });

  it("can unregister after wait time", async () => {
    await clusterRegistry.requestUnregister();

    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).returns();
    await time.increase(WAIT_TIMES[2]);
    await clusterRegistry.unregister();
    await rewardDelegators.mock.removeClusterDelegation.withArgs(addrs[0], DOTHASH).reverts();

    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.isValidCluster).to.be.false;
  });

  it("cannot unregister again after unregister", async () => {
    await clusterRegistry.requestUnregister();

    await rewardDelegators.mock.removeClusterDelegation.returns();
    await time.increase(WAIT_TIMES[2]);
    await clusterRegistry.unregister();

    let clusterData = await clusterRegistry.getCluster(addrs[0]);
    expect(clusterData.isValidCluster).to.be.false;

    await expect(clusterRegistry.unregister()).to.be.revertedWith("CR:UR-Cluster not registered");
  });

  it("cannot unregister before wait time", async () => {
    await clusterRegistry.requestUnregister();

    await rewardDelegators.mock.removeClusterDelegation.returns();
    await time.increase(WAIT_TIMES[2] - 10);

    await expect(clusterRegistry.unregister()).to.be.revertedWith("CR:UR-Unregistration already in progress");
  });

  it("cannot unregister without request", async () => {
    await rewardDelegators.mock.removeClusterDelegation.returns();
    await time.increase(WAIT_TIMES[2]);

    await expect(clusterRegistry.unregister()).to.be.revertedWith("CR:UR-No unregistration request");
  });
});

